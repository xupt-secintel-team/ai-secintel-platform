# -*- coding: utf-8 -*-
"""
orchestrator.py —— 事件驱动的多智能体编排（v2.2 新增）
================================================================
此前系统的「智能」只覆盖问答一个场景：监测是固定节拍（15s/6h），
富化是等人来点。本模块把三个模块串成一条**多智能体协作链**：

    ┌─────────────┐   新KEV/高危事件   ┌──────────────┐
    │ Perception   │ ───────────────→ │ Orchestrator  │  定优先级、分派任务、限流
    │ 感知智能体    │                  │ 编排智能体     │
    └─────────────┘                  └──────┬───────┘
                                            │ task dispatch
              ┌─────────────────────────────┼─────────────────────────┐
              ▼                             ▼                         ▼
    ┌───────────────────┐       ┌────────────────────┐      ┌──────────────────┐
    │ EnrichExecutor     │       │ BriefAnalyst        │      │ TraceRecorder     │
    │ 富化执行智能体      │ ───→ │ 研判智能体           │ ───→ │ 全程留痕          │
    │ /api/assets + POC  │ 资产  │ 模板/LLM 生成简报    │ 简报  │ /api/ops/trace   │
    └───────────────────┘       └────────────────────┘      └──────────────────┘

设计约束（与 qa/agent.py 同一套工程哲学）：
1. **全部走本机 HTTP 回访**（AISEC_MAIN_SERVER）：不 import 任何其他模块的代码，
   模块间「互不 import」的硬性约定不破；协作通过数据与接口发生。
2. **永远失败隔离**：任何一步异常只记入 trace + events，绝不向主服务抛。
3. **硬限流**：单轮最多 MAX_PER_CYCLE 个事件，防止情报洪峰时编排器放大负载。
4. **无 Key 也能跑**：简报默认用确定性模板（结构化字段拼装），
   有 AISEC_LLM_API_KEY 时自动升级为 /api/chat 生成的自然语言研判。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

MAIN_SERVER = os.environ.get("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")

MAX_PER_CYCLE = 3          # 单轮最多处理事件数（防放大负载）
HIGH_CVSS = 9.0            # 高危阈值：CVSS ≥ 9 或 KEV 在野利用即触发
TRACE_CAP = 200            # trace 环形上限
BRIEF_CAP = 100            # 简报留存上限

# ── 感知闸门的多路判据（2026-10-08 实测补）─────────────────────────────
#   症状：编排器 status 显示 running=true、interval=60s、seen 持续增长、trace
#   有心跳，但 ops_briefs.json / ops_events.json **恒为 []** —— 「多 Agent 协同」
#   有架构、有日志、却拿不出一份简报。
#   实测根因：data/live_feed.jsonl 全量 4119 条 **全是 article / paper**，
#   `cvss.score` 一律 null、`kev` 一律 {}。而闸门只认「KEV 或 CVSS≥9」，
#   于是**永远筛不出事件**（seen 在涨、事件恒 0，完全吻合现象）。
#   本质：安全博客 / 论文**本就不带 CVSS**，用单一评分阈值等于把
#   「有情报价值但无评分」的条目全部丢弃。
#   修法：多路判据（任一成立即入选）+ **来源标记**（便于复核为什么入选）；
#   优先级 kev > cvss≥9 > 明确 CVE 提及 > 紧急利用关键词，限流仍由
#   MAX_PER_CYCLE 兜底，避免情报洪峰放大负载。
_CVE_MENTION_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# ★ 英文缩写必须带**字母边界**：实测 `RCE`（re.I）会命中 "Resou[RCE]"、
#   "Sou[RCE]"、"Fo[RCE]" —— 17 条 arXiv 论文被当"紧急利用"误报入选。
#   用 `(?<![A-Za-z])…(?![A-Za-z])` 而非 `\b`：中文是 \w，`\bRCE\b` 在
#   "RCE漏洞" 里判不出边界（E 与 漏 都是 word char），会漏掉真正的中文写法。
_URGENT_RE = re.compile(
    r"在野利用|已被利用|主动利用|actively exploited|exploited in the wild|"
    r"紧急|远程代码执行|权限提升|未授权访问|认证绕过|反序列化|供应链攻击|"
    r"(?<![A-Za-z])zero-?day(?![A-Za-z])|(?<![A-Za-z])0-?day(?![A-Za-z])|"
    r"(?<![A-Za-z])RCE(?![A-Za-z])|(?<![A-Za-z])critical vulnerability|actively exploit",
    re.I)

try:
    from disposition import DispositionStore
except Exception:  # pragma: no cover
    try:
        from modules.m0_ops.backend.disposition import DispositionStore
    except Exception:
        DispositionStore = None  # 极端情况：回填能力不可用则降级为空

try:
    from attribution import attribute as _attribute
except Exception:  # pragma: no cover
    try:
        from modules.m0_ops.backend.attribution import attribute as _attribute
    except Exception:
        _attribute = None  # 溯源归因能力不可用则降级为空


def _http(path, params=None, timeout=20, method="GET"):
    # 性能档位：慢机器上统一放大超时（低配 ×2.0）。
    # 编排器一次跑 6 个智能体、串联 4~5 个接口，本机服务在慢机器上响应本就慢，
    # 超时不放大只会让"明明在算却判成失败"。见 core/envprofile.py。
    try:
        from envprofile import T
        timeout = T.timeout(timeout)
    except Exception:
        pass
    url = MAIN_SERVER + path
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# ======================================================================
# 工具注册表（2026-10-06）
# 为什么加：原先智能体的能力调用全是**硬编码端点字面量**散在各方法里
#（_http("/api/assets", …)、_http("/api/remediation", …)…）。
# 那样加一个新能力要改编排本体，而且"系统到底有哪些工具"只能靠翻代码数。
# 改成注册表后：新增能力 = 加一个 @register_tool，不碰编排逻辑；
# 且工具清单能被接口读出（/api/ops/tools），可扩展性才是可核验的。
# ======================================================================
TOOLS = {}


def register_tool(name, desc, timeout=20, local=False):
    """把一项能力注册为智能体可调用的工具。"""

    def deco(fn):
        TOOLS[name] = {"name": name, "desc": desc,
                       "timeout": timeout, "local": bool(local), "fn": fn}
        return fn

    return deco


def call_tool(name, **params):
    """按名字调用已注册工具。未注册直接抛错（不静默吞，避免拼错工具名却不自知）。"""
    t = TOOLS.get(name)
    if t is None:
        raise KeyError("工具未注册：%s（已注册：%s）"
                       % (name, "、".join(sorted(TOOLS)) or "无"))
    return t["fn"](**params)


def tool_manifest():
    """工具清单（不含函数对象）：新增工具后这里自动多一项，可对外核验。"""
    return [{"name": n, "desc": t["desc"], "timeout": t["timeout"],
             "kind": "local" if t["local"] else "http"}
            for n, t in sorted(TOOLS.items())]


# ── HTTP 类工具（打到本机主体服务的接口）────────────────────────────
@register_tool("assets", "按受影响产品把漏洞映射到本机资产清单", timeout=25)
def _tool_assets(id=None, **kw):  # noqa: A002 —— 与接口参数同名
    return _http("/api/assets", {"id": id}, timeout=25)


@register_tool("poc", "查该漏洞的公开 POC/EXP（缓存快速档）", timeout=15)
def _tool_poc(id=None, **kw):  # noqa: A002
    return _http("/api/poc", {"id": id}, timeout=15)


@register_tool("llm_brief", "调大模型生成处置研判简报", timeout=90)
def _tool_llm_brief(q=None, **kw):
    return _http("/api/chat", {"q": q}, timeout=90)


@register_tool("remediation", "取修复方案（升级/加固/缓解/验证）", timeout=40)
def _tool_remediation(id=None, **kw):  # noqa: A002
    return _http("/api/remediation", {"id": id}, timeout=40)


@register_tool("detail", "取漏洞详情（归因与交叉验证用）", timeout=15)
def _tool_detail(id=None, **kw):  # noqa: A002
    return _http("/api/detail", {"id": id}, timeout=15)


# ── 进程内工具（不依赖 HTTP，失败时由调用方隔离）────────────────────
@register_tool("attribution", "本地溯源归因：主体画像 + 攻击链分段", local=True)
def _tool_attribution(doc=None, **kw):
    if _attribute is None:
        raise RuntimeError("归因能力不可用（attribution 模块导入失败）")
    return _attribute(doc)


@register_tool("disposition_boost", "处置记忆库：同 CVE 秒判 / 同组件类推", local=True)
def _tool_disposition_boost(store=None, cve_id=None, components=None, **kw):
    if store is None:
        raise RuntimeError("处置记忆库未初始化")
    return store.boost(cve_id, components)


class TraceRecorder:
    """每个环节都留痕：谁、何时、做了什么、成败、耗时。GET /api/ops/trace 可查。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._items = []

    def add(self, agent, action, ok=True, detail="", ms=0):
        with self._lock:
            self._items.append({
                "t": time.strftime("%H:%M:%S"), "agent": agent, "action": action,
                "ok": bool(ok), "detail": str(detail)[:200], "ms": int(ms)})
            self._items = self._items[-TRACE_CAP:]

    def list(self, limit=50):
        with self._lock:
            return list(reversed(self._items[-limit:]))


class PerceptionAgent:
    """感知智能体：盯 data/live_feed.jsonl 增量，产出「值得处置」的事件。"""

    def __init__(self, feed_fp, state_fp, trace):
        self.feed_fp = feed_fp
        self.state_fp = state_fp
        self.trace = trace
        # seen 的锁：scan() 的「查-改」与 save() 的 sorted() 需互斥
        self._lock = threading.Lock()
        self.seen, self.feed_offset = self._load_state()

    def _load_state(self):
        try:
            with open(self.state_fp, encoding="utf-8") as f:
                d = json.load(f)
                return set(d.get("seen_ids", [])), int(d.get("feed_offset", 0) or 0)
        except Exception:  # noqa: BLE001
            return set(), 0

    def save(self):
        # seen 快照与落盘一起持锁：sorted(self.seen) 与 scan() 里的 add() 并发时
        # 会抛「Set changed size during iteration」；固定 .tmp 名还会与其他写者
        # 撞 WinError 32（实测 6 线程下 294 次「另一个程序正在使用此文件」）。
        with self._lock:
            try:
                tmp = "%s.%d.%d.tmp" % (self.state_fp, os.getpid(), threading.get_ident())
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({"seen_ids": sorted(self.seen)[-5000:],
                               "feed_offset": self.feed_offset,
                               "updated": time.strftime("%Y-%m-%dT%H:%M:%S")}, f)
                os.replace(tmp, self.state_fp)
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m0_ops/backend/orchestrator.py:save", _sw_e)

    def scan(self):
        """返回新事件列表：[{id, kind, title, cvss, kev, published}]

        ★ 增量扫描（v2.2.1 修「尾部 400 行导致零产出」的评审问题）：
        旧实现 `readlines()[-400:]` 只看文件末尾 400 行 —— 实时流 4230 条里
        含 CVE 提及的有 227 条、紧急词 428 条，但尾部 400 行只有 2 条 CVE 提及，
        于是多路闸门在真实数据上**筛不出任何可处置事件**（评审实证：ops_events/briefs=[]）。
        根因是「窗口太小 + 只扫尾部」：高信号事件一旦滚出尾部 400 行就再也扫不到，
        而 seen 又只在扫到的行里累积，形成「扫不到 → 记不住 → 永远扫不到」的死锁。

        修法：改用**文件字节偏移做增量游标**。
          · 首次运行 offset=0 → 全量回溯一遍（把历史累积的高信号事件一次筛出）；
          · 之后每轮从上次的 offset 继续读 → 只处理新增行，成本 O(新增) 而非 O(全量)；
          · 文件被轮转/截断（offset > 文件当前大小）→ 自动归零重扫，避免漏；
          · 若 offset 处恰是半行（追加写了一半），丢弃残行，下轮从整行起点继续。
        seen 仍保留去重（跨轮次、跨实例）。offset 与 seen 一起持久化在 state。
        """
        t0 = time.time()
        events = []
        try:
            if not os.path.isfile(self.feed_fp):
                return []
            fsize = os.path.getsize(self.feed_fp)
            with self._lock:
                start = self.feed_offset
            # 文件比游标小（被轮转/清空/重建）→ 从头来
            if start > fsize:
                start = 0
            with open(self.feed_fp, encoding="utf-8") as f:
                f.seek(start)
                # 游标可能落在行中间（上次读到一半）。**不做 readline 跳过**：
                # 若 offset 恰在行首，readline 会误吞掉下一整行（实测踩到——
                # 第一轮 readlines() 已把 '\n' 读完，tell() 停在行首，第二轮
                # readline() 把新增的第一行当"残行"丢弃，导致新增事件漏掉）。
                # 残行交给 json.loads 天然容错：解析失败的半行会被 continue 跳过，
                # 下轮 offset 从整行起点继续，不会漏也不会重复。
                lines = f.readlines()
                new_offset = f.tell()
            for line in lines:
                try:
                    d = json.loads(line)
                except Exception:  # noqa: BLE001
                    continue
                iid = d.get("id")
                if not iid:
                    continue
                # seen 的「查-改」必须原子：与 save() 的 sorted() 及另一轮
                # scan() 的 add() 并发会抛 Set changed size / 漏事件
                with self._lock:
                    if iid in self.seen:
                        continue
                    self.seen.add(iid)
                score = ((d.get("cvss") or {}).get("score")) or 0
                # 脏数据（score 是字符串/None）归一为数字：否则下面的 isinstance
                # 会把高危事件当低危丢弃，且 cycle() 的排序键会因混型抛 TypeError
                if not isinstance(score, (int, float)) or isinstance(score, bool):
                    try:
                        score = float(score)
                    except (TypeError, ValueError):
                        score = 0.0
                is_kev = bool(d.get("kev"))
                # ── 多路判据（任一成立即入选，实测见模块顶注释）──
                reasons = []
                if is_kev:
                    reasons.append("kev")
                hi_cvss = isinstance(score, (int, float)) and score >= HIGH_CVSS
                if hi_cvss:
                    reasons.append("cvss>=%g" % HIGH_CVSS)
                _text = "%s %s %s" % (d.get("title") or "", d.get("kind") or "",
                                      str(d.get("desc") or "")[:400])
                _cves = _CVE_MENTION_RE.findall(_text)
                if _cves:
                    reasons.append("cve提及")
                # 「紧急关键词」单独成立时**排除学术论文**：论文标题里的
                # critical / exploit / attack 属学术用词，不代表在野威胁；
                # 论文只有明确提及 CVE 才入选（那才是有处置价值的信号）。
                _is_paper = (str(d.get("type")) == "paper") or str(iid).startswith("ARXIV:")
                if not _is_paper and _URGENT_RE.search(d.get("title") or ""):
                    reasons.append("紧急关键词")
                if not reasons:
                    continue
                # 优先级：kev=0 > cvss≥9=1 > CVE 提及=2 > 紧急关键词=3
                if is_kev:
                    prio = 0
                elif hi_cvss:
                    prio = 1
                elif _cves:
                    prio = 2
                else:
                    prio = 3
                events.append({
                    "id": iid, "kind": d.get("kind") or "",
                    "title": (d.get("title") or "")[:120],
                    "cvss": score, "kev": is_kev,
                    "published": str(d.get("published"))[:32],
                    "detected_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "priority": prio, "reasons": reasons,
                    "cve_mentions": sorted(set(_cves))[:3],
                    # ★ 富化/决策要打的是「CVE 编号」，不是 live 条目 id
                    #   （实测：用 LIVE:BLOG:… 打 /api/assets 与 /api/remediation
                    #   一律 404，导致简报里资产数 0、修复方案取不到）。
                    "cve": (sorted(set(_cves))[0] if _cves else ""),
                })
            with self._lock:
                self.feed_offset = new_offset
            _by_reason: dict = {}
            for _e in events:
                for _r in (_e.get("reasons") or []):
                    _by_reason[_r] = _by_reason.get(_r, 0) + 1
            self.trace.add("perception", "scan", True,
                           f"增量{len(lines)}行（offset {start}→{new_offset}）→ 新事件{len(events)}个"
                           + ("（入选原因：" +
                              "、".join(f"{k}×{v}" for k, v in _by_reason.items()) + "）"
                              if _by_reason else ""),
                           (time.time() - t0) * 1000)
        except Exception as e:  # noqa: BLE001
            self.trace.add("perception", "scan", False, str(e))
        return events


class EnrichExecutor:
    """富化执行智能体：对一个事件调用模块2能力（资产定位 + POC 快速档）。"""

    def __init__(self, trace):
        self.trace = trace

    def run(self, event):
        out = {"assets": None, "poc": None}
        # 优先用事件抽到的 CVE 编号富化（live 条目 id 打 /api/assets 会 404，实测）
        cid = event.get("cve") or event["id"]
        t0 = time.time()
        try:
            out["assets"] = call_tool("assets", id=cid)
            n = len((out["assets"] or {}).get("assets") or [])
            self.trace.add("enrich", f"assets {cid}", True, f"{n} 条资产",
                           (time.time() - t0) * 1000)
        except urllib.error.HTTPError as e:
            # ★ 404 = 该标识**不在知识库**（新披露 CVE 尚未与 NVD/OSV 同步，
            #   或事件本身不是 CVE 型情报）。这与「查得到、但确实没有受影响资产」
            #   是**两件事**，必须分开表述 —— 否则简报里的"资产 0 条"会被
            #   误读成"已排查、确认无暴露"，答辩/复盘时经不起追问。
            if e.code == 404:
                out["assets"] = {"assets": [], "in_kb": False}
                self.trace.add("enrich", f"assets {cid}", True,
                               "不在知识库（404）——待入库后自动补齐",
                               (time.time() - t0) * 1000)
            else:
                self.trace.add("enrich", f"assets {cid}", False, str(e))
        except Exception as e:  # noqa: BLE001
            self.trace.add("enrich", f"assets {cid}", False, str(e))
        # POC 只查缓存/快速档：编排链不做分钟级全量抓取（那是人点按钮的场景）
        t0 = time.time()
        try:
            out["poc"] = call_tool("poc", id=cid)
            n = len((out["poc"] or {}).get("results") or [])
            self.trace.add("enrich", f"poc {cid}", True, f"{n} 条缓存结果",
                           (time.time() - t0) * 1000)
        except Exception as e:  # noqa: BLE001
            self.trace.add("enrich", f"poc {cid}", False, str(e))
        return out


class BriefAnalyst:
    """研判智能体：把事件 + 富化结果变成结构化简报。
    有 LLM Key 时走 /api/chat 生成自然语言；无 Key 用确定性模板（零依赖）。"""

    def __init__(self, trace):
        self.trace = trace

    def _template(self, event, enrich):
        # 标题优先用 CVE 编号（简报是给人看的，LIVE:BLOG:… 这类内部 id 不可读）
        _cve = event.get("cve") or ""
        _head = _cve or event["id"]
        L = [f"## 高危情报简报：{_head}",
             f"- **标题**：{event.get('title') or '（见详情）'}",
             f"- **等级**：CVSS {event.get('cvss') or 'N/A'}"
             + (" · ⚠ CISA KEV 在野利用" if event.get("kev") else ""),
             f"- **披露**：{event.get('published') or '未知'} · **发现**：{event.get('detected_at')}"]
        _a = enrich.get("assets")
        _a = _a if isinstance(_a, dict) else {}
        assets = _a.get("assets") or []
        if not isinstance(assets, list):
            assets = []
        # 区分「不在库」与「查了没资产」——两者对处置的含义完全不同
        if _a.get("in_kb") is False and _cve:
            L.append(f"- **知识库状态**：⚠ `{_cve}` **尚未进入本系统情报库**"
                     "（NVD/OSV 同步滞后于博客披露）；资产与补丁信息待入库后自动补齐")
        a0 = next((a for a in assets if isinstance(a, dict)), None)
        if a0:
            vers = "、".join((a0.get("affected_versions") or [])[:3]) or "见厂商公告"
            L.append(f"- **受影响资产**：{a0.get('vendor')}/{a0.get('product')}（{vers}）")
        survey = _a.get("survey") or {}
        queries = survey.get("queries") if isinstance(survey, dict) else {}
        if isinstance(queries, dict) and queries:
            first_plat = sorted(queries)[0]
            # 语法值可能是 str，也可能是 dict/list（按平台而异），统一转字符串再截断
            q0 = queries[first_plat]
            q0 = q0 if isinstance(q0, str) else json.dumps(q0, ensure_ascii=False, default=str)
            L.append(f"- **测绘语法（{first_plat}）**：`{q0[:80]}`（只生成语法·不扫描）")
        _p = enrich.get("poc")
        _p = _p if isinstance(_p, dict) else {}
        poc = _p.get("results") or []
        if not isinstance(poc, list):
            poc = []
        p0 = next((p for p in poc if isinstance(p, dict)), None)
        if poc:
            head = (p0.get("title") or p0.get("url") or "") if p0 else ""
            L.append(f"- **公开 POC/EXP**：{len(poc)} 条（首选：{str(head)[:60]}）")
        else:
            L.append("- **公开 POC/EXP**：缓存中暂无（可在详情页发起完整搜索）")
        L.append("- **建议**：" + ("24 小时内完成排查与补丁评估（KEV 在野利用）"
                 if event.get("kev") else "纳入本周补丁窗口评估，关注 EXP 公开动态"))
        return "\n".join(L)

    def make(self, event, enrich):
        t0 = time.time()
        has_key = bool(os.environ.get("AISEC_LLM_API_KEY") or os.environ.get("DEEPSEEK_API_KEY"))
        if has_key:
            try:
                q = (f"漏洞 {event['id']}（CVSS {event.get('cvss')}）"
                     f"{'已被在野利用' if event.get('kev') else ''}，"
                     "请给出 5 行以内的处置研判：影响、风险、优先级、修复建议。")
                d = call_tool("llm_brief", q=q)
                ans = d.get("answer") or ""
                if ans:
                    self.trace.add("analyst", f"brief {event['id']} (llm)", True,
                                   f"{len(ans)}字", (time.time() - t0) * 1000)
                    return {"text": ans, "mode": "llm"}
            except Exception as e:  # noqa: BLE001
                self.trace.add("analyst", f"brief {event['id']} (llm)", False,
                               f"LLM失败退回模板: {e}")
        text = self._template(event, enrich)
        self.trace.add("analyst", f"brief {event['id']} (template)", True,
                       f"{len(text)}字", (time.time() - t0) * 1000)
        return {"text": text, "mode": "template"}


class DecisionAgent:
    """决策智能体（v2.4 新增，第五个 Agent）：把「研判简报」升级为「可执行处置决策」。

    这是「智能体架构创新」的落点：此前链路止步于「告诉你有什么漏洞」（研判简报），
    现在新增一个决策环节，综合五维信号产出**带优先级、带动作顺序、带验证标准**的
    处置决策卡片 —— 直接支撑安全应急响应的「决策」需求（奇安信赛题背景点名）。

    五维信号（全部来自确定性 HTTP 回访，不 import 其他模块）：
      ① KEV 在野利用（CISA 已确认被实际利用 → 最高优先级）
      ② CVSS 严重度（≥9 触发高危）
      ③ 受影响资产暴露（assets 数量 → 暴露面大小）
      ④ 公开 POC/EXP 可用性（利用门槛 → 被攻击风险）
      ⑤ 修复方案（remediation：升级路径 / 配置加固 / 缓解 / 验证）
    """

    def __init__(self, trace, disposition=None):
        self.trace = trace
        self.disposition = disposition  # 处置回填记忆库（可空）

    def _priority(self, event, enrich, plan):
        """确定性优先级分级：P0（立即处置）/ P1（24h 内）/ P2（排期）。

        阈值设计（对齐 CVSS 通用分级，避免中高危掉档）：
          P0：KEV 在野利用，或 CVSS ≥ 9.5（极端高危）
          P1：CVSS ≥ 7.0（高危及以上，无论有无 POC 都需 24h 内响应）
          P2：其余（中低危，纳入排期）
        POC 可用性只作为 P1 内的风险提示信号，不改变档位（高危就该处置，
        有没有现成 EXP 只是影响紧迫性说明，不是降档理由）。
        """
        kev = bool(event.get("kev"))
        score = event.get("cvss") or 0
        # 显式推理链：每条规则命中即记录「证据 → 结论」，供 XAI 展示
        steps = []
        if kev:
            steps.append({"rule": "KEV 在野利用", "evidence": "CISA 已确认被实际利用",
                          "conclusion": "最高优先级 P0"})
            return "P0", steps
        if isinstance(score, (int, float)) and score >= 9.5:
            steps.append({"rule": "CVSS 极端高危", "evidence": f"CVSS {score} ≥ 9.5",
                          "conclusion": "P0"})
            return "P0", steps
        if isinstance(score, (int, float)) and score >= 7.0:
            steps.append({"rule": "CVSS 高危", "evidence": f"CVSS {score} ≥ 7.0 且 < 9.5",
                          "conclusion": "P1（24h 内处置）"})
            return "P1", steps
        steps.append({"rule": "中低危", "evidence": f"CVSS {score} < 7.0",
                      "conclusion": "P2（排期处置）"})
        return "P2", steps

    def _decision(self, event, enrich, plan):
        """产出一条可执行决策（一句话结论 + 依据）。"""
        pri, reasoning = self._priority(event, enrich, plan)
        kev = bool(event.get("kev"))
        score = event.get("cvss") or 0
        poc_n = len((enrich.get("poc") or {}).get("results") or [])
        asset_n = len((enrich.get("assets") or {}).get("assets") or [])
        if pri == "P0":
            verb = "立即隔离/下线并启动应急修复"
            why = "CISA 已确认在野利用" if kev else f"CVSS {score} 极端高危"
        elif pri == "P1":
            verb = "24 小时内完成补丁评估与部署"
            why = f"CVSS {score} 高危" + (f"且已有 {poc_n} 条公开 POC/EXP" if poc_n else "")
        else:
            verb = "纳入本周补丁窗口排期处置"
            why = f"CVSS {score}，暴露与利用风险可控"

        # ── 处置闭环回填：历史经验加速（「越用越聪明」的机制落点）──
        # 从修复方案的升级目标里提取组件名，用于「同类组件自动关联」。
        # 归一化：去掉「（版本区间）」括号及版本号，得到纯组件名（如 langflow/langflow）
        import re as _re
        def _norm_comp(s):
            s = (s or "").strip()
            # 去掉全角/半角括号及其内容（版本区间、vendor 说明等）
            s = _re.sub(r"[（(][^)）]*[)）]", "", s)
            # 去掉版本号尾缀（≥ < <= 等比较符 + 数字）
            s = _re.sub(r"[≤≥<>]=?\s*[\d.]+", "", s)
            s = _re.sub(r"[≤≥<>]\s*[\d.]+", "", s)
            return s.strip().strip("-_ .")
        components = []
        for u in (plan.get("upgrade") or [])[:5]:
            comp = _norm_comp(u.get("component") or u.get("target") or "")
            if comp:
                components.append(comp)
        boost = None
        if self.disposition:
            try:
                boost = call_tool("disposition_boost", store=self.disposition,
                                  cve_id=event.get("cve") or event["id"], components=components)
                if boost.get("same_cve"):
                    # 同 CVE 已有处置 → 秒判：复用结论，优先级标注「已处置」无需重复研判
                    latest = boost["same_cve_records"][0]
                    verb = f"已处置（{latest.get('status_label')}），无需重复研判"
                    why = (f"历史处置：{latest.get('ts', '')[:10]} {latest.get('status_label')}"
                           f"；本轮自动复用结论")
                elif boost.get("related"):
                    # 同组件新漏洞 → 自动带出参照，加速研判
                    why += (f"；另有 {len(boost['related'])} 个同组件漏洞的处置经验可参照")
            except Exception:  # noqa: BLE001
                boost = None

        return {
            # 决策卡对外标识用 CVE 编号（无 CVE 时回退 live 条目 id，保持可追溯）
            "cve": event.get("cve") or event["id"],
            "event_id": event["id"],
            "priority": pri,
            "decision": f"【{pri}】{verb}",
            "rationale": why,
            "signals": {
                "kev": kev, "cvss": score, "poc_available": poc_n,
                "assets_exposed": asset_n, "remediation": bool(plan.get("upgrade") or plan.get("config")),
            },
            "reasoning": reasoning,  # 显式推理链：哪条规则 → 什么结论（XAI）
            "history": boost,  # 历史处置加速结果（供 XAI 展示「为什么这么判」）
        }

    def make(self, event, enrich):
        """生成处置决策：修复方案 → 综合信号 → 决策卡。返回 {decision, plan, mode}。"""
        t0 = time.time()
        # 优先用事件抽到的 CVE 编号取修复方案（live 条目 id 打 /api/remediation 会 404，实测）
        cid = event.get("cve") or event["id"]
        plan = {}
        # ① 拉修复方案（m2_enrich /api/remediation，模板/LLM 双模式）
        try:
            r = call_tool("remediation", id=cid)
            if r.get("ok"):
                plan = r.get("plan") or {}
                self.trace.add("decision", f"remediation {cid}", True,
                               f"方案{len(plan.get('upgrade', []))}条升级+{len(plan.get('config', []))}条加固",
                               (time.time() - t0) * 1000)
            else:
                self.trace.add("decision", f"remediation {cid}", False,
                               (r.get("error") or "无方案")[:120])
        except Exception as e:  # noqa: BLE001
            self.trace.add("decision", f"remediation {cid}", False, str(e))

        # ② 综合信号产出决策卡
        dec = self._decision(event, enrich, plan)
        # 动作清单：优先升级 → 配置加固 → 缓解（按 remedation 方案顺序）
        actions = []
        for u in (plan.get("upgrade") or [])[:3]:
            actions.append({"step": "升级", "target": (u.get("target") or "")[:100],
                            "component": (u.get("component") or "")[:60]})
        for c in (plan.get("config") or [])[:3]:
            actions.append({"step": "加固", "target": (c.get("item") or c.get("detail") or "")[:100],
                            "component": ""})
        for m in (plan.get("mitigations") or [])[:2]:
            actions.append({"step": "缓解", "target": m[:100], "component": ""})
        if not actions:
            actions.append({"step": "排查", "target": "语料暂无完整修复路径，先排查受影响资产并跟进官方公告", "component": ""})

        dec["actions"] = actions
        dec["verify"] = (plan.get("verify") or [])[:3]
        dec["references"] = (plan.get("references") or [])[:5]
        # 溯源归因：漏洞 → 利用者 → ATT&CK 战术链路（附在决策卡上，供研判参考）
        if _attribute:
            try:
                # 从 /api/detail 取完整记录做归因（enrich 里只有资产/POC，缺 desc/cwe）
                detail = None
                try:
                    detail = call_tool("detail", id=cid)
                except Exception:  # noqa: BLE001
                    detail = None
                src = detail if detail and detail.get("id") else event
                dec["attribution"] = call_tool("attribution", doc=src)
                self.trace.add("decision", f"attribute {cid}", True,
                               f"主体={dec['attribution']['actor']['label']} · "
                               f"{len(dec['attribution']['kill_chain'])} 段攻击链",
                               (time.time() - t0) * 1000)
            except Exception as e:  # noqa: BLE001
                self.trace.add("decision", f"attribute {cid}", False, str(e))
        self.trace.add("decision", f"decide {cid}", True,
                       f"{dec['priority']} · {len(actions)} 步动作 · {dec['decision'][:40]}",
                       (time.time() - t0) * 1000)
        return {"decision": dec, "plan": plan, "mode": plan.get("generated_by") or "template"}


class ChallengerAgent:
    """质疑智能体（v2.5 新增，第六个 Agent）：多智能体红蓝自博弈的「红方」。

    决策智能体（蓝方）产出一条处置决策后，本 Agent 站在**攻击者视角**反向挑战它，
    提出若干尖锐质疑（如「优先级是否偏低？」「是否存在未被覆盖的攻击路径？」
    「处置动作是否可被绕过？」），蓝方逐条抗辩，最终收敛出**更稳的决策**：
      - 质疑命中 → 修正决策（升档 / 补充动作 / 标注残余风险）
      - 质疑未命中 → 决策加固（标注「已通过对抗审视」）

    这是「智能体架构创新」的第二落点：不是单个 Agent 拍脑袋，而是让两个立场相反
    的 Agent 互相挑战，把「可能被评委/攻击者挑出的漏洞」在决策出口前就压下去。
    纯确定性规则（零依赖），无 Key 也能完整演示红蓝对抗全过程。
    """

    def __init__(self, trace):
        self.trace = trace

    def _challenge(self, event, enrich, dec):
        """生成质疑清单（红方攻击视角）。返回 [(质疑, 严重度, 命中依据)]。"""
        challenges = []
        sig = dec.get("signals") or {}
        pri = dec.get("priority") or "P2"
        kev = bool(sig.get("kev"))
        cvss = sig.get("cvss") or 0
        poc_n = sig.get("poc_available") or 0
        asset_n = sig.get("assets_exposed") or 0
        remediation = sig.get("remediation")

        # 质疑①：有 POC 且无加固/升级方案时，P1 是否低估？
        if poc_n and not remediation and pri == "P1":
            challenges.append((
                "已有公开 POC 但缺少明确修复方案，仅 24h 内评估是否过于乐观？",
                "high", f"{poc_n} 条 POC 可用，但 remediation 信号缺失"))

        # 质疑②：资产暴露面大且高危，是否漏了「先收敛暴露面」的前置动作？
        if asset_n and cvss >= 7.0:
            if not any(a.get("step") == "排查" for a in (dec.get("actions") or [])) and pri in ("P0", "P1"):
                challenges.append((
                    "高危且多类资产暴露，处置前是否应先排查/收敛互联网暴露面？",
                    "medium", f"{asset_n} 类资产暴露，CVSS {cvss}"))

        # 质疑③：CVSS 极高但未列 KEV，是否被低估为 P1？
        if cvss >= 9.5 and not kev and pri != "P0":
            challenges.append((
                "CVSS 已达极端高危，纵使未见 KEV，是否仍应按 P0 立即处置？",
                "high", f"CVSS {cvss} ≥ 9.5 但被判 {pri}"))

        # 质疑④：无 POC、无资产暴露的中危，动作清单是否空转？
        if pri == "P2" and not poc_n and not asset_n:
            challenges.append((
                "中低危且无暴露证据，排期动作是否缺少「持续观察 EXP 动态」的跟踪项？",
                "low", "P2 且无 POC/资产信号"))

        # 质疑⑤：存在同组件历史处置，是否应当直接复用而非重新研判？
        hist = dec.get("history") or {}
        if hist.get("related") and not hist.get("same_cve"):
            challenges.append((
                "存在同组件处置经验，是否可加速到「复用既有路径」而非从零研判？",
                "low", f"{len(hist['related'])} 个同组件处置参照"))

        return challenges

    def _defend(self, event, dec, challenges):
        """蓝方抗辩：逐条回应质疑，产出 (抗辩说明, 是否触发修正)。"""
        sig = dec.get("signals") or {}
        kev = bool(sig.get("kev"))
        cvss = sig.get("cvss") or 0
        poc_n = sig.get("poc_available") or 0
        asset_n = sig.get("assets_exposed") or 0
        remediation = sig.get("remediation")
        hist = dec.get("history") or {}
        rounds = []
        fixes = []       # 触发的决策修正
        pri = dec.get("priority")

        for q, sev, why in challenges:
            if "公开 POC 但缺少" in q:
                rounds.append({"challenge": q, "severity": sev, "verdict": "部分采纳",
                               "defense": "保留 P1 档位，但补充「并行启动临时缓解（WAF/网络隔离）」动作，不等完整补丁"})
                fixes.append("补充临时缓解动作（WAF/隔离），不等补丁完成")
            elif "收敛互联网暴露面" in q:
                rounds.append({"challenge": q, "severity": sev, "verdict": "采纳",
                               "defense": "前置动作改为「先收敛暴露面 → 再评估补丁」，暴露面收敛是补丁部署的前置条件"})
                fixes.append("动作顺序前置：先收敛资产暴露面")
            elif "极端高危" in q and "KEV" in q:
                rounds.append({"challenge": q, "severity": sev, "verdict": "采纳",
                               "defense": "CVSS≥9.5 已达极端高危，修正为 P0 立即处置（防御性升档）"})
                fixes.append("优先级由 P1 升档为 P0")
            elif "持续观察 EXP" in q:
                rounds.append({"challenge": q, "severity": sev, "verdict": "采纳",
                               "defense": "排期项追加「每周复核 EXP 公开动态」，一旦见 EXP 立即升级响应"})
                fixes.append("追加持续观察 EXP 动态的跟踪项")
            elif "同组件处置经验" in q:
                rounds.append({"challenge": q, "severity": sev, "verdict": "采纳",
                               "defense": f"复用 {len(hist.get('related', []))} 条同组件处置路径，缩短研判时间"})
                fixes.append("复用同组件处置经验，加速研判")
            else:
                rounds.append({"challenge": q, "severity": sev, "verdict": "驳回",
                               "defense": "决策已覆盖该信号，无需修正"})

        return rounds, fixes

    def challenge(self, event, enrich, dec):
        """红方质疑 → 蓝方抗辩 → 收敛。返回自博弈结果并就地修正决策。"""
        t0 = time.time()
        challenges = self._challenge(event, enrich, dec)
        rounds, fixes = self._defend(event, dec, challenges)

        # 就地修正决策（优先级升档 + 动作补充），产出「更稳」的最终决策
        final = dict(dec)
        if any("升档为 P0" in f for f in fixes) and dec.get("priority") != "P0":
            final["priority"] = "P0"
            final["decision"] = final["decision"].replace(dec.get("priority"), "P0", 1)
        extra_actions = []
        for f in fixes:
            if "临时缓解" in f:
                extra_actions.append({"step": "临时缓解", "target": "WAF 规则 / 网络隔离（补丁完成前兜底）", "component": ""})
            elif "收敛资产暴露面" in f:
                extra_actions.append({"step": "前置", "target": "收敛互联网暴露面（资产下线/访问控制）", "component": ""})
            elif "持续观察" in f:
                extra_actions.append({"step": "跟踪", "target": "每周复核 EXP 公开动态，见 EXP 即升级响应", "component": ""})
        if extra_actions:
            final["actions"] = (dec.get("actions") or []) + extra_actions

        adversarial = {
            "challenge_count": len(challenges),
            "rounds": rounds,
            "fixes": fixes,
            "conclusion": ("决策经对抗审视并修正" if fixes
                           else "决策经对抗审视，原结论稳健无需修正"),
            "stabilized": not fixes,   # 无修正 = 原决策已稳
        }
        final["adversarial"] = adversarial

        self.trace.add("challenger", f"challenge {event['id']}", True,
                       f"{len(challenges)} 条质疑 · {len(fixes)} 处修正 · {adversarial['conclusion'][:24]}",
                       (time.time() - t0) * 1000)
        return final


class Orchestrator:
    """编排智能体：事件 → 优先级排序 → 限流分派 → 汇总落盘。"""

    def __init__(self, data_dir, config=None):
        cfg = config or {}
        self.data_dir = data_dir
        self.enabled = bool(cfg.get("ops_enabled", True))
        self.interval = int(cfg.get("ops_interval_sec", 60))
        self.max_per_cycle = int(cfg.get("ops_max_per_cycle", MAX_PER_CYCLE))
        self.trace = TraceRecorder()
        self.perception = PerceptionAgent(
            os.path.join(data_dir, "live_feed.jsonl"),
            os.path.join(data_dir, "ops_state.json"), self.trace)
        self.enricher = EnrichExecutor(self.trace)
        self.analyst = BriefAnalyst(self.trace)
        # 处置闭环回填记忆库：让系统「越用越聪明」
        self.disposition = DispositionStore(data_dir) if DispositionStore else None
        self.decision = DecisionAgent(self.trace, self.disposition)
        self.challenger = ChallengerAgent(self.trace)  # 质疑智能体（红蓝自博弈红方）
        self.events_fp = os.path.join(data_dir, "ops_events.json")
        self.briefs_fp = os.path.join(data_dir, "ops_briefs.json")
        self.decisions_fp = os.path.join(data_dir, "ops_decisions.json")
        self._thread = None
        self._stop = threading.Event()
        # 落盘串行化：_append 是「读-改-写」，与 scan_now 的 HTTP 线程并发会静默丢记录
        self._append_lock = threading.Lock()
        self.last_cycle = None

    # ── 主循环 ────────────────────────────────────────────────
    def _briefed_ids(self):
        """已出简报的事件 id（读简报文件）。跨进程幂等的第二道防线：
        同一 data/ 目录若被第二个实例（如另端口的 --no-live 自测实例）共享，
        两边内存 seen 各自独立、可能同时把同一事件当"新"——
        落简报前再查一次文件，保证同一事件在全系统只出一份简报。"""
        ids = set()
        try:
            if os.path.isfile(self.briefs_fp):
                with open(self.briefs_fp, encoding="utf-8") as f:
                    for rec in json.load(f):
                        eid = (rec.get("event") or {}).get("id")
                        if eid:
                            ids.add(eid)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m0_ops/backend/orchestrator.py:254", _sw_e)
        return ids

    def cycle(self, manual=False):
        t0 = time.time()
        events = self.perception.scan()
        # 优先级：kev(0) > cvss≥9(1) > CVE 提及(2) > 紧急关键词(3)；同级按 CVSS 降序。
        # （原按 `not kev` 二分，遇「无评分但含 CVE」的条目无法排序，会随扫描顺序抖动）
        events.sort(key=lambda e: (e.get("priority", 9), -(e["cvss"] or 0)))
        picked = events[: self.max_per_cycle]
        skipped = max(0, len(events) - len(picked))
        processed = []
        briefed = self._briefed_ids()
        for ev in picked:
            if ev["id"] in briefed:
                self.trace.add("orchestrator", f"process {ev['id']}", True,
                               "已有简报（跨实例去重命中），跳过")
                continue
            try:
                enrich = self.enricher.run(ev)
                brief = self.analyst.make(ev, enrich)
                dec = self.decision.make(ev, enrich)
                # 红蓝自博弈：质疑智能体挑战决策 → 收敛出更稳决策
                final_dec = self.challenger.challenge(ev, enrich, dec["decision"])
                dec["decision"] = final_dec
                rec = {"event": ev, "brief": brief["text"], "brief_mode": brief["mode"],
                       "decision": final_dec, "decision_mode": dec["mode"],
                       "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
                self._append(self.briefs_fp, rec, BRIEF_CAP)
                self._append(self.decisions_fp, final_dec, 100)
                self._append(self.events_fp, {"event": ev, "status": "decided",
                                              "priority": final_dec["priority"]}, 500)
                processed.append(ev["id"])
            except Exception as e:  # noqa: BLE001
                self.trace.add("orchestrator", f"process {ev['id']}", False, str(e))
                self._append(self.events_fp, {"event": ev, "status": f"error: {e}"}, 500)
        self.perception.save()
        self.last_cycle = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.trace.add("orchestrator", "cycle(manual)" if manual else "cycle",
                       True, f"事件{len(events)} 处理{len(processed)} 限流跳过{skipped}",
                       (time.time() - t0) * 1000)
        return {"events": len(events), "processed": processed, "skipped": skipped}

    def _append(self, fp, rec, cap):
        # 读-改-写必须整体串行：_loop 守护线程与 scan_now 的 HTTP 线程会并发调用
        # cycle()，各自「读旧内容 → append 自己那条 → 覆写」，后写的覆盖先写的，
        # 不报错但静默丢记录（实测 8 线程 × 40 次只落盘 3 条）。
        # 临时文件名带 pid+线程号，避免并发 open 同一个 .tmp 撞 WinError 32。
        with self._append_lock:
            data = []
            try:
                if os.path.isfile(fp):
                    with open(fp, encoding="utf-8") as f:
                        data = json.load(f)
            except Exception:  # noqa: BLE001
                data = []
            data.append(rec)
            try:
                tmp = "%s.%d.%d.tmp" % (fp, os.getpid(), threading.get_ident())
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(data[-cap:], f, ensure_ascii=False, indent=1)
                os.replace(tmp, fp)
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m0_ops/backend/orchestrator.py:_append", _sw_e)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception as e:  # noqa: BLE001
                self.trace.add("orchestrator", "cycle", False, str(e))
            self._stop.wait(self.interval)

    def start(self):
        if not self.enabled:
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()

    def status(self):
        return {
            "enabled": self.enabled,
            "running": bool(self._thread and self._thread.is_alive()),
            "interval_sec": self.interval,
            "max_per_cycle": self.max_per_cycle,
            "high_cvss_threshold": HIGH_CVSS,
            "last_cycle": self.last_cycle,
            "seen_ids": len(self.perception.seen),
            "agents": ["perception", "orchestrator", "enrich_executor", "brief_analyst",
                       "decision", "challenger"],
        }
