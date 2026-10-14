# -*- coding: utf-8 -*-
"""技术报告正文：第 6 章（实现细节）、第 7 章（核心代码）"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx_engine import C_GREY  # noqa: E402
from report_data import (EN, EXPLOITED, JS_FILES, JS_LINES, MH, PERF,  # noqa: E402
                         POC, PY_FILES, PY_LINES, SOURCES, TERMS, TL, TOTAL)


def build_ch6(R):
    R.h1("第 6 章　系统实现细节")

    R.h2("6.1 模块装载机制")
    R.para(
        '系统采用声明式模块装载。每个模块目录包含一个 module.json，'
        '声明模块标识、负责人、前端资源与路由列表。服务启动时扫描模块目录，'
        '读取声明、加入搜索路径、装载后端入口并注册路由。', indent=False)
    R.code('''
# core/registry.py —— 模块装载的核心逻辑
for man, d in self.discover():
    mid = man["id"]
    cfg_flag = (self.config.get("modules") or {}).get(mid)
    enabled = man.get("enabled", True) if cfg_flag is None else bool(cfg_flag)
    if not enabled:
        self.skipped[mid] = "config.json 中已禁用"
        continue
    # 模块内部互相 import：把 core 与模块自己的 backend 目录放进 sys.path
    for p in (os.path.join(ROOT, "core"),
              os.path.join(d, man.get("backend_dirs", ["backend"])[0])):
        if p not in sys.path:
            sys.path.insert(0, p)
''', caption="代码清单 6-1　模块的发现与装载")
    R.para(
        '该机制带来两个实际好处：模块可以整包替换而不影响其他模块；'
        '单个模块加载失败时会被记录到 skipped 字典中，'
        '服务主体与其他模块照常运行，不会因一个模块的问题导致整体不可用。', indent=True)

    R.h2("6.2 前端资源注入与同步")
    R.para(
        '运行期前端只有 frontend/ 一个根目录，模块的前端资源需要同步进去。'
        '同步由脚本完成，并在持续集成中做一致性检查。'
        '服务端在返回 index.html 时，会把其中的占位符替换为各模块的脚本与样式标签。',
        indent=False)
    R.code('''
# core/server.py —— 把 <!--@modules--> 替换成各模块的 <script>/<link>
def _inject_modules(self, body):
    scripts, ids = [], []
    if REGISTRY is not None:
        for url, _fp in REGISTRY.web_scripts():
            if url.endswith(".css"):
                scripts.append(f'<link rel="stylesheet" href="{url}">')
            else:
                scripts.append(f'<script src="{url}"></script>')
        ids = [{"id": m, "name": c.name, "owner": c.owner}
               for m, c in REGISTRY.modules.items()]
    boot = ("<script>window.AISEC_MODULES=" +
            json.dumps(ids, ensure_ascii=False) + ";</script>")
    return body.decode("utf-8").replace("<!--@modules-->",
                                        boot + "\\n" + "\\n".join(scripts)).encode("utf-8")
''', caption="代码清单 6-2　模块前端资源的运行时注入")

    R.h2("6.3 分类引擎：投票制与阈值")
    R.para(
        '风险分类采用加权投票制。系统为每条记录计算相关性分数，'
        '分数由四类信号累加：命中已知 AI 组件（权重最高）、'
        '描述中的 AI 语义关键词、CWE 指示、模型层风险行为词。'
        '分数超过阈值即判定为 AI 安全情报，并按投票结果确定分类。', indent=False)
    R.code('''
# core/fetch_corpus.py
def classify(rec):
    """返回 (是否AI相关, 相关性分数, 风险分类, 分类依据, 标签)"""
    text = " ".join([rec.get("desc", ""), rec.get("title", ""),
                     " ".join(rec.get("products", [])),
                     " ".join(rec.get("vendors", [])),
                     " ".join(rec.get("tags_raw", []))]).lower()
    score = 0.0
    cat_votes = {}
    # (a) 组件命中：权重最高（命中即 +0.75）
    for p in rec.get("products", []) + rec.get("vendors", []):
        pl = p.lower()
        for name, (cat, w) in AI_PRODUCTS.items():
            if pl == name or pl.replace("_", "-") == name.replace("_", "-"):
                cat_votes[cat] = cat_votes.get(cat, 0) + w
                break
    # (b) 描述关键词命中：每个 +0.16（最多累加到 0.55）
    kw_hits = sorted({k for k in AI_DESC_KEYWORDS if kw_hit(k, text)})
    if kw_hits:
        score += min(0.55, 0.16 * len(kw_hits))
    # (c) CWE 指示：命中 +0.12 并给分类投票 +0.6
    # (d) 模型层行为词：每个 +0.14，并给「② 模型与数据层」投票 +0.7
    score = min(score, 1.0)
    if score >= AI_RELEVANCE_THRESHOLD:            # 阈值 0.45
        category = max(cat_votes.items(), key=lambda x: x[1])[0] \\
                   if cat_votes else DEFAULT_CATEGORY
''', caption="代码清单 6-3　AI 相关性判定与分类投票")
    R.para(
        '词表设计上有一个重要经验：中文关键词必须同时进入描述关键词表与'
        '模型层标签表。原因是二者的计分权重不同——描述关键词每个加 0.16'
        '（是够到 0.45 阈值的主要来源），而模型层标签每个只加 0.14。'
        '早期版本只把中文词加入模型层标签表，导致中文情报最高只能得 0.28 分，'
        '全部被误判为「非 AI 相关」。补齐两张表后，'
        '「训练数据投毒导致模型后门」这类中文表述能被正确识别。', indent=True)

    R.h2("6.4 关键词匹配的边界处理")
    R.para(
        '关键词匹配必须处理词边界，否则会出现子串误判——'
        '例如 dify 会命中 modify，cuda 会命中 barracuda。'
        '系统采用前后否定断言限定词边界。', indent=False)
    R.code('''
def kw_hit(term, text):
    """词边界匹配，避免 dify 命中 modify / cuda 命中 barracuda 这类子串误判"""
    pat = r"(?<![a-z0-9])" + re.escape(term).replace(r"\\ ", r"[\\s\\-_]+") + r"(?![a-z0-9])"
    return re.search(pat, text) is not None
''', caption="代码清单 6-4　词边界匹配")
    R.para(
        '该实现对中文同样有效：中文没有空格分词，边界断言自然退化为子串包含，'
        '这恰好符合中文的匹配需求。', indent=True)

    R.h2("6.5 可信度与论文关联")
    R.para(
        '每条情报都会计算可信度分数，来源权威性、数据完整度、'
        '交叉验证情况均参与计算。此外，系统建立了漏洞与学术论文的关联，'
        '用于支撑归因分析。', indent=False)
    R.para(
        '论文关联采用分级特征策略以抑制泛词造成的弱关联：'
        '共享具体特征（如同一 AI 组件名、同一模型层风险术语）记为强特征，'
        '共享方向性词（如 inference、adversarial）记为弱特征。'
        '关联成立要求加权得分不低于 2 且至少命中一个强特征，'
        '即论文必须与漏洞共享一个具体特征，而非仅仅主题相近。', indent=False)

    R.h2("6.6 日志轮转的实现")
    R.para(
        '服务日志若不加限制地追加，会持续占用磁盘直至写满，'
        '而磁盘写满恰恰是服务无法启动的直接原因，会形成自锁死。'
        '系统实现了按大小轮转的日志写入器。', indent=False)
    R.code('''
# core/logrotate.py —— 关键实现（节选）
def write(self, s):
    if not isinstance(s, str):
        s = str(s)
    nb = len(s.encode(self.encoding, "replace"))
    with self._lock:
        if self._fp is None:
            self._reopen()
        # 轮转决策只此一处判断：_reopen 不再自行判断
        if self._written > 0 and self._written + nb > self.max_bytes:
            self.rotations += 1
            self._reopen(force_rotate=True)
        # 单笔超上限：截断 + 标注（标注行本身也计入预算）
        if nb > self.max_bytes:
            tail_tpl = "[…本条超上限，已截断 %d 字节…]\\n"
            tail_len = len(tail_tpl % len(raw))
            budget = min(self.max_bytes // 2,
                         self.max_bytes - tail_len - 1)
            ...
        self._fp.write(s)
        self._written += nb
    return len(s)
''', caption="代码清单 6-5　日志轮转的字节记账与截断")
    R.para(
        '该实现踩过三个坑，均已在代码注释中固化：'
        '第一，轮转决策必须只在一处判断，若写入与重开各判一次，'
        '两个条件不等价时轮转根本不会触发；'
        '第二，必须显式指定换行符，否则 Windows 平台的换行会让字节账逐行漂移；'
        '第三，阈值不能设下限，否则显式配置的小阈值会被静默改写。', indent=True)

    R.para(
        '另一个平台相关的坑是：在 Windows 上，文件替换操作无法搬动被子进程'
        '继承的句柄。因此日志落盘不能简单地让子进程直接写文件，'
        '而是由父进程建立管道、启动泵线程独占写入。', indent=True)

    R.h2("6.7 前端安全实践")
    R.para('外部数据进入页面的路径有三处，每一处都必须做白名单处理：', indent=False)
    R.code('''
// ① severity 进 class 属性 —— 必须映射，不能直接插值
const SEV_CLS = new Map([
  ['critical', 'crit'], ['high', 'high'], ['medium', 'med'],
  ['low', 'low'], ['info', 'info'],
]);
const sevKey = (s) => String(s == null ? '' : s).trim().toLowerCase();
const sevCls  = (s) => SEV_CLS.get(sevKey(s)) || 'info';
// 用 Map 而非对象字面量：对象字面量下 SEV_CLS['__proto__'] 会命中
// Object.prototype，拼进 class 变成 "[object Object]"

// ② link 进 href —— 只放行 http/https（黑名单写不全变体）
function safeLink(u) {
  const s = String(u == null ? '' : u).trim();
  return /^https?:\\/\\//i.test(s) ? s : '';
}

// ③ color 进 style 属性 —— 按十六进制色白名单
function safeColor(c) {
  return /^#[0-9a-f]{3,8}$/i.test(String(c || '')) ? c : 'var(--txt-4)';
}
''', caption="代码清单 6-6　前端三处白名单处理")
    R.para(
        '三处白名单并非过度设计。实测中曾出现过一篇厂商文章的标题本身含有'
        '尖括号与事件处理器属性，若直接拼接就会形成真实的脚本执行。'
        '这类数据来自外部站点，必须假定其不可信。', indent=True)

    R.h2("6.8 测试体系")
    R.para(
        '系统建立了覆盖后端逻辑、前端渲染与集成行为的自动化测试集，'
        '全部采用离线可运行方式，不依赖网络与外部服务。', indent=False)
    rows = [
        ["后端单元测试", "tools/_test_*.py", "覆盖分类、去重、分级、轮转、"
         "指标采集、报告生成、接口接线等核心逻辑"],
        ["前端桩测试", "tools/_test_*.js", "以最小 DOM 桩渲染真实组件代码，"
         "校验转义、脏数据兜底与产物同步"],
        ["端到端评测", "tools/评测*.py", "多跳推理、问答深度、富化准确率、"
         "检索质量、时效性五个维度"],
        ["持续集成", "运行CI.bat / CI 配置", "全量测试 + 前端同步检查 + "
         "语法编译 + 回环代理自检"],
    ]
    R.table(["测试类型", "位置", "覆盖内容"], rows,
            widths=[2.8, 3.4, 9.4], caption="表 6-1　测试体系构成",
            highlight_col=0)
    R.para(
        '测试设计上有一条重要经验：假数据无法暴露真实数据形态的问题。'
        '例如报告中的工单时限字段可能是「8 天」这样的带单位字符串，'
        '而同一结构中的资产数是整数，测试若只用规整的假数据就会遗漏。'
        '因此系统要求新功能开发后必须用真实产出的数据跑一遍。', indent=True)
    R.pagebreak()


def build_ch7(R):
    R.h1("第 7 章　核心代码说明")

    R.para(
        '本章选取系统中最具代表性的代码片段进行说明，'
        '重点在于说明设计意图而非逐行解释。'
        '需要强调的是，代码注释中大量保留了设计决策的「为什么」——'
        '这些注释记录了实现过程中遇到的真实问题与对应的解决方案，'
        '其信息价值往往高于代码本身。', indent=False)

    R.h2("7.1 检索引擎的评分与排序")
    R.para(
        '检索评分采用 BM25 思路，并对特定字段加权。'
        '标题命中的权重显著高于正文，命中漏洞编号的条目会被优先返回。',
        indent=False)
    R.code('''
# core/engine.py —— 字段权重（节选）
WEIGHTS = {
    "id":     6.0,      # CVE 编号精确命中
    "title":  4.0,      # 标题
    "desc":   2.0,      # 描述首句 / 通告摘要
    "refs":   2.2,      # 引用
    "papers": 2.0,      # 论文关联
    "atlas":  3.0,      # ATT&CK 战术
    "tags":   3.0,
    "advisory": 3.0,    # 厂商公告
    "kev":    2.5,      # 在野利用
}

def search(self, q, filters=None, top_k=30, sort="relevance",
           page=1, expand=True):
    """统一检索入口。expand=True 时对高分工单做详情回填，
    使卡片上的可信度与关联字段完整（否则按可信度排序时会全部沉底）。"""
''', caption="代码清单 7-1　检索评分与字段权重")

    R.h2("7.2 版本区间匹配与脆弱性判定")
    R.para(
        '资产脆弱性判定的核心是 CPE 版本区间比较，'
        '需要正确处理版本号的语义化比较、版本区间的边界包含关系，'
        '以及多来源 CVE 的同漏洞合并。', indent=False)
    R.code('''
# modules/m2_enrich/backend/cmdb_scan.py —— 资产标识的构成
# 资产标识 = CI 编号 + 主机名 + IP + 机房位置（位置由 CI 反查）
# 这样一条处置工单能同时回答：哪台机器、什么组件、放在哪个机房。
#
# 同一漏洞可能被多个源以不同 URL 收录，按漏洞编号 + 组件聚合，
# 合并时 CVSS 取最大值、标签取并集、KEV 状态取或。
''', caption="代码清单 7-2　资产标识与漏洞聚合口径")

    R.para(
        '开发过程中曾遇到一个典型的静默失败：早期版本按漏洞编号去重，'
        '但同一漏洞在 NVD 与厂商公告中的编号格式并不总是相同，'
        '导致同一条漏洞在报告中出现两次。'
        '修复方式是把聚合键明确为「漏洞编号 + 组件」并做归一化。', indent=True)

    R.h2("7.3 去重策略：标题归一优先")
    R.code('''
def _dedup_key(it):
    """去重键：标题优先，其次链接，最后 id。

    为什么不能只用 id —— 实测同一篇厂商文章在语料中出现了 162 次
    （分页抓取导致 URL 带不同后缀，id 也就不同）。
    按 id 去重完全拦不住，日报会出现「162 条一模一样的文章」。
    标题归一（去空白、转小写）后才能真正挡住。
    """
    t = re.sub(r"\\s+", " ", str(it.get("title") or "")).strip().lower()
    if t:
        return ("t", t[:200])
    link = str(it.get("link") or "").strip()
    if link:
        return ("l", link[:300])
    return ("i", str(it.get("id") or ""))
''', caption="代码清单 7-3　去重键的构造")
    R.para(
        '这个案例说明：当上游数据源的行为不可控时，'
        '下游的去重策略必须基于业务语义（标题）而不是技术标识（ID）。'
        '实测该修复使单日条目数从 61 条收敛到 46 条，剔除了 15 条重复。', indent=True)

    R.h2("7.4 严重度分档：区分「低分」与「无分」")
    R.code('''
def _sev(cvss, kev=False, has_score=True):
    """严重度分档。

    ★ has_score 与 cvss 必须分开传：安全博客/研究文章根本没有 CVSS，
      cvss=0 表示「没有评分」而不是「评了 0 分」。
      早期版本不区分两者，导致某天的报告里所有条目都是「低危」，
      看起来像「今天什么大事都没有」——而实际情况是那天有 4 条 KEV。
      现在用独立的 info（资讯）档承接无评分条目。
    """
    if kev:                       # 已在野利用，一律最高
        return "critical"
    if not has_score:
        return "info"             # 无评分 → 资讯
    ...
''', caption="代码清单 7-4　严重度分档的关键设计")
    R.para(
        '这是一个典型的「数据形态决定 UI 语义」的案例。'
        '如果不引入资讯档，报告的等级分布会严重失真，'
        '直接影响评审对当天风险态势的判断。', indent=True)

    R.h2("7.5 采集主循环与日报的节流")
    R.code('''
# modules/m1_monitor/api.py —— 一轮快车道（节选）
with LIVE_LOCK:
    LIVE["last_poll"] = ts
    LIVE["last_ms"] = int((time.time() - t0) * 1000)
    LIVE["last_batch"] = added
    LIVE["per_source"] = dict(getattr(L, "LAST_META", {}).get("per_source") or {})
    # 当日按类报告：轮询有新增就顺手更新一次日报
    # （内部有 1 小时节流 + 每日清理，不会每 15 秒重算一次）
if added:
    _daily_maybe_generate()
''', caption="代码清单 7-5　采集主循环中的日报联动")
    R.para(
        '节流策略的设计依据是实测数据：单次报告生成（含 Excel 渲染）约 0.5 秒。'
        '若无节制地每轮都执行，会在 15 秒的采集节拍中累积可观的开销。'
        '判断是否需要重算只做一次文件状态检查，代价可忽略。', indent=True)

    R.h2("7.6 编排器的跨进程幂等")
    R.code('''
def _briefed_ids(self):
    """已出简报的事件 id（读简报文件）。跨进程幂等的第二道防线：
    同一 data/ 目录若被第二个实例（如另端口的自测实例）共享，
    两边内存 seen 各自独立、可能同时把同一事件当「新」——
    落简报前再查一次文件，保证同一事件在全系统只出一份简报。
    """
    ids = set()
    try:
        if os.path.isfile(self.briefs_fp):
            with open(self.briefs_fp, encoding="utf-8") as f:
                for rec in json.load(f):
                    eid = (rec.get("event") or {}).get("id")
                    if eid:
                        ids.add(eid)
    except Exception as _sw_e:
        _swallow("orchestrator.py:_briefed_ids", _sw_e)
    return ids
''', caption="代码清单 7-6　跨进程幂等的实现")

    R.h2("7.7 保留期清理的安全性")
    R.code('''
def cleanup(retention_days=None, dry_run=False):
    """删除超过保留期的日报。

    只动日报目录下匹配 `YYYY-MM-DD.<ext>` 的文件 ——
    绝不做目录级递归删除（那是不可逆操作，
    且这个目录可能被人手工放过别的东西）。
    """
    for fn in names:
        m = _DAY_FILE_RE.match(fn)
        if not m:
            continue                       # 不是日报文件，碰都不碰
        day = m.group(1)
        if day >= cutoff_s:
            kept += 1
            continue
        fp = os.path.join(d, fn)
        # 先量体积再删：反过来的话 getsize 必然失败，
        # 报出来的 bytes 恒为 0，用户看不到「到底释放了多少空间」
        sz = _size(fp)
        if dry_run:
            removed.append({"date": day, "file": fn, "bytes": sz})
            continue
        os.remove(fp)
        removed.append({"date": day, "file": fn, "bytes": sz})
''', caption="代码清单 7-7　保留期清理的安全约束")
    R.para(
        '该函数体现了三条安全原则：其一，删除范围用文件名正则严格限定，'
        '不做递归；其二，默认预演模式，先返回待删清单让用户确认；'
        '其三，删除前先记录体积，让用户知道释放了多少空间。', indent=True)
    R.pagebreak()
