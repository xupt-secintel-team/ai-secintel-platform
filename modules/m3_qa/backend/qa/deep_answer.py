# -*- coding: utf-8 -*-
"""
deep_answer.py —— 模板模式的「深度分析层」（v2.2 新增）
================================================================
背景：此前模板模式（无 LLM Key 的兜底路径）只会"列证据"，
四类需要**跨文档推理**的提问全部答不出（评测实测 5/12，见
测试报告/多跳推理评测.md 的基线）：

  1. 比较/极值   —— "哪个 CVSS 更高"、"vLLM 最严重的漏洞是哪个"
  2. 版本影响面  —— "影响哪些版本"（数据在模块2 /api/assets，问答不取）
  3. 论文关联    —— "有哪些关联研究"（证据里有 papers 字段但不渲染）
  4. 多轮指代    —— "第一个漏洞的 CWE 是什么"（不解析回指）

本层在**不引入 LLM** 的前提下补齐这四种推理，全部确定性计算：
  - 极值/比较：对检索证据的结构化 CVSS 做 max/差值（可复核，不是生成式编造）
  - 版本影响面：HTTP 回访主体 /api/assets（与 agent.py 同一通道）
  - 论文关联：渲染证据 docs 自带的 papers 字段
  - 指代消解：从历史对话的上一轮答案里抽取第 N 个 CVE，改写进本轮查询
  - 条件链降噪：识别 KEV/CVSS/POC 硬约束后**先过滤证据再渲染**，
    附录"其他相关情报"不再混入不满足条件的条目（评测判错的直接根因）

约定：每个推理结论都带「依据」，让人能一眼复核，不做无来源断言。
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAIN_SERVER = os.environ.get("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")

# ── 意图识别 ─────────────────────────────────────────────────────
_EXTREME_RE = re.compile(r"最高|最大|最严重|最低|最危险|评分.*(?:最|排)|哪个.*(?:高|严重|危险)")
_COMPARE_RE = re.compile(r"哪个.*(?:更高|高)|比较|对比|相比|哪个.*(?:严重|危险)")
# ★ 第 5 轮实测补（2026-10-07）：原表只有 `哪些版本|影响.*版本|版本.*范围|…`，
#   实测「CVE-2026-7482 影响范围」「vLLM 漏洞影响哪些组件」「影响面」
#   **全部命中不了** —— 而"影响范围"恰是用户点名的三类能力之一，
#   且 `content_answer._FIX_Q` 里明确写了 `影响范围`。
#   同一个能力在两处判据不一致 → 用户的问法取决于恰好用了哪个词。
#   这里把"影响范围"这一族说法补全，与 content_answer 对齐。
_VERSION_RE = re.compile(
    r"哪些版本|影响.*版本|版本.*范围|受影响版本|版本区间|"
    r"影响范围|影响面|影响哪些|受影响(?:的)?(?:组件|资产|版本|产品)|"
    r"哪些组件|哪些产品|哪些资产|涉及哪些(?:版本|组件|产品)|"
    r"affected\s*versions?|which\s+versions?", re.I)
# 攻击链 / 利用链 / 攻击路径 —— 用户明确点名的能力之一（"相关攻击链"）
# ★ 实测（2026-10-08，第 2 轮）：原先问"这个漏洞的攻击链是什么样的"命中**零个**
#   意图分支，结论里只有一句"情报汇总"，连"结论（内容要点）"都没有 ——
#   攻击链是**用户明确要求支持**的三类问题之一（影响范围/修复建议/攻击链），
#   却有整整一类没有落点。本段补上。
_ATTACK_RE = re.compile(
    r"攻击链|利用链|攻击路径|攻击过程|利用过程|攻击步骤|利用步骤|"
    r"怎么(?:被)?利用|如何(?:被)?利用|利用方式|攻击方式|攻击手法|"
    r"kill[-\s]?chain|attack\s*chain|exploit\s*chain|exploited|exploiting|exploitation", re.I)

_PAPER_RE = re.compile(r"论文|研究|文献|paper|research", re.I)
_COUNT_RE = re.compile(r"多少|几个|几条|数量|一共有|共计|统计一下")
_MULTI_STATS_RE = re.compile(r"各(?:个|类|种)?|哪些|分布|排行|top\s*\d|最多的是")
_KEV_RE = re.compile(r"在野利用|已被利用|被利用|kev|exploited", re.I)
_POC_RE = re.compile(r"\bpoc\b|\bexp\b|利用代码|公开.*利用", re.I)
_CVSS_COND_RE = re.compile(r"cvss\s*(?:≥|>=|大于等于|不低于|至少)?\s*(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*分", re.I)

# ── 多轮指代消解：两个层次 ───────────────────────────────────────
# ★ 实测踩过的坑（2026-10-07）：原 `_REF_RE` 只认"第N个/首个/它/该漏洞/上述"，
#   实测「那怎么修」「还有别的吗」「继续」**全部不匹配** → 消解完全失效，
#   用户第二轮起就丢失上下文，答案退化成"泛泛的情报汇总"。
#
# 分两类处理，判据不同：
#   A. **显式序号指代**（"第一个漏洞""第2条"）：能唯一定位到上一轮的某个 CVE，
#      用 `_REF_RE` 抽出序号 N，替换成具体编号。
#   B. **隐式承接**（"那怎么修""还有别的吗""继续说说""它的修复建议"）：
#      没有序号，指的是**上一轮的整批结果/第一个结果**。
#      这类不能瞎猜序号，但可以**把上一轮的主实体并入本轮检索式** ——
#      否则「那怎么修」会被当成全新问题，检索式里一个实体都没有。
_REF_RE = re.compile(r"第\s*([一二三四五六七八九\d]+)\s*(?:个|条|项)|首个|第一个|它|该漏洞|这个漏洞|上述")

# 隐式承接信号：命中即说明"本轮问题依赖上一轮的上下文"
_FOLLOWUP_RE = re.compile(
    r"^(?:那|那么|然后|接着|还有|另外|继续|再|其次|"
    r"这些|这(?:些|个|批|几)|它们|其|上述|该|此)"
    r"|怎么修|如何修|修复(?:建议|方案|方法)?$|怎么办|有什么(?:建议|办法)"
    r"|还有(?:别的|其他|更多|吗)|继续(?:说|讲|看)|展开(?:说|讲)|详细(?:说|讲)"
    r"|(?:另外|其他|其它)(?:的)?(?:呢|吗)?$")

# 上一轮实体抽取：产品名 / CVE / CWE（用于把隐式承接"接上电"）
_LAST_ENT_RE = re.compile(
    r"(?:CVE-\d{4}-\d{4,7}|CWE-\d+|GHSA-[a-z0-9-]{4,})"
    r"|(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9_.\-]{2,})(?![A-Za-z0-9])")

_ENTITY_STOP = {"cvss", "cve", "kev", "poc", "exp", "cwe", "epss", "nvd", "ghsa",
                "exploit", "exploited", "vulnerability", "vulnerabilities", "what",
                "which", "have", "has", "been", "with", "that", "this"}


def extract_entities(q: str) -> List[str]:
    """从问题里抽取实体词（产品/厂商/组件名）：去停用词后的英文词，最多 3 个。"""
    out = []
    for t in re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{2,}", q):
        tl = t.lower()
        if tl in _ENTITY_STOP or len(tl) < 4:
            continue
        if tl not in out:
            out.append(tl)
    return out[:3]


def _cn_num(s: str) -> int:
    table = {"一": 1, "二": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9}
    if s.isdigit():
        return int(s)
    return table.get(s, 1)


def is_reference(q: str) -> bool:
    """本轮问题是否**依赖上一轮上下文**（显式序号 或 隐式承接都算）。"""
    if CVE_RE.search(q):          # 自己已经点名了编号，不靠上下文
        return False
    return bool(_REF_RE.search(q)) or bool(_FOLLOWUP_RE.search(q or ""))


def _last_turn_entities(history: List[Dict], limit: int = 2) -> List[str]:
    """从上一轮助手答案里抽「实体」（CVE 编号、产品名），供隐式承接使用。

    为什么要抽实体而不是整句：上一轮答案很长（几千字），整句塞进检索式会
    把 BM25 打分搅乱；只取"上一轮到底在聊哪个东西"最有效。
    优先级：CVE 编号 > 产品名（编号最精确）。
    """
    last = ""
    for h in reversed(history or []):
        if h.get("role") == "assistant":
            last = h.get("content", "") or ""
            break
    if not last:
        return []
    cves: List[str] = []
    for m in CVE_RE.findall(last):
        mu = m.upper()
        if mu not in cves:
            cves.append(mu)
    if cves:
        return cves[:limit]
    # 没有编号 → 抽出现频次最高的产品名（跳过通用安全词）
    from collections import Counter
    stop = {"cve", "cvss", "cwe", "kev", "poc", "exploit", "vulnerability", "high",
            "critical", "medium", "low", "the", "and", "for", "with", "http",
            "https", "com", "www", "ai", "api", "sql", "xss", "rce"}
    cnt = Counter()
    for m in _LAST_ENT_RE.findall(last):
        t = (m or "").strip()
        if not t or len(t) < 3 or t.lower() in stop:
            continue
        cnt[t] += 1
    return [w for w, _ in cnt.most_common(limit)]


def resolve_reference(question: str, history: List[Dict] = None) -> Tuple[str, Optional[str]]:
    """多轮指代消解：把本轮问题"接上"上一轮上下文，返回 (改写后的问题, 解析出的锚点或 None)。

    两类分别处理（实测「那怎么修」「还有别的吗」原先完全不生效）：
      A. 显式序号（"第一个漏洞的 CWE"）→ 取上一轮第 N 个 CVE，替换进本轮问题；
      B. 隐式承接（"那怎么修"/"还有别的吗"/"继续"）→ 取上一轮主旨实体并入检索式。
    返回的第二项（锚点）会写进结果的 `resolved_ref`，前端/评测看得见"本轮接上了谁"。
    """
    if not history or not is_reference(question):
        return question, None
    last_assistant = ""
    for h in reversed(history):
        if h.get("role") == "assistant":
            last_assistant = h.get("content", "")
            break
    cves = [c.upper() for c in CVE_RE.findall(last_assistant)]

    # A. 显式序号：能唯一定位
    m = _REF_RE.search(question)
    if m and m.group(1) and cves:
        n = _cn_num(m.group(1))
        n = max(1, min(n, len(cves)))
        target = cves[n - 1]
        return f"{target} {question}", target

    # B. 隐式承接：把上一轮主旨实体并入检索式（不瞎猜序号）
    ents = _last_turn_entities(history, limit=2)
    if ents:
        anchor = ents[0]
        return f"{anchor} {question}", anchor
    # 兜底：上一轮有编号但本轮无批次指向（如"它/该漏洞"）→ 用第一个
    if cves:
        return f"{cves[0]} {question}", cves[0]
    return question, None


# ── 条件链降噪 ───────────────────────────────────────────────────
def parse_constraints(q: str) -> Dict:
    cons = {}
    if _KEV_RE.search(q):
        cons["kev"] = True
    if _POC_RE.search(q):
        cons["poc"] = True
    m = _CVSS_COND_RE.search(q)
    if m:
        cons["cvss_min"] = float(m.group(1) or m.group(2))
        if re.search(r"恰好|刚好|正好|等于|=\s*" + re.escape(m.group(1) or ""), q):
            cons["cvss_eq"] = cons.pop("cvss_min")
    # 实体约束只跟硬条件一起用（避免普通提问被误过滤）
    if cons:
        ents = extract_entities(q)
        if ents:
            cons["entities"] = ents
    return cons


def filter_by_constraints(docs: List[Dict], cons: Dict) -> List[Dict]:
    """按问题里的硬约束过滤证据。

    ★ 第 3 轮实测修正（R3-2 根因之二）：
      本函数原先对 `kev` / `poc` 做**硬过滤**（不满足直接删）。但上游多跳检索的
      证据池是**混合来源**：
        · `plain` 路 —— 与题面实体相关的条目（框架漏洞，但不一定被在野利用）
        · `cond` 路 —— 结构化算子（kev:yes）精确过滤出来的条目
      对**整池**再硬套一次 kev 约束，等于把 plain 路的相关条目全删掉 ——
      实测「哪些 AI 框架存在在野利用的漏洞」：闸门后 8 条 → 这里砍成 **1 条**，
      丢掉的包括 Ray（CVSS 8.7/5.9）与 vLLM 的真实漏洞，而用户问的是
      "哪些框架有在野利用的漏洞"（枚举题，相关框架信息都要）。
      ✔ 改为**分层**：满足约束的排前面，不满足的**保留在后**（而不是删除）——
        既让"在野利用"的条目优先展示，又不丢"该框架还有其他漏洞"的信息。
      ⚠ 例外：`cvss_min` / `cvss_eq` / `entities` 这类是**用户明确指定的数值/实体
        约束**，必须硬过滤（问 "CVSS>=9" 却给 7.5 的条目是错的）。
    """
    if not cons:
        return docs

    def _hard_ok(d):
        score = ((d.get("cvss") or {}).get("score"))
        if "cvss_min" in cons and (score is None or float(score) < cons["cvss_min"]):
            return False
        if "cvss_eq" in cons and (score is None or abs(float(score) - cons["cvss_eq"]) > 0.051):
            return False
        if cons.get("entities"):
            text = f"{d.get('title','')} {' '.join(d.get('products') or [])} {_plain(d)}".lower()
            if not any(e in text for e in cons["entities"]):
                return False
        return True

    def _soft_ok(d):
        """软约束（kev/poc）：满足即优先，不满足不删。"""
        if cons.get("kev") and not (d.get("exploited") or d.get("kev")):
            return False
        if cons.get("poc") and not ((d.get("poc_count") or 0) > 0 or d.get("poc_links")):
            return False
        return True

    hard = [d for d in docs if _hard_ok(d)]
    if not hard:
        hard = list(docs)          # 安全回退：硬约束过滤后为空则退回（宁可宽不可空）
    # ★ 2026-10-26 补：**复合条件**（数值 + kev/poc）下 kev/poc 必须硬过滤。
    #   实测失分点：问「已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？」，
    #   模板路径把 kev 当软约束 → 证据池里混着非 KEV 条目 → 答案列出的 CVE
    #   不满足"在野利用"，评测按"答出不满足条件的 CVE"判错（多跳 B 类 0/2）。
    #   为什么不影响 R3-2 那次修正：「哪些 AI 框架存在在野利用的漏洞」只有
    #   kev 一个条件、没有数值约束，仍走软分层；只有用户明确给了数值区间时，
    #   才算"复合精确条件"，此时不满足 kev/poc 的条目就是错的。
    if (cons.get("kev") or cons.get("poc")) and (
            "cvss_min" in cons or "cvss_eq" in cons or cons.get("entities")):
        combo = [d for d in hard if _soft_ok(d)]
        if combo:
            return combo

    if not (cons.get("kev") or cons.get("poc")):
        return hard
    good = [d for d in hard if _soft_ok(d)]
    if not good:
        return hard                # 一条都不满足软约束 → 不删（回退，避免整池清空）
    rest = [d for d in hard if not _soft_ok(d)]
    return good + rest             # 分层：满足约束的在前，其余保留在后


# ── 深度推理段落 ─────────────────────────────────────────────────
def _plain(d: Dict) -> str:
    txt = d.get("desc") or ""
    if not txt:
        txt = re.sub(r"<[^>]+>", "", d.get("snippet") or "")
    return txt[:300]


def _score(d):
    s = (d.get("cvss") or {}).get("score")
    return float(s) if s is not None else None


def extreme_section(question: str, docs: List[Dict]) -> Optional[str]:
    """极值/比较结论：极值题做"定向复检"（按实体重新检索一批后取确定性最大值），
    比较题对证据的 CVSS 做差值比较。"""
    if not (_EXTREME_RE.search(question) or _COMPARE_RE.search(question)):
        return None
    # 双 CVE 比较：问题里出现两个编号 → 差值结论
    ids = [c.upper() for c in CVE_RE.findall(question)]
    scored = [(d, _score(d)) for d in docs if _score(d) is not None]
    if len(ids) >= 2 and _COMPARE_RE.search(question):
        pair = {i: None for i in ids[:2]}
        for d, s in scored:
            if d.get("id", "").upper() in pair:
                pair[d["id"].upper()] = (d, s)
        if all(pair.values()):
            (id1, id2) = ids[:2]
            (d1, s1), (d2, s2) = pair[id1], pair[id2]
            hi, lo = ((id1, s1), (id2, s2)) if s1 > s2 else ((id2, s2), (id1, s1))
            return (f"## 结论（跨文档比较）\n"
                    f"**{hi[0]} 的 CVSS 更高**：{hi[1]} vs {lo[1]}，相差 {hi[1]-lo[1]:.1f} 分。\n"
                    f"依据：两条目详情中的结构化 CVSS 字段直接比较。\n\n")
    # 极值题：先尝试"定向复检"——按实体 + 结构化 CVSS 算子分段下探
    # （cvss>=9 → cvss>=7 → 裸实体），取确定性最大值；
    # 相关性排序的 top-N 会漏掉真最大值（评测抓出来的真问题）
    ents = extract_entities(question)
    if ents and _EXTREME_RE.search(question):
        try:
            from qa.retriever import hybrid_search
            pool_scored, used_q = [], ""
            for probe in (f"{ents[0]} cvss>=9", f"{ents[0]} cvss>=7", ents[0]):
                pool = (hybrid_search(probe, top_k=40, skip_vector=True) or {}).get("results") or []
                pool_scored = [(d, _score(d)) for d in pool if _score(d) is not None]
                if pool_scored:
                    used_q = probe
                    break
            if pool_scored:
                best, bs = max(pool_scored, key=lambda x: x[1])
                sev = (best.get("cvss") or {}).get("severity", "")
                ties = [d.get("id") for d, s in pool_scored if s == bs]
                tie_txt = f"（同分并列：{'、'.join(ties[:4])}）" if len(ties) > 1 else ""
                return (f"## 结论（聚合极值）\n"
                        f"对「{ents[0]}」定向复检（`{used_q}`，{len(pool_scored)} 条带评分情报）后，"
                        f"CVSS 最高的是 **[{best.get('id')}]**（{bs}，{sev}）{tie_txt}："
                        f"{best.get('title','')[:80]}\n"
                        f"依据：结构化算子复检结果集内对 CVSS 分值取最大值，非生成式推断。\n\n")
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m3_qa/backend/qa/deep_answer.py:197", _sw_e)
    if len(scored) < 1:
        return None
    best, bs = max(scored, key=lambda x: x[1])
    sev = (best.get("cvss") or {}).get("severity", "")
    return (f"## 结论（聚合极值）\n"
            f"检索到的 {len(docs)} 条证据中，CVSS 最高的是 **[{best.get('id')}]** "
            f"（{bs}，{sev}）：{best.get('title','')[:80]}\n"
            f"依据：对全部证据的结构化 CVSS 分值取最大值，非生成式推断。\n\n")


def stats_section(question: str, docs: List[Dict]) -> Optional[str]:
    """聚合统计（v2.3 新增）：补齐「各组件各几个洞 / 某组件有多少高危」这类跨实体统计。

    分两类：
      - 单实体计数：定向检索拿 total（命中数），叠加 cvss/kev/poc 结构化约束后计数可复核；
      - 多组件分布：对证据池按受影响组件分组计数，输出 top 组件排行。
    """
    if not (_COUNT_RE.search(question) or _MULTI_STATS_RE.search(question)):
        return None
    # 过滤泛词实体，避免「组件」「漏洞」被当成计数对象
    _stats_stop = {"组件", "漏洞", "产品", "系统", "软件", "几个", "多少", "哪些", "各", "top"}
    ents = [e for e in extract_entities(question) if e.lower() not in _stats_stop]
    cons = parse_constraints(question)

    # ── 单实体计数 ──
    if ents and _COUNT_RE.search(question):
        try:
            # 中文严重度 → CVSS 阈值（高危 7.0 / 严重·危急 9.0）
            if cons.get("cvss_min") is None:
                if re.search(r"严重|危急|critical", question, re.I):
                    cons["cvss_min"] = 9.0
                elif re.search(r"高危|高风险|high", question, re.I):
                    cons["cvss_min"] = 7.0
            probe = ents[0]
            cond_txt = ""
            if cons.get("cvss_min") is not None:
                probe = f"{ents[0]} cvss>={cons['cvss_min']}"
                cond_txt = f"（CVSS ≥ {cons['cvss_min']}）"
            elif cons.get("kev"):
                probe = f"{ents[0]} kev:yes"
                cond_txt = "（在野利用）"
            elif cons.get("poc"):
                probe = f"{ents[0]} poc:yes"
                cond_txt = "（含公开 POC）"
            url = MAIN_SERVER + "/api/search?" + urllib.parse.urlencode({"q": probe, "size": 1})
            with urllib.request.urlopen(url, timeout=30) as resp:
                r = json.load(resp)
            total = r.get("total")
            if total is not None:
                return (f"## 结论（聚合统计）\n对「{ents[0]}」定向检索（`{probe}`）命中 **{total}** 条"
                        f"{cond_txt}。依据：结构化算子精确计数（/api/search total），非生成式推断。\n\n")
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m3_qa/backend/qa/deep_answer.py:250", _sw_e)

    # ── 多组件分布 ──
    if _MULTI_STATS_RE.search(question) and not (_COUNT_RE.search(question) and ents):
        from collections import Counter
        c = Counter()
        for d in docs:
            for p in (d.get("products") or [])[:2]:
                if p:
                    c[str(p)] += 1
        if c:
            rows = "\n".join(f"- `{p}`：{n} 条" for p, n in c.most_common(8))
            return (f"## 结论（聚合统计·组件分布）\n{rows}\n"
                    f"依据：对当前证据池（top-{len(docs)}）按受影响组件分组计数，"
                    f"可复核；全库精确分布见检索台分面（products 维度）。\n\n")
    return None


def attack_section(question: str, docs: List[Dict]) -> Optional[str]:
    """攻击链 / 利用链：从命中资料的正文里**抽取**攻击步骤，不做无依据编造。

    ★ 为什么需要（第 2 轮实测）：用户明确要求系统能回答"相关攻击链"，
      但实测「这个漏洞的攻击链是什么样的」命中零个意图分支，
      结论里连"内容要点"都产不出。这是**能力缺口**，不是措辞问题。

    设计原则（延续本模块的"确定性、可复核"底线）：
      - **只从资料原文里抽**攻击相关句子（前置条件 / 触发动作 / 效果），
        不做"通常攻击者会…"这类无来源推断；
      - 抽不到就**如实说明"资料未提供攻击链细节"**并给出可操作建议
        （点开原始资料看全文、换 CVE 编号提问），不硬凑；
      - 每条都标来源编号，读者可回原文复核。
    """
    if not _ATTACK_RE.search(question or ""):
        return None
    if not docs:
        return None

    # 攻击链相关句子：前置条件 / 动作 / 效果 / 权限
    _STEP_RE = re.compile(
        r"攻击者|攻击者可以|可以被|可导致|从而|进而|进而导致|利用(?:该|此)?漏洞|"
        r"触发|构造|发送|注入|上传|执行任意|任意(?:文件|代码|命令)|提权|绕过|越权|"
        r"未授权|前置条件|需要(?:认证|管理员|用户)|远程|无需(?:认证|交互)|"
        r"attacker|exploit|trigger|craft|bypass|escalat|arbitrary|unauth|"
        r"remote|payload|inject|thus|leading to", re.I)

    steps: List[str] = []
    seen = set()
    for d in docs[:4]:
        body = _plain(d)
        body = re.sub(r"<[^>]+>", "", str(body))
        parts = re.split(r"(?<=[。.!！?？;；\n])", body)
        picked = []
        for s in parts:
            s = re.sub(r"\s+", " ", s).strip(" \t\r\n")
            if len(s) < 14 or not _STEP_RE.search(s):
                continue
            key = re.sub(r"\W+", "", s)[:40]
            if key in seen:
                continue
            seen.add(key)
            picked.append(s[:160])
            if len(picked) >= 2:
                break
        if picked:
            steps.append((d.get("id") or "?", picked))
        if len(steps) >= 3:
            break

    if not steps:
        # 抽不到 → 如实说明（不能编造攻击链）
        ids = "、".join("[%s]" % (d.get("id") or "?") for d in docs[:3])
        return ("## 攻击链（利用路径）\n"
                "命中的资料中**未提供成型的攻击链描述**（多为标题/概要级情报）。\n"
                "建议：点开下方「原始详细资料」阅读全文，或用 **CVE 编号**直接提问"
                "（如 `CVE-2024-1234 的攻击链`）以命中含技术细节的条目。\n"
                f"参考条目：{ids}\n"
                "_依据：对命中资料的正文做攻击步骤句式抽取，未作任何生成式推断。_\n\n")

    lines = ["## 攻击链（利用路径）", "",
             "以下为从命中资料正文中抽取的**攻击/利用相关表述**（每条标来源，可回原文复核）：", ""]
    for did, picked in steps:
        lines.append(f"**[{did}]**")
        for s in picked:
            lines.append(f"- {s}")
        lines.append("")
    lines.append("_依据：对命中资料正文按「前置条件／触发动作／效果」句式做确定性抽取，"
                 "未作生成式推断；完整利用细节请点开对应原始资料。_")
    lines.append("")
    return "\n".join(lines)


def version_section(question: str, docs: List[Dict], timeout=15) -> Optional[str]:
    """版本影响面：回访主体 /api/assets（模块2 能力），取受影响版本区间。

    ★ 第 5 轮实测补：原实现只试 `CVE_RE.findall(question)` 的**第一条**，
      且问题里没有 CVE 时只试 `docs[0]`。实测「vLLM 漏洞影响哪些组件」这类
      **产品名提问**（问题里没编号）若 docs[0] 恰好不是资产类条目，
      就静默返回 None —— 明明证据池里有 CVE 条目却不去查。
      改为：把问题里的 CVE + 证据池里所有 CVE 编号**依次尝试**，命中即用。
    """
    if not _VERSION_RE.search(question):
        return None
    cands: List[str] = [c.upper() for c in CVE_RE.findall(question)]
    for d in (docs or []):
        did = str(d.get("id") or "")
        if CVE_RE.fullmatch(did) and did.upper() not in cands:
            cands.append(did.upper())
    if not cands:
        return None

    d = {}
    cid = ""
    for cand in cands[:4]:
        try:
            url = f"{MAIN_SERVER}/api/assets?id=" + urllib.parse.quote(cand)
            with urllib.request.urlopen(url, timeout=timeout) as r:
                d = json.load(r)
        except Exception:  # noqa: BLE001
            continue
        if d.get("assets"):
            cid = cand
            break
    if not d.get("assets"):
        return None
    rows = []
    for it in (d.get("assets") or [])[:5]:
        vers = "、".join(it.get("affected_versions") or []) or "见厂商公告"
        rows.append(f"- `{it.get('vendor')}/{it.get('product')}`：**{vers}**"
                    f"（提取方式：{it.get('extraction_method','')}，置信：{it.get('confidence','')}）")
    if not rows:
        return None
    # 版本区间同时写进一段"一句话结论"，让 conclusion 直接可读（此前只在段落里）
    return (f"## 受影响版本（来自受影响资产定位）\n" + "\n".join(rows) +
            f"\n依据：GET /api/assets?id={cid}（NVD CPE / CPE 字典 / 语义三路提取），"
            "本系统只生成测绘语法、不主动扫描。\n\n")


def _fetch_detail(cid: str, timeout=15) -> Dict:
    try:
        url = f"{MAIN_SERVER}/api/detail?id=" + urllib.parse.quote(cid)
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:  # noqa: BLE001
        return {}


def latest_high_risk_docs(limit: int = 5, scan: int = 12, timeout: int = 15) -> List[Dict]:
    """取知识库中**最高危**的若干条情报，作为「泛指修复意图」的证据池。

    ★ 2026-10-08 实测补 —— 修复意图的**代词指代兜底**：
      问「这些漏洞应该怎么修复？给出修复建议。」时，「这些」是代词指代，
      句子里**没有任何实体**（无 CVE、无产品名）。规则式改写把询问角度词剔净后
      只剩 `这些漏洞应 给出` 这种零信息残渣 → 检索命中被相关度闸门全部拒掉 →
      用户拿到「知识库中没有与该问题匹配的情报」，而 `/api/remediation`
      能力其实完全可用（实测该接口对具体 CVE 能产出升级版本/受影响区间）。

      指代在**没有上文**时的自然含义就是「当前值得关注的高危情报」，
      故这里用 `cvss>=9` 结构化算子取一批高价值条目作证据池，
      再交给 `fix_section` 渲染可操作处置（补丁链接 / 版本区间 / 厂商公告）。

    只在「有修复意图 + 无实体 + 常规检索零命中」时兜底，不干扰正常检索路径。
    """
    try:
        url = (MAIN_SERVER + "/api/search?%s"
               % urllib.parse.urlencode({"q": "cvss>=9", "n": scan}))
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        rows = [x for x in (d.get("results") or d.get("items") or [])
                if isinstance(x, dict) and x.get("id")][:scan]
    except Exception:  # noqa: BLE001
        return []
    if not rows:
        return []
    # ★ 优先保留**挂接了补丁 / 受影响版本区间**的条目：只有它们能产出
    #   「升级到哪个版本」这种最刚需的处置动作。
    #   实测：按 CVSS 取前 5 条，补丁覆盖率为 **0**（全是 NVD 裸记录），
    #   前 12 条里才有 3 条带 patch_links —— 不做这一步，修复建议段只会
    #   退化成「资料里未挂接补丁信息」的空话，等于兜底白做。
    preferred, rest = [], []
    for r in rows:
        det = _fetch_detail(str(r.get("id")), timeout=timeout)
        if det.get("patch_links") or det.get("cpe"):
            preferred.append(r)
        else:
            rest.append(r)
    if not preferred:
        return rows[:limit]
    return (preferred + rest)[:limit]


# ★ 第 5 轮实测补（2026-10-07）—— **修复建议专属段落**
#   实测「CVE-2026-7482 的修复建议」拿到的是**通用情报汇总**
#   （"命中 8 条 / 风险分布 / CVSS 前三"），**完全没有"怎么修"的内容**；
#   而 `/api/detail?id=CVE-2026-7482` 里 **`patch_links` 有 3 条**
#   （含 `releases/tag/v0.17.1`）、`refs` 带 `PATCH` 标签、`cpe` 带
#   `end_excl: 0.17.1` —— **数据完全够，只是没有渲染通道**。
#   修复建议是用户点名的三类能力之一，却只靠 content_answer 的泛化要点兜，
#   对"具体升级到哪个版本"这种最刚需的问题答不出来。本段补上。
_FIX_Q_RE = re.compile(r"修复|补丁|处置|缓解|加固|升级|怎么修|如何修|怎么处置|防范|防御|"
                       r"fix|patch|remediat|mitigat|upgrade", re.I)


def _ver_from_links(links: List[str]) -> List[str]:
    """从补丁/发布链接里抽版本号（如 releases/tag/v0.17.1 → 0.17.1）。

    ★ compare 链接必须取**右侧**：`/compare/v0.1.33...v0.1.34` 的左侧是受影响版本、
      右侧才是修复版本。早先走兜底正则取"首个 vX.Y.Z" → 报出"升级到 v0.1.33"，
      与同一段里的"受影响区间 <0.1.34"直接自相矛盾（0.1.33 落在受影响区间内）。
      安全建议写错等于让用户升级到仍有漏洞的版本，故单列规则处理。
    """
    out: List[str] = []
    for u in links or []:
        if not isinstance(u, str):
            continue
        # ① compare：取右侧（修复版本）
        mc = re.search(r"compare/v?(\d+\.\d+(?:\.\d+)?)\.{2,}v?(\d+\.\d+(?:\.\d+)?)",
                       u, re.I)
        if mc and mc.group(2) not in out:
            out.append(mc.group(2))
            continue
        # ② tag/release
        m = re.search(r"(?:tag|releases?)/v?(\d+\.\d+(?:\.\d+)?)", u, re.I)
        if m and m.group(1) not in out:
            out.append(m.group(1))
            continue
        # ③ 兜底：裸版本号
        m2 = re.search(r"v(\d+\.\d+\.\d+)", u)
        if m2 and m2.group(1) not in out:
            out.append(m2.group(1))
    return out


def fix_section(question: str, docs: List[Dict]) -> Optional[str]:
    """修复建议：从补丁链接 / 受影响版本区间推出**可操作处置**并给出依据。

    设计原则同其他段：**只搬运资料里真实存在的处置依据**（补丁链接、版本区间），
    不编造"CVE 通常建议…"这类无来源说法；一条都没有时如实说明并给替代路径。
    """
    if not _FIX_Q_RE.search(question or ""):
        return None
    if not docs:
        return None

    # 逐个候选（最多 3 条 CVE/仓库条目）回访详情，取补丁与版本信息
    rows: List[str] = []
    seen_ids = set()
    for d in docs[:6]:
        did = str(d.get("id") or "")
        if not did or did in seen_ids:
            continue
        seen_ids.add(did)
        # 先看检索证据里有没有（避免无谓 HTTP）；没有再回访 detail
        detail = d if (d.get("patch_links") or d.get("cpe")) else _fetch_detail(did)
        patch = list(detail.get("patch_links") or [])
        advisory = list(detail.get("advisory_links") or [])
        cpe = detail.get("cpe") or []
        # 受影响版本：优先 cpe 的 end_excl，其次 assets 接口
        vers: List[str] = []
        cpe_fixed: List[str] = []
        for c in cpe:
            if isinstance(c, dict):
                ee = c.get("end_excl") or c.get("end_incl")
                prod = c.get("product") or c.get("vendor") or ""
                if ee:
                    op = "<" if c.get("end_excl") else "≤"
                    vers.append(f"{prod} {op}{ee}".strip())
                    # end_excl=X 表示「受影响止于 X」，即 X 就是第一个修复版本；
                    # end_incl=X 表示 X 仍受影响，修复版本未知，不能用。
                    if c.get("end_excl") and str(ee) not in cpe_fixed:
                        cpe_fixed.append(str(ee))
        # 修复版本：CPE 的 end_excl 是结构化真值，比从链接里猜可靠得多
        # （compare 链接曾把受影响版本取成修复版本），故 CPE 优先、链接兜底
        fixed = cpe_fixed or _ver_from_links(patch) or _ver_from_links(advisory)
        fixed_src = ("上游 CPE 版本区间（end_excl）" if cpe_fixed
                     else "发布/补丁链接")
        if not patch and not vers:
            continue
        # 组装这一条的处置行（只写有依据的部分）
        bits = [f"**[{did}]**"]
        if fixed:
            bits.append(f"  升级到 / 修复版本：**{('、'.join('v' + v for v in fixed))}**"
                        f"（依据：{fixed_src}）")
        if vers:
            bits.append(f"  受影响区间：{'、'.join(sorted(set(vers))[:4])}"
                        f"（依据：上游 CPE/版本区间，命中≠受影响，需核对版本）")
        if patch:
            bits.append(f"  补丁：{patch[0]}" + (f"（共 {len(patch)} 条）" if len(patch) > 1 else ""))
        if advisory:
            bits.append(f"  厂商公告：{advisory[0]}")
        if len(bits) == 1:
            continue
        rows.append("\n".join(bits))
        if len(rows) >= 4:
            break

    if not rows:
        ids = "、".join("[%s]" % (d.get("id") or "?") for d in docs[:3])
        return ("## 修复建议\n"
                "命中的资料里**未挂接补丁/修复版本信息**（多为资讯/博客类条目）。\n"
                "建议：用 **CVE 编号**直接提问（如 `CVE-2024-1234 的修复建议`），"
                "或点开「原始详细资料」查看厂商公告。\n"
                f"参考条目：{ids}\n"
                "_依据：对命中资料的补丁链接/受影响区间字段做抽取，未作生成式推断。_\n\n")

    return ("## 修复建议（可操作处置）\n" +
            "\n".join(rows) +
            "\n_依据：逐条回访详情接口抽取补丁链接与版本区间，全部可复核；"
            "本项目不代替厂商公告，务必以官方修复版本为准。_\n\n")


def paper_section(question: str, docs: List[Dict]) -> Optional[str]:
    """论文关联：渲染证据的 papers 字段；检索结果不含 papers 时回访 /api/detail 补齐。"""
    if not _PAPER_RE.search(question):
        return None
    seen = set()
    rows = []
    pool = list(docs[:3])
    for d in pool:
        papers = d.get("papers")
        if papers is None and d.get("id"):
            papers = _fetch_detail(d["id"]).get("papers") or []
        for p in (papers or []):
            t = p.get("title", "")
            if t and t not in seen:
                seen.add(t)
                rows.append(f"- [{t}]({p.get('url','')})（{p.get('published','')}，关联自 {d.get('id')}）")
    if not rows:
        return ("## 关联研究论文\n当前证据条目没有挂接论文"
                "（论文关联按特征词共现计算，覆盖率有限，见 `缺口补齐对照表.md` 口径说明）。\n\n")
    return "## 关联研究论文\n" + "\n".join(rows[:6]) + "\n\n"


def deep_sections(question: str, docs: List[Dict]) -> str:
    """汇总所有命中的深度推理段落（顺序：极值 → 统计 → **攻击链** → **修复建议** → 版本 → 论文）。"""
    parts = []
    for fn in (extreme_section, stats_section, attack_section,
               fix_section, version_section, paper_section):
        try:
            sec = fn(question, docs)
        except Exception:  # noqa: BLE001
            sec = None
        if sec:
            parts.append(sec)
    return "".join(parts)
