# -*- coding: utf-8 -*-
"""
multi_hop.py — LLM驱动的多跳推理（Agentic RAG）
Planner-Executor架构：
1. Planner（大模型）分析问题，拆成需要检索的子查询
2. Executor分别检索每个子查询，收集结果
3. 大模型判断结果够不够，不够再补检索
4. 最后把所有结果给generator生成答案
"""
import os
import re
import sys
import json
import time
import collections
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qa.config import LLM_CONFIG, LLM_TIMEOUT, LLM_MAX_RETRIES
from qa.config import MULTI_HOP_MAX_HOPS, MULTI_HOP_FOCUS_PER_HOP, QA_BUDGET
from qa.retriever import retrieve
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

POOL_TOP_K = 12        # 每个子查询的召回量（给多样性与条件过滤留足空间）
FINAL_K = 8            # 最终返回给生成器的条数
POOL_TOP_HOP = 8       # 迭代深化跳的召回量（比首跳小：目的只是找"新实体"）

# ── 迭代多跳：上一跳的检索式由上一跳的结果派生（2026-10-06 补）───────────
# 为什么以前不算"多跳"：planner 拆出的多个子查询**全部由原始问题派生**，
# 下一跳既不看上一跳的 title，也不看它的 products/cwe —— 那是 fan-out/fan-in，
# 不是多跳。真正的多跳必须是：
#     第1跳 问题 → 命中漏洞 CVE-x（products=[ollama]）
#     第2跳 派生出「ollama + 在野利用」→ 召回同产品的在野利用漏洞
#     第3跳 派生出「第2跳新出现的 CWE 名 + 属性」→ 召回同类弱点
# 每一步的「派生依据」都记进 chain，答案里带 reasoning_chain，可解释。
LAST_CHAIN: Dict = {}          # 最近一次多跳的推理链（前端 /api/chat 直接回传）


def _norm_ent(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())


# 疑问句式与条件修饰语：这些词不该参与 BM25 打分（条件由结构化算子负责更准）
#
# ★ 第 5 轮实测补（2026-10-07）：原表有 `有哪些|有什么` 但**没有 `是什么`** ——
#   实测 `CVE-2025-15063 的攻击链是什么` 改写成 `CVE-2025-15063 攻击链 什么`，
#   句尾 `什么` 残留并被当成检索词。
# ★ 更关键的是**"询问角度词"污染**（本次串扰的根因）：
#   用户给了明确的 CVE 编号（最强锚点），而 `攻击链`/`修复建议`/`影响范围`
#   是"要回答什么方面"，应由 deep_answer 的对应段落处理，**不该进检索式**
#   —— 检索式带 `攻击链` 后，BM25 把标题含"攻击链"的博客顶上首位，
#   而那篇博客讲的是**另一个 CVE**，导致结论写出一堆无关编号（实测见下）。
_ASK_RE = re.compile(
    r"有哪些|有什么|是什么|什么样的|怎么样|啥|"
    r"有没有|是不是|如何|怎么|为什么|哪些|哪个|多少|几种|"
    r"请问|帮忙|帮我|查一下|看一下|介绍一下|情况如何|"
    r"的攻击链|的利用链|的攻击路径|的攻击过程|的利用过程|的攻击步骤|的利用步骤|"
    r"的修复建议|的修复方案|的处置建议|的处置方案|的缓解措施|的加固建议|"
    r"的影响范围|的影响面|的受影响版本|受影响版本|版本区间|"
    r"的攻击方式|的攻击手法|的利用方式|怎么被利用|如何被利用|"
    r"攻击链|利用链|攻击路径|攻击过程|利用过程|攻击步骤|利用步骤|"
    r"修复建议|修复方案|处置建议|处置方案|缓解措施|加固建议|"
    r"影响范围|影响面|受影响版本|受影响组件|受影响资产")
# ★ 时间/排序类修饰词（第 3 轮实测补）：
#   这类词是**排序意图**（要最新的在前），不是内容词 —— 既不该参与 BM25 打分
#   （"最近"匹配不到任何漏洞标题，纯噪声），也不该留在改写后的检索式里。
#   实测反例：`最近被在野利用的漏洞` 因为「在野利用」被 _COND_MOD_RE 删掉、
#   「被」被 _RESIDUE_RE 删掉、「最近」无人处理 → 改写成 `最近被 的漏洞` 这个
#   **无意义碎片**，检索回 2 篇中文博客当"漏洞"给了用户（严重误导）。
#   排序由引擎的 sort 参数承担（见 _structured_terms），这里只负责不让它污染检索式。
_RECENCY_RE = re.compile(
    r"最近|最新|近期|近期内|近来|当前|目前|最新版|全新的|最新的|"
    r"(?<![A-Za-z0-9])(?:latest|recent|newest|newly)(?![A-Za-z0-9])", re.I)
# 注意：不能用 \b 界定英文词 —— 中英混排时「有POC」的 P 前面是中文（属 \w），
# \bpoc\b 匹配不到。用前后瞻（?<!alnum)/(?!alnum）才正确。
_COND_MOD_RE = re.compile(
    r"高危|严重|危急|中危|低危|"
    r"已被利用|已被攻击|已被攻破|在野利用|已遭利用|被利用|已被|被攻击|被攻破|"
    r"(?:已)?公开(?:的)?\s*(?:利用代码|利用方式|exploit)|"
    r"利用代码|利用方式|"
    r"(?<![A-Za-z0-9])(?:poc|exp|exploit\s*code|critical|high\s*severity|"
    r"zero[-\s]?day|0day)(?![A-Za-z0-9])", re.I)
# 改写后的残留：孤立虚词（前后必须是空格/边界才删，避免误伤正常词）与语气尾词
#
# ★ 第 3 轮实测扩充：`被` 原先只在"前后都是空格"时删，但 `最近被 的漏洞`
#   里的 `被` 紧跟在中文后面（`近被`），\s 边界不成立 → 删不掉，碎片留下。
#   现在把 `被/已/把/将/其/该/存在` 等**纯语法词**改成"任意位置都可删"
#   （它们本身没有检索价值，留在检索式里只会给 BM25 添噪声）。
# ★ 第 5 轮实测再补：`影响`/`版本`/`组件` 这类**询问角度词**（"影响哪些版本"
#   被 `_ASK_RE` 拆掉后剩下的"影响""版本"）也不该进检索式 ——
#   它们是"要答什么方面"，由 deep_answer 的 `version_section` 负责，
#   留在检索式里只会把泛化条目（"版本更新说明"等）勾进来。
_RESIDUE_RE = re.compile(
    r"(?:且|并|已|被|有|是|的|了|吗|呢|把|将|和|与|或|其|该|存在|这个|那个|"
    r"影响|版本|组件|资产|范围|哪些|哪个|怎么|如何|什么|啥|处置|修复|缓解|加固|防范|防御|修|方法|措施|方案|"
    r"(?<![A-Za-z0-9])the(?![A-Za-z0-9]))")
# 连词+助动词连写（"且有POC" 删掉 POC 后残留的 "且有"）
_CONJ_AUX_RE = re.compile(r"(?:且|并|又|还|以及|并且)\s*(?:有|被|已|是)\s*(?=\s|$)")
_TAILWORD_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:可用|怎么用|有用|相关|方面)(?![A-Za-z0-9])|"
    r"(?:^|\s)(?:可用|怎么用)(?=\s|$)")
# 改写后可能拼出的"假实词"：看着像词、其实零信息量（_core_query 退化保护的判据）
_FAKE_TERMS = {"最近", "最近被", "存在", "这", "那", "什么", "哪些", "怎么", "如何"}


def _core_query(question: str, focus: List[str] = None, keep: List[str] = None) -> str:
    """从自然语言问题里抽出「核心检索式」：主实体 + 去掉条件修饰后的名词。

    为什么必须有这一步（实测踩过的坑）：
      把整句原样丢给检索引擎，条件词会**参与 BM25 打分**，把召回彻底带偏 ——
      问「Ollama 有哪些高危且已被在野利用的漏洞？」，原样检索 top12 里
      **0 条是 Ollama**，全是 Drupal / SFOS / ConnectWise —— 全被"漏洞/高危"
      这类泛化词勾走了。而这些条件本来就有更精确的落点：结构化算子
      （`kev:yes cvss>=7`，见 _structured_terms），不需要靠关键词打分。

    改写后首跳检索式变成「ollama 漏洞」，条件仍由 cond_q 精确约束。
    """
    q = _COND_MOD_RE.sub(" ", str(question or ""))
    q = _RECENCY_RE.sub(" ", q)   # 时间/排序词：交给 sort 算子，不进检索式（避免"最近被 的漏洞"碎片）
    q = _ASK_RE.sub(" ", q)
    if keep:
        # 去重追加：base 里可能已经含过这些词（AI 框架扩展先加进 base），
        # 不去重会出现 "vllm ollama … vllm ollama …" 每个词重复两遍，
        # 白白拉长检索式又给 BM25 重复计分。
        _have = set(re.findall(r"[a-z0-9_]+", q.lower()))
        _extra = [k for k in keep if str(k).lower() not in _have]
        if _extra:
            q += " " + " ".join(_extra)
    q = _TAILWORD_RE.sub(" ", q)
    q = re.sub(r"[，,。、？?！!；;：:]+", " ", q)
    # 删孤立虚词产生的连带空洞（最多两轮，第二轮清掉首轮暴露出的新孤立词）
    for _ in range(2):
        q2 = _RESIDUE_RE.sub(" ", q)
        q2 = _CONJ_AUX_RE.sub(" ", q2)
        if q2 == q:
            break
        q = q2
    q = re.sub(r"\s+", " ", q).strip(" ，,、")
    if not q:
        return ""
    # ★ 退化保护（第 3 轮实测补）：改写可能把整句削成无意义碎片 ——
    #   实测 `最近被在野利用的漏洞` 改写成 `最近被 的漏洞`，检索回 2 篇
    #   中文博客冒充"漏洞"。判据：去空格后若只剩**纯语法残渣**
    #   （长度 < 4 且不含任何 ≥2 字的实义汉字串 / 拉丁词），宁可返回空，
    #   让上游用原问题检索（原问题至少有完整语义）。
    _meaningful = re.findall(r"[A-Za-z0-9]{2,}|[\u4e00-\u9fff]{2,}", q)
    # 剔除纯虚词组成的"假实词"（"最近被""存在"这类拼不出来但没信息量的）
    _meaningful = [m for m in _meaningful if m.lower() not in _FAKE_TERMS]
    if not _meaningful:
        return ""
    # 太短（只剩主实体）反而召回太宽，补一个领域词
    # （去重：`最近被在野利用的漏洞` 削完后只剩"漏洞"，再补一次会变成"漏洞 漏洞"）
    if len(q) < 4 and "漏洞" not in q:
        q = (q + " 漏洞").strip()
    return q


def _hop_entities(docs: List[Dict], exclude: set, limit: int) -> List[str]:
    """从上一跳命中文档里抽「新实体」（受影响产品 / 厂商），排除题面里已有的。

    exclude 传题面与历次跳已出现的词，避免第2跳把第1跳的原词再查一遍
    （那不叫深化，叫重复）。
    """
    out: List[str] = []
    seen = set(exclude)
    for d in docs or []:
        for field in ("products", "vendors"):
            for p in (d.get(field) or []):
                if isinstance(p, dict):
                    p = p.get("name") or p.get("product") or ""
                name = _norm_ent(p)
                if not name or len(name) < 2 or len(name) > 40:
                    continue
                if name in seen:
                    continue
                seen.add(name)
                out.append(name)
                if len(out) >= limit:
                    return out
    return out


def _hop_cwe_terms(docs: List[Dict], limit: int) -> List[str]:
    """从命中结果里取 CWE 弱点名 —— 第3跳用它在"同类弱点"维度上继续挖。"""
    out: List[str] = []
    seen = set()
    for d in docs or []:
        for c in (d.get("cwe") or []):
            nm = _norm_ent(c.get("name")) if isinstance(c, dict) else _norm_ent(c)
            if not nm or len(nm) < 4 or nm in seen:
                continue
            seen.add(nm)
            out.append(nm)
            if len(out) >= limit:
                return out
    return out


def _aspect_terms(intent: Dict[str, bool]) -> List[str]:
    """按问题里解析出的条件挑"属性词"，让派生查询带上同样的约束。"""
    t: List[str] = []
    if intent.get("kev"):
        t += ["在野利用", "exploited"]
    if intent.get("poc"):
        t += ["poc", "利用代码"]
    if intent.get("high_sev") or intent.get("rce"):
        t += ["高危", "严重"]
    if intent.get("paper"):
        t += ["论文", "研究"]
    if not t:
        t = ["漏洞", "cve"]
    return t[:3]


def _iterative_expand(base_q: str, pool: List[Dict], seen_ids: set,
                      intent: Dict[str, bool], chain: List[Dict],
                      budget_ms: int = 0, anchor_fn=None) -> List[Dict]:
    """迭代深化：每一跳的检索式都由**上一跳的结果**派生，最多 MULTI_HOP_MAX_HOPS 跳。

    anchor_fn（可调用，传入「该文档是否命中题面主实体」的判定）：
      第1跳召回里混着大量与题面无关的条目 —— 问「Ollama 的漏洞」也会召回
      Debian Linux / Drupal 的条目。若直接从 pool 抽派生实体，第2跳就会跳到
      `debian_linux 在野利用` 这种完全跑偏的查询（实测踩过）。
      所以：**只有命中主实体的条目才有资格贡献派生实体**；一条都不命中就不派生。

    三条不变量（避免"为了多跳而多跳"，把检索搞慢又跑偏）：
      ① 派生不出新实体就停（没有新信息可挖）；
      ② 本跳一条新文档都没召回就停（这条路走不通）；
      ③ 超过端到端预算就停（宁可少一跳，不可让用户等）。
    """
    t0 = time.time()
    used_q = {_norm_ent(base_q)}
    for h in chain:
        used_q.add(_norm_ent(h.get("query")))
    frontier = list(pool)
    aspects = _aspect_terms(intent)

    def _anchored(docs: List[Dict]) -> List[Dict]:
        """只保留命中题面主实体的条目作为"派生实体来源"。"""
        if not anchor_fn:
            return docs
        out = [d for d in docs if anchor_fn(d)]
        return out if out else []

    for step in range(2, MULTI_HOP_MAX_HOPS + 1):
        if budget_ms and (time.time() - t0) * 1000 > budget_ms:
            chain.append({"hop": step, "skipped": "budget",
                          "basis": "已达端到端预算，停止继续深化",
                          "ms": 0})
            break
        src = _anchored(frontier)
        if step == 2:
            ents = _hop_entities(src, set(used_q), MULTI_HOP_FOCUS_PER_HOP)
            basis = "由第1跳命中【题面主实体】的条目的受影响产品/厂商派生"
        else:
            ents = _hop_cwe_terms(src, MULTI_HOP_FOCUS_PER_HOP)
            basis = "由上一跳新命中条目的 CWE 弱点名派生（同类弱点横向关联）"
        if not ents:
            chain.append({"hop": step, "skipped": "no_entity",
                          "basis": ("上一跳没有命中题面主实体的条目，无可派生的新实体，"
                                    "停止深化（避免跑偏到无关产品）"), "ms": 0})
            break

        q = _norm_ent(" ".join(ents) + " " + " ".join(aspects))
        if q in used_q:
            break
        used_q.add(q)

        _t1 = time.time()
        got = retrieve(q, top_k=POOL_TOP_HOP) or []
        fresh: List[Dict] = []
        for r in got:
            rid = r.get("id")
            if rid not in seen_ids:
                r["_tag"] = "hop%d" % step
                pool.append(r)
                seen_ids.add(rid)
                fresh.append(r)
        chain.append({
            "hop": step, "query": q, "basis": basis,
            "derived_entities": ents,
            "hits": len(got), "new_docs": len(fresh),
            "ms": int((time.time() - _t1) * 1000),
        })
        if not fresh:
            break
        frontier = fresh
    return pool

# ── 自然语言 → 结构化检索式（无 LLM 时也能做「条件理解」）────────────────
_RCE_RE = re.compile(r"remote code execution|\brce\b|代码执行|命令执行|远程执行", re.I)


def parse_intent(question: str) -> Dict[str, bool]:
    """从问题文本抽取可执行的结构化条件（在野利用 / POC / 论文 / 高危 / RCE 等）。"""
    return {
        "kev": bool(re.search(r"在野利用|已被利用|已遭利用|被利用|kev|exploited", question, re.I)),
        "poc": bool(re.search(r"poc|exp\b|利用代码|漏洞利用|公开.*利用|exploit code", question, re.I)),
        "paper": bool(re.search(r"论文|学术|paper|研究", question, re.I)),
        "vuln": bool(re.search(r"漏洞|cve|vulnerab|影响", question, re.I)),
        "atlas": bool(re.search(r"atlas|威胁框架", question, re.I)),
        "high_sev": bool(re.search(r"高危|critical|严重|危急|high severity", question, re.I)),
        "rce": bool(_RCE_RE.search(question)),
    }


def _structured_terms(intent: Dict[str, bool]) -> List[str]:
    terms = []
    if intent.get("kev"):
        terms.append("kev:yes")
    if intent.get("poc"):
        terms.append("poc:yes")
    if intent.get("paper"):
        terms.append("type:paper")
    if intent.get("high_sev"):
        terms.append("cvss>=7")
    return terms


# 具体实体（产品 / 组件 / 概念）关键词：用于区分「实体聚焦」与「纯条件过滤」两类问题。
# 实体聚焦问题（"Ollama 有哪些高危漏洞"）主召回要保住实体，条件算子只能作软排序；
# 纯条件过滤问题（"已被在野利用且有公开 POC 的 RCE 漏洞有哪些"）则必须用条件算子硬过滤。
_ENTITY_KW = [
    "ollama", "vllm", "triton", "log4j", "kubernetes", "k8s", "apache",
    "jupyter", "gradio", "prompt injection", "提示词注入", "prompt inject",
    "deserialization", "反序列化", "cwe", "supply chain", "供应链", "投毒",
    "container escape", "容器逃逸", "atlas", "智能体", "agent",
]


# 通用「产品/组件名」抽取时要排除的词：这些是漏洞领域的通用条件词，不是实体。
# 少了这张表，"CVSS 10 分的漏洞" 里的 cvss、"有 POC 的漏洞" 里的 poc 会被当成产品名。
_ENTITY_STOP = {
    "cve", "cvss", "cwe", "kev", "poc", "pocs", "exp", "exploit", "exploits", "rce",
    "vuln", "vulns", "vulnerability", "vulnerabilities", "cveid", "cveid",
    "high", "critical", "severity", "low", "medium", "score", "level",
    "remote", "code", "execution", "injection", "inject", "bypass", "xss",
    "list", "what", "which", "how", "the", "and", "for", "with", "from", "that",
    "latest", "new", "known", "issue", "issues", "problem", "problems", "risk",
    "type", "sort", "year", "product", "vendor", "severitycritical", "yes",
    "framework", "框架", "组件", "漏洞", "问题", "影响",
}


def _ascii_entities(question: str) -> List[str]:
    """从问题里抽取可能是产品/组件名的 ASCII 词（LangChain / Milvus / Ray …）。

    原先实体只认 `_ENTITY_KW` 硬编码表，导致「LangChain 的提示词注入问题」这类
    题被判成"纯条件题"，排序时把无关的高分条目顶上来。这里补一层通用抽取：
    长度 ≥3、非领域停用词、且不是纯数字的 ASCII 词都当作候选实体。
    """
    out: List[str] = []
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9._\-]{2,}", question):
        low = tok.lower()
        if low in _ENTITY_STOP or low.isdigit():
            continue
        if low not in out:
            out.append(low)
    return out


def _entity_focus(question: str) -> List[str]:
    ql = question.lower()
    focus = [kw for kw in _ENTITY_KW if kw in ql]
    for e in _ascii_entities(question):
        if e not in focus and len(focus) < 6:  # 上限防止长句塞进一堆噪声实体
            focus.append(e)
    return focus


def _hits_focus(doc: Dict, focus: List[str]) -> bool:
    blob = " ".join(str(x).lower() for x in (
        doc.get("title"), doc.get("snippet"), doc.get("why"),
        " ".join(map(str, doc.get("products") or [])),
        " ".join(map(str, doc.get("vendors") or [])),
    ))
    return any(kw in blob for kw in focus)


def _match_intent(doc: Dict, intent: Dict[str, bool]) -> bool:
    """文档是否满足问题里的硬性条件（用检索结果自带字段判定，命中条件才校验）。

    注意：/api/search 返回的条目不带 ``kev``/``poc_links`` 原始字段，而是引擎
    展平后的 ``exploited`` / ``poc_count``，故此处按展平字段判定。
    """
    if intent.get("kev") and not doc.get("exploited"):
        return False
    if intent.get("poc") and not (doc.get("poc_count") or doc.get("poc_links")):
        return False
    if intent.get("high_sev"):
        s = (doc.get("cvss") or {}).get("score")
        if not isinstance(s, (int, float)) or s < 7.0:
            return False
    if intent.get("rce"):
        blob = str(doc.get("title") or "") + " " + str(doc.get("snippet") or "") \
            + " " + str(doc.get("why") or "")
        if not _RCE_RE.search(blob):
            return False
    return True


def _cond_rank(doc: Dict, intent: Dict[str, bool]) -> int:
    """软排序键：满足的条件越多越靠前（不做硬过滤，避免误删）。"""
    n = 0
    if intent.get("kev") and doc.get("exploited"):
        n += 1
    if intent.get("poc") and (doc.get("poc_count") or doc.get("poc_links")):
        n += 1
    if intent.get("high_sev") and isinstance((doc.get("cvss") or {}).get("score"), (int, float)) \
            and (doc.get("cvss") or {}).get("score") >= 7.0:
        n += 1
    return n


def _doc_type(doc: Dict) -> str:
    """按 ID 前缀判定来源类型（用于来源多样性重排）。"""
    s = str(doc.get("id") or "")
    if s.startswith("CVE-"):
        return "漏洞库"
    if s.startswith("GHSA-"):
        return "开源公告"
    if s.startswith("ARXIV:") or s.startswith("PAPER:"):
        return "学术论文"
    if s.startswith("LIVE:BLOG") or s.startswith("BLOG:"):
        return "安全博客"
    if s.startswith("HF:") or s.startswith("MODEL:"):
        return "HuggingFace"
    if s.startswith("GH:") or s.startswith("REPO:"):
        return "GitHub仓库"
    if s.startswith("CSDN") or s.startswith("XZ") or s.startswith("AQK") or s.startswith("CN:"):
        return "中文社区"
    if s.startswith("AML."):
        return "MITRE ATLAS"
    return "其他"


def diversity_rerank(docs: List[Dict], k: int = FINAL_K, min_types: int = 1) -> List[Dict]:
    """来源多样性重排。

    - ``min_types == 1``：保持排序后的原顺序（不强制多样，避免给纯实体题硬塞无关来源）。
    - ``min_types >= 2``：先保证至少 ``min_types`` 个不同来源类型各占一席，再按原顺序补齐。
    """
    if min_types <= 1 or len(docs) <= 1:
        return docs[:k]

    chosen: List[Dict] = []
    cnt: Dict[str, int] = collections.Counter()
    used = set()
    # 第一轮：每个来源类型各取排序最靠前的一条，直到凑够 min_types 个类型
    for d in docs:
        t = _doc_type(d)
        if cnt[t] == 0:
            chosen.append(d)
            cnt[t] += 1
            used.add(id(d))
            if len(cnt) >= min_types:
                break
    # 之后：按原顺序补齐
    for d in docs:
        if len(chosen) >= k:
            break
        if id(d) not in used:
            chosen.append(d)
            used.add(id(d))
    return chosen[:k]


def _llm_call(messages: list, cfg: dict = None) -> str:
    """调LLM，返回文本。cfg 为前端传入的 LLM 配置（优先），否则用 config.py 默认值"""
    conf = {**LLM_CONFIG}
    if cfg:
        conf.update({k: v for k, v in cfg.items() if v})
    if not conf.get("api_key"):
        return ""
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=conf["base_url"],
            api_key=conf["api_key"],
            # max_retries 是客户端构造参数；传给 create() 会抛
            # unexpected keyword argument（openai 3.x 实测）
            max_retries=LLM_MAX_RETRIES,
        )
        resp = client.chat.completions.create(
            model=conf["model"],
            messages=messages,
            temperature=0.2,
            max_tokens=500,
            # 2026-10-06：此前无超时，上游挂住会占死线程（页面一直转圈）。
            # Planner 是可降级环节，超时直接回退规则拆解，不影响出答案。
            timeout=conf.get("timeout") or LLM_TIMEOUT,
        )
        return resp.choices[0].message.content
    except Exception as e:
        print(f"[MultiHop] LLM调用失败（{LLM_TIMEOUT}s 超时或异常）: {e}")
        return ""


# 复合问题的切分连接词与噪声词（无 LLM 时的规则式 Planner 用）
_CONN_RE = re.compile(r"^(其中|并且|以及|还有|同时|另外|另外还有|而且|且|然后)")
_NOISE_RE = re.compile(r"(有哪些|有什么|哪几种|哪几个|哪些|哪个)")


def _rule_plan_queries(question: str, focus: List[str]) -> List[str]:
    """无 LLM 时的规则式 Planner：拆复合问题，并给每个片段补回主实体。

    为什么必须有这一步（实测复现的缺陷）：无 Key 时 Planner 原样返回整个问题，
    BM25 会把「Ollama 有哪些高危漏洞？其中哪些已被在野利用？」里高频的条件词
    「在野利用」当作主信号，召回一堆 CVSS 10.0 的通用 KEV 条目（实测首条
    Pulse Connect Secure、次条 Kaseya VSA），与题面实体 Ollama 毫无关系。

    做法：按标点切分片段 → 去掉「其中/并且」这类连接词 → 片段里没有主实体的
    就把实体补回去（"其中哪些已被在野利用" → "ollama 已被在野利用"），
    保证每个子查询都锚定在题面实体上。
    """
    if not focus:
        return []
    main = focus[0]
    out: List[str] = []
    for raw in re.split(r"[？?！!；;。]", question):
        frag = _CONN_RE.sub("", raw.strip()).strip()
        if not frag:
            continue
        if main not in frag.lower():
            frag = f"{main} {_NOISE_RE.sub('', frag)}"
        frag = re.sub(r"\s+", " ", frag).strip(" ，,、")
        if len(frag) >= 2 and frag not in out:
            out.append(frag)
    return out[:3]


def plan_queries(question: str, cfg: dict = None) -> List[str]:
    """
    Planner：让大模型把复杂问题拆成几个检索子查询
    返回子查询列表
    """
    prompt = f"""你是安全情报检索规划专家。用户提了一个问题，请你把它拆成1-3个简单的检索查询，用来从漏洞库里找相关信息。

要求：
1. 只输出JSON数组，不要解释
2. 每个子查询是一个简单的搜索关键词，不要长句子
3. 如果问题很简单，就返回原问题就行
4. 如果是复合问题（比如带时间、严重等级、POC条件），拆成对应的关键词组合

示例：
用户问题："2024年Q1影响Ollama的高危且有POC的漏洞"
输出：["Ollama 2024", "Ollama high severity", "Ollama PoC"]

用户问题："{question}"
输出JSON数组："""

    result = _llm_call([{"role": "user", "content": prompt}], cfg)

    # 解析JSON
    try:
        # 提取JSON数组部分
        start = result.find("[")
        end = result.rfind("]") + 1
        if start >= 0 and end > start:
            sub_queries = json.loads(result[start:end])
            if isinstance(sub_queries, list) and len(sub_queries) > 0:
                return sub_queries[:3]  # 最多3个子查询
    except Exception as _sw_e:
        _swallow("modules/m3_qa/backend/qa/multi_hop.py:291", _sw_e)

    # 解析失败就用原问题
    return [question]


# 「AI 框架」类目展开用的真实产品名（第 3 轮 R3-2）。
# 放在模块级是因为它有两个消费点：① 查询扩展（base）；② 首跳核心检索式（keep=）
# —— 后者若拿不到同一份名单，扩展词会被 _core_query 当残留词剥掉（实测踩过）。
_FRAMEWORK_NAMES = ["vllm", "ollama", "langchain", "sglang", "ray"]


def _cvss_sort_key(rec: Dict) -> float:
    """CVSS 排序键：合并语料里知识条目（论文/模型/仓库/文章）本就没有 CVSS 分数，
    `cvss.score` 为 None。用 `.get("score", 0)` 取默认值时，键存在但值为 None 会
    原样返回 None，与 float 比较即抛 TypeError，把整条问答打成 500。
    此处统一折算为数值——无分数按 -1 排在最后。"""
    s = (rec.get("cvss") or {}).get("score")
    if isinstance(s, bool) or not isinstance(s, (int, float)):
        return -1.0
    return float(s)


def multi_hop_search(question: str, cfg: dict = None,
                     with_chain: bool = False):
    """
    Agentic RAG 主入口：
    1. Planner 拆子查询（有 LLM 用 LLM，无 LLM 退化为原问题）
    2. 规则式结构化改写：把「在野利用 / POC / 论文 / 高危」等自然语言条件
       翻成引擎的结构化算子（kev:/poc:/type:/cvss>=），无 LLM 也能精确过滤
    3. 每个子查询分别检索、合并去重
    4. 硬性条件过滤（命中才生效）+ CVSS 排序 + 来源多样性重排
    """
    intent = parse_intent(question)
    focus = _entity_focus(question)
    is_entity = bool(focus)

    # 查询扩展：把「AI 框架」这类宽泛说法展开成具体框架名，让关键词检索能命中
    #
    # 第 3 轮实测修正（R3-2）：扩展词原先只加在 base 上，而首跳检索式走的是
    # _core_query(base, focus) —— 它对 base 做"剥条件修饰 + 清孤立虚词"，
    # 扩展进来的产品名会被当成残留词一起剥掉（实测 core_q 仍是「AI 框架存在 的漏洞」），
    # 等于扩展白做。所以扩展词必须**显式 keep** 进核心检索式。
    ai_framework = bool(re.search(r"AI\s*框架|ai framework|AI框架", question, re.I))
    base = question
    if ai_framework:
        base = question + " " + " ".join(_FRAMEWORK_NAMES)

    # 1. Planner 拆子查询（有 LLM 用 LLM；无 LLM 时按规则拆分并补回实体）
    sub_queries = plan_queries(base, cfg)
    if is_entity and len(sub_queries) <= 1:
        # plan_queries 在无 Key / 调用失败时原样返回整个问题；复合问题必须拆开，
        # 否则条件词会盖过实体，召回出一堆与题面无关的高分条目。
        planned = _rule_plan_queries(base, focus)
        if planned:
            sub_queries = planned

    # 1b. 首跳检索式改写：剥掉疑问句式与条件修饰语，只留「主实体 + 核心名词」。
    #     不改写的话条件词会参与 BM25 打分，实测「Ollama 的高危在野利用漏洞」
    #     top12 里 0 条是 Ollama；条件改由 cond_q 的结构化算子精确约束。
    #
    #     改写后还要**丢掉与改写式重复的那一路**：无 LLM 时 plan_queries 会把
    #     整个原句原样返回（等于零信息量），而条件又已由 cond_q 承担 ——
    #     多跑这一路纯粹浪费一次检索（实测每路 1.2~1.4s）。
    #     `is_entity=False` 时（"AI 框架"这类**宽泛类目**不是可识别实体）此前直接跳过
    #     改写，结果原句整句进检索 —— 实测「哪些 AI 框架存在在野利用的漏洞」原句
    #     召回 **0 条**，而改写成「AI 框架存在 的漏洞 vllm ollama langchain sglang ray」
    #     能召回框架条目。所以改写不能捆绑 is_entity，只捆绑"有没有可抽的核心名词"。
    _keep = _FRAMEWORK_NAMES if ai_framework else None
    core_q = _core_query(base, focus, keep=_keep)
    if core_q:
        seen_sq = {_norm_ent(core_q)}
        kept = []
        for q in sub_queries:
            nq = _norm_ent(q)
            if nq in seen_sq or nq == _norm_ent(base):
                continue
            seen_sq.add(nq)
            kept.append(q)
        sub_queries = [core_q] + kept

    # 2. 规则式结构化改写：条件算子（kev:/poc:/cvss>=）与跨来源补充召回（type:）
    cond_q = base + " " + " ".join(_structured_terms(intent)) \
        if _structured_terms(intent) else None
    recall_qs: List[str] = []
    if intent.get("paper") and intent.get("vuln"):
        recall_qs.append(base + " type:漏洞")
    if intent.get("atlas"):
        recall_qs.append("ATLAS type:knowledge")

    if intent.get("atlas"):
        ordered_qs = recall_qs + list(sub_queries)
        n_plain = len(recall_qs)
        n_recall = 0
    else:
        ordered_qs = list(sub_queries) + recall_qs + ([cond_q] if cond_q else [])
        n_plain = len(sub_queries)
        n_recall = len(recall_qs)
    print(f"[MultiHop] 子查询 {len(ordered_qs)} 个: {ordered_qs}", flush=True)

    # 3. Executor：按「主查询 → 补充召回 → 条件算子」顺序检索并打标签
    pool: List[Dict] = []
    seen_ids = set()
    chain: List[Dict] = []
    _t0 = time.time()
    for i, sq in enumerate(ordered_qs):
        tag = "plain" if i < n_plain else ("recall" if i < n_plain + n_recall else "cond")
        got = retrieve(sq, top_k=POOL_TOP_K) or []
        n_new = 0
        for r in got:
            rid = r.get("id")
            if rid not in seen_ids:
                r["_tag"] = tag
                pool.append(r)
                seen_ids.add(rid)
                n_new += 1
        chain.append({
            # 第 1 跳是多路并行检索式（原问题 / 跨来源召回 / 条件算子），
            # 每路都各记一条 —— 所以 hops 里会出现多个 hop:1。
            # sub 标明是第几路（从 1 起）、routes 标明本跳共几路，
            # 否则前端按序号渲染会误以为第 1 跳"出现了两次"。
            "hop": 1, "sub": i + 1, "routes": len(ordered_qs), "query": sq,
            "basis": "用户原问题" if tag == "plain"
                     else ("跨来源补充召回" if tag == "recall" else "结构化条件算子"),
            "hits": len(got), "new_docs": n_new,
            "ms": int((time.time() - _t0) * 1000),
        })

    # 3b. 迭代深化：第2跳起，检索式由上一跳命中的实体派生（真正的多跳，见 _iterative_expand）
    pool = _iterative_expand(
        base, pool, seen_ids, intent, chain,
        budget_ms=int(QA_BUDGET * 1000 * 0.45),
        # 派生实体必须锚定题面主实体，否则会从噪声条目跳到无关产品（实测踩过）
        anchor_fn=(lambda d: _hits_focus(d, focus)) if is_entity else None,
    )

    # 4a. 实体聚焦问题：条件算子的结果必须命中实体，否则丢弃（避免「Ollama 高危」
    #     被非 Ollama 的在野利用条目顶掉）；纯条件过滤问题则用条件算子硬过滤置顶。
    #
    # 第 3 轮实测修正（R3-2）：`cond` 路（kev:yes 这类结构化算子）**不带实体约束**，
    #   是"全库扫 KEV"。当题面有明确领域（AI 框架类目）但 focus 抽不出实体时，
    #   这一路的 12 条会全是 Debian / ColdFusion / Android —— 与题面无关却
    #   因为满足 kev 条件而排在前面。此前只有 `is_entity` 才拦得住，
    #   而"AI 框架"不是可识别实体 → 兜底失效。这里补一条**领域词兜底**：
    #   命中 ORIGO 领域词的 `cond` 条目才留，其余降到后面（不直接删，
    #   避免领域词表不全时把真答案也误杀）。
    if is_entity:
        pool = [d for d in pool if d.get("_tag") != "cond" or _hits_focus(d, focus)]
    elif ai_framework:
        # 复用 _hits_focus（同一套"标题/snippet/产品名/厂商"文本面判定）
        _indomain = lambda d: _hits_focus(d, _FRAMEWORK_NAMES)  # noqa: E731
        if any(_indomain(d) for d in pool if d.get("_tag") == "cond"):
            _in = [d for d in pool if d.get("_tag") != "cond" or _indomain(d)]
            _in_ids = {id(d) for d in _in}
            pool = _in + [d for d in pool if id(d) not in _in_ids]
    elif any(intent.get(k) for k in ("kev", "poc", "high_sev", "rce")):
        strict = [d for d in pool if _match_intent(d, intent)]
        if len(strict) >= 2:
            strict_ids = {id(d) for d in strict}
            pool = strict + [d for d in pool if id(d) not in strict_ids]

    # 4b. 排序：实体命中 → 满足条件数 → CVSS（无分数条目排最后）
    #     实测校准过的三个版本，只有这个版本两头都对：
    #       ① 原版（cond→cvss）："Ollama 高危 + 其中在野利用" 首条是无关的
    #          Pulse Secure / Kaseya（CVSS 10 的条件全中条盖过实体条目）；
    #       ② 纯加分版（cvss+2）：复合题仍被 cond_rank 压住，没修好；
    #       ③ 实体一票优先 + 旧实体表：LangChain 题首条变成无关的 CSDN 文章
    #          （因为旧表认不出 langchain，只有"提示词注入"算命中，而无 CVSS
    #          分的中文文章因此被抬到 CVE 前面，D1 90%→80%）。
    #     现在的做法是"实体优先分组 + 组内仍按条件/CVSS 排"，配合通用产品名抽取，
    #     实体相关条目整体前置，组内顺序不被破坏。
    def _score(d: Dict) -> float:
        return float(_cvss_sort_key(d))

    pool.sort(key=lambda d: (_hits_focus(d, focus) if is_entity else 0,
                             _cond_rank(d, intent), _score(d)),
              reverse=True)

    # 4c. 来源多样性重排：需要跨来源（论文/框架类）时才强制多样
    min_types = 2 if (intent.get("paper") or intent.get("atlas")) else 1
    final = diversity_rerank(pool, k=FINAL_K, min_types=min_types)

    # 4c-2. 相关度闸门（v2.6）：多跳链路同样要判"到底相不相关"。
    #   此前 FINAL_K=8 是**固定条数** —— 库里一条都不相关时也会凑满 8 条，
    #   用户看到"命中 8 条"却全是无关内容（实测：不存在的术语返回 PHP 反射类条目）。
    #   这里对**整个池**判一遍，再取相关条目；相关数不足 FINAL_K 就少给，
    #   一条都不相关就返回空列表，由上层如实输出「知识库中没有匹配情报」。
    #   注意：闸门判据是"任一强信号通过"，所以真命中不会被误杀。
    rel_stats = None
    try:
        from qa.relevance import gate as _rel_gate
        pool, rel_stats = _rel_gate(pool, base, keep_min=0)
        final = diversity_rerank(pool, k=FINAL_K, min_types=min_types)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m3_qa/backend/qa/multi_hop.py:gate", _sw_e)
    zero_hit = not final

    # 4d. 推理链落盘：答案带 reasoning_chain —— 前端可展开"它查了什么、为什么这么查"。
    #     这条链是"推理链可解释"的硬证据：每一跳都有 query / basis / 命中数 / 耗时。
    global LAST_CHAIN
    LAST_CHAIN = {
        "strategy": "planner+iterative" if (cfg or {}).get("api_key") else "rule+iterative",
        "hop_count": max([h.get("hop", 1) for h in chain if not h.get("skipped")] or [0]),
        "hops": chain,
        "pool_size": len(pool),
        "returned": len(final),
        "zero_hit": zero_hit,
        "relevance": rel_stats,
        "total_ms": int((time.time() - _t0) * 1000),
    }
    if with_chain:
        return final, LAST_CHAIN
    return final
