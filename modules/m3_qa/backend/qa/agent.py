# -*- coding: utf-8 -*-
"""
agent.py —— 智能体工具编排层（Tool-Calling Agent）
====================================================================
这一层解决的是「智能体到底自不自主」的问题。

改造前：有 LLM 时只拿来**拆子查询**（plan_queries），工具怎么调、调几次、什么时候停，
全部由 `multi_hop.py` 里的规则写死 —— 本质上还是"规则编排为主，模型只做润色"。

改造后：**由模型自己决定调什么工具、顺序、几轮停手**（OpenAI 兼容 function calling）：

    问题 → LLM(带工具声明) → 决定调 2 个工具 → 执行 → 观察结果 → 再决定 → … → 收敛出答案

三条硬约束（这也是为什么它不只是个 demo）：

1. **工具私有、数据不出本机**：所有工具最终都打到本机主体服务的 HTTP 接口或进程内函数，
   检索/详情/图谱/POC/资产全部是自家能力，没有一个外部検索 API。
2. **永远有退路**：`run_agent()` 在没有 Key、LLM 异常、工具全失败、超过轮次上限时，
   **一律返回 None**，交给上层退回原有的 multi_hop + 模板/生成路径 —— 功能不受影响，
   自测（走 no_llm）的行为完全不变。
3. **全程留痕**：每一步工具调用都记进 `trace`（工具名/参数/成败/条数/耗时），
   答案里带上 `agent.mode`，前端与评测都能看到"它到底干了什么"，而不是黑箱吹牛。
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

MAIN_SERVER = os.environ.get("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")

# 单题工具调用上限与轮次上限：防止模型陷入"检索-不满意-再检索"的死循环。
# 2026-10-08 实测下调（3→2 / 6→4）：真实 trace 里第 3 轮的增量证据很少，
# 却要多付一次 3k+ token 的 prefill（工具 schema 占大头）——它是 55.6s 慢问答
# 的主要构成之一。需要更深推理的极少数问题可由 cfg["max_rounds"] 调回。
MAX_ROUNDS = int(os.environ.get("AISEC_QA_AGENT_ROUNDS", "2") or 2)
MAX_CALLS = int(os.environ.get("AISEC_QA_AGENT_CALLS", "4") or 4)
TOOL_TIMEOUT = 20

# 终局答案生成 token 上限。原 2000 —— 实测 deepseek 输出 ~30-40 tok/s，
# 2000 token 光生成就 50-65s，是「55.6s 才出答案」的第一根因。
# 1200 token ≈ 900-1100 汉字，足够"结论先行 + 分点"的完整结论。
ANSWER_MAX_TOKENS = int(os.environ.get("AISEC_QA_ANSWER_TOKENS", "1200") or 1200)

# 列表型快路答案的生成上限（2026-10-08 晚）：列表问答的价值在"结构化逐条
# 可执行"，800 token ≈ 500-600 汉字；实测 26.8s 里生成占 ~20s，砍长度是
# 提速最直接的一档，且不伤信息量（明细本来就在"原始资料"卡片里可点开）。
FAST_ANSWER_TOKENS = int(os.environ.get("AISEC_QA_FAST_TOKENS", "800") or 800)

# Agent 整体预算（规划轮 + 工具 + 终局生成）秒数。到点强制收敛，不让单题占住线程。
AGENT_BUDGET = float(os.environ.get("AISEC_QA_AGENT_BUDGET", "60") or 60)

# 流式生成的 chunk 事件节流（秒）：太密会产生大量小 SSE 帧，太疏首字变慢。
STREAM_FLUSH_INTERVAL = 0.05

try:  # 超时配置统一在 qa.config，缺失时退回 45s（宁可慢，也不无限期挂住）
    from qa.config import LLM_TIMEOUT as _LLM_TIMEOUT
    from qa.config import LLM_MAX_RETRIES as _LLM_RETRIES
    from qa.config import ANSWER_CONFIG as _ANSWER_CFG
except Exception:  # pragma: no cover
    _LLM_TIMEOUT, _LLM_RETRIES = 45.0, 1
    _ANSWER_CFG = {"conclusion_limit": 3600}

# 提示词里的字数上限从 config 读（单一来源），并额外给一个"精简档"：
# 流式场景下短答案 = 更早收尾。3600 字是上限（防灌水），不是目标长度。
_CONCLUSION_LIMIT = int(_ANSWER_CFG.get("conclusion_limit") or 3600)


# ───────────────────────────────────────────────────────────────
# 一、工具执行器：每个工具最终都落到本机能力
# ───────────────────────────────────────────────────────────────

def _http_get(path: str, params: Dict[str, Any], timeout: int = TOOL_TIMEOUT) -> Any:
    url = MAIN_SERVER + path + "?" + urllib.parse.urlencode(
        {k: v for k, v in params.items() if v not in (None, "")})
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def _trim(s: Any, n: int = 400) -> str:
    return str(s or "")[:n]


def tool_hybrid_search(query: str, top_k: int = 6) -> Dict:
    """混合检索（关键词+语义）：口语化、语义改写类提问的主力工具。"""
    from qa.retriever import hybrid_search
    d = hybrid_search(query, top_k=top_k)
    return {"mode": d.get("mode"), "hits": [
        {"id": r.get("id"), "title": _trim(r.get("title"), 120),
         "cvss": (r.get("cvss") or {}).get("score"),
         "severity": (r.get("cvss") or {}).get("severity", ""),
         "exploited": bool(r.get("exploited")),
         "poc_count": r.get("poc_count") or 0,
         # 2026-10-08 晚：补 desc/products —— 此前 hits 只有 id/title/分数，
         # 终局生成时模型对每条无话可说（"回答不佳"的根因之一：证据太瘦）。
         "desc": _trim(r.get("desc"), 150),
         "products": [str(p) for p in (r.get("products") or [])[:4]]}
        for r in d.get("results", [])]}


def tool_keyword_search(query: str, top_k: int = 6) -> Dict:
    """精确路径检索：强标记题（在野利用/高危/POC）用它，避免语义泛相关干扰。"""
    from qa.retriever import hybrid_search
    d = hybrid_search(query, top_k=top_k, skip_vector=True)
    return {"mode": "engine", "hits": [
        {"id": r.get("id"), "title": _trim(r.get("title"), 120),
         "cvss": (r.get("cvss") or {}).get("score"),
         "severity": (r.get("cvss") or {}).get("severity", ""),
         "exploited": bool(r.get("exploited")),
         "poc_count": r.get("poc_count") or 0,
         "desc": _trim(r.get("desc"), 150),
         "products": [str(p) for p in (r.get("products") or [])[:4]]}
        for r in d.get("results", [])]}


def tool_get_detail(doc_id: str) -> Dict:
    """按 CVE/GHSA 编号取完整详情（CVSS、CWE、受影响产品、修复建议）。"""
    from qa.retriever import get_detail
    d = get_detail(doc_id) or {}
    return {"id": d.get("id") or doc_id, "title": _trim(d.get("title"), 160),
            "cvss": (d.get("cvss") or {}).get("score"),
            "severity": (d.get("cvss") or {}).get("severity", ""),
            "products": (d.get("products") or [])[:8],
            "cwe": [w.get("id") if isinstance(w, dict) else str(w) for w in (d.get("cwe") or [])[:5]],
            "exploited": bool(d.get("exploited")),
            "desc": _trim(d.get("desc"), 600)}


def tool_search_ioc(ioc: str, top_k: int = 8) -> Dict:
    """查某个 IOC（IP/域名/hash/URL）关联的情报。回答「这个 IP/域名是什么威胁」
    时用。走引擎的 ioc: 算子（无独立 IOC 源时从漏洞描述/参考里派生提取）。"""
    from qa.retriever import hybrid_search
    d = hybrid_search("ioc:%s" % ioc, top_k=top_k, skip_vector=True)
    return {"ioc": ioc, "hits": [
        {"id": r.get("id"), "title": _trim(r.get("title"), 120),
         "cvss": (r.get("cvss") or {}).get("score"),
         "exploited": bool(r.get("exploited"))}
        for r in d.get("results", [])]}


def tool_get_related(doc_id: str) -> Dict:
    """同组件/同 CWE/同攻击技术的关联情报（用于跨文档推理）。"""
    d = _http_get("/api/related", {"id": doc_id})
    top = (d.get("top_overall") or d.get("related") or [])[:5]
    return {"related": [{"id": x.get("id"), "title": _trim(x.get("title"), 100),
                         "cvss": x.get("cvss")} for x in top]}


def tool_get_graph(doc_id: str) -> Dict:
    """关系图谱：把单条情报放到"组件-弱点-技术-处置"的网络里看。"""
    d = _http_get("/api/graph", {"id": doc_id})
    nodes = d.get("nodes") or []
    edges = d.get("edges") or d.get("links") or []
    return {"nodes": len(nodes), "edges": len(edges),
            "sample": [_trim(n.get("label") or n.get("id"), 40) for n in nodes[:8]]}


def tool_find_poc(cve_id: str) -> Dict:
    """查该 CVE 有没有公开 POC/EXP（调模块2 的能力，连带 A/B/C/D 分级）。"""
    d = _http_get("/api/poc", {"id": cve_id})
    items = d.get("results") or d.get("items") or []
    return {"count": len(items), "prec": [
        {"title": _trim(x.get("title") or x.get("repo") or x.get("name"), 90),
         "tier": x.get("match_tier") or x.get("tier") or "",
         "source": x.get("source") or ""} for x in items[:5]]}


def tool_locate_assets(cve_id: str) -> Dict:
    """受影响资产定位 + 互联网测绘语法（只生成语法，不扫任何第三方主机）。"""
    d = _http_get("/api/assets", {"id": cve_id})
    assets = d.get("assets") or d.get("items") or []
    survey = d.get("survey") or {}
    return {"assets": [{"name": _trim(a.get("name") or a.get("product"), 60),
                        "version": _trim(a.get("version_range") or a.get("version"), 60)}
                       for a in assets[:6]],
            "survey_platforms": list((survey or {}).keys())[:6]}


def tool_latest_intel(limit: int = 5) -> Dict:
    """最近一轮实时监测抓到的新情报（"最近有什么"类问题用它）。"""
    d = _http_get("/api/live", {"limit": limit})
    items = d.get("items") or d.get("results") or []
    return {"count": len(items), "feed_ok": d.get("feed_ok"), "feed_total": d.get("feed_total"),
            "items": [{"title": _trim(x.get("title"), 100), "source": x.get("source") or ""}
                      for x in items[:limit]]}


EXECUTORS = {
    "search_intelligence": lambda a: tool_hybrid_search(a.get("query", ""), int(a.get("top_k") or 6)),
    "search_exact": lambda a: tool_keyword_search(a.get("query", ""), int(a.get("top_k") or 6)),
    "get_detail": lambda a: tool_get_detail(a.get("doc_id", "")),
    "get_related": lambda a: tool_get_related(a.get("doc_id", "")),
    "get_graph": lambda a: tool_get_graph(a.get("doc_id", "")),
    "find_poc": lambda a: tool_find_poc(a.get("doc_id", "")),
    "locate_assets": lambda a: tool_locate_assets(a.get("doc_id", "")),
    "latest_intel": lambda a: tool_latest_intel(int(a.get("limit") or 5)),
    "search_ioc": lambda a: tool_search_ioc(a.get("ioc", ""), int(a.get("top_k") or 8)),
}

# 给 LLM 的函数声明（OpenAI 兼容 function calling schema）
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "search_intelligence",
            "description": "语义+关键词混合检索安全情报。适合口语化提问、概念性提问、语义改写类问题（如'模型文件被人动了手脚怎么发现'）。",
            "parameters": {"type": "object", "properties": {
                "query": {"type": "string", "description": "检索词，用自然语言或关键词均可"},
                "top_k": {"type": "integer", "description": "返回条数，默认6"}
            }, "required": ["query"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_exact",
            "description": "精确路径检索，不掺语义。适合带强标记的过滤型问题：在野利用(KEV)、有公开POC、CVSS高危(cvss>=7)、特定CWE、特定产品、时间范围。这类问题用混合检索会被泛相关结果顶掉，必须用这个工具。",
            "parameters": {"type": "object", "properties": {
                "query": {"type": "string", "description": "可用结构化算子：kev:yes、poc:yes、product:ollama、cwe:CWE-78、cvss>=9、year:>=2025"},
                "top_k": {"type": "integer", "description": "返回条数，默认6"}
            }, "required": ["query"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_detail",
            "description": "按漏洞编号取完整详情：CVSS评分、严重级别、受影响产品与版本、CWE弱点、是否已在野利用、描述全文。要回答具体某个CVE的情况时用。",
            "parameters": {"type": "object", "properties": {
                "doc_id": {"type": "string", "description": "漏洞编号，如 CVE-2024-5565"}
            }, "required": ["doc_id"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_related",
            "description": "取与某漏洞相关的其他情报（同组件/同CWE/同攻击技术），用于跨文档横向对比与归纳。",
            "parameters": {"type": "object", "properties": {
                "doc_id": {"type": "string", "description": "漏洞编号"}
            }, "required": ["doc_id"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_graph",
            "description": "取该漏洞的关系图谱结构（节点与边的规模、主要实体），回答'涉及哪些方面/攻击链'时用。",
            "parameters": {"type": "object", "properties": {
                "doc_id": {"type": "string", "description": "漏洞编号"}
            }, "required": ["doc_id"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_poc",
            "description": "查该漏洞有没有公开的POC/EXP利用代码，并带A/B/C/D可信分级。回答'能不能被打/有没有现成利用'时用。",
            "parameters": {"type": "object", "properties": {
                "doc_id": {"type": "string", "description": "CVE编号"}
            }, "required": ["doc_id"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "locate_assets",
            "description": "定位受影响资产版本区间，并生成 FOFA/Shodan/Quake/ZoomEye 测绘语法（只生成语法，不主动扫描任何主机）。回答'影响面多大/怎么找自家资产'时用。",
            "parameters": {"type": "object", "properties": {
                "doc_id": {"type": "string", "description": "CVE编号"}
            }, "required": ["doc_id"]}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "latest_intel",
            "description": "取最近一轮实时监测抓到的新情报。回答'最近/今天/本周有什么新漏洞'时用。",
            "parameters": {"type": "object", "properties": {
                "limit": {"type": "integer", "description": "返回条数，默认5"}
            }, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_ioc",
            "description": "查某个 IOC（IP/域名/哈希/URL）关联的情报。回答'这个 IP 是什么威胁''这个域名有没有恶意活动'时用。",
            "parameters": {"type": "object", "properties": {
                "ioc": {"type": "string", "description": "要查的 IOC 值，如 1.2.3.4 或 evil.example.com 或一个文件哈希"},
                "top_k": {"type": "integer", "description": "返回条数，默认8"}
            }, "required": ["ioc"]}
        }
    },
]

AGENT_SYSTEM_PROMPT = """你是 AI-SecIntel 的情报分析智能体，手上有 9 个安全情报工具可用。

工作原则：
1. 先判断问题类型再选工具，不要一上来就检索：
   - 带强标记（在野利用/有POC/CVSS高危/特定CWE/特定产品/时间范围）→ 用 search_exact（精确路径）
   - 口语化、概念性、语义改写类提问 → 用 search_intelligence（混合检索）
2. 复杂问题**自己**决定要不要多步：觉得证据不够就继续调工具（比如先检索 → 再取详情 → 再查POC），
   但单题总调用次数不要超过 4 次，觉得够了就直接给答案。
3. 答案必须落在工具返回的事实上，**引用具体漏洞编号**；工具里没有的信息不许编。
4. 如果工具都没查到，就直说"当前知识库没有相关情报"，并说明你查了哪些方向。

【输出结构（必须遵守）】
5. **结论先行**：第一段直接给结论——查到几条、风险分布、最该处置的编号（带 CVSS 与严重等级）、
   建议动作。不要把答案写成"我调用了某某工具"的过程流水账。
6. **全文不超过 %d 字**；结论之后按严重程度分点展开，每点落到具体编号。
   宁可精简也不要灌水：重复资料字段、同义反复的段落一律不写。
""" % _CONCLUSION_LIMIT


def _final_instruction() -> str:
    """Phase 2 终局生成的作答指令（2026-10-08 晚重写）。

    旧版只有"结论先行 + 引用编号"两句，实测模型把答案写成 8 条裸列表：
    每条只有编号和标题，没有影响描述、没有处置动作 —— 用户评价"回答不佳"。
    这里把"每条一行：编号（分数/级别/标记）——影响——处置"的格式显式写死，
    并要求结尾给处置优先级。证据里没有的处置信息明令不许编。
    """
    return (
        "基于以上工具返回的证据直接作答，严格按以下结构：\n"
        "1) 第一行结论：命中数量、风险构成（CRITICAL/HIGH/KEV 各几条）、"
        "最该优先处置的编号；\n"
        "2) 之后按风险从高到低逐条展开，每条一行，格式固定为：\n"
        "   编号（CVSS X.X，严重级别，KEV/有POC 标记）——一句话影响或事件描述——"
        "处置动作（受影响产品/升级或补丁方向，来自证据中的描述与受影响产品字段）；\n"
        "   证据里没有处置依据的写「列入跟踪」，**不许编造补丁或版本号**；\n"
        "3) 结尾给不超过 3 行的处置优先级建议（先处置哪些、为什么）。\n"
        "全文不超过 %d 字。不要复述你调用了什么工具，不要写与证据无关的科普。" % _CONCLUSION_LIMIT)


# ───────────────────────────────────────────────────────────────
# 二、执行单个工具调用（带留痕与容错）
# ───────────────────────────────────────────────────────────────

def execute_tool(name: str, arguments: Dict[str, Any]) -> Dict:
    """执行一个工具调用，返回 {ok, result|error, ms, n} —— 失败不外抛，交给模型自己看着办。"""
    t0 = time.time()
    fn = EXECUTORS.get(name)
    if fn is None:
        return {"ok": False, "error": f"未知工具 {name}", "ms": 0, "n": 0}
    try:
        out = fn(arguments or {})
        n = len(out.get("hits") or out.get("items") or out.get("related") or out.get("assets") or [])
        return {"ok": True, "result": out, "ms": round((time.time() - t0) * 1000, 1), "n": n}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:160], "ms": round((time.time() - t0) * 1000, 1), "n": 0}


# ───────────────────────────────────────────────────────────────
# 二b、意图快路（2026-10-08 晚：列表型问题跳过规划轮，实测 26.8s 的构成之一）
# ───────────────────────────────────────────────────────────────
# 「最近被在野利用的高危漏洞有哪些？」这类问题，Phase 1 规划轮要付一次
# 3k token 的工具 schema prefill + 一次非流式往返（实测 3~8s），最后模型
# 选的还是 search_exact("kev:yes cvss>=7") —— 纯确定性映射，不值得花一次
# LLM 调用。这里用规则直接路由到工具，再进 Phase 2 流式生成。
# 只覆盖「列表意图 + 强标记」的高频形态；识别不了照旧走完整规划轮。

_FAST_LIST_RE = re.compile(r"哪些|有(什么|啥)|列出|盘点|汇总|top\s*\d*|排行", re.I)
_FAST_KEV_RE = re.compile(r"在野利用|已被(利用|攻击)|kev\b|exploited", re.I)
_FAST_POC_RE = re.compile(r"公开?poc|exp\b|利用代码", re.I)
_FAST_LATEST_RE = re.compile(r"最新|最近|今天|本周|刚刚|新增", re.I)
_FAST_HIGH_RE = re.compile(r"高危|严重|critical|high|cvss\s*[>≥]\s*[7-9]", re.I)


def fast_route(question: str):
    """列表型强标记问题 → (tool_name, args) 直达工具；识别不了返回 None。"""
    q = (question or "").strip()
    if not q or not _FAST_LIST_RE.search(q):
        return None
    if _FAST_KEV_RE.search(q):
        op = "kev:yes"
        if _FAST_HIGH_RE.search(q):
            op += " cvss>=7"
        return ("search_exact", {"query": op, "top_k": 8})
    if _FAST_POC_RE.search(q):
        op = "poc:yes"
        if _FAST_HIGH_RE.search(q):
            op += " cvss>=7"
        return ("search_exact", {"query": op, "top_k": 8})
    if _FAST_LATEST_RE.search(q) and not _FAST_HIGH_RE.search(q):
        # 「最近有什么新情报」——不带风险筛选的最新情报流
        return ("latest_intel", {"limit": 8})
    return None


# ───────────────────────────────────────────────────────────────
# 三、Agent 主循环
# ───────────────────────────────────────────────────────────────

def _parse_arguments(raw: Any) -> Dict:
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _collect_ids(result: Dict, citations: List[str]) -> None:
    """从任意工具返回体里抽取可引用的实体 id，并入 citations。

    覆盖 search 的 hits、get_detail 的顶层 id、get_related 的 related[].id，
    以及 find_poc / locate_assets / latest_intel 里可能出现的 id / cve / doc_id 字段，
    让「工具型智能体查了详情/POC/图谱，答案的引用列表里也要有它们」名实相符。
    """
    if not isinstance(result, dict):
        return

    def add(x: Any) -> None:
        if isinstance(x, str) and x and x not in citations:
            citations.append(x)

    add(result.get("id"))
    add(result.get("cve"))
    add(result.get("doc_id"))
    for key in ("hits", "items", "related", "assets", "prec"):
        for it in (result.get(key) or []):
            if isinstance(it, dict):
                add(it.get("id"))
                add(it.get("cve"))
                add(it.get("doc_id"))


def _evidence_of(citations: List[str]) -> List[Dict]:
    """智能体只拿到引用编号 → 回访主体补齐「原始详细资料」卡片（供前端点开全文）。

    拿不到详情也要留占位：宁可少字段，也不能"答案引用了、资料列表里没有"。
    """
    try:
        from qa.report import evidence_from_ids
        return evidence_from_ids(citations)
    except Exception as e:  # noqa: BLE001
        print(f"[Agent] 原始资料补齐失败（不影响作答）: {e}")
        return [{"id": c} for c in (citations or [])[:8]]


def run_agent(question: str, history: List[Dict] = None, llm_config: Dict = None,
              max_rounds: int = MAX_ROUNDS, client: Any = None,
              on_event=None, budget: float = AGENT_BUDGET) -> Optional[Dict]:
    """工具调用式智能体主循环（v3：规划/生成两段式）。

    返回 None 表示"这次不走智能体"（无 Key / LLM 异常 / 全部工具失败），
    上层会退回原有的 multi_hop + generator 路径，**功能不受影响**。

    v3 结构（2026-10-08，针对 55.6s 慢问答实测改造）：
      Phase 1 规划轮（≤max_rounds，非流式）：模型只负责选工具，输出短；
      Phase 2 终局生成（**固定 stream=True**）：工具证据收集齐后单独发一个
        不带 tools 的请求，逐 token 经 on_event("token", t) 推给调用方 ——
        深度问答首字时间从「整段生成完才返回」的 55s 量级降到 ~10s 内，
        用户全程看得见答案在往外蹦。

    on_event(kind, payload)：kind ∈ stage / token；None 则不推送（评测/自测路径零影响）。
    budget：本函数整体预算秒数，超时强制收敛（原实现 3 轮 × 45s 超时 = 最长 135s+，
    且完全不受 QA_BUDGET 约束 —— 这是 55.6s 的第二根因）。

    正常返回：{answer, sources, used_llm, agent:{mode, rounds, trace[], citations[]}}
    `client` 参数用于离线自测注入桩客户端（不联网也能验证编排逻辑）。
    """
    cfg = dict(llm_config or {})
    if cfg.get("disable_llm") or not cfg.get("api_key"):
        return None                       # 模板/无 Key 场景：明确不走智能体

    def _emit(kind, payload):
        if on_event:
            try:
                on_event(kind, payload)
            except Exception:  # noqa: BLE001 —— 推送失败绝不能打断作答
                pass

    t_start = time.monotonic()

    def _left() -> float:
        return budget - (time.monotonic() - t_start)

    messages: List[Dict] = [{"role": "system", "content": AGENT_SYSTEM_PROMPT}]
    for h in (history or [])[-6:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": question})

    trace: List[Dict] = []
    citations: List[str] = []
    calls = 0

    try:
        if client is None:
            from openai import OpenAI
            # max_retries 是客户端构造参数；传给 create() 会抛
            # unexpected keyword argument（openai 3.x 实测）
            client = OpenAI(base_url=cfg.get("base_url") or "https://api.deepseek.com",
                            api_key=cfg["api_key"],
                            max_retries=_LLM_RETRIES)

        model = cfg.get("model") or "deepseek-chat"
        temperature = cfg.get("temperature", 0.2)
        tool_timeout = max(5.0, min(cfg.get("timeout") or _LLM_TIMEOUT, _LLM_TIMEOUT))

        # ── Phase 0：意图快路（2026-10-08 晚）────────────────────────
        # 列表型强标记问题直接执行确定性工具，省掉一次规划轮 LLM 往返
        # （3k token prefill + 3~8s 非流式等待）。失败不回退也不报错——
        # 证据为空时终局生成会如实说"没查到"，与规划轮空手而归等价。
        fast_used = False
        fast = fast_route(question)
        if fast and _left() > 10.0:
            fname, fargs = fast
            _emit("stage", {"stage": "plan",
                            "msg": "识别为列表型检索，直达工具取证（跳过规划轮）…"})
            res = execute_tool(fname, fargs)
            calls = 1
            fast_used = res["ok"]
            step = {"tool": fname, "args": fargs, "ok": res["ok"],
                    "n": res["n"], "ms": res["ms"]}
            if not res["ok"]:
                step["error"] = res.get("error") or ""
            trace.append(step)
            _collect_ids(res.get("result") or {}, citations)
            payload = res.get("result") if res["ok"] else {"error": res.get("error")}
            messages.append({"role": "user", "content":
                "（系统快路）已直接执行工具 %s，参数 %s，返回证据：\n%s"
                % (fname, json.dumps(fargs, ensure_ascii=False),
                   json.dumps(payload, ensure_ascii=False)[:4000])})

        # ── Phase 1：规划轮（非流式；快路已取证则跳过） ─────────────
        direct_answer = ""
        for round_no in range(1, 1 if fast_used else max_rounds + 1):
            if _left() < 12.0:
                # 预算见底：不再做规划，直接进终局生成（现有证据可能为空，
                # 那就让模型回答"没查到"——也比无限期挂着强）
                break
            _emit("stage", {"stage": "plan", "round": round_no,
                            "msg": "智能体第 %d 轮规划中…" % round_no})
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOL_SCHEMAS,
                tool_choice="auto",
                temperature=temperature,
                max_tokens=700,           # 规划轮只输出工具选择，700 足够
                timeout=min(tool_timeout, max(6.0, _left())),
            )
            msg = resp.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None) or []

            if not tool_calls:
                # 模型判断无需工具 → 它给的正文就是答案（罕见但真实存在：
                # 概念性寒暄/明显闲聊）。整包推送，不再进终局生成。
                direct_answer = (getattr(msg, "content", None) or "").strip()
                break

            messages.append({"role": "assistant",
                             "content": getattr(msg, "content", None) or "",
                             "tool_calls": [
                                 {"id": tc.id, "type": "function",
                                  "function": {"name": tc.function.name,
                                               "arguments": tc.function.arguments}}
                                 for tc in tool_calls]})

            for tc in tool_calls:
                if calls >= MAX_CALLS:
                    trace.append({"tool": tc.function.name, "ok": False,
                                  "error": "已达单题工具调用上限", "n": 0})
                    messages.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": json.dumps({"error": "已达调用上限，请直接作答"},
                                                           ensure_ascii=False)})
                    continue
                calls += 1
                args = _parse_arguments(tc.function.arguments)
                _emit("stage", {"stage": "tool", "tool": tc.function.name,
                                "msg": "调用工具 %s…" % tc.function.name})
                res = execute_tool(tc.function.name, args)
                step = {"tool": tc.function.name, "args": args,
                        "ok": res["ok"], "n": res["n"], "ms": res["ms"]}
                if not res["ok"]:
                    # 失败原因必须留在 trace 里：既让模型知道该换条路，
                    # 也让答辩现场能看清"它失败过、并且自己处理了"
                    step["error"] = res.get("error") or ""
                trace.append(step)
                # 引用收集：工具返回体里的实体 id（hits/详情/关联/POC/资产）+ 工具入参 doc_id 一并并入
                _collect_ids(res.get("result") or {}, citations)
                if args.get("doc_id"):
                    _collect_ids({"id": args.get("doc_id")}, citations)
                payload = res.get("result") if res["ok"] else {"error": res.get("error")}
                # 工具结果截断从 4000 → 2600：它直接吃进下一轮 prefill，
                # 对生成速度是纯负担，2600 字证据足够模型引用。
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(payload, ensure_ascii=False)[:2600]})

        if direct_answer:
            record_trace(question, trace, 1, "tool-calling(direct)")
            _emit("token", {"t": direct_answer})
            _emit("token", {"t": "\0"})   # 与流式分支一致的结束标记
            return {
                "answer": direct_answer,
                "conclusion": direct_answer,
                "evidence": _evidence_of(citations),
                "sources": [{"id": c} for c in citations[:8]],
                "used_llm": True,
                "agent": {"mode": "tool-calling(direct)", "rounds": 1,
                          "tool_calls": calls, "trace": trace,
                          "citations": citations[:8]},
                "streamed": True,
            }

        # ── Phase 2：终局生成（固定流式，不带 tools） ────────────────
        #    这是回答延迟的大头。stream=True 后首 token 一到就推给前端，
        #    用户从「黑盒干等 55s」变成「10s 内看见答案逐字生成」。
        _emit("stage", {"stage": "generate",
                        "msg": "证据齐了（%d 次工具调用），正在生成结论…" % calls})
        messages.append({"role": "user", "content": _final_instruction()})
        # 列表型快路用更小的生成预算：这类问答的价值在"结构化逐条"，
        # 800 token ≈ 500-600 汉字足够；深度分析类才给满额 ANSWER_MAX_TOKENS。
        ans_budget = (FAST_ANSWER_TOKENS if fast_used else ANSWER_MAX_TOKENS)
        answer_parts: List[str] = []
        pending: List[str] = []       # 节流窗口内攒下的片段（flush 时一起发）
        last_flush = time.monotonic()
        gen_timeout = max(8.0, min(tool_timeout, max(8.0, _left()) if _left() > 0 else tool_timeout))
        stream = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=cfg.get("max_tokens") or ans_budget,
            stream=True,
            timeout=gen_timeout,
        )
        for chunk in stream:
            try:
                delta = chunk.choices[0].delta
                piece = getattr(delta, "content", None) if delta is not None else None
            except (IndexError, AttributeError):
                piece = None
            if not piece:
                continue
            answer_parts.append(piece)
            pending.append(piece)
            now = time.monotonic()
            if now - last_flush >= STREAM_FLUSH_INTERVAL:
                last_flush = now
                _emit("token", {"t": "".join(pending)})
                pending.clear()
        answer = "".join(answer_parts).strip()
        # 尾巴补发：节流窗口关闭后到达的片段必须发出，否则答案会缺最后一段
        # （2026-10-08 回归抓到：3 个片段同刻到达，第 2、3 片被节流吞掉）。
        if pending:
            _emit("token", {"t": "".join(pending)})
            pending.clear()
        if answer:
            _emit("token", {"t": "\0"})   # 结束标记（前端据此停止打字态）
        if not answer:
            return None
        mode = "fast-path(stream)" if fast_used else "tool-calling(stream)"
        record_trace(question, trace, max(1, min(calls, max_rounds)), mode)
        return {
            "answer": answer,
            "conclusion": answer,          # 结论段由前端置顶渲染（超长由 report.finalize 截断）
            "evidence": _evidence_of(citations),   # 引用编号 → 原始资料卡片（可点开全文）
            "sources": [{"id": c} for c in citations[:8]],
            "used_llm": True,
            "agent": {"mode": mode, "rounds": max(1, min(calls, max_rounds)),
                      "tool_calls": calls, "trace": trace,
                      "citations": citations[:8]},
            "streamed": True,
        }
    except Exception as e:  # noqa: BLE001
        print(f"[Agent] 智能体编排失败，退回原有链路: {e}")
        return None


# ───────────────────────────────────────────────────────────────
# 四、调用留痕（答辩现场要能证明"它真的调了工具"）
# ───────────────────────────────────────────────────────────────

_LAST_TRACES: List[Dict] = []
_TRACE_MAX = 20


def record_trace(question: str, trace: List[Dict], rounds: int, mode: str) -> None:
    """存下最近一次智能体问答的工具调用链路（最多留 20 条）。"""
    _LAST_TRACES.append({
        "ts": time.strftime("%H:%M:%S"),
        "question": question[:80],
        "mode": mode,
        "rounds": rounds,
        "calls": len(trace),
        "tools": [t.get("tool") for t in trace],
        "ok": sum(1 for t in trace if t.get("ok")),
        "trace": trace,
    })
    if len(_LAST_TRACES) > _TRACE_MAX:
        _LAST_TRACES.pop(0)


def last_traces() -> List[Dict]:
    return list(reversed(_LAST_TRACES))


def tools_manifest() -> List[Dict]:
    """对外暴露工具清单（供 /api/qa/agent/tools 与评测脚本统计"登记工具数"）。"""
    out = []
    for s in TOOL_SCHEMAS:
        fn = s["function"]
        out.append({
            "name": fn["name"],
            "description": fn["description"][:80],
            "parameters": list((fn.get("parameters") or {}).get("properties") or {}),
            "required": (fn.get("parameters") or {}).get("required") or [],
            "has_executor": fn["name"] in EXECUTORS,
        })
    return out
