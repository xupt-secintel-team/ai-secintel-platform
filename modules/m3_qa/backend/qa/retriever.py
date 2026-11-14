# -*- coding: utf-8 -*-
"""
retriever.py — 混合检索（BM25关键词 + 向量语义，结果融合）
"""
import os
import re
import sys
import urllib.request
import urllib.parse
import json
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qa.config import RETRIEVER_CONFIG, MAIN_SERVER
from qa.vector_store import vector_store


def bm25_search(query: str, top_k: int = 10) -> List[Dict]:
    """调主服务的BM25搜索"""
    url = MAIN_SERVER + "/api/search?" + urllib.parse.urlencode({"q": query, "size": top_k})
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            d = json.load(resp)
        return d.get("results", [])
    except Exception as e:
        print(f"[Retriever] BM25搜索失败: {e}")
        return []


def vector_search(query: str, top_k: int = 10) -> List[Dict]:
    """向量语义搜索"""
    return vector_store.search(query, top_k)


def fuse_results(bm25_results: List[Dict], vector_results: List[Dict],
                 bm25_weight: float = 0.7, vector_weight: float = 0.3) -> List[Dict]:
    """
    融合 BM25 与向量结果 —— **分数归一化加权**，不是原来的「排名分相加」。

    为什么改：原实现按「排名分」（第1名=len、最后1名=1）相加，BM25 的非线性优势被抹平：
    实测 50/50 排名融合后整体 @10 从 90.0% 掉到 87.5%，P50 从 832ms 涨到 933ms（见
    `测试报告/检索评测.md`）—— 关键词本来排得对的结果被语义的"泛相关"顶下去了。

    现在的做法：
    1) 两路各自 **min-max 归一化** 到 0~1（BM25 的原始分与向量余弦分不在同一量纲）；
    2) BM25 侧给更高权重（默认 0.7/0.3），保证关键词强命中不被挤下去；
    3) 只出现在一路的结果也参与排序，但拿不到另一路的加分。
    """
    def _norm(items: List[Dict], score_key: str) -> Dict[str, float]:
        vals = []
        for i, r in enumerate(items):
            v = r.get(score_key)
            if not isinstance(v, (int, float)):
                v = float(len(items) - i)      # 没有原始分就用名次当分
            vals.append(float(v))
        if not vals:
            return {}
        lo, hi = min(vals), max(vals)
        span = hi - lo
        if span < 1e-9:
            # 所有候选分都一样（典型：纯字段过滤查询，引擎给的是"都命中"）——
            # 此时**必须给满分**而不是 0：归一到 0 会让这一路的全部结果丢掉权重，
            # 被另一路（语义）整体顶下去，实测会让 cwe:/kev: 这类查询从 100% 掉到 0%。
            return {str(r.get("id") or f"_i{i}"): 1.0 for i, r in enumerate(items)}
        return {str(r.get("id") or f"_i{i}"): (float(v) - lo) / span
                for i, (r, v) in enumerate(zip(items, vals))}

    bm = _norm(bm25_results, "score")
    ve = _norm(vector_results, "vector_score")

    merged: Dict[str, Dict] = {}
    for r in bm25_results:
        rid = str(r.get("id"))
        merged[rid] = {"data": r, "score": bm.get(rid, 0.0) * bm25_weight, "src": "bm25"}
    for r in vector_results:
        rid = str(r.get("id"))
        if rid in merged:
            merged[rid]["score"] += ve.get(rid, 0.0) * vector_weight
            merged[rid]["src"] = "bm25+vector"
            # ★ 把向量分写回条目（2026-10-18 实测补）：data 是 BM25 卡对象，
            #   自带字段里没有 vector_score —— 融合后闸门的 _vector_score()
            #   对**双路命中条目**恒拿 None，语义信号整个丢失。实测
            #   《中华人民共和国数据安全法》(DSKB:REG01) 双路命中
            #   （BM25 17.3 + vec 0.8991）却被当纯 BM25 条目判灭。
            if merged[rid]["data"].get("vector_score") is None \
                    and r.get("vector_score") is not None:
                merged[rid]["data"]["vector_score"] = r.get("vector_score")
        else:
            merged[rid] = {"data": r, "score": ve.get(rid, 0.0) * vector_weight, "src": "vector"}

    fused = sorted(merged.values(), key=lambda x: -x["score"])
    for item in fused:
        item["data"]["_fusion"] = item["src"]
    return [item["data"] for item in fused]


# 查询里带「字段/算子」就是结构化意图（cwe:CWE-78、product:ollama、kev:yes、cvss>=9、sort=trust…）：
# 这类查询要的是精确过滤，**不能掺语义的"泛相关"** —— 实测掺了会把 cwe:/kev: 题从 100% 打到 0%。
_FIELD_RE = re.compile(
    r"(^|\s)(cwe|product|vendor|severity|year|kev|type|scope|source|sort|exploited|poc|paper|trust)\s*[:=]"
    r"|(^|\s)(cvss)\s*(>=|<=|>|<|=)", re.I)


def hybrid_search(query: str, top_k: int = 12, filters: Dict = None,
                  skip_vector: bool = False, skip_boost: bool = False) -> Dict:
    """**混合检索**（关键词 + 语义）对外入口，供 /api/hybrid_search 与评测使用。

    与 `retrieve()` 的区别：这里返回结构化结果 + 融合元信息，且可以直接带筛选条件
    （筛选交给引擎侧做，语义侧只在没有强筛选时参与，避免把「只想要 CRITICAL」这类查询搅乱）。

    `skip_vector=True` 强制只用关键词精确路径。来源有三类，都会命中这个开关：
      ① 查询里写了结构化算子（cwe:/kev:/cvss>= …）；
      ② 请求里带了强筛选条件（severity/category/exploited_only/…）；
      ③ **自然语言里含强标记意图**（在野利用 / 有 POC / CVSS 高危 —— 由 `strong_marker()` 判定）。
    第 ③ 条是 v2.1 补的：此前「最近被在野利用的高危漏洞」这类题走混合检索时，
    语义路的"泛相关"会把真正的 KEV 条目顶下去，实测该类 @10 反比纯关键词低 16.7 个点。
    """
    bm25_k = max(int(RETRIEVER_CONFIG.get("bm25_top_k") or 30), top_k * 3)
    bm25_results = _engine_search(query, bm25_k, filters)
    field_filter = bool(_FIELD_RE.search(query or "")) or (bool(filters) and any([
        filters.get("severity"), filters.get("category"), filters.get("source"),
        filters.get("scope"), filters.get("exploited_only"), filters.get("poc_only"),
        filters.get("cvss_min") is not None, filters.get("year_from"), filters.get("year_to"),
    ]))
    strong_filter = skip_vector or field_filter or strong_marker(query)
    vector_results = [] if strong_filter else vector_search(query, RETRIEVER_CONFIG.get("vector_top_k", 10))

    # ── 强标记 → 结构化算子：把"自然语言里的条件"翻成引擎听得懂的过滤式 ──────
    # 例：「最近被在野利用的高危漏洞」→ 追加 kev:yes；「有公开POC的漏洞」→ 追加 poc:yes。
    # 道理很简单：用户说的是人话（"在野利用"），引擎只认算子（kev:yes），
    # 中间这一步以前只发生在 multi_hop 的子查询里，现在单句提问也能吃到。
    # `skip_boost=True`：关掉结构化算子增强，只保留路由决策。
    # 这是为了**同口径 A/B** —— 判据能否命中会受 enrich_desc（是否带完整描述）影响，
    # 所以评测必须固定"是否增强"这一个变量，其他全部不动。
    structured_boost = ""
    if strong_filter and not field_filter and not skip_vector and not skip_boost:
        op = {"kev": "kev:yes", "poc": "poc:yes", "cvss9": "cvss>=9"}.get(strong_marker(query) or "")
        if op:
            boosted_query = (query or "").strip() + " " + op
            boosted_res = _engine_search(boosted_query, bm25_k, filters)
            # 只有确实捞到足够条目才采用（过滤太狠就退回原查询，宁可宽不能空）
            if len(boosted_res) >= max(3, top_k // 2):
                seen_ids = {r.get("id") for r in boosted_res}
                bm25_results = boosted_res + [r for r in bm25_results if r.get("id") not in seen_ids]
                structured_boost = op
    results = fuse_results(bm25_results, vector_results,
                           RETRIEVER_CONFIG.get("bm25_weight", 0.7),
                           RETRIEVER_CONFIG.get("vector_weight", 0.3)) if vector_results else bm25_results

    # ── 相关度闸门（v2.6）：截断**之前**先剔除不相关候选 ──────────────
    # 为什么放在截断前：`results[:top_k]` 会把"排在第 1~8 但本就不相关"的条目
    # 原样交给上层，于是零命中也会凑满 8 条（实测「不存在术语」返回 8 条无关情报）。
    # 闸门判据是"任一强信号通过"（向量余弦 / 实词命中 / BM25 分 / 双路交集），
    # 所以真命中不会被误杀（宁可漏"剔除"、不可误"剔除")。
    # `keep_min=0`：问答链路要的就是"没有就说没有"，不做兜底填充。
    # 结构化查询（cwe:/kev:/product: 等）豁免闸门 —— 那是精确过滤，
    # 引擎已经按字段筛过，用户明确知道自己在过滤什么。
    rel_stats = None
    if not field_filter:
        results, rel_stats = _relevance_gate(results, query)

    total = _ENGINE_META["total"] if _ENGINE_META["query"] == query else None
    return {
        "results": enrich_desc(results[:top_k]),
        "total": total,
        "fusion": {
            "bm25_candidates": len(bm25_results),
            "vector_candidates": len(vector_results),
            "bm25_weight": RETRIEVER_CONFIG.get("bm25_weight", 0.7),
            "vector_weight": RETRIEVER_CONFIG.get("vector_weight", 0.3),
            "skipped_vector_reason": ("强制精确路径" if skip_vector else
                                      "带强筛选条件，走引擎精确路径" if field_filter else
                                      "含强标记意图（在野利用/POC/高危），走精确路径" if strong_filter else ""),
            "structured_boost": structured_boost,
            "counts": _fusion_counts(results),
            "relevance": rel_stats,
        },
        "mode": "hybrid" if vector_results else "engine",
    }


def _relevance_gate(results: List[Dict], query: str):
    """调用 qa.relevance 的闸门；异常时**原样放行**（不能因为判据故障让问答空掉）。"""
    try:
        from qa.relevance import gate as _gate
        return _gate(results, query, keep_min=0)
    except Exception as e:  # noqa: BLE001
        print(f"[Retriever] 相关度闸门异常（放行全部候选）：{e}")
        return results, None


# 自然语言里的「强标记」信号：说了这些，用户要的是**精确过滤**，不是语义上的相近文章。
# 每一种都对应引擎能精确执行的结构化条件 —— 语义路掺进来只会稀释结果。
# 边界很重要：**"高危/严重"这类泛化程度词不进这张表**。
# 因为「vLLM 有哪些高危漏洞」本质是"实体 + 过滤"，用户要的是那个产品，
# 这类题在两条路径上都是 100%（实测没有损失），没必要改它的走法；
# 而"最近被在野利用的高危漏洞"才是真正被语义顶掉的那类（有明确强标记、泛上下文）。
# 判断准则：**只有当这个条件能被引擎翻译成精确算子时，才升级为强标记**。
_STRONG_MARKER_PATTERNS = [
    (re.compile(r"在野利用|已在野|已被利用|已遭利用|被勒索|勒索软件|kev|exploited", re.I), "kev"),
    (re.compile(r"有公开.?poc|公开利用|利用代码|poc|exp\b|exploit code", re.I), "poc"),
    (re.compile(r"cvss\s*(9|10)|10\s*分|满分漏洞|极其严重", re.I), "cvss9"),
]


def strong_marker(query: str) -> str:
    """判断自然语言问题里有没有「强标记」信号；返回命中的标记名（无则空串）。

    这是修复「在野利用类混合检索比纯关键词差 16.7 个点」的关键开关：
    命中就跳过语义路，让引擎的结构化算子（kev:/poc:/cvss>=）独占结果。
    """
    for rx, tag in _STRONG_MARKER_PATTERNS:
        if rx.search(query or ""):
            return tag
    return ""


def _fusion_counts(results: List[Dict]) -> Dict[str, int]:
    c = {"bm25": 0, "vector": 0, "bm25+vector": 0}
    for r in results:
        c[r.get("_fusion") or "bm25"] = c.get(r.get("_fusion") or "bm25", 0) + 1
    return c


# 最近一次引擎检索的命中总数（2026-10-26）：统计类问题（"ollama 有多少个高危漏洞"）
# 必须能拿到 total，否则模型只能看到 top-k 条、答不出准确数字（实测 I 题 FAIL）。
_ENGINE_META = {"query": None, "total": None}


def _engine_search(query: str, size: int, filters: Dict = None) -> List[Dict]:
    """调主服务引擎检索（BM25/字段过滤），支持带筛选条件"""
    params = {"q": query, "size": size}
    fl = filters or {}
    for k in ("severity", "category", "source", "scope"):
        if fl.get(k):
            params[k] = ",".join(fl[k]) if isinstance(fl[k], list) else fl[k]
    if fl.get("exploited_only"):
        params["exploited"] = 1
    if fl.get("poc_only"):
        params["poc"] = 1
    if fl.get("cvss_min") is not None:
        params["cvss_min"] = fl["cvss_min"]
    if fl.get("year_from"):
        params["year_from"] = fl["year_from"]
    if fl.get("year_to"):
        params["year_to"] = fl["year_to"]
    url = MAIN_SERVER + "/api/search?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            d = json.load(resp)
        _ENGINE_META["query"] = query
        _ENGINE_META["total"] = d.get("total")
        return d.get("results", [])
    except Exception as e:
        print(f"[Retriever] 引擎检索失败: {e}")
        return []


def get_detail(cve_id: str) -> Dict:
    """调主服务 /api/detail 取单条情报全量详情（含完整描述）"""
    url = MAIN_SERVER + "/api/detail?" + urllib.parse.urlencode({"id": cve_id})
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.load(resp)
    except Exception as e:
        print(f"[Retriever] 详情获取失败({cve_id}): {e}")
        return {}


def enrich_desc(results: List[Dict]) -> List[Dict]:
    """检索结果回填 desc：/api/search 的卡片只带高亮片段（snippet），
    不含完整描述；生成答案前补上 desc，避免上下文里「描述」为空。"""
    for r in results:
        if r.get("desc"):
            continue
        d = get_detail(r.get("id", ""))
        if d and d.get("desc"):
            r["desc"] = d["desc"]
    return results


def retrieve(query: str, top_k: int = None) -> List[Dict]:
    """混合检索主入口（问答链路用）：关键词 + 语义融合，返回 top_k 条。"""
    if top_k is None:
        top_k = RETRIEVER_CONFIG["final_top_k"]
    return hybrid_search(query, top_k)["results"]
