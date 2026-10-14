# -*- coding: utf-8 -*-
"""
legacy_rag.py — 【已归档·无入口，请勿在此继续开发】
================================================================
原名 rag_engine.py，2026-10-06 代码核查（全项目 grep 引用 + 追 import 链）
确认**零引用**：`qa/__init__.py` 只 import multi_hop / generator / config，
全项目没有任何文件 import 本模块，接口层也不引用。

它实现的是**单轮 RAG**（一次检索 → 拼上下文 → LLM/模板生成），
已被 `multi_hop.py`（迭代多跳 + 推理链）+ `generator.py` 完全取代。
两者并存的实际危害：新人（或以后的自己）会改错文件 ——
改这里完全不生效，但看代码时很难察觉。

保留而不删的理由：里面的意图识别正则与工具调用骨架仍是
`multi_hop` 的对照参考，且删除属于不可逆操作，需要用户明确同意。
在它被真正用起来之前，任何"顺手改进"都应改在 multi_hop.py 上。

如果要复活它：必须在 qa/__init__.py 里显式 import 并加路由，
同时把 tools/_test_ops_observability.py 之外的死代码检查删掉这条豁免。

架构（原实现，供对照）：
  用户问题 → 意图识别 → 检索相关文档 → 拼上下文 → [LLM生成答案] → 返回
  Agent模式下：LLM可调用工具（search_cve / get_detail / get_related）多步推理
"""
import urllib.request
import urllib.parse
import json
import re
from typing import List, Dict, Optional

import os
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass
MAIN_SERVER = os.environ.get("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")


# ============================================================
# 工具函数（Agent可调用的工具，全部对接主搜索服务）
# ============================================================

def tool_search(query: str, size: int = 5) -> List[Dict]:
    """工具1：关键词/语义搜索"""
    url = MAIN_SERVER + "/api/search?" + urllib.parse.urlencode({"q": query, "size": size})
    with urllib.request.urlopen(url, timeout=30) as resp:
        d = json.load(resp)
    return d.get("results", [])


def tool_get_detail(cve_id: str) -> Dict:
    """工具2：获取单个CVE完整详情"""
    url = MAIN_SERVER + "/api/search?" + urllib.parse.urlencode({"q": cve_id, "size": 1})
    with urllib.request.urlopen(url, timeout=30) as resp:
        d = json.load(resp)
    results = d.get("results", [])
    return results[0] if results else {}


def tool_get_related(cve_id: str) -> Dict:
    """工具3：获取关联推荐（同组件/同CWE/同攻击技术）"""
    url = MAIN_SERVER + "/api/related?id=" + urllib.parse.quote(cve_id)
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


def tool_get_graph(cve_id: str) -> Dict:
    """工具4：获取关系图谱"""
    url = MAIN_SERVER + "/api/graph?id=" + urllib.parse.quote(cve_id)
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


# Agent可用工具注册表（后面接LLM function calling时直接用）
AGENT_TOOLS = [
    {
        "name": "search_vulnerability",
        "description": "搜索AI安全漏洞情报，输入关键词/组件名/CVE编号，返回相关漏洞列表",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "搜索关键词"}}}
    },
    {
        "name": "get_cve_detail",
        "description": "获取指定CVE的完整详情，包括CVSS评分、受影响产品、描述、修复建议",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string", "description": "CVE编号，如CVE-2024-5565"}}}
    },
    {
        "name": "get_related",
        "description": "获取与指定CVE相关的其他漏洞（同组件/同CWE/同攻击技术）",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string", "description": "CVE编号"}}}
    },
]


# ============================================================
# 意图识别
# ============================================================

def classify_query(question: str) -> str:
    q = question.lower().strip()
    if re.search(r'cve-\d{4}-\d{4,7}', q):
        return "cve_detail"
    if any(kw in q for kw in ["影响", "哪些产品", "受影响", "哪些组件", "哪些版本"]):
        return "affected_products"
    if any(kw in q for kw in ["修复", "怎么修", "补丁", "缓解", "应对", "怎么办"]):
        return "fix_advice"
    if any(kw in q for kw in ["法", "规", "标准", "政策", "合规", "条例"]):
        return "policy"
    if any(kw in q for kw in ["攻击", "利用", "poc", "exp", "攻击链", "手法", "原理"]):
        return "attack"
    if any(kw in q for kw in ["最新", "最近", "今天", "这周", "新出"]):
        return "latest"
    return "general"


# ============================================================
# LLM生成（预留接口——后面接大模型只改这个函数）
# ============================================================

def llm_generate(question: str, context_docs: List[Dict], history: List[Dict] = None) -> str:
    """
    【预留】调用大模型生成回答。
    当前为模板模式，接入真实LLM时只需要替换这个函数的内部实现。

    接入示例（OpenAI兼容接口，比如通义/DeepSeek/豆包）：
        import openai
        client = openai.OpenAI(base_url="https://api.xxx.com/v1", api_key="你的key")
        prompt = build_prompt(question, context_docs, history)
        resp = client.chat.completions.create(
            model="模型名",
            messages=[
                {"role": "system", "content": "你是AI安全情报助手，基于知识库回答问题"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return resp.choices[0].message.content
    """
    # TODO: 替换为真实LLM调用
    return _template_generate(question, context_docs, history)


def build_prompt(question: str, context_docs: List[Dict], history: List[Dict] = None) -> str:
    """构造给LLM的prompt（后面接LLM时用）"""
    context_text = "\n\n".join([
        f"[文档{i+1}] {d.get('title','')}\nID: {d.get('id','')}\nCVSS: {d.get('cvss',{}).get('score','N/A')}\n{d.get('description','')[:500]}"
        for i, d in enumerate(context_docs[:5])
    ])
    history_text = ""
    if history:
        history_text = "\n历史对话：\n" + "\n".join([f"{h['role']}: {h['content']}" for h in history[-4:]])

    return f"""你是AI安全情报助手。请根据以下知识库资料回答用户问题。
要求：
1. 答案必须基于提供的资料，不要编造
2. 引用具体CVE编号和数据
3. 用中文回答，条理清晰
4. 如果资料里没有答案，直接说不知道

{history_text}

知识库资料：
{context_text}

用户问题：{question}
回答："""


def _template_generate(question: str, results: List[Dict], history: List[Dict] = None) -> str:
    """当前模板模式生成（无LLM时用）"""
    if not results:
        return f"未在知识库中找到与「{question}」直接相关的情报。建议换个关键词或直接搜索CVE编号。"

    top = results[:3]
    qtype = classify_query(question)
    parts = []

    if qtype == "cve_detail":
        r = top[0]
        parts.append(f"## {r['id']} 漏洞详情\n")
        parts.append(f"**标题**：{r['title']}\n")
        cvss = r.get("cvss", {})
        if cvss.get("score"):
            parts.append(f"**CVSS评分**：{cvss['score']}（{cvss.get('severity','')}）\n")
        parts.append(f"**发布时间**：{r.get('published','未知')}\n")
        if r.get("products"):
            parts.append(f"**受影响产品**：{', '.join(r['products'][:8])}\n")
        if r.get("cwe"):
            cwe_ids = [c.get("id","") for c in r["cwe"][:5]]
            parts.append(f"**关联CWE**：{', '.join(cwe_ids)}\n")
        parts.append(f"**数据可信度**：{r.get('trust_label','')}\n")

    elif qtype == "affected_products":
        parts.append(f"根据知识库检索，与「{question}」相关的主要受影响组件：\n")
        all_products = set()
        for r in top:
            for p in r.get("products", []):
                all_products.add(p)
        if all_products:
            for p in sorted(all_products)[:15]:
                parts.append(f"- {p}\n")
        crit = sum(1 for r in results if r.get("cvss",{}).get("severity")=="CRITICAL")
        parts.append(f"\n共{len(results)}条相关情报，其中严重级{crit}条。\n")

    elif qtype == "fix_advice":
        parts.append(f"针对「{question}」的修复建议：\n")
        parts.append("1. 及时升级到厂商最新修复版本\n2. 限制暴露面，仅内网访问\n3. 部署WAF/IDS监控异常请求\n")
        parts.append("\n相关漏洞参考：\n")
        for r in top:
            parts.append(f"- [{r['id']}] {r['title'][:60]}\n")

    else:
        parts.append(f"关于「{question}」，检索到{len(results)}条相关情报：\n\n")
        for i, r in enumerate(top, 1):
            cvss = r.get("cvss", {})
            parts.append(f"### {i}. [{r['id']}] {r['title']}\n")
            parts.append(f"- CVSS：{cvss.get('score','N/A')}（{cvss.get('severity','')}）\n\n")

    return "".join(parts)


# ============================================================
# Agent多步推理（预留框架）
# ============================================================

def agent_reasoning(question: str, history: List[Dict] = None) -> List[Dict]:
    """
    规则版多步推理（当前实现，无需LLM）。
    根据问题类型自动调用多个工具，汇总结果后返回。
    后面接LLM后，把这里换成LLM自主决定调哪些工具即可。
    """
    qtype = classify_query(question)

    # 第一步：基础搜索
    results = tool_search(question, size=8)

    # 第二步：根据问题类型自动追加工具调用（规则版多步推理）
    extra_context = []

    # 如果是CVE详情查询，自动拉关联推荐（跨文档：主漏洞+关联漏洞一起返回）
    if qtype == "cve_detail" and results:
        cve_id = results[0]["id"]
        try:
            rel = tool_get_related(cve_id)
            for item in rel.get("top_overall", [])[:3]:
                extra_context.append({
                    "id": item["id"],
                    "title": item.get("title", ""),
                    "cvss": {"score": item.get("cvss"), "severity": item.get("severity", "")},
                    "published": item.get("published", ""),
                    "products": [],
                    "cwe": [],
                    "trust_label": item.get("trust_label", ""),
                    "confidence": item.get("confidence", 0),
                    "_relation": "related"
                })
        except Exception as _sw_e:
            _swallow("modules/m3_qa/backend/qa/legacy_rag.py:238", _sw_e)

    # 如果是修复建议类问题，自动补充补丁/修复相关情报
    if qtype == "fix_advice" and results:
        try:
            fix_results = tool_search(question + " patch fix", size=3)
            existing_ids = {x["id"] for x in results}
            for r in fix_results:
                if r["id"] not in existing_ids:
                    results.append(r)
        except Exception as _sw_e:
            _swallow("modules/m3_qa/backend/qa/legacy_rag.py:249", _sw_e)

    # 合并结果：原始结果在前，补充的在后
    return results + extra_context


# ============================================================
# 主入口
# ============================================================

def ask(question: str, history: Optional[List[Dict]] = None) -> Dict:
    """
    问答主入口
    - question: 用户问题
    - history: 历史对话 [{"role":"user","content":"..."}, {"role":"assistant","content":"..."}]
    """
    qtype = classify_query(question)

    # 多轮上下文：从最近4轮历史里提取CVE编号，拼进搜索词
    search_query = question
    if history:
        for h in reversed(history[-4:]):
            cve_match = re.search(r'cve-\d{4}-\d{4,7}', h.get("content", ""), re.I)
            if cve_match and qtype not in ("cve_detail",):
                search_query = f"{cve_match.group()} {question}"
                break

    # 检索（Agent模式下这里会做多步工具调用）
    try:
        results = agent_reasoning(search_query, history)
    except Exception as e:
        return {
            "answer": f"检索服务暂时不可用：{str(e)[:100]}",
            "sources": [], "related": [], "confidence": 0,
            "error": "search_unavailable"
        }

    # 生成答案（当前模板，后面换LLM自动生成）
    answer_text = llm_generate(question, results, history)

    # 构造返回
    sources = []
    for r in results[:3]:
        sources.append({
            "id": r["id"],
            "title": r["title"],
            "cvss": r.get("cvss", {}).get("score"),
            "severity": r.get("cvss", {}).get("severity"),
            "published": r.get("published", ""),
            "trust_label": r.get("trust_label", ""),
            "confidence": r.get("confidence", 0),
        })

    avg_conf = sum(r.get("confidence", 0) for r in results[:3]) / min(3, len(results)) if results else 0

    return {
        "answer": answer_text,
        "sources": sources,
        "related": [r["id"] for r in results[3:8]],
        "confidence": round(avg_conf, 1),
        "query_type": qtype,
        "search_query": search_query,
        "total_found": len(results),
        "mode": "template",  # 接了LLM后改成 "llm"
    }
