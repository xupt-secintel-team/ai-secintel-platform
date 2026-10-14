# -*- coding: utf-8 -*-
"""
generator.py — RAG答案生成
把检索到的文档拼进prompt，调LLM生成带引用的回答
支持从请求里传LLM配置，不用写死在config里
"""
import os
import re
import sys
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qa.config import SYSTEM_PROMPT, LLM_CONFIG, LLM_PROVIDERS
from qa.config import LLM_TIMEOUT, LLM_MAX_RETRIES
from qa.report import (CONCLUSION_LIMIT, build_evidence, clip, summarize)


def _plain_desc(d: Dict) -> str:
    """取用于上下文的描述文本：
    优先 desc（详情接口字段）；缺失时回退 snippet（检索卡片的高亮片段，需去 HTML 标签）。"""
    txt = d.get("desc") or ""
    if not txt:
        sni = d.get("snippet") or ""
        if sni:
            txt = re.sub(r"<[^>]+>", "", sni).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    return txt


def build_context(docs: List[Dict]) -> str:
    """把检索到的文档拼成上下文文本"""
    context_parts = []
    for i, d in enumerate(docs, 1):
        cvss = d.get("cvss", {}) or {}
        products = ", ".join(d.get("products", [])[:5]) or "未知"
        cwe = ", ".join(w.get("id", "") for w in (d.get("cwe") or [])[:3])
        trust = d.get("trust_label") or ""
        conf = d.get("confidence")
        part = f"""[文档{i}] CVE编号: {d.get('id','')}
标题: {d.get('title','')}
CVSS评分: {cvss.get('score','N/A')} ({cvss.get('severity','')})
发布时间: {d.get('published','未知')}
受影响产品: {products}
弱点类型: {cwe or '未知'}
数据来源: {', '.join(d.get('sources', [])) or '未知'}{('  可信度: ' + str(trust) + ('/置信度' + str(conf) if conf is not None else '')) if trust else ''}
描述: {_plain_desc(d)[:400]}
"""
        context_parts.append(part)
    return "\n---\n".join(context_parts)


def build_messages(question: str, docs: List[Dict], history: List[Dict] = None) -> List[Dict]:
    """构造给LLM的messages"""
    context = build_context(docs)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # 历史对话
    if history:
        for h in history[-6:]:  # 只保留最近3轮
            messages.append({"role": h["role"], "content": h["content"]})

    # 当前问题+上下文
    user_prompt = f"""知识库资料：
{context}

用户问题：{question}

请按 SYSTEM 要求的「结论先行」结构回答：
第一段直接给出结论（含关键数字与最高风险条目编号），全文不超过 {CONCLUSION_LIMIT} 字；
结论之后再补证据要点，每点必须引用对应的CVE编号。
不要罗列"检索到以下情报"这类套话，也不要重复粘贴资料里的字段。"""

    messages.append({"role": "user", "content": user_prompt})
    return messages


def generate(question: str, docs: List[Dict], history: List[Dict] = None, llm_config: dict = None) -> Dict:
    """
    生成答案
    - llm_config: 用户自己传的LLM配置（base_url, api_key, model），不传就用config.py里的默认值
    返回：{answer: str, sources: [...], used_llm: bool}
    """
    if not docs:
        # ★ 第 4 轮实测修正（R4-A）：这里原先返回一段**自造文案**，绕过了
        #   `_template_generate` 里那条更完整的 `no_hit_note`（含"已尝试的检索词"
        #   与结构化算子的建议），而且**不带 `empty_reason`** ——
        #   前端/评测拿不到"为什么是空的"（no_relevant / expired / error 无法区分）。
        #   现在统一走 no_hit_note，并如实标注 empty_reason。
        try:
            from qa.relevance import no_hit_note
            _note = no_hit_note(question)
        except Exception:  # noqa: BLE001
            _note = ("## 结论\n**知识库中没有与该问题匹配的情报。**\n\n"
                     "请换用更具体的产品名 / CVE 编号 / CWE 编号再问一次。\n")
        return {
            "answer": _note,
            "conclusion": _note,
            "sources": [],
            "evidence": [],
            "evidence_total": 0,
            "used_llm": False,
            "empty_reason": "no_relevant",
        }

    # 合并配置：用户传的优先，没有就用默认的
    cfg = {**LLM_CONFIG}
    if llm_config:
        cfg.update(llm_config)

    # 显式要求不走大模型（自测/离线演示/省钱）：直接用证据模板
    if cfg.get("disable_llm"):
        out = _template_generate(question, docs)
        out["llm_disabled"] = True
        return out

    # 如果没配key，用模板模式
    if not cfg.get("api_key"):
        return _template_generate(question, docs)

    # 调LLM生成
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url=cfg["base_url"],
            api_key=cfg["api_key"],
            # max_retries 是客户端构造参数，不是 create() 的参数 ——
            # openai 3.x 里传给 create() 会抛 unexpected keyword argument。
            max_retries=LLM_MAX_RETRIES,
        )
        messages = build_messages(question, docs, history)
        resp = client.chat.completions.create(
            model=cfg["model"],
            messages=messages,
            temperature=cfg.get("temperature", 0.3),
            max_tokens=cfg.get("max_tokens", 2000),
            # 2026-10-06：此前无超时。生成环节超时会自动落到 _template_generate
            # （下 except 分支），用户拿到的是检索式结论而不是一直转圈。
            timeout=cfg.get("timeout") or LLM_TIMEOUT,
        )
        answer = resp.choices[0].message.content

        # 提取引用的CVE
        sources = []
        for d in docs[:5]:
            sources.append({
                "id": d["id"],
                "title": d.get("title", ""),
                "cvss": (d.get("cvss", {}) or {}).get("score"),
                "severity": (d.get("cvss", {}) or {}).get("severity", ""),
            })

        # 结论：LLM 全文即结论（finalize 会按 3600 字上限截断）；
        # 原始详细资料：把证据池整包给前端，点开即见全文，不再靠一句"引用来源"
        return {"answer": answer, "sources": sources, "used_llm": True,
                "model": cfg.get("model"),
                "conclusion": answer, "evidence": build_evidence(docs)}

    except Exception as e:
        print(f"[Generator] LLM调用失败: {e}，降级到模板模式")
        out = _template_generate(question, docs)
        out["llm_error"] = str(e)[:200]     # 让前端能解释「为什么没走大模型」
        out["model"] = cfg.get("model")
        return out


def _dedupe_deep(conclusion: str, deep: str) -> str:
    """汇总段已经给出「主要受影响组件」时，去掉深度层重复的组件分布段。

    两段算的是同一件事（按组件计数），结论里出现两遍只会让人怀疑哪个准。
    """
    if not deep or "主要受影响组件" not in conclusion:
        return deep
    parts = re.split(r"(?m)^(?=## )", deep)
    return "".join(p for p in parts if not p.startswith("## 结论（聚合统计·组件分布）"))


def _template_generate(question: str, docs: List[Dict]) -> Dict:
    """模板模式（没配LLM时用）：**结论先行**，再附原始详细资料清单

    v2.2：接入 deep_answer 深度分析层 ——
    ① 条件链降噪：KEV/CVSS/POC 硬约束先过滤证据再渲染（附录不再混入不满足条件的条目）；
    ② 深度推理段落：极值/比较结论、受影响版本、关联论文（全部确定性计算、带可复核依据）。

    v2.4：结论不再由"逐条罗列"代替 —— 先对证据池做确定性聚合（严重度分布 / KEV /
    POC / 最高 CVSS / 组件与弱点分布 / 时间跨度）产出**一句话结论 + 要点**，
    再把每条情报作为「原始详细资料」挂到答案后面（前端可点开全文）。
    """
    from qa.deep_answer import parse_constraints, filter_by_constraints, deep_sections
    from qa.content_answer import content_section

    # ── 零命中诚实化（v2.6）：上游相关度闸门判定"一条都不相关"时，
    #    必须如实回答"知识库中没有匹配情报"，**不能**用固定条数兜底凑数。
    #    这是"精准回答"的底线：用户宁可被告知"没有"，也不愿被一份像样的
    #    假报告误导（实测：不存在的术语此前会返回 8 条无关情报 + "命中 8 条"）。
    if not docs:
        try:
            from qa.relevance import no_hit_note
            note = no_hit_note(question)
        except Exception:  # noqa: BLE001
            note = ("## 结论\n**知识库中没有与该问题匹配的情报。**\n\n"
                    "请换用更具体的产品名 / CVE 编号 / CWE 编号再问一次。\n")
        return {"answer": note, "sources": [], "used_llm": False,
                "conclusion": note, "evidence": [], "evidence_total": 0,
                "empty_reason": "no_relevant"}

    docs = filter_by_constraints(docs, parse_constraints(question))
    deep = deep_sections(question, docs)

    # ── 结论分两层，单独成段，供前端置顶渲染 ──
    #  ① 内容要点（v2.5 新增）：直接回答问题 —— 从命中资料的正文/处置字段
    #     抽出的编号要点，每条带来源编号（原来这一层是缺的，结论只剩来源统计）；
    #  ② 情报汇总（原有，保留）：命中条数 / 风险分布 / 时间跨度 / 数据来源。
    content = content_section(question, docs)
    stats = summarize(question, docs)
    conclusion = (content + "\n" + stats) if content else stats
    if deep:
        conclusion += "\n" + _dedupe_deep(conclusion, deep).rstrip() + "\n"
    conclusion, _ = clip(conclusion)

    parts = [conclusion, "\n## 原始详细资料\n\n"]

    for i, d in enumerate(docs[:8], 1):
        cvss = d.get("cvss", {}) or {}
        parts.append(f"### {i}. [{d['id']}] {d.get('title','')}\n")
        parts.append(f"- CVSS: {cvss.get('score','N/A')} ({cvss.get('severity','')})\n")
        parts.append(f"- 发布: {d.get('published','未知')}\n")
        prods = "、".join(d.get("products", [])[:5])
        if prods:
            parts.append(f"- 受影响组件: {prods}\n")
        cwes = "、".join(w.get("id", "") for w in (d.get("cwe") or [])[:3])
        if cwes:
            parts.append(f"- 弱点类型: {cwes}\n")
        if d.get("trust_label"):
            parts.append(f"- 来源可信度: {d['trust_label']}"
                         + (f" / 交叉验证 {d['cross_label']}" if d.get("cross_label") else "")
                         + (f" / 综合置信度 {d['confidence']}" if d.get("confidence") is not None else "")
                         + "\n")
        if d.get("kev"):
            parts.append("- ⚠ 已被 CISA 列入在野利用清单，建议优先处置\n")
        if d.get("poc_count"):
            parts.append(f"- 存在 {d['poc_count']} 条公开 POC/EXP 链接\n")
        parts.append("\n")

    if len(docs) > 8:
        parts.append("其他相关情报：" + "、".join(x.get("id", "") for x in docs[8:16]) + "\n\n")

    # 显式列出所有检索证据里的漏洞编号 / 弱点类型，保证答案自带实体（可复核、可关联）
    cve_ids = [d.get("id") for d in docs if str(d.get("id") or "").startswith(("CVE-", "GHSA-"))]
    if cve_ids:
        parts.append("涉及漏洞条目：" + "、".join(cve_ids[:8]) + "\n")
    all_cwes = []
    for d in docs:
        for w in (d.get("cwe") or [])[:2]:
            wid = w.get("id") if isinstance(w, dict) else str(w)
            if wid and wid not in all_cwes:
                all_cwes.append(wid)
    if all_cwes:
        parts.append("涉及弱点类型：" + "、".join(all_cwes[:8]) + "\n")
    parts.append("提示：配置大模型 API Key 后可获得带引用与修复建议的自然语言回答。")

    sources = []
    for d in docs[:5]:
        sources.append({
            "id": d["id"],
            "title": d.get("title", ""),
            "cvss": (d.get("cvss", {}) or {}).get("score"),
            "severity": (d.get("cvss", {}) or {}).get("severity", ""),
        })

    return {"answer": "".join(parts), "sources": sources, "used_llm": False,
            "conclusion": conclusion, "evidence": build_evidence(docs)}
