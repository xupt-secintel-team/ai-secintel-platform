# -*- coding: utf-8 -*-
"""
augment.py —— 语料增量富化（不重复抓取 NVD）
================================================
对已生成的 data/corpus.json 做三项补强：

  1. 论文关联：重新抓取 arXiv（含重试与退避），按特征词共现把论文挂到漏洞上
  2. 组件推断：NVD 中大量新披露漏洞尚无 CPE（状态 Awaiting Analysis），
     导致「受影响资产」维度缺失 —— 改为从描述文本中用组件名表做有界匹配补齐
  3. CWE 名称补全 + 组件名归一化（下划线 → 连字符，保证检索一致性）

运行： python augment.py
"""

import io
import json
import os
import re
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 注意：stdout 的 UTF-8 包装只在 __main__ 下做——本模块会被 monitor/server 导入，
# 模块级包装会替换宿主进程的 stdout（服务端输出会被连带破坏）。

import fetch_corpus as F  # noqa: E402
import papers as P  # noqa: E402
import extra_sources as X  # noqa: E402
from atlas import AtlasKB  # noqa: E402
from taxonomy import AI_PRODUCTS  # noqa: E402
from engine import SearchEngine  # noqa: E402
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）


HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = paths.data_path("corpus.json")
PAPER_CACHE = paths.data_path("papers.json")
QUERY_CACHE = paths.data_path("paper_queries.json")

# 论文检索式：AI 安全各方向（arXiv 主源 + Crossref 备源，均可消化该语法）
PAPER_QUERIES = [
    'all:"prompt injection"',
    'all:"large language model" AND all:"vulnerability"',
    'all:"LLM agent" AND all:"security"',
    'all:"model extraction attack"',
    'all:"adversarial machine learning" AND all:"security"',
    'all:"jailbreak" AND all:"language model"',
    'prompt injection large language model vulnerability',
    'LLM agent security attack framework',
    'machine learning supply chain security',
    'model stealing extraction attack neural network',
    # —— 扩充方向（2026-09 修订：覆盖 RAG / MCP / 智能体 / 防护栏 / 红队）——
    'all:"RAG poisoning"',
    'all:"retrieval augmented generation" AND all:"attack"',
    'all:"model context protocol" AND all:"security"',
    'all:"LLM guardrails" AND all:"safety"',
    'all:"AI red teaming"',
    'all:"membership inference" AND all:"language model"',
    'all:"LLM firewall" AND all:"injection"',
    'all:"agentic AI" AND all:"security"',
    # —— 扩充（2026-09-23：间接注入 / 后门 / 系统提示词 / CTF）——
    'all:"indirect prompt injection"',
    'all:"system prompt" AND all:"leak"',
    'all:"backdoor" AND all:"large language model"',
    'all:"LLM" AND all:"CTF" AND all:"security"',
    'all:"model inversion"',
    'all:"watermarking" AND all:"language model"',
    # —— 全领域安全方向（通用网络安全学术研究）——
    'all:"sql injection" AND all:"detection"',
    'all:"cross-site scripting" AND all:"detection"',
    'all:"web application security" AND all:"vulnerability"',
    'all:"fuzzing" AND all:"vulnerability discovery"',
    'all:"malware detection" AND all:"deep learning"',
    'all:"intrusion detection" AND all:"deep learning"',
    'all:"ransomware" AND all:"detection"',
    'all:"vulnerability detection" AND all:"code"',
    'all:"smart contract" AND all:"vulnerability detection"',
    'all:"android malware" AND all:"detection"',
    'all:"software vulnerability" AND all:"prediction"',
    'all:"phishing" AND all:"detection" AND all:"machine learning"',
    'all:"botnet" AND all:"detection"',
    'all:"static analysis" AND all:"vulnerability"',
    'all:"container security" AND all:"kubernetes"',
]

# 不适合作文本推断的通用短名（易误命中或语义过于宽泛）
INFER_BLACK = {"mcp", "torch", "numpy", "docker", "kubernetes", "airflow", "keras",
               "openai", "anthropic", "datasets", "tokenizers", "superset", "streamlit",
               "n8n", "accelerate", "onnx", "jupyter"}
INFER_NAMES = sorted(
    [n for n in AI_PRODUCTS if n not in INFER_BLACK and len(n) >= 3 and not n.isdigit()],
    key=len, reverse=True,
)

EXTRA_CWE = {
    "CWE-401": "Missing Release of Memory", "CWE-346": "Origin Validation Error",
    "CWE-441": "Confused Deputy", "CWE-918": "Server-Side Request Forgery",
    "CWE-74": "Injection", "CWE-138": "Improper Neutralization of Special Elements",
    "CWE-158": "Improper Neutralization of Null Byte", "CWE-193": "Off-by-one Error",
    "CWE-208": "Observable Timing Discrepancy", "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions", "CWE-319": "Cleartext Transmission",
    "CWE-327": "Broken Crypto Algorithm", "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-354": "Improper Validation of Integrity Check Value", "CWE-367": "TOCTOU Race Condition",
    "CWE-436": "Interpretation Conflict", "CWE-444": "HTTP Request Smuggling",
    "CWE-459": "Incomplete Cleanup", "CWE-489": "Active Debug Code",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-540": "Information Exposure Through Source Code", "CWE-552": "Files Accessible to External Parties",
    "CWE-565": "Reliance on Cookies without Validation", "CWE-610": "Externally Controlled Reference",
    "CWE-639": "Authorization Bypass Through User-Controlled Key", "CWE-641": "Improper Restriction of Names",
    "CWE-657": "Violation of Secure Design Principles", "CWE-674": "Uncontrolled Recursion",
    "CWE-693": "Protection Mechanism Failure", "CWE-754": "Improper Check for Unusual Conditions",
    "CWE-755": "Improper Handling of Exceptional Conditions", "CWE-835": "Infinite Loop",
    "CWE-843": "Type Confusion", "CWE-909": "Missing Initialization of Resource",
    "CWE-917": "Expression Language Injection", "CWE-1004": "Sensitive Cookie Without HttpOnly",
    "CWE-1173": "Improper Use of Validation Framework", "CWE-1187": "DEPRECATED",
    "CWE-1230": "Exposure of Sensitive Information Through Metadata",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-1299": "Missing Protection Mechanism for Alternate Hardware Interface",
    "CWE-1333": "Inefficient Regular Expression Complexity",
    "CWE-1389": "Incorrect Parsing of Numbers with Different Radices",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompting",
    "CWE-1426": "Improper Validation of Generative AI Output",
    "CWE-150": "Improper Neutralization of Escape/Control Sequences",
}
F.CWE_NAMES.update(EXTRA_CWE)


def norm_product(p):
    return (p or "").replace("_", "-").strip().lower()


def infer_products(rec):
    """从描述中做有界组件匹配，补齐缺失的受影响组件"""
    blob = (rec.get("desc", "") + " " + rec.get("title", "")).lower()
    found = []
    for n in INFER_NAMES:
        pat = r"(?<![a-z0-9])" + re.escape(n).replace(r"\ ", r"[\s\-_]") + r"(?![a-z0-9])"
        if re.search(pat, blob):
            found.append(n)
    # 归一化 + 去重，保留最短的互为前缀者
    out = []
    for n in sorted(set(found), key=len):
        if not any(n != o and (n.startswith(o + "-") or n.endswith("-" + o)) for o in out):
            out.append(n)
    return out[:6]


# --------------------------------------------------------------------------
# KEV 定向补充采集：CISA KEV 里的 AI 组件条目 = 高价值在野利用情报，
# 很可能不在常规关键词采集范围内（如 LiteLLM / Langflow），必须主动并入。
# --------------------------------------------------------------------------
KEV_ALIASES = {
    "litellm": "litellm", "berriai": "litellm", "langflow": "langflow", "langfuse": "langfuse",
    "openwebui": "open-webui", "flowiseai": "flowise", "n8n": "n8n", "ray-project": "ray",
    "jupyter": "jupyter", "huggingface": "huggingface-hub", "mlflow": "mlflow",
    "superset": "superset", "airflow": "airflow", "anythingllm": "anythingllm",
    "comfyui": "comfyui", "gradio": "gradio", "dify": "dify", "milvus": "milvus",
    "qdrant": "qdrant", "weaviate": "weaviate", "chroma": "chromadb",
    "vllm": "vllm", "triton": "triton", "ollama": "ollama", "langchain": "langchain",
}
KEV_NAMES = sorted(set(AI_PRODUCTS) | set(KEV_ALIASES), key=len, reverse=True)
KEV_CACHE = paths.data_path("kev_cve_cache.json")


def kev_supplement(records, papers):
    """把 CISA KEV 中属于 AI 组件的条目补入语料（缺则按 CVE 号回捞 NVD）"""
    try:
        kev = F.fetch_kev()
    except Exception as e:  # noqa: BLE001
        print("KEV 下载失败，跳过补充采集：", e)
        return 0

    have = {r["id"] for r in records}
    matched = []
    for cid, ent in kev.items():
        blob = f"{ent.get('vendor','')} {ent.get('product','')} {ent.get('short_desc','')}".lower()
        hits = sorted({n for n in KEV_NAMES
                       if re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", blob)})
        if hits:
            matched.append((cid, hits))
    print(f"KEV 中属于 AI 组件的条目：{len(matched)} 条，其中 {sum(1 for c, _ in matched if c not in have)} 条不在语料中")

    # 命中别名时归一化为标准组件名
    norm_hits = {}
    for cid, hits in matched:
        norm_hits[cid] = sorted({KEV_ALIASES.get(h, h) for h in hits})

    cache = {}
    if os.path.isfile(KEV_CACHE):
        with open(KEV_CACHE, "r", encoding="utf-8") as f:
            cache = json.load(f)

    todo = [cid for cid, _ in matched if cid not in have and cid not in cache]
    if todo:
        print(f"需回捞 NVD 的条目：{len(todo)} 条")
        for i, cid in enumerate(todo, 1):
            try:
                cve = F.fetch_nvd_cve(cid)
                if cve:
                    cache[cid] = cve
                print(f"  [{i}/{len(todo)}] {cid} {'OK' if cve else 'EMPTY'}", flush=True)
            except Exception as e:  # noqa: BLE001
                print(f"  [{i}/{len(todo)}] {cid} 失败：{str(e)[:60]}", flush=True)
            time.sleep(6.5)   # NVD 无 Key 限速
        with open(KEV_CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)

    added = 0
    for cid, hits in matched:
        if cid in have or cid not in cache:
            continue
        rec = F.build_record(cache[cid], kev, {}, papers, extra_products=norm_hits.get(cid, hits))
        if rec is None:
            continue
        rec["tags"].append("KEV定向补充")
        rec["intake"] = "KEV 定向补充采集（在野利用驱动）"
        records.append(rec)
        added += 1
    print(f"KEV 补充新增情报：{added} 条")
    return added


def main():
    print("载入语料 ...")
    with open(CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    records = corpus["records"]

    # ---------- 0. 学术论文（arXiv 主源 + Crossref 备源，增量采集） ----------
    papers = []
    done_queries = []
    if os.path.isfile(PAPER_CACHE):
        with open(PAPER_CACHE, "r", encoding="utf-8") as f:
            papers = json.load(f)
        print(f"复用论文缓存：{len(papers)} 篇")
    if os.path.isfile(QUERY_CACHE):
        with open(QUERY_CACHE, "r", encoding="utf-8") as f:
            done_queries = json.load(f)
    new_queries = [q for q in PAPER_QUERIES if q not in done_queries]
    if new_queries:
        print(f"新增检索方向 {len(new_queries)} 组，增量抓取（arXiv + Crossref）...")
        got = P.collect(new_queries)
        seen = {p["title"].lower()[:180] for p in papers}
        add = 0
        for p in got:
            k = p["title"].lower()[:180]
            if k and k not in seen:
                seen.add(k)
                papers.append(p)
                add += 1
        print(f"  增量新增 {add} 篇，论文池合计 {len(papers)} 篇")
        with open(PAPER_CACHE, "w", encoding="utf-8") as f:
            json.dump(papers, f, ensure_ascii=False, indent=1)
        done_queries = list({*done_queries, *PAPER_QUERIES})
        with open(QUERY_CACHE, "w", encoding="utf-8") as f:
            json.dump(done_queries, f, ensure_ascii=False, indent=1)
    else:
        print("论文检索方向无变化，全部命中缓存")
    corpus["papers"] = papers
    print(f"论文合计：{len(papers)}")

    # ---------- 1. KEV 定向补充采集（在野利用驱动的增量监测） ----------
    n_kev_new = kev_supplement(records, papers)

    # ---------- 1.5 扩展数据源（GitHub Advisory / GitHub 仓库 / CSDN 文章） ----------
    X_OUT = paths.data_path("extra_sources.json")
    if "--refresh-extra" in sys.argv or not os.path.isfile(X_OUT):
        extra = X.collect_all()
    else:
        with open(X_OUT, "r", encoding="utf-8") as f:
            extra = json.load(f)
        print(f"复用扩展源缓存（GitHub/CSDN）：repo {len(extra['repos'])} / "
              f"article {len(extra['articles'])} / GHSA {extra['meta'].get('ghsa', 0)}（--refresh-extra 强制重抓）")

    # GHSA 与已有 CVE 去重合并：公告信息并入原记录（来源、公告链接、受影响包）
    n_merge = 0
    rec_by_id = {r["id"].upper(): r for r in records}
    for cve, advisories in (extra.get("ghsa_by_cve") or {}).items():
        r = rec_by_id.get(cve)
        if not r:
            continue
        for a in advisories:
            if "GitHub Advisory" not in r["sources"]:
                r["sources"].append("GitHub Advisory")
            for u in a.get("advisory_links", []):
                if u not in r["advisory_links"]:
                    r["advisory_links"].append(u)
            for pkg in a.get("products", []):
                pkg_n = norm_product(pkg)
                if pkg_n and pkg_n not in r["osv_packages"] and pkg_n not in r["products"]:
                    r["osv_packages"].append(pkg_n)
            if a.get("desc") and a["desc"] not in r.get("osv_summaries", []):
                r.setdefault("osv_summaries", []).append(
                    "GitHub Advisory " + a["id"] + "：" + a["desc"][:300])
            if "供应链公告" not in r["tags"]:
                r["tags"].append("供应链公告")
            n_merge += 1
    print(f"GitHub 公告并回已有 CVE：{n_merge} 处")

    extra_knowledge = list(extra.get("ghsa_standalone") or []) \
        + list(extra.get("repos") or []) + list(extra.get("articles") or [])
    print(f"扩展源知识条目：{len(extra_knowledge)} 条（GHSA 独立 / 仓库 / 文章）")
    # 论文也转为可检索知识条目（论文研究方向从此可被直接检索，而非仅依附漏洞关联）
    paper_knowledge = X.papers_to_knowledge(papers)
    print(f"论文知识条目：{len(paper_knowledge)} 篇")
    extra_knowledge = extra_knowledge + paper_knowledge

    # ---------- 2. 组件名归一化 ----------
    for r in records:
        r["products"] = sorted({norm_product(p) for p in r.get("products", []) if p and p != "*"})
        r["vendors"] = sorted({norm_product(v) for v in r.get("vendors", []) if v and v != "*"})

    # ---------- 3. 组件推断 ----------
    n_infer = 0
    for r in records:
        if r["products"]:
            continue
        got = infer_products(r)
        if got:
            r["products"] = got
            r["product_source"] = "描述文本推断"
            n_infer += 1
    print(f"从描述推断出受影响组件：{n_infer} 条")

    # ---------- 4. CWE 名称补全 ----------
    for r in records:
        for w in r.get("cwe", []):
            if not w.get("name"):
                w["name"] = F.CWE_NAMES.get(w["id"], "")

    # ---------- 4.5 重分类与重打分（组件补齐后，分类规则需重新应用） ----------
    kept, dropped = [], 0
    for r in records:
        ok, score, cat, reason, tags = F.classify(r)
        # 全领域扩展：非 AI 记录不再丢弃，按通用安全分类保留
        r["scope"] = "AI安全" if ok else "通用安全"
        r["ai_score"], r["category"], r["category_reason"], r["risk_tags"] = score, cat, reason, tags
        t = list(tags) + [cat]
        if r.get("kev"):
            t.append("在野利用")
        if r.get("poc_links"):
            t.append("存在POC")
        r["tags"] = sorted(set(t))
        kept.append(r)
    records[:] = kept
    n_ai = sum(1 for r in records if r.get("scope") == "AI安全")
    print(f"重分类：保留 {len(records)} 条（AI安全 {n_ai} / 通用安全 {len(records) - n_ai}）")

    # ---------- 4.6 MITRE ATLAS 威胁技术映射（补齐模型层风险覆盖） ----------
    print("接入 MITRE ATLAS 威胁知识库 ...")
    try:
        kb = AtlasKB()
    except Exception as e:  # noqa: BLE001
        print("  ATLAS 不可用，跳过该富化维度：", str(e)[:160])
        kb = None
    if kb is not None:
        print("  ATLAS：", kb.stats())
        n_atlas = 0
        for r in records:
            # ATLAS 是 AI 威胁知识库：仅映射 AI 安全域记录（通用安全记录直接置空，省时且避免误映射）
            if r.get("scope", "AI安全") != "AI安全":
                r["atlas"], r["atlas_evidence"], r["atlas_mitigations"] = [], [], []
                continue
            techs, why = kb.map_record(r)
            r["atlas"] = techs
            r["atlas_evidence"] = why
            if techs:
                n_atlas += 1
                r["atlas_mitigations"] = kb.mitigations_for([t["id"] for t in techs])
            else:
                r["atlas_mitigations"] = []
        corpus["atlas"] = {
            "version": kb.version,
            "tactics": [{"id": k, "name": v} for k, v in kb.tactics.items()],
            "technique_count": len(kb.tech),
            "mitigation_count": len(kb.mitigations),
            "case_study_count": len(kb.case_studies),
        }
        # ATLAS 技术本身转为可检索知识条目（模型层风险没有 CVE，必须靠知识库覆盖）
        knowledge = kb.to_records()
        # 扩展源知识条目并入同一知识底座
        knowledge = knowledge + extra_knowledge
        corpus["knowledge"] = knowledge
        print(f"知识条目合计：{len(knowledge)} 条（ATLAS {len(kb.tech)} + 扩展源 {len(extra_knowledge)}）")
        print(f"映射到 ATLAS 技术的漏洞：{n_atlas} 条 / {len(records)}")
        print("  ATLAS 技术命中分布：",
              Counter(t["id"] + " " + t["name"] for r in records for t in r.get("atlas", [])).most_common(10))

    # ---------- 5. 论文关联（全量重算，含新增条目） ----------
    if papers:
        n_link = 0
        for r in records:
            r["papers"] = F.link_papers(r, papers)
            if r["papers"]:
                n_link += 1
        print(f"成功关联论文的漏洞：{n_link} 条")

    # ---------- 6. 重算修复建议（依赖补全后的组件与链接） ----------
    for r in records:
        r["remediation"] = F.remediation(r)

    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    corpus["meta"].update({
        "papers": len(papers),
        "augmented_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "product_inferred": n_infer,
        "kev_supplemented": n_kev_new,
        "records": len(records),
        "records_with_product": sum(1 for r in records if r["products"]),
        "extra_sources": {
            "ghsa_advisories": extra["meta"].get("ghsa", 0),
            "ghsa_merged": n_merge,
            "repos": len(extra.get("repos") or []),
            "articles": len(extra.get("articles") or []),
        },
    })

    with open(CORPUS, "w", encoding="utf-8") as f:
        # 紧凑格式（2026-09-30）：同 fetch_corpus.py —— indent=1 让文件膨胀
        # 60%+，直接影响解析耗时、索引缓存体积和冷启动时间。
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    print(f"已保存 {CORPUS} ({os.path.getsize(CORPUS)/1024/1024:.2f} MB)")

    # ---------- 概览 ----------
    print("\n情报条目总数：", len(records))
    print("有受影响组件：", sum(1 for r in records if r["products"]))
    print("产品 TOP15：", Counter(p for r in records for p in r["products"]).most_common(15))
    print("关联论文：", sum(1 for r in records if r["papers"]))
    print("含POC：", sum(1 for r in records if r["poc_links"]))
    print("在野利用：", sum(1 for r in records if r["kev"]))
    print("重建索引校验 ...")
    e = SearchEngine(CORPUS)
    print("  索引文档：", len(e.docs), " 词项：", len(e.df), " 平均文档长度：", round(e.avgdl, 1))


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
