# -*- coding: utf-8 -*-
"""
link_papers.py —— 后处理：把离线论文知识库关联到CVE记录（宽松匹配）
按论文标题核心词直接匹配 rec.title/desc/category/products。
"""
import json, os, sys, io, re
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 安全 UTF-8 输出设置：用 reconfigure 而非重建 TextIOWrapper，
# 否则模块被 import 时会关闭原 stdout（合并/复用场景下的隐患）
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception as _sw_e:
    _swallow("modules/m1_monitor/backend/link_papers.py:19", _sw_e)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = paths.DATA_DIR
EC = os.path.join(DATA, "enriched_cache.json")
PK = os.path.join(DATA, "papers_kb.json")


def load(p, d):
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as _sw_e:
            _swallow("modules/m1_monitor/backend/link_papers.py:33", _sw_e)
    return d


# 每篇论文的核心匹配关键词（小写）
PAPER_KEYWORDS = {
    "Not What You've Signed Up For": ["prompt injection", "indirect prompt", "rag", "retrieval"],
    "Jailbroken: How Does LLM Safety Training Fail?": ["jailbreak", "safety training", "alignment"],
    "Universal Adversarial Triggers": ["adversarial", "universal trigger", "nlp attack"],
    "Explaining and Harnessing Adversarial Examples": ["adversarial example", "adversarial", "fgsm"],
    "Adversarial Examples in the Physical World": ["adversarial", "physical world"],
    "Backdoor Learning: A Survey": ["backdoor", "poisoning", "trojan"],
    "Poisoning and Back Attack of Pre-Trained Models": ["poisoning", "pre-trained", "supply chain", "backdoor"],
    "Stealing Machine Learning Models via Prediction APIs": ["model extraction", "model stealing", "model theft"],
    "Extracting Training Data from Large Language Models": ["training data", "memorization", "training data leakage"],
    "Membership Inference Attack against Machine Learning Models": ["membership inference", "membership"],
    " membership Inference Attacks from First Principles": ["membership inference", "membership"],
    "Deep Leakage from Gradients": ["gradient leakage", "federated learning", "gradient"],
    "Deep Learning with Differential Privacy": ["differential privacy", "dp-sgd", "privacy"],
    "RAG Defence: Mitigating Indirect Prompt Injection": ["prompt injection", "rag", "retrieval-augmented"],
    "Prompt Injection attack against LLM-integrated Applications": ["prompt injection", "tool", "agent"],
    "Semantic Prompt Injection Attacks on LLMs": ["prompt injection", "semantic"],
    "AgentBench: Evaluating LLMs as Agents": ["agent", "agentic", "tool use"],
    "ToolEmu: LLM-integrated Tool Security Evaluation": ["tool", "agent", "tool call"],
    "Constitutional AI: Harmlessness from AI Feedback": ["alignment", "rlhf", "constitutional"],
    "Red Teaming Language Models to Reduce Harms": ["red team", "safety", "harassment", "jailbreak"],
    "A Watermark for Large Language Models": ["watermark", "provenance", "deepfake"],
}


def match_papers(rec, papers):
    text = (rec.get("title", "") + " " + rec.get("desc", "") + " " +
            " ".join(rec.get("products", [])) + " " + rec.get("category", "")).lower()
    matched = []
    for p in papers:
        title = p["title"]
        kws = PAPER_KEYWORDS.get(title, [])
        hits = sum(1 for k in kws if k in text)
        if hits >= 1:
            matched.append({
                "title": title,
                "url": p.get("url", ""),
                "published": p.get("published", ""),
                "authors": p.get("authors", []),
                "venue": p.get("categories", []),
                "source": p.get("source", ""),
                "summary": (p.get("summary", "") or "")[:420],
            })
    return matched[:3]


def main():
    ec = load(EC, {"done": [], "records": []})
    pk = load(PK, {"papers": []})
    papers = pk["papers"]
    records = ec["records"]
    print(f"records={len(records)} papers={len(papers)}")

    linked = 0
    for rec in records:
        # 只关联AI安全类记录（scope=AI安全或category是①-④）
        is_ai = rec.get("scope") == "AI安全" or rec.get("category", "").startswith(("①", "②", "③", "④"))
        if not is_ai:
            continue
        papers_match = match_papers(rec, papers)
        if papers_match:
            rec["papers"] = papers_match
            linked += 1

    tmp = EC + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ec, f, ensure_ascii=False)
    os.replace(tmp, EC)
    print(f"关联完成：{linked} 条AI记录关联到论文")


if __name__ == "__main__":
    main()
