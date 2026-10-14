# -*- coding: utf-8 -*-
"""
evaluate.py —— 检索准确率评测与消融实验
==========================================
评测设计：
  · 标准答案（Ground Truth）**不依赖检索管线**，而是由结构化字段严格判定
    （CPE 厂商/产品精确匹配、描述字面命中、CWE 编号），避免自证循环。
  · 指标：P@5 / P@10 / R@20 / MRR@10 / nDCG@10 / 首条命中位置
  · 消融：Full（四层） vs 去概念层 vs 去扩展层，量化每层的增益。
    —— 中文提问与英文语料存在语言鸿沟，扩展层的增益最能说明问题。

运行： python evaluate.py
输出： data/eval_report.json （供技术报告引用）
"""

import io
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# 安全 UTF-8 输出：用 reconfigure 而非重建 TextIOWrapper，
# 否则模块被 import 时会关闭原 stdout（合并/复用场景下的隐患）
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception as _sw_e:  # noqa: BLE001 —— 非标准流（如已被重定向）时忽略
    _swallow("core/evaluate.py:27", _sw_e)
from engine import SearchEngine  # noqa: E402
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = paths.data_path("corpus.json")

VECTOR_DB = {"chroma", "chromadb", "milvus", "qdrant", "weaviate", "pgvector", "faiss", "lancedb", "pymilvus"}


def has_prod(names):
    ns = {n.lower() for n in names}
    return lambda d: bool(ns & {p.lower() for p in d.get("products", []) + d.get("vendors", [])})


def desc_has(*keys):
    return lambda d: any(k in (d.get("desc", "") + " " + d.get("title", "")).lower() for k in keys)


def cwe_has(*ids):
    return lambda d: any(w["id"] in ids for w in d.get("cwe", []))


def AND(*fns):
    return lambda d: all(f(d) for f in fns)


def OR(*fns):
    return lambda d: any(f(d) for f in fns)


# ==========================================================================
# 查询集（中英混合，覆盖四类风险与多种意图）
# ==========================================================================
QUERIES = [
    # ---- 组件定位类（英文） ----
    ("ollama vulnerabilities", has_prod(["ollama"]), "① 推理框架"),
    ("vllm security issue", has_prod(["vllm"]), "① 推理框架"),
    ("nvidia triton inference server vulnerability", has_prod(["triton", "triton-inference-server"]), "① 推理框架"),
    ("langchain vulnerability", has_prod(["langchain", "langchain-core"]), "③ 应用智能体"),
    ("gradio vulnerability", has_prod(["gradio"]), "③ 应用智能体"),
    ("jupyter notebook vulnerability", has_prod(["jupyter", "jupyterlab"]), "④ 供应链"),
    ("huggingface transformers vulnerability", has_prod(["transformers", "huggingface-hub", "huggingface_hub"]), "② 模型数据"),

    # ---- 漏洞类型类（英文） ----
    ("prompt injection vulnerability", desc_has("prompt injection"), "② 模型数据"),
    ("insecure deserialization machine learning model",
     OR(cwe_has("CWE-502"), desc_has("deserializ")), "② 模型数据"),
    ("path traversal vulnerability", OR(cwe_has("CWE-22"), desc_has("path traversal", "directory traversal")), "① 推理框架"),
    ("remote code execution", desc_has("remote code execution", "arbitrary code execution"), "① 推理框架"),
    ("model context protocol MCP vulnerability",
     OR(desc_has("model context protocol", "mcp "), has_prod(["mcp", "modelcontextprotocol"])), "③ 应用智能体"),
    ("jailbreak large language model bypass", desc_has("jailbreak"), "② 模型数据"),
    ("supply chain attack third party dependency", desc_has("supply chain"), "④ 供应链"),
    ("server-side request forgery", OR(cwe_has("CWE-918"), desc_has("server-side request forgery", "ssrf")), "① 推理框架"),
    ("data poisoning training data", desc_has("poisoning", "poisoned"), "② 模型数据"),
    ("vector database vulnerability", has_prod(list(VECTOR_DB)), "② 模型数据"),

    # ---- 组件定位类（中文提问 → 英文语料） ----
    ("ollama 有哪些漏洞", has_prod(["ollama"]), "① 推理框架"),
    ("vllm 的漏洞", has_prod(["vllm"]), "① 推理框架"),
    ("langchain 安全问题", has_prod(["langchain", "langchain-core"]), "③ 应用智能体"),

    # ---- 漏洞类型类（中文提问） ----
    ("提示词注入漏洞", desc_has("prompt injection"), "② 模型数据"),
    ("反序列化漏洞", OR(cwe_has("CWE-502"), desc_has("deserializ")), "② 模型数据"),
    ("路径穿越漏洞", OR(cwe_has("CWE-22"), desc_has("path traversal", "directory traversal")), "① 推理框架"),
    ("远程代码执行漏洞", desc_has("remote code execution", "arbitrary code execution"), "① 推理框架"),
    ("越狱绕过大模型", desc_has("jailbreak"), "② 模型数据"),
    ("供应链投毒", desc_has("poisoning", "supply chain"), "④ 供应链"),
    ("向量数据库漏洞", has_prod(list(VECTOR_DB)), "② 模型数据"),
    ("智能体框架漏洞", OR(has_prod(["langchain", "langchain-core", "autogen", "crewai", "dify", "flowise"]),
                    desc_has("ai agent", "agentic")), "③ 应用智能体"),
    ("模型窃取攻击", desc_has("model extraction", "model theft"), "② 模型数据"),
    ("服务端请求伪造", OR(cwe_has("CWE-918"), desc_has("server-side request forgery", "ssrf")), "① 推理框架"),
    ("任意文件读取", desc_has("arbitrary file read", "path traversal"), "① 推理框架"),

    # ---- CVE 号精确检索 ----
    ("CVE-2024-37032", lambda d: d["id"] == "CVE-2024-37032", "精确定位"),

    # ---- 注：原「全领域安全」查询块（⑤ Web安全 / ⑥ 系统二进制 / ⑧ 云原生 /
    #      ⑨ 身份访问 / ⑩ 恶意代码 / 工具仓库 / 文章教程）已移除。
    #      语料已收敛为 AI 安全四大类（非 AI 一律舍弃），保留这些查询会因
    #      语料中不存在对应文档而把 P@5/MRR 拉低，产出误导性的评测报告。 ----
]

K_LIST = [5, 10, 20]


# ==========================================================================
# 指标
# ==========================================================================
def dcg(rels):
    return sum(r / math.log2(i + 2) for i, r in enumerate(rels))


def metrics(ranked_ids, gt_flags, total_rel):
    m = {}
    for k in K_LIST:
        top = ranked_ids[:k]
        hits = sum(gt_flags.get(i, 0) for i in top)
        m[f"P@{k}"] = hits / k
        m[f"R@{k}"] = hits / total_rel if total_rel else 0.0
    # MRR@10
    mrr = 0.0
    for idx, i in enumerate(ranked_ids[:10], 1):
        if gt_flags.get(i):
            mrr = 1 / idx
            break
    m["MRR@10"] = mrr
    # nDCG@10
    rels = [gt_flags.get(i, 0) for i in ranked_ids[:10]]
    ideal = sorted(gt_flags.values(), reverse=True)[:10]
    m["nDCG@10"] = dcg(rels) / dcg(ideal) if dcg(ideal) > 0 else 0.0
    # 首条命中位置
    first = next((idx for idx, i in enumerate(ranked_ids, 1) if gt_flags.get(i)), None)
    m["first_hit"] = first
    return m


def avg(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    vals = [0 if v is None else v for v in vals]
    return round(sum(vals) / len(vals), 4) if vals else 0.0


# ==========================================================================
# 消融变体
# ==========================================================================
class NoConcept(SearchEngine):
    """去掉 L3 概念空间层"""
    def __init__(self, p):
        super().__init__(p)
        self.concept_vecs = [{} for _ in self.docs]

    def parse_query(self, q, expand=True):
        qp = super().parse_query(q, expand=expand)
        qp["concepts"] = {}
        return qp


class NoExpand(SearchEngine):
    """去掉中英术语扩展与概念层（退化为纯字段加权 BM25）"""
    def __init__(self, p):
        super().__init__(p)
        self.concept_vecs = [{} for _ in self.docs]

    def parse_query(self, q, expand=True):
        import re
        import engine as E
        low = (q or "").lower()
        ids = [m.group(0).upper() for m in E.CVE_RE.finditer(q or "")]
        terms = {}
        from collections import Counter
        c = Counter(E.tokenize(low))
        terms.update(c)
        return {"raw": q, "ids": ids, "terms": dict(terms), "phrases": [],
                "concepts": {}, "expansion": [], "cn_terms": [],
                "intent": self._detect_intent(low)[0], "intent_evidence": []}


def run(engine, name):
    rows = []
    for q, label, group in QUERIES:
        gt = {d["id"]: 1 for d in engine.docs if label(d)}
        total_rel = len(gt)
        r = engine.search(q, top_k=20, page=1)
        ranked = [x["id"] for x in r["results"]]
        m = metrics(ranked, gt, total_rel)
        m.update({"query": q, "group": group, "n_rel": total_rel,
                  "recall_pool": round(min(total_rel, 20) / total_rel, 3) if total_rel else 0})
        rows.append(m)
    return rows


def summarize(rows, name):
    keys = ["P@5", "P@10", "R@20", "MRR@10", "nDCG@10"]
    s = {k: avg(rows, k) for k in keys}
    hits = [r["first_hit"] for r in rows if r["first_hit"]]
    s["首条命中均位"] = round(sum(hits) / len(hits), 2) if hits else None
    s["零命中查询数"] = sum(1 for r in rows if not r["first_hit"])
    s["查询总数"] = len(rows)
    print(f"\n=== {name} ===")
    for k, v in s.items():
        print(f"  {k:16s} {v}")
    return s


def main():
    print("构建索引 ...")
    full = SearchEngine(CORPUS)
    print(f"文档 {len(full.docs)} 条 | 评测查询 {len(QUERIES)} 条")

    out = {}
    all_rows = {}
    for name, eng in [("Full（词法+短语+概念+重排）", full),
                      ("- 去概念层", NoConcept(CORPUS)),
                      ("- 去概念层与术语扩展（纯BM25）", NoExpand(CORPUS))]:
        rows = run(eng, name)
        all_rows[name] = rows
        out[name] = summarize(rows, name)

    print("\n=== 分组表现（Full） ===")
    from collections import defaultdict
    grp = defaultdict(list)
    for r in all_rows["Full（词法+短语+概念+重排）"]:
        grp[r["group"]].append(r)
    for g, rs in grp.items():
        print(f"  {g:10s} P@5={avg(rs,'P@5'):.3f}  R@20={avg(rs,'R@20'):.3f}  nDCG@10={avg(rs,'nDCG@10'):.3f}  n={len(rs)}")

    print("\n=== 逐条明细（Full，按 P@5 升序） ===")
    for r in sorted(all_rows["Full（词法+短语+概念+重排）"], key=lambda x: x["P@5"]):
        flag = "  " if r["P@5"] >= 0.6 else ("△ " if r["P@5"] > 0 else "✗ ")
        print(f"  {flag}P@5={r['P@5']:.2f} R@20={r['R@20']:.2f} nDCG={r['nDCG@10']:.2f} "
              f"首中={r['first_hit']} n_rel={r['n_rel']:3d} | {r['query']}")

    with open(paths.data_path("eval_report.json"), "w", encoding="utf-8") as f:
        json.dump({"summary": out, "detail": all_rows}, f, ensure_ascii=False, indent=1)
    print("\n报告已写入 data/eval_report.json")
    return out


if __name__ == "__main__":
    main()
