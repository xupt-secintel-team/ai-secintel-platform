# -*- coding: utf-8 -*-
"""
query_anchor.py —— 把"改写式提问"锚定到真实产品名（第 3 轮新增）
================================================================
实测发现的问题（2026-10-08，第 3 轮）：

  用户要求"支持跨文档的语义检索"，但实测**不含产品名的改写式提问会大面积跑偏**：
    问「本地跑开源大模型的那个工具，有文件读取安全问题」→ 期望 Ollama，
      实测返回 dspy / llama-hub / stanza / snappy（全错）
    问「搭建大模型推理服务时，那个框架存在代码执行问题」→ 期望 vLLM，
      实测返回 rpyc（全错）

  为什么阈值救不了：实测这类改写问句与**正确产品描述句**的余弦是
  0.906~0.926，而**错误结果**的余弦是 0.9046~0.9071 —— **两者在噪声内不可分**。
  换句话说：这不是"门槛调低/调高"的问题，是**该问句压根没锚点**。

  根本原因：向量库的元数据只保留了 `title`（建库时嵌入了 title+desc[:1000]，
  但 `search()` 返回的 `desc` 是空串），而语料里 AI 框架类条目的 title 很短
  （`Ollama (HEAD f0...`），无法承载"本地跑开源大模型的工具"这种描述性语义。

  解决办法（本模块）：**在检索前把改写式提问锚定到真实产品名**。
  即"用户说的是人话（本地跑开源大模型的工具），系统知道他其实在问 Ollama"，
  然后把产品名作为检索词补进查询 —— 这样关键词路与语义路就都有了锚点。

设计原则：
  - **只认本项目领域内的产品**（AI 框架 / 安全工具），不做通用百科；
  - 映射表是**可维护的显式数据**，不是黑盒；加产品只需加一行；
  - **只在"提问里没有产品名"时才介入**（提问里本来就写了 Ollama 就不要动它）；
  - 命中多个候选时全部返回，交给检索层去融合（不擅自替用户选一个）。
"""
from __future__ import annotations

import re
from typing import Dict, List

# ── 领域产品词表：产品名 → 触发线索（别名 / 中文描述 / 典型说法） ──────────
# 说明：线索用**小写子串**匹配（中文直接子串）。宁可多列线索、不要漏 ——
# 命中后只是把产品名补进检索式，多補一个词不会把结果带偏（反而提高召回）。
PRODUCT_HINTS: Dict[str, List[str]] = {
    "ollama": ["ollama", "本地跑", "本地运行", "本地部署", "本地模型",
               "开源大模型工具", "跑开源大模型", "本地大模型"],
    "vllm": ["vllm", "推理服务", "推理引擎", "高吞吐", "服务引擎", "部署推理",
             "大模型推理", "模型服务"],
    "langchain": ["langchain", "编排", "llm 应用", "应用框架", "工具链",
                  "agent 框架", "链式调用"],
    "langflow": ["langflow"],
    "llamaindex": ["llamaindex", "llama_index", "llama-index", "rag 框架"],
    "ray": ["ray", "分布式计算"],
    "sglang": ["sglang"],
    "mlflow": ["mlflow", "模型管理", "实验跟踪"],
    "dify": ["dify"],
    "gradio": ["gradio"],
    "streamlit": ["streamlit"],
    "transformers": ["transformers", "huggingface"],
    "vllm-ascend": ["vllm-ascend"],
    # 安全类工具（本项目语料里常出现）
    "burp": ["burp", "burpsuite", "抓包"],
    "nmap": ["nmap", "端口扫描"],
    "metasploit": ["metasploit", "msf"],
    "wireshark": ["wireshark"],
}

# 产品名本身（用于判"提问里已经写了产品名没有"）
_ALL_PRODUCTS = set(PRODUCT_HINTS.keys())


def _has_product(query: str) -> bool:
    """提问里是否**已经出现**产品名（出现就不需要锚定）。"""
    q = (query or "").lower()
    for p in _ALL_PRODUCTS:
        if p in q:
            return True
    # 也认常见写法（大小写已在 lower 里统一）
    return False


def anchor_products(query: str, limit: int = 3) -> List[str]:
    """从改写式提问里锚定候选产品名。

    返回**按线索匹配强度排序**的产品名列表（可能为空 = 没有可锚定的）。
    例：
      "本地跑开源大模型的那个工具，有文件读取的安全问题" → ["ollama"]
      "编排 LLM 应用的工具链有没有注入风险"          → ["langchain"]
      "Ollama 有哪些漏洞"（已含产品名）              → []
    """
    q = (query or "").lower()
    if _has_product(q):
        return []                      # 用户已经点名，不插手
    scored: List[tuple] = []
    for prod, hints in PRODUCT_HINTS.items():
        hit = 0
        for h in hints:
            if h in q:
                hit += len(h)          # 更长的线索更具体 → 权重更高
        if hit:
            scored.append((hit, prod))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [p for _, p in scored[:limit]]


def expand_query(query: str, limit: int = 3) -> str:
    """把锚定到的产品名补进查询串（供检索层直接使用）。

    没有可锚定的就原样返回 —— 绝不无中生有。
    """
    prods = anchor_products(query, limit=limit)
    if not prods:
        return query
    return ("%s %s" % (query, " ".join(prods))).strip()


def anchor_note(query: str) -> str:
    """给答案附一句"我把你的说法锚定成了谁"（可解释、可复核）。"""
    prods = anchor_products(query)
    if not prods:
        return ""
    return "（已把提问中的描述锚定为候选产品：%s）" % "、".join("`%s`" % p for p in prods)
