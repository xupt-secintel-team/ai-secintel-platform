# -*- coding: utf-8 -*-
"""
config.py — 问答模块配置
LLM 和 Embedding 都做成多供应商可切换，填哪个用哪个。

密钥优先级（从高到低）：
  1. 前端设置页传入（POST /api/chat 的 base_url / api_key / model）
  2. 环境变量 AISEC_LLM_API_KEY / AISEC_LLM_BASE_URL / AISEC_LLM_MODEL
  3. 本文件里对应供应商的 api_key

  安全提示：本文件会随项目一起分发（含共享盘）。**不要**把真实 API Key
  写进这里提交；推荐用环境变量，或只在前端设置页里临时填写。
  未配置 Key 时系统自动降级为「模板模式」（基于检索证据拼装答案，不调用大模型），
  问答接口依然可用。
"""
import os

# ============ LLM 多供应商配置 ============
# 选一个用：把 LLM_PROVIDER 改成下面其中一个名字就行
# 支持：deepseek / doubao / qwen / openai / custom
LLM_PROVIDER = os.environ.get("AISEC_LLM_PROVIDER", "deepseek")

LLM_PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key": "",              # 在此填 DeepSeek Key，或设环境变量 AISEC_LLM_API_KEY
        "model": "deepseek-chat",
    },
    "doubao": {
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "api_key": "",              # 在此填豆包/火山 Key
        "model": "doubao-pro-4k",
    },
    "qwen": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key": "",              # 在此填通义千问 Key
        "model": "qwen-turbo",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key": "",
        "model": "gpt-3.5-turbo",
    },
    "custom": {
        "base_url": "",             # 自定义接口地址（OpenAI 兼容）
        "api_key": "",
        "model": "",
    },
}

LLM_CONFIG = dict(LLM_PROVIDERS[LLM_PROVIDER])

# 环境变量覆盖（推荐用法，避免把 Key 写进随项目分发的文件）
if os.environ.get("AISEC_LLM_BASE_URL"):
    LLM_CONFIG["base_url"] = os.environ["AISEC_LLM_BASE_URL"]
if os.environ.get("AISEC_LLM_API_KEY"):
    LLM_CONFIG["api_key"] = os.environ["AISEC_LLM_API_KEY"]
if os.environ.get("AISEC_LLM_MODEL"):
    LLM_CONFIG["model"] = os.environ["AISEC_LLM_MODEL"]

LLM_CONFIG["temperature"] = 0.3
LLM_CONFIG["max_tokens"] = 2000

# ============ Embedding 多供应商配置 ============
# 选一个用：把 EMBEDDING_PROVIDER 改成下面其中一个名字就行
# 支持：openai / local / custom
EMBEDDING_PROVIDER = os.environ.get("AISEC_EMBEDDING_PROVIDER", "openai")

EMBEDDING_PROVIDERS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key": "",              # 填 OpenAI embedding key（或用上面 LLM 同一个 key）
        "model": "text-embedding-3-small",
        "dimension": 1536,
    },
    "local": {
        # 本地 bge-m3，后面跑本地模型用
        "model": "bge-m3",
        "dimension": 1024,
    },
    "custom": {
        "base_url": "",
        "api_key": "",
        "model": "",
        "dimension": 1024,
    },
}

EMBEDDING_CONFIG = EMBEDDING_PROVIDERS[EMBEDDING_PROVIDER]

# ============ 向量库配置 ============
VECTOR_CONFIG = {
    "persist_dir": "data/vector_store",   # ① 语义向量库（NumPy 后端：embeddings.npy + meta.jsonl）
    "collection_name": "vulns",
    "top_k": 10,
}

# ============ 检索配置 ============
# 问答模块通过 HTTP 调用主检索服务；主服务换端口时改这里（或设环境变量）
MAIN_SERVER = os.environ.get("AISEC_MAIN_SERVER", "http://127.0.0.1:8848")

RETRIEVER_CONFIG = {
    "bm25_top_k": 50,
    "vector_top_k": 35,
    "final_top_k": 8,
    # 融合权重：关键词 0.7 / 语义 0.3（分数归一化后加权）。
    # 为什么不是 50/50：实测 50/50 排名融合会让 @10 从 90% 掉到 87.5%、P50 涨 100ms
    # （关键词排对的结果被语义"泛相关"顶下去），见 测试报告/检索评测.md 第五、七节。
    # v2.1 加强：候选池从 30/20 扩到 50/35 —— 仅增大召回候选，融合后top_k不变，
    # 不会把已命中的结果顶掉，但能让"排在第 11~30 的相关条目"进入融合视野，抬高@10。
    "bm25_weight": 0.7,
    "vector_weight": 0.3,
}

# ============ 答案产出配置（结论 + 原始详细资料） ============
ANSWER_CONFIG = {
    # 结论字数上限（字符数）—— 前端置顶展示，超出由 qa/report.py 硬截断并标注
    "conclusion_limit": int(os.environ.get("AISEC_QA_CONCLUSION_LIMIT", 3600)),
    # 附带的「原始详细资料」最多条数（每条可点开全文详情）
    "evidence_limit": int(os.environ.get("AISEC_QA_EVIDENCE_LIMIT", 12)),
}

# ============ 超时与响应预算（2026-10-06 补） ============
# 为什么必须有：此前三处 LLM 调用（generator / multi_hop planner / agent）
# 都没传 timeout —— 上游 LLM 一旦挂住不返回，整个问答请求会无限期占住线程，
# 用户看到的就是"页面一直转圈"。评分要求"深度问答响应可控"，先要有硬上限。
#
# AISEC_LLM_TIMEOUT   单次 LLM 调用超时秒数（默认 45）
# AISEC_QA_BUDGET     一次问答的端到端预算秒数（默认 25）。
#                     超预算不返回空，而是**降级**为"用已检索到的证据出模板结论"，
#                     保证任何情况下都有可读答案，并在 reasoning_chain 里标记超时点。
LLM_TIMEOUT = float(os.environ.get("AISEC_LLM_TIMEOUT", "45") or 45)
LLM_MAX_RETRIES = int(os.environ.get("AISEC_LLM_RETRIES", "1") or 1)
QA_BUDGET = float(os.environ.get("AISEC_QA_BUDGET", "25") or 25)

# 迭代多跳：最大跳数与每跳新增实体上限
# （多跳是"上一跳结果派生下一跳查询"，见 multi_hop.py::_iterative_expand）
MULTI_HOP_MAX_HOPS = int(os.environ.get("AISEC_QA_MAX_HOPS", "3") or 3)
MULTI_HOP_FOCUS_PER_HOP = int(os.environ.get("AISEC_QA_HOP_FOCUS", "3") or 3)

# ============ 系统提示词 ============
SYSTEM_PROMPT = """你是AI安全情报助手，基于知识库中的漏洞数据回答用户问题。

【输出结构（必须遵守）】
1. **结论先行**：开头直接给出结论段——本次命中多少条、风险分布如何、
   最该处置的是哪几个编号（带 CVSS 与严重等级）、建议动作是什么。
   读者只看结论段就能决策，不需要往后翻。
2. 结论之后再写要点分析（分点、按严重程度排序），每点必须落到具体编号上。
3. **全文不超过 {limit} 字**，宁可精简也不要灌水重复资料里已有的字段。

【事实约束】
4. 答案必须引用具体CVE编号，格式如[CVE-2024-1234]
5. 如果知识库中没有相关信息，直接说"知识库中未找到相关情报"，绝对不许编造CVE编号、CVSS评分或受影响产品
6. 回答用中文，条理清晰，分点说明
7. 涉及多个漏洞时，按严重程度排序（CRITICAL > HIGH > MEDIUM > LOW）
8. 提到CVSS评分时同时给出严重等级
9. 只使用「知识库资料」中出现的信息，不做无证据推断
""".replace("{limit}", str(ANSWER_CONFIG["conclusion_limit"]))
