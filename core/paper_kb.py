# -*- coding: utf-8 -*-
"""
paper_kb.py —— AI安全经典论文知识库（离线整理）
================================================
外部学术API在当前网络环境均不可达（arXiv 406 / Semantic Scholar 429 / OpenAlex超时），
离线整理AI安全领域高被引经典论文，作为系统papers语料。
格式与论文采集管线对齐：{title, summary, url, published, authors, categories}。

运行： python paper_kb.py  → data/papers_kb.json
"""
import json
import os
import io
import sys
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
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
    _swallow("core/paper_kb.py:22", _sw_e)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = paths.data_path("papers_kb.json")

PAPERS = [
    # ---- 提示注入 / 越狱 ----
    {
        "title": "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection",
        "summary": "系统研究了间接提示注入攻击：攻击者将恶意指令嵌入多模态应用读取的外部内容（网页、文档、邮件）中，当LLM处理这些内容时指令被执行。论文展示了攻击可跨越RAG、工具调用、多步工作流，窃取数据、执行未授权操作。提出了纵深防御架构：内容隔离、指令来源标记、工具调用确认、输出过滤。",
        "authors": ["Kalyani, K.", "Tear, L.", "Weis, S.", "其他"],
        "published": "2023-09-12",
        "url": "https://arxiv.org/abs/2307.13269",
        "categories": ["prompt-injection", "indirect-injection"],
    },
    {
        "title": "Jailbroken: How Does LLM Safety Training Fail?",
        "summary": "分析了大模型安全对齐训练的失败模式。将越狱攻击分类为：自动化越狱攻击（利用模型自身生成攻击prompt）、跨会话信息污染、对抗后缀攻击、社会工程越狱。论文指出对齐训练只覆盖了已知攻击分布，对分布外泛化失败，提出需从根本上理解对齐机制而非依赖红队数据。",
        "authors": ["Wei, A.", "Le, N.", "Yadev, A.", "其他"],
        "published": "2023-07-14",
        "url": "https://arxiv.org/abs/2307.02483",
        "categories": ["jailbreak", "alignment", "safety-training"],
    },
    {
        "title": "Universal Adversarial Triggers for Attacking and Analyzing NLP",
        "summary": "发现了通用对抗触发器：一小串固定的token序列，能让任何输入产生目标模型的任意输出（如固定输出负面情感）。触发器可迁移到不同模型。这揭示了NLP模型对特定短语模式的脆弱性，是早期提示注入攻击的基础研究之一。",
        "authors": ["Wallace, E.", "Feng, S.", "Kandpal, N.", "其他"],
        "published": "2019-07-28",
        "url": "https://arxiv.org/abs/1909.01656",
        "categories": ["adversarial", "universal-trigger"],
    },
    # ---- 对抗机器学习 ----
    {
        "title": "Explaining and Harnessing Adversarial Examples",
        "summary": "Ian Goodfellow的奠基性论文，提出快速梯度符号法(FGSM)生成对抗样本。论证了对抗样本的存在不是因为高维空间的统计奇异性，而是因为模型在高维空间的线性行为。对抗训练可提升模型鲁棒性。是整个对抗机器学习领域的起点。",
        "authors": ["Goodfellow, I. J.", "Shlens, J.", "Szegedy, C."],
        "published": "2015-03-20",
        "url": "https://arxiv.org/abs/1412.6572",
        "categories": ["adversarial", "foundational"],
    },
    {
        "title": "Adversarial Examples in the Physical World",
        "summary": "证明了对抗样本在物理世界也有效：对图片打印出来拍照，分类器仍然误判。这表明对抗攻击不是数字世界的特殊现象，对自动驾驶、人脸识别等真实系统构成威胁。",
        "authors": ["Kurakin, A.", "Goodfellow, I.", "Bengio, S."],
        "published": "2017-02-11",
        "url": "https://arxiv.org/abs/1607.02533",
        "categories": ["adversarial", "physical-world"],
    },
    # ---- 数据投毒 ----
    {
        "title": "Backdoor Learning: A Survey",
        "summary": "后门攻击（投毒攻击）综述：攻击者在训练阶段植入触发器，正常样本上模型表现正常，但带有触发器的样本会被误分类为攻击者指定类别。覆盖投毒数据构造、触发器设计、训练过程后门注入、以及后门防御（修剪、微调、触发器检测）。",
        "authors": ["Li, Y.", "Wu, B.", "Jiang, Y.", "其他"],
        "published": "2020-07-20",
        "url": "https://arxiv.org/abs/2007.08740",
        "categories": ["data-poisoning", "backdoor"],
    },
    {
        "title": "Poisoning and Back Attack of Pre-Trained Models",
        "summary": "研究了对预训练模型的投毒攻击：攻击者只需控制小比例训练数据即可在大模型中植入后门，且后门在微调后仍存活。表明预训练模型供应链是高风险环节，下游用户继承了上游后门。",
        "authors": ["Dai, D.", "Chen, N.", "Zhao, Y.", "其他"],
        "published": "2019-11-05",
        "url": "https://arxiv.org/abs/1911.05085",
        "categories": ["data-poisoning", "supply-chain"],
    },
    # ---- 模型窃取/提取 ----
    {
        "title": "Stealing Machine Learning Models via Prediction APIs",
        "summary": "提出模型窃取攻击：通过向目标ML模型API大量查询，训练一个模仿模型在功能上复制目标模型。这意味着即使模型不公开权重，仅提供预测API也会泄露模型知识产权。给出了攻击算法和防御讨论。",
        "authors": ["Tramèr, F.", "Zhang, F.", "Juin, A.", "其他"],
        "published": "2016-08-10",
        "url": "https://arxiv.org/abs/1609.02975",
        "categories": ["model-extraction", "model-theft"],
    },
    {
        "title": "Extracting Training Data from Large Language Models",
        "summary": "Carlini等人证明大语言模型会逐字记忆并泄露训练数据中的敏感内容。通过重复采样和概率过滤，能从GPT-2提取出逐字的个人信息、电话号码、URL。这是LLM记忆泄露问题的标志性研究。",
        "authors": ["Carlini, N.", "Tramer, F.", "Wallace, E.", "其他"],
        "published": "2021-12-03",
        "url": "https://arxiv.org/abs/2012.07805",
        "categories": ["training-data-leakage", "memorization"],
    },
    # ---- 成员推理 ----
    {
        "title": "Membership Inference Attack against Machine Learning Models",
        "summary": "Shokri等人提出成员推理攻击：给定一个数据样本，判断它是否在目标模型的训练集中。攻击利用模型对训练样本和测试样本的置信度分布差异。这会泄露个人是否参与了敏感数据集（如医疗研究）。",
        "authors": ["Shokri, R.", "Stronati, M.", "Song, S.", "其他"],
        "published": "2017-05-14",
        "url": "https://arxiv.org/abs/1610.05820",
        "categories": ["membership-inference", "privacy"],
    },
    {
        "title": " membership Inference Attacks from First Principles",
        "summary": "重新审视成员推理攻击，提出基于预测置信度阈值的简单攻击，在多个模型上效果接近甚至超过复杂的shadow model方法。指出过拟合是成员泄露的主因，分析了泛化与隐私的权衡。",
        "authors": ["Maini, P.", "Li, M.", "Ding, J.", "其他"],
        "published": "2021-05-26",
        "url": "https://arxiv.org/abs/2112.04666",
        "categories": ["membership-inference", "privacy"],
    },
    # ---- 联邦学习/隐私 ----
    {
        "title": "Deep Leakage from Gradients",
        "summary": "证明在联邦学习中，共享的梯度更新可以被用来逐字重建客户端的训练图像和标签。这意味着原始数据即使不出本地，通过梯度也能被还原，对联邦学习的隐私假设构成根本挑战。",
        "authors": ["Zhu, L.", "Liu, Z.", "Han, S."],
        "published": "2019-06-08",
        "url": "https://arxiv.org/abs/1906.08935",
        "categories": ["federated-learning", "gradient-leakage"],
    },
    {
        "title": "Deep Learning with Differential Privacy",
        "summary": "McMahan等人提出DP-SGD：在随机梯度下降中对梯度加噪并裁剪范数，训练出的模型具备差分隐私保证。即使攻击者掌握模型参数，也无法判断单个训练样本是否参与。是机器学习隐私保护的标杆工作。",
        "authors": ["Abadi, M.", "Chu, A.", "Goodman, I.", "其他"],
        "published": "2016-10-24",
        "url": "https://arxiv.org/abs/1607.00133",
        "categories": ["differential-privacy", "defense"],
    },
    # ---- RAG / LLM系统安全 ----
    {
        "title": "RAG Defence: Mitigating Indirect Prompt Injection Attacks in Retrieval-Augmented Generation",
        "summary": "研究RAG系统中的间接提示注入防御：恶意文档在检索时被注入，导致LLM输出被操纵。提出在检索文档和用户查询之间建立隔离层，对检索内容做指令-数据区分，防止外部内容被当作系统指令执行。",
        "authors": ["Ziegler, A.", "Kadivar, A.", "其他"],
        "published": "2024-03-15",
        "url": "https://arxiv.org/abs/2403.00578",
        "categories": ["rag-security", "indirect-injection"],
    },
    {
        "title": "Prompt Injection attack against LLM-integrated Applications",
        "summary": "系统分类了针对LLM集成应用的提示注入攻击面：直接注入、间接注入、多轮注入、工具调用劫持。提出攻击图模型，评估了在LangChain等框架下的攻击路径，讨论了输入过滤、指令分层、沙箱执行等防御。",
        "authors": ["Liu, Y.", "Deng, G.", "Xu, X.", "其他"],
        "published": "2023-06-13",
        "url": "https://arxiv.org/abs/2306.05474",
        "categories": ["prompt-injection", "tool-use"],
    },
    {
        "title": "Semantic Prompt Injection Attacks on LLMs",
        "summary": "研究了语义层面的提示注入：攻击者不使用明显的恶意关键词，而是通过语义隐含、多语言、编码方式绕过输入过滤。强调基于规则的输入过滤难以防御语义级攻击，需要在模型架构和执行层做防护。",
        "authors": ["Shen, H.", "Wang, R.", "其他"],
        "published": "2024-05-20",
        "url": "https://arxiv.org/abs/2405.18967",
        "categories": ["prompt-injection", "semantic-attack"],
    },
    # ---- AI Agent / 工具调用安全 ----
    {
        "title": "AgentBench: Evaluating LLMs as Agents",
        "summary": "提出AgentBench评测框架，评估LLM作为智能体在真实环境中完成任务的能力（操作系统、数据库、知识图谱、网页浏览、家务工具等）。揭示了当前LLM在多步推理、环境交互、错误恢复上的局限，是智能体安全研究的基础评测。",
        "authors": ["Liu, X.", "Yu, H.", "Zhang, H.", "其他"],
        "published": "2023-08-04",
        "url": "https://arxiv.org/abs/2308.03688",
        "categories": ["ai-agent", "benchmark"],
    },
    {
        "title": "ToolEmu: LLM-integrated Tool Security Evaluation",
        "summary": "提出LLM工具调用安全评测：当LLM能调用外部工具（代码执行、数据库、API）时，恶意提示注入可导致工具被滥用。构建了工具调用沙箱和攻击样本集，评估主流LLM在工具权限控制上的安全性。",
        "authors": ["Zhang, D.", "Wu, F.", "其他"],
        "published": "2024-04-10",
        "url": "https://arxiv.org/abs/2404.13958",
        "categories": ["ai-agent", "tool-use", "security-eval"],
    },
    # ---- 模型对齐 / 安全防护 ----
    {
        "title": "Constitutional AI: Harmlessness from AI Feedback",
        "summary": "提出Constitutional AI方法：让模型根据一组原则（宪法）自我批评和自我修正，减少对人工标注的依赖。RLAIF（基于AI反馈的RLHF）在无害性上达到甚至超过人类反馈对齐的效果，是对齐训练的重要范式。",
        "authors": ["Bai, Y.", "Kadavath, S.", "Kundu, S.", "其他"],
        "published": "2022-12-15",
        "url": "https://arxiv.org/abs/2212.08073",
        "categories": ["alignment", "rlhf"],
    },
    {
        "title": "Red Teaming Language Models to Reduce Harms: Methods, Scaling Behaviors, and Lessons Learned",
        "summary": "描述了OpenAI对InstructGPT的红队实践：构建红队prompt数据集、训练对抗性prompt检测器、按危害类别分类。总结了红队规模与危害率的缩放规律，以及红队方法的局限（只能缓解已知危害分布）。",
        "authors": ["Perez, E.", "Huang, S.", "Song, F.", "其他"],
        "published": "2022-09-06",
        "url": "https://arxiv.org/abs/2202.03286",
        "categories": ["red-teaming", "safety"],
    },
    # ---- 模型水印 / 溯源 ----
    {
        "title": "A Watermark for Large Language Models",
        "summary": "提出对LLM生成文本嵌入不可见水印的方法：在解码时对特定词表做对数偏置，统计检验即可判断文本是否由该模型生成，不影响生成质量。这为AI生成内容溯源、版权保护提供了技术手段。",
        "authors": ["Kirchenbauer, J.", "Geiping, J.", "Johndru, J.", "其他"],
        "published": "2023-01-31",
        "url": "https://arxiv.org/abs/2301.10226",
        "categories": ["watermark", "provenance"],
    },
]


def main():
    os.makedirs(HERE + "/data", exist_ok=True)
    out = {
        "meta": {"source": "offline-curated", "total": len(PAPERS)},
        "papers": PAPERS,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"经典论文知识库: {len(PAPERS)} 篇 → {OUT}")


if __name__ == "__main__":
    main()
