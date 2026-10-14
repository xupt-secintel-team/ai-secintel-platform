# -*- coding: utf-8 -*-
"""
standards_kb.py —— AI 安全标准 / 政策法规结构化知识底座（P0-1）
==============================================================
为什么加这个
------------
赛题五、明确点名系统要「同步采集最新的 AI 安全学术论文、**技术标准**与**政策法规**，
构建完整的 AI 安全知识底座」。而本项目此前：
  · `core/data_security_kb.py` 只有 4 条法规，且全是**静态硬编码字符串**，
    无版本、无生效日期、无结构化义务；
  · 语料 `data/corpus.json` 里**没有任何「技术标准 / 政策法规」类目**，
    对 ISO/IEC 42001、EU AI Act、NIST AI RMF、TC260 的命中都是 0。

本模块把标准/法规从「散文片段」升级为**可检索、可核验、带版本与生效日期的结构化条目**，
内容**逐条取自** `_standards_factsheet_20261013.md`（唯一事实来源，严禁编造编号/日期）。

关键设计取舍（与增量架构设计一致）
----------------------------------
1. **不重写 291MB 语料**（硬约束 C3）：条目落在独立文件 `data/standards_kb.json`，
   运行期用 `inject(engine)` → `engine.add_documents()` 合并进索引（与快车道同机制）。
   回滚 = 删/改名 `data/standards_kb.json`，或 config.json 设 `standards_enabled:false`。
2. **两级计数**（架构裁决 A）：标准级（一条标准=一条记录）+ 义务级（把已逐条列出的义务
   拆成子条目，`parent_id` 指向父标准）。两级合计 ≥ 40，且**全部是事实表已有事实**。
3. **自动采集定位为「增量比对 + 变更留痕」**（团队实测口径）：官方源可达性参差
   （ISO 官方页 403 反爬、EUR-Lex 返回 202），因此主体内容来自内置基线，
   `refresh()` 只做「可达性探测 + fetched_at 留痕 + 离线降级」，绝不伪造抓取成功。
4. **类别隔离**：条目的 `category` 归入非编号类目「AI安全标准与法规」，
   保证既有 ①~⑪ 分类计数（P0-5 回归对照 414/741/1139/538）零变更。

对外接口（由 m1_monitor/api.py 注册）
------------------------------------
    GET  /api/standards          带筛选的标准/法规条目列表
    POST /api/standards/refresh  触发一次增量比对（离线降级为 degraded）
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):  # type: ignore
            pass

# 网络一律走 httpcompat（有 requests 用 requests，无则 urllib 兜底）——硬约束 C2
try:
    import requests  # noqa: F401
    import requests as _http
except ImportError:  # pragma: no cover —— 无 requests 时走标准库兜底
    import httpcompat as _http  # type: ignore

STD_FILE = paths.data_path("standards_kb.json")

# 条目的分类落在**非编号类目**上：既让 /api/search 的 category faceting 能看到，
# 又不打散 ①~⑪ 的历史统计（P0-5 AC-5 回归口径 414/741/1139/538 不减少）。
STD_CATEGORY = "AI安全标准与法规"

# 计数口径枚举（P0-1 AC-1 / AC-5）
KINDS = ("技术标准", "政策法规", "行业规范", "供应链合规")
REGIONS = ("CN", "EU", "US", "INTL")
STATUSES = ("现行", "草案", "已废止")


# --------------------------------------------------------------------------
# 结构化条目模型（标准级 + 义务级）
# --------------------------------------------------------------------------
# 字段与 data_security_kb._kb() / atlas.to_records() 对齐并扩展：
#   id / parent_id / level / title / title_en / issuer / region / kind / version /
#   effective_date / status / applies_to / key_requirements / refs / tags /
#   review_status / fetched_at / stale / desc
def _std(sid: str, title: str, title_en: str, issuer: str, region: str, kind: str,
         version: str, effective_date: str, status: str, applies_to: List[str],
         key_requirements: List[str], refs: List[str], tags: List[str],
         source: str = "") -> Dict[str, Any]:
    """构造一条**标准级**条目。"""
    return {
        "id": sid, "parent_id": None, "level": "standard",
        "title": title, "title_en": title_en,
        "issuer": issuer, "region": region, "kind": kind, "version": version,
        "effective_date": effective_date, "status": status,
        "applies_to": applies_to, "key_requirements": key_requirements,
        "refs": refs, "tags": tags, "source": source or issuer,
        "review_status": "auto", "fetched_at": "", "stale": False,
    }


def _obl(pid: str, suffix: str, title: str, key_requirements: List[str],
         tags: Optional[List[str]] = None) -> Dict[str, Any]:
    """构造一条**义务级**子条目：继承父标准字段（在 _expand 里补齐）。"""
    return {
        "id": "%s-%s" % (pid, suffix), "parent_id": pid, "level": "obligation",
        "title": title, "key_requirements": key_requirements,
        "tags": tags or [], "refs": [],
    }


# --------------------------------------------------------------------------
# 一、中国：强制性国家标准（技术标准）
# --------------------------------------------------------------------------
_CN_STANDARDS = [
    _std("STD:GB-45438-2025",
         "GB 45438—2025 网络安全技术 人工智能生成合成内容标识方法",
         "GB 45438-2025 Cybersecurity technology - Labeling method for AI-generated synthetic content",
         "国家市场监督管理总局、国家标准化管理委员会（归口 252，委托 TC260 执行）",
         "CN", "技术标准", "2025", "2025-09-01", "现行",
         ["生成合成内容服务提供者", "AI 内容平台", "内容标识相关工具厂商"],
         ["对人工智能生成合成内容加显式标识（可见水印/文字提示）",
          "在文件元数据中嵌入隐式标识，实现内容可溯源",
          "不得恶意删除、篡改、伪造、隐匿标识",
          "与中国《人工智能生成合成内容标识办法》配套实施"],
         ["https://www.tc260.org.cn/"], ["技术标准", "强制性国标", "AI 内容标识", "TC260"]),

    # —— 中国：推荐性国家标准（技术标准）——
    _std("STD:GB-T-45654-2025",
         "GB/T 45654—2025 网络安全技术 生成式人工智能服务安全基本要求",
         "GB/T 45654-2025 Cybersecurity technology - Basic security requirements for generative AI services",
         "国家市场监督管理总局、国家标准化管理委员会（TC260）",
         "CN", "技术标准", "2025", "2025-11-01", "现行",
         ["生成式人工智能服务提供者", "大模型备案与安全测评机构"],
         ["训练数据安全要求：数据来源合法性、语料安全、去标识化",
          "模型安全要求：模型可靠性、抗攻击、生成内容安全",
          "安全措施要求：安全管理、应急处置、安全评估与证实方法",
          "可作为生成式人工智能大模型备案与安全测评依据"],
         ["https://www.tc260.org.cn/"], ["技术标准", "推荐性国标", "生成式AI", "备案测评"]),

    _std("STD:GB-T-45652-2025",
         "GB/T 45652—2025 网络安全技术 生成式人工智能预训练和优化训练数据安全规范",
         "GB/T 45652-2025 Cybersecurity technology - Security specification for pre-training and optimization data of generative AI",
         "国家市场监督管理总局、国家标准化管理委员会（TC260）",
         "CN", "技术标准", "2025", "2025-11-01", "现行",
         ["生成式人工智能服务提供者", "训练数据提供方"],
         ["规定预训练数据及其处理活动的安全要求",
          "规定优化训练数据安全要求",
          "给出训练数据安全的评价方法"],
         ["https://www.tc260.org.cn/"], ["技术标准", "推荐性国标", "训练数据安全"]),

    _std("STD:CN-AI-CLASSIFY-DRAFT",
         "网络安全技术 人工智能应用安全分类分级方法（在编国家标准）",
         "Draft national standard - AI application security classification and grading method",
         "全国网络安全标准化技术委员会（TC260 WG9）",
         "CN", "技术标准", "在编", "征求意见 2026-07-15", "草案",
         ["AI 应用运营者", "AI 安全评估机构"],
         ["建立人工智能应用安全的分类与分级方法",
          "公开征求意见期至 2027-09-13（TC260 2026-07 起）"],
         ["https://www.tc260.org.cn/"], ["技术标准", "在编", "TC260", "分类分级"]),

    _std("STD:CN-AI-EMERGENCY-GUIDE-DRAFT",
         "网络安全技术 人工智能应用安全（应急管理 / 教育 / 金融 / 广播电视指导性技术文件，在编）",
         "Draft guidance - AI application security for emergency/education/finance/broadcasting sectors",
         "全国网络安全标准化技术委员会（TC260 WG9，人工智能安全标准工作组）",
         "CN", "技术标准", "在编", "2026-07 启动/征集参编", "草案",
         ["重点行业 AI 应用运营者", "行业安全评估机构"],
         ["面向应急管理、教育、金融、广播电视四类行业给出 AI 应用安全指导性要求",
          "2026 年 TC260 WG9 在编"],
         ["https://www.tc260.org.cn/"], ["技术标准", "在编", "TC260", "行业指导"]),

    # —— 国际：框架与标准（技术标准）——
    _std("STD:NIST-AI-RMF",
         "NIST AI RMF 1.0（NIST AI 100-1）人工智能风险管理框架",
         "NIST AI Risk Management Framework 1.0 (NIST AI 100-1)",
         "美国国家标准与技术研究院（NIST）",
         "US", "技术标准", "1.0", "2023-01-26", "现行",
         ["AI 系统开发者", "AI 系统部署者", "风险管理与合规人员"],
         ["四大功能：GOVERN（治理）、MAP（映射）、MEASURE（度量）、MANAGE（管理）",
          "GOVERN 是其余三项的基础，贯穿 AI 系统全生命周期",
          "为组织提供自愿性、可定制的 AI 风险管理框架"],
         ["https://www.nist.gov/itl/ai-risk-management-framework"],
         ["技术标准", "国际框架", "NIST", "AI 风险管理"]),

    _std("STD:NIST-AI-600-1",
         "NIST AI 600-1 生成式人工智能剖面（Generative AI Profile）",
         "NIST AI 600-1 Generative AI Profile",
         "美国国家标准与技术研究院（NIST）",
         "US", "技术标准", "2024", "2024-07", "现行",
         ["生成式 AI / LLM 系统开发者与部署者"],
         ["面向 LLM 与生成式系统的专项指引，是 AI RMF 的配套剖面",
          "梳理生成式 AI 特有的人工智能风险并给出缓解建议"],
         ["https://www.nist.gov/itl/ai-risk-management-framework"],
         ["技术标准", "NIST", "生成式AI", "LLM"]),

    _std("STD:ISO-42001",
         "ISO/IEC 42001:2023 人工智能管理体系（AIMS）",
         "ISO/IEC 42001:2023 Information technology - Artificial intelligence - Management system",
         "国际标准化组织 / 国际电工委员会（ISO/IEC）",
         "INTL", "技术标准", "2023（第 1 版）", "2023-12", "现行",
         ["任何组织（可认证的 AI 管理体系）", "AI 治理与合规团队"],
         ["建立人工智能管理体系（AIMS）",
          "要求 AI 影响评估、成文政策、角色与职责定义",
          "要求内部审计、管理评审与持续改进",
          "证书三年有效 + 年度监督审核（可认证）"],
         ["https://www.iso.org/standard/81230.html"],
         ["技术标准", "国际标准", "ISO/IEC 42001", "AI 管理体系", "可认证"]),

    _std("STD:ISO-42005",
         "ISO/IEC 42005:2025 人工智能系统影响评估",
         "ISO/IEC 42005:2025 Information technology - Artificial intelligence - AI system impact assessment",
         "国际标准化组织 / 国际电工委员会（ISO/IEC）",
         "INTL", "技术标准", "2025（第 1 版）", "2025-05", "现行",
         ["AI 系统开发与运营组织"],
         ["对 AI 系统开展影响评估，覆盖个人、群体与社会影响",
          "要求在 AI 系统全生命周期内维护影响评估"],
         ["https://www.iso.org/standard/81230.html"],
         ["技术标准", "国际标准", "ISO/IEC 42005", "影响评估"]),

    _std("STD:ISO-23894",
         "ISO/IEC 23894:2023 人工智能风险管理指南",
         "ISO/IEC 23894:2023 Information technology - Artificial intelligence - Guidance on risk management",
         "国际标准化组织 / 国际电工委员会（ISO/IEC）",
         "INTL", "技术标准", "2023（第 1 版）", "2023-02", "现行",
         ["AI 系统组织"],
         ["给出 AI 风险管理指南，融入组织既有风险管理流程",
          "与 ISO 31000 风险管理原则保持一致"],
         ["https://www.iso.org/standard/81230.html"],
         ["技术标准", "国际标准", "ISO/IEC 23894", "AI 风险管理"]),

    _std("STD:NIST-AI-AGENT-INITIATIVE",
         "NIST AI Agent Standards Initiative 智能体标准倡议",
         "NIST AI Agent Standards Initiative",
         "美国国家标准与技术研究院（NIST）",
         "US", "技术标准", "2026", "2026-02-17（启动）", "现行",
         ["AI Agent / 智能体开发与部署组织"],
         ["三支柱：产业主导的 Agent 标准、社区主导的开放协议、Agent 安全与身份研究",
          "面向智能体（Agentic AI）的安全与身份标准化工作"],
         ["https://www.nist.gov/"], ["技术标准", "NIST", "AI Agent", "标准化"]),

    _std("STD:CISA-AI-OT-2025",
         "CISA 等《Secure Integration of AI in OT》（AI 融入运营技术安全集成指南）",
         "Secure Integration of AI in OT (joint guidance)",
         "CISA + NSA AI 安全中心 + FBI + ACSC + 加/德/荷/新/英",
         "INTL", "技术标准", "2025", "2025-12-03", "现行",
         ["OT（运营技术）环境中的 AI 集成方", "关键基础设施运营者"],
         ["原则一：理解系统（Understand the system）",
          "原则二：评估用例（Assess the use case）",
          "原则三：保障数据与供应链来源（Secure data and supply chain provenance）",
          "原则四：维持人类监督与可审计性（Maintain human oversight and auditability）"],
         ["https://www.cisa.gov/"], ["技术标准", "国际指南", "CISA", "OT", "人类监督"]),
]

# --------------------------------------------------------------------------
# 二、中国：部门规章 / 政策文件（政策法规）
# --------------------------------------------------------------------------
_CN_REGULATIONS = [
    _std("REG:GENAI-INTERIM-MEASURES",
         "《生成式人工智能服务管理暂行办法》",
         "Interim Measures for the Management of Generative AI Services",
         "国家网信办等七部门",
         "CN", "政策法规", "2023", "2023-08-15（施行）", "现行",
         ["向境内公众提供生成式 AI 服务的提供者"],
         ["面向境内公众、具舆论属性或社会动员能力的生成式 AI 服务须完成安全评估 + 算法备案",
          "不得非法留存用户输入与使用记录，不得向第三方提供",
          "发现违法内容应立即停止传输并报告"],
         ["https://www.cac.gov.cn/"], ["政策法规", "网信办", "生成式AI", "算法备案"]),

    _std("REG:AI-LABELING-MEASURES",
         "《人工智能生成合成内容标识办法》",
         "Measures for Labeling AI-Generated Synthetic Content",
         "国家网信办、工业和信息化部、公安部、国家广播电视总局",
         "CN", "政策法规", "2025", "2025-09-01（施行）", "现行",
         ["生成合成内容服务提供者", "内容传播平台"],
         ["生成合成内容须加显式标识",
          "生成合成内容须加隐式标识（文件元数据）",
          "不得恶意删除、篡改、伪造、隐匿标识"],
         ["https://www.cac.gov.cn/"], ["政策法规", "网信办", "内容标识", "TC260 归口 252"]),

    _std("REG:TC260-AI-GOV-FRAME",
         "TC260《人工智能安全治理框架》1.0",
         "TC260 AI Security Governance Framework 1.0",
         "全国网络安全标准化技术委员会（TC260）",
         "CN", "政策法规", "1.0", "2024-09", "现行",
         ["AI 研发、应用与治理主体"],
         ["区分内生安全风险（模型算法、数据、系统）",
          "区分应用安全风险（网络域、现实域、认知域、伦理域）",
          "构建覆盖内生与应用两个维度的治理框架"],
         ["https://www.tc260.org.cn/"], ["政策法规", "TC260", "治理框架"]),

    _std("REG:GOV-LLM-DEPLOY-GUIDE",
         "《政务领域人工智能大模型部署应用指引》",
         "Guideline for the Deployment and Application of Large Model in Government Affairs",
         "中央网信办 + 国家发展改革委",
         "CN", "政策法规", "2025", "2025-10", "现行",
         ["政务领域 AI 大模型部署应用单位"],
         ["数据保密要求",
          "建立安全责任制度",
          "日志审计要求",
          "明确辅助型定位（辅助决策而非替代决策）"],
         ["https://www.cac.gov.cn/"], ["政策法规", "政务AI", "日志审计"]),

    _std("REG:AI-STANDARDS-SYSTEM-GUIDE-2024",
         "《国家人工智能产业综合标准化体系建设指南（2024版）》",
         "National AI Industry Comprehensive Standardization System Construction Guide (2024)",
         "工业和信息化部等",
         "CN", "政策法规", "2024", "2024", "现行",
         ["AI 产业标准化相关单位"],
         ["提出 2026 年前出台 50 项以上国家/行业标准",
          "为国家人工智能产业综合标准化体系提供建设指引"],
         ["https://www.miit.gov.cn/"], ["政策法规", "工信部", "标准化体系"]),

    _std("REG:VULN-MGMT-REGULATION",
         "《网络产品安全漏洞管理规定》",
         "Regulation on the Management of Network Product Security Vulnerabilities",
         "国家网信办等",
         "CN", "政策法规", "—", "—（事实表未标注施行日期）", "现行",
         ["网络产品提供者", "网络运营者", "漏洞收集平台"],
         ["要求企业建立漏洞情报「收集、研判、通报、修复」全流程管理体系",
          "要求具备 7×24 小时漏洞监测能力"],
         ["https://www.cac.gov.cn/"], ["政策法规", "漏洞管理", "7×24 监测"]),

    _std("REG:AGENT-GOV-OPINIONS",
         "《智能体规范应用与创新发展实施意见》",
         "Implementation Opinions on Standardized Application and Innovative Development of AI Agents",
         "国家网信办等三部委",
         "CN", "政策法规", "—", "—（事实表未标注施行日期）", "现行",
         ["智能体（Agent）研发与应用主体"],
         ["从供应链安全维度做风险治理",
          "从内生安全维度做风险治理",
          "防范衍生风险"],
         ["https://www.cac.gov.cn/"], ["政策法规", "网信办", "智能体", "供应链安全"]),

    _std("REG:CNNVD-AIVD",
         "国家人工智能安全漏洞库（AIVD）",
         "National AI Vulnerability Database (AIVD)",
         "中国国家信息安全漏洞库（CNNVD）",
         "CN", "政策法规", "—", "2026-04（启动）", "现行",
         ["AI 相关企业与漏洞治理单位"],
         ["建设国家级 AI 专项漏洞库",
          "企业需并行建设「漏洞智能化 + AI 内生安全」两套管控架构"],
         ["https://www.cnnvd.org.cn/"], ["政策法规", "CNNVD", "AIVD", "AI 漏洞库"]),
]

# --------------------------------------------------------------------------
# 三、国际：政策法规（政策法规）
# --------------------------------------------------------------------------
_INTL_REGULATIONS = [
    _std("REG:EU-AI-ACT",
         "EU AI Act（Regulation (EU) 2024/1689）欧盟人工智能法案",
         "EU AI Act (Regulation (EU) 2024/1689)",
         "欧洲议会与欧盟理事会",
         "EU", "政策法规", "2024/1689", "2024-08-01（生效）", "现行",
         ["在欧盟市场提供/使用 AI 系统的提供者与部署者（域外适用）"],
         ["风险分级：禁止 / 高风险 / 有限风险 / 最小风险",
          "禁止性实践 2025-02-02 起适用；GPAI 义务 2025-08-02 起适用",
          "运营核心 Article 12 事件自动记录（日志）、13 透明度与使用说明、"
          "14 有效人类监督（可否决/推翻/中断）、15 准确性/鲁棒性/网络安全",
          "部署者日志留存 ≥6 个月（Art. 26）",
          "罚款最高达全球营业额 7%",
          "⚠️ 高风险义务生效日存在两种表述：原定 2026-08-02（另有表述：2027-12-02，需人工确认）"],
         ["https://eur-lex.europa.eu/eli/reg/2024/1689/oj"],
         ["政策法规", "EU", "高风险", "人类监督", "域外适用"]),

    _std("REG:EU-2026-1744",
         "Regulation (EU) 2026/1744（Digital Omnibus on AI）",
         "Regulation (EU) 2026/1744 (Digital Omnibus on AI)",
         "欧洲议会与欧盟理事会",
         "EU", "政策法规", "2026/1744", "2026-07-08 签署 / 2026-07-24 公布并生效", "现行",
         ["欧盟 AI 法案下受监管的 AI 提供者与部署者"],
         ["将 Annex III 高风险系统义务推迟至 2027-12-02",
          "Annex I 嵌入式（受监管产品）义务推迟至 2028-08-02",
          "⚠️ 本项目调研资料对高风险义务生效日存在 2026-08-02 与 2027-12-02 "
          "两种表述，知识库条目必须并列说明（需人工确认）"],
         ["https://eur-lex.europa.eu/"], ["政策法规", "EU", "数字综合法案", "高风险义务推迟"]),
]

# --------------------------------------------------------------------------
# 四、行业规范（行业规范 —— 不计入 AC-1 的 ≥40 口径）
# --------------------------------------------------------------------------
_INDUSTRY = [
    _std("STD:OWASP-LLM-TOP10",
         "OWASP Top 10 for LLM Applications（2025 版）",
         "OWASP Top 10 for Large Language Model Applications (2025)",
         "OWASP（开放式 Web 应用安全项目）",
         "INTL", "行业规范", "2025", "2025", "现行",
         ["LLM 应用开发者与安全团队"],
         ["LLM01 提示词注入（Prompt Injection）",
          "LLM06 过度自主权（Excessive Agency）",
          "LLM10 无界消耗（Unbounded Consumption，含 Denial-of-Wallet）"],
         ["https://genai.owasp.org/llm-top-10/"],
         ["行业规范", "OWASP", "LLM 应用", "提示词注入"]),

    _std("STD:OWASP-AGENTIC-TOP10",
         "OWASP Top 10 for Agentic Applications（2025-12-09 发布）",
         "OWASP Top 10 for Agentic Applications",
         "OWASP（开放式 Web 应用安全项目）",
         "INTL", "行业规范", "2025", "2025-12-09（发布）", "现行",
         ["智能体（Agentic AI）开发者与安全团队"],
         ["agent goal hijack（智能体目标劫持）",
          "tool misuse（工具滥用）",
          "身份与权限滥用",
          "智能体供应链风险（含被攻陷的 MCP Server）"],
         ["https://genai.owasp.org/"],
         ["行业规范", "OWASP", "Agentic", "MCP Server", "供应链"]),

    _std("STD:MITRE-ATLAS",
         "MITRE ATLAS 对抗性威胁技术知识库",
         "MITRE ATLAS - Adversarial Threat Landscape for Artificial-Intelligence Systems",
         "MITRE",
         "INTL", "行业规范", "持续更新", "—（持续更新，无固定生效日）", "现行",
         ["AI 系统红队与威胁建模团队"],
         ["AML.T0051 LLM Prompt Injection（提示词注入）",
          "AML.T0020 Training Data Poisoning（训练数据投毒）",
          "覆盖对抗性威胁技术目录与缓解措施"],
         ["https://atlas.mitre.org/"],
         ["行业规范", "MITRE", "ATLAS", "威胁技术"]),
]

# --------------------------------------------------------------------------
# 五、义务级子条目（逐条取自事实表已列出的义务，不新增编号/条款）
# --------------------------------------------------------------------------
_OBLIGATIONS = [
    # EU AI Act —— 四篇运营核心 Article + 部署者留存义务（事实表逐条列出）
    _obl("REG:EU-AI-ACT", "12", "Article 12 事件自动记录（日志）",
         ["高风险 AI 系统须对运行期间事件进行自动记录（日志）", "日志用于事后追溯与合规审计"]),
    _obl("REG:EU-AI-ACT", "13", "Article 13 透明度与使用说明",
         ["向部署者提供充分透明的使用说明", "使其能够正确理解与使用高风险 AI 系统"]),
    _obl("REG:EU-AI-ACT", "14", "Article 14 有效人类监督",
         ["高风险 AI 系统须设计为可由自然人有效监督",
          "监督者可否决、推翻或中断系统输出"]),
    _obl("REG:EU-AI-ACT", "15", "Article 15 准确性、鲁棒性与网络安全",
         ["高风险 AI 系统须达到适当准确性", "须具备鲁棒性与网络安全能力"]),
    _obl("REG:EU-AI-ACT", "26", "Article 26 部署者日志留存 ≥6 个月",
         ["部署者须保留高风险 AI 系统日志至少 6 个月"]),
    # EU 2026/1744 —— 两条推迟义务
    _obl("REG:EU-2026-1744", "ANNEX-III", "Annex III 高风险系统义务推迟至 2027-12-02",
         ["数字综合法案将 Annex III 高风险系统义务推迟至 2027-12-02（需人工确认）"]),
    _obl("REG:EU-2026-1744", "ANNEX-I", "Annex I 嵌入式受监管产品义务推迟至 2028-08-02",
         ["Annex I 嵌入式（受监管产品）义务推迟至 2028-08-02"]),
    # NIST AI RMF —— 四功能（事实表明确 GOVERN/MAP/MEASURE/MANAGE）
    _obl("STD:NIST-AI-RMF", "GOVERN", "GOVERN 治理",
         ["建立 AI 风险治理的组织文化、职责与流程", "是 MAP / MEASURE / MANAGE 的基础"]),
    _obl("STD:NIST-AI-RMF", "MAP", "MAP 映射",
         ["识别并框定 AI 相关的上下文与风险", "把 AI 系统能力与风险对应到组织目标"]),
    _obl("STD:NIST-AI-RMF", "MEASURE", "MEASURE 度量",
         ["采用定性与定量方法度量已识别的 AI 风险"]),
    _obl("STD:NIST-AI-RMF", "MANAGE", "MANAGE 管理",
         ["对已度量的 AI 风险进行优先级排序与处置", "建立持续监控与响应机制"]),
    # GB/T 45654 —— 训练数据 / 模型 / 安全措施（事实表明确）
    _obl("STD:GB-T-45654-2025", "DATA", "训练数据安全要求",
         ["语料来源合法性审查", "训练数据去标识化与安全处理"]),
    _obl("STD:GB-T-45654-2025", "MODEL", "模型安全要求",
         ["模型可靠性与抗攻击要求", "生成内容安全要求"]),
    _obl("STD:GB-T-45654-2025", "MEASURE", "安全措施要求",
         ["安全管理与应急处置", "安全评估与证实方法（可用于备案与测评）"]),
    # 生成式 AI 暂行办法 —— 两条关键义务
    _obl("REG:GENAI-INTERIM-MEASURES", "ASSESS", "安全评估 + 算法备案义务",
         ["面向境内公众、具舆论属性或社会动员能力的生成式 AI 服务须完成安全评估",
          "并履行算法备案"]),
    _obl("REG:GENAI-INTERIM-MEASURES", "DATA", "数据与内容合规义务",
         ["不得非法留存用户输入与使用记录，不得向第三方提供",
          "发现违法内容立即停止传输并报告"]),
    # 标识办法 —— 显式 / 隐式标识
    _obl("REG:AI-LABELING-MEASURES", "VISIBLE", "显式标识义务",
         ["生成合成内容须添加显式标识"]),
    _obl("REG:AI-LABELING-MEASURES", "INVISIBLE", "隐式标识与防篡改义务",
         ["在文件元数据中嵌入隐式标识",
          "不得恶意删除、篡改、伪造、隐匿标识"]),
    # TC260 治理框架 —— 内生 / 应用两维风险
    _obl("REG:TC260-AI-GOV-FRAME", "ENDOGENOUS", "内生安全风险治理",
         ["覆盖模型算法风险、数据风险、系统风险"]),
    _obl("REG:TC260-AI-GOV-FRAME", "APPLIED", "应用安全风险治理",
         ["覆盖网络域、现实域、认知域、伦理域风险"]),
    # 政务指引 —— 日志审计 / 安全责任
    _obl("REG:GOV-LLM-DEPLOY-GUIDE", "AUDIT", "日志审计与数据保密要求",
         ["落实数据保密要求", "落实日志审计要求"]),
    # 标准化体系指南
    _obl("REG:AI-STANDARDS-SYSTEM-GUIDE-2024", "TARGET",
         "2026 年前 50 项以上国家/行业标准目标",
         ["提出 2026 年前出台 50 项以上 AI 国家/行业标准"]),
    # 漏洞管理规定 —— 全流程 + 7×24
    _obl("REG:VULN-MGMT-REGULATION", "FLOW", "漏洞全流程管理义务",
         ["建立漏洞情报收集、研判、通报、修复全流程管理体系"]),
    _obl("REG:VULN-MGMT-REGULATION", "MONITOR", "7×24 漏洞监测义务",
         ["具备 7×24 小时漏洞监测能力"]),
    # 智能体实施意见 —— 供应链 + 内生
    _obl("REG:AGENT-GOV-OPINIONS", "SUPPLY", "智能体供应链安全治理",
         ["从供应链安全维度治理智能体风险"]),
    _obl("REG:AGENT-GOV-OPINIONS", "ENDO", "智能体内生安全治理",
         ["从内生安全维度治理智能体风险", "防范衍生风险"]),
    # AIVD —— 双管控架构
    _obl("REG:CNNVD-AIVD", "DUAL", "漏洞智能化 + AI 内生安全双管控架构",
         ["企业并行建设「漏洞智能化 + AI 内生安全」两套管控架构"]),
    # CISA AI in OT —— 四原则（事实表明确四原则）
    _obl("STD:CISA-AI-OT-2025", "P1", "原则：理解系统",
         ["理解所集成的 AI/OT 系统边界与依赖"]),
    _obl("STD:CISA-AI-OT-2025", "P2", "原则：评估用例",
         ["评估 AI 在 OT 场景下的具体用例与风险"]),
    _obl("STD:CISA-AI-OT-2025", "P3", "原则：保障数据与供应链来源",
         ["保障数据与供应链来源可信"]),
    _obl("STD:CISA-AI-OT-2025", "P4", "原则：维持人类监督与可审计",
         ["维持人类监督与可审计性"]),
    # GB/T 45652 —— 两条
    _obl("STD:GB-T-45652-2025", "PRETRAIN", "预训练数据安全要求",
         ["规定预训练数据及其处理活动的安全要求"]),
    _obl("STD:GB-T-45652-2025", "EVAL", "训练数据安全评价方法",
         ["给出训练数据安全的评价方法"]),
    # ISO/IEC 42001 —— 影响评估 / 管理体系
    _obl("STD:ISO-42001", "AIA", "AI 影响评估（AIA）要求",
         ["对 AI 系统开展影响评估", "评估结果纳入管理系统决策"]),
    _obl("STD:ISO-42001", "AUDIT", "内部审计与管理评审要求",
         ["开展内部审计与管理评审，推动持续改进"]),
]


def _all_raw() -> List[Dict[str, Any]]:
    """全部原始条目（标准级 + 义务级，未展开）。"""
    return (_CN_STANDARDS + _CN_REGULATIONS + _INTL_REGULATIONS + _INDUSTRY
            + _OBLIGATIONS)


def _expand() -> List[Dict[str, Any]]:
    """展开为完整条目：义务级子条目继承父标准的 region/kind/issuer/生效日期等。"""
    by_id = {it["id"]: it for it in _all_raw()}
    out = []
    for it in _all_raw():
        if it.get("level") == "standard":
            out.append(dict(it))
            continue
        parent = by_id.get(it.get("parent_id") or "")
        if not parent:
            # 父标准缺失：跳过该子条目（不产生悬空引用）
            continue
        merged = dict(parent)
        merged.update({
            "id": it["id"], "parent_id": it["parent_id"], "level": "obligation",
            "title": it["title"], "key_requirements": it["key_requirements"],
            "tags": list(dict.fromkeys(list(parent.get("tags", [])) + list(it.get("tags", [])))),
            "refs": parent.get("refs", []),
        })
        out.append(merged)
    return out


def build_all(write: bool = True) -> List[Dict[str, Any]]:
    """依据内置基线（事实表）生成条目并落盘 data/standards_kb.json。

    返回条目列表（不论是否写盘）。
    """
    items = _expand()
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    for it in items:
        if not it.get("fetched_at"):
            it["fetched_at"] = now
        it.setdefault("stale", False)
    if write:
        payload = {
            "meta": {
                "generated_at": now,
                "total": len(items),
                "standard_level": sum(1 for i in items if i["level"] == "standard"),
                "obligation_level": sum(1 for i in items if i["level"] == "obligation"),
                "source": "内置基线（_standards_factsheet_20261013.md，零编造）",
            },
            "items": items,
        }
        _atomic_write(STD_FILE, payload)
    return items


def _atomic_write(path: str, obj: Any) -> None:
    """先写 .tmp 再 os.replace（对齐 circuit.py::_save_state 的原子写）。"""
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except OSError as e:
        _swallow("core/standards_kb.py:_atomic_write", e)
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def load_items() -> List[Dict[str, Any]]:
    """读盘；文件缺失/损坏时回退内置基线（**不抛异常**）。"""
    try:
        with open(STD_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        items = d.get("items") if isinstance(d, dict) else d
        if isinstance(items, list) and items:
            return items
    except (OSError, ValueError) as e:
        _swallow("core/standards_kb.py:load_items", e)
    return _expand()


# --------------------------------------------------------------------------
# 转成引擎可索引的文档（与 _kb() / atlas.to_records() 同构）
# --------------------------------------------------------------------------
def _published_of(it: Dict[str, Any]) -> str:
    """published 仅用于排序/年份分面，取发布日期；不足月/日的补 01 归一化。"""
    raw = str(it.get("effective_date") or "")
    import re
    m = re.match(r"(\d{4})(?:-(\d{1,2}))?(?:-(\d{1,2}))?", raw)
    if not m:
        return ""
    y = m.group(1)
    mo = m.group(2) or "01"
    d = m.group(3) or "01"
    return "%s-%02d-%02d" % (y, int(mo), int(d))


def to_doc(it: Dict[str, Any]) -> Dict[str, Any]:
    """把标准/法规条目转成引擎文档结构。"""
    kind = it.get("kind", "")
    issuer = it.get("issuer", "")
    reqs = it.get("key_requirements") or []
    title = it.get("title", "")
    desc = " ".join([
        title, issuer, "；".join(reqs),
        "适用主体：" + "、".join(it.get("applies_to") or []),
        "类别：" + kind, "地区：" + str(it.get("region", "")),
    ])
    tags = list(dict.fromkeys(["标准法规", kind] + list(it.get("tags") or [])))
    return {
        "id": it["id"],
        "type": "knowledge",
        "kind": kind,                      # ← /api/search facets.kind 与 /api/stats.kind_counts 的键
        "title": title,
        "desc": desc,
        "published": _published_of(it),
        "modified": "",
        "status": it.get("status", "现行"),
        "scope": "AI安全",
        "cvss": {"score": None, "severity": "", "vector": "", "version": "",
                 "exploitability": None, "impact": None},
        "cwe": [], "cpe": [], "products": [], "vendors": [],
        "refs": [{"url": u} for u in (it.get("refs") or []) if u],
        "poc_links": [], "patch_links": [], "advisory_links": [],
        "osv_packages": [], "osv_summaries": [], "osv_refs": [],
        "sources": [it.get("source") or issuer or "标准法规知识库"],
        "kev": {},
        "tags": tags,
        "risk_tags": [],
        "ai_score": 1.0,
        "category": STD_CATEGORY,          # ← 非编号类目，不打散 ①~⑪ 统计
        "category_reason": "标准/法规结构化知识底座条目（%s·%s）" % (
            kind, it.get("region", "")),
        "atlas": [], "atlas_mitigations": [],
        "papers": [],
        "remediation": reqs[:5],
        # —— 结构化附加字段（供 /api/standards 逐字段返回，供核验）——
        "std_issuer": issuer,
        "std_region": it.get("region", ""),
        "std_version": it.get("version", ""),
        "std_effective_date": it.get("effective_date", ""),
        "std_review_status": it.get("review_status", "auto"),
        "std_stale": bool(it.get("stale")),
        "std_level": it.get("level", "standard"),
        "std_parent_id": it.get("parent_id"),
        "trust_score": 80,
        "trust_level": "official",
        "trust_label": "官方标准/法规",
        "cross_count": 1,
        "cross_verified": False,
        "cross_label": "官方来源",
        "cross_sources": [{"source": it.get("source") or issuer, "label": "官方标准/法规"}],
        "exploit_score": 0,
        "exploit_level": "none",
        "exploit_label": "无公开利用",
        "exploit_signals": [],
        "freshness": 0.95,
        "confidence": 80.0,
    }


def inject(engine, clear_cache=None) -> int:
    """运行期合并：把条目并入引擎索引（与快车道 _live_replay 同机制）。

    参数
    ----
    engine      : SearchEngine 实例
    clear_cache : 可选，无参可调用对象；注入后清空检索/统计缓存
                  （一般传 CoreCapabilities.clear_search_cache，避免 core→server 反向依赖）

    返回实际新增条数。
    """
    if engine is None:
        return 0
    items = load_items()
    docs = [to_doc(it) for it in items]
    n = engine.add_documents(docs)
    if clear_cache:
        try:
            clear_cache()
        except Exception as e:  # noqa: BLE001
            _swallow("core/standards_kb.py:inject/clear_cache", e)
    return n


# --------------------------------------------------------------------------
# 增量比对 + 变更留痕（离线降级）
# --------------------------------------------------------------------------
# 官方来源可达性（团队 2026-10-13 实测）：tc260/nist/genai.owasp/cnnvd 可达；
# ISO 官方页 403 反爬；EUR-Lex 返回 202。判定"成功"必须按 2xx（含 202/206）。
_OFFICIAL_SOURCES = [
    {"name": "TC260", "url": "https://www.tc260.org.cn/", "blocked": False},
    {"name": "NIST", "url": "https://www.nist.gov/itl/ai-risk-management-framework",
     "blocked": False},
    {"name": "OWASP GenAI", "url": "https://genai.owasp.org/llm-top-10/", "blocked": False},
    {"name": "CNNVD", "url": "https://www.cnnvd.org.cn/", "blocked": False},
    {"name": "ISO", "url": "https://www.iso.org/standard/81230.html", "blocked": True},
    {"name": "EUR-Lex", "url": "https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
     "blocked": False},
]


def _probe(url: str, timeout: float = 12.0) -> Optional[int]:
    """探测一个来源，返回 HTTP 状态码；网络异常返回 None。"""
    try:
        r = _http.get(url, timeout=timeout, headers={"User-Agent": "AI-SecIntel/2.3"})
        return int(getattr(r, "status_code", 0) or 0)
    except Exception as e:  # noqa: BLE001 —— 网络异常 = 不可达，如实降级
        _swallow("core/standards_kb.py:_probe", e)
        return None


def refresh(sources: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """增量比对官方来源 → 变更留痕；离线/不可达则降级。

    **定位**：本函数做「可达性探测 + fetched_at 留痕 + 离线降级」，
    主体内容始终来自内置基线（事实表），**不伪造抓取成功**。

    返回值字段（约定 AC-4）：``{ok, degraded, added, changed, invalidated, stale,
    total, reachable[], skipped_blocked[], failed[], fetched_at}``。
    无论成败，**条目数不减少**。
    """
    srcs = sources or _OFFICIAL_SOURCES
    reachable, blocked, failed = [], [], []
    for s in srcs:
        code = _probe(s["url"])
        if code is None:
            failed.append(s["name"])
        elif 200 <= code < 300:
            reachable.append({"name": s["name"], "http": code})
        elif code in (401, 403, 451) and s.get("blocked"):
            # ISO 官方页反爬（403）是**预期行为**，归入 skipped_blocked 而非 failed，
            # 否则每轮刷新都刷一堆告警 —— 那正是 P0-3 要治的"告警疲劳"病根。
            blocked.append({"name": s["name"], "http": code,
                            "note": "官方页面反爬，链接仅作引用（不经由系统抓取）"})
        else:
            # 其它非 2xx（含 EUR-Lex 之外的异常码）如实记为 failed
            failed.append("%s(HTTP %s)" % (s["name"], code))

    degraded = len(reachable) == 0
    now = time.strftime("%Y-%m-%dT%H:%M:%S")

    items = load_items()
    changed = 0
    if not degraded:
        # 可达时只更新时间戳留痕（增量比对无外网解析器，如实 added/changed=0）
        for it in items:
            it["fetched_at"] = now
            it["stale"] = False
        changed = 0
    else:
        # 离线：保留内置基线，标记 stale=true，条目不减少
        for it in items:
            it["stale"] = True
    _atomic_write(STD_FILE, {
        "meta": {"generated_at": now, "total": len(items),
                 "degraded": degraded, "reachable": reachable,
                 "skipped_blocked": blocked, "failed": failed},
        "items": items,
    })

    return {
        "ok": True,
        "degraded": degraded,
        "added": 0,
        "changed": changed,
        "invalidated": 0,
        "stale": len(items) if degraded else 0,
        "total": len(items),
        "reachable": reachable,
        "skipped_blocked": blocked,
        "failed": failed,
        "fetched_at": now,
        "note": ("可达时仅做「时间戳留痕 + 增量比对」；条目内容来自内置基线（事实表），"
                 "不伪造抓取成功。离线时保留基线并标记 stale。"),
    }


# --------------------------------------------------------------------------
# 查询（GET /api/standards）
# --------------------------------------------------------------------------
def query(q: str = "", kind: str = "", region: str = "", status: str = "",
          size: int = 60) -> Dict[str, Any]:
    """按关键词/类别/地区/状态筛选条目，返回计数与列表。"""
    items = load_items()
    kw = (q or "").strip().lower()
    out = []
    for it in items:
        if kind and it.get("kind") != kind:
            continue
        if region and it.get("region") != region:
            continue
        if status and it.get("status") != status:
            continue
        if kw:
            blob = " ".join([
                str(it.get("title", "")), str(it.get("title_en", "")),
                str(it.get("issuer", "")), " ".join(it.get("tags") or []),
                " ".join(it.get("key_requirements") or []),
            ]).lower()
            if kw not in blob:
                continue
        out.append(it)
    counts: Dict[str, int] = {k: 0 for k in KINDS}
    for it in items:
        k = it.get("kind")
        if k in counts:
            counts[k] += 1
    # 排序：标准级在前，再按 id
    out.sort(key=lambda x: (0 if x.get("level") == "standard" else 1, x.get("id", "")))
    return {
        "ok": True,
        "total": len(out),
        "all_total": len(items),
        "counts": counts,
        "items": out[:max(1, int(size))],
    }
