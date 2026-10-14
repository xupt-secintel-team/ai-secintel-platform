# -*- coding: utf-8 -*-
"""
attribution.py —— 溯源归因（决赛创新点③：漏洞 → 利用者 → ATT&CK 战术映射）
============================================================================
决策链路此前止步于「这个漏洞有多严重、该怎么处置」。本模块再往前推一层，
回答安全分析师更本质的问题：

    「是谁在利用它？他们走的是一条怎样的攻击链？」

产出三件事（全部确定性规则驱动，零外部依赖、无 Key 也能完整演示）：

  1. **威胁主体画像（actor）**：由漏洞信号推断最可能的利用者群体
     —— 勒索组织 / APT 定向 / 供应链投毒者 / 脚本小子（机会型）等。
     信号源：KEV 在野利用、CWE 类型、描述关键词（ransomware/APT/供应链）、
     受影响产品是否为高价值目标（安全设备/身份系统/网关等）。

  2. **ATT&CK 战术链路（kill_chain）**：把漏洞映射到一条可解释的攻击链
     —— Initial Access → Execution → ... → Impact，并落到具体战术阶段，
     与情报的 ATLAS 攻击技术（已有）互补，补足「传统 ATT&CK 视角」。

  3. **归因置信度（confidence）与依据（evidence）**：每条推断都可解释，
     便于答辩时讲清「为什么判这个主体、这条链路」，而非黑盒。

纯规则、可解释，与 orchestrator 同一工程哲学：不 import 任何其他模块，
只消费事件/详情字段，作为决策智能体的上游富化信号。
"""
from __future__ import annotations

# --------------------------------------------------------------------------
# 威胁主体画像规则：命中关键词 → 主体标签 + 权重 + 说明
# --------------------------------------------------------------------------
ACTOR_RULES = [
    # (关键词集合, 主体标签, 权重, 说明)
    ({"ransomware", "ransom", "extortion", "encrypting files", "locked files",
      "bitlocker", "double extortion"}, "勒索组织", 3.0,
     "描述含勒索/加密文件特征，符合勒索软件运营模式（RaaS/定向勒索）"),
    ({"apt", "nation-state", "state-sponsored", "espionage", "advanced persistent",
      "cyber espionage", "intelligence gathering"}, "APT 定向攻击组织", 3.0,
     "描述含 APT/国家级/间谍活动特征，符合高隐蔽性定向攻击画像"),
    ({"supply chain", "dependency confusion", "typosquat", "malicious package",
      "npm", "pypi", "crates", "go module", "backdoor in upstream"},
     "供应链投毒者", 2.5, "攻击面指向上游依赖/包分发链，符合供应链投毒画像"),
    ({"credential", "password", "authentication bypass", "login bypass",
      "default credential", "hardcoded secret"}, "身份窃取/横向移动者", 2.0,
     "漏洞直击身份认证，利用者以窃取凭证、横向渗透为目标"),
    ({"remote code execution", "rce", "code injection", "command injection",
      "deserialization"}, "机会型攻击者（脚本小子/自动化扫描）", 1.5,
     "RCE/注入类漏洞易被自动化工具批量利用，多为机会型扫描与蠕虫式传播"),
    ({"denial of service", "dos", "resource exhaustion", "amplification"},
     "破坏型攻击者（DoS/勒索前置）", 1.5, "漏洞用于资源耗尽，符合破坏/勒索前置打击画像"),
]

# 高价值目标产品关键词：命中则提升「APT/定向」倾向（这些设备是高级攻击者的首选目标）
HIGH_VALUE_TARGETS = {
    "vpn", "firewall", "gateway", "fortinet", "palo alto", "cisco", "junos",
    "pulse", "citrix", "f5", "ivanti", "vcenter", "exchange", "sharepoint",
    "active directory", "identity", "sso", "edr", "endpoint", "siem",
    "kubernetes", "kubernetes api", "istio", "vault", "key management",
}

# --------------------------------------------------------------------------
# CWE → ATT&CK 战术链路（漏洞类型决定攻击链走法）
# --------------------------------------------------------------------------
# 每条链路 = 有序战术阶段列表，从 Initial Access 到 Impact。
CWE_TO_KILL_CHAIN = {
    # 代码执行 / 注入：完整 RCE 链
    "CWE-78": ["Initial Access", "Execution", "Privilege Escalation", "Impact"],
    "CWE-94": ["Initial Access", "Execution", "Impact"],
    "CWE-77": ["Initial Access", "Execution", "Impact"],
    "CWE-502": ["Initial Access", "Execution", "Impact"],
    "CWE-20": ["Initial Access", "Execution", "Impact"],
    # 认证绕过：凭证 → 横向移动
    "CWE-287": ["Initial Access", "Credential Access", "Lateral Movement", "Impact"],
    "CWE-306": ["Initial Access", "Credential Access", "Lateral Movement"],
    "CWE-798": ["Initial Access", "Credential Access", "Lateral Movement"],
    "CWE-862": ["Initial Access", "Privilege Escalation", "Lateral Movement"],
    "CWE-863": ["Initial Access", "Privilege Escalation", "Lateral Movement"],
    # 注入类
    "CWE-89": ["Initial Access", "Execution", "Exfiltration"],
    "CWE-79": ["Initial Access", "Execution", "Credential Access"],
    # 越界读写 / 内存破坏
    "CWE-787": ["Initial Access", "Execution", "Impact"],
    "CWE-125": ["Initial Access", "Defense Evasion", "Impact"],
    "CWE-416": ["Initial Access", "Execution", "Impact"],
    # 路径穿越 / 文件
    "CWE-22": ["Initial Access", "Execution", "Exfiltration"],
    "CWE-200": ["Initial Access", "Discovery", "Exfiltration"],
}

# 默认链路（CWE 未命中时按描述关键词兜底）
DEFAULT_CHAIN = ["Initial Access", "Execution", "Impact"]

# ATT&CK 战术中文名（展示用）
TACTIC_NAMES = {
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Defense Evasion": "防御规避",
    "Credential Access": "凭证访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Exfiltration": "数据渗出",
    "Impact": "影响/破坏",
}


def _pick_actor(text, products, cwe_ids, kev):
    """由文本 + 产品 + CWE + KEV 推断威胁主体画像。"""
    text_l = (text or "").lower()
    prod_l = " ".join(products or []).lower()
    votes = {}
    evidence = []

    # 1) 关键词规则
    for keys, label, w, why in ACTOR_RULES:
        hits = [k for k in keys if k in text_l]
        if hits:
            votes[label] = votes.get(label, 0) + w
            evidence.append(f"命中特征词「{hits[0]}」→ {label}")

    # 2) 高价值目标产品 → 提升 APT/定向 倾向
    if any(t in prod_l for t in HIGH_VALUE_TARGETS):
        votes["APT 定向攻击组织"] = votes.get("APT 定向攻击组织", 0) + 2.0
        evidence.append("受影响产品属高价值目标（安全/身份/网关类），提升 APT 定向倾向")

    # 3) KEV 在野利用 → 有实际利用者，倾向「组织化」
    if kev:
        votes["有组织利用者（CISA 已确认在野）"] = votes.get("有组织利用者（CISA 已确认在野）", 0) + 2.5
        evidence.append("CISA KEV 确认在野利用，存在真实、活跃的利用者")

    # 4) CWE 兜底（无关键词命中时）
    if not votes:
        auth_cwes = {"CWE-287", "CWE-306", "CWE-798", "CWE-862", "CWE-863"}
        if auth_cwes & set(cwe_ids):
            votes["身份窃取/横向移动者"] = 2.0
            evidence.append("认证类 CWE → 身份窃取/横向移动画像")

    if not votes:
        return {"label": "未知/待进一步情报关联", "confidence": 0.0,
                "evidence": ["当前信号不足，无法高置信归因（建议结合威胁情报平台交叉验证）"]}

    # 归一化置信度（0~1），并选最高分主体
    total = sum(votes.values())
    label, score = max(votes.items(), key=lambda kv: kv[1])
    confidence = round(min(score / 3.5, 1.0), 2)
    return {
        "label": label,
        "confidence": confidence,
        "evidence": evidence[:6],
        "candidates": sorted(
            [{"label": k, "score": round(v, 2)} for k, v in votes.items()],
            key=lambda x: -x["score"])[:3],
    }


def _pick_kill_chain(cwe_ids):
    """CWE → ATT&CK 战术链路（有序）。"""
    for cwe in cwe_ids:
        if cwe in CWE_TO_KILL_CHAIN:
            return CWE_TO_KILL_CHAIN[cwe]
    return DEFAULT_CHAIN


def attribute(rec):
    """对一条漏洞情报做溯源归因。返回 {actor, kill_chain, confidence, evidence}。"""
    text = (rec.get("desc", "") or "") + " " + (rec.get("title", "") or "")
    products = rec.get("products", []) or []
    cwe_ids = [w.get("id") for w in (rec.get("cwe", []) or []) if isinstance(w, dict) and w.get("id")]
    kev = bool(rec.get("kev"))

    actor = _pick_actor(text, products, cwe_ids, kev)
    chain = _pick_kill_chain(cwe_ids)

    # 链路落点：结合 CWE 名称给每个阶段一句可解释说明
    chain_steps = []
    for stage in chain:
        chain_steps.append({
            "tactic": stage,
            "tactic_name": TACTIC_NAMES.get(stage, stage),
            "note": _stage_note(stage, cwe_ids, products),
        })

    return {
        "actor": actor,
        "kill_chain": chain_steps,
        "cwe": cwe_ids[:4],
        "kev": kev,
    }


def _stage_note(stage, cwe_ids, products):
    """给每个战术阶段一句可解释的说明。"""
    prod = (products or ["该组件"])[0]
    if stage == "Initial Access":
        return f"利用漏洞从互联网侧触达 {prod}（公开暴露面）"
    if stage == "Execution":
        return "漏洞被触发后执行恶意代码/载荷"
    if stage == "Privilege Escalation":
        return "借漏洞提权，获取更高系统权限"
    if stage == "Credential Access":
        return "窃取或绕过凭证，为横向移动铺路"
    if stage == "Lateral Movement":
        return "以受损资产为跳板，横向渗透内网"
    if stage == "Exfiltration":
        return "窃取敏感数据并外传"
    if stage == "Impact":
        return "达成最终破坏（加密/中断/数据泄露）"
    if stage == "Defense Evasion":
        return "规避检测，延长驻留时间"
    if stage == "Discovery":
        return "探测内网资产与高价值目标"
    return ""


if __name__ == "__main__":
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    demo = {
        "id": "CVE-2025-12345",
        "title": "Fortinet VPN remote code execution",
        "desc": "A remote code execution vulnerability in the SSL VPN. Attackers exploit "
                "public-facing VPN to run ransomware and double extortion campaigns.",
        "products": ["fortinet", "vpn"],
        "cwe": [{"id": "CWE-78", "name": "OS Command Injection"}],
        "kev": {"exploited": True},
    }
    r = attribute(demo)
    print("主体:", r["actor"]["label"], "置信度", r["actor"]["confidence"])
    for e in r["actor"]["evidence"]:
        print("  -", e)
    print("攻击链:", " → ".join(s["tactic"] for s in r["kill_chain"]))
    for s in r["kill_chain"]:
        print("  ", s["tactic"], "|", s["note"])
