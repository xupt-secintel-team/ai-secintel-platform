# -*- coding: utf-8 -*-
"""
_test_innovation.py —— 决赛三项创新点专项自测（不依赖运行中的服务）
====================================================================
覆盖：
  ① CTI 知识图谱多跳关联（CVE↔组件↔资产↔攻击技术）
  ② 多智能体红蓝自博弈（决策智能体 vs 质疑智能体）
  ③ 溯源归因（漏洞→利用者→ATT&CK 战术映射）

运行：python tools/_test_innovation.py
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m0_ops", "backend"))

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

_passed = 0
_failed = 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {name}" + (f"  —— {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  [FAIL] {name}" + (f"  —— {detail}" if detail else ""))


print("=" * 60)
print("① CTI 知识图谱多跳关联")
print("=" * 60)
import graph_data as GD

demo = {
    "id": "CVE-2024-12345", "title": "Inference Server RCE",
    "products": ["vllm"], "category": "test",
    "cwe": [{"id": "CWE-78", "name": "OS Command Injection"}],
    "atlas": [{"id": "AML.T0049", "name": "Exploit Public-Facing App", "tactics": ["AML.TA0001"]}],
    "poc_links": ["https://github.com/demo/repo"],
    "cvss": {"score": 9.1, "severity": "CRITICAL"},
}
docs = [demo, {
    "id": "CVE-2024-67890", "title": "Another vllm issue",
    "products": ["vllm"], "cwe": [{"id": "CWE-78"}], "atlas": [],
    "cvss": {"score": 7.5, "severity": "HIGH"},
}, {
    "id": "CVE-2024-99999", "title": "Unrelated app", "products": ["other"],
    "cwe": [{"id": "CWE-79"}], "atlas": [], "cvss": {"score": 5.0, "severity": "MEDIUM"},
}]
idx = GD.build_neighbor_index(docs)
g = GD.build_graph_multi(demo, docs, index=idx, max_hops=2)
check("向后兼容：nodes/links/categories 三字段齐全",
      all(k in g for k in ("nodes", "links", "categories")))
check("多跳游走到第 2 跳", g.get("hops") == 2, f"hops={g.get('hops')}")
check("并入关联 CVE 节点", any(n.get("kind") == "related_cve" for n in g["nodes"]),
      f"nodes={g['stats']['nodes']} links={g['stats']['links']}")
check("产出可读多跳路径", bool(g.get("path_examples")), str(g.get("path_examples")))
check("图例含「关联漏洞」", any(c["name"] == "关联漏洞" for c in g["categories"]))
check("相邻 CVE 命中关系可解释",
      bool(g.get("related_cves")) and g["related_cves"][0].get("shared_products"),
      str(g.get("related_cves")))

# 无 index 时降级为单跳，不崩
g0 = GD.build_graph_multi(demo, docs, index=None)
check("无 index 降级单跳不崩", g0.get("hops") == 1, f"hops={g0.get('hops')}")

print("\n" + "=" * 60)
print("② 多智能体红蓝自博弈")
print("=" * 60)
from orchestrator import ChallengerAgent  # noqa: E402


class _T:
    def add(self, *a, **k):
        pass


chal = ChallengerAgent(_T())

# 场景 A：CVSS 9.8 无 KEV 被判 P1 + 有 POC 无方案 → 应升档 P0 并补动作
dec_a = {"cve": "CVE-A", "priority": "P1", "decision": "【P1】24小时内完成补丁评估",
         "signals": {"kev": False, "cvss": 9.8, "poc_available": 2, "assets_exposed": 3, "remediation": False},
         "actions": [], "history": {}}
out_a = chal.challenge({"id": "CVE-A", "kev": False, "cvss": 9.8},
                       {"poc": {"results": [1, 2]}, "assets": {"assets": [1, 2, 3]}}, dec_a)
check("极端 CVSS 误判 P1 → 升档 P0", out_a["priority"] == "P0", f"final={out_a['priority']}")
check("补充临时缓解动作", any("临时缓解" in a["step"] for a in out_a["actions"]))
check("记录对抗质疑轮次", out_a["adversarial"]["challenge_count"] >= 2,
      f"{out_a['adversarial']['challenge_count']} 条质疑")
check("标注「已修正」", out_a["adversarial"]["stabilized"] is False)

# 场景 B：稳健决策（KEV P0）→ 质疑后仍稳，不降档
dec_b = {"cve": "CVE-B", "priority": "P0", "decision": "【P0】立即隔离",
         "signals": {"kev": True, "cvss": 9.0, "poc_available": 0, "assets_exposed": 0, "remediation": True},
         "actions": [{"step": "升级"}], "history": {}}
out_b = chal.challenge({"id": "CVE-B", "kev": True, "cvss": 9.0}, {}, dec_b)
check("稳健决策保持 P0 不降档", out_b["priority"] == "P0", f"final={out_b['priority']}")

print("\n" + "=" * 60)
print("③ 溯源归因")
print("=" * 60)
import attribution as AT  # noqa: E402

r1 = AT.attribute({
    "title": "Fortinet VPN RCE", "desc": "remote code execution in SSL VPN, ransomware double extortion",
    "products": ["fortinet", "vpn"], "cwe": [{"id": "CWE-78"}], "kev": {"exploited": True},
})
check("勒索+VPN → 勒索组织画像", r1["actor"]["label"] == "勒索组织", r1["actor"]["label"])
check("归因置信度可解释", r1["actor"]["confidence"] > 0.5, f"conf={r1['actor']['confidence']}")
check("ATT&CK 战术链路有序", len(r1["kill_chain"]) >= 3, "→".join(s["tactic"] for s in r1["kill_chain"]))
check("每段链路可解释", all(s.get("note") for s in r1["kill_chain"]))
check("归因带依据", len(r1["actor"]["evidence"]) >= 1, str(r1["actor"]["evidence"][:2]))

r2 = AT.attribute({
    "title": "Malicious pypi package", "desc": "dependency confusion supply chain malicious package",
    "products": ["pypi"], "cwe": [{"id": "CWE-494"}], "kev": {},
})
check("供应链 → 投毒者画像", "投毒" in r2["actor"]["label"] or "供应链" in r2["actor"]["label"], r2["actor"]["label"])

r3 = AT.attribute({"title": "x", "desc": "x", "products": [], "cwe": [], "kev": {}})
check("无信号 → 明确标注未知", "未知" in r3["actor"]["label"], r3["actor"]["label"])

r4 = AT.attribute({
    "title": "auth bypass", "desc": "authentication bypass", "products": ["app"],
    "cwe": [{"id": "CWE-287"}], "kev": {},
})
check("认证绕过 → 凭证/横向移动链路", "Lateral Movement" in [s["tactic"] for s in r4["kill_chain"]],
      "→".join(s["tactic"] for s in r4["kill_chain"]))

print("\n" + "=" * 60)
print(f"结果：通过 {_passed} / 失败 {_failed}")
print("=" * 60)
sys.exit(1 if _failed else 0)
