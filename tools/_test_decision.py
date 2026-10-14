# -*- coding: utf-8 -*-
"""DecisionAgent（决策智能体）离线桩测试：不联网，用桩替换 _http。"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules", "m0_ops", "backend"))

import orchestrator as ORT

passed = failed = 0
def check(cond, name, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}  {extra}")

# ── 桩：伪造 HTTP 回访 ──
RESP = {}
def fake_http(path, params=None, timeout=20, method="GET"):
    if path == "/api/remediation":
        return {"ok": True, "plan": {
            "upgrade": [{"component": "ollama", "target": "升级到 >=0.1.34"}],
            "config": [{"item": "暴露面收敛", "detail": "内网 ACL"}],
            "mitigations": ["【在野利用】隔离受影响系统"],
            "verify": ["升级后复核版本指纹"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-X"],
            "generated_by": "template",
        }}
    if path == "/api/assets":
        return {"assets": [{"vendor": "ollama", "product": "ollama"}], "survey": {}}
    if path == "/api/poc":
        return {"results": [{"title": "poc1"}]}
    return {}
ORT._http = fake_http

trace = ORT.TraceRecorder()
agent = ORT.DecisionAgent(trace)

print("=== ① KEV 在野利用 → P0 立即处置 ===")
ev = {"id": "CVE-2025-63389", "cvss": 9.8, "kev": True}
enrich = {"assets": {"assets": [{}]}, "poc": {"results": [{}]}}
r = agent.make(ev, enrich)
d = r["decision"]
check(d["priority"] == "P0", "KEV 判定为 P0", d["priority"])
check("立即隔离" in d["decision"] or "立即" in d["decision"], "决策含立即动作", d["decision"])
check(len(d["actions"]) >= 3, "动作清单完整（升级+加固+缓解）", str(len(d["actions"])))
check(len(d["verify"]) >= 1, "含验证标准")
check(d["signals"]["kev"] is True and d["signals"]["remediation"] is True, "信号字段正确", str(d["signals"]))

print("=== ② CVSS≥9.5 非 KEV → P0 ===")
ev2 = {"id": "CVE-2026-99999", "cvss": 9.6, "kev": False}
r2 = agent.make(ev2, enrich)
check(r2["decision"]["priority"] == "P0", "极端 CVSS 判 P0", r2["decision"]["priority"])

print("=== ③ CVSS 9.0 + POC → P1 ===")
ev3 = {"id": "CVE-2026-88888", "cvss": 9.0, "kev": False}
r3 = agent.make(ev3, {"assets": {"assets": [{}]}, "poc": {"results": [{}]}})
check(r3["decision"]["priority"] == "P1", "高危+POC 判 P1", r3["decision"]["priority"])

print("=== ③b CVSS 8.8 无 POC → P1（高危不该降档） ===")
ev3b = {"id": "CVE-2024-37032", "cvss": 8.8, "kev": False}
r3b = agent.make(ev3b, {"assets": {"assets": [{}]}, "poc": {"results": []}})
check(r3b["decision"]["priority"] == "P1", "高危无 POC 仍判 P1", r3b["decision"]["priority"])

print("=== ④ 低危无 POC → P2 排期 ===")
ev4 = {"id": "CVE-2026-77777", "cvss": 5.0, "kev": False}
r4 = agent.make(ev4, {"assets": {"assets": []}, "poc": {"results": []}})
check(r4["decision"]["priority"] == "P2", "低危判 P2", r4["decision"]["priority"])

print("=== ⑤ 修复方案缺失也降级产出决策 ===")
ORT._http = lambda path, **kw: {"ok": False, "error": "不存在"} if path == "/api/remediation" else {}
r5 = agent.make(ev4, {"assets": {}, "poc": {}})
check("decision" in r5 and r5["decision"]["priority"], "无方案仍产出决策")
check(any(a["step"] == "排查" for a in r5["decision"]["actions"]), "无方案时给排查动作")

print("=== ⑥ trace 留痕 ===")
acts = [t["agent"] for t in trace.list(100)]
check("decision" in acts, "决策动作进入 trace", str(set(acts)))

print(f"\n结果：{passed} 通过 / {failed} 失败")
sys.exit(1 if failed else 0)
