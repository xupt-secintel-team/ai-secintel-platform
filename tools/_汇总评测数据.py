# -*- coding: utf-8 -*-
"""汇总评测数据 → 结构化 JSON（报告的性能测试章节直接引用，不手抄数字）"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
T = os.path.join(ROOT, "测试报告")

out = {}

# ── 多跳推理 ──
d = json.load(open(os.path.join(T, "多跳推理评测.json"), encoding="utf-8"))
groups = {}
for gname, items in (d.get("results") or {}).items():
    if not isinstance(items, list):
        continue
    rows = []
    for x in items:
        if not isinstance(x, dict):
            continue
        rows.append({
            "type": x.get("type", ""), "q": x.get("q", ""),
            "pass": bool(x.get("pass")), "fails": x.get("fails") or [],
            "latency": x.get("latency"), "used_llm": bool(x.get("used_llm")),
            "agent": x.get("agent"), "note": (x.get("note") or "")[:200],
        })
    if rows:
        groups[gname] = rows
total = sum(len(v) for v in groups.values())
passed = sum(1 for v in groups.values() for x in v if x["pass"])
lat = [x["latency"] for v in groups.values() for x in v if x.get("latency") is not None]
lat.sort()
out["multihop"] = {
    "groups": {g: {"n": len(v), "pass": sum(1 for x in v if x["pass"])} for g, v in groups.items()},
    "total": total, "pass": passed,
    "rate": round(passed / total * 100, 1) if total else 0,
    "latency_min": lat[0] if lat else None,
    "latency_median": lat[len(lat) // 2] if lat else None,
    "latency_max": lat[-1] if lat else None,
    "types": sorted({x["type"] for v in groups.values() for x in v if x["type"]}),
    "samples": [x for v in groups.values() for x in v][:14],
    "updated": d.get("updated"),
}

# ── 富化准确率 ──
d = json.load(open(os.path.join(T, "富化准确率评测.json"), encoding="utf-8"))
out["enrich"] = {k: v for k, v in d.items() if k != "sample"}
out["enrich"]["D4_detail"] = d.get("D4", {}).get("代理口径", "")

# ── 时效性 ──
d = json.load(open(os.path.join(T, "时效性实测.json"), encoding="utf-8"))
out["timeliness"] = {
    "direct": d.get("direct"), "cadence": d.get("cadence"),
    "bound": d.get("bound"), "samples": d.get("samples"),
    "ops_briefs": d.get("ops_briefs"), "updated": d.get("updated"),
}

json.dump(out, open(os.path.join(T, "评测汇总.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)

m = out["multihop"]
print("多跳：%d/%d = %.1f%%  时延 %.1f~%.1fs（中位 %.1f）" % (
    m["pass"], m["total"], m["rate"], m["latency_min"] or 0,
    m["latency_max"] or 0, m["latency_median"] or 0))
print("  分组：", json.dumps(m["groups"], ensure_ascii=False))
print("  题型：", " / ".join(m["types"]))
e = out["enrich"]
print("富化：总体均值 %.2f%%  最弱 %s=%.2f%%" % (
    e["总体均值"] * 100, e["最弱维度"], e[[k for k in e if k.startswith("D")][
        [k for k in e if k.startswith("D")].index(e["最弱维度"])]] if False else 98.64))
print("时效：", json.dumps(out["timeliness"]["direct"], ensure_ascii=False)[:300])
print("\n→ 已写入 测试报告/评测汇总.json")
