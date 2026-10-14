# -*- coding: utf-8 -*-
"""验证：感知闸门多路判据后，能否从真实 live_feed 里筛出事件。

对比「旧判据（仅 kev/cvss>=9）」与「新判据（多路）」的产出。
用临时 state 文件，不污染真实 data/ops_state.json。
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
try:
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
sys.path.insert(0, os.path.join(ROOT, "modules", "m0_ops", "backend"))

from orchestrator import PerceptionAgent, TraceRecorder, HIGH_CVSS  # noqa: E402

FEED = os.path.join(ROOT, "data", "live_feed.jsonl")
STATE = os.path.join(tempfile.gettempdir(), "_probe_ops_seen.json")
if os.path.exists(STATE):
    os.remove(STATE)

trace = TraceRecorder()
agent = PerceptionAgent(FEED, STATE, trace)
events = agent.scan()

print("=== 新判据结果 ===")
print("事件数:", len(events))
import collections  # noqa: E402
by_reason = collections.Counter()
for e in events:
    for r in e["reasons"]:
        by_reason[r] += 1
print("入选原因分布:", dict(by_reason))
print()
for e in events[:10]:
    print("  prio=%d %-22s cvss=%-5s %s" % (
        e["priority"], ",".join(e["reasons"]), e["cvss"], e["title"][:56]))

print()
print("=== 对照：旧判据（仅 kev 或 cvss>=9）会筛出几条 ===")
old = [e for e in events if e["kev"] or (isinstance(e["cvss"], (int, float)) and e["cvss"] >= HIGH_CVSS)]
print("旧判据:", len(old), "条")

print()
print("=== trace 末条 ===")
for t in trace.list(3):
    print(" ", t.get("agent"), t.get("action"), "|", str(t.get("detail"))[:120])
