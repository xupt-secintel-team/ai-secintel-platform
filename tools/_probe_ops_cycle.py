# -*- coding: utf-8 -*-
"""端到端验证：完整编排 cycle 能否产出简报 / 事件。

用临时 data_dir（仅拷 live_feed.jsonl），**不污染**真实 ops_briefs.json。
富化环节会打本机 /api/assets（需服务在跑）。
"""
import json
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
try:
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
sys.path.insert(0, os.path.join(ROOT, "modules", "m0_ops", "backend"))

from orchestrator import Orchestrator  # noqa: E402

TD = tempfile.mkdtemp(prefix="_ops_cycle_")
shutil.copy(os.path.join(ROOT, "data", "live_feed.jsonl"),
            os.path.join(TD, "live_feed.jsonl"))

orch = Orchestrator(TD, {"ops_enabled": False})
print("data_dir:", TD)

t0 = time.time()
r = orch.cycle(manual=True)
print("cycle 返回:", json.dumps(r, ensure_ascii=False)[:400])
print("耗时: %.1fs" % (time.time() - t0))

bf = os.path.join(TD, "ops_briefs.json")
ef = os.path.join(TD, "ops_events.json")
briefs = json.load(open(bf, encoding="utf-8")) if os.path.isfile(bf) else []
events = json.load(open(ef, encoding="utf-8")) if os.path.isfile(ef) else []
print("\n简报数:", len(briefs), "| 事件数:", len(events))
for b in briefs[:3]:
    print("\n--- 简报 ---")
    print("  事件:", (b.get("event") or {}).get("id"),
          "| 来源:", (b.get("event") or {}).get("kind"))
    print("  入选原因:", (b.get("event") or {}).get("reasons"))
    print("  模式:", b.get("brief_mode"))
    print("  正文:", str(b.get("brief"))[:300])
    print("  决策:", json.dumps(b.get("decision"), ensure_ascii=False)[:200])

print("\n=== trace（最近 12 条）===")
for t in orch.trace.list(12):
    print("  %-12s %-28s %s" % (t.get("agent"), str(t.get("action"))[:28],
                                str(t.get("detail"))[:80]))

shutil.rmtree(TD, ignore_errors=True)
