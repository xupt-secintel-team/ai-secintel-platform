# -*- coding: utf-8 -*-
import json, os, collections
D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
h=json.load(open(os.path.join(D,"source_health.json"),encoding="utf-8"))
src=h["sources"]; st=collections.Counter(v.get("state") for v in src.values())
print("SOURCES", len(src), "ROUNDS", h.get("rounds"), "updated", h.get("updated_at"))
print("STATES", st.most_common())
fail=[(k,v.get("consecutive_failures"),v.get("state")) for k,v in src.items() if v.get("consecutive_failures")]
print("FAILING", len(fail), fail[:12])
ok=[k for k,v in src.items() if v.get("state")=="ok"]
print("OK", len(ok), ok[:15])
