# -*- coding: utf-8 -*-
import io, sys, json, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def get(p, **kw):
    with urllib.request.urlopen(B+p+"?"+urllib.parse.urlencode(kw), timeout=60) as r:
        return json.loads(r.read().decode())
d=get("/api/detail", id="CVE-2026-94627")
print("keys:", sorted(d.keys()))
print("papers:", json.dumps(d.get("papers"), ensure_ascii=False)[:400])
e=get("/api/search", q="ollama cvss>=7", size=1)
print("count ollama cvss>=7:", e.get("total"))
