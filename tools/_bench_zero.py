# -*- coding: utf-8 -*-
import io, sys, json, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def get(p, **kw):
    with urllib.request.urlopen(B+p+"?"+urllib.parse.urlencode(kw), timeout=120) as r:
        return json.loads(r.read().decode())
for q in ["zzzqqq不存在的术语xyzzy", "如何做红烧肉", "foobarbaz-9x 的安全漏洞"]:
    d=get("/api/hybrid_search", q=q, size=10)
    rel=(d.get("fusion") or {}).get("relevance") or {}
    print(q, "-> n=", len(d.get("results") or []), "cand=", rel.get("candidates"), "kept=", rel.get("relevant"))
