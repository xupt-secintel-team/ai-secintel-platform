# -*- coding: utf-8 -*-
import io, sys, json, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def get(p, **kw):
    u=B+p+"?"+urllib.parse.urlencode(kw)
    with urllib.request.urlopen(u, timeout=120) as r: return json.loads(r.read().decode())
for q in ["模型会不会被指令绕过、怎么防","训练框架反序列化导致的危险","大模型输出被投毒污染"]:
    d=get("/api/hybrid_search", q=q, size=10)
    print(q, "mode=", d.get("mode"), "n=", len(d.get("results") or []), "fusion=", json.dumps(d.get("fusion"), ensure_ascii=False)[:400])
    e=get("/api/search", q=q, size=10)
    print("   engine total=", e.get("total"), "first=", ((e.get("results") or [{}])[0].get("title") or "")[:60])
