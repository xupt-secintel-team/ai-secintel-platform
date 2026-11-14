# -*- coding: utf-8 -*-
import io, sys, json, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def get(p, **kw):
    with urllib.request.urlopen(B+p+"?"+urllib.parse.urlencode(kw), timeout=120) as r:
        return json.loads(r.read().decode())
for q in ["模型会不会被指令绕过、怎么防","大模型输出被投毒污染","如何做红烧肉","zzzqqq不存在的术语xyzzy","Ollama 有哪些高危漏洞"]:
    d=get("/api/search", q=q, size=15)
    rs=d.get("results") or []
    print(q, "total=", d.get("total"), "scores=", [round(r.get("score") or 0,1) for r in rs[:10]])
