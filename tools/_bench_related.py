# -*- coding: utf-8 -*-
import io, sys, json, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(p, o, t=180):
    r=urllib.request.Request(B+p, data=json.dumps(o,ensure_ascii=False).encode(), headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(r, timeout=t) as x: return json.loads(x.read().decode())
d=post("/api/chat", {"q":"vLLM 有哪些高危漏洞","no_llm":True})
print("related:", len(d.get("related") or []), json.dumps((d.get("related") or [])[:3], ensure_ascii=False)[:500])
print("evidence:", len(d.get("evidence") or []), "elapsed:", d.get("elapsed_ms"), "cache_hit:", d.get("cache_hit"))
