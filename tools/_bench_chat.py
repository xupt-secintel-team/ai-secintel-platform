# -*- coding: utf-8 -*-
import io, sys, json, time, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(path, obj, timeout=180):
    req=urllib.request.Request(B+path, data=json.dumps(obj,ensure_ascii=False).encode(), headers={"Content-Type":"application/json"})
    t0=time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r: d=json.loads(r.read().decode())
    return (time.time()-t0)*1000, d
for q in ["Ollama 有哪些远程代码执行漏洞？","最近被在野利用的高危漏洞有哪些？"]:
    for i in range(2):
        ms,d = post("/api/chat", {"q":q,"no_llm":True})
        rc = d.get("reasoning_chain") or {}
        print("%s #%d  %.0fms  elapsed_ms=%s  strategy=%s hops=%s" % (q[:16], i, ms, d.get("elapsed_ms"), rc.get("strategy"), [(h.get("query"), h.get("hits"), h.get("ms")) for h in (rc.get("hops") or [])]))
