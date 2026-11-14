# -*- coding: utf-8 -*-
import io, sys, json, time, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(path, obj, timeout=180):
    req=urllib.request.Request(B+path, data=json.dumps(obj,ensure_ascii=False).encode(), headers={"Content-Type":"application/json"})
    t0=time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r: d=json.loads(r.read().decode())
    return (time.time()-t0)*1000, d
qs=["Ollama 有哪些远程代码执行漏洞？","最近被在野利用的高危漏洞有哪些？","vLLM 有哪些高危漏洞？"]
for q in qs:
    ms,d=post("/api/chat", {"q":q})
    ag=d.get("agent") or {}
    print("%.0fms used_llm=%s mode=%s calls=%s citations=%d ans=%d" % (ms,d.get("used_llm"),ag.get("mode"),ag.get("tool_calls"),len(ag.get("citations") or []),len(d.get("answer") or "")))
    print("   trace:", [(t.get("tool"), t.get("n"), t.get("ms")) for t in (ag.get("trace") or [])])
