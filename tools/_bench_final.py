# -*- coding: utf-8 -*-
import io, sys, json, time, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def get(p, **kw):
    with urllib.request.urlopen(B+p+"?"+urllib.parse.urlencode(kw), timeout=120) as r:
        return json.loads(r.read().decode())
def post(p, o, t=240):
    r=urllib.request.Request(B+p, data=json.dumps(o,ensure_ascii=False).encode(), headers={"Content-Type":"application/json"})
    t0=time.time()
    with urllib.request.urlopen(r, timeout=t) as x: d=json.loads(x.read().decode())
    return (time.time()-t0)*1000, d
d=get("/api/enrich/coverage")
print("coverage total:", d.get("total_docs"))
for x in (d.get("build_time_dims") or []): print("  B", x["key"], x["covered"], str(x["coverage_pct"])+"%")
for x in (d.get("on_demand_dims") or []): print("  O", x["key"], x["cached"], str(x["coverage_pct"])+"%")

print("== LLM latency ==")
qs=["Ollama 有哪些远程代码执行漏洞？","vLLM 有哪些高危漏洞？","GitLab 相关的、已被在野利用的漏洞有哪些？","已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？"]
for q in qs:
    ms,d=post("/api/chat", {"q":q})
    ag=d.get("agent") or {}
    print("%7.0fms used_llm=%s mode=%s calls=%s ans=%d" % (ms,d.get("used_llm"),ag.get("mode"),ag.get("tool_calls"),len(d.get("answer") or "")))
    print("        trace:", [(t.get("tool"), t.get("n"), t.get("ms")) for t in (ag.get("trace") or [])][:5])
print("== cache replay ==")
ms,d=post("/api/chat", {"q":"vLLM 有哪些高危漏洞？"})
print("%7.0fms cache_hit=%s elapsed=%s" % (ms, d.get("cache_hit"), d.get("elapsed_ms")))
