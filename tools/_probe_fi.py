# -*- coding: utf-8 -*-
import io, sys, json, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(p,o,t=240):
    r=urllib.request.Request(B+p,data=json.dumps(o,ensure_ascii=False).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(r,timeout=t) as x: return json.loads(x.read().decode())
for q in ["CVE-2026-94627（vLLM）有哪些关联的研究论文？","ollama 有多少个高危漏洞（CVSS≥7）？"]:
    d=post("/api/chat", {"q":q})
    ag=d.get("agent") or {}
    print("Q:", q)
    print(" mode:", ag.get("mode"), "trace:", [(t.get("tool"), t.get("n")) for t in (ag.get("trace") or [])][:6])
    print(" ans:", (d.get("answer") or "")[:700].replace("\n"," "))
    print(" evidence:", [e.get("id") for e in (d.get("evidence") or [])][:5])
    print("---")
