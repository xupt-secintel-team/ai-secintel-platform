# -*- coding: utf-8 -*-
import io, sys, json, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(p,o,t=240):
    r=urllib.request.Request(B+p,data=json.dumps(o,ensure_ascii=False).encode(),headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(r,timeout=t) as x: return json.loads(x.read().decode())
q="GitLab 相关的、已被在野利用的漏洞有哪些？"
d=post("/api/chat", {"q":q,"no_llm":True})
print("answer head:", (d.get("answer") or "")[:600].replace("\n"," "))
rc=d.get("reasoning_chain") or {}
print("hops:", [(h.get("query"), h.get("hits")) for h in (rc.get("hops") or [])])
print("evidence:", [e.get("id") for e in (d.get("evidence") or [])][:8])
