# -*- coding: utf-8 -*-
import io, sys, json, time, urllib.request, statistics
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B="http://127.0.0.1:8848"
def post(p,o,t=240):
    r=urllib.request.Request(B+p,data=json.dumps(o,ensure_ascii=False).encode(),headers={"Content-Type":"application/json"})
    t0=time.time()
    with urllib.request.urlopen(r,timeout=t) as x: d=json.loads(x.read().decode())
    return (time.time()-t0)*1000, d
qs=[
 "Ollama 有哪些远程代码执行漏洞？",
 "vLLM 有哪些高危漏洞？",
 "GitLab 相关的、已被在野利用的漏洞有哪些？",
 "已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？",
 "CVE-2024-37032 影响哪些版本？",
 "LangChain 的提示词注入问题怎么防？",
 "最近有哪些新的 AI 安全漏洞？",
 "Milvus 的严重漏洞有哪些？",
 "有公开 POC 且 CVSS≥9 的 XenForo 漏洞有哪些？",
 "提示词注入的攻击原理是什么？",
]
lats=[]
for q in qs:
    ms,d=post("/api/chat", {"q":q})
    ag=d.get("agent") or {}
    lats.append(ms)
    print("%7.0fms  %-12s %s" % (ms, ag.get("mode") or ("template" if not d.get("used_llm") else "?"), q[:34]))
lats_sorted=sorted(lats)
print("P50=%.0fms  P90=%.0fms  max=%.0fms  mean=%.0fms" % (
    lats_sorted[len(lats)//2], lats_sorted[int(len(lats)*0.9)], lats_sorted[-1], statistics.mean(lats)))
ms,d=post("/api/chat", {"q":qs[1]})
print("repeat: %.0fms cache_hit=%s" % (ms, d.get("cache_hit")))
