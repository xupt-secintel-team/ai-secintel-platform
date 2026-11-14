# -*- coding: utf-8 -*-
import io, sys, json, time, urllib.parse, urllib.request
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
B = "http://127.0.0.1:8848"
def get(path, **params):
    url = B + path + ("?" + urllib.parse.urlencode(params) if params else "")
    t0 = time.time()
    with urllib.request.urlopen(url, timeout=120) as r:
        data = json.loads(r.read().decode("utf-8"))
    return (time.time()-t0)*1000, data

def post(path, obj, timeout=180):
    req = urllib.request.Request(B+path, data=json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type":"application/json"})
    t0=time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8"))
    return (time.time()-t0)*1000, data

qs = ["vLLM 有哪些高危漏洞", "ollama 漏洞", "CVE-2024-37032", "提示词注入怎么防",
      "kev:yes cvss>=9", "最近被在野利用的高危漏洞", "LangChain 提示词注入", "影响面很大的网络设备漏洞"]
print("== search ==")
lat=[]
for q in qs:
    ms, d = get("/api/search", q=q, size=10)
    lat.append(ms)
    print("%7.0fms  total=%s  %s" % (ms, d.get("total"), q))
lat.sort(); print("search p50=%.0fms" % lat[len(lat)//2])

print("== chat template (no_llm) ==")
for q in ["Ollama 有哪些远程代码执行漏洞？", "最近被在野利用的高危漏洞有哪些？", "CVE-2024-37032 影响哪些版本？"]:
    ms, d = post("/api/chat", {"q": q, "no_llm": True})
    print("%7.0fms used_llm=%s src=%d  %s" % (ms, d.get("used_llm"), len(d.get("sources") or []), q))
