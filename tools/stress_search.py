# -*- coding: utf-8 -*-
"""重活检索压力测试：连续跑多轮大结果查询，看服务会不会倒（排查崩溃用）"""
import json
import sys
import time
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 12

QS = [("", {"size": 5}), ("漏洞", {"size": 5, "sort": "trust"}),
      ("gradio 漏洞", {"size": 5}), ("prompt injection", {"size": 5})]

ok = fail = 0
for i in range(N):
    for q, extra in QS:
        p = {"q": q, **extra}
        url = BASE + "/api/search?" + urllib.parse.urlencode(p)
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=180) as r:
                d = json.loads(r.read().decode("utf-8"))
            ok += 1
            print(f"  [{i+1}] OK  q={q!r:<18} total={d.get('total')} {(time.time()-t0):.2f}s", flush=True)
        except Exception as e:  # noqa: BLE001
            fail += 1
            print(f"  [{i+1}] !!  q={q!r:<18} {type(e).__name__}: {e}", flush=True)
            time.sleep(2)
print(f"结果：成功 {ok} / 失败 {fail}")
