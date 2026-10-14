# -*- coding: utf-8 -*-
"""_probe_live_check.py —— 校核两件事（承接复检中"疑似是我的探针错了"的点）

1. /api/live 真实返回结构与条目数：之前 _probe_rubric 用 body["items"] 解析，
   而 live_status 实际返回的是 "recent"（见 modules/m1_monitor/api.py:68-71），
   —— 用错键会读出恒 0。这里直接把**原始键名**打出来，避免我误判系统。
2. 冷启动首问延迟：复检时测到 18.6s（基线 3.8s），需判断是否环境干扰。
   这里连问同一题 3 次，看首问与后续问的差值（冷 vs 热）。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8934
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def get(path, timeout=120):
    t0 = time.time()
    r = urllib.request.urlopen(BASE + path, timeout=timeout)
    return r.status, r.read().decode("utf-8", "replace"), time.time() - t0


def post(path, payload, timeout=180):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.status, r.read().decode("utf-8", "replace"), time.time() - t0


def main() -> int:
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    threading.Thread(target=lambda: p.stdout.read(), daemon=True).start()
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            st, _, _ = get("/api/health", timeout=5)
            if st == 200:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2)
    print("启动可服务\n")

    st, body, dt = get("/api/live?n=50")
    print("[1] /api/live → %s · %.0fms" % (st, dt * 1000))
    print("    原始顶层键：%s" % list(json.loads(body).keys()))
    d = json.loads(body)
    rec = d.get("recent") or []
    print("    recent 条数：%d · live_docs=%s · feed_ok=%s · feed_fail=%s"
          % (len(rec), d.get("live_docs"), d.get("feed_ok"), str(d.get("feed_fail"))[:80]))
    if rec:
        print("    首条：%s" % str(rec[0])[:140])
        print("    是否回放（含 replay 标记）：%s"
              % any("replay" in str(x) for x in rec[:10]))

    print("\n[2] 冷/热延迟：同一题连问 3 次")
    for i in range(3):
        st, body, dt = post("/api/chat", {"q": "Ollama 有哪些高危漏洞？"})
        n = len(json.loads(body).get("answer") or "") if st == 200 else -1
        print("    第 %d 次：%.1fs · 答案 %d 字" % (i + 1, dt, n))

    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n已关闭测试实例（端口 %d）" % PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
