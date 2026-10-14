# -*- coding: utf-8 -*-
"""_probe_fix_answer.py —— 只看一件事：泛指修复意图的追问，答案里到底有没有"修复建议"

承接复检：改动后 "这些漏洞应该怎么修复？给出修复建议。" 不再返回"知识库无匹配"，
但答案开头是「情报汇总（来源与风险统计）」。这里把**完整答案**打出来，
人工判读：修复建议段（补丁链接 / 版本区间 / 升级路径）到底有没有进正文。
用法： py tools/_probe_fix_answer.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8935
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def get(path, timeout=60):
    return urllib.request.urlopen(BASE + path, timeout=timeout).status


def post(path, payload, timeout=180):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.read().decode("utf-8", "replace"), time.time() - t0


def main() -> int:
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    threading.Thread(target=lambda: p.stdout.read(), daemon=True).start()
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if get("/api/health") == 200:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2)
    print("启动可服务\n")

    # 场景一：先问 Ollama，再泛指追问（带 history）
    q1 = "Ollama 有哪些高危漏洞？"
    b1, _ = post("/api/chat", {"q": q1})
    a1 = json.loads(b1).get("answer") or ""
    b2, dt = post("/api/chat", {"q": "这些漏洞应该怎么修复？给出修复建议。",
                                "history": [{"role": "user", "content": q1},
                                            {"role": "assistant", "content": a1[:1500]}]})
    d2 = json.loads(b2)
    ans = d2.get("answer") or ""
    print("=== 场景一·带 history 的泛指修复追问（%.1fs，%d 字）===" % (dt, len(ans)))
    print(ans[:2400])
    print("\n-- 判读 --")
    for kw in ("修复", "补丁", "升级", "版本", "缓解", "配置"):
        print("  含「%s」：%s（%d 处）" % (kw, kw in ans, ans.count(kw)))

    # 场景二：直接问 CVE 的修复建议（有明确实体）
    b3, dt3 = post("/api/chat", {"q": "CVE-2024-37032 应该怎么修复？给出修复建议。"})
    d3 = json.loads(b3)
    ans3 = d3.get("answer") or ""
    print("\n\n=== 场景二·带明确 CVE 的修复追问（%.1fs，%d 字）===" % (dt3, len(ans3)))
    print(ans3[:1800])

    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n已关闭测试实例（端口 %d）" % PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
