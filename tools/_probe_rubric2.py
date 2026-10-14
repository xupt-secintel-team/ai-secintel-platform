# -*- coding: utf-8 -*-
"""_probe_rubric2.py —— 复测：多轮带 history + 实时流热态 + 修复建议字段

承接 _probe_rubric.py 的两个"疑似问题"，做公平复测：
  1. 上一轮追问失败可能是因为**没带 history**（系统支持多轮，UI 会传）
     → 这里按契约 [{role,content}] 带上首轮问答，再问"这些漏洞应该怎么修复"
  2. 冷启动首屏 /api/live 为 0 → 等一个轮询周期（15s）后复测，判断是冷启动竞态还是真空
用法： py tools/_probe_rubric2.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8922
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def get(path, timeout=120):
    t0 = time.time()
    try:
        r = urllib.request.urlopen(BASE + path, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:  # noqa: BLE001
        return 0, str(e), time.time() - t0


def post(path, payload, timeout=180):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(BASE + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:  # noqa: BLE001
        return 0, str(e), time.time() - t0


def boot():
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    threading.Thread(target=lambda: [p.stdout.read()], daemon=True).start()
    deadline = time.time() + 180
    while time.time() < deadline:
        st, _, _ = get("/api/health", timeout=5)
        if st == 200:
            return p
        time.sleep(2)
    return None


def main() -> int:
    p = boot()
    if not p:
        print("启动失败")
        return 1
    print("启动可服务\n")

    st, body, _ = get("/api/live?n=50")
    n0 = 0
    try:
        n0 = len(json.loads(body).get("items") or [])
    except Exception:  # noqa: BLE001
        pass
    print("[实时流] 冷启动即刻 /api/live 条目：%d" % n0)
    time.sleep(45)   # 等 3 个快车道轮询周期（15s/次）
    st, body, _ = get("/api/live?n=50")
    n1 = 0
    try:
        n1 = len(json.loads(body).get("items") or [])
    except Exception:  # noqa: BLE001
        pass
    print("[实时流] 等待 45s 后 /api/live 条目：%d  → %s"
          % (n1, "恢复正常" if n1 > 0 else "仍为空（真问题）"))

    # ── 多轮：带上首轮问答再追问修复建议
    q1 = "Ollama 有哪些高危漏洞？"
    st, body, dt = post("/api/chat", {"q": q1})
    a1 = ""
    try:
        a1 = json.loads(body).get("answer") or ""
    except Exception:  # noqa: BLE001
        pass
    print("\n[多轮] 首轮 → %s · %.0fms · 答案 %d 字" % (st, dt * 1000, len(a1)))

    q2 = "这些漏洞应该怎么修复？给出修复建议。"
    st, body, dt = post("/api/chat", {"q": q2, "history": [
        {"role": "user", "content": q1},
        {"role": "assistant", "content": a1[:1500]},
    ]})
    print("[多轮] 追问（带 history）→ %s · %.0fms" % (st, dt * 1000))
    try:
        d = json.loads(body)
        ans = d.get("answer") or ""
        print("  答案 %d 字 · used_llm=%s · note=%s"
              % (len(ans), d.get("used_llm"), (d.get("history_note") or "")[:80]))
        print("  前 300 字：%s" % ans[:300].replace("\n", " "))
        for k in ("fix_section", "version_section", "attack_section"):
            v = d.get(k)
            if v:
                s = json.dumps(v, ensure_ascii=False)
                print("  %s: %s" % (k, s[:220]))
    except Exception as e:  # noqa: BLE001
        print("  解析失败", e, body[:300])

    # ── 修复建议：直接按 CVE 查修复字段
    st, body, dt = get("/api/detail?id=CVE-2024-37032")
    print("\n[富化·修复] /api/detail?CVE-2024-37032 → %s · %.0fms" % (st, dt * 1000))
    try:
        d = json.loads(body)
        rec = d.get("item") or d.get("data") or d
        for k in ("cvss", "cwe", "cpe", "products", "poc_links", "papers",
                  "patch_links", "remediation", "kev"):
            v = rec.get(k)
            print("  %-12s %s %s" % (k, "空" if v in (None, "", [], {}) else "有值",
                                     str(v)[:80] if v else ""))
    except Exception as e:  # noqa: BLE001
        print("  解析失败", e, body[:300])

    st, body, dt = get("/api/remediation?id=CVE-2024-37032")
    print("\n[富化·修复方案] /api/remediation → %s · %.0fms · %s"
          % (st, dt * 1000, body[:200].replace("\n", " ")))

    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n已关闭测试实例（端口 %d）" % PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
