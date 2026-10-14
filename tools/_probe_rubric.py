# -*- coding: utf-8 -*-
"""_probe_rubric.py —— 按评分表口径实测三大能力（真起服务打接口，自收自撤）

测什么（对应评分表"功能/性能"项）：
  1. 监测：/api/live 实时条数 + 源健康度；/api/stats 语料规模
  2. 富化：/api/detail 取一条真实 CVE，看 CVSS/KEV/POC/论文/资产/修复 是否真的带值
  3. 问答：/api/chat 连问三类（影响范围 / 修复建议 / 攻击链），记耗时与是否含证据引用
  4. Agent：/api/ops/trace、/api/qa/agent/trace 看编排与问答智能体留痕
用法： py tools/_probe_rubric.py [端口]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8921
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def get(path, timeout=120):
    url = BASE + path
    t0 = time.time()
    try:
        r = urllib.request.urlopen(url, timeout=timeout)
        body = r.read().decode("utf-8", "replace")
        return r.status, body, time.time() - t0
    except Exception as e:  # noqa: BLE001
        return 0, str(e), time.time() - t0


def post(path, payload, timeout=180):
    url = BASE + path
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                 method="POST")
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:  # noqa: BLE001
        return 0, str(e), time.time() - t0


def main() -> int:
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    lines = []

    def pump():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=pump, daemon=True).start()

    ok = False
    deadline = time.time() + 180
    while time.time() < deadline:
        st, _, _ = get("/api/health", timeout=5)
        if st == 200:
            ok = True
            break
        time.sleep(2)
    print("启动可服务：%s\n" % ok)
    if not ok:
        p.terminate()
        return 1

    # ── 1 监测
    st, body, dt = get("/api/live?n=200")
    print("[监测] /api/live → %s · %.0fms" % (st, dt * 1000))
    try:
        d = json.loads(body)
        items = d.get("items") or []
        print("  实时条目：%d · total=%s" % (len(items), d.get("total")))
        srcs = {}
        for it in items:
            srcs[it.get("source") or it.get("src") or "?"] = srcs.get(it.get("source") or it.get("src") or "?", 0) + 1
        print("  本批来源数：%d → %s" % (len(srcs), list(srcs)[:12]))
        health = d.get("sources_health") or d.get("health") or []
        if health:
            good = [h for h in health if (h.get("ok") if isinstance(h, dict) else None)]
            print("  源健康度：%d 个源，其中 ok %d" % (len(health), len(good)))
    except Exception as e:  # noqa: BLE001
        print("  解析失败", e, body[:200])

    # ── 2 富化：找一条带 CVSS 的真实 CVE
    st, body, dt = get("/api/search?q=" + urllib.parse.quote("ollama") + "&n=5")
    cve = None
    try:
        d = json.loads(body)
        for it in (d.get("items") or []):
            if str(it.get("id", "")).startswith("CVE-"):
                cve = it["id"]
                break
    except Exception:  # noqa: BLE001
        pass
    print("\n[富化] 取样 CVE：%s" % cve)
    if cve:
        st, body, dt = get("/api/detail?id=" + urllib.parse.quote(cve))
        print("  /api/detail → %s · %.0fms" % (st, dt * 1000))
        try:
            d = json.loads(body)
            rec = d.get("item") or d.get("data") or d
            keys = ["cvss", "cwe", "cpe", "kev", "exploited", "poc_links", "poc_count",
                    "papers", "products", "patch_links", "remediation", "refs", "atlas"]
            for k in keys:
                v = rec.get(k)
                tag = "空" if v in (None, "", [], {}) else "有值"
                short = str(v)[:70].replace("\n", " ")
                print("    %-12s %s %s" % (k, tag, short if tag == "有值" else ""))
        except Exception as e:  # noqa: BLE001
            print("  解析失败", e, body[:300])

    # ── 3 问答：评分表点名的三类问题
    qs = [
        "Ollama 有哪些高危漏洞？影响范围是什么？",
        "这些漏洞应该怎么修复？给出修复建议。",
        "针对 Ollama 的漏洞，可能的攻击链是怎样的？",
    ]
    for q in qs:
        st, body, dt = post("/api/chat", {"q": q})
        print("\n[问答] %s → %s · %.0fms" % (q, st, dt * 1000))
        if st != 200:
            print("  ", body[:200])
            continue
        try:
            d = json.loads(body)
            ans = d.get("answer") or d.get("text") or ""
            cits = d.get("citations") or d.get("refs") or []
            print("  答案长度 %d 字 · 引用 %d 条 · used_llm=%s"
                  % (len(ans), len(cits), d.get("used_llm")))
            print("  答案前 260 字：%s" % ans[:260].replace("\n", " "))
            sec = [k for k in ("version_section", "fix_section", "attack_section") if d.get(k)]
            print("  三段能力字段：%s" % (sec or "无"))
        except Exception as e:  # noqa: BLE001
            print("  解析失败", e, body[:300])

    # ── 4 Agent 留痕
    for path in ("/api/ops/trace", "/api/ops/status", "/api/qa/agent/trace",
                 "/api/enrich/dimensions"):
        st, body, _ = get(path)
        head = body[:160].replace("\n", " ")
        print("\n[Agent] %s → %s · %s" % (path, st, head))

    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n已关闭测试实例（端口 %d）" % PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
