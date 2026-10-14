# -*- coding: utf-8 -*-
"""_probe_qa.py —— 情报问答模块**实测探针**（真起服务打接口，输出原始观察）

不是断言测试，是"看清现状"的工具：把 /api/chat 的多轮对话、语义检索、
跨文档推理、响应时间全部真打一遍，把**原始响应**打出来供人工判读。
用法： py tools/_probe_qa.py [端口]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8917
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def req(method, path, payload=None, timeout=120):
    url = BASE + path
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, body, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, e.read(), (time.time() - t0) * 1000
    except Exception as e:
        return -1, str(e).encode(), (time.time() - t0) * 1000


def show(label, st, body, ms, limit=900):
    txt = body.decode("utf-8", "replace")
    try:
        j = json.loads(txt)
        txt = json.dumps(j, ensure_ascii=False, indent=1)
    except Exception:
        pass
    print("\n--- %s ---" % label)
    print("HTTP %s · %.0f ms" % (st, ms))
    print(txt[:limit] + (" …[截断]" if len(txt) > limit else ""))


def main() -> int:
    print("起服务：%s core/server.py %d" % (PYEXE, PORT))
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logs = []

    def pump():
        for line in p.stdout:
            logs.append(line.decode("utf-8", "replace"))
    threading.Thread(target=pump, daemon=True).start()

    ok = False
    for _ in range(90):
        if p.poll() is not None:
            break
        st, _, _ = req("GET", "/api/health", timeout=3)
        if st in (200, 503):
            ok = True
            break
        time.sleep(0.5)
    if not ok:
        print("服务未起来。日志尾部：")
        print("".join(logs[-40:]))
        try:
            p.kill()
        except Exception:
            pass
        return 1
    print("服务就绪。")

    try:
        show("① /api/qa/status（模块能力自述）", *req("GET", "/api/qa/status"))
        show("② /api/qa/coverage（知识覆盖）", *req("GET", "/api/qa/coverage"))
        show("③ /api/qa/agent/tools（工具清单）", *req("GET", "/api/qa/agent/tools"))

        print("\n\n########## 问答主链路 ##########")
        qs = [
            ("基础检索问答", "Ollama 有什么漏洞"),
            ("影响范围", "CVE-2024-37032 影响哪些版本"),
            ("修复建议", "怎么修复 Ollama 的远程代码执行"),
            ("语义（不给关键词）", "有没有能让攻击者在我服务器上执行任意代码的组件问题"),
            ("跨文档推理", "哪些在野利用的漏洞和勒索软件有关"),
            ("多跳推理", "从提示词注入到数据泄漏的完整攻击链是什么"),
        ]
        for label, q in qs:
            st, body, ms = req("POST", "/api/chat", {"q": q, "message": q, "question": q})
            show("POST /api/chat · %s：%s" % (label, q), st, body, ms, 1200)

        print("\n\n########## 多轮对话（同一 session 追问） ##########")
        sid = "probe-%d" % int(time.time())
        for i, q in enumerate(["Ollama 的漏洞", "它影响哪些版本", "那怎么修", "还有别的吗"]):
            st, body, ms = req("POST", "/api/chat",
                               {"q": q, "message": q, "question": q, "session": sid, "sid": sid,
                                "history": [{"role": "user", "content": "Ollama 的漏洞"}]} if i == 0
                               else {"q": q, "message": q, "question": q, "session": sid, "sid": sid,
                                     "history": [{"role": "user", "content": "Ollama 的漏洞"},
                                                 {"role": "assistant", "content": "（上轮回答）"}]})
            show("多轮 #%d：%s" % (i + 1, q), st, body, ms, 900)

        print("\n\n########## 边界与错误路径 ##########")
        for label, payload in [
            ("空问题", {"q": "", "message": ""}),
            ("超长问题", {"q": "漏洞" * 2000}),
            ("纯符号", {"q": "???"}),
            ("无匹配内容", {"q": "zzzqqq不存在的术语xyzzy"}),
            ("缺字段", {}),
        ]:
            st, body, ms = req("POST", "/api/chat", payload, timeout=60)
            show("边界 · %s" % label, st, body, ms, 500)

        print("\n\n########## 其它问答接口 ##########")
        show("GET /api/qa/vector_probe", *req("GET", "/api/qa/vector_probe?q=ollama&k=3"))
        show("GET /api/hybrid_search", *req("GET", "/api/hybrid_search?q=ollama&k=3"))
        show("GET /api/qa/agent/trace", *req("GET", "/api/qa/agent/trace"))

    finally:
        try:
            p.terminate()
            p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
