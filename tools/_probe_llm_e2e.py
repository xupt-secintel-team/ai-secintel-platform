# -*- coding: utf-8 -*-
"""端到端验证：临时实例（新代码 + secrets.env 的 Key）能否真走 LLM 模式。

覆盖两件事：
  ① `/api/qa/status` 的 `env_key` 变 true（Key 加载链路）
  ② **GET 与 POST** 两条路径都走 LLM（验证 handle_chat_get 读环境配置的修复）

用独立端口 + 独立子进程，跑完主动撤掉，不留后台进程。
"""
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9061
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def jget(path, timeout=240):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.load(r)


def jpost(path, body, timeout=300):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


env = dict(os.environ)
env["AISEC_MAIN_SERVER"] = BASE
print("起临时实例 %s （端口 %d，加载语料需 20~60s）…" % (PYEXE, PORT))
p = subprocess.Popen([PYEXE, "-u", os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
try:
    ok = False
    for _ in range(600):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
            ok = True
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    if not ok:
        print("❌ 实例 300s 内未就绪")
        sys.exit(1)
    print("✅ 实例就绪")

    st = jget("/api/qa/status", timeout=60)
    print("\n① /api/qa/status → env_key=%s | model=%s | hint=%s"
          % (st.get("env_key"), st.get("model"), st.get("env_key_hint")))
    print("   vector_count=%s" % st.get("vector_count"))

    print("\n② POST /api/chat（走 LLM）…")
    t0 = time.time()
    r1 = jpost("/api/chat", {"q": "Ollama 有哪些已公开利用的漏洞？"})
    rc1 = r1.get("reasoning_chain") or {}
    print("   used_llm=%s | 模型=%s | strategy=%s | %.1fs | 结论 %d 字"
          % (r1.get("used_llm"), r1.get("model"), rc1.get("strategy"),
             time.time() - t0, len(r1.get("conclusion") or "")))
    print("   返回键：%s" % sorted(r1.keys()))
    if rc1.get("rounds") is not None:
        print("   agent 轮数=%s | 工具调用留痕条数=%s"
              % (rc1.get("rounds"), len(rc1.get("hops") or [])))
    print("   结论前 200 字：%s" % (r1.get("conclusion") or "")[:200].replace("\n", " "))

    print("\n③ GET /api/chat（验证 GET 也读环境配置）…")
    t0 = time.time()
    r2 = jget("/api/chat?q=" + urllib.parse.quote("提示词注入怎么防？"), timeout=300)
    print("   used_llm=%s | 模型=%s | %.1fs | 结论 %d 字"
          % (r2.get("used_llm"), r2.get("model"), time.time() - t0,
             len(r2.get("conclusion") or "")))

    print("\n④ GET /api/chat?no_llm=1（显式强制模板）…")
    r3 = jget("/api/chat?q=" + urllib.parse.quote("Ollama 漏洞") + "&no_llm=1")
    print("   used_llm=%s （应为 False）" % r3.get("used_llm"))

    print("\n=== 判定 ===")
    print("env_key 为真      :", bool(st.get("env_key")))
    print("POST 走 LLM       :", bool(r1.get("used_llm")))
    print("GET 走 LLM        :", bool(r2.get("used_llm")))
    print("no_llm 强制模板   :", r3.get("used_llm") is False)
finally:
    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n临时实例已撤。")
