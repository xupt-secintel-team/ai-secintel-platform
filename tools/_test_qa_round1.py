# -*- coding: utf-8 -*-
"""_test_qa_round1.py —— 情报问答「第 1 轮实测审计」全部修复项的综合验证

一次真起服务，验证 4 个修复项在**真实 HTTP 链路**上都生效：
  A. 零命中诚实化（不存在术语 → 明确说没匹配、证据为空）
  B. 冷启动（首问不再排队在预热后面 → 秒级）
  C. 多轮上下文（"那怎么修"能接上上一轮实体，返回 resolved_ref）
  D. 口径一致（/api/qa/status 的 vector_model 非空，且与 probe 一致）

用法： py tools/_test_qa_round1.py [端口]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8941
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable
PASS = FAIL = SKIP = 0


def ok(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (label, extra))


def _start():
    env = dict(os.environ)
    env["AISEC_MAIN_SERVER"] = BASE
    p = subprocess.Popen([PYEXE, os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         env=env, bufsize=1, universal_newlines=True,
                         encoding="utf-8", errors="replace")
    state = {"up": None, "ready": None}
    t0 = time.time()

    def pump():
        for line in p.stdout:
            if state["up"] is None and "控制台已启动" in line:
                state["up"] = time.time() - t0
            if "预热处理完成" in line:
                state["ready"] = time.time() - t0
    threading.Thread(target=pump, daemon=True).start()
    for _ in range(400):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
            if state["up"] is None:
                state["up"] = time.time() - t0
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    return p, state, t0


def _get(path, timeout=120):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.load(r)


def _chat(q, history=None, timeout=180):
    body = {"q": q, "no_llm": True}
    if history:
        body["history"] = history
    req = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    t = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r), (time.time() - t)


def main():
    p, state, t0 = _start()
    if state["up"] is None:
        print("服务未能启动"); p.terminate(); return 1
    try:
        print("端口可用 %.2fs" % state["up"])

        print("\n[B] 冷启动：端口开后首问必须秒级（不排队在预热后）")
        r1, ms1 = _chat("Ollama 有哪些漏洞")
        ok("首问耗时 < 8s（修复前实测 31.93s）", ms1 < 8.0, "%.2fs" % ms1)
        r2, ms2 = _chat("vLLM 有哪些漏洞")
        ok("次问也快", ms2 < 8.0, "%.2fs" % ms2)
        ok("首问/次问耗时不悬殊（说明不在预热后面排队）",
           abs(ms1 - ms2) < 6.0, "首 %.2f 次 %.2f" % (ms1, ms2))

        print("\n[A] 零命中诚实化")
        rn, _ = _chat("zzzqqq不存在的术语xyzzy")
        cn = (rn.get("conclusion") or rn.get("answer") or "")
        m_hit = re.search(r"命中\s*\**\s*(\d+)\s*\**\s*条\s*相关情报", cn)
        ok("不得自称'命中 N 条相关情报'", not m_hit,
           (m_hit.group(0) if m_hit else "") + " | " + cn[:100])
        ok("结论明确表示未命中",
           any(k in cn for k in ("没有与该问题匹配", "未命中高相关度", "未在情报库中检索到")),
           cn[:120])
        ok("证据为空（不兜底填充）",
           len(rn.get("evidence") or []) == 0 and len(rn.get("sources") or []) == 0)
        rc = rn.get("reasoning_chain") or {}
        ok("reasoning_chain 标记 zero_hit", rc.get("zero_hit") is True,
           json.dumps(rc.get("relevance"), ensure_ascii=False)[:120])

        print("\n[C] 多轮上下文")
        hist = [{"role": "user", "content": r1.get("conclusion", "")[:0] or "Ollama 有哪些漏洞"},
                {"role": "assistant", "content": (r1.get("conclusion") or "")[:2000]}]
        rm, _ = _chat("那怎么修", history=hist)
        ok("多轮承接返回 resolved_ref", bool(rm.get("resolved_ref")),
           str(rm.get("resolved_ref")))
        rm2, _ = _chat("还有别的吗", history=hist)
        ok("'还有别的吗' 也承接", bool(rm2.get("resolved_ref")), str(rm2.get("resolved_ref")))

        print("\n[D] 口径一致")
        st = _get("/api/qa/status")
        vm = (st or {}).get("vector_model") or ""
        ok("/api/qa/status.vector_model 非空", bool(vm), "vector_model=%r" % vm)
        vc = st.get("vector_count") or 0
        ok("向量库条数 > 0", vc > 0, "count=%d" % vc)
        if vc > 0:
            probe = _get("/api/qa/vector_probe?q=ollama&k=3")
            pm = ((probe or {}).get("embedder") or {}).get("model") or (probe or {}).get("model") or ""
            ok("status 与 probe 的模型口径一致（或 probe 未暴露该字段）",
               (not pm) or (pm == vm), "status=%r probe=%r" % (vm, pm))
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()

    print("\n" + "=" * 60)
    print("  通过 %d · 失败 %d · 跳过 %d" % (PASS, FAIL, SKIP))
    print("=" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
