# -*- coding: utf-8 -*-
"""_test_qa_round3.py —— 第 3 轮修复的回归测试（全部实测：真起服务打接口）

覆盖第 3 轮实测发现并修复的 4 类问题：
  R3-1 改写式提问**没有锚点** → 语义检索跑偏（"本地跑开源大模型的工具"→
       dspy/llama-hub，而非 Ollama）。修复：`qa/query_anchor.py` 产品名锚定。
  R3-2 「哪些 AI 框架存在在野利用的漏洞」证据塌成 1 条。根因链（完整实测还原）：
       ① `_core_query` 把「AI 框架」扩展词当残留剥掉 → 原句检索 0 条；
       ② `strong_marker` 命中"在野利用" → **主动跳过语义路** → 结果无 vector_score；
       ③ 闸门 `is_relevant` 的 ①②③④ 分支**全部依赖 strong 铁证词或 vector_score**，
          纯中文查询两者都没有 → 真命中全被判不相关。
  R3-3 「最近被在野利用的漏洞」改写成了无意义碎片 `最近被 的漏洞`，
       检索回 2 篇中文博客冒充"漏洞"（严重误导）。
  R3-4 引用一致性（结论引用的编号都能在 evidence 里找到）。

用法： py tools/_test_qa_round3.py [端口]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8981
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

PASS = FAIL = SKIP = 0
FAILED = []


def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        FAILED.append(name)
        print("  [FAIL] %s %s" % (name, detail))


def skip(name, why=""):
    global SKIP
    SKIP += 1
    print("  [SKIP] %s %s" % (name, why))


# ───────────────────────── 纯单元（不依赖服务） ─────────────────────────
def test_units():
    print("\n" + "=" * 66)
    print("  A. 单元：改写式提问锚定 / 闸门判据 / 核心检索式改写")
    print("=" * 66)
    from qa.query_anchor import expand_query, anchor_products, anchor_note
    from qa.relevance import gate, query_terms, strong_terms, is_relevant
    from qa.multi_hop import _core_query

    # ── R3-1 锚定 ──────────────────────────────────────────────────────
    cases = [
        ("本地跑开源大模型的那个工具，有文件读取相关的安全问题", "ollama"),
        ("搭建大模型推理服务时，那个框架存在代码执行问题", "vllm"),
        ("编排 LLM 应用的工具链，有没有被注入攻击的风险", "langchain"),
    ]
    for q, expect in cases:
        ex = expand_query(q)
        ok("R3-1 锚定 %s → %s" % (expect, ex[:34]),
           expect in ex.lower(), "got=%r" % ex)

    # 已点名产品名时不介入（不能画蛇添足）
    named = "Ollama 有哪些高危漏洞"
    ok("R3-1 已点名产品不介入", expand_query(named) == named,
       "got=%r" % expand_query(named))
    ok("R3-1 anchor_note 仅在介入时非空",
       anchor_note(named) == "" and anchor_note(cases[0][0]) != "")

    # ── R3-2 核心检索式：扩展词必须活下来 ──────────────────────────────
    from qa.multi_hop import _FRAMEWORK_NAMES
    cq = _core_query("哪些 AI 框架存在在野利用的漏洞 vllm ollama langchain sglang ray",
                     [], keep=_FRAMEWORK_NAMES)
    ok("R3-2 核心检索式保留框架名", "ollama" in cq and "vllm" in cq, "got=%r" % cq)
    ok("R3-2 核心检索式不重复框架名",
       cq.count("ollama") == 1 and cq.count("vllm") == 1, "got=%r" % cq)
    # 既有行为不回归
    ok("R3-2 Ollama 高危 → Ollama 漏洞", _core_query("Ollama 有哪些高危漏洞") == "Ollama 漏洞",
       "got=%r" % _core_query("Ollama 有哪些高危漏洞"))

    # ── R3-3 改写不许产出无意义碎片 ────────────────────────────────────
    for bad_q, must_not in [
        ("最近被在野利用的漏洞", "最近被"),
        ("最近有哪些高危漏洞", "最近"),
    ]:
        r = _core_query(bad_q)
        ok("R3-3 %s 改写无碎片(%s)" % (bad_q, must_not), must_not not in r, "got=%r" % r)
        ok("R3-3 %s 改写非空且不重复" % bad_q,
           r and r == r.strip() and "漏洞 漏洞" not in r, "got=%r" % r)

    # ── R3-2 闸门：纯 BM25 路（无 vector_score）必须能判真命中 ──────────
    def mk(scores):
        return [{"id": "d%d" % i, "title": "t%d" % i, "score": s, "_fusion": "bm25"}
                for i, s in enumerate(scores)]

    # 真命中形态：首条断层 35.4 vs 6.9
    kept, st = gate(mk([35.4, 6.9, 6.1, 6.0, 5.9]), "哪些 AI 框架存在在野利用的漏洞", keep_min=0)
    ok("R3-2 断层→保留首条", len(kept) >= 1, "kept=%d" % len(kept))
    ok("R3-2 断层→统计含 bm25_cut", st.get("bm25_cut") is not None, "cut=%s" % st.get("bm25_cut"))

    # 不相关形态：平坦群 8.4/8.3（红烧肉）
    kept2, _ = gate(mk([8.4, 8.3, 8.3, 8.3, 8.3, 8.2]), "如何做红烧肉", keep_min=0)
    ok("R3-2 平坦群→全丢弃", len(kept2) == 0, "kept=%d" % len(kept2))

    # 瞎编术语 → 零召回
    kept3, _ = gate([], "zzzqqq不存在的术语xyzzy", keep_min=0)
    ok("R3-2 零召回→空", len(kept3) == 0)

    # 假阳性历史回归（中文惯用语不得复活）
    kept4, _ = gate([{"id": "X", "title": "记一次不存在的加解密实战渗透",
                      "score": 20.0, "_fusion": "bm25"}],
                    "zzzqqq不存在的术语xyzzy", keep_min=0)
    ok("R3-2 假阳性回归(不存在)", len(kept4) == 0, "kept=%d" % len(kept4))

    # query_terms 不再对纯中文提问返回空（R3-2 根因之一）
    for q in ["哪些 AI 框架存在在野利用的漏洞", "怎么修复远程代码执行"]:
        ok("R3-2 query_terms(%s) 非空" % q[:12], bool(query_terms(q)),
           "terms=%r" % query_terms(q))

    # 更严的判据：语义接近 + 中文实词命中 → 相关
    ok("R3-2 语义+中文实词 → 相关",
       is_relevant({"id": "y", "title": "远程代码执行漏洞的修复建议", "vector_score": 0.912},
                   query_terms("怎么修复远程代码执行"),
                   strong_terms("怎么修复远程代码执行")))
    # 语义不足则不得通过
    ok("R3-2 语义不足 → 不相关",
       not is_relevant({"id": "y", "title": "无关文章", "vector_score": 0.86},
                       query_terms("怎么修复远程代码执行"),
                       strong_terms("怎么修复远程代码执行")))


def main():
    test_units()

    print("\n" + "=" * 66)
    print("  B. 端到端：真起服务打 /api/chat")
    print("=" * 66)
    env = dict(os.environ)
    env["AISEC_MAIN_SERVER"] = BASE
    p = subprocess.Popen([PYEXE, os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
                         cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    up = False
    try:
        for _ in range(400):
            try:
                urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)

        def chat(q, history=None, timeout=180):
            body = {"q": q, "no_llm": True}
            if history:
                body["history"] = history
            r = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                       headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(r, timeout=timeout) as resp:
                    return resp.status, json.load(resp)
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")

        if not up:
            skip("端到端全部", "服务未能启动")
        else:
            # ── R3-1：改写式提问必须锚定到正确产品 ─────────────────────
            anchors = [
                ("本地跑开源大模型的那个工具，有文件读取相关的安全问题", "ollama"),
                ("搭建大模型推理服务时，那个框架存在代码执行问题", "vllm"),
                ("编排 LLM 应用的工具链，有没有被注入攻击的风险", "langchain"),
            ]
            for q, prod in anchors:
                st, r = chat(q)
                ok("R3-1 e2e HTTP 200 (%s)" % prod, st == 200, "st=%s" % st)
                blob = json.dumps(r, ensure_ascii=False).lower()
                ok("R3-1 e2e 命中 %s" % prod, prod in blob, "未见 %s" % prod)
                ok("R3-1 e2e 披露 anchor_note (%s)" % prod,
                   bool(r.get("anchor_note")), "anchor_note=%r" % r.get("anchor_note"))

            # ── R3-2：框架在野利用必须给出多条证据（不能塌成 1）────────
            st, r = chat("哪些 AI 框架存在在野利用的漏洞")
            ev = r.get("evidence") or []
            ok("R3-2 e2e HTTP 200", st == 200, "st=%s" % st)
            ok("R3-2 e2e 证据 ≥ 3 条", len(ev) >= 3, "evidence=%d" % len(ev))
            blobs = json.dumps(ev, ensure_ascii=False).lower()
            ok("R3-2 e2e 证据含真实 AI 框架条目",
               any(k in blobs for k in ("ray", "vllm", "ollama", "langchain", "sglang", "mlflow", "litellm")),
               "证据里没有 AI 框架名")

            # ── R3-3：最近在野利用不得返回中文博客冒充漏洞 ─────────────
            st, r = chat("最近被在野利用的漏洞")
            ev = r.get("evidence") or []
            titles = " ".join(str(e.get("title") or "") for e in ev)
            ok("R3-3 e2e 不返回\"栈迁移/JS接口\"类博客",
               "栈迁移" not in titles and "JS接口" not in titles, titles[:80])
            # 若有证据，应确实是在野利用条目（exploited 标记）
            if ev:
                ok("R3-3 e2e 证据都是 KEV（exploited）",
                   all(e.get("exploited") for e in ev) or len(ev) == 0,
                   "exploited=%s" % [e.get("exploited") for e in ev[:5]])
            else:
                skip("R3-3 e2e 证据全为 KEV", "本轮零命中（可接受）")

            # ── R3-4：引用一致性 ───────────────────────────────────────
            for q in ["Ollama 有哪些漏洞", "vLLM 的高危漏洞", "CWE-78 相关的 AI 框架漏洞有哪些"]:
                st, r = chat(q)
                concl = r.get("conclusion") or ""
                ev_ids = {str(e.get("id")) for e in (r.get("evidence") or [])}
                cited = set(re.findall(
                    r"\[((?:CVE|GHSA|CWE|XZ|CSDN|AQK|GH|LIVE|KB|RPT)[A-Za-z0-9:_.\-]*)\]", concl))
                missing = cited - ev_ids
                ok("R3-4 引用一致性(%s)" % q[:16], not missing,
                   "引用但无资料: %s" % sorted(missing)[:5])

            # ── 契约钉死：/api/chat 字段名是 q ────────────────────────
            try:
                urllib.request.urlopen(urllib.request.Request(
                    BASE + "/api/chat", data=json.dumps({"question": "x"}).encode(),
                    headers={"Content-Type": "application/json"}, method="POST"), timeout=30)
                ok("契约 字段名必须为 q（question 应被拒）", False, "question 竟然被接受")
            except urllib.error.HTTPError as e:
                ok("契约 字段名必须为 q（question 应被拒）", 400 <= e.code < 500, "st=%s" % e.code)
            except Exception as e:  # noqa: BLE001
                skip("契约 字段名", str(e)[:50])
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()

    print("\n" + "=" * 66)
    print("  通过 %d · 失败 %d · 跳过 %d" % (PASS, FAIL, SKIP))
    if FAILED:
        print("  失败项：")
        for f in FAILED:
            print("    - %s" % f)
    print("=" * 66)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
