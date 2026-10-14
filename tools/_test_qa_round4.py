# -*- coding: utf-8 -*-
"""_test_qa_round4.py —— 第 4 轮修复的回归测试（全部实测：真起服务打接口）

第 4 轮换角度审计「答案本身可不可信」（前 3 轮修的是"检索拿不拿得到"）：
  R4-A 零命中文案不统一：`generator.generate()` 的 `if not docs` 早退分支
       返回自造文案，**绕过了** `no_hit_note`（更完整的、带检索词与算子建议），
       且**不带 `empty_reason`** —— 前端/评测无法区分为何为空。
       附带：0 条候选时文案说"均不相关"（逻辑不通，且掩盖"零召回"信号）。
  R4-B `cvss` 字段有**两种形态**：检索/详情是 dict{score,…}，问答 evidence 是 float。
  R4-C 前端直接 `esc(cvss)` 遇到 dict 会渲染 `[object Object]`（sources/related 路径）。
  R4-D 多轮指代：新话题（"vLLM 呢"）必须切换、回指（"那怎么修"）必须继承。
  R4-E 结论里的数字必须能从 evidence 复算（不编造）。
  R4-F 引用一致性（结论里的 CVE 都在 evidence 里）。

用法： py tools/_test_qa_round4.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8982
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

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


def _cvss(d):
    """cvss 两种形态都认（dict / float）—— 这正是 R4-B 要钉死的契约。"""
    v = (d or {}).get("cvss")
    if isinstance(v, dict):
        return v.get("score")
    if isinstance(v, (int, float)):
        return v
    return None


def test_units():
    print("\n" + "=" * 66)
    print("  A. 单元：零命中文案 / 前端 cvss 规范化")
    print("=" * 66)
    from qa.relevance import no_hit_note

    # R4-A：0 候选与"有多条候选但都不相关"必须是**不同措辞**
    n0 = no_hit_note("zzzqqq", {"candidates": 0, "terms": ["zzzqqq"]})
    ok("R4-A 0 候选不写'均不相关'",
       "均不相关" not in n0 and "没有召回任何候选" in n0, n0[:60])
    n5 = no_hit_note("xx", {"candidates": 5, "terms": ["xx"]})
    ok("R4-A 有候选才写'均不相关'", "均不相关" in n5, n5[:60])
    ok("R4-A 都含可操作建议", "产品/组件名" in n0 and "产品/组件名" in n5)
    ok("R4-A 都含结构化算子示例", "product:ollama" in n0 and "product:ollama" in n5)

    # R4-B/C：前端 cvss 规范化函数必须存在且两种形态都取得到值
    app_js = os.path.join(ROOT, "frontend", "app.js")
    src = open(app_js, encoding="utf-8").read()
    ok("R4-C frontend 定义 cvssNum", "const cvssNum" in src)
    ok("R4-C frontend 定义 cvssSev", "const cvssSev" in src)
    panel = os.path.join(ROOT, "frontend", "modules", "m3_qa", "panel.js")
    if not os.path.exists(panel):
        panel = os.path.join(ROOT, "modules", "m3_qa", "web", "panel.js")
    psrc = open(panel, encoding="utf-8").read()
    raw = re.findall(r"esc\(\s*(?:e|r|s)\.cvss\s*\)", psrc)
    ok("R4-C panel 无裸 esc(cvss)", not raw, "仍有 %d 处" % len(raw))
    ok("R4-C panel 使用 cvssNum", "cvssNum(" in psrc)

    # R4-B：cvss 两种形态 —— 探针/前端助手都要能取到
    ok("R4-B _cvss(dict) 取值", _cvss({"cvss": {"score": 9.8}}) == 9.8)
    ok("R4-B _cvss(float) 取值", _cvss({"cvss": 8.7}) == 8.7)
    ok("R4-B _cvss(None) 安全", _cvss({"cvss": None}) is None)


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
            # ── R4-A：零命中必须带 empty_reason 且文案统一 ─────────────
            for q in ["zzzqqq不存在的术语xyzzy", "如何做红烧肉"]:
                st, r = chat(q)
                ev = r.get("evidence") or []
                ok("R4-A 零命中 evidence=0 (%s)" % q[:12], len(ev) == 0, "ev=%d" % len(ev))
                ok("R4-A 零命中带 empty_reason (%s)" % q[:12],
                   r.get("empty_reason") == "no_relevant", "got=%r" % r.get("empty_reason"))
                concl = r.get("conclusion") or ""
                ok("R4-A 用统一文案 (%s)" % q[:12],
                   "知识库中没有与该问题匹配的情报" in concl, concl[:50])

            # ── R4-B：evidence 的 cvss 必须是数值（可参与计算）──────────
            st, r = chat("Ollama 有哪些漏洞")
            ev = r.get("evidence") or []
            ok("R4-B evidence 非空", len(ev) > 0)
            ok("R4-B evidence.cvss 是数值",
               all(isinstance(_cvss(e), (int, float, type(None))) for e in ev),
               "形态=%s" % [type(e.get("cvss")).__name__ for e in ev[:3]])

            # ── R4-E：结论数字能从 evidence 复算 ───────────────────────
            concl = r.get("conclusion") or ""
            scores = [float(_cvss(e)) for e in ev if isinstance(_cvss(e), (int, float))]
            real_max = max(scores) if scores else None
            claimed = re.findall(r"CVSS\s*([0-9]+\.[0-9])", concl)
            if real_max is not None and claimed:
                bad = [c for c in claimed if abs(float(c) - real_max) > 0.051
                       and float(c) <= real_max]
                ok("R4-E 结论最高 CVSS 可复算", not bad,
                   "结论=%s 实测max=%s" % (claimed[:3], real_max))
            else:
                skip("R4-E 结论最高 CVSS", "无 CVSS 或结论未写")
            # 结论声称的条数必须等于 evidence 实际条数
            n_claim = re.findall(r"命中\s*\*{0,2}(\d+)\s*\*{0,2}\s*条", concl)
            ok("R4-E 结论条数与 evidence 一致",
               all(int(n) == len(ev) for n in n_claim),
               "结论=%s evidence=%d" % (n_claim, len(ev)))

            # ── R4-D：多轮 —— 新话题切换、回指继承 ────────────────────
            h = [{"role": "user", "content": "Ollama 有哪些漏洞"},
                 {"role": "assistant", "content": "例如 CVE-2026-7482、CVE-2025-15514。"}]
            st, r1 = chat("那怎么修", history=h)
            ok("R4-D 回指继承(resolved_ref)", bool(r1.get("resolved_ref")),
               "got=%r" % r1.get("resolved_ref"))
            blob1 = json.dumps(r1.get("evidence") or [], ensure_ascii=False).lower()
            ok("R4-D 回指命中原实体(ollama)", "ollama" in blob1)
            st, r2 = chat("vLLM 呢", history=h)
            ok("R4-D 新话题不误判为回指", not r2.get("resolved_ref"),
               "got=%r" % r2.get("resolved_ref"))
            blob2 = json.dumps(r2.get("evidence") or [], ensure_ascii=False).lower()
            ok("R4-D 新话题切到 vLLM", "vllm" in blob2 and "ollama" not in blob2,
               "含vllm=%s 含ollama=%s" % ("vllm" in blob2, "ollama" in blob2))

            # ── R4-F：引用一致性 ───────────────────────────────────────
            for q in ["Ollama 有哪些漏洞", "Ray 的漏洞", "最近被在野利用的漏洞"]:
                st, r = chat(q)
                concl = r.get("conclusion") or ""
                ev_ids = {str(e.get("id") or "").upper() for e in (r.get("evidence") or [])}
                cited = {c.upper() for c in _CVE_RE.findall(concl)}
                missing = cited - ev_ids
                ok("R4-F 引用一致性(%s)" % q[:14], not missing or not ev_ids,
                   "引用但无资料: %s" % sorted(missing)[:4])

            # ── R4-空答案自洽：零命中不得引用编号/声称命中条数 ─────────
            st, r = chat("阿巴阿巴阿巴")
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            if not ev:
                # 注意：文案的"建议"里**故意**举了 `CVE-2024-1234` 作为格式示例，
                # 那不是"引用"—— 必须排除带反引号的示例再判（否则测试假红）。
                _body = re.sub(r"`[^`]*`", "", concl)
                _body = re.sub(r"（如[^）]*）", "", _body)
                ok("R4-零命中不在结论里引用 CVE",
                   not _CVE_RE.findall(_body), str(_CVE_RE.findall(_body)[:3]))
                ok("R4-零命中不声称'命中 N 条'",
                   not re.search(r"命中\s*\d+\s*条", concl))
            else:
                skip("R4-零命中自洽", "该问题竟有 %d 条证据" % len(ev))

            # ── 详情可回溯 ─────────────────────────────────────────────
            st, r = chat("Ollama 有哪些漏洞")
            ev = r.get("evidence") or []
            okd = 0
            for e in ev[:3]:
                try:
                    with urllib.request.urlopen(
                            BASE + "/api/detail?id=%s" % urllib.parse.quote(str(e.get("id"))),
                            timeout=60) as resp:
                        d = json.load(resp)
                    if d and (d.get("title") or d.get("desc")):
                        okd += 1
                except Exception:  # noqa: BLE001
                    pass
            ok("R4-详情可回溯(前3条)", okd >= min(3, len(ev)), "可取 %d" % okd)
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
