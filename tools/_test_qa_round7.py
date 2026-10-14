# -*- coding: utf-8 -*-
"""_test_qa_round7.py —— 第 7 轮（终轮）回归测试：真实验收 + 交叉一致性 + 互不冲突

第 7 轮做**终验**（前 6 轮各审一个角度后的综合验收）：
  ① 真实分析师剧本（多轮）—— 上下文承接 + 三项能力串联；
  ② 交叉一致性 —— 同一事实不同问法不矛盾；
  ③ 前 6 轮修复互不冲突 —— 关键场景在同一实例连打（防"修了 A 坏了 B"）；
  ④ R7-A' 新缺陷 —— `/api/chat` 对畸形 history **静默丢失上下文**，
     本轮补非破坏性 `history_note` 提示。

★ 重要（本轮踩到的探针 bug，防止以后重踩）：
  `POST /api/chat` 的 `history` 契约是 **`[{role:'user'|'assistant', content}]`**
  （与 OpenAI 消息格式一致，前端 `panel.js` 就是这么传的）。
  若按 `[{q,a}]` 传（我第一版探针的错误），`resolve_reference` 读不到
  `role=='assistant'` 的 `content` → **静默退回、完全丢失多轮上下文**，
  表现为"多轮承接失效"，看着像产品 bug，实际是调用方格式错。

用法： py tools/_test_qa_round7.py [端口]
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9051
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

PASS = FAIL = SKIP = 0


def ok(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, ("— " + str(detail)[:170]) if detail else ""))


def skip(name, why):
    global SKIP
    SKIP += 1
    print("  [SKIP] %s — %s" % (name, why))


def vers(text):
    return set(re.findall(r"\d+\.\d+(?:\.\d+)?", text or ""))


def main():
    env = dict(os.environ)
    env["AISEC_MAIN_SERVER"] = BASE
    p = subprocess.Popen([PYEXE, os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
                         cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(400):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.5)

    def chat(q, history=None, timeout=240):
        body = {"q": q, "no_llm": True}
        if history is not None:
            body["history"] = history
        r = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                   headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")

    try:
        # ═════════════════════════════════════════════════════════
        print("=" * 70)
        print("  ① 真实分析师剧本（多轮，正确 history 契约）")
        print("=" * 70)
        hist = []
        script = ["我的 Ollama 服务被扫了，有哪些相关高危漏洞？",
                  "第一个 CVE 的修复建议是什么？",
                  "它的影响范围呢？",
                  "那攻击链是什么样的？"]
        resolved_chain = []
        for q in script:
            st, r = chat(q, history=hist or None)
            c = r.get("conclusion") or ""
            resolved_chain.append(r.get("resolved_ref"))
            ok("剧本 HTTP 200: %s" % q[:20], st == 200)
            hist.append({"role": "user", "content": q})
            hist.append({"role": "assistant", "content": c[:600]})
        # 第 2~4 问都应接上上一轮（resolved_ref 非空）
        ok("剧本 第2问显式序号承接（resolved_ref）",
           bool(resolved_chain[1]), resolved_chain)
        ok("剧本 第3问隐式承接（'它的'）",
           bool(resolved_chain[2]), resolved_chain)
        ok("剧本 第4问隐式承接（'那'）",
           bool(resolved_chain[3]), resolved_chain)
        # 承接同一实体（同一 CVE）
        targets = [x for x in resolved_chain[1:] if x]
        ok("剧本 2~4 问承接同一实体",
           len(set(targets)) == 1 and len(targets) >= 2, targets)

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 70)
        print("  ② 交叉一致性：同一事实不同问法不矛盾")
        print("=" * 70)
        st1, r1 = chat("CVE-2026-7482 影响范围")
        st2, r2 = chat("CVE-2026-7482 的修复建议")
        c1, c2 = r1.get("conclusion") or "", r2.get("conclusion") or ""
        ok("一致性 影响范围含 0.17.x 版本上界",
           bool(re.search(r"[<>≤]\s*0?\.?17", c1)) or "0.17" in c1, c1[-200:])
        ok("一致性 修复建议含修复版本 0.17.1",
           "0.17.1" in c2, c2[-200:])
        ok("一致性 两问指向同一产品 ollama",
           ("ollama" in c1.lower()) and ("ollama" in c2.lower()))

        st3, r3 = chat("CVE-2025-15063 的攻击链")
        st4, r4 = chat("CVE-2025-15063 怎么被利用")
        ids3 = {str(e.get("id")) for e in (r3.get("evidence") or [])}
        ids4 = {str(e.get("id")) for e in (r4.get("evidence") or [])}
        ok("一致性 攻击链/怎么被利用 命中集合重合",
           len(ids3 & ids4) >= 1, "3=%s 4=%s" % (sorted(ids3)[:3], sorted(ids4)[:3]))
        ok("一致性 都以被问 CVE 为主",
           "CVE-2025-15063" in ids3 and "CVE-2025-15063" in ids4,
           "3has=%s 4has=%s" % ("CVE-2025-15063" in ids3, "CVE-2025-15063" in ids4))

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 70)
        print("  ③ 前 6 轮修复互不冲突（关键场景连打）")
        print("=" * 70)
        checks = [
            ("R1 零命中诚实", "zzzqqq不存在的术语xyzzy",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R2 正常提问", "Ollama 有哪些漏洞",
             lambda r: len(r.get("evidence") or []) > 0),
            ("R3 改写式锚定", "本地跑开源大模型的那个工具，有文件读取相关的安全问题",
             lambda r: len(r.get("evidence") or []) > 0),
            ("R3 在野利用过滤", "哪些 AI 框架存在在野利用的漏洞",
             lambda r: len(r.get("evidence") or []) > 0),
            ("R4 零命中文案统一", "CVE-2099-99999 的修复建议",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R5 影响范围渲染", "CVE-2026-7482 影响范围",
             lambda r: "受影响版本" in (r.get("conclusion") or "")),
            ("R5 修复建议渲染", "CVE-2026-7482 的修复建议",
             lambda r: "修复建议" in (r.get("conclusion") or "")
                       and bool(vers(r.get("conclusion")))),
            ("R5 检索式收敛", "CVE-2025-15063 的攻击链是什么",
             lambda r: len([e for e in (r.get("evidence") or [])
                            if str(e.get("id", "")).startswith("CVE-")]) <= 2
                       and len(r.get("evidence") or []) > 0),
            ("R6 假实体诚实", "foobarbaz-9x 的安全漏洞",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R6 真 CVE 不误杀", "CVE-2021-44228 的修复建议",
             lambda r: len(r.get("evidence") or []) > 0),
            ("底 边界 too_long", "漏洞" * 2500,
             lambda r: r.get("empty_reason") == "too_long"),
            ("底 边界 invalid_input", "🤔🤔",
             lambda r: r.get("empty_reason") == "invalid_input"),
            ("底 仅编号可答", "CVE-2026-7482",
             lambda r: True),  # 只验不崩、200
            ("底 仅算子可答", "kev:yes",
             lambda r: True),
        ]
        npass = 0
        for label, q, judge in checks:
            st, r = chat(q)
            try:
                good = st == 200 and bool(judge(r))
            except Exception:  # noqa: BLE001
                good = False
            npass += 1 if good else 0
            if not good:
                print("  [FAIL] %-20s HTTP %s ev=%s empty=%s" % (
                    label, st, len(r.get("evidence") or []), r.get("empty_reason")))
        ok("互不冲突 连打 %d/%d" % (npass, len(checks)), npass == len(checks))

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 70)
        print("  ④ R7-A' history 契约自检（非破坏性提示）")
        print("=" * 70)
        st, r = chat("Ollama 漏洞", history=[{"q": "x", "a": "y"}])
        ok("畸形 history → 附 history_note", bool(r.get("history_note")),
           r.get("history_note"))
        ok("畸形 history 不改 HTTP 状态", st == 200, st)
        ok("畸形 history 不改回答（仍有结论）",
           bool((r.get("conclusion") or "").strip()))
        st, r = chat("Ollama 漏洞", history=[{"role": "user", "content": "Ollama 漏洞"},
                                             {"role": "assistant", "content": "1.CVE-2026-7482"}])
        ok("正确 history → 无 history_note", not r.get("history_note"), r.get("history_note"))
        st, r = chat("Ollama 漏洞")
        ok("无 history → 无 history_note", not r.get("history_note"), r.get("history_note"))
        # 垃圾 history 不崩
        st, r = chat("Ollama 漏洞", history=[{"foo": "bar"}, 123, "字符串"])
        ok("垃圾 history 不崩（HTTP 200）", st == 200, st)

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 70)
        print("  ⑤ 结论可复核（带依据/来源）")
        print("=" * 70)
        st, r = chat("Ollama 有哪些高危漏洞")
        c = r.get("conclusion") or ""
        ok("结论含『依据』说明", "依据" in c)
        ok("结论含来源编号", bool(re.search(r"\[[A-Za-z]+[:0-9-]+\]", c)), c[:120])
        ok("响应含 reasoning_chain", bool(r.get("reasoning_chain")))
        ok("响应含 elapsed_ms", isinstance(r.get("elapsed_ms"), int))

        print("\n" + "=" * 70)
        print("  通过 %d · 失败 %d · 跳过 %d" % (PASS, FAIL, SKIP))
        print("=" * 70)
        return 1 if FAIL else 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
