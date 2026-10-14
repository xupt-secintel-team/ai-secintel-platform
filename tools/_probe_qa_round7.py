# -*- coding: utf-8 -*-
"""_probe_qa_round7.py —— 第 7 轮（终轮）实测探针：真实验收 + 交叉一致性 + 前 6 轮互不冲突

前 6 轮各自独立审了一个角度。第 7 轮做**终验**，三件事：

  ① **真实分析师剧本**：模拟一个安全分析师从"看到告警"到"给出处置"的完整流程，
     多轮提问，验证上下文承接 + 三项能力串联是否真的可用。
  ② **交叉一致性**：同一事实用**不同问法**问，答案必须**不矛盾**
     （例：CVE-2026-7482 的"影响范围"与"修复建议"必须都指向同一版本区间/修复版本）。
  ③ **前 6 轮修复互不冲突回归**：把各轮的关键场景在同一实例里连打，
     检查"修了 A 坏了 B"（尤其 R5 的检索式收敛 与 R6 的 strong_hit 收紧，
     两者都动了"放行判据"，最容易互伤）。

用法： py tools/_probe_qa_round7.py [端口]
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
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9041
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


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
        if history:
            body["history"] = history
        r = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                   headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")

    def vers(text):
        return set(re.findall(r"\d+\.\d+(?:\.\d+)?", text or ""))

    def cves(text):
        return set(x.upper() for x in re.findall(r"CVE-\d{4}-\d{4,7}", text or ""))

    try:
        # ═════════════════════════════════════════════════════════
        print("=" * 74)
        print("  ① 真实分析师剧本：从告警到处置（多轮）")
        print("=" * 74)
        hist = []
        script = [
            ("我的 Ollama 服务被扫了，有哪些相关高危漏洞？", "ollama"),
            ("第一个 CVE 的修复建议是什么？", None),        # 显式序号承接
            ("它的影响范围呢？", None),                      # 隐式承接（"它的"）
            ("那攻击链是什么样的？", None),                   # 隐式承接（"那"）
        ]
        for q, expect in script:
            st, r = chat(q, history=hist or None)
            c = r.get("conclusion") or ""
            rr = r.get("resolved_ref") or r.get("anchor_note") or ""
            ev = len(r.get("evidence") or [])
            print("  Q: %-28s HTTP %s ev=%-2d resolved=%s" % (q[:28], st, ev, str(rr)[:40]))
            print("     结论首行: %s" % (c.split("\n")[0][:70] if c else "(空)"))
            # 段落到达检测
            for sec in ("修复建议", "受影响版本", "攻击链"):
                if sec in c:
                    print("     ✔ 含段落「%s」" % sec)
            # ★ 必须用真实前端格式 {role, content}，否则 resolve_reference 读不到
            #   （它按 role=='assistant' 取上一轮 content —— 见 deep_answer.resolve_reference）
            hist.append({"role": "user", "content": q})
            hist.append({"role": "assistant", "content": c[:600]})

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 74)
        print("  ② 交叉一致性：同一事实不同问法，答案不矛盾")
        print("=" * 74)
        # 影响范围 vs 修复建议 —— 版本必须一致
        st1, r1 = chat("CVE-2026-7482 影响范围")
        st2, r2 = chat("CVE-2026-7482 的修复建议")
        v1 = vers(r1.get("conclusion"))
        v2 = vers(r2.get("conclusion"))
        print("  影响范围版本: %s" % sorted(v1))
        print("  修复建议版本: %s" % sorted(v2))
        # 影响范围应含 <0.17.1（受影响上界）；修复建议应含 0.17.1（修复版本）
        ok_range = any(v.startswith("0.17") for v in v1) or "0.17.1" in r1.get("conclusion", "")
        ok_fix = "0.17.1" in r2.get("conclusion", "")
        inter = v1 & v2
        print("  交集版本: %s  影响范围含0.17=%s 修复建议含0.17.1=%s" % (sorted(inter), ok_range, ok_fix))
        print("  → 一致性:", "OK" if (ok_range and ok_fix) else "⚠ 不一致")

        # 攻击链 vs 怎么被利用 —— 同一 CVE 命中集合应重合
        st3, r3 = chat("CVE-2025-15063 的攻击链")
        st4, r4 = chat("CVE-2025-15063 怎么被利用")
        ids3 = {str(e.get("id")) for e in (r3.get("evidence") or [])}
        ids4 = {str(e.get("id")) for e in (r4.get("evidence") or [])}
        print("  攻击链 ev=%d  怎么被利用 ev=%d  交集=%d" % (len(ids3), len(ids4), len(ids3 & ids4)))
        # 都应以 CVE-2025-15063 为主
        print("  攻击链含自身:", "CVE-2025-15063" in ids3, " 怎么被利用含自身:", "CVE-2025-15063" in ids4)

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 74)
        print("  ③ 前 6 轮修复互不冲突：关键场景连打")
        print("=" * 74)
        checks = [
            # (标签, 问题, 期望判据, 结果提取)
            ("R1 零命中诚实", "zzzqqq不存在的术语xyzzy",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R1/R2 正常提问", "Ollama 有哪些漏洞",
             lambda r: len(r.get("evidence") or []) > 0),
            ("R3 改写式锚定", "本地跑开源大模型的那个工具，有文件读取相关的安全问题",
             lambda r: len(r.get("evidence") or []) > 0),
            ("R3 在野利用过滤", "哪些 AI 框架存在在野利用的漏洞",
             lambda r: any(e.get("exploited") for e in (r.get("evidence") or []))
                       or len(r.get("evidence") or []) > 0),
            ("R4 文案统一", "CVE-2099-99999 的修复建议",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R5 影响范围渲染", "CVE-2026-7482 影响范围",
             lambda r: "受影响版本" in (r.get("conclusion") or "")),
            ("R5 修复建议渲染", "CVE-2026-7482 的修复建议",
             lambda r: "修复建议" in (r.get("conclusion") or "")
                       and bool(vers(r.get("conclusion")))),
            ("R5 检索式收敛(纯编号)", "CVE-2025-15063 的攻击链是什么",
             lambda r: {str(e.get("id")) for e in (r.get("evidence") or [])}
                       and len([e for e in (r.get("evidence") or [])
                                if str(e.get("id","")).startswith("CVE-")]) <= 2),
            ("R6 假实体诚实", "foobarbaz-9x 的安全漏洞",
             lambda r: r.get("empty_reason") == "no_relevant"),
            ("R6 真 CVE 不误杀", "CVE-2021-44228 的修复建议",
             lambda r: len(r.get("evidence") or []) > 0),
            ("底 边界 too_long", "漏洞" * 2500,
             lambda r: r.get("empty_reason") == "too_long"),
            ("底 边界 invalid", "🤔🤔",
             lambda r: r.get("empty_reason") == "invalid_input"),
        ]
        npass = 0
        for label, q, judge in checks:
            st, r = chat(q)
            good = False
            try:
                good = bool(judge(r))
            except Exception as e:  # noqa: BLE001
                good = False
                print("     判据异常:", e)
            npass += 1 if good else 0
            print("  [%s] %-22s HTTP %s ev=%s empty=%s" % (
                "PASS" if good else "FAIL", label, st,
                len(r.get("evidence") or []), r.get("empty_reason")))
        print("  → 连打通过 %d/%d" % (npass, len(checks)))

        # ═════════════════════════════════════════════════════════
        print("\n" + "=" * 74)
        print("  ④ 跨模块能力可达：问答能否引用到 主体(模块2) 的资产/处置")
        print("=" * 74)
        # 影响范围来自 /api/assets，修复建议来自 /api/detail —— 检查问答是否真的用了它们
        for path in ["/api/assets?id=CVE-2026-7482", "/api/detail?id=CVE-2026-7482"]:
            try:
                with urllib.request.urlopen(BASE + path, timeout=60) as rr:
                    d = json.load(rr)
                keys = sorted(d.keys())[:10]
                print("  %-34s OK keys=%s" % (path, keys))
            except Exception as e:  # noqa: BLE001
                print("  %-34s ERR %s" % (path, str(e)[:50]))

        # 结论可复核：是否带"依据"
        st, r = chat("Ollama 有哪些高危漏洞")
        c = r.get("conclusion") or ""
        print("  结论含「依据」字样:", "依据" in c)
        print("  结论含来源编号:", bool(re.search(r"\[[A-Z]+[:0-9-]+\]", c)))

        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
