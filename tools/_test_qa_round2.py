# -*- coding: utf-8 -*-
"""_test_qa_round2.py —— 第 2 轮实测审计的修复回归

第 2 轮独立复检发现的两类问题（都有实测证据）：
  ★ A. **攻击链能力缺口**：用户明确要求支持"相关攻击链"，但实测
       「这个漏洞的攻击链是什么样的」命中**零个**意图分支，
       结论里连"内容要点"都产不出，只剩一句统计。
       → 新增 `deep_answer.attack_section`（从资料正文确定性抽取，不编造）。
       注：同时**纠正第 1 轮的一个误判** —— 第 1 轮说"问题类型未分流"，
       复检发现影响范围/数量统计/关联论文**各有专门小节**，是分流的；
       真正缺的只有攻击链这一类。
  ★ B. **输入健壮性**：`???` / 纯空白 / emoji 原先一路走完多跳检索，
       返回 200 + 一堆无关条目（误导用户以为"听懂了"）；超长问题同理。
       → 新增 `qa._precheck`，在**检索之前**判掉并给可操作反馈。

用法： py tools/_test_qa_round2.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8961
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable
PASS = FAIL = 0


def ok(label, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % label)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (label, extra))


def unit():
    print("\n[1] 攻击链意图识别（单元）")
    from qa.deep_answer import attack_section, _ATTACK_RE
    for q in ("这个漏洞的攻击链是什么样的", "漏洞怎么被利用", "攻击路径是什么",
              "利用链有哪些环节", "kill chain", "how is it exploited"):
        ok("识别「%s」为攻击链问题" % q, bool(_ATTACK_RE.search(q)), "未命中")
    for q in ("Ollama 有哪些漏洞", "怎么修复", "影响哪些版本"):
        ok("「%s」不被误判为攻击链" % q, not _ATTACK_RE.search(q), "误命中")

    docs = [{"id": "CVE-X", "title": "t",
             "desc": "攻击者可以构造恶意模型文件，通过反序列化触发远程代码执行。"
                     "前置条件：受害者加载该模型。从而获取服务器权限。"}]
    s = attack_section("这个漏洞的攻击链是什么样的", docs)
    ok("攻击链段落有内容", bool(s) and "攻击链" in s, str(s)[:80])
    ok("攻击链段落标注来源编号", "CVE-X" in (s or ""), str(s)[:120])
    ok("攻击链段落声明'未作生成式推断'", "未作生成式推断" in (s or ""), str(s)[:200])
    ok("非攻击链问题不产出该段",
       attack_section("Ollama 有哪些漏洞", docs) is None)
    # 抽不到时如实说明
    s2 = attack_section("攻击链", [{"id": "CVE-Y", "title": "t", "desc": "短标题情报。"}])
    ok("抽不到攻击细节时如实说明（不编造）",
       bool(s2) and "未提供" in s2, str(s2)[:120])

    print("\n[2] 输入前置校验（单元）")
    from qa import _precheck, MAX_QUESTION_CHARS
    ok("纯符号 → invalid_input",
       (_precheck("???") or {}).get("empty_reason") == "invalid_input")
    ok("纯空白 → invalid_input",
       (_precheck("   ") or {}).get("empty_reason") == "invalid_input")
    ok("emoji → invalid_input",
       (_precheck("🔒🚨") or {}).get("empty_reason") == "invalid_input")
    ok("超长 → too_long",
       (_precheck("漏洞" * (MAX_QUESTION_CHARS)) or {}).get("empty_reason") == "too_long")
    ok("正常问题 → 通过", _precheck("Ollama 有哪些漏洞") is None)
    ok("含 CVE 的问题 → 通过", _precheck("CVE-2024-1234 怎么修") is None)
    ok("校验结果含明确提示文案",
       "结论" in ((_precheck("???") or {}).get("conclusion") or ""))
    ok("校验结果 evidence 为空（不伪造证据）",
       (_precheck("???") or {}).get("evidence") == [])


def api():
    print("\n[3] 真起服务 · 端到端")
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
    else:
        print("  [SKIP] 服务未能启动"); p.terminate(); return

    def chat(q, timeout=180):
        r = urllib.request.Request(BASE + "/api/chat",
                                   data=json.dumps({"q": q, "no_llm": True}).encode(),
                                   headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")

    try:
        st, r = chat("Ollama 漏洞的攻击链是什么样的")
        secs = re.findall(r"(?m)^##\s*(.+?)\s*$", r.get("conclusion") or "")
        ok("攻击链问题在真实链路产出「攻击链」小节",
           any("攻击链" in s for s in secs), str(secs))
        for label, q, want in [("纯符号", "???", "invalid_input"),
                               ("纯空白", "   ", "invalid_input"),
                               ("emoji", "🔒🚨", "invalid_input"),
                               ("超长", "漏洞" * 2000, "too_long")]:
            st, r = chat(q)
            ok("%s → %s" % (label, want), r.get("empty_reason") == want,
               "got=%s" % r.get("empty_reason"))
        st, r = chat("Ollama 有哪些漏洞")
        ok("正常提问不受影响",
           not r.get("empty_reason") and bool(r.get("conclusion")))
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    print("=" * 60)
    print("  情报问答 · 第 2 轮审计修复回归")
    print("=" * 60)
    unit()
    api()
    print("\n" + "=" * 60)
    print("  通过 %d · 失败 %d" % (PASS, FAIL))
    print("=" * 60)
    sys.exit(1 if FAIL else 0)
