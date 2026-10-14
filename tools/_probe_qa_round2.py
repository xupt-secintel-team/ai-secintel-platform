# -*- coding: utf-8 -*-
"""_probe_qa_round2.py —— 第 2 轮实测探针：问题类型分流 / 输入健壮性 / trace 留痕

第 1 轮修了"零命中诚实化 / 冷启动 / 多轮 / 口径"。第 2 轮独立复检三件事：
  ① 不同类型的提问（影响范围 / 修复建议 / 攻击链 / 有什么漏洞）产出的结论
     **是否真的分流**，还是都套同一个模板；
  ② 输入健壮性：超长 / 纯符号 / 空白 / 特殊字符，接口是否给出合理反馈；
  ③ /api/qa/agent/trace 有没有留痕（第 1 轮实测恒空）。
用法： py tools/_probe_qa_round2.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8951
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def _start():
    env = dict(os.environ)
    env["AISEC_MAIN_SERVER"] = BASE
    p = subprocess.Popen([PYEXE, os.path.join(ROOT, "core", "server.py"), "--port", str(PORT)],
                         cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(400):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=2).read()
            return p
        except Exception:  # noqa: BLE001
            time.sleep(0.5)
    p.terminate()
    return None


def _chat(q, no_llm=True, timeout=180):
    body = {"q": q}
    if no_llm:
        body["no_llm"] = True
    req = urllib.request.Request(BASE + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception as e:  # noqa: BLE001
        return -1, {"err": str(e)[:200]}


def _sections(concl):
    """从结论里抽出 ## 级小标题，用来判断"不同类型是否走了不同模板"。"""
    return re.findall(r"(?m)^##\s*(.+?)\s*$", concl or "")


def main():
    p = _start()
    if not p:
        print("服务未能启动"); return 1
    try:
        print("=" * 66)
        print("  ① 问题类型分流：不同意图的结论结构是否不同")
        print("=" * 66)
        cases = [
            ("影响范围", "Ollama 漏洞影响哪些版本"),
            ("修复建议", "Ollama 漏洞怎么修复，有什么缓解措施"),
            ("攻击链", "这个漏洞的攻击链是什么样的"),
            ("有什么漏洞", "Ollama 有哪些漏洞"),
            ("数量统计", "Ollama 有多少个高危漏洞"),
            ("关联论文", "Ollama 有哪些关联研究论文"),
        ]
        sigs = {}
        for label, q in cases:
            st, r = _chat(q)
            concl = r.get("conclusion") or r.get("answer") or ""
            secs = _sections(concl)
            sigs[label] = tuple(secs)
            print("\n--- [%s] %s  (HTTP %s) ---" % (label, q, st))
            print("  结论小节: %s" % (secs or "（无 ## 小节）"))
            print("  结论前 200 字: %s" % concl[:200].replace("\n", " ⏎ "))
        # 结构是否分流
        uniq = set(sigs.values())
        print("\n>>> 结论结构去重后共 %d 种：%s" % (len(uniq), uniq))
        print(">>> 判定：%s" % ("已分流" if len(uniq) >= 3 else
                              "★ 未充分分流（多种意图共用一个模板）"))

        print("\n" + "=" * 66)
        print("  ② 输入健壮性")
        print("=" * 66)
        edge = [
            ("超长问题(4000字)", "漏洞" * 2000),
            ("纯符号", "???"),
            ("纯空白", "   "),
            ("单个字符", "a"),
            ("超长无空格", "x" * 5000),
            ("emoji", "🔒🚨 有什么漏洞"),
            ("SQL 注入样", "'; DROP TABLE docs;--"),
            ("XSS 样", "<script>alert(1)</script>"),
        ]
        for label, q in edge:
            st, r = _chat(q, timeout=90)
            concl = (r.get("conclusion") or r.get("answer") or "")
            print("  %-16s HTTP %-4s len=%-5d %s" % (
                label, st, len(concl),
                ("错误: " + str(r.get("error"))[:60]) if r.get("error") else concl[:70].replace("\n", " ")))

        print("\n" + "=" * 66)
        print("  ③ agent/trace 留痕")
        print("=" * 66)
        with urllib.request.urlopen(BASE + "/api/qa/agent/trace", timeout=30) as resp:
            tr = json.load(resp)
        print("  /api/qa/agent/trace -> traces 条数 = %d" % len(tr.get("traces") or []))
        print("  （无 LLM Key 时走传统链路）")
        # 多跳链路自己有没有链
        st, r = _chat("Ollama 有哪些漏洞")
        rc = r.get("reasoning_chain") or {}
        print("  传统链路 reasoning_chain.hops 条数 = %d, strategy=%s" % (
            len(rc.get("hops") or []), rc.get("strategy")))
        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
