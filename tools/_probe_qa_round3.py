# -*- coding: utf-8 -*-
"""_probe_qa_round3.py —— 第 3 轮实测探针：语义检索质量 / 跨文档推理 / 推理链可解释性

前两轮修了：零命中诚实化、冷启动、多轮、口径、攻击链、输入校验。
第 3 轮换角度，独立复检**能力宣称是否属实**：
  ① 语义检索是否真的优于关键词（用户要求"跨文档的语义检索"）；
  ② 跨文档关联推理是否成立（用户要求"关联推理"）；
  ③ reasoning_chain 每一跳的信息是否完整可信（用户要求"可解释"）；
  ④ 引用一致性：答案里引用的编号，是否都在 evidence 里能找到。
用法： py tools/_probe_qa_round3.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8971
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

    def get(path, timeout=120):
        with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
            return json.load(r)

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

    try:
        print("=" * 66)
        print("  ① 语义检索 vs 纯关键词（'跨文档语义检索'是否属实）")
        print("=" * 66)
        # 用【不含关键词】的语义描述提问：只有语义路能命中
        semantic_qs = [
            "搭建大模型推理服务时，那个框架存在代码执行问题",   # 不出现 vLLM
            "本地跑开源大模型的那个工具，有文件读取相关的安全问题",  # 不出现 Ollama
            "编排 LLM 应用的工具链，有没有被注入攻击的风险",      # 不出现 LangChain
        ]
        for q in semantic_qs:
            st, r = chat(q)
            ev = r.get("evidence") or []
            ids = [e.get("id") for e in ev[:4]]
            titles = [str(e.get("title") or "")[:36] for e in ev[:4]]
            print("  Q: %s" % q)
            print("     HTTP %s · evidence %d 条 · ids=%s" % (st, len(ev), ids))
            for t in titles:
                print("       · %s" % t)

        print("\n  ①b 对比：同一问题的纯关键词检索（hybrid_search 直打）")
        for q in ["vLLM", "Ollama", "LangChain"]:
            try:
                d = get("/api/hybrid_search?q=%s&k=3" % urllib.parse.quote(q))
                rr = d.get("results") or []
                print("  %-12s -> %d 条 · %s" % (q, len(rr),
                      [str(x.get("title") or "")[:30] for x in rr[:3]]))
            except Exception as e:  # noqa: BLE001
                print("  %-12s -> 失败 %s" % (q, str(e)[:60]))

        print("\n" + "=" * 66)
        print("  ② 跨文档关联推理（'关联推理'是否属实）")
        print("=" * 66)
        cross_qs = [
            "Ollama 和 vLLM 这两个框架，谁的漏洞更严重",
            "哪些 AI 框架存在在野利用的漏洞",
            "CWE-78 相关的 AI 框架漏洞有哪些",
        ]
        for q in cross_qs:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            prods = set()
            for e in ev:
                for pr in (e.get("products") or [])[:3]:
                    prods.add(str(pr))
            print("  Q: %s" % q)
            print("     证据 %d 条 · 涉及组件 %s" % (len(ev), sorted(prods)[:8]))
            print("     结论首行: %s" % (concl.split("\n")[0][:70] if concl else "（空）"))

        print("\n" + "=" * 66)
        print("  ③ reasoning_chain 可解释性（每跳信息是否完整）")
        print("=" * 66)
        st, r = chat("Ollama 高危且在野利用的漏洞")
        rc = r.get("reasoning_chain") or {}
        hops = rc.get("hops") or []
        print("  strategy=%s · hop_count=%s · pool=%s · returned=%s" % (
            rc.get("strategy"), rc.get("hop_count"), rc.get("pool_size"), rc.get("returned")))
        for h in hops:
            missing = [k for k in ("hop", "query", "basis", "hits") if k not in h]
            print("    hop=%s sub=%s query=%-28s basis=%-14s hits=%s%s" % (
                h.get("hop"), h.get("sub"), str(h.get("query"))[:28],
                str(h.get("basis"))[:14], h.get("hits"),
                ("  ⚠缺:" + str(missing)) if missing else ""))

        print("\n" + "=" * 66)
        print("  ④ 引用一致性：结论里引用的编号是否都在 evidence 里")
        print("=" * 66)
        for q in ["Ollama 有哪些漏洞", "最近被在野利用的漏洞", "vLLM 的高危漏洞"]:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev_ids = {str(e.get("id")) for e in (r.get("evidence") or [])}
            cited = set(re.findall(r"\[((?:CVE|GHSA|CWE|XZ|CSDN|AQK|GH)[A-Za-z0-9:\-]*)\]", concl))
            missing = cited - ev_ids
            print("  Q: %-22s 引用 %d 个 · evidence %d 条 · 引用但无资料 %d 个 %s" % (
                q, len(cited), len(ev_ids), len(missing),
                ("★ " + str(sorted(missing)[:5])) if missing else ""))
        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    import urllib.parse  # noqa: E402  (用于①b)
    sys.exit(main())
