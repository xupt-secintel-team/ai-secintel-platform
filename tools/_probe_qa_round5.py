# -*- coding: utf-8 -*-
"""_probe_qa_round5.py —— 第 5 轮实测探针：三项能力硬复检 + 并发与边界

第 4 轮审计了"答案可不可信"。第 5 轮直接对照**用户点名的三项能力**逐条硬复检，
并补前 4 轮完全没碰的**并发**与**边界压力**：

  ① 漏洞**影响范围**：问"X 影响哪些版本/组件"时，答案是否给出**版本区间**与
     **受影响组件清单**（而不是只复述标题）？
  ② 修复**建议**：问"怎么修"时，答案是否给出**可操作处置**（升级到哪个版本）？
  ③ 相关**攻击链**：问"攻击链/怎么被利用"时，是否有攻击步骤或如实说明"未提供"？
  ④ **跨文档语义检索**：同一个问题，语义描述与关键词命中的**是否同一批**？
  ⑤ **并发**：连打 N 个并发请求，是否全部 200、无 500、无串答案（答案与问题不对应）？
  ⑥ **边界压力**：超长问题 / 单字符 / 纯 emoji / 仅算子 / 仅编号，响应是否可控？
  ⑦ **响应时间**：每类问题的耗时是否在预算内（用户要求"响应可控"）。

用法： py tools/_probe_qa_round5.py [端口]
"""
from __future__ import annotations

import concurrent.futures as cf
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8977
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
        t = time.time()
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return resp.status, json.load(resp), time.time() - t
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}"), time.time() - t

    try:
        print("=" * 72)
        print("  ① 漏洞影响范围：是否给出受影响版本区间 / 组件清单")
        print("=" * 72)
        for q in ["Ollama 的漏洞影响哪些版本", "CVE-2026-7482 影响范围", "vLLM 漏洞影响哪些组件"]:
            st, r, ms = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            has_range = bool(re.search(r"(<=|>=|<|>|至|区间|版本)\s*[\d.]", concl))
            prods = set()
            for e in ev:
                for x in (e.get("products") or [])[:4]:
                    prods.add(str(x if isinstance(x, str) else (x or {}).get("name")))
            print("  Q: %-30s HTTP %s %.1fs evidence=%d" % (q[:30], st, ms, len(ev)))
            print("     版本区间/升级提示=%s · 组件=%s" % (has_range, sorted(prods)[:5]))
            print("     结论含'受影响版本'段=%s" % ("受影响版本" in concl or "版本区间" in concl))

        print("\n" + "=" * 72)
        print("  ② 修复建议：是否给出可操作处置（升级到哪版 / 怎么做）")
        print("=" * 72)
        for q in ["Ollama 漏洞怎么修复", "CVE-2026-7482 的修复建议", "vLLM 高危漏洞如何处置"]:
            st, r, ms = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            has_fix = bool(re.search(r"(升级|修复|补丁|mitigat|patch|update|处置|建议)", concl, re.I))
            has_ver = bool(re.search(r"(\d+\.\d+\.\d+|升级至|升级到)", concl))
            print("  Q: %-30s HTTP %s %.1fs evidence=%d" % (q[:30], st, ms, len(ev)))
            print("     含处置词=%s · 含具体版本=%s" % (has_fix, has_ver))
            # 找处置段落原文
            for ln in concl.split("\n"):
                if re.search(r"处置|修复建议|升级", ln):
                    print("     处置行: %s" % ln.strip()[:80])
                    break

        print("\n" + "=" * 72)
        print("  ③ 相关攻击链：是否有攻击步骤 / 如实说明")
        print("=" * 72)
        for q in ["CVE-2025-15063 的攻击链是什么", "Ollama 漏洞怎么被利用", "提示词注入的攻击链"]:
            st, r, ms = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            has_chain = bool(re.search(r"(攻击链|攻击步骤|利用步骤|攻击路径|exploit chain)", concl))
            has_steps = bool(re.search(r"(第\s*[1-9一二三]步|步骤\s*[1-9]|→|1\.\s|2\.\s)", concl))
            says_none = bool(re.search(r"(未提供|未包含|未找到|没有.{0,6}攻击|知识库中)", concl))
            print("  Q: %-30s HTTP %s %.1fs evidence=%d" % (q[:30], st, ms, len(ev)))
            print("     有攻击链标题=%s · 有步骤=%s · 如实说明无=%s" % (has_chain, has_steps, says_none))

        print("\n" + "=" * 72)
        print("  ④ 跨文档语义检索：语义描述 vs 关键词，命中是否同批")
        print("=" * 72)
        pairs = [("Ollama 有哪些漏洞", "本地跑开源大模型的那个工具，有文件读取相关的安全问题"),
                 ("vLLM 高危漏洞", "搭建大模型推理服务时，那个框架存在代码执行问题")]
        for kw, sem in pairs:
            st1, r1, _ = chat(kw)
            st2, r2, _ = chat(sem)
            ids1 = {str(e.get("id")) for e in (r1.get("evidence") or [])}
            ids2 = {str(e.get("id")) for e in (r2.get("evidence") or [])}
            inter = ids1 & ids2
            print("  关键词: %-22s -> %d 条" % (kw[:22], len(ids1)))
            print("  语义式: %-22s -> %d 条" % (sem[:22], len(ids2)))
            print("     交集 %d 条 · 语义独有 %d 条（语义扩展能力）" % (len(inter), len(ids2 - ids1)))

        print("\n" + "=" * 72)
        print("  ⑤ 并发：N 个并发请求是否全部 200 且答案与问题对应")
        print("=" * 72)
        qs = ["Ollama 有哪些漏洞", "vLLM 的高危漏洞", "LangChain 的漏洞",
              "Ray 的漏洞", "SGLang 的漏洞", "最近被在野利用的漏洞"]
        results = {}
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(chat, q): q for q in qs}
            for fu in cf.as_completed(futs):
                q = futs[fu]
                try:
                    st, r, ms = fu.result()
                    results[q] = (st, r, ms)
                except Exception as e:  # noqa: BLE001
                    results[q] = (0, {"_err": str(e)[:60]}, 0)
        all200 = all(v[0] == 200 for v in results.values())
        print("  全部 HTTP 200: %s" % all200)
        for q in qs:
            st, r, ms = results[q]
            ev = r.get("evidence") or []
            blob = json.dumps(ev, ensure_ascii=False).lower()
            # 串答案检测：答案里应含该问题的关键词
            key = {"Ollama 有哪些漏洞": "ollama", "vLLM 的高危漏洞": "vllm",
                   "LangChain 的漏洞": "langchain", "Ray 的漏洞": "ray",
                   "SGLang 的漏洞": "sglang", "最近被在野利用的漏洞": None}.get(q)
            matched = (key in blob) if key else "n/a"
            print("    %-26s HTTP %s %5.1fs ev=%d 关键词命中=%s" % (q[:26], st, ms, len(ev), matched))

        print("\n" + "=" * 72)
        print("  ⑥ 边界压力：超长/单字符/emoji/仅算子/仅编号")
        print("=" * 72)
        edge = [
            ("超长(5000字)", "漏洞" * 2500),
            ("单字符", "?"),
            ("纯 emoji", "🤔🤔🤔"),
            ("纯空白", "   "),
            ("仅算子", "kev:yes"),
            ("仅编号", "CVE-2026-7482"),
            ("仅 CWE", "CWE-78"),
            ("SQL 注入串", "'; DROP TABLE docs;--"),
            ("超长单token", "a" * 3000),
        ]
        for name, q in edge:
            try:
                st, r, ms = chat(q)
                ev = r.get("evidence") or []
                concl = (r.get("conclusion") or "").split("\n")[0][:44]
                print("  %-14s HTTP %-3s %5.1fs ev=%-2d empty=%-10s %s" % (
                    name, st, ms, len(ev), str(r.get("empty_reason")), concl))
            except Exception as e:  # noqa: BLE001
                print("  %-14s ★异常 %s" % (name, str(e)[:60]))

        print("\n" + "=" * 72)
        print("  ⑦ 响应时间：各类问题耗时是否可控")
        print("=" * 72)
        for q in ["Ollama 有哪些漏洞", "哪些 AI 框架存在在野利用的漏洞",
                  "CVE-2026-7482 影响范围", "zzzqqq不存在的术语xyzzy"]:
            st, r, ms = chat(q)
            rc = r.get("reasoning_chain") or {}
            print("  %-34s %.2fs (hops=%s) budget=%sms spent=%sms" % (
                q[:34], ms, rc.get("hop_count"), rc.get("budget_ms"), rc.get("spent_ms")))
        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
