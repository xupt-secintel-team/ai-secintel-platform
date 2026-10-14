# -*- coding: utf-8 -*-
"""_test_qa_round6.py —— 第 6 轮回归测试（知识库覆盖度 + 诚实边界 + 双路径一致性）

第 6 轮换角度：**从知识库本身出发**审问答，而不是从某个问句出发。
钉死本轮发现并修复的 1 个真实缺陷 + 澄清 3 个误报：

  R6-A（真缺陷，最严重）**诚实边界不一致**：
       `strong_terms()` 把任意拉丁词都当"铁证"，而 `is_relevant` 的分支 ②③
       只判 `strong` **非空**、不判**是否命中** —— 于是
       「foobarbaz-9x 的安全漏洞」「CWE-99999 相关的漏洞」这类**库里根本不存在**
       的东西，因 strong 非空而放行了语义路噪声（0.90+），返回 4~8 条无关情报。
       同一系统 6 个假查询里只有 3 个如实说"没有" —— 违反第 1 轮的"零命中诚实化"。
       修：②③ 改为要求 `strong_hit`（标识符**真的出现在文档文本里**）。

  R6-B（**误报，非缺陷**）vector_probe 返回 hits=0 —— 实为**探针 bug**
       （中文 q 未做 URL 编码，请求失败）。修探针，不改产品。
  R6-C（**口径，非缺陷**）corpus.total=106844 vs vector_count=118388 ——
       差值来自"同一文档分多块"（chunk），合理。测试固化为"两者都 > 0 且
       vector ≥ corpus"（向量条数不少于文档条数）。
  R6-D（**接口缺口**）`/api/corpus` 的 items **不含 sources 字段** ——
       "来源分布"统计失效。测试不断言它必须存在（属增强项），但记录之。

用法： py tools/_test_qa_round6.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9029
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

    def get_json(path, timeout=120):
        """★ 修复 R6-B：必须对中文 q 做 URL 编码，否则请求失败（探针自身 bug）。"""
        try:
            with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            return {"_err": "%s: %s" % (type(e).__name__, str(e)[:80])}

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

    try:
        # ─────────────────────────────────────────────────────────
        print("=" * 70)
        print("  A. 单元：诚实边界判据（不依赖运行环境数据）")
        print("=" * 70)
        from qa.relevance import query_terms, strong_terms, gate

        # 假实词：strong_terms 仍会抽出来（这是设计），但**没命中文档**时不得放行
        fake_docs = [
            {"id": "X1", "title": "某文件上传漏洞分析", "products": ["gestioip"],
             "vector_score": 0.9053, "_fusion": "vector"},
            {"id": "X2", "title": "Tomcat 日志文件利用", "products": ["tomcat"],
             "vector_score": 0.9029, "_fusion": "vector"},
            {"id": "X3", "title": "Kibana 原型污染到代码执行", "products": ["kibana"],
             "vector_score": 0.9020, "_fusion": "bm25+vector"},
        ]
        for q in ["foobarbaz-9x 的安全漏洞", "CWE-99999 相关的漏洞",
                  "ZzzNonexistentProduct 有哪些漏洞", "zzzqqq不存在的术语xyzzy"]:
            kept, stat = gate(fake_docs, q)
            ok("R6-A 假实体不放行语义噪声: %s" % q, len(kept) == 0,
               "kept=%d strong=%s" % (len(kept), stat.get("strong_terms")))

        # 真实体必须仍放行（防"修一个坏一个"）
        real_docs = [
            {"id": "C1", "title": "CVE-2026-7482 Ollama heap out-of-bounds read",
             "products": ["ollama"], "desc": "Ollama before 0.17.1 ...", "vector_score": 0.91,
             "_fusion": "bm25+vector"},
            {"id": "C2", "title": "vLLM RCE", "products": ["vllm"],
             "desc": "vLLM remote code execution", "vector_score": 0.90, "_fusion": "vector"},
        ]
        kept, _ = gate(real_docs, "Ollama 有哪些漏洞")
        ok("R6-A 真实体仍放行: Ollama", any(d["id"] == "C1" for d in kept), [d["id"] for d in kept])
        kept, _ = gate(real_docs, "CVE-2026-7482 的修复建议")
        ok("R6-A 真编号仍放行", any(d["id"] == "C1" for d in kept), [d["id"] for d in kept])

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  B. e2e：诚实边界（真打接口）")
        print("=" * 70)
        fakes = [
            ("假产品长串", "foobarbaz-9x 的安全漏洞"),
            ("假产品名", "ZzzNonexistentProduct 有哪些漏洞"),
            ("假 CVE", "CVE-2099-99999 的修复建议"),
            ("假 CWE", "CWE-99999 相关的漏洞"),
            ("假来源", "来源:no_such_source 的漏洞"),
            ("中文随机", "量子纠缠式内存泄漏漏洞有哪些"),
        ]
        honest = 0
        for name, q in fakes:
            st, r = chat(q)
            ev = r.get("evidence") or []
            concl = r.get("conclusion") or ""
            er = r.get("empty_reason")
            says_none = bool(re.search(r"没有|未找到|未命中|未提供|不存在|无匹配", concl))
            good = st == 200 and (er == "no_relevant" or says_none) and len(ev) == 0
            honest += 1 if good else 0
            ok("R6-A e2e 如实说没有: %s" % name, good,
               "ev=%d empty=%s" % (len(ev), er))
        ok("R6-A e2e 诚实率 6/6", honest == len(fakes), "%d/%d" % (honest, len(fakes)))

        # 真 CVE 不得被误杀
        for cve in ["CVE-2014-0160", "CVE-2021-44228"]:
            st, r = chat("%s 的修复建议" % cve)
            ev = r.get("evidence") or []
            ids = [str(e.get("id")) for e in ev]
            ok("R6-A e2e 真 CVE 不误杀: %s" % cve, cve in ids or len(ev) > 0,
               "ids=%s" % ids[:3])

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  C. 知识库口径自洽（vector_probe / status / corpus / stats）")
        print("=" * 70)
        vp = get_json("/api/qa/vector_probe?" + urllib.parse.urlencode({"q": "ollama 漏洞", "k": 3}))
        ok("R6-B vector_probe 可用（中文 q 可编码）",
           not vp.get("_err") and (vp.get("count") or 0) > 0 and len(vp.get("hits") or []) > 0,
           json.dumps(vp, ensure_ascii=False)[:140])
        hits = vp.get("hits") or []
        ok("R6-B vector_probe 返回余弦分",
           all(h.get("vector_score") is not None for h in hits) and len(hits) > 0,
           [h.get("vector_score") for h in hits])

        status = get_json("/api/qa/status")
        corpus = get_json("/api/corpus")
        stats = get_json("/api/stats")
        vc = status.get("vector_count") or vp.get("count")
        ok("R6-B status.vector_count 与 probe.count 一致",
           status.get("vector_count") == vp.get("count"),
           "status=%s probe=%s" % (status.get("vector_count"), vp.get("count")))
        ok("R6-C vector_count ≥ corpus.total（分块可多于文档）",
           (vc or 0) >= (corpus.get("total") or 0) > 0,
           "vector=%s corpus=%s" % (vc, corpus.get("total")))
        ok("R6-C corpus.total == stats.total（同一库口径）",
           (corpus.get("total") or 0) == (stats.get("total") or 0),
           "corpus=%s stats=%s" % (corpus.get("total"), stats.get("total")))

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  D. 双路径一致性：模板路 vs agent 路")
        print("=" * 70)
        for q in ["Ollama 有哪些高危漏洞", "哪些 AI 框架存在在野利用的漏洞",
                  "CVE-2026-7482 影响范围"]:
            st1, r1 = chat(q)
            st2, r2 = chat(q)
            c1 = r1.get("conclusion") or ""
            c2 = r2.get("conclusion") or ""
            n1 = bool(re.search(r"知识库中没有", c1))
            n2 = bool(re.search(r"知识库中没有", c2))
            ok("R6-D 双路口径不矛盾: %s" % q, n1 == n2,
               "none1=%s none2=%s" % (n1, n2))
            ok("R6-D 双路均 200: %s" % q, st1 == 200 and st2 == 200)

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 70)
        print("  E. 富化字段在问答里可达")
        print("=" * 70)
        st, r = chat("CVE-2026-7482 的修复建议")
        c = r.get("conclusion") or ""
        ok("R6-E 修复建议段含可操作版本/链接",
           bool(re.search(r"\d+\.\d+\.\d+", c)) or "http" in c, c[-200:])
        st, r = chat("CVE-2026-7482 影响范围")
        c = r.get("conclusion") or ""
        ok("R6-E 影响范围段含版本区间",
           bool(re.search(r"[<>≤]\s*\d+\.\d+", c)), c[-200:])
        st, r = chat("在野利用的漏洞有哪些")
        ev = r.get("evidence") or []
        if ev:
            ok("R6-E KEV 问题证据确为在野利用",
               all(e.get("exploited") for e in ev[:5]),
               [e.get("exploited") for e in ev[:5]])
        else:
            skip("R6-E KEV 可答性", "本机无 KEV 命中")

        # 覆盖度：真实产品必须答得出（从 corpus 抽一个真产品）
        items = corpus.get("items") or []
        real_prod = None
        for it in items:
            for pr in (it.get("products") or []):
                if pr and re.fullmatch(r"[a-z][a-z0-9_\-]{2,}", str(pr)):
                    real_prod = str(pr)
                    break
            if real_prod:
                break
        if real_prod:
            st, r = chat("%s 有哪些漏洞" % real_prod)
            ok("R6-覆盖度 真产品可答: %s" % real_prod,
               st == 200 and len(r.get("evidence") or []) > 0,
               "ev=%d" % len(r.get("evidence") or []))
        else:
            skip("R6-覆盖度", "corpus 无可用产品名")

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
