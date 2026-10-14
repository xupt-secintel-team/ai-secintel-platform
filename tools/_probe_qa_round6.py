# -*- coding: utf-8 -*-
"""_probe_qa_round6.py —— 第 6 轮实测探针：知识库覆盖度 + 双路径一致性 + 诚实边界

前 5 轮分别审了：诚实化/冷启动（R1）、类型分流/攻击链/健壮（R2）、
锚定/三层缺陷/闸门（R3）、文案统一/cvss 双形态/多轮（R4）、三项能力渲染通道（R5）。

第 6 轮换角度 —— **从"知识库本身"出发**，而不是从"某个问句"出发：

  ① **覆盖度实测**：知识库里到底有哪些产品/CVE/CWE/来源？抽真实分布，
     再据此出题 —— 覆盖到的必须答得出，覆盖不到的必须说"没有"。
  ② **诚实边界**：问完全不存在的东西（假产品/假 CVE/假 CWE/伪造来源），
     是否**一致地**回答"没有"（不是有时有、有时没有）。
  ③ **边界外推**：问一个真实存在但**知识库没有**的 CVE（如 CVE-2017-0144 永恒之蓝），
     是否如实说"知识库中没有"，而不是拿相似 CVE 凑数。
  ④ **双路径一致性**：同一问题，no_llm（模板路）与默认（agent 路）——
       - agent 不可用时是否**自动降级**且答案仍可用？
       - 两条路给出的**证据集合/结论口径**是否矛盾（一个说有、一个说没有）？
  ⑤ **富化字段可答性**：富化产物（remediation / 受影响版本 / KEV / POC / 论文）
     是否真的在问答里**可达**（不是躺在库里没人用）。
  ⑥ **知识库口径自洽**：`/api/qa/status`、`/api/qa/vector_probe`、`/api/stats`
      报出的"库有多大/多少条/什么模型"是否**互相一致**（口径不能打架）。

用法： py tools/_probe_qa_round6.py [端口]
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
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9011
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

    def get(path, timeout=60):
        try:
            with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            return {"_err": str(e)[:100]}

    def chat(q, history=None, timeout=240, no_llm=True):
        body = {"q": q}
        if no_llm:
            body["no_llm"] = True
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
        print("=" * 74)
        print("  ① 知识库覆盖度：真实分布（产品 / 来源 / CWE / KEV / 版本）")
        print("=" * 74)
        corpus = get("/api/corpus", timeout=120)
        items = corpus.get("items") or []
        print("  corpus.total =", corpus.get("total"), "items =", len(items))
        prod_c = Counter()
        src_c = Counter()
        sev_c = Counter()
        kev_n = 0
        for it in items:
            for pr in (it.get("products") or []):
                if pr:
                    prod_c[str(pr).lower()] += 1
            for s in (it.get("sources") or []):
                src_c[str(s)] += 1
            sev_c[str(it.get("severity"))] += 1
            if it.get("exploited"):
                kev_n += 1
        print("  来源 TOP8:", src_c.most_common(8))
        print("  严重度:", sev_c.most_common())
        print("  KEV(exploited) 条数:", kev_n)
        print("  产品 TOP15:", [x[0] for x in prod_c.most_common(15)])

        stats = get("/api/stats")
        print("  /api/stats:", {k: stats.get(k) for k in
                               ("total", "kev", "poc", "vulns", "papers", "by_severity")
                               if k in stats} or list(stats.keys())[:8])

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 74)
        print("  ② 诚实边界：不存在的东西必须一致地说'没有'")
        print("=" * 74)
        fakes = [
            ("假产品", "ZzzNonexistentProduct 有哪些漏洞"),
            ("假产品2", "foobarbaz-9x 的安全漏洞"),
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
            print("  %-10s HTTP %s ev=%-2d empty=%-12s 说没有=%s" % (name, st, len(ev), str(er), says_none))
            if st == 200 and (er or says_none) and len(ev) <= 2:
                honest += 1
        print("  → 诚实回答 %d/%d" % (honest, len(fakes)))

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 74)
        print("  ③ 边界外推：真实但库中没有的 CVE，是否如实说'没有'")
        print("=" * 74)
        for cve in ["CVE-2017-0144", "CVE-2014-0160", "CVE-2021-44228"]:
            st, r = chat("%s 的修复建议" % cve)
            ev = r.get("evidence") or []
            ids = [e.get("id") for e in (ev or [])][:4]
            concl = r.get("conclusion") or ""
            has_self = cve.upper() in " ".join(str(x).upper() for x in ids)
            says_none = bool(re.search(r"没有|未找到|未提供|不存在", concl))
            print("  %-16s ev=%-2d 命中自身=%s 说没有=%s ids=%s" % (
                cve, len(ev), has_self, says_none, ids))
            # 关键：如果命中自身为 False，则不应硬凑（evidence 里不该全是最新无关 CVE）
            if not has_self:
                extra = [x for x in ids if str(x).upper().startswith("CVE-")]
                print("       ⚠ 未命中自身但返回了 CVE: %s" % extra[:3])

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 74)
        print("  ④ 双路径一致性：no_llm(模板) vs 默认(agent)")
        print("=" * 74)
        qs = ["Ollama 有哪些高危漏洞", "哪些 AI 框架存在在野利用的漏洞",
              "CVE-2026-7482 影响范围", "最新被在野利用的漏洞"]
        for q in qs:
            st1, r1 = chat(q, no_llm=True)
            st2, r2 = chat(q, no_llm=False, timeout=300)
            rc1 = (r1.get("reasoning_chain") or {}).get("strategy")
            rc2 = (r2.get("reasoning_chain") or {}).get("strategy")
            e1 = len(r1.get("evidence") or [])
            e2 = len(r2.get("evidence") or [])
            # 口径矛盾检测：一个有内容一个说"没有"
            c1_none = bool(re.search(r"知识库中没有", r1.get("conclusion") or ""))
            c2_none = bool(re.search(r"知识库中没有", r2.get("conclusion") or ""))
            print("  %-30s 模板(%s ev=%d)/agent(%s ev=%d) 口径矛盾=%s" % (
                q[:30], rc1, e1, rc2, e2, (c1_none != c2_none)))
            print("     r1.empty=%s r2.empty=%s r1.used_llm=%s r2.used_llm=%s" % (
                r1.get("empty_reason"), r2.get("empty_reason"),
                r1.get("used_llm"), r2.get("used_llm")))

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 74)
        print("  ⑤ 富化字段可答性：remediation/版本/KEV/POC/论文 是否可达")
        print("=" * 74)
        detail = get("/api/detail?id=CVE-2026-7482")
        fields = {k: bool(detail.get(k)) for k in
                  ("patch_links", "advisory_links", "poc_links", "cpe", "cwe", "refs")}
        print("  detail 字段:", fields)
        # 富化产物在问答里是否被用到
        st, r = chat("CVE-2026-7482 的修复建议")
        concl = r.get("conclusion") or ""
        print("  修复建议段含补丁链接/版本:", bool(re.search(r"http|v\d+\.\d+", concl)))
        st, r = chat("CVE-2026-7482 影响范围")
        concl = r.get("conclusion") or ""
        print("  影响范围段含版本区间:", bool(re.search(r"[<>≤]\s*\d+\.\d+", concl)))
        # KEV 可答性
        st, r = chat("在野利用的漏洞有哪些")
        ev = r.get("evidence") or []
        kev_ok = all(e.get("exploited") for e in ev[:5]) if ev else None
        print("  在野利用问题: ev=%d 前5条全 exploited=%s" % (len(ev), kev_ok))

        # ─────────────────────────────────────────────────────────
        print("\n" + "=" * 74)
        print("  ⑥ 知识库口径自洽：status / vector_probe / stats / corpus 互相不打架")
        print("=" * 74)
        qs_ = get("/api/qa/status")
        vp = get("/api/qa/vector_probe?q=ollama 漏洞&k=3")
        print("  qa/status:", {k: qs_.get(k) for k in
                              ("vector_ready", "vector_count", "vector_model", "vector_dim",
                               "corpus_total", "kev_count") if k in qs_} or list(qs_.keys())[:8])
        print("  vector_probe.count =", vp.get("count"), " hits =", len(vp.get("hits") or vp.get("results") or []))
        # 一致性判据
        c_total = corpus.get("total")
        s_total = stats.get("total")
        v_count = qs_.get("vector_count")
        print("  口径: corpus.total=%s stats.total=%s vector_count=%s" % (c_total, s_total, v_count))
        if c_total and s_total:
            print("  corpus vs stats 一致:", abs((c_total or 0) - (s_total or 0)) <= 1)

        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
