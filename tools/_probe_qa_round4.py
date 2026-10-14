# -*- coding: utf-8 -*-
"""_probe_qa_round4.py —— 第 4 轮实测探针：答案落地性 / 跨文档关联 / 结论可信度

前 3 轮修的是"检索能不能拿到对的东西"（零命中诚实化、冷启动、多轮、锚定、闸门）。
第 4 轮换**完全不同的角度**，独立复检"拿到之后，答案本身可不可信"——
即用户宣称里的「**精准回答**」「**关联推理**」：

  ① **答案落地性**：结论里的每个数字（条数/最高分/组件名）是否真能从 evidence 复算出来？
     结论说"最高 CVSS 9.8"，evidence 里是否真有 9.8？（防止生成式编造）
  ② **跨文档关联**：问"哪些组件同时有 X 和 Y"，结论是否真的做了**跨条目聚合**
     （而不是只讲第一条）？
  ③ **结论与证据一致性**：结论提到的组件名，是否都在 evidence 的 products 里？
  ④ **多轮上下文保真**：第二轮追问时，第一轮的实体是否被继承（不丢也不串）？
  ⑤ **详情可回溯**：每条 evidence 的 id 能否真的取到 /api/detail 全文？
  ⑥ **空答案边界**：只落盘"没有"时，断言是否也自洽（不出现"命中 0 条"却引用编号）？

用法： py tools/_probe_qa_round4.py [端口]
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
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8975
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _cvss(d):
    """cvss 字段在本项目里有两种形态：dict{score,severity} 或裸 float。
    探针必须两种都认（实测踩过：evidence 里出现过 float）。"""
    v = (d or {}).get("cvss")
    if isinstance(v, dict):
        return v.get("score")
    if isinstance(v, (int, float)):
        return v
    return None


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
        print("=" * 70)
        print("  ① 答案落地性：结论里的数字能否从 evidence 复算出来")
        print("=" * 70)
        for q in ["Ollama 有哪些漏洞", "vLLM 的高危漏洞", "哪些 AI 框架存在在野利用的漏洞"]:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            # 从 evidence 复算最高 CVSS
            scores = [_cvss(e) for e in ev]
            scores = [float(s) for s in scores if isinstance(s, (int, float))]
            real_max = max(scores) if scores else None
            # 结论里声称的最高分
            claimed = re.findall(r"最高\s*CVSS[^\d]{0,8}(\d+\.\d)", concl)
            claimed += re.findall(r"CVSS\s*(\d+\.\d)\s*（最高", concl)
            n_claim = re.findall(r"命中\s*(\d+)\s*条", concl)
            print("  Q: %s" % q)
            print("     evidence=%d · evidence_total=%s" % (len(ev), r.get("evidence_total")))
            print("     实测最高 CVSS=%s · 结论声称=%s" % (real_max, claimed[:2]))
            print("     结论声称命中=%s（evidence 实际 %d）" % (n_claim[:2], len(ev)))
            if claimed and real_max is not None:
                bad = [c for c in claimed if abs(float(c) - real_max) > 0.051]
                print("     ⚠ 与 evidence 不符的最高分：%s" % bad if bad else "     ✔ 最高分一致")
            if n_claim:
                bad_n = [n for n in n_claim if int(n) != len(ev)]
                print("     ⚠ 条数与 evidence 不符：%s" % bad_n if bad_n else "     ✔ 条数一致")

        print("\n" + "=" * 70)
        print("  ② 跨文档关联：多组件问题的结论是否做了跨条目聚合")
        print("=" * 70)
        for q in ["Ollama 和 vLLM 这两个框架，谁的漏洞更严重", "CWE-78 相关的 AI 框架漏洞有哪些"]:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            ev_prods = set()
            for e in ev:
                for pr in (e.get("products") or [])[:4]:
                    nm = pr if isinstance(pr, str) else (pr or {}).get("name")
                    if nm:
                        ev_prods.add(str(nm).lower())
            # 结论里提到了多少个不同组件
            mentioned = {p for p in ev_prods if p and p in concl.lower()}
            print("  Q: %s" % q)
            print("     evidence %d 条 · 涉及组件 %d 个" % (len(ev), len(ev_prods)))
            print("     结论提到的组件：%s" % sorted(mentioned)[:6])
            cvss_in_concl = re.findall(r"(\d+\.\d)", concl)
            print("     结论中的数值：%s" % cvss_in_concl[:8])

        print("\n" + "=" * 70)
        print("  ③ 结论与证据一致性：结论里的 CVE 编号是否都在 evidence 里")
        print("=" * 70)
        for q in ["Ollama 有哪些漏洞", "最近被在野利用的漏洞", "Ray 的漏洞"]:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev_ids = {str(e.get("id") or "").upper() for e in (r.get("evidence") or [])}
            cited = {c.upper() for c in _CVE_RE.findall(concl)}
            missing = cited - ev_ids
            print("  Q: %-24s 结论引用 CVE %d 个 · evidence %d 条 · 引用但不在证据 %d %s" % (
                q[:24], len(cited), len(ev_ids), len(missing),
                ("★ " + str(sorted(missing)[:4])) if missing else ""))

        print("\n" + "=" * 70)
        print("  ④ 多轮上下文保真：第二轮是否继承第一轮实体（不丢不串）")
        print("=" * 70)
        h1 = [{"role": "user", "content": "Ollama 有哪些漏洞"},
              {"role": "assistant", "content": "Ollama 存在多个漏洞，例如 CVE-2026-7482、CVE-2025-15514。"}]
        followups = ["那怎么修", "第一个漏洞的 CWE 是什么", "还有别的吗", "vLLM 呢"]
        for fu in followups:
            st, r = chat(fu, history=h1)
            ev = r.get("evidence") or []
            blob = json.dumps(ev, ensure_ascii=False).lower()
            has_ollama = "ollama" in blob
            print("  追问 %-26s -> HTTP %s evidence=%d 含Ollama=%s resolved=%s" % (
                fu, st, len(ev), has_ollama, r.get("resolved_ref")))

        print("\n" + "=" * 70)
        print("  ⑤ 详情可回溯：每个 evidence 的 id 能否取到 /api/detail")
        print("=" * 70)
        st, r = chat("Ollama 有哪些漏洞")
        ev = r.get("evidence") or []
        okn = miss = 0
        for e in ev[:5]:
            eid = e.get("id")
            if not eid:
                miss += 1
                continue
            try:
                d = get("/api/detail?id=%s" % urllib.parse.quote(str(eid)), timeout=60)
                okn += 1 if (d and (d.get("title") or d.get("desc"))) else 0
                if not (d and (d.get("title") or d.get("desc"))):
                    miss += 1
                    print("      ⚠ %s 取到但为空" % eid)
            except Exception as ex:  # noqa: BLE001
                miss += 1
                print("      ⚠ %s 取详情失败：%s" % (eid, str(ex)[:50]))
        print("  详情可取 %d 条 · 失败 %d 条（共试 %d）" % (okn, miss, len(ev[:5])))

        print("\n" + "=" * 70)
        print("  ⑥ 空答案边界：零命中时断言自洽")
        print("=" * 70)
        for q in ["zzzqqq不存在的术语xyzzy", "如何做红烧肉", "阿巴阿巴阿巴"]:
            st, r = chat(q)
            concl = r.get("conclusion") or ""
            ev = r.get("evidence") or []
            cited = _CVE_RE.findall(concl)
            has_hit_word = bool(re.search(r"命中\s*\d+\s*条", concl))
            print("  Q: %-24s HTTP %s evidence=%d" % (q[:24], st, len(ev)))
            print("     结论首行: %s" % (concl.split("\n")[0][:64] if concl else "（空）"))
            if not ev:
                print("     自洽检查: 引用CVE=%d（应0） 出现'命中N条'=%s（应False）" % (
                    len(cited), has_hit_word))
        return 0
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            p.kill()


if __name__ == "__main__":
    sys.exit(main())
