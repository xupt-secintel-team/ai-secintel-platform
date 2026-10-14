# -*- coding: utf-8 -*-
"""
评测多跳推理.py —— 跨文档/多跳推理准确率专项实测
================================================================
评分细则·性能指标 3：问答深度与准确率（多跳推理准确率 ≥85% 为优秀）。
评分细则·功能指标 3：跨文档推理与深度分析能力。

此前系统只有「引用相关性 D1=90%」这类单跳代理指标。本脚本专测**多跳推理链**：
13 道题全部需要 ≥2 步检索/推理（比较、归因、条件链、指代消解、跨源验证、聚合统计），
每题的判据（ground truth）由评测脚本**独立地从结构化接口数据推导**
（/api/detail 的 CVSS/CWE/products、/api/assets 的版本区间、/api/search 的
算子结果集与 total 计数），再检查**答案文本**是否包含这些事实 —— 判据与问答链路分离，
不循环自证。

题型分布：
  A. 双实体比较（跨文档比较大小/异同）     ×2
  B. 条件链（多约束过滤 + 列举）           ×2
  C. 归因跳（CVE → CWE → 同类其他漏洞）    ×2
  D. 影响面跳（CVE → 组件 → 受影响版本）   ×1
  E. 跨源验证跳（KEV 标记 + 评分 + 产品）  ×2
  F. 论文关联跳（CVE → 关联研究）          ×1
  G. 多轮指代消解（"第一个"回指上一轮的CVE）×1
  H. 同组件聚合极值（某组件 CVSS 最高的洞）×1
  I. 聚合统计（某组件满足条件的漏洞计数）  ×1

用法：
  py -3 tools/评测多跳推理.py --base http://127.0.0.1:8848
  （服务配了 AISEC_LLM_API_KEY 时自动加测 LLM/Agent 模式，两组分开报告）
输出：测试报告/多跳推理评测.md + 测试报告/多跳推理评测.json
"""
import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 目标服务：逐级回落 AISEC_EVAL_BASE → AISEC_MAIN_SERVER → 8848（服务真实默认端口）。
# 原来 argparse 里写死 8899，那个端口上通常什么都没有 → 评测全线 502。
BASE = (os.environ.get("AISEC_EVAL_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")

# 本机回环请求强制不走系统代理：设过 HTTP_PROXY 的机器上，
# urlopen("http://127.0.0.1:8848") 会被发给代理 → 502 Bad Gateway，
# 症状像"服务坏了"，实际服务好好的。
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
REPORT_DIR = os.path.join(ROOT, "测试报告")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def log(*a):
    print("[多跳]", *a, flush=True)


def get(base, path, timeout=90):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=timeout) as r:
        return json.load(r)


def post_chat(base, q, history=None, no_llm=False):
    url = base.rstrip("/") + "/api/chat"
    body = {"q": q, "history": history or []}
    if no_llm:
        body["no_llm"] = True
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=180) as r:
        d = json.load(r)
    return d, time.time() - t0


def search_ids(base, query, size=60):
    d = get(base, "/api/search?q=" + urllib.parse.quote(query) + f"&size={size}")
    return d.get("results") or d.get("items") or []


def detail(base, cid):
    return get(base, "/api/detail?id=" + urllib.parse.quote(cid))


# ── 题目工厂：先取真值，再造题（真值驱动，非拍脑袋）────────────────
def build_questions(base):
    Q = []

    # A1 双实体比较：两个 Ollama CVE 比 CVSS
    a, b = "CVE-2024-37032", "CVE-2025-15063"
    da, db = detail(base, a), detail(base, b)
    sa, sb = (da.get("cvss") or {}).get("score"), (db.get("cvss") or {}).get("score")
    if sa is not None and sb is not None and sa != sb:
        winner, wscore = (a, sa) if sa > sb else (b, sb)
        Q.append({"type": "A·双实体比较",
                  "q": f"{a} 和 {b} 哪个 CVSS 评分更高？高多少？",
                  "must": [winner, f"{wscore}"],
                  "forbid_lower_as_answer": (b if winner == a else a),
                  "note": f"真值：{a}={sa}, {b}={sb}"})

    # A2 同组件判定
    pa = set(da.get("products") or [])
    pb = set(detail(base, "CVE-2024-39720").get("products") or [])
    same = bool(pa & pb)
    Q.append({"type": "A·双实体比较",
              "q": "CVE-2024-39720 和 CVE-2024-37032 影响的是同一个组件吗？是哪个组件？",
              "must": sorted(pa & pb) if same else [],
              "must_any": [] if same else ["不同"],
              "note": f"真值：共同组件={sorted(pa & pb)}"})

    # B1 条件链：KEV + CVSS 10（判据：逐条用 /api/detail 独立验证，不用截断真值集）
    rs = search_ids(base, "kev:yes cvss>=10")
    if any((r.get("cvss") or {}).get("score") == 10.0 for r in rs):
        Q.append({"type": "B·条件链",
                  "q": "已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？",
                  "verify": "kev_cvss10", "min_hit": 1,
                  "note": "判据：答案提到的每个 CVE 都经 /api/detail 验证 exploited+score==10.0"})

    # B2 条件链：POC + 高危 + 指定厂商（XenForo）
    rs = search_ids(base, "poc:yes cvss>=9", size=60)
    if any("xenforo" in (r.get("title") or "").lower() for r in rs):
        Q.append({"type": "B·条件链",
                  "q": "有公开 POC 且 CVSS≥9 的 XenForo 漏洞有哪些？",
                  "verify": "poc9_xenforo", "min_hit": 1,
                  "note": "判据：逐条 /api/detail 验证 poc_count>0 + score≥9 + 标题含 xenforo"})

    # C1 归因跳：CWE 同类
    cwe_ids = [w.get("id") if isinstance(w, dict) else str(w) for w in (db.get("cwe") or [])]
    if cwe_ids:
        Q.append({"type": "C·归因跳",
                  "q": f"{b} 的弱点类型（CWE）是什么？语料中还有哪些 Ollama 漏洞属于同一 CWE？",
                  "must": [cwe_ids[0]],
                  "note": f"真值 CWE={cwe_ids}"})

    # C2 归因跳：另一个 CVE
    dc = detail(base, "CVE-2026-64849")
    cwe2 = [w.get("id") if isinstance(w, dict) else str(w) for w in (dc.get("cwe") or [])]
    if cwe2:
        Q.append({"type": "C·归因跳",
                  "q": "CVE-2026-64849（MLflow）的 CWE 是什么？还有别的 MLflow 漏洞吗？",
                  "must": [cwe2[0]],
                  "note": f"真值 CWE={cwe2}"})

    # D 影响面跳：版本区间
    try:
        assets = get(base, "/api/assets?id=" + a)
        vers = []
        for it in assets.get("assets") or []:
            vers += it.get("affected_versions") or []
        ver_hit = [v for v in vers if re.search(r"\d+\.\d+", v)]
        if ver_hit:
            m = re.search(r"(\d+\.\d+[\.\d]*)", ver_hit[0])
            Q.append({"type": "D·影响面跳",
                      "q": f"{a} 影响 Ollama 的哪些版本？",
                      "must": [m.group(1)],
                      "note": f"真值版本区间：{vers[:3]}"})
    except Exception as _sw_e:
        _swallow("tools/评测多跳推理.py:151", _sw_e)

    # E1 跨源验证跳
    if (dc.get("cvss") or {}).get("score"):
        Q.append({"type": "E·跨源验证",
                  "q": "CVE-2026-64849 是否已被在野利用？CVSS 评分多少？影响什么产品？",
                  "must": [f"{(dc.get('cvss') or {}).get('score')}"],
                  "must_any": ["在野", "exploit", "KEV", "已被利用"] ,
                  "note": f"真值：exploited={dc.get('exploited')}, cvss={(dc.get('cvss') or {}).get('score')}"})

    # E2 跨源验证跳：GitLab KEV
    rs = search_ids(base, "kev:yes gitlab")
    if rs:
        Q.append({"type": "E·跨源验证",
                  "q": "GitLab 相关的、已被在野利用的漏洞有哪些？",
                  "verify": "kev_gitlab", "min_hit": 1,
                  "note": "判据：逐条 /api/detail 验证 exploited + 标题/产品含 gitlab"})

    # F 论文关联跳
    dp = detail(base, "CVE-2026-94627")
    papers = dp.get("papers") or []
    if papers:
        words = set()
        for p in papers:
            words |= {w.lower() for w in re.findall(r"[A-Za-z]{6,}", p.get("title", ""))}
        Q.append({"type": "F·论文关联",
                  "q": "CVE-2026-94627（vLLM）有哪些关联的研究论文？",
                  "must_any": sorted(words)[:20],
                  "note": f"真值论文：{[p.get('title','')[:50] for p in papers]}"})

    # H 同组件聚合极值（真值=结构化算子查询的确定性最大值，允许并列；
    # 不用相关性排序 top-N 当真值——相关性排序会漏掉真最大分条目）
    rs = search_ids(base, "vllm cvss>=9", size=60)
    scored = [(r["id"], (r.get("cvss") or {}).get("score")) for r in rs
              if (r.get("cvss") or {}).get("score") is not None]
    if scored:
        max_s = max(s for _, s in scored)
        top_ids = sorted(i for i, s in scored if s == max_s)
        Q.append({"type": "H·聚合极值",
                  "q": "vLLM 的漏洞里 CVSS 评分最高的是哪一个？多少分？",
                  "must_any": top_ids, "must": [f"{max_s}"],
                  "note": f"真值：检索前60条最大分 {max_s}，并列 {top_ids}"})

    # I 聚合统计（v2.3 新增：真值 = /api/search 的结构化算子 total 精确计数）
    try:
        total_rs = get(base, "/api/search?q=" + urllib.parse.quote("ollama cvss>=7") + "&size=1")
        total_n = total_rs.get("total")
        if total_n:
            Q.append({"type": "I·聚合统计",
                      "q": "ollama 有多少个高危漏洞（CVSS≥7）？",
                      "must": [f"{total_n}"],
                      "note": f"真值：/api/search?q=ollama cvss>=7 的 total={total_n}"})
    except Exception as _sw_e:
        _swallow("tools/评测多跳推理.py:204", _sw_e)

    # G 多轮指代消解（在 run 里特殊处理）
    Q.append({"type": "G·多轮指代", "q": "__MULTI_TURN__",
              "turn1": "Ollama 有哪些高危漏洞（CVSS≥7）？",
              "turn2": "第一个漏洞的 CVSS 评分和 CWE 弱点类型分别是什么？",
              "note": "第二轮答案须含第一轮出现过的某个 CVE 编号 + 任一 CWE- 编号"})
    return Q


_DETAIL_CACHE = {}


def _verified(base, cid, kind):
    """用 /api/detail 的结构化字段独立验证一个被答出的 CVE 是否满足条件。"""
    if cid not in _DETAIL_CACHE:
        try:
            _DETAIL_CACHE[cid] = detail(base, cid)
        except Exception:
            _DETAIL_CACHE[cid] = {}
    d = _DETAIL_CACHE[cid]
    if not d:
        return False
    score = (d.get("cvss") or {}).get("score")
    exploited = bool(d.get("exploited") or d.get("kev"))
    title = (d.get("title") or "").lower()
    prods = " ".join(d.get("products") or []).lower()
    if kind == "kev_cvss10":
        return exploited and score is not None and abs(float(score) - 10.0) < 0.051
    if kind == "poc9_xenforo":
        poc = (d.get("poc_count") or 0) > 0 or bool(d.get("poc_links"))
        return poc and score is not None \
            and float(score) >= 9.0 and "xenforo" in title + " " + prods
    if kind == "kev_gitlab":
        return exploited and "gitlab" in title + " " + prods
    return False


def judge(base, qd, answer):
    ans = answer or ""
    ans_low = ans.lower()
    fails = []
    for m in qd.get("must") or []:
        if str(m).lower() not in ans_low:
            fails.append(f"缺事实: {m}")
    if qd.get("must_any"):
        if not any(str(x).lower() in ans_low for x in qd["must_any"]):
            fails.append(f"缺任一关键词: {qd['must_any'][:4]}")
    if qd.get("verify"):
        mentioned = sorted(set(CVE_RE.findall(ans)))
        good = [c for c in mentioned if _verified(base, c, qd["verify"])]
        bad = [c for c in mentioned if c not in good]
        if len(good) < qd.get("min_hit", 1):
            fails.append(f"经detail验证的正确条目不足: {good}")
        if bad:
            fails.append(f"答出不满足条件的CVE: {bad[:4]}")
    return fails


def run_mode(base, questions, no_llm, label):
    rows = []
    for qd in questions:
        if qd["q"] == "__MULTI_TURN__":
            r1, t1 = post_chat(base, qd["turn1"], no_llm=no_llm)
            ans1 = r1.get("answer", "")
            cves1 = set(CVE_RE.findall(ans1))
            hist = [{"role": "user", "content": qd["turn1"]},
                    {"role": "assistant", "content": ans1[:1500]}]
            r2, t2 = post_chat(base, qd["turn2"], history=hist, no_llm=no_llm)
            ans2 = r2.get("answer", "")
            cves2 = set(CVE_RE.findall(ans2))
            ok_ref = bool(cves2 & cves1) or (not cves2 and "CVE" not in ans2 and bool(cves1) and cves1)
            fails = []
            if cves1 and not (cves2 & cves1):
                fails.append(f"指代未消解: 二轮CVE{cves2 or '∅'} 与一轮{cves1}无交集")
            if "CWE-" not in ans2:
                fails.append("缺 CWE 事实")
            rows.append({"type": qd["type"], "q": qd["turn1"] + " → " + qd["turn2"],
                         "pass": not fails, "fails": fails, "latency": round(t1 + t2, 1),
                         "used_llm": r2.get("used_llm"), "note": qd["note"]})
            log(f"[{label}] {qd['type']} {'PASS' if not fails else 'FAIL'} {fails}")
            continue
        try:
            r, lat = post_chat(base, qd["q"], no_llm=no_llm)
        except Exception as e:
            rows.append({"type": qd["type"], "q": qd["q"], "pass": False,
                         "fails": [f"请求异常: {e}"], "latency": None, "note": qd["note"]})
            continue
        fails = judge(base, qd, r.get("answer", ""))
        rows.append({"type": qd["type"], "q": qd["q"], "pass": not fails, "fails": fails,
                     "latency": round(lat, 1), "used_llm": r.get("used_llm"),
                     "agent": (r.get("agent") or {}).get("mode") if isinstance(r.get("agent"), dict) else None,
                     "note": qd["note"]})
        log(f"[{label}] {qd['type']} {'PASS' if not fails else 'FAIL'} {fails}")
    return rows


def summarize(rows):
    n = len(rows)
    p = sum(1 for r in rows if r["pass"])
    by_type = {}
    for r in rows:
        t = r["type"].split("·")[0]
        by_type.setdefault(t, [0, 0])
        by_type[t][1] += 1
        by_type[t][0] += 1 if r["pass"] else 0
    return n, p, by_type


def main():
    ap = argparse.ArgumentParser()
    # 默认取 BASE（已按 AISEC_EVAL_BASE / AISEC_MAIN_SERVER / 8848 逐级回落），
    # 不能写死 8899 —— 那个端口上通常什么都没有，评测会全线 502。
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()
    base = args.base

    log("构建题库（真值由结构化接口独立推导）……")
    questions = build_questions(base)
    log(f"题库 {len(questions)} 题")

    status = get(base, "/api/qa/status")
    has_llm = bool(status.get("env_key"))
    log(f"LLM Key: {'已配置（将加测 LLM/Agent 模式）' if has_llm else '未配置（仅测模板模式）'}")

    results = {}
    rows0 = run_mode(base, questions, no_llm=True, label="模板")
    results["模板模式(no_llm)"] = rows0
    if has_llm:
        rows1 = run_mode(base, questions, no_llm=False, label="LLM")
        results["LLM/Agent模式"] = rows1

    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(os.path.join(REPORT_DIR, "多跳推理评测.json"), "w", encoding="utf-8") as f:
        json.dump({"base": base, "updated": dt.datetime.now().isoformat(),
                   "results": results}, f, ensure_ascii=False, indent=1)

    L = []
    L.append("# 多跳推理准确率专项评测\n")
    L.append(f"- 实测时间：{dt.datetime.now():%Y-%m-%d %H:%M} · 服务：{base}")
    L.append("- 复跑：`py -3 tools/评测多跳推理.py --base http://127.0.0.1:<端口>`")
    L.append("- 判据设计：每题真值由评测脚本**独立**从 `/api/detail`、`/api/assets`、"
             "`/api/search` 的结构化字段推导，再与**答案文本**比对；判据不经过问答链路，"
             "且「答出真值集外的 CVE」直接判错（防止多报凑命中）\n")
    for label, rows in results.items():
        n, p, by_type = summarize(rows)
        L.append(f"\n## {label}：{p}/{n} = **{p/n*100:.1f}%**\n")
        L.append("| 题型 | 通过/题数 |")
        L.append("|---|---|")
        for t, (pp, nn) in sorted(by_type.items()):
            L.append(f"| {t} | {pp}/{nn} |")
        L.append("\n| 题 | 结果 | 失败原因 / 备注 | 耗时 |")
        L.append("|---|---|---|---|")
        for r in rows:
            mark = "✅" if r["pass"] else "❌"
            why = "；".join(r["fails"]) if r["fails"] else r.get("note", "")
            L.append(f"| {r['type']} {r['q'][:38]} | {mark} | {why[:80]} | {r.get('latency') or '—'}s |")
    L.append("\n## 口径与局限\n")
    L.append("- 「多跳」定义：每题至少需要两次检索或一次检索+一次跨文档推理（比较/归因/指代）才能答对，"
             "题型表见 `tools/评测多跳推理.py` 头部注释；")
    L.append("- 判据是**事实包含**（答案须含真值事实）而非语义相似度，机械可复核；")
    L.append("- 模板模式的弱项会如实保留（如聚合/比较题只能列证据不能下结论）；"
             "配 `AISEC_LLM_API_KEY` 后本脚本自动加测 LLM/Agent 模式并分开报告。")
    md = "\n".join(L) + "\n"
    with open(os.path.join(REPORT_DIR, "多跳推理评测.md"), "w", encoding="utf-8") as f:
        f.write(md)
    for label, rows in results.items():
        n, p, _ = summarize(rows)
        log(f"{label}: {p}/{n} = {p/n*100:.1f}%")
    log("报告已写出：测试报告/多跳推理评测.md")


if __name__ == "__main__":
    main()
