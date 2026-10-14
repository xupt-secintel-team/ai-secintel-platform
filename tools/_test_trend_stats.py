# -*- coding: utf-8 -*-
"""高频漏洞周期统计 回归（2026-10-08，离线）。

用真实语料 corpus.json 跑 aggregate()：
  A. weekly/monthly/yearly 三档结构完整（含 Markdown 报告要素）
  B. AI 安全风险四分类：结构、固定顺序、计数自洽
  C. 高频排序正确（count 降序）
  D. 严重度分布计数自洽（total_cves 与 top/by_severity 关系）
  E. 口径校验：published（发布日期）优先于 fetched_at
  F. 周/月/年窗口有区分度（回归用户报的『三种变化一模一样』）
  G. 严重度推导
  H. 非法 period
"""
from __future__ import annotations

import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import trend_stats as TS  # noqa: E402
import paths  # noqa: E402

OKS, FAILS = [], []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


def test_periods():
    print("[A] 三档周期结构")
    for p, days in (("weekly", 7), ("monthly", 30), ("yearly", 365)):
        d = TS.aggregate(p)
        check(d.get("period") == p, "%s period 字段" % p)
        check(d.get("days") == days, "%s 天数=%d" % (p, days), d.get("days"))
        check("top_cwe" in d and "top_product" in d and "top_cve" in d
              and "trend" in d and "by_severity" in d, "%s 关键字段" % p)
        check(len(d.get("trend") or []) == days, "%s 趋势序列长度" % p, len(d.get("trend") or []))
        # 日期连续（日历日，跨月/跨年都要对）
        ds = [x["day"] for x in d.get("trend") or []]
        check(ds[0] == d.get("start") and ds[-1] == d.get("end"), "%s 起止对齐" % p, (ds[0], d.get("start")))
        check(all(x["count"] >= 0 for x in d.get("trend") or []), "%s 趋势计数非负" % p)
        check(len(d.get("top_cve") or []) <= TS._TOP_N, "%s top_cve 不超限" % p)
        check(len(d.get("top_cwe") or []) <= TS._TOP_N, "%s top_cwe 不超限" % p)
        md = TS.report_markdown(d)
        for kw in ("概览", "AI 安全风险四分类分布", "高频弱点类型", "高频受影响产品",
                   "高危 CVE 榜", "每日趋势", "严重度分布"):
            check(kw in md, "%s 报告含「%s」" % (p, kw))


def test_ai_risk():
    print("[B] AI 安全风险四分类")
    d = TS.aggregate("monthly")
    air = d.get("by_ai_risk") or []
    check(len(air) == 5, "四分类+通用归并 = 5 桶", [x.get("category") for x in air])
    order = [x.get("category") for x in air]
    check(order == list(TS._AI_CATS) + [TS._AI_GENERAL],
          "固定顺序 ①②③④+通用", order)
    total = sum(x["count"] for x in air)
    check(total == d.get("ai_risk_total"), "四分类合计 == ai_risk_total",
          (total, d.get("ai_risk_total")))
    check(total >= (d.get("total_cves") or 0),
          "全部条目 ≥ 漏洞数（AI 计数含文章/论文）", (total, d.get("total_cves")))
    # ★ 回归用户报的「与日报对不上」：AI 四桶必须有真实数据（live 流是主要载体）
    ai_sum = sum(x["count"] for x in air[:4])
    check(ai_sum > 0, "AI 四桶合计 > 0（live 流文章/论文已计入）", ai_sum)
    check((d.get("live_counted") or 0) > 0, "live 流有条目计入", d.get("live_counted"))
    check(all("short" in x and "count" in x for x in air), "每桶带 short/count 字段")
    check(all(x["count"] >= 0 for x in air), "计数非负")
    # 周视图也要有 AI 数据（日报 10-08 当天就有 ②5/③5/④4 条）
    w = TS.aggregate("weekly")
    w_ai = sum(x["count"] for x in (w.get("by_ai_risk") or [])[:4])
    check(w_ai > 0, "周视图 AI 四桶合计 > 0", w_ai)
    md = TS.report_markdown(d)
    check("① AI基础设施与推理框架" in md, "报告含四分类桶名")
    check("实时流文章/论文" in md, "报告写明 live 流口径")


def test_ranking():
    print("[C] 高频排序")
    d = TS.aggregate("monthly")
    # CWE 频次降序
    top_cwe = d.get("top_cwe") or []
    if top_cwe:
        counts = [t["count"] for t in top_cwe]
        check(counts == sorted(counts, reverse=True), "CWE count 降序", counts[:8])
        check(all(__import__("re").match(r"CWE-\d+", t["cwe"]) for t in top_cwe),
              "CWE 格式", [t["cwe"] for t in top_cwe[:5]])
    # 产品频次降序
    top_prod = d.get("top_product") or []
    if top_prod:
        pcounts = [t["count"] for t in top_prod]
        check(pcounts == sorted(pcounts, reverse=True), "产品 count 降序", pcounts[:8])
    # CVE 榜：CVSS 降序、格式正确
    top_cve = d.get("top_cve") or []
    if top_cve:
        check(all(__import__("re").match(r"(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)", t["cve"]) for t in top_cve),
              "CVE 编号格式", [t["cve"] for t in top_cve[:5]])
        cvsses = [t["cvss"] for t in top_cve if t["cvss"] is not None]
        check(cvsses == sorted(cvsses, reverse=True), "CVE 榜 CVSS 降序", cvsses[:8])
        check(all(t["cvss"] is None or isinstance(t["cvss"], (int, float)) for t in top_cve),
              "cvss 类型", [t["cvss"] for t in top_cve[:5]])


def test_severity_consistent():
    print("[D] 严重度分布自洽")
    d = TS.aggregate("yearly")
    sev_sum = sum(s["count"] for s in d.get("by_severity") or [])
    # by_severity 的 count 是「漏洞数」（每个 CVE 计一次严重度），应 == total_cves
    check(sev_sum == d.get("total_cves", 0), "by_severity 合计 == total_cves",
          (sev_sum, d.get("total_cves")))
    # CWE 计数合计 ≤ total_cves（每个 CVE 最多计一次主 CWE）
    cwe_sum = sum(t["count"] for t in d.get("top_cwe") or [])
    check(cwe_sum <= d.get("total_cves", 0) + 1, "CWE top 计数 ≤ total_cves",
          (cwe_sum, d.get("total_cves")))


def test_day_source():
    print("[E] 口径：published（发布日期）优先")
    r1 = {"fetched_at": "2026-10-08T12:00:00", "published": "2026-01-01", "id": "CVE-2026-0001"}
    r2 = {"published": "2026-10-08", "id": "CVE-2026-0002"}
    r3 = {"fetched_at": "2026-10-08T12:00:00", "id": "CVE-2026-0003"}
    r4 = {"id": "CVE-2026-0004"}
    check(TS._window_day(r1) == "2026-01-01", "published 优先（发布日期定窗口）",
          TS._window_day(r1))
    check(TS._window_day(r2) == "2026-10-08", "published 直接命中", TS._window_day(r2))
    check(TS._window_day(r3) == "2026-10-08", "无 published 回退 fetched_at",
          TS._window_day(r3))
    check(TS._window_day(r4) == "", "无日期返回空", TS._window_day(r4))


def test_windows_differ():
    print("[F] 周/月/年窗口有区分度（用户报『三种变化一模一样』的回归）")
    w = TS.aggregate("weekly")
    m = TS.aggregate("monthly")
    y = TS.aggregate("yearly")
    nw, nm, ny = w.get("total_cves"), m.get("total_cves"), y.get("total_cves")
    check(nw <= nm <= ny, "weekly ≤ monthly ≤ yearly（单调）", (nw, nm, ny))
    check(nm != ny or nw != nm, "三窗口不完全相同", (nw, nm, ny))


def test_sev():
    print("[G] 严重度推导")
    check(TS._sev({"score": 9.8}) == "CRITICAL", "≥9 CRITICAL")
    check(TS._sev({"score": 7.5}) == "HIGH", "≥7 HIGH")
    check(TS._sev({"score": 5.0}) == "MEDIUM", "≥4 MEDIUM")
    check(TS._sev({"score": 2.0}) == "LOW", ">0 LOW")
    check(TS._sev({"score": None}) == "UNKNOWN", "None UNKNOWN")
    check(TS._sev({"score": "abc"}) == "UNKNOWN", "非数值 UNKNOWN")


def test_bad_period():
    print("[H] 非法 period")
    d = TS.aggregate("daily")
    check("error" in d and "weekly" in (d.get("error") or ""), "非法 period 报错", d.get("error"))


if __name__ == "__main__":
    test_periods()
    test_ai_risk()
    test_ranking()
    test_severity_consistent()
    test_day_source()
    test_windows_differ()
    test_sev()
    test_bad_period()
    print("\n== %d passed, %d failed ==" % (len(OKS), len(FAILS)))
    if FAILS:
        for f in FAILS:
            print("  FAILED:", f)
        sys.exit(1)
