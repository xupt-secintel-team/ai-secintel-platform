# -*- coding: utf-8 -*-
"""trend_stats.py —— 高频漏洞周期统计（周/月/年）
================================================================
为什么做（2026-10-08 用户需求）：日报看「今天」，缺一个「过去一周/
一月/一年到底什么漏洞最频繁、趋势怎么走」的聚合视图。

口径（务必写清，避免与日报口径打架）：
1. **按漏洞实体聚合**：以 CVE/GHSA 编号为键，跨来源去重后按「命中次数」
   （同一编号在多少条情报条目里出现）排名，得到「高频漏洞」。
2. **时间窗按漏洞发布日期 published**（源站口径——「最近一周/月/年
   新发的漏洞」），缺失时回退 fetched_at。
   ★ 2026-10-08 实测修正：原 fetched_at 优先口径下，全量收割是突发批量
   入库、fetched_at 全挤在收割那几天 → 周/月/年三个窗口几乎一模一样
   （5516/6119/6119，月年完全相同）。published 口径下 1370/5997/16383，
   梯度分明。日报「今天系统发现了什么」的 fetched_at 口径不受影响。
3. 周期定义（日历，非滑动）：
   - weekly  = 最近 7 个自然日（含今天）
   - monthly = 最近 30 个自然日
   - yearly  = 最近 365 个自然日
4. 数据源：corpus.json 全量 records（含 published/fetched_at/cvss/kev/category）。
   实时流 live_feed.jsonl 不单独计入（去重后大多是文章/论文，CVE 提及少，
   且 corpus 已含入库条目）——保持「漏洞高频」聚焦在真实 CVE 上。
5. **AI 安全风险四分类**（2026-10-08 用户指定）：① 基础设施与推理框架 /
   ② 模型与数据层 / ③ 应用与智能体 / ④ 供应链与平台，直接取语料
   category 字段（taxonomy 全项目唯一分类入口），**不重新实现分类**；
   通用七类与未分类归并展示为「通用网络安全」，数据不丢。
   ★ 计数范围 = 窗口内**全部情报条目**（corpus 漏洞 + live 流文章/论文，
   按 id 去重）——corpus records 全是 CVE，AI 分类的主要载体（文章/论文）
   只在 live 流里，不读它 AI 四类恒为 0、与日报页对不上（实测已踩）。

产出：
  - aggregate(period) → {period, days, total_cves, top:[...],
                          trend:[{day,count}], by_severity:{...},
                          by_category:[...], by_ai_risk:[...]}
  - report_markdown(period, data) → 周/月/年报 Markdown
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter, OrderedDict

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    import paths

_PERIOD_DAYS = {"weekly": 7, "monthly": 30, "yearly": 365}
_PERIOD_LABEL = {"weekly": "周报", "monthly": "月报", "yearly": "年报"}
_TOP_N = 20            # 高频漏洞榜前 N

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9-]+)\b", re.I)
_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")

# 严重度区间（与项目其它处一致，CVSS v3.1）
_SEV_LABEL = {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"}

# AI 安全风险四分类（2026-10-08 用户指定的分类标准；与日报/方向卡同一份口径，
# 标签值 = core/taxonomy.py RISK_CATEGORIES 的分类键，语料 category 字段原值）。
_AI_CATS = ("① AI基础设施与推理框架", "② 模型与数据层",
            "③ AI应用与智能体", "④ AI供应链与平台")
_AI_GENERAL = "通用网络安全"     # ⑤~⑪ 通用七类 + 未分类的归并展示桶（数据不丢）
_AI_SHORT = {                    # 图表 X 轴短标签
    "① AI基础设施与推理框架": "基础设施/\n推理框架",
    "② 模型与数据层": "模型与\n数据层",
    "③ AI应用与智能体": "应用与\n智能体",
    "④ AI供应链与平台": "供应链\n与平台",
    _AI_GENERAL: "通用\n网络安全",
}


def _sev(cvss: dict) -> str:
    try:
        s = float((cvss or {}).get("score") or 0)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9:
        return "CRITICAL"
    if s >= 7:
        return "HIGH"
    if s >= 4:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "UNKNOWN"


def _window_day(rec: dict) -> str:
    """趋势统计的时间窗口径：**漏洞发布日期 published 优先**（源站口径），
    缺失回退 fetched_at。

    为什么与日报（fetched_at 口径）**刻意不同**：全量收割是突发批量入库，
    fetched_at 全挤在收割那几天 → 周/月/年三个窗口几乎一模一样
    （2026-10-08 实测：fetched_at 命中 5516/6119/6119，月年完全相同；
    published 命中 1370/5997/16383，梯度分明）。趋势统计要的是
    「最近一周/月/年**新发**的漏洞」，所以按 published 开窗。
    日报的「今天系统发现了什么」语义不受影响（那是 daily_report 自己的口径）。
    """
    m = _DATE_RE.match(str(rec.get("published") or ""))
    if m:
        return m.group(1)
    m = _DATE_RE.match(str(rec.get("fetched_at") or ""))
    return m.group(1) if m else ""


def _read_corpus():
    fp = paths.CORPUS_FP
    if not os.path.isfile(fp):
        return []
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d.get("records", []) if isinstance(d, dict) else []
    except (OSError, ValueError):
        return []


def _read_live():
    """live_feed.jsonl（实时情报流：社区文章 / 论文 / KEV·GHSA 增量）。

    ★ 为什么 AI 四分类必须读它（2026-10-08 用户实测"对不上"）：
    corpus records **全部是 CVE**（68018 条全是 CVE- 前缀），而 AI 分类
    的主要载体（社区文章、arXiv 论文）**只存在于 live 流**——实测近 7 天
    ③ AI应用与智能体 786 条 / ② 模型与数据层 194 条全在 live_feed 里。
    只读 corpus 会让 AI 四类恒为 0，与日报页（读 live 流）对不上。
    每条都带 category（0 缺失，taxonomy 全项目唯一分类入口），直接用。
    """
    fp = os.path.join(paths.DATA_DIR, "live_feed.jsonl")
    if not os.path.isfile(fp):
        return []
    out = []
    try:
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict):
                    out.append(e)
    except OSError:
        return []
    return out


def _date_range(period: str):
    """返回 (开始日期, 结束日期, 日期列表[旧→新])。"""
    days = _PERIOD_DAYS.get(period, 7)
    end = time.localtime()
    dates = []
    for i in range(days):
        t = time.localtime(time.time() - (days - 1 - i) * 86400)
        dates.append(time.strftime("%Y-%m-%d", t))
    return dates[0], dates[-1], dates


def aggregate(period: str = "weekly", top_n: int = _TOP_N) -> dict:
    """聚合高频漏洞。返回可直接给前端画图 + 生成报告的结构。

    ★ 口径（2026-10-08 实测修正）：
    「高频漏洞」的"高频"应落在**可重复出现的维度**上——CWE（弱点类型）与
    受影响产品。CVE 编号在语料里按 id 去重后每个只出现 1 次，"按 CVE 计数"
    会退化成恒为 1 的无意义排序（实测 2944 个 CVE 的 count 全是 1）。
    所以：
      top_cwe   = 窗口内弱点类型频次榜（真正的高频）
      top_product = 窗口内受影响产品频次榜
      top_cve   = 窗口内高危 CVE 榜（按 CVSS 降序，非频次）
    trend / by_severity / by_category 按「不同 CVE 数」统计（每条 record 一个 CVE）。
    """
    if period not in _PERIOD_DAYS:
        return {"error": "period 只支持 weekly / monthly / yearly", "period": period}
    start, end, dates = _date_range(period)
    date_set = set(dates)

    # cve → 聚合信息；trend 按「不同 CVE」计；严重度/分类/CWE/产品按 CVE 计
    cve_map = {}              # cve -> {rec}（去重后每个 cve 一条）
    trend = Counter()         # day -> 当天出现的不同 CVE 数
    severity_counter = Counter()
    category_counter = Counter()
    ai_risk_counter = Counter()
    cwe_counter = Counter()
    product_counter = Counter()
    kev_total = 0             # ★ 窗口内全部在野利用（KEV）漏洞数（2026-10-18 口径修复）

    seen_ids = set()          # corpus ∪ live 的去重集合（同 id 不重复计数）
    n_live_counted = 0

    for rec in _read_corpus():
        if not isinstance(rec, dict):
            continue
        day = _window_day(rec)
        if day not in date_set:
            continue
        cve = str(rec.get("id") or "")
        if not _CVE_RE.match(cve):
            continue
        sev = _sev(rec.get("cvss"))
        cat = str(rec.get("category") or "").strip()
        if cve in cve_map:
            continue                       # 同 CVE 多 record（极少）只计一次
        cve_map[cve] = rec
        seen_ids.add(cve)
        trend[day] += 1
        severity_counter[sev] += 1
        # ★ 在野利用计数与「窗口内新发漏洞」同口径（2026-10-18 修复"对不上"）：
        #   原 kev_count 只数 TOP20 高危榜里的 KEV —— KEV 条目 CVSS 不够高没进榜
        #   就漏计（实测 weekly 窗口内实际 3 个 KEV，页面却显示 0，与日报页
        #   的 KEV 条目对不上）。改为全窗口计数。
        if bool((rec.get("kev") or {}).get("exploited") or rec.get("exploited")):
            kev_total += 1
        if cat in _AI_CATS:
            ai_risk_counter[cat] += 1      # 用户指定的 AI 四分类口径
        else:
            ai_risk_counter[_AI_GENERAL] += 1   # 通用七类/未分类归并展示，数据不丢
        if cat:
            category_counter[cat] += 1
        for w in (rec.get("cwe") or []):
            wid = w.get("id") if isinstance(w, dict) else str(w)
            if wid and wid.startswith("CWE-"):
                cwe_counter[wid] += 1
                break                       # 主 CWE 只取第一个
        for p in (rec.get("products") or [])[:1]:
            if p:
                product_counter[str(p)] += 1
                break

    # live 流（社区文章/论文/KEV 增量）：只进「AI 四分类 / 分类分布」两个计数器。
    # CWE/产品/CVE 榜等漏洞维度保持 corpus-CVE 口径不变（live 里的文章没有这些字段，
    # 混进去会稀释"漏洞高频"的语义）。与日报同源（daily_report 也读 live 流），
    # 周视图的 AI 四类从此与日报页对得上。
    for e in _read_live():
        if not isinstance(e, dict):
            continue
        eid = str(e.get("id") or "")
        if not eid or eid in seen_ids:
            continue                        # 与 corpus / 前面条目去重
        day = _window_day(e)
        if day not in date_set:
            continue
        seen_ids.add(eid)
        cat = str(e.get("category") or "").strip()
        if cat in _AI_CATS:
            ai_risk_counter[cat] += 1
        else:
            ai_risk_counter[_AI_GENERAL] += 1
        if cat:
            category_counter[cat] += 1
        n_live_counted += 1

    # 高危 CVE 榜：按 CVSS 降序（有 KEV 的优先）
    def _cve_rank(cve, rec):
        cvss = ((rec.get("cvss") or {}).get("score") or 0)
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0
        kev = bool((rec.get("kev") or {}).get("exploited") or rec.get("exploited"))
        return (-cvss, not kev)

    ordered_cve = sorted(cve_map.items(), key=lambda kv: _cve_rank(kv[0], kv[1]))[:top_n]
    top_cve = []
    for cve, rec in ordered_cve:
        cvss = rec.get("cvss") or {}
        top_cve.append({
            "cve": cve,
            "cvss": cvss.get("score"),
            "severity": _sev(cvss),
            "kev": bool((rec.get("kev") or {}).get("exploited") or rec.get("exploited")),
            "title": (rec.get("title") or rec.get("desc") or "")[:180],
            "category": rec.get("category") or "",
        })

    top_cwe = [{"cwe": k, "count": v} for k, v in cwe_counter.most_common(top_n)]
    top_product = [{"product": k, "count": v} for k, v in product_counter.most_common(top_n)]

    # 日粒度趋势（图表用）：只保留有数据的天（没 CVE 的天 = 0，仍要给点，图表才连续）
    trend_series = [{"day": d, "count": trend.get(d, 0)} for d in dates]

    # 严重度分布（图表用，固定顺序）
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    by_severity = [{"severity": s, "label": _SEV_LABEL.get(s, "未知"),
                    "count": severity_counter.get(s, 0)} for s in sev_order]

    # 分类分布 TOP（图表用）
    by_category = [{"category": k, "count": v}
                   for k, v in category_counter.most_common(8)]

    # AI 安全风险四分类（固定顺序 ①②③④ + 通用归并，图表用；
    # 口径 = 语料 category 字段（taxonomy 全项目唯一分类入口），非重新分类）
    by_ai_risk = [{"category": c,
                   "short": _AI_SHORT.get(c, c),
                   "count": ai_risk_counter.get(c, 0)}
                  for c in _AI_CATS + (_AI_GENERAL,)]

    return {
        "period": period,
        "label": _PERIOD_LABEL[period],
        "days": _PERIOD_DAYS[period],
        "start": start,
        "end": end,
        "total_cves": len(cve_map),          # 窗口内出现的不同 CVE 总数（漏洞维度口径）
        "live_counted": n_live_counted,      # live 流计入 AI 分类/分类分布的条数
        "total_entries": len(cve_map) + n_live_counted,   # 全部情报条目（漏洞+文章+论文）
        "top_cve": top_cve,
        "top_cwe": top_cwe,
        "top_product": top_product,
        "top_n": top_n,
        "trend": trend_series,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_ai_risk": by_ai_risk,
        "ai_risk_total": sum(x["count"] for x in by_ai_risk),
        # 在野利用数 = 窗口内全部 KEV 漏洞（与 total_cves 同口径），
        # 不再是"TOP20 高危榜里的 KEV 数"
        "kev_count": kev_total,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def report_markdown(data: dict) -> str:
    """周/月/年报 Markdown（表格驱动，对齐日报版式）。"""
    if data.get("error"):
        return "# 高频漏洞统计\n\n> %s" % data["error"]
    L = []
    L.append("# AI 安全高频漏洞%s · %s ~ %s" % (data["label"], data["start"], data["end"]))
    L.append("")
    L.append("- **统计窗口**：最近 %d 个自然日" % data["days"])
    L.append("- **生成时间**：%s" % data["generated_at"])
    L.append("- **口径**：按**漏洞发布日期**（published，源站口径，缺失回退 fetched_at）统计；"
             "「高频」落在**弱点类型（CWE）与受影响产品**两个可重复维度，"
             "CVE 编号因语料去重不参与频次排序，单独按 CVSS 列高危榜")
    L.append("- **数据源**：本地情报库 corpus.json 全量 records")
    L.append("")
    L.append("## 一、概览")
    L.append("")
    L.append("| 指标 | 数值 |")
    L.append("|---|---|")
    L.append("| 窗口内不同漏洞（CVE/GHSA） | **%d** |" % data["total_cves"])
    L.append("| 高频弱点类型（CWE） | %d 类 |" % len(data.get("top_cwe") or []))
    L.append("| 高频受影响产品 | %d 个 |" % len(data.get("top_product") or []))
    L.append("| 在野利用（KEV）漏洞 | %d |" % data["kev_count"])
    L.append("")
    air = data.get("by_ai_risk") or []
    if air:
        L.append("## 二、AI 安全风险四分类分布")
        L.append("")
        L.append("| 分类 | 情报条目数 | 占比 |")
        L.append("|---|---:|---:|")
        _tot = data.get("ai_risk_total") or 1
        for x in air:
            pct = (x["count"] / _tot * 100) if _tot else 0
            L.append("| %s | %d | %.1f%% |" % (x["category"], x["count"], pct))
        L.append("")
        L.append("> 口径：窗口内**全部情报条目**（corpus 漏洞 %d + 实时流文章/论文 %d，"
                 "按 id 去重，按发布日期开窗）。分类直接取 category 字段"
                 "（taxonomy 全项目唯一分类入口），通用七类与未分类归并展示，数据不丢。"
                 % (data.get("total_cves") or 0, data.get("live_counted") or 0))
        L.append("")
    L.append("## 三、高频弱点类型 TOP %d" % data["top_n"])
    L.append("")
    if data.get("top_cwe"):
        L.append("| # | 弱点类型 | 关联漏洞数 |")
        L.append("|---|---|---:|")
        for i, t in enumerate(data["top_cwe"], 1):
            L.append("| %d | %s | %d |" % (i, t["cwe"], t["count"]))
    else:
        L.append("窗口内无 CWE 记录。")
    L.append("")
    L.append("## 四、高频受影响产品 TOP %d" % data["top_n"])
    L.append("")
    if data.get("top_product"):
        L.append("| # | 产品 | 关联漏洞数 |")
        L.append("|---|---|---:|")
        for i, t in enumerate(data["top_product"], 1):
            L.append("| %d | %s | %d |" % (i, t["product"].replace("|", "\\|"), t["count"]))
    else:
        L.append("窗口内无产品记录。")
    L.append("")
    L.append("## 五、高危 CVE 榜 TOP %d（按 CVSS）" % data["top_n"])
    L.append("")
    if data.get("top_cve"):
        L.append("| # | 编号 | CVSS | 严重度 | KEV | 标题 |")
        L.append("|---|---|---:|---|---|---|")
        for i, t in enumerate(data["top_cve"], 1):
            L.append("| %d | [%s] | %s | %s | %s | %s |"
                     % (i, t["cve"], t.get("cvss") or "—",
                        _SEV_LABEL.get(t["severity"], t["severity"]),
                        "✓" if t["kev"] else "",
                        (t["title"] or "—").replace("|", "\\|")[:100]))
    else:
        L.append("窗口内无 CVE 记录。")
    L.append("")
    L.append("## 六、每日趋势（去重 CVE 数）")
    L.append("")
    L.append("| 日期 | 去重 CVE 数 |")
    L.append("|---|---:|")
    for p in data["trend"]:
        bar = "█" * min(40, p["count"])
        L.append("| %s | %d %s |" % (p["day"], p["count"], bar))
    L.append("")
    L.append("## 七、严重度分布")
    L.append("")
    L.append("| 严重度 | 数量 |")
    L.append("|---|---:|")
    for s in data["by_severity"]:
        L.append("| %s | %d |" % (s["label"], s["count"]))
    L.append("")
    if data["by_category"]:
        L.append("## 八、风险分类分布 TOP")
        L.append("")
        L.append("| 分类 | 数量 |")
        L.append("|---|---:|")
        for c in data["by_category"]:
            L.append("| %s | %d |" % (c["category"], c["count"]))
        L.append("")
    return "\n".join(L)
