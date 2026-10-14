# -*- coding: utf-8 -*-
"""
credibility.py —— 情报证据可信度与多源交叉验证
================================================
解决RAG幻觉问题的后端核心模块：

1. SOURCE_TRUST    数据源权威度分级（官方/厂商/学术/社区）
2. trust_score()   计算单条情报的可信度评分(0-100)
3. cross_validate() 多源交叉验证状态（几个独立源确认）
4. exploitability() POC可利用性评分
5. enrich_record() 给情报记录批量挂载可信度字段

输出字段（供前端直接使用）：
  trust_level    权威等级：official/vendor/academic/community
  trust_score    可信度评分 0-100
  trust_label    中文标签：官方确认/厂商确认/学术支撑/社区来源
  cross_sources  交叉验证源列表
  cross_count    交叉验证源数量
  cross_verified 是否多源验证(≥2独立源)
  exploit_score  可利用性评分 0-10
  exploit_level  可利用性等级：high/medium/low
  confidence     综合置信度（可信度+可利用性+时效）
"""

# ==========================================================================
# 数据源权威度分级
# ==========================================================================
# 权重越高越权威
SOURCE_TRUST = {
    # 官方政府/标准机构
    "NVD": {"weight": 95, "level": "official", "label": "官方权威", "kind": "政府标准库"},
    "CISA KEV": {"weight": 98, "level": "official", "label": "官方权威", "kind": "政府威胁情报"},
    # 厂商/官方安全公告
    "GitHub Advisory": {"weight": 85, "level": "vendor", "label": "厂商公告", "kind": "官方供应链公告"},
    "OSV/GHSA": {"weight": 82, "level": "vendor", "label": "厂商公告", "kind": "开源漏洞库"},
    # 学术来源
    "arXiv": {"weight": 70, "level": "academic", "label": "学术支撑", "kind": "同行评议前预印本"},
    # 社区来源
    "GitHub": {"weight": 55, "level": "community", "label": "社区来源", "kind": "公开仓库"},
    "CSDN": {"weight": 40, "level": "community", "label": "社区经验", "kind": "社区技术文章"},
    "MITRE ATLAS": {"weight": 88, "level": "vendor", "label": "权威知识库", "kind": "MITRE维护"},
}

# 交叉验证时视为"独立来源"的分组（同组内不算独立交叉验证）
SOURCE_GROUP = {
    "NVD": "nvd",
    "CISA KEV": "cisa",
    "GitHub Advisory": "ghsa",
    "OSV/GHSA": "ghsa",      # GHSA和OSV/GHSA同源，不算独立
    "arXiv": "arxiv",
    "GitHub": "github",
    "CSDN": "csdn",
    "MITRE ATLAS": "atlas",
}


def trust_score(sources):
    """根据数据源列表计算可信度评分（取最高权威源为基准，其他源小幅加成）"""
    if not sources:
        return 30, "community", "未知来源"

    scored = []
    for s in sources:
        info = SOURCE_TRUST.get(s)
        if info:
            scored.append((s, info["weight"], info["level"], info["label"]))

    if not scored:
        return 35, "community", "其他来源"

    # 按权重排序
    scored.sort(key=lambda x: -x[1])
    top_name, top_weight, top_level, top_label = scored[0]

    # 多源加成：每增加一个不同组的独立源 +3分，上限+12
    groups = {SOURCE_GROUP.get(s, s) for s, *_ in scored}
    bonus = min((len(groups) - 1) * 3, 12)

    score = min(top_weight + bonus, 99)
    return score, top_level, top_label


def cross_validate(sources, has_kev=False, has_poc=False, has_papers=False):
    """多源交叉验证：返回独立验证源列表和验证状态"""
    independent = {}

    for s in sources:
        grp = SOURCE_GROUP.get(s, s)
        info = SOURCE_TRUST.get(s, {"label": s})
        if grp not in independent:
            independent[grp] = {"source": s, "label": info.get("label", s), "group": grp}

    # KEV是独立强信号
    if has_kev and "cisa" not in independent:
        independent["cisa"] = {"source": "CISA KEV", "label": "官方权威", "group": "cisa"}

    cross_list = list(independent.values())
    return {
        "cross_sources": cross_list,
        "cross_count": len(cross_list),
        "cross_verified": len(cross_list) >= 2,
        "cross_level": (
            "triple" if len(cross_list) >= 3
            else "double" if len(cross_list) >= 2
            else "single"
        ),
        "cross_label": (
            "三源交叉确认" if len(cross_list) >= 3
            else "双源交叉验证" if len(cross_list) >= 2
            else "单源情报(待验证)"
        ),
    }


# ==========================================================================
# POC可利用性评分
# ==========================================================================
def exploitability_score(rec):
    """
    POC可利用性评分(0-10)：
      CISA KEV在野利用        +3.5
      Exploit-DB公开exp       +2.5
      GitHub PoC仓库          +2.0
      有补丁对比链接           +0.5
      社区writeup文章         +1.0
      CVSS可利用性评分         +0.5*(CVSS exploitability/4)
    """
    score = 0.0
    signals = []

    # 在野利用（最强信号）
    if rec.get("kev"):
        score += 3.5
        signals.append({"factor": "CISA KEV在野利用", "points": 3.5})

    poc_urls = rec.get("poc_links", [])
    refs = rec.get("refs", [])
    all_urls = [r["url"] if isinstance(r, dict) else r for r in refs] + poc_urls

    # Exploit-DB
    if any("exploit-db" in u.lower() or "exploit_db" in u.lower() for u in all_urls):
        score += 2.5
        signals.append({"factor": "Exploit-DB公开利用代码", "points": 2.5})

    # GitHub PoC
    gh_poc = [u for u in all_urls if "github.com" in u.lower() or "gist.github" in u.lower()]
    if gh_poc:
        score += 2.0
        signals.append({"factor": f"GitHub PoC仓库×{len(gh_poc)}", "points": 2.0})

    # 补丁链接
    if rec.get("patch_links"):
        score += 0.5
        signals.append({"factor": "补丁/提交可对比", "points": 0.5})

    # 社区writeup（通过tags或文章关联检测）
    tags = rec.get("tags", [])
    if any("writeup" in str(t).lower() or "复现" in str(t) for t in tags):
        score += 1.0
        signals.append({"factor": "公开复现文章", "points": 1.0})

    # CVSS exploitability子分
    cvss_exploit = (rec.get("cvss", {}) or {}).get("exploitability")
    if cvss_exploit:
        add = round(0.5 * min(float(cvss_exploit) / 4.0, 1.0), 2)
        score += add
        if add > 0:
            signals.append({"factor": f"CVSS可利用性({cvss_exploit})", "points": add})

    score = min(round(score, 2), 10.0)

    if score >= 6.0:
        level, label = "high", "高可利用性"
    elif score >= 3.0:
        level, label = "medium", "中等可利用性"
    elif score > 0:
        level, label = "low", "低可利用性"
    else:
        level, label = "none", "无公开利用"

    return {
        "exploit_score": score,
        "exploit_level": level,
        "exploit_label": label,
        "exploit_signals": signals,
    }


# ==========================================================================
# 时效衰减因子
# ==========================================================================
def freshness_factor(published, modified=None):
    """情报时效性因子（0.7-1.0），越新越可信"""
    from datetime import datetime, timezone
    date_str = modified or published
    if not date_str:
        return 0.85
    try:
        ds = date_str[:19].replace("Z", "")
        dt = datetime.fromisoformat(ds).replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - dt).days
        if age_days <= 90:
            return 1.0
        elif age_days <= 365:
            return 0.95
        elif age_days <= 730:
            return 0.88
        elif age_days <= 1825:
            return 0.8
        return 0.7
    except Exception:
        return 0.85


# ==========================================================================
# 综合置信度
# ==========================================================================
def compute_confidence(trust_sc, cross_count, exploit_sc, freshness):
    """综合置信度评分(0-100)"""
    # 可信度50% + 交叉验证20% + 可利用性15% + 时效15%
    cross_component = min(cross_count / 3.0, 1.0) * 100
    exploit_component = (exploit_sc / 10.0) * 100
    conf = (
        trust_sc * 0.50
        + cross_component * 0.20
        + exploit_component * 0.15
        + freshness * 100 * 0.15
    )
    return round(min(conf, 99), 1)


# ==========================================================================
# 主入口：给一条情报记录挂载全部可信度字段
# ==========================================================================
def enrich_record(rec):
    """给情报记录添加可信度/交叉验证/可利用性/置信度字段（原地修改）"""
    sources = rec.get("sources", [])
    has_kev = bool(rec.get("kev"))
    has_poc = bool(rec.get("poc_links"))
    has_papers = bool(rec.get("papers"))

    # 可信度
    t_score, t_level, t_label = trust_score(sources)
    rec["trust_score"] = t_score
    rec["trust_level"] = t_level
    rec["trust_label"] = t_label

    # 多源交叉验证
    cross = cross_validate(sources, has_kev, has_poc, has_papers)
    rec.update(cross)

    # POC可利用性
    exploit = exploitability_score(rec)
    rec.update(exploit)

    # 时效性
    fresh = freshness_factor(rec.get("published", ""), rec.get("modified"))
    rec["freshness"] = fresh

    # 综合置信度
    rec["confidence"] = compute_confidence(
        t_score, cross["cross_count"], exploit["exploit_score"], fresh
    )

    return rec


def enrich_all(records):
    """批量富化"""
    for r in records:
        enrich_record(r)
    return records


# ==========================================================================
# 可信度统计（供dashboard）
# ==========================================================================
def credibility_stats(records):
    """可信度分布统计"""
    from collections import Counter
    trust_dist = Counter()
    cross_dist = Counter()
    exploit_dist = Counter()
    conf_buckets = Counter()

    for r in records:
        if "trust_level" not in r:
            enrich_record(r)
        trust_dist[r["trust_label"]] += 1
        cross_dist[r["cross_label"]] += 1
        exploit_dist[r["exploit_label"]] += 1

        c = r["confidence"]
        if c >= 85:
            conf_buckets["高置信(≥85)"] += 1
        elif c >= 65:
            conf_buckets["中置信(65-84)"] += 1
        elif c >= 45:
            conf_buckets["低置信(45-64)"] += 1
        else:
            conf_buckets["待验证(<45)"] += 1

    confidences = [r["confidence"] for r in records]
    return {
        "trust_distribution": trust_dist.most_common(),
        "cross_distribution": cross_dist.most_common(),
        "exploit_distribution": exploit_dist.most_common(),
        "confidence_distribution": conf_buckets.most_common(),
        "avg_confidence": round(sum(confidences) / len(confidences), 1) if confidences else 0,
        "high_confidence_count": sum(1 for c in confidences if c >= 80),
        "cross_verified_count": sum(1 for r in records if r.get("cross_verified")),
    }


# ==========================================================================
# 判定依据解释（按需调用 —— 只在详情接口里对单条记录算，不落盘、不占内存）
# ==========================================================================
# 背景（2026-10-12）：详情面板此前只显示「学术支撑」「双源交叉验证」这类标签，
# 但用户看不出**是什么在支撑它** —— 学术支撑背后是哪几篇论文？双源是哪两源、
# 为什么算两源？这里把每一步判定的输入都摊开，供前端点击展开。
CONF_WEIGHTS = (
    ("trust", "来源权威度", 0.50),
    ("cross", "多源交叉验证", 0.20),
    ("exploit", "POC 可利用性", 0.15),
    ("fresh", "情报时效性", 0.15),
)

# 同源体系的分组说明：交叉验证时同组只算一个独立源，这里解释"为什么"
GROUP_NOTE = {
    "nvd": "美国 NIST 国家漏洞库，政府标准库",
    "cisa": "CISA 已知被利用漏洞目录（KEV），政府威胁情报",
    "ghsa": "GitHub Advisory 与 OSV/GHSA 属同一开源供应链公告体系，合并记为 1 个独立源",
    "arxiv": "arXiv 学术预印本（同行评议前），与厂商/官方公告相互独立",
    "github": "GitHub 公开仓库，社区贡献来源",
    "csdn": "CSDN 社区技术文章，社区经验来源",
    "atlas": "MITRE ATLAS 攻击技术知识库，由 MITRE 维护",
}

TRUST_RULE = (
    "取本条全部来源中权威度最高者作为等级基准："
    "CISA KEV=98 · NVD=95(官方权威) · MITRE ATLAS=88 · GitHub Advisory=85 · OSV/GHSA=82 · "
    "arXiv=70(学术支撑) · GitHub=55 · CSDN=40。"
    "再按「独立来源组数」每多一组 +3 分，上限 +12。"
)

CROSS_RULE = (
    "先按同源体系把来源归并，再数独立源个数：GHSA 与 OSV/GHSA 属同一体系只算 1 个源；"
    "来源被 CISA KEV 标记为在野利用时，即使语料里没写 KEV 也补算 1 个独立源。"
)

EXPLOIT_RULE = (
    "CISA KEV 在野利用 +3.5 · Exploit-DB 公开利用代码 +2.5 · GitHub PoC 仓库 +2.0 · "
    "公开复现文章 +1.0 · 补丁可对比 +0.5 · CVSS 可利用性子分 +0~0.5（按 exploitability/4 折算）；"
    "合计 ≥6 判为高可利用性、≥3 为中、>0 为低、=0 为无公开利用。"
)


def _trust_explain(rec):
    sources = rec.get("sources") or []
    rows, groups = [], set()
    for src in sources:
        info = SOURCE_TRUST.get(src)
        if not info:
            rows.append({"source": src, "weight": None, "level": "unknown",
                         "label": "未收录来源",
                         "kind": "权威度表里没有这一源，按最低权重参与计算"})
            continue
        rows.append({"source": src, "weight": info["weight"], "level": info["level"],
                     "label": info["label"], "kind": info["kind"]})
        groups.add(SOURCE_GROUP.get(src, src))
    rows.sort(key=lambda x: -(x["weight"] or 0))

    papers = []
    for p in (rec.get("papers") or [])[:6]:
        if not isinstance(p, dict):
            continue
        papers.append({
            "title": p.get("title", ""),
            "url": p.get("url", ""),
            "terms": p.get("match_terms") or [],
            "score": p.get("match_score"),
            "published": (p.get("published") or "")[:10],
        })

    return {
        "rule": TRUST_RULE,
        "label": rec.get("trust_label", ""),
        "score": rec.get("trust_score"),
        "groups": len(groups),
        "bonus": min(max(len(groups) - 1, 0) * 3, 12),
        "rows": rows,
        "papers": papers,
        "papers_note": ("以下论文是本系统按「组件 / 弱点类型 / 攻击面」与该项自动关联的结果，"
                        "构成「学术支撑」标签的条目级证据。") if papers else
                       ("本条没有条目级关联论文：若等级显示为「学术支撑」，"
                        "它来自数据源自身的学术属性（arXiv 预印本），而非关联推理。"),
    }


def _cross_explain(rec):
    groups = {}
    for s in (rec.get("cross_sources") or []):
        if not isinstance(s, dict):
            continue
        g = s.get("group") or s.get("source") or "?"
        groups.setdefault(g, []).append(s.get("source") or g)
    return {
        "rule": CROSS_RULE,
        "threshold": "独立来源 ≥2 才算交叉验证，≥3 记作三源确认；只有 1 个源时标注为「单源情报(待验证)」。",
        "count": rec.get("cross_count", len(groups)),
        "label": rec.get("cross_label", ""),
        "groups": [{"group": g, "sources": ss, "note": GROUP_NOTE.get(g, "")}
                   for g, ss in groups.items()],
    }


def _confidence_explain(rec):
    fresh = rec.get("freshness") or 0.0
    cross_raw = rec.get("cross_count") or 0
    exploit_raw = rec.get("exploit_score") or 0.0
    values = {
        "trust": rec.get("trust_score") or 0,
        "cross": round(min(cross_raw / 3.0, 1.0) * 100, 1),
        "exploit": round(exploit_raw / 10.0 * 100, 1),
        "fresh": round(fresh * 100, 1),
    }
    rows = []
    for key, name, w in CONF_WEIGHTS:
        v = values[key]
        rows.append({"key": key, "name": name, "value": v, "weight": w,
                     "contribution": round(v * w, 1)})
    return {
        "formula": "综合置信度 = 来源权威度×50% + 多源交叉验证×20% + POC 可利用性×15% + 情报时效性×15%",
        "cross_raw": cross_raw,
        "exploit_raw": exploit_raw,
        "fresh": round(fresh, 2),
        "rows": rows,
        "total": rec.get("confidence"),
    }


def explain_record(rec):
    """一条情报的「判定依据」明细（可信度 / 交叉验证 / 置信度 / 可利用性）"""
    if not isinstance(rec, dict):
        return {}
    return {
        "trust": _trust_explain(rec),
        "cross": _cross_explain(rec),
        "confidence": _confidence_explain(rec),
        "exploit": {
            "rule": EXPLOIT_RULE,
            "score": rec.get("exploit_score", 0),
            "level": rec.get("exploit_label", ""),
            "signals": rec.get("exploit_signals") or [],
        },
    }


if __name__ == "__main__":
    # 自测
    test = {
        "id": "CVE-2024-TEST",
        "sources": ["NVD", "CISA KEV", "OSV/GHSA"],
        "kev": {"exploited": True},
        "poc_links": ["https://github.com/test/poc"],
        "patch_links": ["https://github.com/test/commit/abc"],
        "refs": [{"url": "https://www.exploit-db.com/exploits/12345"}],
        "cvss": {"score": 9.8, "severity": "CRITICAL", "exploitability": 3.9},
        "published": "2024-06-01T00:00:00",
        "tags": [],
    }
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    enrich_record(test)
    for k in ["trust_score", "trust_label", "cross_label", "cross_count",
              "exploit_score", "exploit_label", "confidence", "freshness"]:
        print(f"  {k:16s} {test[k]}")
    print("  signals:", [(s['factor'], s['points']) for s in test['exploit_signals']])
