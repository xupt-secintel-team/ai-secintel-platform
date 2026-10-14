# -*- coding: utf-8 -*-
"""
report_export.py —— 情报报告导出
==================================
根据检索结果生成结构化的安全情报报告（Markdown格式）。

API挂载：
  GET /api/export?q=xxx&format=md   导出Markdown报告
  GET /api/export?id=xxx&format=md  单条情报详情报告

报告结构：
  1. 报告概要（生成时间、查询条件、情报总量）
  2. 风险总览（严重度分布、分类分布、统计图表数据）
  3. 重点情报（在野利用、高可利用性、高危条目）
  4. 情报明细（每条：编号、评分、组件、弱点、摘要、链接）
  5. 处置建议（汇总修复路径）
  6. 数据来源与免责声明
"""

import time
from collections import Counter

# ★ 原文页推导（2026-10-12）：与检索卡片、详情面板共用同一个口径，
#   避免"报告里只有 CNA 参考链接、看不到文章/仓库/论文原文"。
try:
    from engine import canonical_url as _canonical_url
except Exception:  # pragma: no cover —— 独立调用/导入路径未就绪时安全降级
    def _canonical_url(_d):
        return ""


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}


def _md_table(headers, rows):
    """生成Markdown表格"""
    out = "| " + " | ".join(headers) + " |\n"
    out += "| " + " | ".join(["---"] * len(headers)) + " |\n"
    for r in rows:
        out += "| " + " | ".join(str(c) if c is not None else "—" for c in r) + " |\n"
    return out


def _esc_md(text):
    """Markdown文本转义（管道符等）"""
    if text is None:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def export_search_report(q, search_data, stats_data=None):
    """根据搜索结果生成完整情报报告（Markdown）"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    answer = search_data.get("answer", {})
    results = search_data.get("results", [])
    facets = search_data.get("facets", {})
    total = search_data.get("total", 0)

    lines = []

    # ===== 报告头 =====
    lines.append("# AI安全情报检索报告")
    lines.append("")
    lines.append("> 本报告由 AI-SecIntel 智能体驱动的全领域安全知识情报系统自动生成")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ===== 1. 报告概要 =====
    lines.append("## 一、报告概要")
    lines.append("")
    lines.append(_md_table(
        ["项目", "内容"],
        [
            ["报告生成时间", now],
            ["检索条件", _esc_md(q) if q else "全量浏览"],
            ["识别意图", answer.get("intent", "—")],
            ["情报命中总数", str(total)],
            ["检索耗时", str(search_data.get("elapsed_ms", "—")) + " ms"],
        ],
    ))
    lines.append("")

    # ===== 2. 风险总览 =====
    lines.append("## 二、风险总览")
    lines.append("")

    astats = answer.get("stats", {})

    # 关键指标
    lines.append("### 2.1 关键指标")
    lines.append("")
    lines.append(_md_table(
        ["指标", "数量"],
        [
            ["情报总数", astats.get("total", total)],
            ["高危/严重条目", astats.get("critical_high", 0)],
            ["在野利用条目", astats.get("exploited", 0)],
            ["存在公开验证代码", astats.get("poc", 0)],
            ["关联学术研究", astats.get("papers", 0)],
        ],
    ))
    lines.append("")

    # 严重度分布
    if facets.get("severity"):
        lines.append("### 2.2 严重度分布")
        lines.append("")
        lines.append(_md_table(
            ["严重等级", "数量", "占比"],
            [[sev, cnt, f"{round(cnt/max(total,1)*100,1)}%"]
             for sev, cnt in facets["severity"]],
        ))
        lines.append("")

    # 分类分布
    if facets.get("category"):
        lines.append("### 2.3 风险分类分布")
        lines.append("")
        lines.append(_md_table(
            ["风险分类", "数量", "占比"],
            [[_esc_md(cat), cnt, f"{round(cnt/max(total,1)*100,1)}%"]
             for cat, cnt in facets["category"][:10]],
        ))
        lines.append("")

    # 高频组件
    if facets.get("product"):
        lines.append("### 2.4 高频受影响组件 Top10")
        lines.append("")
        lines.append(_md_table(
            ["组件", "出现次数"],
            [[prod, cnt] for prod, cnt in facets["product"][:10]],
        ))
        lines.append("")

    # ===== 3. 重点情报 =====
    lines.append("## 三、重点情报")
    lines.append("")

    # 在野利用
    kev_items = [r for r in results if r.get("exploited")]
    if kev_items:
        lines.append("### 3.1 已被在野利用（最高优先级）")
        lines.append("")
        for r in kev_items[:10]:
            lines.append(
                "- **" + r["id"] + "**（" + str(r.get("cvss", {}).get("score") or "—") + "）"
                + _esc_md(r.get("title", ""))
            )
        lines.append("")

    # 高可利用性
    high_exploit = [r for r in results if (r.get("exploit_score") or 0) >= 6]
    if high_exploit:
        lines.append("### 3.2 高可利用性情报")
        lines.append("")
        for r in high_exploit[:10]:
            lines.append(
                "- **" + r["id"] + "** 可利用性评分:" + str(r.get("exploit_score"))
                + " | " + _esc_md(r.get("title", ""))
            )
        lines.append("")

    # CRITICAL/HIGH
    crit_items = [r for r in results
                  if r.get("cvss", {}).get("severity") in ("CRITICAL", "HIGH")]
    if crit_items:
        lines.append("### 3.3 高危/严重漏洞")
        lines.append("")
        lines.append(_md_table(
            ["编号", "评分", "严重度", "受影响组件", "情报标题"],
            [[r["id"], r.get("cvss", {}).get("score"),
              r.get("cvss", {}).get("severity"),
              _esc_md(", ".join(r.get("products", [])[:3])),
              _esc_md(r.get("title", "")[:60])]
             for r in crit_items[:15]],
        ))
        lines.append("")

    # ===== 4. 情报明细 =====
    lines.append("## 四、情报明细")
    lines.append("")
    lines.append(_md_table(
        ["编号", "评分", "严重度", "受影响组件", "弱点(CWE)", "可信度", "发布日期"],
        [[
            r["id"],
            r.get("cvss", {}).get("score"),
            r.get("cvss", {}).get("severity", ""),
            _esc_md(", ".join(r.get("products", [])[:3])),
            _esc_md(", ".join(w["id"] for w in r.get("cwe", [])[:2])),
            r.get("trust_label", ""),
            r.get("published", ""),
        ] for r in results[:30]],
    ))
    lines.append("")

    # 每条情报详情（精简）
    lines.append("### 情报详情摘要")
    lines.append("")
    for r in results[:15]:
        lines.append("#### " + r["id"] + " · " + _esc_md(r.get("title", "")))
        lines.append("")
        lines.append("- **严重度：** " + str(r.get("cvss", {}).get("severity", "—"))
                     + "（" + str(r.get("cvss", {}).get("score") or "—") + "）")
        if r.get("products"):
            lines.append("- **受影响组件：** " + _esc_md(", ".join(r["products"][:6])))
        if r.get("cwe"):
            lines.append("- **弱点类型：** " + _esc_md(", ".join(
                w["id"] + " " + w.get("name", "") for w in r["cwe"][:3])))
        lines.append("- **可信度：** " + str(r.get("trust_label", "—"))
                     + "（综合置信度 " + str(r.get("confidence", "—")) + "）")
        if r.get("exploit_score") is not None:
            lines.append("- **可利用性：** " + str(r.get("exploit_label"))
                         + "（评分 " + str(r.get("exploit_score")) + "/10）")
        lines.append("- **命中原因：** " + _esc_md(r.get("why", "")))
        lines.append("")

    # ===== 5. 处置建议 =====
    lines.append("## 五、处置建议")
    lines.append("")
    plan = answer.get("plan", [])
    if plan:
        lines.append("### 建议处置路径")
        lines.append("")
        for i, p in enumerate(plan, 1):
            lines.append(str(i) + ". " + _esc_md(p))
        lines.append("")

    # 汇总修复建议（从各条情报）
    all_remediations = []
    for r in results[:10]:
        # 修复建议在detail里才有，搜索结果可能没有
        pass
    if all_remediations:
        lines.append("### 具体修复措施")
        lines.append("")
        for rem in all_remediations[:15]:
            lines.append("- " + _esc_md(rem))
        lines.append("")

    # ===== 6. 数据来源与免责 =====
    lines.append("## 六、数据来源与免责声明")
    lines.append("")
    lines.append("### 数据来源")
    lines.append("")
    lines.append("本报告情报来源于：NVD（美国国家漏洞数据库）、CISA KEV（在野利用目录）、"
                 "OSV/GitHub Advisory（开源组件安全公告）、arXiv（学术论文）、"
                 "MITRE ATLAS（AI对抗知识库）、GitHub公开仓库、CSDN社区文章。")
    lines.append("")
    lines.append("### 免责声明")
    lines.append("")
    lines.append("本报告由系统自动生成，情报来源于第三方公开渠道，不对原始情报的准确性、"
                 "完整性或时效性做保证。社区来源情报可能存在错误，请以官方原始来源核验。"
                 "报告中涉及的验证代码链接仅用于安全防御研究，严禁用于非法攻击活动。")
    lines.append("")
    lines.append("---")
    lines.append("*报告生成完毕 · AI-SecIntel v2.0*")

    return "\n".join(lines)


def export_detail_report(rec):
    """单条情报的详情报告（Markdown）"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("# 安全情报详情报告：" + rec.get("id", ""))
    lines.append("")
    lines.append("> AI-SecIntel 自动生成 · " + now)
    lines.append("")
    lines.append("---")
    lines.append("")

    # 基本信息
    lines.append("## 一、基本信息")
    lines.append("")
    cvss = rec.get("cvss", {})
    lines.append(_md_table(["字段", "内容"], [
        ["情报编号", rec.get("id")],
        ["情报类型", rec.get("kind", rec.get("type", "—"))],
        ["严重等级", cvss.get("severity", "—")],
        ["CVSS评分", cvss.get("score", "—")],
        ["CVSS向量", cvss.get("vector", "—")],
        ["发布日期", (rec.get("published") or "—")[:10]],
        ["更新日期", (rec.get("modified") or "—")[:10]],
        ["数据来源", _esc_md(", ".join(rec.get("sources", [])))],
        ["可信度等级", rec.get("trust_label", "—")],
        ["交叉验证", rec.get("cross_label", "—")],
        ["综合置信度", rec.get("confidence", "—")],
    ]))
    lines.append("")

    # 标题与描述
    lines.append("## 二、情报描述")
    lines.append("")
    lines.append("**" + _esc_md(rec.get("title", "")) + "**")
    lines.append("")
    lines.append(rec.get("desc", ""))
    lines.append("")

    # 弱点
    if rec.get("cwe"):
        lines.append("## 三、弱点分析")
        lines.append("")
        for w in rec["cwe"]:
            lines.append("- **" + w["id"] + "** " + w.get("name", ""))
        lines.append("")

    # 受影响组件
    if rec.get("products"):
        lines.append("## 四、受影响组件")
        lines.append("")
        for p in rec["products"]:
            lines.append("- " + p)
        lines.append("")

    # 攻击技术
    if rec.get("atlas"):
        lines.append("## 五、攻击技术映射（MITRE ATLAS）")
        lines.append("")
        for t in rec["atlas"]:
            lines.append("### " + t["id"] + " · " + t.get("name", ""))
            lines.append("")
            if t.get("tactics"):
                lines.append("- 战术阶段：" + _esc_md(", ".join(t["tactics"])))
            lines.append("- 技术说明：" + t.get("description", "")[:400])
            lines.append("")

    # 可利用性
    lines.append("## 六、可利用性评估")
    lines.append("")
    lines.append(_md_table(["评估项", "结果"], [
        ["可利用性等级", rec.get("exploit_label", "—")],
        ["可利用性评分", str(rec.get("exploit_score", "—")) + "/10"],
        ["在野利用", "是" if rec.get("kev") else "否"],
        ["验证代码数量", str(len(rec.get("poc_links", [])))],
    ]))
    lines.append("")

    if rec.get("exploit_signals"):
        lines.append("**可利用性信号：**")
        lines.append("")
        for s in rec["exploit_signals"]:
            lines.append("- " + s["factor"] + "（+" + str(s["points"]) + "）")
        lines.append("")

    # 关联论文
    if rec.get("papers"):
        lines.append("## 七、关联学术研究")
        lines.append("")
        for p in rec["papers"]:
            lines.append("### " + _esc_md(p.get("title", "")))
            lines.append("")
            lines.append("- 作者：" + _esc_md(", ".join(p.get("authors", [])[:4])))
            lines.append("- 发布：" + str(p.get("published", "—")))
            lines.append("- 摘要：" + _esc_md(p.get("summary", "")[:300]))
            if p.get("url"):
                lines.append("- 链接：" + p["url"])
            lines.append("")

    # 缓解措施
    if rec.get("atlas_mitigations"):
        lines.append("## 八、缓解措施")
        lines.append("")
        for m in rec["atlas_mitigations"]:
            lines.append("### " + m["id"] + " · " + m.get("name", ""))
            lines.append("")
            lines.append(m.get("use", m.get("description", "")))
            lines.append("")

    # 修复建议
    if rec.get("remediation"):
        lines.append("## 九、修复建议")
        lines.append("")
        for r in rec["remediation"]:
            lines.append("- " + _esc_md(r))
        lines.append("")

    # 参考链接
    all_refs = []
    # ★ 原文页放最前（2026-10-12）：article_url / repo_url / link / pdf 这几个字段
    #   此前完全没进报告，导致文章、仓库、论文、HF 模型这四类条目导出的 Markdown
    #   里一个链接都没有。这里用与检索卡片相同的 canonical_url() 补上。
    _src = _canonical_url(rec)
    if _src:
        all_refs.append((_src, "原文"))
    for r in rec.get("refs", []):
        all_refs.append((r.get("url"), ",".join(r.get("tags", []))))
    for u in rec.get("poc_links", []):
        all_refs.append((u, "验证代码"))
    for u in rec.get("patch_links", []):
        all_refs.append((u, "补丁"))
    for u in rec.get("advisory_links", []):
        all_refs.append((u, "公告"))

    if all_refs:
        lines.append("## 十、参考链接")
        lines.append("")
        seen = set()
        for url, tag in all_refs:
            if url in seen:
                continue
            seen.add(url)
            lines.append("- [" + tag + "] " + url)
        lines.append("")

    lines.append("---")
    lines.append("*报告生成完毕 · AI-SecIntel v2.0*")

    return "\n".join(lines)


if __name__ == "__main__":
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    demo_search = {
        "total": 1,
        "elapsed_ms": 5.2,
        "answer": {
            "intent": "测试",
            "stats": {"total": 1, "critical_high": 1, "exploited": 1, "poc": 1, "papers": 0},
            "plan": ["测试路径1", "测试路径2"],
        },
        "results": [{
            "id": "CVE-2024-TEST", "title": "Test Vulnerability",
            "cvss": {"score": 9.8, "severity": "CRITICAL"},
            "products": ["test-product"],
            "cwe": [{"id": "CWE-78", "name": "Command Injection"}],
            "exploited": True, "exploit_score": 7.5, "exploit_label": "高可利用性",
            "trust_label": "官方权威", "confidence": 92,
            "published": "2024-06-01", "why": "测试命中",
        }],
        "facets": {
            "severity": [["CRITICAL", 1]],
            "category": [["test", 1]],
            "product": [["test-product", 1]],
        },
    }

    report = export_search_report("test query", demo_search)
    print(report[:800])
    print("\n... 报告总长度:", len(report), "字符")
