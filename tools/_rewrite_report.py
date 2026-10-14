# -*- coding: utf-8 -*-
"""按评审给定的六节模板重写 report_to_markdown。

新结构：
  一、风险概览（统计表 + TOP10 资产）
  二、漏洞分布分析（按严重度/组件/业务/位置/处置状态）
  三、处置工单清单（按 CVE 聚合：责任人 + 期限 + SLA + 优先级 + 命中资产）
  四、逐条 CVE 修复方案（受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚）
  五、验收标准
  六、数据覆盖率与已知漏报说明
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "modules", "m2_enrich", "backend", "cmdb_scan.py")
NEW = '''def report_to_markdown(rep: dict) -> str:
    """导出成可直接交付的 Markdown 报告（六节模板，2026-10-05 第 4 版）。

    模板对应评审意见：
      一、风险概览          → 统计表 + TOP10 高风险资产（含机房位置）
      二、漏洞分布分析      → 严重度 / 组件 / 业务 / 机房 / 处置状态 / 监管
      三、处置工单清单      → 按漏洞编号聚合，每条含责任人 / 期限 / SLA / 优先级 / 命中资产
      四、逐条 CVE 修复方案 → 受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚
      五、验收标准          → 可执行、可留痕的验证动作
      六、覆盖率与已知漏报  → 编号覆盖率 / 位置覆盖率 / 不可定位记录 / 判定口径

    台账模式（data_source 含「漏洞台账」）走新模板；资产 CPE 模式保留旧结构。
    """
    r = rep.get("risk", {})
    s = r.get("summary", {})
    ds = rep.get("data_source") or ""
    is_ledger = "漏洞台账" in ds
    sc = rep.get("scale") or {}
    prio = rep.get("priority") or []
    L: List[str] = []
    A = L.append

    # ================= 报告头 =================
    A("# 公司 CMDB 资产风险分析报告")
    A("")
    A("- **报告编号**：%s" % rep.get("id"))
    A("- **数据来源**：%s" % rep.get("source_name"))
    A("- **生成时间**：%s" % rep.get("created_at"))
    A("- **数据口径**：%s" % ds)
    A("- **判定依据**：%s" % rep.get("basis"))
    A("- **情报库规模**：%s 条文档参与交叉验证" % s.get("scanned_docs"))
    if s.get("ledger_rows"):
        A("- **台账规模**：%s 条漏洞记录（CMDB vulnerability 表）" % s.get("ledger_rows"))
    A("")

    if not is_ledger:
        return _report_markdown_asset_mode(rep, L)

    # ================= 一、风险概览 =================
    A("## 一、风险概览")
    A("")
    A("| 指标 | 数值 | 说明 |")
    A("| --- | ---: | --- |")
    A("| 漏洞记录总数 | %s | CMDB vulnerability 台账全量 |" % s.get("ledger_rows"))
    A("| 去重后漏洞数 | %s | 按「漏洞编号 + 组件」聚合 |" % s.get("cve_hits"))
    A("| 涉及资产数 | %s | CI_ID 去重（已剔除不可定位记录） |" % s.get("hosts"))
    A("| 涉及组件数 | %s | 受影响组件去重 |" % s.get("products"))
    A("| 严重（CRITICAL） | %s | CVSS ≥ 9.0 |" % s.get("critical"))
    A("| 高危（HIGH） | %s | 7.0 ≤ CVSS < 9.0 |" % s.get("high"))
    A("| 中危（MEDIUM） | %s | 4.0 ≤ CVSS < 7.0 |" % s.get("medium"))
    A("| 低危（LOW） | %s | 0.1 ≤ CVSS < 4.0 |" % s.get("low"))
    A("| 信息（INFO） | %s | CVSS = 0（台账标为信息级） |" % s.get("info"))
    A("| 已在野利用（KEV） | %s | CISA KEV 确认 exploited |" % s.get("exploited"))
    A("| 互联网暴露记录 | %s | IS_INTERNET_FACING = Y |" % s.get("rows_internet"))
    A("| 监管合规资产 | %s | IS_REGULATORY = Y |" % s.get("rows_regulatory"))
    A("| 已闭环记录 | %s | FIX_STATUS = 已修复/已闭环 |" % s.get("rows_closed"))
    A("")
    sb = s.get("status_breakdown") or {}
    if sb:
        A("**处置状态分布**：" + "、".join("%s %s 条" % (k, v) for k, v in sb.items() if v))
        A("")
    if s.get("kev_ids"):
        A("> ⚠️ **CISA KEV 在野利用清单（%d 条）**：%s" % (
            s.get("exploited"), "、".join(s["kev_ids"])))
        A("")

    hosts = r.get("hosts") or []
    if hosts:
        A("### TOP 10 高风险资产")
        A("")
        A("| # | 资产标识（CI_ID） | 主机名 | IP | 机房位置 | 业务系统 | 责任人 | 最高等级 | 风险分 | 命中 |")
        A("| ---: | --- | --- | --- | --- | --- | --- | --- | ---: | ---: |")
        for i, h in enumerate(hosts[:10], 1):
            A("| %d | %s | %s | %s | %s | %s | %s | %s | %.1f | %s |" % (
                i, h.get("asset_id") or h.get("name") or "—",
                h.get("ci_name") or "—", h.get("ci_ip") or "—",
                h.get("location") or "未登记", h.get("app") or "—",
                h.get("owner") or "—", h.get("max_sev") or "—",
                float(h.get("_score") or 0.0), h.get("vuln_count") or 0))
        A("")
    A("> **清单口径**：本次共分析 %s 条 CI 记录，其中有风险资产 %s 个、组件 %s 个；"
      "第三节展示 TOP %s 条处置工单，资产明细与组件明细在报告 JSON 中完整保留。"
      "零命中（无已知风险）条目已剔除。" % (
          sc.get("ci_total"), s.get("hosts"), s.get("products"), len(prio)))
    A("")

    # ================= 二、漏洞分布分析 =================
    A("## 二、漏洞分布分析")
    A("")
    A("### 2.1 按严重度分布")
    A("")
    A("```")
    A("严重 CRITICAL  %5d  %s" % (s.get("critical") or 0, _bar(s.get("critical"), s.get("cve_hits"))))
    A("高危 HIGH      %5d  %s" % (s.get("high") or 0, _bar(s.get("high"), s.get("cve_hits"))))
    A("中危 MEDIUM    %5d  %s" % (s.get("medium") or 0, _bar(s.get("medium"), s.get("cve_hits"))))
    A("低危 LOW       %5d  %s" % (s.get("low") or 0, _bar(s.get("low"), s.get("cve_hits"))))
    A("信息 INFO      %5d  %s" % (s.get("info") or 0, _bar(s.get("info"), s.get("cve_hits"))))
    A("```")
    A("")
    prods = r.get("products") or []
    if prods:
        A("### 2.2 按组件分布（TOP 15）")
        A("")
        A("| 组件 | 命中资产数 | 漏洞记录数 | 最高等级 | 最高 CVSS |")
        A("| --- | ---: | ---: | --- | ---: |")
        for c in prods[:15]:
            A("| %s | %s | %s | %s | %.1f |" % (
                c.get("name"), c.get("asset_count", 0), c.get("vuln_count", 0),
                c.get("severity") or "—", float(c.get("max_cvss") or 0.0)))
        A("")
    # 业务线分布
    bg = _count_by(prio, "apps", lambda p: p.get("apps") or [])
    if bg:
        A("### 2.3 按业务系统分布（TOP 10）")
        A("")
        A("| 业务系统 | 涉及漏洞数 | 其中严重/高危 |")
        A("| --- | ---: | ---: |")
        for name, cnt, ch in bg[:10]:
            A("| %s | %d | %d |" % (name, cnt, ch))
        A("")
    # 机房分布
    loc = _count_locations(hosts)
    if loc:
        A("### 2.4 按机房分布（TOP 10）")
        A("")
        A("| 机房位置 | 涉及资产数 | 严重/高危资产 |")
        A("| --- | ---: | ---: |")
        for name, cnt, ch in loc[:10]:
            A("| %s | %d | %d |" % (name, cnt, ch))
        A("")
    A("### 2.5 按处置状态分布")
    A("")
    A("| 处置状态 | 记录数 | 占比 |")
    A("| --- | ---: | ---: |")
    tot = sum(v for v in (sb or {}).values()) or 1
    for k, v in (sb or {}).items():
        A("| %s | %d | %.1f%% |" % (k, v, v * 100.0 / tot))
    A("")

    # ================= 三、处置工单清单 =================
    A("## 三、处置工单清单（按漏洞编号聚合，共 %d 条）" % len(prio))
    A("")
    if not prio:
        A("未发现需处置的风险。")
        A("")
    A("| # | 优先级 | 漏洞编号 | 组件 | 受影响版本→修复版本 | 等级 | CVSS | 风险分 | 命中资产 | 公网 | 监管 | 责任人 | 计划期限 | SLA | 建议截止 | 状态 | 官方链接 |")
    A("| ---: | --- | --- | --- | --- | --- | ---: | ---: | ---: | :-: | :-: | --- | --- | --- | --- | --- | --- |")
    for i, p in enumerate(prio, 1):
        A("| %d | %s | %s | %s | %s | %s | %s | %.1f | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            i, p.get("priority_label") or "—",
            p.get("cve") or "（源数据未填编号）",
            p.get("component") or "—",
            _ver_arrow(p.get("comp_versions"), p.get("fix_versions")),
            p.get("severity") or "—",
            ("%.1f" % p["cvss"]) if p.get("cvss") else "—",
            float(p.get("score") or 0.0),
            p.get("asset_count") or 0,
            "是" if (p.get("internet_count") or 0) else "—",
            "是" if (p.get("regulatory_count") or 0) else "—",
            "、".join(p.get("owners") or []) or "—",
            "、".join(p.get("plan_fix") or []) or "—",
            p.get("sla_days") or "—",
            p.get("sla_due") or "—",
            "、".join(p.get("fix_statuses") or []) or "—",
            _link(p.get("official_url") or p.get("nvd_url"))))
    A("")
    A("> 风险分 = %s。已在野利用（KEV）×%.1f、互联网暴露 ×%.1f、核心/生产资产 ×%.1f、"
      "监管合规资产 ×%.1f；CVSS 缺失时按严重度折算。" % (
          "CVSS", FACTOR_KEV, FACTOR_INTERNET, FACTOR_IMPORTANCE, FACTOR_REGULATORY))
    A("")

    # 每条工单的命中资产明细（只列前 10 条工单，避免报告膨胀到无法阅读）
    A("### 3.1 重点工单命中资产明细（TOP 10 工单）")
    A("")
    for i, p in enumerate(prio[:10], 1):
        A("#### 工单 %d：%s —— %s %s（%s）" % (
            i, p.get("cve") or "（源数据未填编号）", p.get("severity"),
            ("CVSS %.1f" % p["cvss"]) if p.get("cvss") else "",
            p.get("component") or "未标注组件"))
        A("")
        A("- **优先级 / SLA**：%s，建议 %s 内完成（截止 %s）" % (
            p.get("priority_label") or "—", p.get("sla_days") or "—",
            p.get("sla_due") or "—"))
        A("- **风险分**：%.1f（%s）" % (
            float(p.get("score") or 0.0), p.get("factors") or "—"))
        A("- **责任人**：%s（%d 名）" % (
            "、".join(p.get("owners") or []) or "台账未填", p.get("owner_count") or 0))
        A("- **计划修复期限**：%s" % ("、".join(p.get("plan_fix") or []) or "台账未填"))
        A("- **处置状态**：%s（已闭环 %d / 共 %d 条记录）" % (
            "、".join(p.get("fix_statuses") or []) or "台账未填",
            p.get("closed_count") or 0, p.get("asset_count") or 0))
        if p.get("vtype"):
            A("- **漏洞类型**：%s%s" % (
                p.get("vtype"),
                ("（%s）" % "、".join(p.get("vnames") or [])) if p.get("vnames") else ""))
        if p.get("cwe"):
            A("- **CWE 弱点**：%s" % "、".join(p["cwe"]))
        if p.get("exploited"):
            A("- **在野利用**：CISA KEV 已确认（收录 %s%s）" % (
                p.get("kev_added") or "日期未知",
                ("，整改期限 %s" % p["kev_due"]) if p.get("kev_due") else ""))
        if p.get("vuln_ids"):
            A("- **台账记录号**（内部）：%s" % "、".join(p["vuln_ids"]))
        top = p.get("top_assets") or []
        if top:
            A("")
            A("| 资产标识 | 主机名 | IP | 机房位置 | 业务系统 | 受影响版本 | 责任人 | 期限 | 状态 | 风险分 |")
            A("| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: |")
            for a in top:
                A("| %s | %s | %s | %s | %s | %s → %s | %s | %s | %s | %.1f |" % (
                    a.get("asset_id") or "—", a.get("ci_name") or "—",
                    a.get("ci_ip") or "—", a.get("location") or "未登记",
                    a.get("app") or "—",
                    a.get("component_version") or "—", a.get("fix_version") or "—",
                    a.get("owner") or "—", a.get("plan_fix") or "—",
                    a.get("fix_status") or "—", float(a.get("score") or 0.0)))
            if (p.get("asset_count") or 0) > len(top):
                A("")
                A("> 该漏洞共命中 %d 台资产，此处列风险分最高的 %d 台；"
                  "完整清单见报告 JSON。" % (p.get("asset_count"), len(top)))
        A("")

    # ================= 四、逐条 CVE 修复方案 =================
    A("## 四、逐条漏洞修复方案（TOP 10）")
    A("")
    A("每条给六项：受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚方案。")
    A("")
    for i, p in enumerate(prio[:10], 1):
        fp = p.get("fix_plan") or {}
        A("### 4.%d %s —— %s" % (i, p.get("cve") or "（源数据未填编号）",
                                  p.get("component") or "未标注组件"))
        A("")
        A("| 项 | 内容 |")
        A("| --- | --- |")
        A("| 受影响组件 | %s |" % (fp.get("component") or p.get("component") or "—"))
        A("| 当前版本 | %s |" % (fp.get("affected_version") or "台账未填"))
        A("| 修复版本 | %s |" % (fp.get("fix_version") or "台账未填，需查厂商公告"))
        A("| 受影响版本区间（CPE） | %s |" % (
            "；".join(fp.get("affected_cve_range") or []) or "台账无 CPE 区间（以厂商公告为准）"))
        A("| 官方漏洞公告 | %s |" % (_link(fp.get("official_advisory")) or "—"))
        A("| 官方补丁下载 | %s |" % (_link(fp.get("vendor_patch_page")) or "—"))
        A("| 台账补丁编号 | %s |" % ("、".join(fp.get("patch_ids") or []) or "—"))
        A("| 发现工具 | %s |" % ("、".join(fp.get("discover_tool") or []) or "—"))
        cw = fp.get("change_window") or {}
        A("| 变更窗口 | %s |" % (cw.get("window") or "—"))
        A("| 变更前置条件 | %s |" % (cw.get("pre") or "—"))
        A("| 回滚方案 | %s |" % (fp.get("rollback") or "—"))
        A("")
        A("**临时缓解措施（不等补丁）**")
        A("")
        for m in (fp.get("mitigations") or []):
            A("- **%s**：%s" % (m.get("item"), m.get("detail")))
            if m.get("code"):
                A("")
                A("  ```bash")
                for ln in str(m["code"]).splitlines():
                    A("  " + ln)
                A("  ```")
            A("")
        A("")

    # ================= 五、验收标准 =================
    A("## 五、验收标准")
    A("")
    A("每条工单完成后需同时满足以下四项，缺一不视为闭环：")
    A("")
    A("1. **版本核对**：目标资产上 `%s --version` 输出等于修复版本（以厂商公告为准，"
      "不采信台账未核实的版本号）。" % (prio[0].get("component") if prio else "目标组件"))
    A("2. **复扫无命中**：用原发现工具（见工单的「发现工具」行）对该 CI 重扫，"
      "确认该漏洞不再命中，扫描报告归档。")
    A("3. **台账闭环**：在 CMDB 的 vulnerability 台账里把对应记录的 FIX_STATUS 改为"
      "「已修复」，回填 ACTUAL_FIX_DATE 与 FIX_DURATION_DAYS。")
    A("4. **业务确认**：由 %s 责任人签字确认业务功能正常，无新增告警。" % (
        "、".join(prio[0].get("owners") or ["台账责任人"]) if prio else "台账责任人"))
    A("")
    A("**验收抽样清单**（取风险分最高的 10 台资产，运维可逐台核对）")
    A("")
    A("| 资产标识 | 主机名 | IP | 机房位置 | 责任人 | 最高等级 | 未闭环漏洞数 | 需验证 |")
    A("| --- | --- | --- | --- | --- | --- | ---: | --- |")
    for h in hosts[:10]:
        A("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            h.get("asset_id") or "—", h.get("ci_name") or "—", h.get("ci_ip") or "—",
            h.get("location") or "未登记", h.get("owner") or "—",
            h.get("max_sev") or "—", h.get("open_vulns", h.get("vuln_count")),
            "是" if (h.get("open_vulns", 0) or 0) > 0 else "否"))
    A("")

    # ================= 六、覆盖率与已知漏报 =================
    A("## 六、数据覆盖率与已知漏报说明")
    A("")
    idc = s.get("id_coverage") or {}
    if idc:
        A("### 6.1 漏洞编号覆盖率")
        A("")
        A("| 编号类型 | 数量 | 占比 | 可核查入口 |")
        A("| --- | ---: | ---: | --- |")
        tot = idc.get("total") or 1
        A("| CVE（可查 NVD + CPE 区间 + KEV） | %d | %.1f%% | https://nvd.nist.gov/vuln/detail/ |" % (
            idc.get("with_cve", 0), idc.get("with_cve", 0) * 100.0 / tot))
        A("| CNVD（国家信息安全漏洞库） | %d | %.1f%% | https://www.cnvd.org.cn/flaw/show/ |" % (
            idc.get("with_cnvd", 0), idc.get("with_cnvd", 0) * 100.0 / tot))
        A("| CNNVD（国家信息安全漏洞共享平台） | %d | %.1f%% | https://www.cnnvd.org.cn/ |" % (
            idc.get("with_cnnvd", 0), idc.get("with_cnnvd", 0) * 100.0 / tot))
        A("| **源数据未填编号** | %d | %.1f%% | 无（无法生成官方链接） |" % (
            idc.get("no_id", 0), idc.get("no_id", 0) * 100.0 / tot))
        A("")
        A("> 非 CVE 编号（CNVD / CNNVD）无法在 NVD 情报库检索 CPE 版本区间，"
          "因此这部分漏洞的「受影响版本区间」需以厂商安全公告为准。"
          "源数据未填编号的 %d 条已在第三节标注，不做编号推测。" % idc.get("no_id", 0))
        A("")
    A("### 6.2 已知漏报与数据缺陷")
    A("")
    if s.get("non_asset_rows"):
        A("- **不可定位记录 %d 条**：其 CI_ID 指向软件包 / 补丁 / 工单的记录主键"
          "（SW- / PATCH- / ALERT- 前缀），且 CI_IP 列填的是端口号而非 IP，"
          "在 CMDB 里查不到对应机器，无法派单。它们仍计入漏洞总数，"
          "但不进资产风险排序。" % s.get("non_asset_rows"))
    if s.get("loc_resolved") is not None:
        A("- **位置覆盖率**：%d / %d 台资产可回溯到机房位置（%.1f%%）；"
          "其余为中间件/容器等经宿主二级解析仍无登记的记录，报告中标为「未登记」，"
          "不做推测。" % (s.get("loc_resolved") or 0, s.get("hosts") or 0,
                          (s.get("loc_resolved") or 0) * 100.0 / max(1, s.get("hosts") or 0)))
    A("- **严重度口径**：按 CVSS v3.1 官方区间由分值推导"
      "（9.0+ CRITICAL / 7.0+ HIGH / 4.0+ MEDIUM / 0.1+ LOW），"
      "不使用台账 SEVERITY 列的人工标签，避免出现「CVSS 10.0 却标 HIGH」的矛盾。"
      "CVSS 分值为 0 的记录（%s 条）按台账标签归入 INFO。" % (s.get("info") or 0))
    A("- **组件版本口径**：台账的 COMPONENT_VERSION / FIX_VERSION 为 CMDB 登记值，"
      "报告原样引用并逐条标注「→ 修复版本」；未做 CPE 区间二次匹配，"
      "修复前须以厂商公告核对（第四节已列出官方公告入口）。")
    A("- **不覆盖的范围**：本报告基于 CMDB 漏洞台账的**已登记**漏洞。"
      "未在台账中登记的组件漏洞（漏扫、漏登记）不在本报告范围内，"
      "需通过第四节的复扫动作持续补全。")
    A("- **数据处理**：全部解析与匹配在本机完成，CMDB 资产数据不外发、不联网。")
    A("")
    return "\\n".join(L)


def _bar(n, total) -> str:
    """文本条形图（报告在 Markdown 预览里看）。"""
    n = int(n or 0)
    total = int(total or 0) or 1
    width = max(1, int(round(n * 40.0 / total)))
    return "█" * width


def _link(url) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    return "[%s](%s)" % (u.split("/")[-1] or u, u)


def _ver_arrow(cvers, fvers) -> str:
    c = "、".join(cvers or []) or "台账未填"
    f = "、".join(fvers or []) or "待确认"
    return "%s → %s" % (c, f)


def _count_by(prio, field, getter):
    """按某个多值字段聚合（返回 [(名称, 漏洞数, 严重高危数)]）。"""
    cnt = {}
    for p in prio:
        vals = getter(p) or []
        sev = p.get("severity") in ("CRITICAL", "HIGH")
        for v in vals:
            e = cnt.setdefault(v, [0, 0])
            e[0] += 1
            if sev:
                e[1] += 1
    return sorted(((k, v[0], v[1]) for k, v in cnt.items()),
                  key=lambda x: (-x[1], x[0]))


def _count_locations(hosts):
    """按机房位置聚合资产（返回 [(位置, 资产数, 严重高危数)]）。"""
    cnt = {}
    for h in hosts or []:
        loc = (h.get("location") or "").strip()
        if not loc:
            continue
        e = cnt.setdefault(loc, [0, 0])
        e[0] += 1
        if h.get("max_sev") in ("CRITICAL", "HIGH"):
            e[1] += 1
    return sorted(((k, v[0], v[1]) for k, v in cnt.items()),
                  key=lambda x: (-x[1], x[0]))


'''

src = io.open(P, encoding="utf-8").read()
i = src.find("def report_to_markdown(rep: dict) -> str:")
j = src.find("def markdown_of(scan_id: str)")
assert i > 0 and j > i, (i, j)
out = src[:i] + NEW + src[j:]
io.open(P, "w", encoding="utf-8", newline="\n").write(out)
print("replaced: old %d lines -> new file %d lines" % (src[i:j].count("\n"), out.count("\n")))
