# -*- coding: utf-8 -*-
"""按评审六节模板重写 report_to_markdown，同时保留原「资产 CPE 模式」渲染分支。

资产 CPE 模式（无漏洞台账时用）的渲染逻辑从旧函数里原样抽出为
_report_markdown_asset_mode，避免这次重写把老路径弄丢。
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "modules", "m2_enrich", "backend", "cmdb_scan.py")
src = io.open(P, encoding="utf-8").read()

# ---- 1. 抽出旧函数里「资产模式」的渲染体，改造成独立函数 ----
i = src.find("def report_to_markdown(rep: dict) -> str:")
j = src.find("def markdown_of(scan_id: str)")
assert i > 0 and j > i
old_fn = src[i:j]

ASSET_MODE = '''
def _report_markdown_asset_mode(rep: dict, L: List[str]) -> str:
    """资产 CPE 匹配模式（无漏洞台账时）的报告渲染。

    保留 2026-10-05 之前的结构：优先处置清单（单资产级）+ 资产风险清单 + 组件明细。
    台账模式走 report_to_markdown 的六节新模板，不进这里。
    """
    r = rep.get("risk", {})
    s = r.get("summary", {})
    sc = rep.get("scale") or {}
    prio = rep.get("priority") or []
    A = L.append

    A("## 一、总体结论")
    A("")
    A("| 资产 | 组件 | 命中漏洞 | 严重 | 高危 | 在野利用 | 高风险资产 |")
    A("| --- | --- | --- | --- | --- | --- | --- |")
    A("| %s | %s | %s | %s | %s | %s | %s |" % (
        s.get("hosts"), s.get("products"), s.get("cve_hits"), s.get("critical"),
        s.get("high"), s.get("exploited"), s.get("risk_hosts")))
    A("")
    if sc:
        A("> **清单口径**：本次共分析 %s 个 CI，其中**有风险**资产 %s 个、组件 %s 个；"
          "零命中条目（%s 个资产 / %s 个组件）已剔除，完整数据见报告 JSON。" % (
              sc.get("ci_total"), sc.get("hosts_risky", sc.get("hosts_total")),
              sc.get("products_risky", sc.get("products_total")),
              sc.get("hosts_dropped", 0), sc.get("products_dropped", 0)))
        A("")
    if s.get("kev_ids"):
        A("> ⚠️ **已被在野利用（CISA KEV）**：%s" % "、".join(s["kev_ids"]))
        A("")

    A("## 二、优先处置清单（现在先修什么）")
    A("")
    if not prio:
        A("未发现严重 / 高危风险资产。")
        A("")
    for i2, p in enumerate(prio, 1):
        A("### %d. %s —— %s %s%s" % (
            i2, p.get("cve"), p.get("severity"), p.get("score"),
            "（在野利用）" if p.get("exploited") else ""))
        A("")
        A("- **所在资产**：%s" % p.get("host"))
        A("- **漏洞**：%s" % p.get("title"))
        A("- **为什么优先**：%s" % (
            "CISA 已确认在野利用" + (("（%s）" % p.get("kev_added")) if p.get("kev_added") else "")
            if p.get("exploited") else
            ("CVSS %s %s" % (p.get("severity"), p.get("score")))))
        if p.get("cwe"):
            A("- **弱点类型**：%s" % "、".join(p["cwe"]))
        plan = p.get("plan")
        if plan:
            ups = plan.get("upgrade") or []
            if ups:
                A("- **怎么修（升级）**：%s" % "；".join(
                    "%s → %s" % (u.get("component"), u.get("target")) for u in ups[:3]))
            cfgs = plan.get("config") or []
            if cfgs:
                A("- **怎么修（加固）**：%s" % "；".join(c.get("item") for c in cfgs[:3]))
            verif = plan.get("verify") or []
            if verif:
                A("- **怎么检查已修复**：%s" % "；".join(verif[:2]))
        elif p.get("remediation"):
            A("- **处置建议**：%s" % "；".join(p["remediation"][:2]))
        A("")

    A("## 三、资产风险清单（按风险分排序）")
    A("")
    for h in (r.get("hosts") or []):
        cid = h.get("ci_id") or ""
        label = h.get("label") or ""
        if not label:
            nm = h.get("ci_name") or h.get("name") or ""
            label = ("%s（%s）" % (cid, nm)) if (cid and nm) else (cid or nm)
        comp = "、".join("%s %s" % (c.get("name"), c.get("version") or "")
                         for c in (h.get("components") or [])[:4])
        A("- **%s**（%s）：%s，命中 %s 条%s%s%s" % (
            label, h.get("risk_level"), comp or "—", h.get("cve_count"),
            "，在野利用 %s 条" % h.get("kev_count") if h.get("kev_count") else "",
            "，责任人 %s" % h.get("owner") if h.get("owner") else "",
            "，互联网暴露" if h.get("scope") == "公网" else ""))
    A("")

    A("## 四、软件组件命中明细")
    A("")
    for p in (r.get("products") or []):
        if not p.get("findings"):
            continue
        A("#### %s %s（风险：%s，命中 %s 条）" % (
            p.get("display") or p.get("name"), p.get("version") or "版本未知",
            p.get("risk_level"), p.get("cve_count")))
        A("")
        A("| CVE | 严重度 | CVSS | 在野利用 | 依据 |")
        A("| --- | --- | --- | --- | --- |")
        for f in p["findings"][:20]:
            A("| %s | %s | %s | %s | %s |" % (
                f["id"], f["severity"], f.get("score"),
                "是" if f.get("exploited") else "—", f.get("evidence", "")))
        A("")

    A("## 五、说明")
    A("")
    A("- 脆弱性判定采用 NVD 原始 CPE 版本区间（含 versionStartIncluding / "
      "versionEndExcluding），仅当资产版本落在受影响区间内才计入，非关键词命中。")
    A("- 处置方案由系统自动生成（模板 / LLM 双模式），上线前请结合官方公告核对版本号"
      "并在测试环境验证。")
    A("- 全部解析与匹配在本机完成，CMDB 资产数据不外发、不联网。")
    return "\\n".join(L)


'''

# 把 ASSET_MODE 插到 report_to_markdown 之前
new_src = src[:i] + ASSET_MODE.lstrip("\n") + src[i:]
io.open(P, "w", encoding="utf-8", newline="\n").write(new_src)
print("asset-mode renderer inserted")
