"""简略版处置台账导出（2026-10-06）—— 参照客户提供的《SVMS_TKT_06_OCT 1.xlsx》格式。

★ 为什么要有「简略版」
--------------------
现有七章制 Markdown 报告适合**存档与评审**：有推导过程、有证据链、有附录。
但运维/安全团队日常真正要的是一张能直接派单、能按人筛选、能统计进度的表 ——
客户给的参考模板正是如此：三个 sheet 分别是
    Sheet1  风险等级透视（Risk Level × Count）
    Sheet2  责任人 × 风险等级 × 处置阶段 × 三步期限
    Page 1  明细工单（77 列的完整台账）

本模块生成**结构同构但列更少**的简略版：保留"谁、什么时候之前、做什么"这条主线，
去掉评审用的推导列。既能对齐客户既有流程，又不会把几百 MB 的报告塞进邮件。

★ 与原报告的关系：**互不替代**
--------------------------------
    简略版（xlsx）→ 日常派单、按责任人分发、填进客户既有台账
    七章制（md）   → 评审、归档、追溯"为什么判这个等级"
两个导出入口并存，各自独立，不覆盖对方。
"""
from __future__ import annotations

import io
import re
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# —— 与 cmdb_scan._SLA_DAYS 保持一致的兜底（导出器不能 import 分析器，避免循环）——
_SLA_DAYS = {"CRITICAL": 7, "HIGH": 15, "MEDIUM": 30, "LOW": 60, "INFO": 90}

# —— 等级归一：把 CRITICAL/HIGH/… 和 中文"严重/高" 统一到 R1~R4 + 中文标签 ——
_SEV_MAP = {
    "CRITICAL": ("R1", "严重"),
    "HIGH": ("R2", "高"),
    "MEDIUM": ("R3", "中"),
    "LOW": ("R4", "低"),
    "INFO": ("R5", "信息"),
    "UNKNOWN": ("R5", "待定"),
}

# —— 三步期限的默认天数（对齐参考模板 Step1/2/3 的间隔规律）——
_STEP_DAYS = {"step1": 2, "step2": 12, "step3": 90}

# 单元格最大字符数：Excel 单元格上限 32767，但超长文本会让文件体积暴涨且没人看得完
_MAX_CELL = 30000


def _s(v: Any, n: int = _MAX_CELL) -> str:
    """安全转字符串：None→空、超长截断、去掉会破坏 XML 的控制字符。"""
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        v = "、".join(str(x) for x in v if str(x or "").strip())
    t = str(v)
    # XML 1.0 不允许这些控制字符，写进 xlsx 会让 openpyxl 抛 IllegalCharacterError
    t = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", t)
    return t[:n]


def _sev(v: Any) -> Tuple[str, str]:
    """等级 → (R编号, 中文标签)。认英文也认中文。"""
    t = str(v or "").strip().upper()
    if t in _SEV_MAP:
        return _SEV_MAP[t]
    for k, val in _SEV_MAP.items():
        if k in t:
            return val
    zh = {"严重": "R1", "高危": "R2", "高": "R2", "中": "R3", "低": "R4"}
    for k, code in zh.items():
        if k in str(v or ""):
            return (code, {"R1": "严重", "R2": "高", "R3": "中",
                           "R4": "低"}.get(code, "待定"))
    return ("R5", "待定")


def _host_owner_index(rep: Dict[str, Any]) -> Dict[str, str]:
    """主机 → 责任人 的反查表。

    为什么需要：不是每份报告的 priority 工单都带 owners（早期版本 / 只做资产
    CPE 匹配而非台账聚合的报告就没有）。但 CMDB 台账的 meta 里始终有 host+owner，
    所以可以按工单里的 host 反查责任人 —— 否则简略台账最关键的"责任人"列
    整列都是「未指定」，这张表就没法用来派单了。
    """
    idx: Dict[str, str] = {}
    for m in (rep.get("meta") or []):
        if not isinstance(m, dict):
            continue
        h = _s(m.get("host") or m.get("name") or "").strip()
        o = _s(m.get("owner") or "").strip()
        if h and o and h not in idx:
            idx[h] = o
    return idx


_NUM_RE = re.compile(r"-?\d+")


def _to_int(v: Any, default: int = 0) -> int:
    """把 CMDB 台账里五花八门的"数字"安全转成 int。

    ★ 2026-10-06 修：真实报告里 sla_days 出现过「8 天」这种带单位的字符串，
      而这里是裸 int() 解析 —— 一崩就是**整份 xlsx 导不出来**，前端只看到
      「简略台账生成失败」，完全指不到是哪张单的哪个字段。
      台账里少一个数字可以接受，整份导出失败不行，所以：
      从字符串里抽第一个整数，抽不到就用 default。
    """
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        try:
            return int(v)
        except (ValueError, OverflowError):
            return default
    m = _NUM_RE.search(str(v or ""))
    if not m:
        return default
    try:
        return int(m.group(0))
    except (ValueError, OverflowError):
        return default


def _prio_rows(rep: Dict[str, Any]) -> List[Dict[str, Any]]:
    """取处置工单；兼容"字段全的"与"字段少的"两种历史报告。"""
    pri = rep.get("priority") or []
    owner_idx = _host_owner_index(rep)
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for r in pri:
        if not isinstance(r, dict):
            continue
        owners = [_s(x) for x in (r.get("owners") or []) if _s(x)]
        if not owners and r.get("owner"):
            owners = [_s(r["owner"])]
        # ★ 兜底一：工单自带 owner/owners
        #   兜底二：按 host 去 CMDB 台账的 meta 里反查
        if not owners:
            for h in _as_list(r.get("hosts") or r.get("host")):
                o = owner_idx.get(_s(h).strip())
                if o and o not in owners:
                    owners.append(o)
        cve = _s(r.get("cve") or "") or "—"
        # ★ 去重：历史报告里同一 (CVE, 组件) 可能重复多行（多资产未聚合）。
        #   台账的意义是"一件事一张单"，重复行会让责任人工作量统计虚高数倍。
        #   ★ 但键里必须带受影响资产数：早期报告组件字段为空，只按 (cve, 空组件)
        #     去重会把 200 条不同资产的工单压成 1 条 —— 那不是去重，是丢数据。
        #     判据：资产数不同 = 不同的一批机器，就是不同的单。
        ukey = (cve, _s(r.get("component") or ""), _to_int(r.get("asset_count")))
        if ukey in seen:
            continue
        seen.add(ukey)
        out.append({
            "cve": cve,
            "component": _s(r.get("component") or "—"),
            "severity": _s(r.get("severity") or ""),
            "cvss": r.get("cvss") or r.get("score") or 0.0,
            "score": r.get("score") or 0.0,
            "asset_count": _to_int(r.get("asset_count")),
            "internet_count": _to_int(r.get("internet_count")),
            "owners": owners,
            "plan_fix": [_s(x) for x in (r.get("plan_fix") or []) if _s(x)],
            "sla_days": _to_int(r.get("sla_days")) or _SLA_DAYS.get(
                str(r.get("severity") or "").upper(), 30),
            "sla_due": _s(r.get("sla_due") or ""),
            "status": _s(r.get("status") or r.get("fix_status") or "待处置"),
            "exploited": bool(r.get("exploited")),
            "label": _s(r.get("priority_label") or ""),
            "url": _s(r.get("url") or r.get("ref") or ""),
            "advice": [_s(x) for x in (r.get("remediation") or []) if _s(x)],
        })
    return out


def _as_list(v: Any) -> List[Any]:
    """把 str / list / None 统一成 list（工单里 hosts 字段两种形态都出现过）。"""
    if not v:
        return []
    if isinstance(v, (list, tuple, set)):
        return [x for x in v if _s(x).strip()]
    return [v]


def _base_date(rep: Dict[str, Any]) -> datetime:
    """报告基准日期：三步期限都从它起算。取不到就用今天。"""
    for k in ("created_at", "generated_at", "ts"):
        v = str(rep.get(k) or "").strip()
        if not v:
            continue
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", v)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                pass
    return datetime.now()


def _dates(r: Dict[str, Any], base: datetime) -> Tuple[str, str, str]:
    """按基准日 + SLA 天数推出 (Step1, Step2, Step3) 三个截止日。

    ★ 先统一把 sla_days 归一成 int 再参与运算：字符串（如「8 天」）去做加法
      会在进入 _add 的 try 之前就抛 TypeError，那种崩法连兜底都拦不住。
    """
    sla = _to_int(r.get("sla_days")) or 30

    def _add(days: int) -> str:
        try:
            return (base + timedelta(days=max(0, _to_int(days)))).strftime("%Y-%m-%d")
        except (ValueError, OverflowError, TypeError):
            return ""
    d1 = _s(r.get("sla_due")) or _add(sla)
    d2 = _add(sla + _STEP_DAYS["step2"])
    d3 = _add(sla + _STEP_DAYS["step3"])
    return (d1, d2, d3)


def _stage(r: Dict[str, Any]) -> str:
    """处置阶段（对齐参考模板的 Survey of Countermeasures 取值）。"""
    st = str(r.get("status") or "").strip()
    if not st or st == "待处置":
        return "Step.1 Response Policy"
    low = st.lower()
    if "已修复" in st or "完成" in st or "closed" in low or "done" in low:
        return "Step.3 Permanent measure"
    if "缓解" in st or "mitigat" in low:
        return "Step.2 Interim measure"
    return "Step.1 Response Policy"


def _owner_cell(owners: List[str]) -> str:
    if not owners:
        return "未指定"
    return "、".join(owners[:6]) + ("…" if len(owners) > 6 else "")


# ======================================================================
# 主入口
# ======================================================================
def _mask_workbook(wb: Any, mask: str) -> int:
    """对整本台账做文本脱敏，返回被改动的单元格数。

    ★ 2026-10-06 修：原来 mask 只写进「说明」页的一句话，**数据本身是原文** ——
      结果同一张表里一边写"已按基础脱敏处理内网 IP / 邮箱"，一边写
      "本表含责任人姓名、内网 IP 与业务系统名"，自相矛盾，而且发给外部邮箱时
      正文（七章制 md）脱敏了、附件却是原文。
      这里复用 cmdb_scan.mask_text（与正文同一套规则），保证两份口径一致。
    """
    if mask not in ("basic", "strict"):
        return 0
    try:
        import cmdb_scan as CM  # 无循环导入：cmdb_scan 不反向依赖本模块
        rule = getattr(CM, "mask_text", None) or CM._mask_markdown
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    try:
        for ws in wb.worksheets:
            for row in ws.iter_rows():
                for c in row:
                    v = c.value
                    if isinstance(v, str) and v:
                        nv = rule(v, mask)
                        if nv != v:
                            c.value = nv
                            n += 1
    except Exception:  # noqa: BLE001  脱敏失败不该让导出整个失败
        return n
    return n


def build_xlsx(rep: Dict[str, Any], mask: str = "off") -> bytes:
    """生成简略版台账 xlsx（三个 sheet，结构对齐参考模板）。返回字节流。"""
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.utils import get_column_letter
    except ImportError as e:  # noqa: BLE001
        raise RuntimeError("需要 openpyxl 才能导出 Excel：%s" % e)

    rows = _prio_rows(rep)
    base = _base_date(rep)
    rid = _s(rep.get("id") or "")

    wb = openpyxl.Workbook()

    # ——— 样式（一次建好复用，别在循环里 new）———
    thin = Side(style="thin", color="FFD0D0D0")
    bd = Border(left=thin, right=thin, top=thin, bottom=thin)
    hdr_fill = PatternFill("solid", fgColor="FF2F3B52")
    hdr_font = Font(bold=True, color="FFFFFFFF", size=10)
    cell_font = Font(size=10)
    wrap = Alignment(vertical="top", wrap_text=True)
    center = Alignment(horizontal="center", vertical="center")

    # 等级配色：红→黄→绿，和安全运营惯例一致
    sev_fill = {
        "R1": PatternFill("solid", fgColor="FFFFC7CE"),
        "R2": PatternFill("solid", fgColor="FFFFD9B3"),
        "R3": PatternFill("solid", fgColor="FFFFF2CC"),
        "R4": PatternFill("solid", fgColor="FFDDEEDD"),
    }

    def _head(ws, headers, widths):
        ws.append(headers)
        for i, h in enumerate(headers, 1):
            c = ws.cell(row=1, column=i)
            c.fill, c.font, c.border = hdr_fill, hdr_font, bd
            c.alignment = center
            ws.column_dimensions[get_column_letter(i)].width = widths[i - 1] if i <= len(widths) else 14
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions

    # ============ Sheet1：风险等级透视 ============
    ws1 = wb.active
    ws1.title = "风险等级统计"
    _head(ws1, ["风险等级", "工单数", "受影响资产数", "在野利用", "涉及责任人"],
          [14, 10, 14, 12, 40])
    by_sev: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    for r in rows:
        code, _zh = _sev(r["severity"])
        g = by_sev.setdefault(code, {"n": 0, "assets": 0, "kev": 0, "owners": set()})
        g["n"] += 1
        g["assets"] += r["asset_count"]
        g["kev"] += 1 if r["exploited"] else 0
        g["owners"].update(r["owners"])
    # 固定顺序输出，空等级也保留一行，方便对比
    for code in ("R1", "R2", "R3", "R4", "R5"):
        g = by_sev.get(code)
        _zh = {v[0]: v[1] for v in _SEV_MAP.values()}.get(code, "待定")
        label = "%s（%s）" % (code, _zh)
        if not g:
            ws1.append([label, 0, 0, 0, ""])
            continue
        ws1.append([label, g["n"], g["assets"], g["kev"],
                    _owner_cell(sorted(g["owners"]))])
    for row in ws1.iter_rows(min_row=2, max_row=ws1.max_row):
        for c in row:
            c.border, c.font = bd, cell_font
        row[0].fill = sev_fill.get(str(row[0].value).split("（")[0],
                                  PatternFill("solid", fgColor="FFFFFFFF"))

    # ============ Sheet2：按责任人分派 ============
    ws2 = wb.create_sheet("按责任人分派")
    _head(ws2, ["责任人", "风险等级", "处置阶段", "工单数", "最早截止日",
                "涉及漏洞（最多 8 个）"],
          [16, 12, 26, 10, 14, 60])
    by_owner: "OrderedDict[Tuple[str, str], Dict[str, Any]]" = OrderedDict()
    for r in rows:
        code, _ = _sev(r["severity"])
        d1, _d2, _d3 = _dates(r, base)
        for o in (r["owners"] or ["未指定"]):
            k = (o, code)
            g = by_owner.setdefault(k, {"n": 0, "cves": [], "due": ""})
            g["n"] += 1
            if len(g["cves"]) < 8:
                g["cves"].append(r["cve"])
            if d1 and (not g["due"] or d1 < g["due"]):
                g["due"] = d1
    for (owner, code), g in sorted(by_owner.items(),
                                   key=lambda kv: (kv[0][1], -kv[1]["n"])):
        ws2.append([owner, code, _stage({"status": "待处置"}), g["n"],
                    g["due"] or "—",
                    "、".join(g["cves"]) + ("…" if g["n"] > 8 else "")])
        ws2.cell(row=ws2.max_row, column=2).fill = sev_fill.get(
            code, PatternFill("solid", fgColor="FFFFFFFF"))
    for row in ws2.iter_rows(min_row=2, max_row=ws2.max_row):
        for c in row:
            c.border, c.font = bd, cell_font
            if c.column in (2, 3, 4, 5):
                c.alignment = center

    # ============ Page 1：工单明细（核心，列对齐参考模板精简版）============
    ws3 = wb.create_sheet("工单明细")
    _head(ws3, ["编号", "漏洞编号", "组件", "风险等级", "CVSS", "风险分",
                "受影响资产", "公网暴露", "在野利用", "责任人",
                "计划修复期限", "Step1 截止", "Step2 截止", "Step3 截止",
                "SLA(天)", "处置阶段", "状态", "整改建议"],
          [10, 20, 26, 10, 8, 8, 11, 10, 10, 22, 14, 13, 13, 13, 9, 24, 12, 60])
    for i, r in enumerate(rows, 1):
        code, _ = _sev(r["severity"])
        d1, d2, d3 = _dates(r, base)
        advice = "；".join(r.get("advice") or []) or \
            "按厂商公告升级至修复版本；无法立即升级时先执行官方缓解措施。"
        ws3.append([
            "TKT%05d" % i, r["cve"], r["component"], code,
            ("%.1f" % r["cvss"]) if r["cvss"] else "—",
            "%.1f" % r["score"], r["asset_count"],
            "是" if r["internet_count"] else "—",
            "是" if r["exploited"] else "—",
            _owner_cell(r["owners"]),
            "、".join(r["plan_fix"]) or d1 or "—",
            d1 or "—", d2 or "—", d3 or "—",
            r["sla_days"], _stage(r), r["status"] or "待处置",
            _s(advice, 2000),
        ])
        ws3.cell(row=ws3.max_row, column=4).fill = sev_fill.get(
            code, PatternFill("solid", fgColor="FFFFFFFF"))
    for row in ws3.iter_rows(min_row=2, max_row=ws3.max_row):
        for c in row:
            c.border, c.font, c.alignment = bd, cell_font, wrap
            if c.column in (1, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 17):
                c.alignment = center

    # ============ 说明页（口径与免责，简略版也要说清数据边界）============
    ws4 = wb.create_sheet("说明")
    ws4.column_dimensions["A"].width = 18
    ws4.column_dimensions["B"].width = 88
    _head(ws4, ["项目", "说明"], [18, 88])
    rid_s = rid or "—"
    notes = [
        ("报告编号", rid_s),
        ("生成时间", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("基准日期", base.strftime("%Y-%m-%d") + "（三步期限均以此日起算）"),
        ("工单总数", str(len(rows))),
        ("口径说明", "按漏洞编号聚合；同一 CVE 命中多台资产时，受影响资产数累加、责任人为该资产的归属人"),
        ("风险等级", "R1 严重 / R2 高 / R3 中 / R4 低 / R5 待定，由 CVSS 与在野利用标记综合判定"),
        ("三步期限", "Step1 响应承诺 → Step2 缓解措施 → Step3 永久修复；"
                     "Step1 取报告给出的 SLA 建议截止日，Step2/Step3 按 SLA 天数顺延"),
        ("SLA 基准", "严重 7 天 / 高 15 天 / 中 30 天 / 低 60 天；"
                     "在野利用(KEV)、公网暴露、监管资产会进一步压缩"),
        ("未指定责任人", "CMDB 台账里没有归属人的工单归入「未指定」，需人工分派后再纳入考核"),
        ("本表用途", "日常派单、按责任人分发进度、与客户既有台账（SVMS_TKT）对接"),
        ("完整版报告", "同一份分析另有七章制 Markdown 版，含推导过程与证据链，用于评审与追溯"),
        ("保密提示", "本表含责任人姓名与业务系统名；内网 IP / 邮箱已按所选级别处理，"
                     "对外提供前请再复核业务系统名是否需要替换"),
    ]
    if mask in ("basic", "strict"):
        notes.insert(len(notes) - 1,
                     ("脱敏级别", "全表已按「%s」处理：邮箱→首字母***@***、IPv4→前三段.x%s"
                      % ("基础脱敏" if mask == "basic" else "严格脱敏",
                         "；另抹除 IPv6、工号/资产号整体替换" if mask == "strict" else "")))
    for k, v in notes:
        ws4.append([_s(k), _s(v, 2000)])
    for row in ws4.iter_rows(min_row=2, max_row=ws4.max_row):
        for c in row:
            c.border, c.font = bd, cell_font
        row[0].font = Font(size=10, bold=True)
        row[1].alignment = wrap

    # ★ 脱敏必须在 save 之前：openpyxl 保存后再改单元格不会进字节流
    _mask_workbook(wb, mask)

    buf = io.BytesIO()
    wb.save(buf)
    wb.close()
    return buf.getvalue()


def build_rows_preview(rep: Dict[str, Any]) -> Dict[str, Any]:
    """给接口/测试用的轻量预览（不生成 xlsx，只回统计）。"""
    rows = _prio_rows(rep)
    base = _base_date(rep)
    return {
        "tickets": len(rows),
        "base_date": base.strftime("%Y-%m-%d"),
        "by_severity": dict(Counter(_sev(r["severity"])[0] for r in rows)),
        "owners": sorted({o for r in rows for o in r["owners"]}),
        "exploited": sum(1 for r in rows if r["exploited"]),
    }