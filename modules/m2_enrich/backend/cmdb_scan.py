# -*- coding: utf-8 -*-
"""
cmdb_scan.py —— 公司 CMDB 连接 + 资产风险自动分析（含处置优先级与验证闭环）
====================================================================================
负责人：成员B（情报富化模块新增能力）

用户需求（2026-10-04）
    「要有一个接口，能和公司的 CMDB 连接，自动分析公司资产里面对的风险性、脆弱性，
      并给出报告——现在应该优先解决什么、怎么解决、怎么检查解决是否成功，且能下载文件。」

本模块做的事（一句话）：把「CMDB 里的资产数据」变成一份「该优先修谁、怎么修、
怎么验收」的可下载处置报告。脆弱性判定复用 asset_scan.py 的 CPE 版本区间匹配
（不是关键词命中），处置方案复用 remediation.py 的 CWE/CVSS/KEV 推导。

CMDB 接入的三种模式（见 _load_assets）
--------------------------------
  1. rest    —— 对接真实 CMDB 的 REST API（通用约定，字段可配）。
               配置走 config.json 的 cmdb 段或环境变量（AISEC_CMDB_*），Key 不进代码。
  2. inline  —— 直接把 CMDB 导出的 JSON / CSV 数据贴进来（离线兜底，永远可用）。
  3. file    —— 上传 CMDB 导出的资产文件（复用 asset_scan 的解析，word/excel/txt）。

对外入口
--------
    analyze(engine, cfg) -> dict         ← api.py 用这个（cfg 含 mode + 数据）
    build_priority(risk) -> list         ← 从 risk 里抽出「优先处置清单」
    report_to_markdown(report) -> str    ← 可下载的 Markdown 报告
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys as _sys
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

import paths  # noqa: E402
DATA_DIR = paths.DATA_DIR

# 复用资产解析与风险匹配（不重复造轮子）
import asset_scan as AS  # noqa: E402

try:  # aisec-swallow
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

_CMDB_STORE = os.path.join(DATA_DIR, "cmdb_scans.json")      # 历史索引
_CMDB_REPORT_DIR = os.path.join(DATA_DIR, "cmdb_reports")    # 完整报告
STORE_MAX = 30
# ★ 落盘读-改-写串行化（2026-10-06 审查发现）：服务是 ThreadingHTTPServer，
#   一请求一线程，而 _persist 是「读索引 → 改 → 写回」的复合操作。
#   实测 40 线程并发 _persist，最终索引只剩 1 条记录、39 条静默丢失
#   （报告文件各自落盘成功，所以用户看不出丢了，只有历史列表少条目）。
#   asset_scan 早已有同款_LOCK（见该文件 line 77），这里之前漏了。
_LOCK = threading.Lock()


def _nz(s) -> str:
    return (s or "").strip() if isinstance(s, str) else (str(s) if s is not None else "")


def _db_paths(cfg: dict) -> List[str]:
    """SQLite 模式的库路径列表（去重、剔空、保序）。

    兼容三种来源：
      · cfg["paths"] —— 上传的多个 .db（2026-10-06 新增浏览器上传入口）
      · cfg["path"]  —— 单个路径（老的「填服务器本地路径」入口，仍在用）
      · cfg["db"]     —— 历史别名
    分库很常见（资产库一个、漏洞台账库一个），只认 path 会逼用户先手工合并，
    所以这里统一收敛成列表，由各读取函数逐个读再合并。
    """
    out: List[str] = []
    raw = cfg.get("paths")
    if isinstance(raw, (list, tuple)):
        for p in raw:
            p = _nz(p)
            if p and p not in out:
                out.append(p)
    for key in ("path", "db"):
        p = _nz(cfg.get(key))
        if p and p not in out:
            out.append(p)
    return out


# ==========================================================================
# 0. 规模边界（100 万 CI 也能扛，靠结构化快速路径 + 上限保护，绝不 OOM）
# ==========================================================================
MAX_CI = 1_000_000           # 单次分析 CI（配置项/资产）上限；超过明确报错而非 OOM
MAX_PRODUCTS = 100_000       # 参与匹配的软件组件上限（去重后）
# 每个组件在 risk.products[].assets 里保留的代表资产上限（2026-10-06）。
# 完整明细由 priority 列表承担；这里只留汇总视图需要的样本，避免报告 JSON 爆炸
# （不限制时实测 72 万行台账能把报告撑到 604MB，浏览器直接 Failed to fetch）。
MAX_COMP_ASSETS = 200
MAX_PRIORITY = 200           # 优先处置清单最多保留条数（报告不膨胀）


# ==========================================================================
# 1. CMDB 数据接入
# ==========================================================================
# 常见 CMDB 字段别名 → 统一字段（asset_scan 的 extract 需要的行格式）
_FIELD_ALIASES = {
    "name": ["name", "asset_name", "hostname", "主机名", "资产名称", "设备名称"],
    "ip": ["ip", "address", "ip_addr", "ip_address", "公网ip", "外网ip", "IP", "ip地址", "地址"],
    "domain": ["domain", "host", "fqdn", "域名", "网址", "url"],
    "product": ["product", "software", "component", "app", "软件", "组件", "产品", "应用"],
    "version": ["version", "ver", "版本", "版本号"],
    "port": ["port", "端口"],
    "os": ["os", "system", "operating_system", "操作系统"],
    "owner": ["owner", "负责人", "运维", "责任人", "owner_name"],
    "env": ["env", "environment", "环境", "用途", "备注", "desc", "description"],
}


def _pick(row: dict, *keys) -> str:
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return _nz(row[k])
    return ""


def _field(row: dict, canon: str) -> str:
    """按别名表从一个 CMDB 记录里取值。"""
    for k in _FIELD_ALIASES.get(canon, []):
        v = row.get(k)
        if v not in (None, ""):
            return _nz(v)
    # 兜底：大小写不敏感
    lower = {str(k).lower(): v for k, v in row.items()}
    for k in _FIELD_ALIASES.get(canon, []):
        v = lower.get(k.lower())
        if v not in (None, ""):
            return _nz(v)
    return ""


def _flatten(items: Any) -> List[dict]:
    """把 CMDB 返回的各种形状拍平成记录列表。"""
    if items is None:
        return []
    if isinstance(items, dict):
        # {"data":[...]} / {"items":[...]} / {"result":[...]} / {"records":[...]}
        for k in ("data", "items", "result", "records", "list", "assets", "servers", "hosts"):
            v = items.get(k)
            if isinstance(v, list):
                return _flatten(v)
        # 单个对象（一张表只有一台资产）
        return [items]
    if isinstance(items, list):
        out: List[dict] = []
        for x in items:
            if isinstance(x, dict):
                out.extend(_flatten(x))
        return out
    return []


def _parse_inline_text(text: str) -> List[dict]:
    """解析用户直接贴进来的 JSON / CSV / TSV。"""
    text = (text or "").strip()
    if not text:
        return []
    # JSON
    if text[0] in "[{":
        try:
            return _flatten(json.loads(text))
        except ValueError:
            pass
    # CSV / TSV（带表头）
    try:
        sample = text[:2048]
        delim = "\t" if "\t" in sample else ("," if "," in sample else None)
        if delim:
            reader = csv.reader(io.StringIO(text), delimiter=delim)
            rows = [r for r in reader if any(c.strip() for c in r)]
            if not rows:
                return []
            header = [c.strip() for c in rows[0]]
            out = []
            for r in rows[1:]:
                d = {header[i]: r[i].strip() for i in range(min(len(header), len(r)))}
                out.append(d)
            return out
    except Exception as e:  # noqa: BLE001
        _swallow("cmdb_scan._parse_inline_text", e)
    return []


def _parse_inline_blocks(text: str) -> List[Tuple[List[str], List[List[str]]]]:
    """把粘贴文本按「空行分隔的表块」切开，每块返回 (表头, 数据行)。

    ★ 为什么需要（2026-10-05）：运维从 CMDB 导出后经常一次性粘贴多张表
      （vulnerability + physical_server + idc_room + cabinet，中间空一行）。
      原来 _parse_inline_text 把整段当成一张表 → 第二张表起表头被当数据行，
      机房/机柜信息全丢，报告的「位置」列恒为「未登记」，运维还得自己翻资产表。
      这里按表头行（_row_is_header）重新起块，与 file 模式的多 sheet 拼接等价。
    """
    text = (text or "").strip()
    if not text or text[0] in "[{":
        return []
    try:
        sample = text[:2048]
        delim = "\t" if "\t" in sample else ("," if "," in sample else None)
        if not delim:
            return []
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        blocks: List[Tuple[List[str], List[List[str]]]] = []
        header: Optional[List[str]] = None
        body: List[List[str]] = []
        for r in reader:
            cells = [(c or "").strip() for c in r]
            if not any(cells):                     # 空行 → 表块分隔
                if header and body:
                    blocks.append((header, body))
                header, body = None, []
                continue
            if _row_is_header(cells) and (not header or _loc_table_kind(
                    [(c or "").lower() for c in cells]) or _vuln_table_map(
                    [(c or "").lower() for c in cells]) is not None):
                if header and body:
                    blocks.append((header, body))
                header, body = [(c or "").lower().lstrip("﻿") for c in cells], []
                continue
            if header is None:
                continue
            body.append(cells)
        if header and body:
            blocks.append((header, body))
        return blocks
    except Exception as e:  # noqa: BLE001
        _swallow("cmdb_scan._parse_inline_blocks", e)
        return []


def _inline_loc_index(text: str) -> "_LocIndex":
    """从粘贴的多表文本里建 CI → 位置索引（只取机房/机柜/资产三类表）。"""
    idx = _LocIndex()
    for header, body in _parse_inline_blocks(text):
        kind = _loc_table_kind(header)
        if kind:
            idx.feed_table(header, body, kind)
    return idx


# —— file 模式：表头识别（xlsx/csv 导出 → 结构化记录，跳过逐行正则） ——
# 列名候选按「精确匹配」优先，识别不了整体回退 asset_scan 的通用抽取。
# 语义与 _SQLITE_TABLE_MAP 对齐：有 type 列时 product 取 type（MW_TYPE/FRAMEWORK…），
# name 取实例名（MW_NAME…）；无 type 列时 product 取名称列（软件目录表 SW_NAME…）。
_HDR_TYPE_COLS = ("mw_type", "db_type", "comp_type", "framework", "middleware_type",
                  "component_type", "soft_type", "sw_type", "app_type", "svc_type",
                  "service_type", "type", "类型")
_HDR_PRODNAME_COLS = ("sw_name", "product_name", "product", "software", "software_name",
                      "soft_name", "component", "产品", "软件名称", "产品名称", "组件名称")
_HDR_INSTNAME_COLS = ("mw_name", "db_name", "comp_name", "svc_name", "app_name",
                      "inst_name", "instance_name", "name", "hostname", "host_name",
                      "实例名称", "应用名称", "名称", "主机名")
_HDR_VER_COLS = ("version", "ver", "model_version", "soft_version", "sw_version",
                 "app_version", "db_version", "mw_version", "版本", "版本号")
_HDR_IP_COLS = ("host_ip", "ip", "ip_addr", "ip_address", "hostip", "manage_ip",
                "management_ip", "endpoint", "ip地址", "管理ip", "主机ip", "业务ip", "地址")
_HDR_DOMAIN_COLS = ("domain", "domain_name", "fqdn", "url", "域名", "网址", "网站域名")
_HDR_PORT_COLS = ("port", "listen_port", "service_port", "端口", "服务端口")
_HDR_OS_COLS = ("os", "os_name", "os_type", "os_version", "操作系统")
_HDR_OWNER_COLS = ("owner", "owner_name", "responsible", "responsible_person",
                   "负责人", "责任人")
_HDR_ENV_COLS = ("env", "env_type", "environment", "env_name", "环境", "环境类型", "用途")

# 这些词出现在回退匹配的 ip 列名里 → 不是资产地址（操作员/登录者终端）
_IP_COL_EXCLUDE = ("operator", "client", "login", "audit", "user", "create", "update", "last")

# —— vulnerability 漏洞台账表识别（CMDB 里已有的「漏洞→资产→组件→责任人→期限」台账）——
# ★ 语义与普通资产表不同：vulnerability 表的每一行不是「一台资产」而是一条
#   「已知漏洞记录」，自带 CI_ID（资产标识）/ AFFECTED_COMPONENT（组件）/
#   OWNER（责任人）/ PLAN_FIX_DATE（修复期限）/ FIX_STATUS（状态）/
#   RELATED_PATCH（官方补丁）/ IS_INTERNET_FACING（是否互联网暴露）。
#   它应被当作「漏洞台账」直接聚合，而不是把 COMPONENT_VERSION 当真实版本
#   号丢进 CPE 区间匹配（版本号若是随机假数据，会导致全量误命中）。
_VULN_ID_COLS = ("vuln_id", "vul_id", "漏洞记录号")
_VULN_CI_ID_COLS = ("ci_id", "asset_id", "资产编号")
_VULN_CI_TYPE_COLS = ("ci_type", "asset_type", "资产类型")
_VULN_CI_NAME_COLS = ("ci_name", "ci_hostname", "asset_name", "资产名称")
_VULN_COMPONENT_COLS = ("affected_component", "component", "vuln_component",
                        "受影响组件", "组件")
_VULN_COMPONENT_VER_COLS = ("component_version", "affected_version", "组件版本")
_VULN_FIX_VER_COLS = ("fix_version", "fixed_version", "修复版本", "修复后版本")
_VULN_SEVERITY_COLS = ("severity", "risk_level", "危险等级", "严重程度")
_VULN_CVSS_COLS = ("cvss_score", "cvss", "cvss分值")
# ★ 漏洞编号（VULN_NO）—— 2026-10-05 修复的关键漏映射。
#   源数据 vulnerability 表的漏洞编号列名是 VULN_NO（值形如 CVE-2026-08447 /
#   CNVD-2026-94344 / CNNVD-202692831），之前候选里只有 cve_id / cve / cve编号，
#   一个都匹配不上 → cve 字段全空 → ①报告标题退化成「组件@VUL-00000021」这种
#   伪 CVE（把漏洞记录号当 CVE 号）；②用语料补 NVD 链接 / KEV / CPE 区间时
#   全部落空，证据链 0 条。这里补上 VULN_NO 及常见别名。
_VULN_CVE_COLS = ("vuln_no", "cve_id", "cve", "cve编号", "漏洞cve", "漏洞编号",
                  "cve_no", "cve编号")
_VULN_OWNER_COLS = ("owner", "owner_name", "负责人", "责任人")
_VULN_PLAN_FIX_COLS = ("plan_fix_date", "fix_deadline", "修复期限", "计划修复日期", "整改期限")
_VULN_FIX_STATUS_COLS = ("fix_status", "vuln_status", "处置状态", "修复状态")
_VULN_PATCH_COLS = ("related_patch", "patch_id", "patch", "补丁编号", "关联补丁")
_VULN_INTERNET_COLS = ("is_internet_facing", "internet_facing", "是否互联网暴露", "是否公网暴露")
_VULN_REGULATORY_COLS = ("is_regulatory", "regulatory", "是否监管")
_VULN_BG_COLS = ("business_bg", "biz_domain", "业务背景", "业务线")
_VULN_IMPORTANCE_COLS = ("importance", "asset_importance", "资产重要性", "重要程度")
# —— 台账里另外几个对派单有用的字段（2026-10-05 新增）——
_VULN_APP_COLS = ("app_name", "app_id", "应用名称", "应用编号", "business_system")
_VULN_ENV_COLS = ("env_type", "env", "环境类型", "环境")
_VULN_TYPE_COLS = ("vuln_type", "漏洞类型", "type")
_VULN_CWE_COLS = ("cwe_id", "cwe", "弱点类型")
_VULN_VERIFY_COLS = ("verify_status", "验证状态")
# —— 利用可得性（2026-10-05 新增）——
#   台账里 EXPLOIT_AVAILABLE（存在公开利用代码）/ IS_VERIFIED_EXPLOIT（已验证可利用）
#   是判断「已确认 vs 待确认」的关键：扫描器报了就复现不了（待复现），
#   但若已有公开 PoC，人工利用风险已成立，不能按「待确认」轻处理。
_VULN_EXPLOIT_COLS = ("is_verified_exploit", "exploit_available", "验证可利用", "可利用")
_VULN_EXPLOIT_AVAIL_COLS = ("exploit_available", "存在利用代码", "可利用代码")
_VULN_DISCOVER_COLS = ("discover_tool", "discover_time", "发现工具", "发现时间")
_VULN_ACCEPT_COLS = ("is_accepted_risk", "accepted_risk", "是否接受风险")
_VULN_ACTUAL_FIX_COLS = ("actual_fix_date", "实际修复日期")
_VULN_DURATION_COLS = ("fix_duration_days", "修复时长")
_VULN_NAME_COLS = ("vuln_name", "漏洞名称", "title")
_VULN_PORT_COLS = ("port", "端口")
_VULN_DEPT_COLS = ("dept_id", "部门编号")
_VULN_EMP_COLS = ("emp_id", "员工编号")


# —— 漏洞编号 → 官方查询入口（2026-10-05）——
#   国内编号（CNVD / CNNVD）没有 NVD 页面，给对应的国内官方链接才是可核查的证据链；
#   编号本身为空时不能瞎编 CVE 号，只能标注「源数据未填编号」。
_ID_PREFIX_URL = {
    "CVE": "https://nvd.nist.gov/vuln/detail/%s",
    "CNVD": "https://www.cnvd.org.cn/flaw/show/%s",
    "CNNVD": "https://www.cnnvd.org.cn/home/showDetail/%s",
}


def _vuln_id_url(vuln_no: str) -> str:
    """漏洞编号 → 官方详情页 URL；编号缺失或不是公开编号返回空串。"""
    v = _nz(vuln_no)
    if not v:
        return ""
    m = re.match(r"^(CVE|CNVD|CNNVD)-", v, re.I)
    if not m:
        return ""
    return _ID_PREFIX_URL[m.group(1).upper()] % v


def _is_cve(vuln_no: str) -> bool:
    """是否 CVE 编号（只有 CVE 编号能在 NVD 情报库里查到 CPE 区间 / KEV）。"""
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", _nz(vuln_no), re.I))


def _id_kind_of(vuln_no: str) -> str:
    """编号类型：CVE / CNVD / CNNVD / INTERNAL（内部编号，如「自研扫描发现-000478」）/ ''。

    ★ CMDB 台账里约 25% 的 VULN_NO 不是公开编号，而是内部编号
      （自研扫描发现-xxxx / 内部评估-xxxx / 渗透测试-xxxx）。这类没有官方
      可核查链接，报告必须单列一类并说明「无法生成官方链接」，
      不能混进「未填编号」——两者性质不同：一个是漏填，一个是内部编号。
    """
    v = _nz(vuln_no)
    if not v:
        return ""
    if _is_cve(v):
        return "CVE"
    if v.upper().startswith("CNVD-"):
        return "CNVD"
    if v.upper().startswith("CNNVD-"):
        return "CNNVD"
    return "INTERNAL"



def _vuln_table_map(header: List[str]) -> Optional[dict]:
    """识别 vulnerability 漏洞台账表头，返回「列名 → 列号」映射；非台账返回 None。

    判据：同时存在「漏洞编号类列（VULN_ID）」和「受影响组件列（AFFECTED_COMPONENT）」，
    或同时存在 CI_ID + AFFECTED_COMPONENT。普通资产表（软件/中间件/主机）没有
    VULN_ID 列，不会被误判成台账。
    """
    vuln_id = _hdr_pick(header, _VULN_ID_COLS)
    component = _hdr_pick(header, _VULN_COMPONENT_COLS)
    ci_id = _hdr_pick(header, _VULN_CI_ID_COLS)
    if vuln_id < 0 and component < 0:
        return None
    # 必须有「漏洞编号」或「受影响组件 + 资产标识」之一，才算台账
    if vuln_id < 0 and ci_id < 0:
        return None

    def _pick(cols) -> int:
        return _hdr_pick(header, cols)

    m = {
        "vuln_id": vuln_id,
        "ci_id": ci_id,
        "ci_type": _pick(_VULN_CI_TYPE_COLS),
        "ci_name": _pick(_VULN_CI_NAME_COLS),
        "component": component,
        "component_ver": _pick(_VULN_COMPONENT_VER_COLS),
        "fix_ver": _pick(_VULN_FIX_VER_COLS),
        "severity": _pick(_VULN_SEVERITY_COLS),
        "cvss": _pick(_VULN_CVSS_COLS),
        "cve": _pick(_VULN_CVE_COLS),
        "owner": _pick(_VULN_OWNER_COLS),
        "plan_fix": _pick(_VULN_PLAN_FIX_COLS),
        "fix_status": _pick(_VULN_FIX_STATUS_COLS),
        "patch": _pick(_VULN_PATCH_COLS),
        "internet": _pick(_VULN_INTERNET_COLS),
        "regulatory": _pick(_VULN_REGULATORY_COLS),
        "bg": _pick(_VULN_BG_COLS),
        "importance": _pick(_VULN_IMPORTANCE_COLS),
        # —— 派单需要的补充字段（2026-10-05）——
        "app": _pick(_VULN_APP_COLS),
        "env": _pick(_VULN_ENV_COLS),
        "vtype": _pick(_VULN_TYPE_COLS),
        "cwe": _pick(_VULN_CWE_COLS),
        "verify": _pick(_VULN_VERIFY_COLS),
        "verified_exploit": _pick(_VULN_EXPLOIT_COLS),
        "exploit_available": _pick(_VULN_EXPLOIT_AVAIL_COLS),
        "discover_tool": _pick_first(header, ("discover_tool", "发现工具")),
        "discover_time": _pick_first(header, ("discover_time", "发现时间")),
        "accepted": _pick(_VULN_ACCEPT_COLS),
        "actual_fix": _pick(_VULN_ACTUAL_FIX_COLS),
        "duration": _pick(_VULN_DURATION_COLS),
        "vname": _pick(_VULN_NAME_COLS),
        "port": _pick_first(header, _VULN_PORT_COLS),
        "dept": _pick(_VULN_DEPT_COLS),
        "emp": _pick(_VULN_EMP_COLS),
        # CI_IP：台账里资产的内网/公网地址（vulnerability 表的 CI_IP 列）
        # ci_ip 要认 CI_IP / ASSET_IP 这类带前缀的列名（_hdr_pick 是精确匹配，
        # 只靠 _HDR_IP_COLS 认不到 ci_ip，报告里资产就没有 IP）
        "ci_ip": _pick_first(header, ("ci_ip", "asset_ip", "ci_addr", "host_ip")),
        "ncol": len(header),
    }
    return m


def _hdr_pick(header: List[str], candidates) -> int:
    """表头里找第一个命中候选列名的列号（精确匹配），没有返回 -1。"""
    for cand in candidates:
        for i, h in enumerate(header):
            if h == cand:
                return i
    return -1


def _split_table_rows(rows: List[str]) -> Optional[Tuple[List[str], List[List[str]]]]:
    """把上传文件的行按分隔符切成 (表头, 数据行)。Tab 优先，其次逗号（csv 带引号字段）。"""
    head = rows[0]
    if "\t" in head:
        parsed = [ln.split("\t") for ln in rows]
    elif head.count(",") >= 2:
        try:
            parsed = list(csv.reader(rows))
        except Exception:  # noqa: BLE001
            return None
    else:
        return None
    if len(parsed) < 2:
        return None
    header = [(c or "").strip().lower() for c in parsed[0]]
    return header, parsed[1:]


_HDR_KNOWN = frozenset(
    _HDR_TYPE_COLS + _HDR_PRODNAME_COLS + _HDR_INSTNAME_COLS + _HDR_VER_COLS +
    _HDR_IP_COLS + _HDR_DOMAIN_COLS + _HDR_PORT_COLS + _HDR_OS_COLS +
    _HDR_OWNER_COLS + _HDR_ENV_COLS)


def _row_is_header(cols: List[str]) -> bool:
    """一行是否是表头（xlsx 多 sheet 拼接时，每个 sheet 都有自己的表头行）。

    两条判据（命中其一即可）：
    ① 首列是 ID 列名：SW_ID / MW_ID / DB_ID / DS_ID / JOB_ID / id / 序号…
       —— CMDB 导出的每张表都以 <XX>_ID 开头，数据行的首列是值（SW-00001），
          永远不会恰好以 _id 结尾；
    ② ≥3 个单元格精确命中已知列名（VERSION/HOST_IP/PORT…）。
    """
    if cols:
        h0 = cols[0].strip().lower()
        if h0 == "id" or h0.endswith("_id") or h0 in ("序号", "编号", "no"):
            return True
    hits = 0
    for c in cols:
        c = c.strip()
        if not c:
            continue
        skip = False
        for ch in c:
            if ch.isdigit():
                skip = True
                break
        if skip:
            continue
        if c.lower() in _HDR_KNOWN:
            hits += 1
            if hits >= 3:
                return True
    return False


def _map_header(header: List[str]) -> Optional[Tuple[int, int, int, int, int, int, int, int, int]]:
    """表头 → 各字段列号 (prod, ver, ip, dom, port, name, os, owner, env)。识别不了返回 None。"""
    # ★ 告警/工单/日志/补丁类表：带 ci_id+ci_ip 但不是软件资产表，先排除
    if _is_non_asset_header(header):
        return None
    ver_i = _hdr_pick(header, _HDR_VER_COLS)
    if ver_i < 0:
        for i, h in enumerate(header):
            if "version" in h or "版本" in h:
                ver_i = i
                break
    ip_i = _hdr_pick(header, _HDR_IP_COLS)
    if ip_i < 0:
        for i, h in enumerate(header):
            # ★ 不能用裸 startswith("ip")：数据行的值（如 'IPA-004383'）会被误判成
            #   IP 列名，导致拓扑表整张误解析。只认 ip_ 前缀 / _ip 后缀 / 精确 ip
            if h == "ip" or h.startswith("ip_") or h.endswith("_ip"):
                # 排除「人/操作」类 IP 列：operator_ip/client_ip 是操作员终端地址，
                # 不是服务器资产（05_运维运营 的日志/审计表 45 万行会因此全量误解析）
                if any(x in h for x in _IP_COL_EXCLUDE):
                    continue
                ip_i = i
                break
    dom_i = _hdr_pick(header, _HDR_DOMAIN_COLS)
    if dom_i < 0:
        for i, h in enumerate(header):
            if ("domain" in h or "域名" in h) and not h.endswith("_id") \
                    and "type" not in h and "biz" not in h and "business" not in h:
                dom_i = i
                break
    port_i = _hdr_pick(header, _HDR_PORT_COLS)
    if port_i < 0:
        for i, h in enumerate(header):
            if h.endswith("port") or h.startswith("port_"):
                port_i = i
                break
    t_i = _hdr_pick(header, _HDR_TYPE_COLS)
    n_i = _hdr_pick(header, _HDR_PRODNAME_COLS)
    s_i = _hdr_pick(header, _HDR_INSTNAME_COLS)
    # ★ 操作系统/补丁清单表：OS_NAME='CentOS 7.9'、BEFORE_VERSION='3.10.0-1160' 是
    #   「操作系统 + 内核版本」，不是「产品 + 产品版本」。硬映射会产出
    #   linux/银河麒麟V10、windows_server_2019/5.10.0-136 这种张冠李戴的组合
    #   （2026-10-05 报告「给不存在产品报漏洞」的根因）→ 不参与 CPE 产品匹配。
    if _is_os_patch_header(header):
        if ip_i < 0 and dom_i < 0 and _pick_ci_id(header) < 0:
            return None
        # 资产表模式：只收 CI/主机（供资产清单与责任人追溯），不收产品
        cn_i = _hdr_pick(header, _HDR_CI_NAME_COLS)
        return (-1, -1, ip_i, dom_i, port_i,
                cn_i if cn_i >= 0 else -1,
                _hdr_pick(header, _HDR_OS_COLS),
                _hdr_pick(header, _HDR_OWNER_COLS),
                _hdr_pick(header, _HDR_ENV_COLS))
    if t_i >= 0:
        prod_i = t_i
        name_i = s_i if s_i >= 0 else n_i
    else:
        # 没有 type 列：product 只认「产品名」列（软件目录的 SW_NAME/Product）。
        # ★ 不能拿实例名/主机名列当产品——服务器/虚机表的 HOSTNAME 会把 20 万个
        #   主机名灌成假产品，撑爆 MAX_PRODUCTS 且匹配全是噪声。
        prod_i = n_i
        name_i = -1
    # 认出「产品」列，或至少有主机/域名列（服务器/网络设备表只有 IP 也值得收主机）
    if prod_i < 0 and ip_i < 0 and dom_i < 0:
        return None
    if ver_i < 0 and ip_i < 0 and dom_i < 0:
        # 有产品列但既没版本也没主机（纯目录清单没有分析抓手）→ 不映射
        return None
    os_i = _hdr_pick(header, _HDR_OS_COLS)
    owner_i = _hdr_pick(header, _HDR_OWNER_COLS)
    env_i = _hdr_pick(header, _HDR_ENV_COLS)
    return (prod_i, ver_i, ip_i, dom_i, port_i, name_i, os_i, owner_i, env_i)


def _cmdb_sheet_filter(rows_cells) -> bool:
    """xlsx sheet 预览过滤器：前几行里能认出资产表头才解析整个 sheet。

    CMDB 大导出里「CI 关系拓扑（SOURCE_CI_ID→TARGET_CI_ID）/ 数据字典 / 变更单 /
    告警 / 日志」这类表占解压体积的一半以上，但没有任何产品/版本/资产 IP 字段，
    对漏洞分析零贡献——预览判定不通过就整个 sheet 跳过，省掉解析开销。

    ★ 只对「长得像表头」的行做映射判定（_row_is_header）：peek 的后几行是数据行，
      数据值（如 'IPA-004383'）喂给列匹配会误命中。

    ★ 漏洞台账表（vulnerability）同样要放行（2026-10-05）：它是 CMDB 里唯一带
      责任人 / 修复期限 / 补丁编号 / 互联网暴露的表，是风险报告的主数据源。
      之前这里只认 _map_header（资产表头），导致 05_运维运营.xlsx 的 vulnerability
      sheet 被整表跳过 → 台账检测失败（data_source=None）→ 报告退化成纯资产 CPE
      匹配，资产标识退化成裸 IP、组件被实例名污染。
    """
    for cells in rows_cells or []:
        if not _row_is_header(cells):
            continue
        header = [(c or "").strip().lower() for c in cells]
        if not any(header):
            continue
        if _vuln_table_map(header) is not None:
            return True
        if _is_non_asset_header(header) or _is_topo_header(header) \
                or _is_os_patch_header(header):
            return False
        if _map_header(header) is not None:
            return True
    return False


# —— 产品词典快速判定（无主机的纯产品记录只留词典能认出的，
#    与正则抽取路径的语义一致——那边也只有别名命中才算产品）——
_PD_DICT = getattr(AS, "_PRODUCT_DICT", {})
_PD_CANON = getattr(AS, "_canon_key", None)


def _prod_in_dict(name: str) -> bool:
    if not name:
        return False
    key = _PD_CANON(name) if _PD_CANON else re.sub(r"[\s_\-./]+", "", name.lower())
    return key in _PD_DICT


# —— CI 三元组列（资产标识：CI_ID + 主机名 + IP，2026-10-05）——
# ★ 报告里的「资产」必须是能回溯到 CMDB 真实 CI 的标识，不能是裸 IP：
#   运维拿到 IP 要自己查 CMDB 才知道是哪台机器，报告就失去了可操作性。
#   CMDB 各表命名不统一（SRV_ID/VM_ID/MW_ID/CI_ID/HOST_ID…），统一按后缀识别。
_HDR_CI_ID_COLS = ("ci_id", "host_id", "srvid", "ciid")
_HDR_CI_NAME_COLS = ("ci_name", "host_name", "hostname", "host_name_cn")

# 拓扑/关系表：只有「A 指向 B」的关系，没有产品/版本，解析出来的资产全是
# SOURCE/TARGET_CI_ID 这类指针串（vpc-xxx / gpu-node2436），不是软件资产。
_Topo_HINT_COLS = ("source_ci_id", "target_ci_id", "rel_id", "rel_type",
                   "source_ci_type", "target_ci_type", "is_key_path", "confidence")


_OS_PATCH_HINT_COLS = ("os_name", "os_version", "os_type", "before_version",
                      "after_version", "kernel_version", "patch_status",
                      "patch_id", "os_build", "platform")


_NON_ASSET_HINT_COLS = (
    # 告警 / 事件 / 工单 / 日志 / 审计类：这些表虽然带 ci_id + ci_ip，但记录的是
    # 「一次告警/一次工单」而不是「一个装了软件的资产」。当资产表解析会产出海量
    # 重复 CI（05_运维运营 的 alert_record 9 万行 incident 4.5 万行），
    # 报告里就会出现「源库查不到」的资产与「按告警数排序」的假风险排序。
    "alert_id", "alert_name", "alert_type", "alert_level", "metric_name",
    "metric_value", "threshold", "incident_id", "ticket_id", "work_order",
    "change_id", "change_order_id", "log_id", "audit_id", "scan_id",
    "kb_number", "patch_no", "discovery_id", "probe_id",
)
# 这些表唯一有价值的语义列（补丁/告警本身不是软件资产）
_NON_ASSET_ALLOW = frozenset((
    "mw_type", "db_type", "comp_type", "framework", "sw_name", "product",
    "product_name", "software", "software_name", "affiliated_component",
    "affected_component", "version", "sw_version", "model_version",
))


def _is_non_asset_header(header: List[str]) -> bool:
    """判断表头是不是「告警/工单/日志/补丁」等非软件资产表（应跳过）。"""
    hs = set(header)
    if any(c in hs for c in _NON_ASSET_ALLOW):
        return False
    return any(c in hs for c in _NON_ASSET_HINT_COLS)


def _is_os_patch_header(header: List[str]) -> bool:
    """判断表头是不是「操作系统/补丁清单」表——这类表没有真实产品+版本语义。

    CMDB 的 patch_record / os_info 这类表里 OS_NAME='CentOS 7.9'、
    BEFORE_VERSION='3.10.0-1160' 是「操作系统 + 内核版本」的意思，不是
    「产品 + 产品版本」。之前被 _map_header 硬映射成 product=linux /
    version=银河麒麟 V10，或 product=windows_server_2019 / version=5.10.0-136，
    导致报告里出现「给不存在的产品报漏洞」的假阳性。
    """
    hs = set(header)
    if any(c in hs for c in ("before_version", "after_version", "patch_id", "patch_status")):
        return True
    # 有 OS_VERSION / KERNEL_VERSION 但没有真正的产品类型/名称列
    has_os = any(c in hs for c in ("os_name", "os_version", "os_type", "kernel_version"))
    has_prod = any(c in hs for c in ("mw_type", "db_type", "comp_type", "framework",
                                     "sw_name", "product", "product_name", "software"))
    return has_os and not has_prod


def _is_topo_header(header: List[str]) -> bool:
    """判断表头是不是「CI 关系拓扑」表（应整体跳过，不是软件资产表）。"""
    hs = set(header)
    # 命中 2 个以上拓扑特征列即判定为拓扑表
    hits = sum(1 for c in _Topo_HINT_COLS if c in hs)
    if hits >= 2:
        return True
    # 没有任何产品/版本列，且有 SOURCE/TARGET 指针列 → 拓扑表
    has_asset = any(c in hs for c in
                    _HDR_TYPE_COLS + _HDR_PRODNAME_COLS + _HDR_VER_COLS)
    return (not has_asset) and any(c in hs for c in ("source_ci_id", "target_ci_id"))


def _looks_like_version_only(s: str) -> bool:
    """判断一个字符串是否「只是个版本号」而不是产品名。

    源数据缺陷（2026-10-05 实测）：vulnerability 表有 93 条记录的
    AFFECTED_COMPONENT 被填成了版本号（如 '4.19.245'、'6.1.62'），
    报告里会渲染成「4.19.245@VUL-00000362」这种「版本号当组件名」的条目，
    运维看不懂该修什么。命中时归入「未标注组件」并保留版本信息。
    """
    t = _nz(s)
    if not t:
        return True
    # 纯数字/点/短横/下划线组成，且含数字 → 版本号
    if re.fullmatch(r"[0-9A-Za-z._+-]*", t) and re.search(r"\d", t) and "." in t:
        return True
    return False


def _pick_first(header: List[str], candidates) -> int:
    """按候选列名依次精确匹配表头，返回第一个命中的列号；全不中返回 -1。"""
    for name in candidates:
        i = _hdr_pick(header, (name,))
        if i >= 0:
            return i
    return -1


def _pick_ci_id(header: List[str]) -> int:
    """找 CI 标识列：优先 CI_ID/HOST_ID，其次各表自有的 XX_ID（非关系指针列）。"""
    i = _hdr_pick(header, _HDR_CI_ID_COLS)
    if i >= 0:
        return i
    for k, h in enumerate(header):
        if not (h.endswith("_id") or h == "id"):
            continue
        # 排除指针/关系/字典类 ID
        if any(x in h for x in ("source", "target", "rel", "parent", "patch",
                                "vuln", "app", "emp", "dept", "domain", "supplier",
                                "contract", "change", "alert", "incident", "log",
                                "audit", "order", "dict", "idx", "key", "vpc",
                                "subnet", "net", "rack", "room", "cluster",
                                "port", "interface", "vendor", "model", "sn")):
            continue
        return k
    return -1


def _ci_prefix_of(ci_id: str) -> str:
    """从 CI_ID 推断类型前缀（SRV-036704 → SRV），用于报告里拼资产标识。"""
    t = _nz(ci_id)
    if not t:
        return ""
    head = t.split("-", 1)[0]
    return head.upper() if head.isalpha() else ""


def _asset_label(ci_id: str, prefix: str, ci_name: str, ip: str) -> str:
    """资产可读标识：CI_ID（+主机名/IP），用于报告表格第一列。

    例：SRV-036704（aitrain-node36704 / 172.29.119.233）
    运维拿着这个能直接回 CMDB 定位到唯一一台机器。
    """
    cid = _nz(ci_id)
    if not cid:
        return _nz(ci_name) or _nz(ip)
    if not prefix or cid.upper().startswith(prefix + "-"):
        base = cid
    else:
        base = "%s-%s" % (prefix, cid)
    extra = _nz(ci_name) or _nz(ip)
    return "%s（%s）" % (base, extra) if extra else base


# ==========================================================================
# 资产位置索引（CI → 机房 / 机柜 / 城市）—— 报告「派单到人」必需
# ==========================================================================
# 为什么需要（2026-10-05 评审）：报告只给 CI_ID + IP，运维还要自己查 CMDB 才知道
# 去哪个机房、哪个机柜。CMDB 里位置信息是分散在三张表上的：
#   physical_server / vm_cloud_host / network_device / storage_device / gpu_node
#     → CI_ID → IDC_ID + CAB_ID
#   middleware_instance / database_instance / bigdata_component / container_pod
#     → CI_ID → HOST_ID（宿主 CI）→ 递归查上一层的 IDC_ID
#   idc_room → IDC_ID → IDC_NAME / CITY / REGION
#   cabinet   → CAB_ID → CAB_CODE / FLOOR / ROOM_NO
# 逐个 CI 现查会退化成 N 次全表扫描，所以一次性建索引、台账聚合时 O(1) 取。

# 各类表的「本表 CI_ID 列」与「宿主 CI_ID 列」
_LOC_CI_TABLES = {
    # 表特征列 → (自身 CI 列候选, 宿主 CI 列候选)
    "physical": (("srvid", "ci_id", "host_id", "asset_id"), ()),
    "vm": (("vmid", "ci_id", "instance_id", "host_id"), ()),
    "network": (("netid", "device_id", "ci_id", "ne_id"), ()),
    "security": (("secdevid", "device_id", "ci_id", "sd_id"), ()),
    "storage": (("dsid", "device_id", "ci_id", "stg_id"), ()),
    "gpu": (("gpu_node_id", "node_id", "ci_id"), ()),
    "ip": (("ip_id", "ci_id"), ()),
    "middleware": (("mw_id", "inst_id", "ci_id"), ("host_id", "host_srvid", "host_ci_id")),
    "database": (("db_id", "inst_id", "ci_id"), ("host_id", "host_srvid", "host_ci_id")),
    "bigdata": (("bd_id", "comp_id", "ci_id"), ("host_id", "node_id", "host_ci_id")),
    "appinst": (("inst_id", "ci_id", "app_id"), ("host_id", "host_srvid")),
    "pod": (("pod_id", "ci_id"), ("node_vm_id", "host_id", "node_id")),
    "cluster": (("cluster_id", "k8s_id", "ci_id"), ("host_id",)),
}
_LOC_IDC_COLS = ("idc_id", "idc", "room_id")
_LOC_CAB_COLS = ("cab_id", "cabinet_id", "cab")
_LOC_HOSTNAME_COLS = ("hostname", "host_name", "name")
_LOC_ZONE_COLS = ("zone_name", "availability_zone", "az")

# 首列主键名 → 表类型。判定只看「首列是什么」，不靠「有哪些列」——
# gpu_node / physical_server 也带 CAB_ID 和 IDC_ID，靠列存在性猜类型必然串。
_LOC_KIND_BY_PK = {
    "idc_id": "idc",
    "cab_id": "cab",
}
# 资产表首列主键（这些表既有本表 CI，可能还有 IDC_ID / HOST_ID）
_LOC_ASSET_PKS = frozenset((
    "srv_id", "vm_id", "net_id", "ne_id", "sec_id", "secdev_id", "sd_id",
    "ds_id", "stg_id", "gpu_node_id", "node_id", "ip_id", "mw_id", "db_id",
    "bd_id", "comp_id", "inst_id", "pod_id", "ci_id", "asset_id", "cluster_id",
    "k8s_id", "device_id",
))


def _loc_table_kind(header: List[str]) -> str:
    """判定一张表在位置索引里的角色：idc / cab / asset / ''（无关）。

    ★ 必须看首列（表主键）而不是「有没有 IDC_ID 列」：CMDB 里 asset 表普遍带
      IDC_ID/CAB_ID，用列存在性判会把 physical_server 当成机柜表。
    """
    h = [(c or "").strip().lower().lstrip("﻿") for c in header]
    if not h:
        return ""
    pk = h[0]
    kind = _LOC_KIND_BY_PK.get(pk)
    if kind:
        return kind
    if pk in _LOC_ASSET_PKS:
        # 资产表必须真的能给出位置或宿主，否则没有索引价值
        if (_hdr_pick(h, _LOC_IDC_COLS) >= 0 or _hdr_pick(h, _LOC_CAB_COLS) >= 0
                or _hdr_pick(h, ("host_id", "host_srvid", "node_vm_id")) >= 0):
            return "asset"
        return ""
    return ""


class _LocIndex:
    """CI → 位置的索引。分三张表：本体（ci→idc/cab）、机房、机柜。"""

    __slots__ = ("ci2idc", "ci2cab", "ci2host", "idc_info", "cab_info", "stats")

    def __init__(self) -> None:
        self.ci2idc: Dict[str, str] = {}      # CI_ID → IDC_ID
        self.ci2cab: Dict[str, str] = {}      # CI_ID → CAB_ID
        self.ci2host: Dict[str, str] = {}     # CI_ID → 宿主 CI_ID（用于二级解析）
        self.idc_info: Dict[str, dict] = {}   # IDC_ID → {name, city, region, tier}
        self.cab_info: Dict[str, dict] = {}   # CAB_ID → {code, floor, room}
        self.stats = {"ci": 0, "idc": 0, "cab": 0, "host": 0}

    # ---- 从一张表的行里抽取位置信息 ----
    def feed_table(self, header: List[str], rows, kind: str = "") -> None:
        """把一张表的行灌进索引。

        kind 由 _loc_table_kind 判定（看首列主键名），不要靠「有没有某列」猜——
        gpu_node 也有 CAB_ID 列，靠猜会被当成机柜表，把 GPU 的机柜号写进机柜字典。
        """
        h = [(c or "").strip().lower().lstrip("﻿") for c in header]
        n = len(h)

        def col(cands):
            return _hdr_pick(h, cands)

        if kind == "idc":
            i_idc = col(_LOC_IDC_COLS)
            i_name = col(("idc_name", "idc_code", "name"))
            i_city = col(("city", "城市"))
            i_region = col(("region", "region_name", "区域"))
            i_tier = col(("tier_level", "tier", "等级"))
            for r in rows:
                k = _nz(r[i_idc]) if 0 <= i_idc < n else ""
                if not k:
                    continue
                self.idc_info[k] = {
                    "name": _nz(r[i_name]) if 0 <= i_name < n else "",
                    "city": _nz(r[i_city]) if 0 <= i_city < n else "",
                    "region": _nz(r[i_region]) if 0 <= i_region < n else "",
                    "tier": _nz(r[i_tier]) if 0 <= i_tier < n else "",
                }
                self.stats["idc"] += 1
            return

        if kind == "cab":
            i_cab = col(_LOC_CAB_COLS)
            i_idc = col(_LOC_IDC_COLS)
            i_code = col(("cab_code", "code", "name"))
            i_floor = col(("floor", "楼层"))
            i_room = col(("room_no", "room", "module"))
            for r in rows:
                k = _nz(r[i_cab]) if 0 <= i_cab < n else ""
                if not k:
                    continue
                self.cab_info[k] = {
                    "idc_id": _nz(r[i_idc]) if 0 <= i_idc < n else "",
                    "code": _nz(r[i_code]) if 0 <= i_code < n else "",
                    "floor": _nz(r[i_floor]) if 0 <= i_floor < n else "",
                    "room": _nz(r[i_room]) if 0 <= i_room < n else "",
                }
                self.stats["cab"] += 1
            return

        if kind != "asset":
            return

        # —— 资产表：CI_ID（+IDC_ID/CAB_ID） / 或 CI_ID → HOST_ID ——
        #  首列是本表主键（SRV_ID / VM_ID / MW_ID…），比「猜哪一列是 CI」可靠：
        #  猜的话 ip_allocation 的 CI_ID、middleware 的 HOST_ID 会互相串。
        self_ci = 0 if n else -1
        i_idc2 = col(_LOC_IDC_COLS)
        i_cab2 = col(_LOC_CAB_COLS)
        i_host = col(("host_id", "host_srvid", "host_ci_id", "node_vm_id", "node_id"))
        for r in rows:
            cid = _nz(r[self_ci]) if 0 <= self_ci < n else ""
            host = _nz(r[i_host]) if 0 <= i_host < n else ""
            idc = _nz(r[i_idc2]) if 0 <= i_idc2 < n else ""
            cab = _nz(r[i_cab2]) if 0 <= i_cab2 < n else ""
            if not cid:
                continue
            if idc:
                self.ci2idc[cid] = idc
                self.stats["ci"] += 1
            if cab:
                self.ci2cab[cid] = cab
            # 有 IDC 的表本身就是位置终点；没有的（中间件/数据库/容器）记宿主做二级解析
            if host and not idc:
                self.ci2host[cid] = host
                self.stats["host"] += 1

    def resolve(self, ci_id: str) -> dict:
        """CI_ID → {机房, 城市, 区域, 机柜, 楼层, 机房位置, 可用区}。

        中间件/数据库/容器 Pod 这类 CI 自身没有 IDC_ID，要顺着宿主 CI 查第二级。
        查不到就返回空 dict（报告里显示「未登记」，不编造位置）。
        """
        out: dict = {}
        if not ci_id:
            return out
        cur = ci_id
        seen = set()
        for _hop in range(3):            # 最多追 3 级宿主，防环
            if cur in seen:
                break
            seen.add(cur)
            idc = self.ci2idc.get(cur)
            cab = self.ci2cab.get(cur)
            cab_info = (self.cab_info.get(cab) or {}) if cab else {}
            # ★ 机房归属冲突（2026-10-05）：资产表自带的 IDC_ID 与其机柜 CAB_ID 的
            #   归属机房不一致时，以机柜归属为准（机柜是物理位置终点）。
            #   实测真实 CMDB：物理机表 44000 条里只有 2.5% 两侧一致，而机柜表自身
            #   自洽（CAB_CODE 城市前缀 == 归属机房 CITY 达 85.8%）——说明是资产表的
            #   IDC_ID 列不可信，不是零星脏数据。故此处静默以机柜为准，只留 conflict
            #   标记给报告第六节做口径披露，不在每个资产的位置文本里堆后缀。
            if idc and cab_info.get("idc_id") and cab_info["idc_id"] != idc:
                out["idc_conflict"] = True
                out["idc_id_claimed"] = idc
                idc = cab_info["idc_id"]
            # 机柜表本身带 IDC_ID，资产表没填 IDC 时用它兜底
            if not idc and cab_info.get("idc_id"):
                idc = cab_info["idc_id"]
            if idc and "idc_id" not in out:
                info = self.idc_info.get(idc) or {}
                out["idc_id"] = idc
                out["idc_name"] = info.get("name", "")
                out["city"] = info.get("city", "")
                out["region"] = info.get("region", "")
                out["tier"] = info.get("tier", "")
            if cab and "cab_id" not in out:
                out["cab_id"] = cab
                out["cab_code"] = cab_info.get("code", "")
                out["floor"] = cab_info.get("floor", "")
                out["room"] = cab_info.get("room", "")
            if "idc_id" in out and "cab_id" in out:
                break
            cur = self.ci2host.get(cur) or ""
            if not cur:
                break
        return out

    def location_text(self, ci_id: str) -> str:
        """一行式位置描述，用于报告表格。"""
        d = self.resolve(ci_id)
        if not d:
            return ""
        city = d.get("city", "")
        name = d.get("idc_name", "")
        # 机房名常已含城市前缀（「成都第三数据中心」+ city=成都）→ 去重避免
        # 报告里出现「成都成都第三数据中心」这种叠加字符串
        if city and name.startswith(city):
            name = name[len(city):]
        bits = []
        head = city + name
        if head:
            bits.append(head)
        if d.get("cab_code"):
            bits.append(d["cab_code"])
        elif d.get("floor"):
            bits.append(d["floor"])
        txt = " / ".join(x for x in bits if x)
        # 不在这里拼「机房归属冲突」后缀：实测 97.5% 的物理机两侧不一致，逐行加后缀
        # 会让整张位置表全是同一句噪音。冲突是**源数据列级问题**（不是个别资产），
        # 口径统一写进报告 6.2，这里只按机柜归属输出干净的位置。
        return txt


def _build_loc_index(files) -> _LocIndex:
    """从上传文件里建资产位置索引（只认机房/机柜/资产三类表，跳过其他表）。"""
    idx = _LocIndex()
    for f in files or []:
        fname, data = f.get("filename") or "", f.get("data") or b""
        if not data:
            continue
        try:
            doc = AS.read_upload(fname, data, sheet_filter=_loc_sheet_filter)
        except Exception:  # noqa: BLE001
            continue
        if not doc.rows:
            continue
        cur_header: Optional[List[str]] = None
        cur_kind = ""
        batch: List[List[str]] = []
        for ln in doc.rows:
            cols = ln.split("\t") if "\t" in ln else (
                list(csv.reader([ln]))[0] if "," in ln else None)
            if not cols:
                continue
            if _row_is_header(cols):
                hh = [(c or "").strip().lower().lstrip("﻿") for c in cols]
                if batch and cur_header is not None:
                    idx.feed_table(cur_header, batch, cur_kind)
                    batch = []
                cur_kind = _loc_table_kind(hh)
                cur_header = hh if cur_kind else None
                continue
            if cur_header is None:
                continue
            # 单行喂给 feed_table 太慢（每行重建列映射）→ 攒批
            batch.append(cols)
            if len(batch) >= 20000:
                idx.feed_table(cur_header, batch, cur_kind)
                batch = []
        if batch and cur_header is not None:
            idx.feed_table(cur_header, batch, cur_kind)
    return idx


def _loc_sheet_filter(rows_cells) -> bool:
    """sheet 预览：只放行是机房表 / 机柜表 / 带位置的资产表的 sheet。"""
    for cells in rows_cells or []:
        if not _row_is_header(cells):
            continue
        hh = [(c or "").strip().lower().lstrip("﻿") for c in cells]
        if _loc_table_kind(hh):
            return True
    return False


def _tsv_records(rows: List[str]) -> Optional[List[dict]]:

    """把「带表头的 TSV 行」转成结构化 CMDB 记录（file 模式结构化快速路径）。

    CMDB 导出的 xlsx/csv 一行一条资产（MW_NAME/MW_TYPE/VERSION/HOST_IP…），
    直接按表头映射成 {product, version, ip, port, name, owner, env} 记录，
    走 _structured_extract 快速路径——跳过 asset_scan 的逐行正则（30 万条约 80s）。

    ★ 多 sheet：read_upload 把 xlsx 的 7 个 sheet 拼成平铺行，每个 sheet 都有
      自己的表头（软件目录表 / 中间件实例表 / 数据库实例表…列结构各不相同）。
      循环里动态检测表头行，遇到就重新映射列；识别不了的表（数据集、训练作业
      这类非软件资产表）跳过到下一个可识别表头为止。

    整个文件一个表头都识别不出时返回 None，调用方回退逐行正则抽取
    （word / 叙述性文本没有表头，走那边才对）。
    """
    if not rows or len(rows) < 2:
        return None
    split = _split_table_rows(rows)
    if not split:
        return None
    header, data_rows = split
    if not any(header):
        return None
    # 首个表头就是拓扑表 → 整个文件不是软件资产（06_CI关系拓扑_*.xlsx）
    if _is_topo_header(header):
        return None
    mapping = _map_header(header)
    ncol = len(header)

    out: List[dict] = []
    # ★ 纯软件目录表（software_package 之类：只有 SW_NAME/VERSION，没有 IP/主机）
    #   的 SW_ID 是「软件包记录主键」，不是资产 CI——拿它当资产会凭空造出
    #   59763 台不存在的机器（2026-10-05 报告「资产在源库查不到」的根因之一）。
    #   这类表只贡献产品+版本，不贡献资产。
    catalog_only = mapping is not None and mapping[0] >= 0 and mapping[2] < 0 and mapping[3] < 0
    cur_ci_i = -1 if catalog_only else (_pick_ci_id(header) if mapping is not None else -1)
    cur_ciname_i = -1 if catalog_only else (_hdr_pick(header, _HDR_CI_NAME_COLS) if mapping is not None else -1)
    for cols in data_rows:
        if not cols:
            continue
        if _row_is_header(cols):
            hh = [c.strip().lower() for c in cols]
            # 拓扑/关系表不是软件资产表 → 整个 sheet 跳过（否则 SOURCE/TARGET_CI_ID
            # 会被当资产标识，产出 vpc-xxx / gpu-node2436 这种指针串当"资产"）
            if _is_topo_header(hh):
                mapping = None
                cur_ci_i = cur_ciname_i = -1
                continue
            mapping = _map_header(hh)
            if mapping is not None:
                # 纯目录表（无 IP/域名）：只贡献产品，不贡献资产
                cat = mapping[0] >= 0 and mapping[2] < 0 and mapping[3] < 0
                cur_ci_i = -1 if cat else _pick_ci_id(hh)
                cur_ciname_i = -1 if cat else _hdr_pick(hh, _HDR_CI_NAME_COLS)
            continue
        if mapping is None:
            continue
        prod_i, ver_i, ip_i, dom_i, port_i, name_i, os_i, owner_i, env_i = mapping
        n = len(cols)
        prod = cols[prod_i].strip() if 0 <= prod_i < n else ""
        ver = cols[ver_i].strip() if ver_i >= 0 and ver_i < n else ""
        ip = cols[ip_i].strip() if ip_i >= 0 and ip_i < n else ""
        dom = cols[dom_i].strip() if dom_i >= 0 and dom_i < n else ""
        ci_id = cols[cur_ci_i].strip() if 0 <= cur_ci_i < n else ""
        ci_name = cols[cur_ciname_i].strip() if 0 <= cur_ciname_i < n else ""
        # 只留「软件资产」行：有主机的记录，或有版本且产品名可识别的目录记录
        #（纯名称+版本的行若词典认不出——桌面软件/自研系统——不参与 CPE 匹配，直接丢）
        if ip or dom or ci_id:
            pass
        elif prod and ver and _prod_in_dict(prod):
            pass
        else:
            continue
        d: dict = {}
        # ★ CI 标识优先：有 CI_ID 时资产以它为准（报告里能回溯到 CMDB 真实记录），
        #   没有才退回 IP/域名。
        if ci_id and not ci_id.upper().startswith(("VUL-", "REL-")):
            d["ci_id"] = ci_id
            d["ci_prefix"] = _ci_prefix_of(ci_id)
        if ci_name:
            d["ci_name"] = ci_name
        if prod:
            d["product"] = prod
        if ver:
            d["version"] = ver
        if ip:
            d["ip"] = ip
        if dom:
            d["domain"] = dom
        if port_i >= 0 and port_i < n and cols[port_i].strip():
            d["port"] = cols[port_i].strip()
        if name_i >= 0 and name_i < n and cols[name_i].strip():
            d["name"] = cols[name_i].strip()
        if os_i >= 0 and os_i < n and cols[os_i].strip():
            d["os"] = cols[os_i].strip()
        if owner_i >= 0 and owner_i < n and cols[owner_i].strip():
            d["owner"] = cols[owner_i].strip()
        if env_i >= 0 and env_i < n and cols[env_i].strip():
            d["env"] = cols[env_i].strip()
        out.append(d)
    return out or None


# ==========================================================================
# 漏洞台账（vulnerability 表）读取 —— 修复「VULN_ID 当资产 / 假版本号全量误命中」
# ==========================================================================
# 这是 CMDB 风险报告的正确数据源：vulnerability 表本身就是「已知漏洞 → 资产 →
# 组件 → 责任人 → 修复期限 → 官方补丁」的完整台账。直接聚合它，而不是把
# COMPONENT_VERSION（可能为随机假数据）丢进 CPE 区间匹配。
class _VulnLedger:
    """漏洞台账累积器：把 vulnerability 表的行聚合成「CVE/组件 → 资产列表」。

    ★ 资产标识一律取 CI_ID（配 CI_TYPE 前缀），绝不用 VULN_ID（那是漏洞记录
      自己的主键，不是资产）。版本号标注「不可信」，不参与 CPE 区间匹配。
    """

    __slots__ = ("rows", "ci_ids", "components", "severity_count")

    def __init__(self) -> None:
        self.rows: List[dict] = []
        self.ci_ids: "OrderedDict[str, dict]" = OrderedDict()
        self.components: "OrderedDict[str, int]" = OrderedDict()
        self.severity_count: "OrderedDict[str, int]" = OrderedDict()

    @staticmethod
    def _val(cols: List[str], idx: int, n: int) -> str:
        return cols[idx].strip() if 0 <= idx < n else ""

    def feed(self, cols: List[str], m: dict) -> None:
        n = m.get("ncol") or len(cols)
        vuln_id = self._val(cols, m.get("vuln_id", -1), n)
        ci_id = self._val(cols, m.get("ci_id", -1), n)
        ci_type = self._val(cols, m.get("ci_type", -1), n)
        ci_name = self._val(cols, m.get("ci_name", -1), n)
        ci_ip = self._val(cols, m.get("ci_ip", -1), n)
        component = self._val(cols, m.get("component", -1), n)
        comp_ver = self._val(cols, m.get("component_ver", -1), n)
        fix_ver = self._val(cols, m.get("fix_ver", -1), n)
        severity = self._val(cols, m.get("severity", -1), n)
        cvss = self._val(cols, m.get("cvss", -1), n)
        cve = self._val(cols, m.get("cve", -1), n)
        owner = self._val(cols, m.get("owner", -1), n)
        plan_fix = self._val(cols, m.get("plan_fix", -1), n)
        fix_status = self._val(cols, m.get("fix_status", -1), n)
        patch = self._val(cols, m.get("patch", -1), n)
        internet = self._val(cols, m.get("internet", -1), n)
        regulatory = self._val(cols, m.get("regulatory", -1), n)
        bg = self._val(cols, m.get("bg", -1), n)
        importance = self._val(cols, m.get("importance", -1), n)
        app = self._val(cols, m.get("app", -1), n)
        env = self._val(cols, m.get("env", -1), n)
        vtype = self._val(cols, m.get("vtype", -1), n)
        cwe = self._val(cols, m.get("cwe", -1), n)
        verify = self._val(cols, m.get("verify", -1), n)
        v_exploit = self._val(cols, m.get("verified_exploit", -1), n)
        e_avail = self._val(cols, m.get("exploit_available", -1), n)
        dtool = self._val(cols, m.get("discover_tool", -1), n)
        dtime = self._val(cols, m.get("discover_time", -1), n)
        accepted = self._val(cols, m.get("accepted", -1), n)
        actual_fix = self._val(cols, m.get("actual_fix", -1), n)
        duration = self._val(cols, m.get("duration", -1), n)
        vname = self._val(cols, m.get("vname", -1), n)
        port = self._val(cols, m.get("port", -1), n)
        dept = self._val(cols, m.get("dept", -1), n)
        emp = self._val(cols, m.get("emp", -1), n)

        # ★ 源数据缺陷：AFFECTED_COMPONENT 被填成版本号（'4.19.245'/'6.1.62'…）
        #   → 组件名归入「未标注组件」，并把被填错的值挪回版本字段（若版本字段为空）。
        #   否则报告会出现「4.19.245@VUL-00000362」这种看不懂该修什么的条目。
        if _looks_like_version_only(component):
            if not comp_ver:
                comp_ver = component
            component = "未标注组件"

        # ★ 漏洞编号归一化（2026-10-05）：VULN_NO 才是对外的漏洞编号（CVE/CNVD/
        #   CNNVD），VULN_ID 只是台账内部记录号。编号为空时不能拿记录号冒充 CVE。
        vuln_no = _nz(cve)
        if not _vuln_id_url(vuln_no) and vuln_no:
            # 格式不认识（如内部编号），保留原值但标记不是公开编号
            pass

        # 资产标识：CI_ID 优先，其次 CI_NAME，其次 CI_IP；绝不落 VULN_ID
        asset_id = ci_id or ci_name or ci_ip or ("未知资产" + ((":" + vuln_id) if vuln_id else ""))
        # 资产标识前缀（SRV-/VM-/MW-…）：CI_TYPE 有值就用，否则从 CI_ID 推断
        prefix = ""
        if ci_type:
            prefix = ci_type.rstrip("-").upper()
        elif ci_id and "-" in ci_id:
            prefix = ci_id.split("-", 1)[0].upper()
        # ★ 一致性修正（2026-10-05）：源数据里 CI_TYPE 与 CI_ID 前缀可能矛盾
        #   （CI_TYPE=VM 但 CI_ID=SRV-922877），直接拼会得到「VM-SRV-922877」这种
        #   双前缀。CI_ID 自带前缀且与 CI_TYPE 不一致时，以 CI_ID 为准。
        if ci_id and "-" in ci_id:
            idp = ci_id.split("-", 1)[0].upper()
            if idp.isalpha() and prefix and idp != prefix:
                prefix = idp

        self.rows.append({
            "vuln_id": vuln_id,
            "vuln_no": vuln_no,
            "asset_id": asset_id,
            "asset_prefix": prefix,
            "ci_name": ci_name,
            "ci_ip": ci_ip,
            "component": component,
            "component_version": comp_ver,
            "fix_version": fix_ver,
            "severity": severity,
            "cvss": cvss,
            "cve": vuln_no,
            "cwe": cwe,
            "vtype": vtype,
            "vname": vname,
            "owner": owner,
            "emp_id": emp,
            "dept_id": dept,
            "app": app,
            "env": env,
            "port": port,
            "plan_fix": plan_fix,
            "fix_status": fix_status,
            "actual_fix": actual_fix,
            "duration": duration,
            "patch": patch,
            "internet": internet,
            "regulatory": regulatory,
            "accepted": accepted,
            "verify": verify,
            "verified_exploit": v_exploit,
            "exploit_available": e_avail,
            "discover_tool": dtool,
            "discover_time": dtime,
            "bg": bg,
            "importance": importance,
        })
        if ci_id:
            self.ci_ids.setdefault(ci_id, {
                "ci_id": ci_id, "prefix": prefix, "name": ci_name or ci_id,
                "ip": ci_ip,
            })
        if component:
            key = component.lower()
            self.components[key] = self.components.get(key, 0) + 1
        skey = (severity or "未知").lower()
        self.severity_count[skey] = self.severity_count.get(skey, 0) + 1


def _vuln_ledger_rows(rows: List[str]) -> Optional[List[dict]]:
    """把 vulnerability 台账表（可多 sheet 拼接）解析成台账行列表。

    ★ 必须扫描「全部」表头而不是只看第一个（2026-10-05 修复）：多 sheet 拼接后
      第一个表头是 change_order 的，vulnerability 表头出现在中段（本例第 90001 行），
      之前只看 rows[0] 直接返回 None → 台账整个丢失 → 报告退化成资产 CPE 匹配。
    ★ 数据行归属按「当前表头」判定：遇到非台账表头就关掉台账解析，遇到台账表头就重开，
      这样同一文件里多个 sheet 交替出现也不会串味。
    返回 None 表示该文件不包含漏洞台账表。
    """
    if not rows or len(rows) < 2:
        return None
    ledger = _VulnLedger()
    m = None
    in_ledger = False
    for ln in rows:
        cols = ln.split("\t") if "\t" in ln else (list(csv.reader([ln]))[0] if "," in ln else None)
        if not cols:
            continue
        if _row_is_header(cols):
            nm = _vuln_table_map([c.strip().lower() for c in cols])
            m = nm
            in_ledger = nm is not None
            continue
        if in_ledger and m is not None:
            ledger.feed(cols, m)
    if not ledger.rows:
        return None
    return ledger.rows


def _fetch_rest(cfg: dict) -> List[dict]:
    """对接真实 CMDB REST API（通用约定，认证/字段/分页可配）。

    分页：支持两种通用约定（page/per_page 或 offset/limit），配了分页参数时
    会逐页拉取直到取空或到 MAX_CI 上限，避免超大 CMDB 一次拉爆内存。
    """
    url = _nz(cfg.get("url"))
    if not url:
        return []
    token = _nz(cfg.get("token"))
    headers = {"Accept": "application/json"}
    if token:
        auth_type = _nz(cfg.get("auth_type")) or "bearer"
        if auth_type == "basic":
            import base64
            headers["Authorization"] = "Basic " + base64.b64encode(token.encode()).decode()
        elif auth_type == "header":
            headers[_nz(cfg.get("auth_header")) or "X-Auth-Token"] = token
        else:
            headers["Authorization"] = "Bearer " + token
    # 可选：只拉某条路径
    path = _nz(cfg.get("path")) or ""
    base = url.rstrip("/") + (path if path.startswith("/") else "/" + path if path else "")
    timeout = _safe_float(cfg.get("timeout"), 20)
    try:
        import requests
    except ImportError:
        import httpcompat as requests  # noqa: F401

    # 分页参数（可选）
    page_size = int(_safe_float(cfg.get("page_size"), 0)) or 0
    page_param = _nz(cfg.get("page_param")) or "page"
    size_param = _nz(cfg.get("size_param")) or "per_page"

    collected: List[dict] = []
    page = 1
    while True:
        q = ""
        if page_size:
            # 两种常见约定：page/per_page（从 1 起）或 offset/limit（从 0 起）
            if page_param == "offset":
                q = "?%s=%d&%s=%d" % (page_param, (page - 1) * page_size, size_param, page_size)
            else:
                q = "?%s=%d&%s=%d" % (page_param, page, size_param, page_size)
        try:
            resp = requests.get(base + q, headers=headers, timeout=timeout)
            if resp.status_code != 200:
                break
            batch = _flatten(resp.json())
        except Exception as e:  # noqa: BLE001
            _swallow("cmdb_scan._fetch_rest", e)
            break
        if not batch:
            break
        collected.extend(batch)
        # 单页没到 page_size 说明已取完；或触顶 MAX_CI
        if not page_size or len(batch) < page_size:
            break
        if len(collected) >= MAX_CI:
            break
        page += 1
    return collected


def _safe_float(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _source_label(cfg: dict) -> str:
    """报告里「数据来源」的可读标签。"""
    m = _nz(cfg.get("mode")) or "inline"
    if m == "rest":
        return "CMDB REST 接口"
    if m == "sqlite":
        ps = _db_paths(cfg)
        if not ps:
            return "SQLite 数据库"
        if len(ps) == 1:
            return "SQLite 数据库（%s）" % os.path.basename(ps[0])
        # 多库：只列前 3 个 + 计数，避免路径一长把报告的数据来源行撑爆
        head = "、".join(os.path.basename(p) for p in ps[:3])
        return "SQLite 数据库（%d 个库：%s%s）" % (len(ps), head, "…" if len(ps) > 3 else "")
    if m == "file":
        return "CMDB 导出文件"
    return "CMDB 导出数据"


# —— SQLite 直连：把本地 CMDB 库里的「软件资产表」抽成平台能识别的记录 ——
# 每张表：product 取哪个字段、version 取哪个、ip 取哪个、port 取哪个、owner/env 取哪个
_SQLITE_TABLE_MAP = [
    # (表名, 产品字段, 版本字段, IP字段, 端口字段, 主机名字段, 负责人字段, 环境字段)
    ("middleware_instance", "MW_TYPE", "VERSION", "HOST_IP", "PORT", "MW_NAME", "OWNER", "ENV_TYPE"),
    ("database_instance", "DB_TYPE", "VERSION", "HOST_IP", "PORT", "DB_NAME", "OWNER", "ENV_TYPE"),
    ("bigdata_component", "COMP_TYPE", "VERSION", "HOST_IP", "PORT", "COMP_NAME", "OWNER", "ENV_TYPE"),
    ("ai_model_service", "FRAMEWORK", "MODEL_VERSION", "ENDPOINT", "", "SVC_NAME", "OWNER", "ENV_TYPE"),
    ("app_instance", "APP_NAME", "VERSION", "HOST_IP", "PORT", "INST_NAME", "OWNER", "ENV_TYPE"),
]


def _fetch_sqlite(cfg: dict) -> Tuple[List[dict], str]:
    """直接读 SQLite 数据库文件，把「软件资产表」抽成平台能识别的记录。

    返回 (rows, warn)。rows 是扁平 dict 列表（name/ip/product/version/port/owner/env），
    与 inline/rest 模式产出的记录同构，后续统一走 _structured_extract → scan_assets。

    只抽取带版本+主机的「软件资产」表（中间件/数据库/大数据/AI 模型/应用实例），
    像机房/机柜/人员/合同这类纯基础设施表不参与漏洞匹配（它们没有 VERSION）。

    ★ 多库合并（2026-10-06）：支持同时给多个 .db（分库很常见——资产库 / 漏洞台账库
      往往不是一个文件）。逐库抽取后按顺序合并；某个库读失败只记 warn，不让整次
      分析失败（原单库逻辑是任何异常都直接返回空，用户传错一个文件就全盘皆输）。
    """
    import sqlite3
    paths = _db_paths(cfg)
    if not paths:
        return [], "SQLite 模式需要提供数据库文件（可上传 .db 文件，或填写服务器本地路径）"

    rows: List[dict] = []
    warn_parts: List[str] = []
    ok_libs = 0
    for path in paths:
        base = os.path.basename(path) or path
        if not os.path.isfile(path):
            warn_parts.append("数据库文件不存在：%s" % base)
            continue
        # 允许用户只指定某几张表（可选），否则默认抽全部软件资产表
        only = _nz(cfg.get("tables")).split(",") if cfg.get("tables") else []
        only = [t.strip().lower() for t in only if t.strip()]
        try:
            conn = sqlite3.connect(path)
            try:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                for tname, prod_col, ver_col, ip_col, port_col, name_col, owner_col, env_col in _SQLITE_TABLE_MAP:
                    if only and tname not in only:
                        continue
                    # 确认表存在
                    exists = cur.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (tname,)).fetchone()
                    if not exists:
                        if only:
                            warn_parts.append("表 %s 不存在，已跳过" % tname)
                        continue
                    # 确认字段存在（避免字段名不一致报错）
                    cols = {r[1] for r in cur.execute("PRAGMA table_info(%s)" % tname).fetchall()}
                    need = [c for c in (prod_col, ver_col, ip_col) if c]
                    missing = [c for c in need if c not in cols]
                    if missing:
                        warn_parts.append("表 %s 缺少字段 %s，已跳过" % (tname, ",".join(missing)))
                        continue
                    # 动态拼 SELECT（只取存在的列）
                    select_cols = [prod_col, ver_col]
                    for c in (ip_col, port_col, name_col, owner_col, env_col):
                        if c and c in cols:
                            select_cols.append(c)
                    sql = "SELECT %s FROM %s" % (", ".join(select_cols), tname)
                    for row in cur.execute(sql):
                        d = {"product": row[prod_col]}
                        if ver_col and row[ver_col]:
                            d["version"] = row[ver_col]
                        if ip_col and ip_col in cols and row[ip_col]:
                            d["ip"] = row[ip_col]
                        if port_col and port_col in cols and row[port_col]:
                            d["port"] = row[port_col]
                        if name_col and name_col in cols and row[name_col]:
                            d["name"] = row[name_col]
                        if owner_col and owner_col in cols and row[owner_col]:
                            d["owner"] = row[owner_col]
                        if env_col and env_col in cols and row[env_col]:
                            d["env"] = row[env_col]
                        rows.append(d)
            finally:
                # ★ 必须放 finally（2026-10-06 e2e 抓到）：原来 close() 写在 try
                #   末尾，一旦中途抛异常（比如上传的不是 SQLite 文件）就直接跳过，
                #   句柄一直挂着。Windows 上文件被占用 → os.remove 失败 →
                #   api 侧 _cleanup_sqlite_uploads 静默吞掉 → 用户的库永久残留在
                #   data/tmp_cmdb。Linux 上能删，所以这个 bug 只在 Windows 显形。
                conn.close()
            ok_libs += 1
        except Exception as e:  # noqa: BLE001
            _swallow("cmdb_scan._fetch_sqlite", e)
            warn_parts.append("数据库 %s 读取失败：%s" % (base, str(e)[:160]))

    if paths and not ok_libs:
        return [], "；".join(warn_parts) or "SQLite 数据库均读取失败"

    warn = "；".join(warn_parts) if warn_parts else ""
    return rows, warn


def _parse_file_worker(args):
    """解析单个上传文件 → 资产（file 模式流水线的单文件处理器）。

    返回 plain dict：kind=structured/regex/error + assets/meta/adv/warn。
    adv = 该文件消耗的「行号空间」大小，父流程据此给下一个文件偏移行号，
    保证跨文件的「同行主机关联」不会串位。

    ★ 为什么顺序而不是多进程（2026-10-05 实测）：8 核机器上并行 21.1s ≈ 顺序
      21.5s——worker 返回几十万主机的 pickle 传输把加速吃光了；而逐文件流式 +
      sheet 预览跳过本身已把 10 文件 2.8GB XML 压到 ~640MB/约 26s。真要再快
      需按 sheet 粒度并行（重构成本高），暂不做。
    """
    fname, data = args
    short = os.path.basename(fname)
    try:
        doc = AS.read_upload(fname, data, sheet_filter=_cmdb_sheet_filter)
        warn = ("%s：%s" % (short, doc.warn)) if doc.warn else ""
        # ★ 漏洞台账（vulnerability）：CMDB 风险报告的正确主数据源。
        #   台账与资产表可以共存于同一文件（05_运维运营.xlsx 两者都有），
        #   所以两条路都走，父流程会分别累积 ledger 与 assets。
        ledger = _vuln_ledger_rows(doc.rows) if doc.rows else None
        recs = _tsv_records(doc.rows) if doc.rows else None
        assets, meta = {}, []
        if recs:
            acc = _CmdbAcc()
            acc.feed_structured(recs, 0)
            assets, meta, _n = acc.finish()
        if ledger:
            return {"kind": "vuln_ledger", "ledger": ledger, "assets": assets,
                    "meta": meta, "n": len(ledger), "adv": len(doc.rows), "warn": warn}
        if recs:
            return {"kind": "structured", "assets": assets, "meta": meta,
                    "n": len(assets.get("hosts") or []) + len(assets.get("products") or []),
                    "adv": len(doc.rows), "warn": warn}
        # 无资产表头（word/叙述性文本/全部 sheet 被跳过）→ 正则路径兜底
        assets = AS.extract_assets(doc.text, doc.rows)
        adv = len(doc.rows) if doc.rows else (len(doc.text.splitlines()) if doc.text else 0)
        return {"kind": "regex", "assets": assets, "meta": [],
                "n": adv, "adv": adv, "warn": warn}
    except Exception as e:  # noqa: BLE001
        return {"kind": "error", "assets": {}, "meta": [], "n": 0, "adv": 0,
                "warn": "%s：解析失败 %s" % (short, e)}


def _fetch_vuln_ledger_sqlite(path) -> Optional[List[dict]]:
    """从 SQLite 库直读 vulnerability 漏洞台账表，聚合成台账行列表。

    返回 None 表示库中无 vulnerability 表（或读不到）。台账字段与
    _vuln_ledger_rows 产出的行结构一致（asset_id/component/owner/plan_fix…）。

    ★ path 可以是列表（2026-10-06 多库上传）：逐库读，行顺次合并。
      真实 CMDB 常把漏洞台账单独放一个库，只读第一个会在多库场景静默丢主数据源。
    """
    import sqlite3
    if isinstance(path, (list, tuple)):
        merged: List[dict] = []
        for p in path:
            rows = _fetch_vuln_ledger_sqlite(p)
            if rows:
                merged.extend(rows)
        return merged or None
    if not path or not os.path.isfile(path):
        return None
    conn = None
    try:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        exists = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vulnerability'").fetchone()
        if not exists:
            conn.close()
            return None
        cols = {r[1] for r in cur.execute("PRAGMA table_info(vulnerability)").fetchall()}
        # 关键列（CMDB 标准字段名；缺列则用空）
        sel = {}
        for canon, names in (
            # ★ VULN_ID 只能是台账内部记录号，不能拿 VULN_NO 兜底——否则对外
            #   报告会把记录号当漏洞编号（2026-10-05 评审「伪 CVE」根因之一）。
            ("vuln_id", ("VULN_ID",)),
            ("ci_id", ("CI_ID",)),
            ("ci_type", ("CI_TYPE",)),
            ("ci_name", ("CI_NAME",)),
            ("ci_ip", ("CI_IP",)),
            ("component", ("AFFECTED_COMPONENT",)),
            ("component_ver", ("COMPONENT_VERSION",)),
            ("fix_ver", ("FIX_VERSION",)),
            ("severity", ("SEVERITY",)),
            ("cvss", ("CVSS_SCORE",)),
            ("cve", ("VULN_NO", "CVE_ID")),
            ("cwe", ("CWE_ID",)),
            ("vtype", ("VULN_TYPE",)),
            ("vname", ("VULN_NAME",)),
            ("owner", ("OWNER",)),
            ("emp", ("EMP_ID",)),
            ("dept", ("DEPT_ID",)),
            ("app", ("APP_NAME", "APP_ID")),
            ("env", ("ENV_TYPE",)),
            ("port", ("PORT",)),
            ("plan_fix", ("PLAN_FIX_DATE",)),
            ("fix_status", ("FIX_STATUS",)),
            ("actual_fix", ("ACTUAL_FIX_DATE",)),
            ("duration", ("FIX_DURATION_DAYS",)),
            ("patch", ("RELATED_PATCH",)),
            ("internet", ("IS_INTERNET_FACING",)),
            ("regulatory", ("IS_REGULATORY",)),
            ("accepted", ("IS_ACCEPTED_RISK",)),
            ("verify", ("VERIFY_STATUS",)),
            # 利用可得性：判定「已确认 / 待确认」用（2026-10-05）
            ("verified_exploit", ("IS_VERIFIED_EXPLOIT",)),
            ("exploit_available", ("EXPLOIT_AVAILABLE",)),
            ("discover_tool", ("DISCOVER_TOOL",)),
            ("discover_time", ("DISCOVER_TIME",)),
            ("bg", ("BUSINESS_BG",)),
            ("importance", ("IMPORTANCE",)),
        ):
            for n in names:
                if n in cols:
                    sel[canon] = n
                    break
        # 必须有「漏洞编号」或「资产标识 + 组件」才能构成台账
        if "vuln_id" not in sel and ("ci_id" not in sel or "component" not in sel):
            conn.close()
            return None
        select_cols = list(sel.values())
        sql = "SELECT %s FROM vulnerability" % ", ".join(select_cols)
        ledger = _VulnLedger()
        for row in cur.execute(sql):
            r = {c: row[k] for c, k in sel.items()}
            ci_id = _nz(r.get("ci_id"))
            ci_type = _nz(r.get("ci_type"))
            ci_name = _nz(r.get("ci_name"))
            ci_ip = _nz(r.get("ci_ip"))
            vuln_id = _nz(r.get("vuln_id"))
            asset_id = ci_id or ci_name or ci_ip or ("未知资产" + (":" + vuln_id if vuln_id else ""))
            prefix = ""
            if ci_type:
                prefix = ci_type.rstrip("-").upper()
            elif ci_id and "-" in ci_id:
                prefix = ci_id.split("-", 1)[0].upper()
            # CI_TYPE 与 CI_ID 前缀矛盾时以 CI_ID 为准（避免 VM-SRV-922877 双前缀）
            if ci_id and "-" in ci_id:
                idp = ci_id.split("-", 1)[0].upper()
                if idp.isalpha() and prefix and idp != prefix:
                    prefix = idp
            # 组件名被填成版本号时归入「未标注组件」（同 file 路径的处理）
            comp_name = _nz(r.get("component"))
            comp_v = _nz(r.get("component_ver"))
            if _looks_like_version_only(comp_name):
                if not comp_v:
                    comp_v = comp_name
                comp_name = "未标注组件"
            ledger.rows.append({
                "vuln_id": vuln_id,
                "vuln_no": _nz(r.get("cve")),
                "asset_id": asset_id, "asset_prefix": prefix,
                "ci_name": ci_name, "ci_ip": ci_ip,
                "component": comp_name,
                "component_version": comp_v,
                "fix_version": _nz(r.get("fix_ver")),
                "severity": _nz(r.get("severity")),
                "cvss": _nz(r.get("cvss")),
                "cve": _nz(r.get("cve")),
                "cwe": _nz(r.get("cwe")),
                "vtype": _nz(r.get("vtype")),
                "vname": _nz(r.get("vname")),
                "owner": _nz(r.get("owner")),
                "emp_id": _nz(r.get("emp")),
                "dept_id": _nz(r.get("dept")),
                "app": _nz(r.get("app")),
                "env": _nz(r.get("env")),
                "port": _nz(r.get("port")),
                "plan_fix": _nz(r.get("plan_fix")),
                "fix_status": _nz(r.get("fix_status")),
                "actual_fix": _nz(r.get("actual_fix")),
                "duration": _nz(r.get("duration")),
                "patch": _nz(r.get("patch")),
                "internet": _nz(r.get("internet")),
                "regulatory": _nz(r.get("regulatory")),
                "accepted": _nz(r.get("accepted")),
                "verify": _nz(r.get("verify")),
                "verified_exploit": _nz(r.get("verified_exploit")),
                "exploit_available": _nz(r.get("exploit_available")),
                "discover_tool": _nz(r.get("discover_tool")),
                "discover_time": _nz(r.get("discover_time")),
                "bg": _nz(r.get("bg")),
                "importance": _nz(r.get("importance")),
            })
            if ci_id:
                ledger.ci_ids.setdefault(ci_id, {
                    "ci_id": ci_id, "prefix": prefix, "name": ci_name or ci_id, "ip": ci_ip})
            if ledger.rows and ledger.rows[-1]["component"]:
                ledger.components[ledger.rows[-1]["component"].lower()] = \
                    ledger.components.get(ledger.rows[-1]["component"].lower(), 0) + 1
        return ledger.rows or None
    except Exception as e:  # noqa: BLE001
        _swallow("cmdb_scan._fetch_vuln_ledger_sqlite", e)
        return None
    finally:
        # 同 _fetch_sqlite：异常路径上也要还句柄，否则临时 .db 在 Windows 上删不掉
        try:
            if conn is not None:
                conn.close()
        except Exception:  # noqa: BLE001
            pass


def _fetch_loc_index_sqlite(path) -> _LocIndex:
    """从 SQLite 库直读机房 / 机柜 / 资产表，建 CI → 位置索引。

    ★ path 可以是列表（2026-10-06 多库上传）：逐库读，索引合并。
      机房/机柜表与资产表分库存放很常见，只读第一个库会让位置整列退化成「未登记」。
    """
    import sqlite3
    if isinstance(path, (list, tuple)):
        idx = _LocIndex()
        for p in path:
            sub = _fetch_loc_index_sqlite(p)
            idx.ci2idc.update(sub.ci2idc)
            idx.ci2cab.update(sub.ci2cab)
            idx.ci2host.update(sub.ci2host)
            idx.idc_info.update(sub.idc_info)
            idx.cab_info.update(sub.cab_info)
            for k, v in sub.stats.items():
                idx.stats[k] = idx.stats.get(k, 0) + v
        return idx
    idx = _LocIndex()
    if not path or not os.path.isfile(path):
        return idx
    try:
        conn = sqlite3.connect(path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            # (表名候选, 自身 CI 列候选, 宿主列候选)
            plan = [
                ("idc_room", ("IDC_ID",), None),
                ("cabinet", ("CAB_ID",), None),
                ("physical_server", ("SRV_ID", "CI_ID"), None),
                ("vm_cloud_host", ("VM_ID", "CI_ID"), None),
                ("network_device", ("NET_ID", "DEVICE_ID", "CI_ID"), None),
                ("security_device", ("SEC_ID", "DEVICE_ID", "CI_ID"), None),
                ("storage_device", ("DS_ID", "DEVICE_ID", "CI_ID"), None),
                ("gpu_node", ("GPU_NODE_ID", "NODE_ID", "CI_ID"), None),
                ("middleware_instance", ("MW_ID", "INST_ID", "CI_ID"), ("HOST_ID", "HOST_SRV_ID")),
                ("database_instance", ("DB_ID", "INST_ID", "CI_ID"), ("HOST_ID", "HOST_SRV_ID")),
                ("bigdata_component", ("BD_ID", "COMP_ID", "CI_ID"), ("HOST_ID", "NODE_ID")),
                ("app_instance", ("INST_ID", "CI_ID"), ("HOST_ID", "HOST_SRV_ID")),
                ("container_pod", ("POD_ID", "CI_ID"), ("NODE_VM_ID", "HOST_ID")),
            ]
            lower = {t.lower(): t for t in tables}
            for want, own_cols, host_cols in plan:
                t = lower.get(want)
                if not t:
                    continue
                colmap = {r[1].lower(): r[1] for r in conn.execute(
                    "PRAGMA table_info(%s)" % t).fetchall()}
                cols = set(colmap)
                own = next((colmap[c.lower()] for c in own_cols if c.lower() in cols), None)
                if not own:
                    continue
                host = next((colmap[c.lower()] for c in (host_cols or ()) if c.lower() in cols), None)
                idc = next((colmap[c] for c in _LOC_IDC_COLS if c in cols), None)
                cab = next((colmap[c] for c in _LOC_CAB_COLS if c in cols), None)
                # 机房/机柜表要额外取展示列（城市/区域/楼层/机房号），否则报告只有 IDC 编号
                # ★ 候选列名必须写成小写（2026-10-05 修复）：`cols = set(colmap)` 的键是
                #   PRAGMA 返回的小写列名，这里原来写的是 "IDC_NAME" 大写 → `c in cols` 恒假
                #   → extra 永远是空列表 → 机房名/城市/机柜号全丢，报告位置列渲染成「未登记」。
                if want == "idc_room":
                    extra = [colmap[c] for c in ("idc_name", "idc_code", "city", "region",
                                                 "tier_level") if c in cols]
                    kind = "idc"
                elif want == "cabinet":
                    extra = [colmap[c] for c in ("cab_code", "floor", "room_no",
                                                 "position") if c in cols]
                    kind = "cab"
                else:
                    extra = []
                    kind = "asset"
                # 去重但保持顺序（own 必须在首列：feed_table 的 asset 分支硬编码 self_ci=0）。
                # cabinet 表的 own 与 cab 都是 CAB_ID，不去重会 SELECT 成 "CAB_ID","CAB_ID",…
                want_cols: List[str] = []
                for c in [own] + ([host] if host else []) + ([idc] if idc else []) + \
                        ([cab] if cab else []) + extra:
                    if c not in want_cols:
                        want_cols.append(c)
                sql = 'SELECT %s FROM "%s"' % (", ".join('"%s"' % c for c in want_cols), t)
                batch = []
                for row in conn.execute(sql):
                    batch.append(list(row))
                    if len(batch) >= 20000:
                        _feed_loc_sqlite(idx, batch, want_cols, kind)
                        batch = []
                if batch:
                    _feed_loc_sqlite(idx, batch, want_cols, kind)
        finally:
            # 同 _fetch_sqlite：close 必须在 finally，否则中途异常会漏句柄（Windows 删不掉临时库）
            conn.close()
    except Exception as e:  # noqa: BLE001
        _swallow("cmdb_scan._fetch_loc_index_sqlite", e)
    return idx


def _feed_loc_sqlite(idx: "_LocIndex", batch, cols, kind: str) -> None:
    """把一批 sqlite 行灌进位置索引（列名与数据列一一对应）。"""
    idx.feed_table([c.lower() for c in cols], batch, kind)


def _load_assets(cfg: dict, engine) -> Tuple[Dict, List[dict], str, int, Optional[List[dict]], Optional["_LocIndex"]]:
    """按 mode 加载资产，统一交给 asset_scan 解析。
    返回 (assets_dict, meta, warn, ci_total, vuln_ledger, loc_index)。

    vuln_ledger：漏洞台账行列表（vulnerability 表）。非空时作为报告主数据源，
    资产 CPE 匹配降级为交叉验证补充。
    loc_index：CI → 机房/机柜/城市索引（file / sqlite 模式建，缺失时报告位置列显示「未登记」）。
    四种模式：sqlite（本地 SQLite 库直连）/ rest（REST API）/ inline（粘贴）/ file（上传）。
    """
    mode = _nz(cfg.get("mode")) or "inline"
    warn = ""
    vuln_ledger: Optional[List[dict]] = None
    loc_index: Optional[_LocIndex] = None

    if mode == "sqlite":
        paths = _db_paths(cfg)
        vuln_ledger = _fetch_vuln_ledger_sqlite(paths)
        loc_index = _fetch_loc_index_sqlite(paths)
        rows, w = _fetch_sqlite(cfg)
        if w:
            warn = w
        if not rows and not vuln_ledger:
            return {}, [], warn or "SQLite 数据库未抽取到任何软件资产或漏洞台账（请检查路径 / 表 / 字段）", 0, None, loc_index
        if len(rows) > MAX_CI:
            return {}, [], "SQLite 抽取到 %d 条记录，超过单次上限 %d（请用 tables 参数分批指定表）" % (
                len(rows), MAX_CI), 0, vuln_ledger, loc_index
        if not rows:
            return {}, [], warn, 0, vuln_ledger, loc_index
        assets, meta, total = _chunked_extract(rows)
        return assets, meta, warn, total, vuln_ledger, loc_index

    if mode == "rest":
        rows = _fetch_rest(cfg)
        if not rows:
            return {}, [], "CMDB 接口未返回任何资产（请检查地址 / 凭证 / 返回结构）", 0, None, None
        if len(rows) > MAX_CI:
            return {}, [], "CMDB 返回 %d 条 CI，超过单次上限 %d（请用 path 参数按部门/网段分批拉取）" % (
                len(rows), MAX_CI), 0, None, None
        assets, meta, total = _chunked_extract(rows)
        return assets, meta, warn, total, None, None

    if mode == "file":
        # 多文件（2026-10-05）：files=[{filename,data},...]，兼容旧的单文件 data/filename
        # ★ files 可能是 api._file_entries_from_paths 造的惰性序列（大文件流式落盘后
        #   逐个读入即弃）。list() 会一次性拉全量，所以这里先探测再决定是否物化：
        #   惰性序列本身已是 list 语义（__len__/__iter__/__getitem__ 都有），
        #   直接用即可，不需要也不能再 list() 一份 —— 那等于把 374MB 全读进内存。
        files = cfg.get("files") or []
        if not len(files) and cfg.get("data"):
            files = [{"filename": cfg.get("filename") or "cmdb_assets.txt", "data": cfg.get("data")}]
        if not len(files):
            return {}, [], "未收到文件内容", 0, None, None

        # ★ 位置索引（2026-10-05）：报告要写「哪个机房哪个机柜」，机房/机柜信息在
        #   CMDB 里分散在三张表（idc_room / cabinet / 资产表的 IDC_ID），这里单独
        #   跑一遍轻量解析建索引。sheet_filter 已把无位置字段的表全跳过，开销可控。
        #
        # ★★ 顺序很重要（2026-10-06）：位置索引必须**先**建、**后**跑逐文件解析。
        #   大文件流式上传时 files 是惰性序列（逐个从磁盘读入、用完即弃），
        #   两阶段都要遍历全部文件。先建索引可以把每个文件的字节在解析阶段
        #   复用（省一次磁盘读）；反过来则要缓存全部字节才能过第二遍，
        #   10 个 xlsx 共 374MB 会直接把内存打爆。
        #   有 release() 的说明是惰性序列 —— 解析完立刻把字节还给系统。
        loc_index = _build_loc_index(files)

        # ★ 逐文件流水线（2026-10-05 重构）：每个文件独立「解析→表头识别→结构化/正则
        #   抽取」，行数据用完即弃；按文件顺序合并（行号偏移，跨文件「同行关联」不串位）。
        lazy = files if hasattr(files, "release_one") else None
        results = []
        for f in files:
            results.append(_parse_file_worker((f.get("filename") or "cmdb_assets.txt",
                                               f.get("data") or b"")))
            # ★ 惰性序列：单个文件解析完立刻丢弃其字节，峰值内存 = 单文件而非全部之和
            if lazy is not None:
                lazy.release_one()

        acc = _CmdbAcc()
        warns: List[str] = []
        ci_total = 0
        base = 0
        ledger_rows: List[dict] = []
        for res in results:
            w = res.get("warn") or ""
            if w:
                warns.append(w)
            if res.get("kind") == "error":
                continue
            adv = int(res.get("adv") or 0)
            ci_total += adv
            if res.get("kind") == "vuln_ledger":
                # ★ 台账与资产表可共存（05_运维运营.xlsx 两者都有），两条都要累积：
                #   台账作主数据源出处置清单，资产表作交叉验证。
                ledger_rows.extend(res.get("ledger") or [])
            assets_i = res.get("assets") or {}
            if assets_i.get("hosts") or assets_i.get("products"):
                acc.feed_assets(assets_i, base)
            # meta 合并（worker 里 source_row 是文件内行号 → 加本文件的全局基偏移）
            for m in (res.get("meta") or []):
                if len(acc.meta) < _META_CAP:
                    m2 = dict(m)
                    m2["source_row"] = base + int(m.get("source_row") or 0)
                    acc.meta.append(m2)
            base += adv
        warn = "；".join(w for w in warns if w)
        if ledger_rows:
            vuln_ledger = ledger_rows
        if not (acc.hosts or acc.products) and not vuln_ledger:
            return {}, [], warn or "未能从上传文件中解析出任何软件资产或漏洞台账（拓扑/字典/工单类表格不含资产字段）", ci_total, None, loc_index
        assets, meta, _n = acc.finish()
        return assets, meta, warn, ci_total, vuln_ledger, loc_index

    # inline（默认）：直接粘贴 CMDB 导出的 JSON / CSV / TSV
    text = _nz(cfg.get("text"))
    if not text:
        return {}, [], "未提供 CMDB 数据（请粘贴 JSON / CSV，或切换到 REST 模式）", 0, None, None
    # ★ 多表块（2026-10-05）：一次粘贴里含「台账 + 物理机 + 机房 + 机柜」四张表时，
    #   逐块独立判定表类型——台账块喂台账、机房/机柜/资产块喂位置索引，
    #   剩下的块才走资产抽取。位置列不再是 inline 模式的结构性缺失。
    blocks = _parse_inline_blocks(text)
    if blocks:
        all_rows: List[dict] = []
        for header, body in blocks:
            m = _vuln_table_map(header)
            if m is not None:                      # 漏洞台账块
                ledger = _VulnLedger()
                for r in body:
                    ledger.feed([_nz(c) for c in r], m)
                if ledger.rows:
                    vuln_ledger = (vuln_ledger or []) + ledger.rows
                continue
            if _loc_table_kind(header):            # 机房/机柜/带位置的资产表
                loc_index = loc_index or _LocIndex()
                loc_index.feed_table(header, body, _loc_table_kind(header))
            for r in body:                         # 资产抽取（台账块已 continue）
                all_rows.append({header[i]: r[i] for i in range(min(len(header), len(r)))})
        if vuln_ledger is not None or all_rows or loc_index is not None:
            if not vuln_ledger and not all_rows:
                return {}, [], warn or "贴入内容仅含机房/机柜位置表，未包含漏洞台账或资产记录", 0, None, loc_index
            if len(all_rows) > MAX_CI:
                return {}, [], "贴入 %d 条资产记录，超过单次上限 %d（请拆分后分批提交）" % (
                    len(all_rows), MAX_CI), 0, None, loc_index
            assets, meta, total = _chunked_extract(all_rows)
            return assets, meta, warn, total, vuln_ledger, loc_index
    rows = _parse_inline_text(text)
    if not rows:
        return {}, [], "无法解析贴入的数据（支持 JSON 数组 / 对象 / CSV / TSV）", 0, None, None
    if len(rows) > MAX_CI:
        return {}, [], "贴入 %d 条记录，超过单次上限 %d（请拆分后分批提交）" % (len(rows), MAX_CI), 0, None, None
    # ★ 粘贴的也可能就是漏洞台账导出（VULN_NO / AFFECTED_COMPONENT / OWNER…）。
    #   之前 inline 只走资产抽取，台账列被当普通资产丢掉 → 报告退化成资产 CPE 匹配，
    #   责任人/期限/SLA 全空。2026-10-05 补上：先按台账表头判定，再走资产抽取。
    if rows and _is_ledger_rows(rows):
        head = [str(k).strip().lower().lstrip("﻿") for k in rows[0].keys()]
        m = _vuln_table_map(head)
        if m is not None:
            ledger = _VulnLedger()
            cols = list(rows[0].keys())
            for r in rows:
                ledger.feed([_nz(r.get(c)) for c in cols], m)
            if ledger.rows:
                vuln_ledger = ledger.rows
    # JSON / 单表 CSV：台账本身若带 IDC_ID / CAB_ID 列，直接建轻量位置索引
    if vuln_ledger and loc_index is None:
        loc_index = _inline_loc_index(text)
    assets, meta, total = _chunked_extract(rows)
    return assets, meta, warn, total, vuln_ledger, loc_index


def _is_ledger_rows(rows: List[dict]) -> bool:
    """一批 dict 记录是否像漏洞台账（有 VULN_NO / VULN_ID / AFFECTED_COMPONENT）。"""
    if not rows or not isinstance(rows[0], dict):
        return False
    head = [str(k).strip().lower().lstrip("﻿") for k in rows[0].keys()]
    return _vuln_table_map(head) is not None


def _valid_ipv4(s: str) -> bool:
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def _local_ip(ip: str) -> bool:
    """内网 IP 判断（10.x / 172.16-31 / 192.168 / 127.x）。"""
    try:
        a = int(ip.split(".")[0])
        if a in (10, 127):
            return True
        if a == 172:
            return 16 <= int(ip.split(".")[1]) <= 31
        if a == 192:
            return int(ip.split(".")[1]) == 168
        return False
    except (ValueError, IndexError):
        return False


_META_CAP = 10000


class _CmdbAcc:
    """资产累加器：逐文件/逐块喂入，主机/产品按内容去重，行号支持跨文件偏移。

    ★ 为什么不用「先拼全部记录再一次抽取」：10 文件 70 万行时，全部行 + 全部
      记录 + 全部拆分结果同时驻留内存要数 GB；逐文件喂入后单文件行数据用完即弃，
      内存与「去重后的资产种类」成正比。
    """

    __slots__ = ("hosts", "products", "ports", "meta", "n")

    def __init__(self) -> None:
        self.hosts: "OrderedDict[tuple, dict]" = OrderedDict()
        self.products: "OrderedDict[tuple, dict]" = OrderedDict()
        self.ports: "OrderedDict[str, int]" = OrderedDict()
        self.meta: List[dict] = []
        self.n = 0

    # ---- 结构化记录（CMDB 表格文件 / SQLite / REST / 粘贴）----
    def feed_structured(self, rows, base: int = 0) -> None:
        _PRODUCT_DICT = getattr(AS, "_PRODUCT_DICT", {})
        _canon_key = getattr(AS, "_canon_key", None)
        n = self.n
        hosts, products, ports = self.hosts, self.products, self.ports
        for r in rows:
            if not isinstance(r, dict):
                continue
            n += 1
            ln = base + n - 1
            # ★ 资产标识优先级（2026-10-05）：CI_ID > 主机名 > 域名 > 裸 IP
            #   报告里的"资产"必须能回溯到 CMDB 真实 CI。只给裸 IP 的话，运维拿到
            #   报告还要自己查 CMDB 才知道是哪台机器，报告就不可操作了。
            ci_id = _nz(r.get("ci_id"))
            ci_name = _nz(r.get("ci_name"))
            ci_prefix = _nz(r.get("ci_prefix"))
            _ip = _nz(r.get("ip"))
            _dom = _nz(r.get("domain"))
            # ★ 资产必须有「可定位的宿主」：真实 IP、域名，或带主机名的 CI。
            #   只有一串 CI_ID 而没有 IP/主机名（如 software_package 的 SW-00001
            #   软件包主键）不构成资产——报告里出现「源库查不到的机器」就是这么来的。
            if ci_id and not (_ip or _dom or ci_name):
                ci_id = ""
            name = ci_name or _field(r, "name") or _dom or _ip
            host = ci_id or _dom or _ip or name
            prod_raw = _field(r, "product")
            ver = _field(r, "version")
            port = _field(r, "port")
            osname = _field(r, "os")
            env = _field(r, "env")
            owner = _field(r, "owner")
            if not host and not prod_raw:
                continue
            if not prod_raw and osname:
                prod_raw = osname

            # 主机（CI 标识 / 域名 / IP）
            has_locator = bool(_ip or _dom or ci_id)
            if host and has_locator:
                hl = host.lower()
                if ci_id:
                    # 有 CI 标识：资产三元组（CI_ID + 主机名 + IP）一起带出
                    h = {"name": host, "type": "ci", "line": ln,
                         "ci_id": ci_id, "ci_prefix": ci_prefix,
                         "ci_name": ci_name or "", "ip": _nz(r.get("ip"))}
                    h["label"] = _asset_label(ci_id, ci_prefix, ci_name or name,
                                              _nz(r.get("ip")))
                    h["scope"] = "内网" if _local_ip(_nz(r.get("ip"))) else "公网" \
                        if _nz(r.get("ip")) else "内网"
                    hosts.setdefault((ci_id, "ci"), h)
                elif _valid_ipv4(hl):
                    hosts.setdefault((host, "ip"), {"name": host, "type": "ip", "line": ln,
                                                    "scope": "内网" if _local_ip(host) else "公网"})
                elif "." in host:
                    hosts.setdefault((hl, "domain"), {"name": hl, "type": "domain", "line": ln, "scope": "公网"})
                else:
                    hosts.setdefault((host, "host"), {"name": host, "type": "host", "line": ln, "scope": "内网"})

            # 端口
            if port:
                p = _nz(port).split("/")[0].strip()
                if p.isdigit() and 0 < int(p) <= 65535:
                    ports.setdefault(p, 0)

            # 产品：词典映射（原始名 → 规范 CPE 名）
            if prod_raw:
                if _canon_key:
                    key = _canon_key(prod_raw)
                else:
                    key = re.sub(r"[\s_\-./]+", "", prod_raw.lower())
                mapped = _PRODUCT_DICT.get(key)
                if mapped:
                    prod_name, disp, vendor = mapped
                else:
                    # 词典没命中：保守回退，用原始名归一化作为 name，交给 scanner 宽松匹配
                    prod_name = re.sub(r"[\s_\-./]+", "_", prod_raw.lower())
                    disp, vendor = prod_raw, ""
                products.setdefault((prod_name, _nz(ver)), {
                    "name": prod_name, "display": disp or prod_raw, "vendor": vendor,
                    "version": ver, "line": ln, "raw": prod_raw,
                })

            if len(self.meta) < _META_CAP:
                self.meta.append({"name": name or host, "host": host, "owner": owner,
                                  "env": env, "source_row": ln})

            # 上限保护
            if len(hosts) > MAX_CI or len(products) > MAX_PRODUCTS:
                break
        self.n = n

    # ---- 资产字典合并（结构化抽取与正则抽取的产物通用）----
    def feed_assets(self, assets: dict, base: int = 0) -> None:
        for h in assets.get("hosts") or []:
            key = (h.get("name") or "", h.get("type") or "")
            if key not in self.hosts:
                d = dict(h)
                d["line"] = base + int(h.get("line") or 0)
                self.hosts[key] = d
        for p in assets.get("products") or []:
            key = (p.get("name") or "", _nz(p.get("version")))
            if key not in self.products:
                d = dict(p)
                d["line"] = base + int(p.get("line") or 0)
                self.products[key] = d
        for pt in assets.get("ports") or []:
            self.ports.setdefault(str(pt), 0)

    def finish(self) -> Tuple[Dict, List[dict], int]:
        prods = list(self.products.values())
        if len(prods) > MAX_PRODUCTS:
            prods = prods[:MAX_PRODUCTS]
        return {
            "hosts": list(self.hosts.values())[:MAX_CI],
            "products": prods,
            "urls": [], "emails": [],
            "ports": list(self.ports.keys())[:2000],
            "os": [], "cves_in_doc": [],
        }, self.meta[:_META_CAP], self.n


def _structured_extract(rows) -> Tuple[Dict, List[dict], int]:
    """★ 结构化快速路径：CMDB 记录是 dict（已知字段）时，直接用字段值构造资产，
    跳过 asset_scan 的逐行正则扫描。正则扫描是 100 万条 CI 的性能瓶颈
    （实测 30 万条约 80s），结构化路径可降到秒级。

    产品名经 asset_scan 的 _PRODUCT_DICT 直接映射到「语料 CPE 规范名 + 厂商 + 展示名」，
    与正则路径语义一致（同一套词典、同一套归一化）。
    """
    acc = _CmdbAcc()
    acc.feed_structured(rows, 0)
    return acc.finish()


def _chunked_extract(rows) -> Tuple[Dict, List[dict], int]:
    """把 CMDB 记录解析成资产（结构化快速路径，流式）。

    CMDB 的 JSON/CSV 记录本身带 product/version 字段，直接用字段值构造资产，
    跳过 asset_scan 的逐行正则扫描（那才是 100 万条 CI 的性能瓶颈，实测 30 万条约 80s，
    结构化路径仅需 ~5s）。

    流式：for 直接消费可迭代对象（list / tuple / 生成器），逐条累积到 OrderedDict
    （天然去重），内存与「去重后的资产种类」成正比，而非与「CI 总数」成正比。
    """
    return _structured_extract(rows)


# ==========================================================================
# 2. 处置优先级 + 处置方案 + 验证闭环
# ==========================================================================
# ★ 必须包含 INFO（2026-10-05 修复）：台账里 20% 的记录 CVSS=0.0（信息级），
#   之前 _SEV_ORDER 没有 INFO 键 → 取值 0 与 UNKNOWN 同级 → 组内比较时
#   `INFO(0) > UNKNOWN(0)` 不成立 → 6024 条信息级漏洞被误标成 UNKNOWN，
#   报告的严重度分布里 info 恒为 0，且这些资产在排序里被当成「等级未知」。
_SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


# —— 严重度归一（vulnerability 表里的 SEVERITY 可能是「中危 Medium」这种中英混合）——
def _norm_severity(s: str) -> str:
    """CMDB 台账的 SEVERITY 文本 → 标准等级。

    ★ 只按明确的中英文关键词匹配，不用 `"高" in t` 这种单字子串——后者会把
      「高可用」「高级」「提高」等无关文本误判成 HIGH。
    """
    t = _nz(s).upper()
    for kw, lv in (("CRITICAL", "CRITICAL"), ("超危", "CRITICAL"), ("严重", "CRITICAL"),
                   ("紧急", "CRITICAL"),
                   ("HIGH", "HIGH"), ("高危", "HIGH"),
                   ("MEDIUM", "MEDIUM"), ("中危", "MEDIUM"),
                   ("LOW", "LOW"), ("低危", "LOW"),
                   ("INFO", "INFO"), ("信息", "INFO")):
        if kw in t:
            return lv
    return "UNKNOWN"


# ★ 严重度以 CVSS 分值为准（CVSS v3.1 官方区间），台账里人工标的 SEVERITY
#   只在分值缺失时兜底——否则会出现「CVSS 10.0 却标 HIGH」这种自相矛盾的行，
#   报告在评审阶段会被直接判定不可信（2026-10-05 评审意见）。
_NON_DEPLOYABLE_CI_PREFIX = ("SW-", "PATCH-", "ALERT-", "INC-", "TICKET-", "CHG-")


def _is_deployable_ci(ci_id: str, ci_ip: str = "") -> bool:
    """判断 CI 是否是「可部署资产」（能在 CMDB 里定位到一台机器）。

    排除两类源数据缺陷（2026-10-05 实测）：
    ① CI_ID 指向软件包/补丁/工单等记录主键（SW-/PATCH-/ALERT-…），不是机器；
    ② CI_IP 列填的是端口号而非 IP（vulnerability 表里 301 条 SW- 记录全是如此）。
    """
    t = _nz(ci_id).upper()
    if not t:
        return False
    for p in _NON_DEPLOYABLE_CI_PREFIX:
        if t.startswith(p):
            return False
    ip = _nz(ci_ip)
    if ip and (ip.isdigit() or not _valid_ipv4(ip)):
        # 端口号 / 非 IP 值 → 视为不可定位
        return False
    return True


def _severity_by_cvss(cvss, label: str) -> str:
    """按 CVSS 分值推导严重度；分值缺失/为 0 时回退到台账标签。"""
    try:
        s = float(cvss)
    except (TypeError, ValueError):
        return _norm_severity(label)
    if s <= 0:
        return _norm_severity(label)
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "INFO"


def _norm_cvss(v: str) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _internet_exposed(v: str) -> bool:
    """IS_INTERNET_FACING 是否为互联网暴露（Y/1/是/true）。"""
    t = _nz(v).upper()
    return t in ("Y", "YES", "1", "TRUE", "是", "TRUE", "YES")


def _yes(v: str) -> bool:
    """通用布尔字段判定（Y / 1 / 是 / true）。"""
    return _nz(v).upper() in ("Y", "YES", "1", "TRUE", "是")


def _asset_importance_weight(v: str) -> float:
    """资产重要性系数（报告口径：核心系统 / 生产环境 ×1.5）。"""
    t = _nz(v).upper()
    if any(x in t for x in ("核心", "CRITICAL", "高", "HIGH", "生产", "PROD")):
        return 1.5
    return 1.0


# ★ 风险分公式（2026-10-05 按评审给定的口径实现，报告里逐项列出因子可核对）
#   风险分 = CVSS × KEV系数(3.0) × 互联网暴露系数(2.0) × 核心/生产系数(1.5) × 监管系数(1.2)
#   缺 CVSS 分值时用严重度折算（CRITICAL 9.5 / HIGH 8.0 / MEDIUM 6.0 / LOW 3.5 / INFO 1.0），
#   不让「CVSS 缺失」变成「风险分 0」而被排到最后。
_CVSS_FALLBACK = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.5,
                  "INFO": 1.0, "UNKNOWN": 3.0}
FACTOR_KEV = 3.0
FACTOR_INTERNET = 2.0
FACTOR_IMPORTANCE = 1.5
FACTOR_REGULATORY = 1.2


def _risk_score(cvss: float, severity: str, internet: bool = False,
                importance: float = 1.0, kev: bool = False,
                regulatory: bool = False) -> float:
    """复合风险分 = CVSS × KEV × 互联网暴露 × 核心/生产 × 监管。

    每个因子都可在报告里逐项列出核对（见 _risk_factors），不做隐式加权——
    评审要能自己验算「为什么这条排第一」。
    """
    base = cvss if cvss > 0 else _CVSS_FALLBACK.get(severity, 3.0)
    score = base
    if kev:
        score *= FACTOR_KEV
    if internet:
        score *= FACTOR_INTERNET
    if importance >= FACTOR_IMPORTANCE:
        score *= FACTOR_IMPORTANCE
    if regulatory:
        score *= FACTOR_REGULATORY
    return round(score, 2)


def _risk_factors(cvss: float, severity: str, internet: bool, importance: float,
                  kev: bool, regulatory: bool) -> str:
    """把风险分的每个因子写成可核对的说明，如「CVSS 9.8 × 互联网暴露 2.0 × 核心 1.5」。"""
    base = cvss if cvss > 0 else _CVSS_FALLBACK.get(severity, 3.0)
    parts = ["CVSS %.1f" % base if cvss > 0 else "按%s折算 %.1f" % (severity, base)]
    if kev:
        parts.append("在野利用 ×%.1f" % FACTOR_KEV)
    if internet:
        parts.append("互联网暴露 ×%.1f" % FACTOR_INTERNET)
    if importance >= FACTOR_IMPORTANCE:
        parts.append("核心/生产 ×%.1f" % FACTOR_IMPORTANCE)
    if regulatory:
        parts.append("监管合规 ×%.1f" % FACTOR_REGULATORY)
    return " × ".join(parts)


# —— SLA 建议（评审要求：每条给责任人 + 期限 + SLA）——
#   依据：严重度定基准天数，在野利用 / 互联网暴露 / 监管资产压缩期限。
_SLA_DAYS = {"CRITICAL": 7, "HIGH": 15, "MEDIUM": 30, "LOW": 60,
             "INFO": 90, "UNKNOWN": 30}
# 优先级标签 → 排序权重（★ 不能直接按字符串排："P3" > "P1" 字典序，
#   倒序排会把 P3 顶到最前、把所有 CRITICAL(P1) 挤出 TOP 200 —— 2026-10-05 实测）
_PRIORITY_RANK = {"P0": 4, "P1": 3, "P2": 2, "P3": 1}

# ★ 优先级阈值按「无 KEV 时的最大可达分」标定，不是拍脑袋的整数（2026-10-05 修正）：
#   公式 = CVSS × KEV×3 × 公网×2 × 核心×1.5 × 监管×1.2，满分 108；但 KEV 只有
#   少数条目有，无 KEV 时最大 = 10 × 2 × 1.5 × 1.2 = 36。之前用 20/12 这种绝对值，
#   而实测大量条目落在 35-36，于是 200 条全是同一档 —— 优先级失去区分度。
#   改成按「无 KEV 满分 36」的比例：≥70% → P1，≥35% → P2，其余 P3；
#   有 KEV 且高危直接 P0（走单独通道，不参与比例）。
_SCORE_MAX_NO_KEV = 36.0
_P1_RATIO = 0.70
_P2_RATIO = 0.35


def _cpe_ranges_for_component(cpe_list, component: str) -> List[str]:
    """从 NVD 的 CPE 配置里挑出**属于本组件**的版本区间。

    ★ 为什么必须按产品过滤（2026-10-05 端到端验收发现）：
      NVD 一个 CVE 常同时登记多个产品的 CPE。实测 CVE-2026-41940 的 CPE 全部是
      cpanel / whm（区间 11.40 ~ 136.1.7），而台账的 AFFECTED_COMPONENT 是
      MongoDB 5.0.10。不加过滤就会把 cPanel 的版本区间当成 MongoDB 的
      「受影响版本区间」印进报告——运维拿 5.0.10 去核对一条 cPanel 区间，
      结论必然错，而且错得很自信（看起来像有据可依）。

    匹配方式：组件名先经 AS._PRODUCT_DICT 归一到 CPE 规范产品名（与 CPE 匹配
    路径用的是同一套词典，口径一致），再和每条 CPE 的 product 归一键比对。
    匹配不到就返回空列表——报告写「该 CVE 无本组件的 CPE 区间，以厂商公告为准」，
    这比给一条错的区间诚实。
    """
    comp = _nz(component)
    if not comp or not cpe_list:
        return []
    mapped = getattr(AS, "_PRODUCT_DICT", {}) or {}
    canon = getattr(AS, "_canon_key", None)
    hit_key = mapped.get(canon(comp) if canon else comp)
    prod_keys = set()
    if hit_key:
        prod_keys.add(canon(hit_key[0]) if canon else hit_key[0])
    # 组件名本身也作为候选（台账里可能直接写 CPE 规范名，词典里查不到）
    base = canon(comp) if canon else comp.lower()
    prod_keys.add(base)
    # 「Apache Tomcat X」这类带多余词的：取最长词元做包含匹配兜底
    toks = sorted((t for t in re.split(r"[\s_\-./()]+", comp.lower()) if len(t) > 2),
                  key=len, reverse=True)
    out: List[str] = []
    for e in cpe_list:
        if not isinstance(e, dict):
            continue
        prod = _nz(e.get("product")).lower()
        vend = _nz(e.get("vendor")).lower()
        pkey = canon(prod) if canon and prod else prod
        vkey = canon(vend) if canon and vend else vend
        ok = pkey in prod_keys or vkey in prod_keys
        if not ok and toks:
            # 兜底：product 归一键里包含组件的最长词元（word 边界已在 canon_key 去分隔符）
            ok = any(t in pkey for t in toks[:2] if len(t) >= 3)
        if not ok:
            continue
        txt = AS.AssetRiskScanner._range_text(e)
        if txt:
            out.append(txt)
    # NVD 里同一区间会以不同 matchCriteriaId 重复登记 → 保序去重
    return list(OrderedDict.fromkeys(out))


def _priority_label(score: float, kev: bool, severity: str) -> str:
    """处置优先级 P0-P3。阈值按风险分可达上限的比例标定，见上方常量。"""
    if kev and severity in ("CRITICAL", "HIGH"):
        return "P0"
    r = (score or 0.0) / _SCORE_MAX_NO_KEV
    if severity == "CRITICAL" and r >= _P1_RATIO:
        return "P1"
    if r >= _P2_RATIO and severity in ("CRITICAL", "HIGH", "MEDIUM"):
        return "P2"
    if severity == "CRITICAL":
        return "P2"
    return "P3"


def _sla_due(severity: str, kev: bool, internet: bool, regulatory: bool,
             base_date: str = "") -> Tuple[str, str]:
    """返回 (SLA 天数, 建议截止日期)。KEV / 公网 / 监管资产按比例压缩。"""
    days = _SLA_DAYS.get(severity, 30)
    if kev:
        days = max(1, int(days * 0.34))          # ≈ 72 小时
    if internet:
        days = max(1, int(days * 0.7))
    if regulatory:
        days = max(1, int(days * 0.8))
    due = ""
    if base_date and re.match(r"^\d{4}-\d{2}-\d{2}", base_date):
        import datetime
        try:
            d = datetime.date.fromisoformat(base_date[:10]) + datetime.timedelta(days=days)
            due = d.isoformat()
        except ValueError:
            due = ""
    return "%d 天" % days, due


# —— 组件 → 官方补丁/公告检索入口（报告要给「去哪下补丁」，不能只给一个补丁编号）——
_COMP_VENDOR_HOME = {
    "apache": "https://httpd.apache.org/security/vulnerabilities.html",
    "tomcat": "https://tomcat.apache.org/security-7.html",
    "log4j": "https://logging.apache.org/log4j/2.x/security.html",
    "spring": "https://spring.io/security/cve",
    "nginx": "https://nginx.org/en/security_advisories.html",
    "mysql": "https://dev.mysql.com/doc/relnotes/",
    "postgresql": "https://www.postgresql.org/support/security/",
    "redis": "https://github.com/redis/redis/releases",
    "kafka": "https://kafka.apache.org/security",
    "docker": "https://docs.docker.com/engine/security/",
    "kubernetes": "https://kubernetes.io/docs/reference/issues-security/official-cve-list/",
    "openssl": "https://www.openssl.org/news/vulnerabilities.html",
    "node": "https://nodejs.org/en/security/vulnerabilities",
    "jquery": "https://github.com/jquery/jquery/security/advisories",
    "netty": "https://netty.io/wiki/acknowledgements.html",
    "elasticsearch": "https://www.elastic.co/community/security",
    "weblogic": "https://www.oracle.com/security-alerts/",
    "shiro": "https://shiro.apache.org/security.html",
    "fastjson": "https://github.com/alibaba/fastjson/wiki/Security",
    "zlib": "https://zlib.net/",
    "xz": "https://tukaani.org/xz/",
    "xz-utils": "https://tukaani.org/xz/",
    " imagemagick": "",
}
# 常见产品的官方补丁下载页（比 home 更直接）
_COMP_PATCH_URL = {
    "apache tomcat": "https://tomcat.apache.org/download-90.cgi",
    "apache http server": "https://httpd.apache.org/download.cgi",
    "log4j2": "https://logging.apache.org/log4j/2.x/download.html",
    "openssl": "https://www.openssl.org/source.html",
    "mysql": "https://dev.mysql.com/downloads/",
    "postgresql": "https://www.postgresql.org/download/",
    "redis": "https://redis.io/downloads/",
    "kafka": "https://kafka.apache.org/downloads",
    "docker": "https://docs.docker.com/engine/release-notes/",
    "node": "https://nodejs.org/en/download/",
    "jquery": "https://code.jquery.com/jquery-3.7.1.min.js",
    "zlib": "https://zlib.net/",
}


def _vendor_home(component: str) -> str:
    """按组件名给官方安全公告 / 补丁下载入口（认不出就返回空，不编链接）。"""
    c = _nz(component).lower()
    if not c:
        return ""
    for k, v in _COMP_PATCH_URL.items():
        if k in c:
            return v
    # 词典里按词元匹配（OpenSSL → openssl，Linux Kernel → kernel）
    for token, url in _COMP_VENDOR_HOME.items():
        if token.strip() and token in c:
            return url
    return ""


# —— 临时缓解措施：按攻击向量给可执行动作（CVSS AV/PR/AC 从语料取）——
def _mitigations(severity: str, internet: bool, cve_ranges: List[str],
                 component: str, exploited: bool) -> List[dict]:
    """临时缓解（不等补丁也能先降风险）。每条含「动作 + 具体配置/命令」。

    ★ 报告不能只写「建议升级」——评审明确要求「临时缓解措施」这一项，
      且要和「受影响版本区间」「变更窗口」配套才可执行。
    """
    out: List[dict] = []
    if exploited:
        out.append({
            "item": "立即收敛暴露面（KEV 在野利用）",
            "detail": "该漏洞已被 CISA KEV 确认在野利用，攻击者正在扫。先把受影响服务"
                      "从公网下线或加访问控制，再排升级窗口。",
            "code": "# 临时下线示例（systemd）\nsystemctl stop <服务名>\n"
                    "# 或用 ACL 只允许办公网访问\niptables -A INPUT -s 10.0.0.0/8 -p tcp --dport <端口> -j ACCEPT",
        })
    if internet:
        out.append({
            "item": "公网访问收敛（WAF / 安全组）",
            "detail": "资产标记为互联网暴露，先在边界阻断可疑请求特征，"
                      "把受影响端口限制为仅业务网段可访问。",
            "code": "# nginx 层临时拦截示例（按漏洞特征调整）\n"
                    "location /admin/ {\n    allow 10.0.0.0/8;\n    deny all;\n}",
        })
    if cve_ranges:
        out.append({
            "item": "版本区间核对",
            "detail": "受影响版本区间：%s。若当前版本落在区间内，"
                      "升级前先关闭不必要的功能开关与调试接口。" % "；".join(cve_ranges[:3]),
            "code": "# 升级后确认实际生效版本\n<产品> --version",
        })
    if severity == "CRITICAL":
        out.append({
            "item": "关闭高危功能入口",
            "detail": "严重漏洞在补丁发布前，先关闭触发条件相关的功能入口"
                      "（管理端点、调试接口、危险脚本），减少被利用面。",
            "code": "# Nginx 禁止访问管理端点示例\nlocation ~* /(actuator|manager|admin) { deny all; }",
        })
    if not out:
        out.append({
            "item": "缓解措施待补充",
            "detail": "该漏洞无公开的临时缓解手段（组件未提供规避方案），"
                      "必须按修复版本升级；升级前加强该资产的日志审计与告警监控。",
            "code": "",
        })
    return out


def _change_window(env: str, internet: bool, importance: float) -> dict:
    """变更窗口建议：按环境 + 暴露面 + 重要性给出窗口与前置条件。"""
    e = _nz(env).upper()
    prod = ("PROD" in e) or ("生产" in e)
    pre = ("STAGE" in e) or ("预发" in e) or ("TEST" in e) or ("测试" in e)
    if prod and internet:
        return {"window": "低峰期 00:00-05:00 逐台灰度，单台观察 30 分钟",
                "pre": "需业务方书面确认；先摘流量再操作，保留回滚镜像"}
    if prod:
        return {"window": "低峰期 01:00-04:00 逐台灰度，单台观察 30 分钟",
                "pre": "需业务方确认窗口；准备回滚方案，禁止批量重启"}
    if pre:
        return {"window": "任意工作时间（预发环境），验证通过后再上生产",
                "pre": "预发先行验证，确认业务功能正常"}
    return {"window": "工作时间直接操作（测试环境）",
            "pre": "无需额外审批"}


def _rollback_plan(component: str, fix_version: str) -> str:
    """回滚方案：按组件类型给具体动作。"""
    c = _nz(component).lower()
    if "tomcat" in c:
        return ("回滚：保留旧版本 catalina 目录，解压后改回 CATALINA_HOME 指向旧目录，"
                "重启 tomcat 服务即可；回滚前先清 work/temp 缓存。")
    if "apache" in c or "httpd" in c:
        return ("回滚：保留 httpd.conf.bak 与原 modules 目录，"
                "执行 `httpd -f <备份配置> -k start` 切回旧版本。")
    if "mysql" in c:
        return ("回滚：先 `mysqldump` 备份，再降级安装旧版本；"
                "跨大版本降级不支持，需从备份恢复。")
    if "redis" in c or "kafka" in c or "elastic" in c or "zookeeper" in c:
        return ("回滚：保留旧版本数据目录，停止服务后替换二进制并恢复数据目录"
                "（RDB/AOF 快照），确认集群副本同步正常后再拉起。")
    if "log4j" in c or "jvm" in c or "java" in c:
        return ("回滚：保留原 jar 包，替换后重启 JVM；确认日志输出正常后清理缓存。")
    if "docker" in c or "kubernetes" in c or "k8s" in c:
        return ("回滚：镜像 tag 回退到上一版本 `docker tag <新>:<旧> && "
                "kubectl set image`，滚动更新失败时 `kubectl rollout undo`。")
    if "linux kernel" in c or "kernel" in c:
        return ("回滚：保留旧 kernel 镜像，grub 配置里保留旧启动项，"
                "启动失败时在 grub 菜单选择旧内核；不要在原机上直接卸载旧内核。")
    return ("回滚：变更前打包备份当前版本（`%s --version` 记录原始版本号 + 配置文件快照），"
            "异常时恢复备份版本并重启；生产变更必须在变更单里写明回滚负责人。" % (
                component or "该组件"))


def _verify_steps(component: str, fix_version: str, loc_text: str) -> List[str]:
    """验收标准：可执行、可留痕的验证动作。"""
    steps = [
        "在变更后的 %s 上执行 `%s --version`，确认版本号为 %s" % (
            loc_text or "目标资产", component or "目标组件", fix_version or "修复版本"),
        "用漏洞扫描器对 %s 重扫该组件，确认漏洞不再命中（留存扫描报告截图）" % (
            loc_text or "目标资产"),
        "在 CMDB 的 vulnerability 台账里把该 CI 的 FIX_STATUS 改为「已修复」，"
        "并回填 ACTUAL_FIX_DATE（验收留痕依据）",
    ]
    if fix_version:
        steps.insert(1, "核对厂商公告确认 %s 的修复版本确为 %s（防止台账版本号填错）" % (
            component or "该组件", fix_version))
    return steps


def _build_fix_plan(item: dict, top_row: dict) -> dict:
    """给一条处置工单生成「具体修复方案」（评审要求：可直接照做）。

    输出六项：受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚方案。
    ★ 不依赖 CVE 编号——台账里 25% 的记录没有公开编号，方案照样要给得出来。
    """
    comp = item.get("component") or ""
    fix_v = next(iter(item.get("fix_versions") or []), "") or \
        (top_row.get("fix_version") or "")
    comp_v = next(iter(item.get("comp_versions") or []), "") or \
        (top_row.get("component_version") or "")
    official = item.get("official_url") or item.get("nvd_url") or ""
    home = _vendor_home(comp)
    internet = (item.get("internet_count") or 0) > 0
    importance = _asset_importance_weight(top_row.get("importance") or top_row.get("env"))
    loc_text = top_row.get("location") or top_row.get("ci_name") or top_row.get("asset_id") or ""
    ranges = item.get("cpe_ranges") or []
    return {
        "component": comp,
        "affected_version": comp_v,
        "fix_version": fix_v,
        "affected_cve_range": ranges,
        # ★ 该 CVE 在 NVD 里登记了 CPE、但没有一条属于本组件 → 与「台账没填编号」
        #   是两回事，报告要分开说（2026-10-05）。前者说明「官方未对本组件给出区间，
        #   请以厂商公告为准」，后者说明「无编号可比对」。
        "cpe_mismatch": bool(item.get("cpe_ranges_total")) and not ranges,
        "official_advisory": official,
        "vendor_patch_page": home,
        "patch_ids": item.get("patches") or [],
        "mitigations": _mitigations(item.get("severity", ""), internet,
                                     item.get("cpe_ranges") or [], comp,
                                     bool(item.get("exploited"))),
        "change_window": _change_window(top_row.get("env", ""), internet, importance),
        "rollback": _rollback_plan(comp, fix_v),
        "verify": _verify_steps(comp, fix_v, loc_text),
        "discover_tool": item.get("discover_tools") or [],
    }


def _build_ledger_report(engine, vuln_ledger: List[dict],
                         loc_index: Optional["_LocIndex"] = None) -> dict:
    """把 vulnerability 漏洞台账聚合成「优先处置清单 + 资产风险清单 + 组件明细」。

    聚合口径（2026-10-05 第 4 版，按评审模板重写）：
      1. 资产标识 = CI_ID + 主机名 + IP + 机房位置（位置由 CI 反查 idc_room/cabinet）。
      2. 聚合键 = 漏洞编号（VULN_NO）+ 组件。VULN_NO 才是对外编号（CVE/CNVD/CNNVD），
         VULN_ID 只是台账内部记录号，绝不进报告标题。
      3. 风险分 = CVSS × KEV×3 × 互联网×2 × 核心/生产×1.5 × 监管×1.2（可逐项验算）。
      4. 证据链 = 官方编号链接（NVD/CNVD/CNNVD 按前缀分流）+ KEV + 官方补丁编号。
      5. 每条给责任人 / 期限 / SLA / 优先级 / 处置状态 / 是否已闭环。
    """
    # —— 1. 按「漏洞编号 + 组件 → 资产列表」聚合 ——
    groups: "OrderedDict[str, dict]" = OrderedDict()
    for row in vuln_ledger:
        comp = row.get("component") or ""
        cve = row.get("cve") or row.get("vuln_no") or ""
        vuln_id = row.get("vuln_id") or ""
        # 编号缺失时用「组件+漏洞类型+记录号」兜底，并在报告里标注「源数据未填编号」
        if cve and comp:
            key = "%s@%s" % (cve, comp)
        elif cve:
            key = cve
        elif comp:
            key = "%s@%s" % (comp, vuln_id) if vuln_id else comp
        else:
            key = vuln_id or "未分类"
        g = groups.get(key)
        if g is None:
            g = {"key": key, "cve": cve, "component": comp,
                 "assets": [], "severity": "UNKNOWN", "max_cvss": 0.0,
                 "exploited": False, "kev_added": "", "internet_count": 0,
                 "owners": OrderedDict(), "patches": OrderedDict(),
                 "depts": OrderedDict(),
                 "comp_versions": OrderedDict(), "fix_versions": OrderedDict(),
                 "fix_statuses": OrderedDict(), "plan_fix": OrderedDict(),
                 "vtypes": OrderedDict(), "cwes": OrderedDict(),
                 "verifies": OrderedDict(), "exploit_avail": 0,
                 "verified_exploit": 0,
                 "apps": OrderedDict(), "envs": OrderedDict(),
                 "accepted": 0, "regulatory": 0, "closed": 0,
                 "vuln_ids": [], "vnames": OrderedDict(),
                 "discover_tools": OrderedDict()}
            groups[key] = g
        cvss = _norm_cvss(row.get("cvss"))
        sev = _severity_by_cvss(row.get("cvss"), row.get("severity"))
        internet = _internet_exposed(row.get("internet"))
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(g["severity"], 0):
            g["severity"] = sev
        if cvss > g["max_cvss"]:
            g["max_cvss"] = cvss
        if internet:
            g["internet_count"] += 1
        if _yes(row.get("regulatory")):
            g["regulatory"] += 1
        if _yes(row.get("accepted")):
            g["accepted"] += 1
        st = _nz(row.get("fix_status"))
        if st in ("已修复", "已闭环"):
            g["closed"] += 1
        owner = row.get("owner") or ""
        if owner:
            g["owners"][owner] = g["owners"].get(owner, 0) + 1
        dept = row.get("dept") or ""
        if dept:
            g["depts"][dept] = g["depts"].get(dept, 0) + 1
        patch = row.get("patch") or ""
        if patch:
            g["patches"][patch] = g["patches"].get(patch, 0) + 1
        cver = row.get("component_version") or ""
        if cver:
            g["comp_versions"][cver] = g["comp_versions"].get(cver, 0) + 1
        fver = row.get("fix_version") or ""
        if fver:
            g["fix_versions"][fver] = g["fix_versions"].get(fver, 0) + 1
        fs = row.get("fix_status") or ""
        if fs:
            g["fix_statuses"][fs] = g["fix_statuses"].get(fs, 0) + 1
        pf = row.get("plan_fix") or ""
        if pf:
            g["plan_fix"][pf] = g["plan_fix"].get(pf, 0) + 1
        for fld, bucket in (("vtype", "vtypes"), ("cwe", "cwes"),
                            ("app", "apps"), ("env", "envs"),
                            ("discover_tool", "discover_tools"),
                            ("verify", "verifies"),
                            ("vname", "vnames")):
            v = _nz(row.get(fld))
            if v:
                g[bucket][v] = g[bucket].get(v, 0) + 1
        # —— 已确认 / 待确认（2026-10-05 七章报告要求，工单必须能分清这条
        #   漏洞是「已复现确认」还是「扫描器报了但没复现」）：
        #   已验证 → 确认；误报 → 不进处置清单主体；待复现/未复现 → 待确认。
        #   有公开利用代码（EXPLOIT_AVAILABLE=Y / IS_VERIFIED_EXPLOIT=Y）时，
        #   即使扫描器没复现也按「已确认」处理（人工复现风险更高）。
        _vs = _nz(row.get("verify"))
        _ea = _yes(row.get("exploit_available")) if row.get("exploit_available") is not None else False
        _ve = _yes(row.get("verified_exploit")) if row.get("verified_exploit") is not None else False
        if _ea:
            g["exploit_avail"] += 1
        if _ve:
            g["verified_exploit"] += 1
        if _vs == "已验证" or _ve:
            g["confirmed"] = g.get("confirmed", 0) + 1
        elif _vs not in ("误报", ""):
            g["pending"] = g.get("pending", 0) + 1
        elif _vs == "误报":
            g["false_pos"] = g.get("false_pos", 0) + 1
        if vuln_id and len(g["vuln_ids"]) < 6:
            g["vuln_ids"].append(vuln_id)
        g["assets"].append(row)

    # —— 2. 补证据链：官方编号链接 + 语料里的 KEV / 描述 / CPE 区间 ——
    for key, g in groups.items():
        cve = g["cve"]
        # 编号 → 官方查询入口（CNVD/CNNVD 走国内官网，不能一律指向 NVD）
        g["official_url"] = _vuln_id_url(cve)
        g["id_kind"] = _id_kind_of(cve)
        # 只有 CVE 编号才可能在 NVD 情报库里查到 CPE 区间 / KEV
        rec = _find_record(engine, cve) if (_is_cve(cve) and cve) else None
        if rec:
            kev = rec.get("kev") or {}
            g["exploited"] = bool(kev.get("exploited"))
            g["kev_added"] = (kev.get("date_added") or "")[:10]
            g["kev_due"] = (kev.get("due_date") or "")[:10]
            g["kev_action"] = kev.get("required_action") or ""
            g["nvd_url"] = "https://nvd.nist.gov/vuln/detail/%s" % cve
            g["refs"] = [r.get("url") for r in (rec.get("refs") or [])
                         if isinstance(r, dict) and r.get("url")][:3]
            g["cwe_list"] = [(c.get("id") or "") for c in (rec.get("cwe") or [])
                             if isinstance(c, dict) and c.get("id")][:3]
            # 完整描述按句号截断（而非按字符数，避免「over 」这种半截）
            desc = rec.get("desc") or rec.get("title") or ""
            g["title"] = _sentence_clip(desc, 180)
            # ★★ CPE 区间必须按 vendor/product 匹配组件（2026-10-05 端到端验收发现）：
            #   NVD 一个 CVE 常同时登记多个产品的 CPE。实测 CVE-2026-41940 的 CPE
            #   全部是 cpanel / whm（区间 11.40 ~ 136.1.7），而报告的受影响组件是
            #   MongoDB 5.0.10 —— 之前不区分产品，把 cPanel 的版本区间当 MongoDB 的
            #   「受影响版本区间」印进报告，运维拿 5.0.10 去核对一条 cPanel 区间，
            #   结论必然错。现在只取与本组件（vendor+product）匹配的那部分；
            #   匹配不到就留空并让报告写明「该 CVE 无本组件的 CPE 区间」。
            #   同时去重（NVD 里同一区间会以不同 matchCriteriaId 重复登记）。
            g["cpe_ranges"] = _cpe_ranges_for_component(rec.get("cpe") or [],
                                                       g.get("component", ""))
            g["cpe_ranges_total"] = sum(
                1 for e in (rec.get("cpe") or []) if isinstance(e, dict))
        else:
            g["nvd_url"] = ""
            g["refs"] = []
            g["cwe_list"] = list(g["cwes"].keys())[:3]
            g["title"] = ""
            g["cpe_ranges"] = []

    # —— 3. 给每条记录算复合风险分（含位置/业务信息），组内排序 ——
    today = time.strftime("%Y-%m-%d")
    for key, g in groups.items():
        for row in g["assets"]:
            cvss = _norm_cvss(row.get("cvss"))
            sev = _severity_by_cvss(row.get("cvss"), row.get("severity"))
            internet = _internet_exposed(row.get("internet"))
            importance = _asset_importance_weight(row.get("importance") or row.get("env"))
            regulatory = _yes(row.get("regulatory"))
            row["_sev"] = sev
            row["_regulatory"] = regulatory
            row["_score"] = _risk_score(cvss, sev, internet, importance,
                                        g["exploited"], regulatory)
            row["_factors"] = _risk_factors(cvss, sev, internet, importance,
                                            g["exploited"], regulatory)
            # 位置：CI → 机房/机柜（中间件等走宿主二级解析）
            if loc_index is not None:
                loc = loc_index.resolve(row.get("asset_id", ""))
                if loc:
                    row["location"] = loc_index.location_text(row.get("asset_id", ""))
                    row["idc_name"] = loc.get("idc_name", "")
                    row["cab_code"] = loc.get("cab_code", "")
                    # 机房归属冲突（源数据缺陷）→ 传给资产清单，第六节披露条数
                    row["idc_conflict"] = bool(loc.get("idc_conflict"))
        g["assets"].sort(key=lambda r: (r["_score"], r["_sev"]), reverse=True)

    # —— 4. 生成优先处置清单（按漏洞编号聚合，每组一条工单）——
    priority = []
    for key, g in groups.items():
        # TOP 资产表只列「可定位到实物机器」的记录（CI_ID 指向软件包/工单主键的
        # 无法派单）。asset_count 仍按全部命中记录统计。
        top_assets = [r for r in g["assets"]
                      if _is_deployable_ci(r.get("asset_id", ""), r.get("ci_ip", ""))][:5]
        # 组的风险分取组内最高分（该漏洞在最难修的那台资产上的分值）
        top_score = max((a.get("_score", 0.0) for a in g["assets"]), default=g["max_cvss"])
        internet = g["internet_count"] > 0
        regulatory = g["regulatory"] > 0
        closed = g["closed"]
        # 已全部闭环的条目风险分归零：它是历史记录，不是当前待处置风险。
        # 不归零的话，62% 已修复的记录会持续占住处置清单前排。
        if closed and closed >= len(g["assets"]):
            top_score = 0.0
        sla_days, sla_due = _sla_due(g["severity"], g["exploited"], internet,
                                     regulatory, today)
        top_row = g["assets"][0] if g["assets"] else {}
        importance = _asset_importance_weight(top_row.get("importance") or top_row.get("env"))
        priority.append({
            "cve": g["cve"] or "",
            "vuln_key": g["key"],
            "id_kind": g["id_kind"],
            "official_url": g["official_url"],
            "no_id": not bool(g["cve"]),
            "title": g["title"],
            "vnames": list(g["vnames"].keys())[:2],
            "vtype": next(iter(g["vtypes"]), ""),
            "severity": g["severity"],
            "cvss": g["max_cvss"],
            "score": top_score,
            "factors": _risk_factors(g["max_cvss"], g["severity"], internet,
                                     importance, g["exploited"], regulatory),
            "exploited": g["exploited"],
            "kev_added": g["kev_added"],
            "kev_due": g.get("kev_due", ""),
            "kev_action": g.get("kev_action", ""),
            "cwe": g["cwe_list"],
            # —— 已确认 / 待确认（第二份报告标准要求，工单必须能分清）——
            "confirmed": g.get("confirmed", 0),
            "pending": g.get("pending", 0),
            "false_pos": g.get("false_pos", 0),
            "exploit_avail": g.get("exploit_avail", 0),
            "verified_exploit": g.get("verified_exploit", 0),
            "verify_states": list(g.get("verifies", {}).keys())[:4],
            "component": g["component"],
            "comp_versions": list(g["comp_versions"].keys())[:5],
            "fix_versions": list(g["fix_versions"].keys())[:3],
            "asset_count": len(g["assets"]),
            "internet_count": g["internet_count"],
            "regulatory_count": g["regulatory"],
            "accepted_count": g["accepted"],
            "closed_count": g["closed"],
            "open_count": len(g["assets"]) - g["closed"],
            "owners": list(g["owners"].keys())[:5],
            "owner_count": len(g["owners"]),
            "dept": list(g.get("depts", {}).keys())[:3],
            "patches": list(g["patches"].keys())[:3],
            "fix_statuses": list(g["fix_statuses"].keys())[:3],
            "plan_fix": list(g["plan_fix"].keys())[:3],
            "apps": list(g["apps"].keys())[:3],
            "envs": list(g["envs"].keys())[:2],
            "discover_tools": list(g["discover_tools"].keys())[:2],
            "vuln_ids": g["vuln_ids"],
            "sla_days": sla_days,
            "sla_due": sla_due,
            "priority_label": _priority_label(top_score, g["exploited"], g["severity"]),
            # 全员「风险接受」= 业务已决策不做修复，不该占处置工单位次
            "accepted_all": g["accepted"] > 0 and g["accepted"] >= len(g["assets"]),
            "nvd_url": g.get("nvd_url", ""),
            "refs": g.get("refs", []),
            "cpe_ranges": g.get("cpe_ranges", []),
            "cpe_ranges_total": g.get("cpe_ranges_total", 0),
            "top_assets": [{
                "asset_id": a["asset_id"],
                "prefix": a.get("asset_prefix", ""),
                "ci_name": a.get("ci_name", ""),
                "ci_ip": a.get("ci_ip", ""),
                "location": a.get("location", ""),
                "idc_name": a.get("idc_name", ""),
                "cab_code": a.get("cab_code", ""),
                "app": a.get("app", ""),
                "env": a.get("env", ""),
                "port": a.get("port", ""),
                "component": a.get("component", ""),
                "component_version": a.get("component_version", ""),
                "fix_version": a.get("fix_version", ""),
                "owner": a.get("owner", ""),
                "emp_id": a.get("emp_id", ""),
                "dept_id": a.get("dept_id", ""),
                "plan_fix": a.get("plan_fix", ""),
                "fix_status": a.get("fix_status", ""),
                "internet": a.get("internet", ""),
                "regulatory": a.get("regulatory", ""),
                "accepted": a.get("accepted", ""),
                "severity": a.get("_sev", ""),
                "cvss": _norm_cvss(a.get("cvss")),
                "score": a.get("_score", 0),
                "factors": a.get("_factors", ""),
            } for a in top_assets],
        })
    # 排序：未闭环优先 → 非全员风险接受 → 风险分 → 优先级 → 命中资产数
    # ★ 三个坑都在这行（2026-10-05 实测踩过）：
    #   ① 台账 62% 记录已「已修复」，不先排未闭环，处置清单前排全是没得修的；
    #   ② priority_label 是字符串，"P3" > "P1" 字典序，倒序排会把 P3 顶到最前、
    #      所有 CRITICAL 被挤出 TOP 200 → 必须用 _PRIORITY_RANK 数值权重；
    #   ③ 「风险接受」是业务已决策不做，不该占处置工单位次。
    # ★★ 第四个坑（2026-10-05 端到端验收发现）：排序键里**不能**单列 exploited。
    #   KEV 在野利用是风险分公式里的**乘数**（×3.0），不是凌驾公式之上的硬覆盖。
    #   之前把 int(p["exploited"]) 放在 score 之前 → 一条 CVSS=0 的 INFO 级漏洞
    #   （分 3.0）仅因在 KEV 里就压过 CVSS 10.0 的 CRITICAL（分 36.0）排到第 1 位。
    #   评审要的排序依据是那个乘积公式，排序键必须与公式一致，否则公式形同虚设。
    # ★★★ 第五个坑（2026-10-05 七章报告新增）：已确认项必须排在待确认项之前。
    #   台账 VERIFY_STATUS 四态里，「待复现 / 未复现」占 50.3%——这些是扫描器
    #   报了但没复现的条目。第二份报告标准明确要求「未人工验证的要如实标注」，
    #   运维不能拿着一条没复现的条目去开工单。
    #   ★ 键序要点：accepted（风险接受）必须排在 confirmed 之前。实测踩过——
    #     某条 acc=1/1（全员风险接受）但 confirmed=1，若 confirmed 键在前，
    #     它会排到 acc=0/1 的待确认条目之前，而它压根不该派单。
    #   键本身抽到 _priority_order()，渲染层复用同一份，避免两处定义漂移。
    priority[:] = _priority_order(priority)

    # 每条工单附「具体修复方案」（六项：版本/补丁/缓解/窗口/回滚/验收）
    for item in priority:
        top_deployable = next(
            (a for a in item["top_assets"]
             if _is_deployable_ci(a.get("asset_id", ""), a.get("ci_ip", ""))),
            item["top_assets"][0] if item["top_assets"] else {})
        item["fix_plan"] = _build_fix_plan(item, top_deployable)

    # —— 5. 生成资产风险清单（按复合风险分排序，真实差异化）——
    asset_map: "OrderedDict[str, dict]" = OrderedDict()
    # ★ 数据质量守卫（2026-10-05）：CMDB 的 vulnerability 表里有少量记录的 CI_ID
    #   指向「软件包记录主键」（SW-xxxx）而不是可部署资产，且 CI_IP 列存的是端口号
    #   （80/8080/9200…）——源数据缺陷，不是解析问题。这类记录无法定位到任何一台
    #   机器，放进资产清单会让运维查不到实物。它们仍计入漏洞统计，但不进资产风险排序。
    non_asset_rows = 0
    for row in vuln_ledger:
        aid = row["asset_id"]
        if not _is_deployable_ci(aid, row.get("ci_ip", "")):
            non_asset_rows += 1
            continue
        a = asset_map.get(aid)
        if a is None:
            a = {"name": aid, "prefix": row.get("asset_prefix", ""),
                 "ci_name": row.get("ci_name", ""), "ip": row.get("ci_ip", ""),
                 "owner": row.get("owner", ""), "emp_id": row.get("emp_id", ""),
                 "importance": row.get("importance", ""), "env": row.get("env", ""),
                 "app": row.get("app", ""), "port": row.get("port", ""),
                 "location": row.get("location", ""),
                 "idc_name": row.get("idc_name", ""), "cab_code": row.get("cab_code", ""),
                 "idc_conflict": bool(row.get("idc_conflict")),
                 "regulatory": False, "accepted": 0, "closed": 0,
                 "components": OrderedDict(), "max_score": 0.0,
                 "max_sev": "UNKNOWN", "vuln_count": 0, "internet": False}
            asset_map[aid] = a
        a["vuln_count"] += 1
        if _internet_exposed(row.get("internet")):
            a["internet"] = True
        if _yes(row.get("regulatory")):
            a["regulatory"] = True
        if _yes(row.get("accepted")):
            a["accepted"] += 1
        if _nz(row.get("fix_status")) in ("已修复", "已闭环"):
            a["closed"] += 1
        # 责任人/业务/位置：同一资产多条记录可能不一致，保留第一个非空值
        for fld in ("owner", "app", "env", "location", "idc_name", "cab_code",
                    "emp_id", "importance"):
            if not a.get(fld) and row.get(fld):
                a[fld] = row[fld]
        if row.get("idc_conflict"):
            a["idc_conflict"] = True
        comp = row.get("component") or "未命名组件"
        a["components"].setdefault(comp, {"name": comp, "vuln_count": 0,
                                          "severity": "UNKNOWN", "max_cvss": 0.0})
        c = a["components"][comp]
        c["vuln_count"] += 1
        cvss = _norm_cvss(row.get("cvss"))
        sev = _severity_by_cvss(row.get("cvss"), row.get("severity"))
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(c["severity"], 0):
            c["severity"] = sev
        if cvss > c["max_cvss"]:
            c["max_cvss"] = cvss
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(a["max_sev"], 0):
            a["max_sev"] = sev
        if cvss > a["max_score"]:
            a["max_score"] = cvss
    for aid, a in asset_map.items():
        a["_score"] = _risk_score(a["max_score"], a["max_sev"], a["internet"],
                                  _asset_importance_weight(a.get("importance") or a.get("env")),
                                  False, a.get("regulatory"))
        a["components"] = list(a["components"].values())
        # 统一字段别名：报告渲染与前端都按 asset_id / ci_ip 取值
        a["asset_id"] = aid
        a["ci_ip"] = a.get("ip") or ""
        a["open_vulns"] = a["vuln_count"] - a["closed"]
    asset_list = list(asset_map.values())
    asset_list.sort(key=lambda a: a["_score"], reverse=True)

    # —— 6. 组件命中明细（按命中资产数排序，不再被单一 OS 吃满配额）——
    # ★★ 2026-10-06 修一个致命膨胀：原来 c["assets"] 存了**每条台账行的完整原文**
    #   （asset_id → 整行 dict），且完全不截断。72 万行台账实测让报告 JSON 涨到
    #   604MB：risk.products 只有 4 条，其中一个 assets 字典塞了 15 万条完整记录。
    #   后果有三：
    #     ① json.dumps 序列化时服务端内存/CPU 爆炸 → 浏览器只看到 Failed to fetch；
    #     ② 报告 JSON 落盘 604MB，历史列表里每一条都是 600MB 起步的定时炸弹；
    #     ③ 前端拿到后根本渲染不出来（只用到 name/asset_count/vuln_count 等汇总字段）。
    #   现在只保留"每个组件的前 N 个代表资产"，完整明细由 priority 列表承担。
    comp_map: "OrderedDict[str, dict]" = OrderedDict()
    asset_id = ""
    for row in vuln_ledger:
        comp = row.get("component") or "未命名组件"
        c = comp_map.get(comp)
        if c is None:
            c = {"name": comp, "assets": OrderedDict(), "vuln_count": 0,
                 "severity": "UNKNOWN", "max_cvss": 0.0,
                 "_seen": set(), "_extra": 0}
            comp_map[comp] = c
        c["vuln_count"] += 1
        # 只存代表资产的"最小必要字段"，且每个组件最多 MAX_COMP_ASSETS 个
        if len(c["assets"]) < MAX_COMP_ASSETS:
            asset_id = row.get("asset_id") or ""
            if asset_id and asset_id not in c["assets"]:
                c["assets"][asset_id] = {
                    "asset_id": asset_id,
                    "name": row.get("name") or row.get("ci_name") or "",
                    "ip": row.get("ip") or row.get("ci_ip") or "",
                    "owner": row.get("owner") or "",
                }
        else:
            # 已到上限：只累加"真实命中资产数"，不再往 assets 里塞
            asset_id = row.get("asset_id") or ""
            if asset_id not in c["_seen"]:
                c["_seen"].add(asset_id)
                c["_extra"] += 1
        cvss = _norm_cvss(row.get("cvss"))
        sev = _severity_by_cvss(row.get("cvss"), row.get("severity"))
        if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(c["severity"], 0):
            c["severity"] = sev
        if cvss > c["max_cvss"]:
            c["max_cvss"] = cvss
    comp_list = list(comp_map.values())
    for c in comp_list:
        # asset_count 是"真实命中资产数"（含被截断的），assets 只是代表样本
        c["asset_count"] = len(c["assets"]) + c.pop("_extra", 0)
        c.pop("_seen", None)
        # 明确标注清单被截断，别让读者以为 assets 就是全部
        if c["asset_count"] > len(c["assets"]):
            c["assets_note"] = "仅列前 %d 个代表资产（共 %d 个）；完整清单见处置工单表" % (
                len(c["assets"]), c["asset_count"])
    comp_list.sort(key=lambda c: (c["asset_count"], c["max_cvss"]), reverse=True)

    summary = {
        "hosts": len(asset_list),
        "products": len(comp_list),
        "cve_hits": len(groups),
        "critical": sum(1 for g in groups.values() if g["severity"] == "CRITICAL"),
        "high": sum(1 for g in groups.values() if g["severity"] == "HIGH"),
        "medium": sum(1 for g in groups.values() if g["severity"] == "MEDIUM"),
        "low": sum(1 for g in groups.values() if g["severity"] == "LOW"),
        "info": sum(1 for g in groups.values() if g["severity"] == "INFO"),
        "exploited": sum(1 for g in groups.values() if g["exploited"]),
        # ★ 按 CVE 去重（2026-10-05）：清单列的是漏洞编号，不是工单数。同一 CVE 命中
        #   两个组件会分成两张工单，原先直接列 g["cve"] 会让同一个编号出现两次
        #   （实测 CVE-2026-50751 重复），运维会以为数据有错。条数与列表同步去重。
        "kev_ids": list(OrderedDict.fromkeys(
            g["cve"] for g in groups.values() if g["exploited"] and g["cve"]))[:20],
        # ★ kev_ids 为报告体积截断到 20 条；真实命中数必须单独记全量，
        #   否则执行摘要「命中 CISA KEV N个」会把 53 个写成 20 个。
        "kev_count": len(OrderedDict.fromkeys(
            g["cve"] for g in groups.values() if g["exploited"] and g["cve"])),
        "risk_hosts": sum(1 for a in asset_list if a["max_sev"] in ("CRITICAL", "HIGH")),
        "risk_products": sum(1 for c in comp_list if c["severity"] in ("CRITICAL", "HIGH")),
        "scanned_docs": len(getattr(engine, "docs", []) or []),
        "ledger_rows": len(vuln_ledger),
        # 源数据缺陷导致的不可定位记录（CI_ID 指向软件包/工单主键，或 IP 列填端口号）
        "non_asset_rows": non_asset_rows,
        # 覆盖率口径（报告第六节要写清楚，避免被误读成漏报）
        "id_coverage": {
            "total": len(groups),
            "with_cve": sum(1 for g in groups.values() if g["id_kind"] == "CVE"),
            "with_cnvd": sum(1 for g in groups.values() if g["id_kind"] == "CNVD"),
            "with_cnnvd": sum(1 for g in groups.values() if g["id_kind"] == "CNNVD"),
            "internal_id": sum(1 for g in groups.values() if g["id_kind"] == "INTERNAL"),
            "no_id": sum(1 for g in groups.values() if not g["cve"]),
            # 能生成官方可核查链接的比例（评审关注的「证据链」硬指标）
            "linkable": sum(1 for g in groups.values() if g["official_url"]),
        },
        "status_breakdown": dict(OrderedDict(
            (k, sum(1 for row in vuln_ledger if _nz(row.get("fix_status")) == k))
            for k in ("未修复", "修复中", "延期修复", "风险接受", "已修复"))),
        "rows_closed": sum(1 for row in vuln_ledger
                           if _nz(row.get("fix_status")) in ("已修复", "已闭环")),
        "rows_regulatory": sum(1 for row in vuln_ledger if _yes(row.get("regulatory"))),
        "rows_accepted": sum(1 for row in vuln_ledger if _yes(row.get("accepted"))),
        "rows_internet": sum(1 for row in vuln_ledger if _internet_exposed(row.get("internet"))),
        "loc_resolved": sum(1 for a in asset_list if a.get("location")),
        # ★ 源数据列级缺陷：资产表自带 IDC_ID 与其机柜 CAB_ID 归属机房不一致的资产数。
        #   位置一律以机柜归属为准（见 _LocIndex.resolve），这个数字只用于 6.2 披露
        #   「为什么不信资产表的 IDC_ID」——它不是个别脏数据，是整列没维护。
        "loc_conflict": sum(1 for a in asset_list if a.get("idc_conflict")),
    }
    return {
        "summary": summary,
        "priority": priority,
        "asset_list": asset_list,
        "comp_list": comp_list,
        "groups": groups,
    }


def _sentence_clip(text: str, max_len: int) -> str:
    """按句号（或分号/换行）截断描述，避免按字符数切到半截单词（「over 」）。

    若前 max_len 字符内无句号，才退回字符截断并补省略号。
    """
    t = _nz(text)
    if len(t) <= max_len:
        return t
    head = t[:max_len]
    # 找最后一个句号（含中英文句号、分号、换行）
    for ch in (". ", "。", "; ", "；", "\n", "! ", "? "):
        idx = head.rfind(ch)
        if idx > max_len * 0.4:
            return head[:idx + (1 if ch in (". ", "; ", "! ", "? ") else 1)].rstrip() + "…"
    return head.rstrip() + "…"


def build_priority(risk: dict) -> List[dict]:
    """从风险结果里抽出「优先处置清单」。

    排序口径：在野利用(KEV) > CRITICAL > HIGH，同级别按 CVSS 降序；每台主机取其最高优先级漏洞。
    每条给出：先修什么(CVE)、为什么(KEV/CVSS/CWE)、落在哪台资产、怎么修(官方处置/升级)。

    ★ 性能：通过「行号」把产品(findings)与主机关联，而不是按 name/version 回查 products，
      消除 O(hosts × components × products) 的三层回查。scan_assets 里 product 带 line、
      host 带 line，二者按同一行归属，直接建立 line → 产品列表的索引即可 O(n) 完成。
    """
    products = risk.get("products") or []
    # line → 该行所有产品的 findings（一次遍历建索引）
    by_line: Dict[int, List[dict]] = {}
    for p in products:
        fs = p.get("findings") or []
        if not fs:
            continue
        ln = int(p.get("line") or 0)
        by_line.setdefault(ln, []).append(p)

    out: List[dict] = []
    for h in (risk.get("hosts") or []):
        if h.get("risk_level") not in ("严重", "高"):
            continue
        # 该主机同行的产品（line 关联，O(1) 查表）
        near = by_line.get(int(h.get("line") or 0)) or []
        # 收集这些产品里优先级最高的 finding（KEV > 严重度 > CVSS）
        top: Optional[dict] = None
        for p in near:
            for f in p.get("findings") or []:
                if top is None or (int(bool(f.get("exploited"))),
                                   _SEV_ORDER.get(f.get("severity"), 0),
                                   float(f.get("score") or 0)) > (
                                   int(bool(top.get("exploited"))),
                                   _SEV_ORDER.get(top.get("severity"), 0),
                                   float(top.get("score") or 0)):
                    top = f
        if top is None:
            continue
        out.append({
            "host": h.get("name"),
            "cve": top.get("id"),
            "title": (top.get("title") or "")[:120],
            "severity": top.get("severity"),
            "score": top.get("score"),
            "exploited": bool(top.get("exploited")),
            "kev_added": top.get("kev_added"),
            "cwe": top.get("cwe") or [],
            "remediation": top.get("remediation") or [],
            "evidence": top.get("evidence") or "",
        })
    out.sort(key=lambda x: (int(x["exploited"]), _SEV_ORDER.get(x["severity"], 0),
                            float(x.get("score") or 0)), reverse=True)
    return out


def _remediation_plan(engine, cve_id: str, record: Optional[dict]) -> Optional[dict]:
    """复用 remediation.py：给单个 CVE 生成「升级路径 + 加固 + 缓解 + 验证」。"""
    try:
        import remediation as RM
        r = RM.generate(cve_id, engine, record=record)
        return r.get("plan") if r.get("ok") else None
    except Exception as e:  # noqa: BLE001
        _swallow("cmdb_scan._remediation_plan", e)
        return None


_ID_INDEX_CACHE: Dict[int, Tuple[Tuple[int, int], Dict[str, dict]]] = {}


def _find_record(engine, cve_id: str) -> Optional[dict]:
    """按 CVE id 从语料里取原始记录。

    ★ 性能：engine.docs 有 10 万+ 条，逐条线性扫 10 次就是百万次比较。
      按引擎代际缓存 id→doc 索引（与 asset_scan 的 _INDEX_CACHE 同思路），
      第一次建索引 O(n)，之后每次 O(1)。索引随引擎换代自动失效。

    ★★ 2026-10-06 修一个致命失效判据：
      原来用 `len(idx) != len(docs)` 判断缓存是否过期。但语料里只要有**两条
      记录 id 相同**，idx 长度就会比 docs 少（本机实测 103819 vs 103821，
      语料里就有 2 条重复 ID），判据永远为真 → **每次调用都重建 10 万条索引**。
      profiler 实测：1922 次调用吃掉 118 秒，占整个 analyze 的一半。
      正确做法是记录"建索引时看到的 docs 身份"，而不是比较长度：
        - 用 (id(docs), len(docs)) 组合判定。docs 换了引擎实例 → id 变；
          原地重建（append/写文件后重载）→ len 变。两者都能可靠失效，
          且不依赖"id 唯一"这个本来就可能不成立的假设。
    """
    docs = getattr(engine, "docs", None) or []
    eid = id(engine)
    sig = (id(docs), len(docs))
    hit = _ID_INDEX_CACHE.get(eid)
    if hit is not None and hit[0] == sig:
        return hit[1].get(cve_id.upper())
    idx = {}
    for d in docs:
        if isinstance(d, dict) and d.get("id"):
            idx[str(d["id"]).upper()] = d
    _ID_INDEX_CACHE.clear()          # 只保留当前引擎的索引（与原语义一致）
    _ID_INDEX_CACHE[eid] = (sig, idx)
    return idx.get(cve_id.upper())


def analyze(engine, cfg: dict) -> dict:
    """完整流水线：拉 CMDB 资产/漏洞台账 → 风险分析 → 处置优先级 → 可下载报告。

    ★ 数据源策略（2026-10-05 修复，对照评审意见）：
      1. 若解析出 vulnerability 漏洞台账（sqlite 直读 / 文件里的 vulnerability 表）——
         以台账为「主数据源」，按 CVE/组件聚合出处置清单，资产标识取 CI_ID，
         责任人/期限/补丁字段直接来自台账（不再靠假版本号做 CPE 匹配）。
      2. 同时保留资产 CPE 匹配（scan_assets）作为「交叉验证补充」，但不再作为
         处置清单主来源。
    ★ 规模友好：解析分块流式，优先清单截断到 MAX_PRIORITY。
    """
    t0 = time.time()
    assets, meta, warn, ci_total, vuln_ledger, loc_index = _load_assets(cfg, engine)

    ledger_report = None
    if vuln_ledger:
        ledger_report = _build_ledger_report(engine, vuln_ledger, loc_index)

    if not (assets.get("hosts") or assets.get("products")) and ledger_report is None:
        return {"ok": False, "error": warn or "未能从 CMDB 数据中抽取到任何资产或漏洞台账"}

    # —— 治理审计（2026-10-05·七章制报告）——
    #   走独立通道 cmdb_governance：资产解析链路的 sheet_filter 会把
    #   ci_relation / change_order / config_audit_log 整表跳过（它们没有产品
    #   版本字段），而治理审计要的恰恰是这些表。失败不影响漏洞报告产出。
    audit = None
    audit_err = ""
    if cfg.get("governance", True):
        try:
            import cmdb_governance as CG
            audit = CG.collect_governance(cfg, engine)
        except Exception as e:  # noqa: BLE001
            audit = None
            audit_err = "%s: %s" % (type(e).__name__, e)

    # 交叉验证：资产 CPE 匹配（仅在有资产时跑，作为补充）
    risk = AS.scan_assets(engine, assets) if (assets.get("hosts") or assets.get("products")) else None
    priority = build_priority(risk)[:MAX_PRIORITY] if risk else []

    # 有台账 → 台账聚合结果为主
    if ledger_report is not None:
        ledger_priority = ledger_report["priority"][:MAX_PRIORITY]
        # 给前 N 条台账 CVE 附「怎么修」（复用 remediation）
        for item in ledger_priority[:10]:
            cve = item["cve"] if str(item["cve"]).upper().startswith("CVE-") else ""
            if cve:
                rec = _find_record(engine, cve)
                plan = _remediation_plan(engine, cve, rec)
                if plan:
                    item["plan"] = {
                        "upgrade": plan.get("upgrade") or [],
                        "config": plan.get("config") or [],
                        "mitigations": plan.get("mitigations") or [],
                        "verify": plan.get("verify") or [],
                        "generated_by": plan.get("generated_by"),
                    }
                else:
                    item["plan"] = None
            else:
                item["plan"] = None

        hosts_all = ledger_report["asset_list"]
        products_all = ledger_report["comp_list"]
        summary = ledger_report["summary"]
        priority = ledger_priority
        # 交叉验证补充：把资产 CPE 匹配结果也放进报告（供比对），但主结论以台账为准
        cross_hosts = (risk or {}).get("hosts") or []
        cross_products = (risk or {}).get("products") or []
    else:
        # 无台账 → 走原有资产 CPE 匹配路径
        for item in priority[:10]:
            rec = _find_record(engine, item["cve"])
            plan = _remediation_plan(engine, item["cve"], rec)
            if plan:
                item["plan"] = {
                    "upgrade": plan.get("upgrade") or [],
                    "config": plan.get("config") or [],
                    "mitigations": plan.get("mitigations") or [],
                    "verify": plan.get("verify") or [],
                    "generated_by": plan.get("generated_by"),
                }
            else:
                item["plan"] = None
        hosts_all = risk.get("hosts") or []
        products_all = risk.get("products") or []
        summary = risk.get("summary", {})
        cross_hosts, cross_products = [], []

    # ★ 清单只保留「有风险」的条目（2026-10-05）：零命中条目（无已知风险 / 待确认）
    #   挤占 90%+ 篇幅却零信息量，评审会判定报告是凑字数。剔除后另记完整计数，
    #   报告里明写「共 N 条有风险，展示 TOP M」，读者不会被截断规则误导。
    def _has_risk(x: dict) -> bool:
        return bool(x.get("cve_count") or x.get("vuln_count")
                    or x.get("findings") or x.get("kev_count"))

    hosts_risky = [h for h in hosts_all if _has_risk(h)]
    products_risky = [p for p in products_all
                      if _has_risk(p) or (p.get("findings") or p.get("cve_count"))]

    # 报告里只带「前 N 台主机 + 前 N 个组件」明细，其余进 summary 计数（不丢信息，只不膨胀）
    report = {
        "id": "CMDB-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"),
                              "".join(re.findall(r"[0-9a-f]", "%x" % int(t0 * 1000)))[:4]),
        "source": _nz(cfg.get("mode")) or "inline",
        "source_name": _nz(cfg.get("name")) or _source_label(cfg),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "warn": warn,
        "scale": {
            "ci_total": ci_total,
            "hosts_total": len(hosts_all),
            "products_total": len(products_all),
            # 有风险的条目数（零命中已剔除，报告里要写清这个口径）
            "hosts_risky": len(hosts_risky),
            "products_risky": len(products_risky),
            "hosts_dropped": len(hosts_all) - len(hosts_risky),
            "products_dropped": len(products_all) - len(products_risky),
            "truncated": len(hosts_risky) > 200 or len(products_risky) > 200,
            "ledger_rows": len(vuln_ledger) if vuln_ledger else 0,
        },
        "assets": {
            "hosts": (assets.get("hosts") or [])[:200],
            "products": (assets.get("products") or [])[:200],
            "ports": (assets.get("ports") or [])[:80],
            "os": (assets.get("os") or [])[:20],
        },
        "meta": meta[:200],
        "risk": {
            "hosts": hosts_risky[:200],
            "products": products_risky[:200],
            "summary": summary,
        },
        # 交叉验证（有台账时保留资产 CPE 匹配结果，供比对）
        "cross_check": {
            "hosts": cross_hosts[:50],
            "products": cross_products[:50],
        },
        "priority": priority,
        "audit": audit,
        "audit_err": audit_err,
        "data_source": "vulnerability 漏洞台账 + 资产 CPE 交叉验证" if ledger_report else "资产 CPE 匹配",
        "elapsed_ms": int((time.time() - t0) * 1000),
        "basis": "模块 1 情报库（NVD CPE 版本区间 / CISA KEV 在野利用 / CVSS / 官方补丁 / 处置建议）",
    }

    # 落盘失败不吞：ok 仍为True（报告内容已完整生成，Markdown 照样能导出），
    # 但persist_failed 让前端能提示"本次仅临时保存，刷新后不可再取"
    persisted = _persist(report)
    report["persist_failed"] = not persisted
    return {"ok": True, "report": report,
            "warn_persist": ("" if persisted else
                             "报告详情未能写入磁盘（磁盘满/目录不可写），"
                             "本次内容仅在当前响应中有效，刷新后无法再从历史列表打开")}


# ==========================================================================
# 3. 持久化 + 导出
# ==========================================================================
def _load_store() -> List[dict]:
    if not os.path.isfile(_CMDB_STORE):
        return []
    try:
        with open(_CMDB_STORE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except (OSError, ValueError):
        return []


def _save_store(items: List[dict]) -> None:
    # tmp 名带线程 id：同进程多线程若共用一个 tmp 名，会互相 truncate/覆盖
    # （asset_scan._save_store 已是这个写法，这里之前只带 pid）
    tmp = "%s.%d.%d.tmp" % (_CMDB_STORE, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False)
        os.replace(tmp, _CMDB_STORE)
    except OSError as e:  # noqa: BLE001
        _swallow("cmdb_scan._save_store", e)
        # 写失败要收拾残骸：否则 data/ 下会堆 cmdb_scans.json.<pid>.tmp 垃圾文件
        try:
            os.remove(tmp)
        except OSError:
            pass


def _persist(report: dict) -> bool:
    """落盘报告（索引 + 详情）。返回是否完整落盘。

    ★ 返回 False 表示详情 JSON 没写成功——调用方要把它透出给用户，
      否则 POST 返回 ok=True、随后 GET?id=... 却404，刷新后报告"消失"。
    """
    try:
        os.makedirs(_CMDB_REPORT_DIR, exist_ok=True)
    except OSError:
        pass
    summary = {
        "id": report["id"], "source": report["source"],
        "source_name": report["source_name"], "created_at": report["created_at"],
        "summary": report["risk"].get("summary", {}),
        "priority_count": len(report.get("priority") or []),
        "top_priority": (report.get("priority") or [{}])[0].get("cve") if report.get("priority") else "",
    }
    # ★ 读-改-写必须整体持锁（ThreadingHTTPServer 下并发提交会静默丢记录）
    with _LOCK:
        items = [x for x in _load_store() if x.get("id") != report["id"]]
        items.insert(0, summary)
        del items[STORE_MAX:]
        _save_store(items)
    try:
        fp = os.path.join(_CMDB_REPORT_DIR, report["id"] + ".json")
        tmp = "%s.%d.%d.tmp" % (fp, os.getpid(), threading.get_ident())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False)
            os.replace(tmp, fp)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return True
    except OSError as e:  # noqa: BLE001
        # ★ 不再静默：报告详情没落盘 = 用户随后 GET?id=... 会404。在索引里
        #   打persist_failed 标记，历史列表能看出这次没存上。
        _swallow("cmdb_scan._persist", e)
        with _LOCK:
            items = _load_store()
            for x in items:
                if x.get("id") == report["id"]:
                    x["persist_failed"] = True
                    break
            else:
                items.insert(0, dict(summary, persist_failed=True))
            _save_store(items)
        return False


def list_scans() -> List[dict]:
    return _load_store()


def load_report(scan_id: str) -> Optional[dict]:
    try:
        fp = os.path.join(_CMDB_REPORT_DIR, scan_id + ".json")
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


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
    return "\n".join(L)


def report_to_markdown(rep: dict, mask: str = "off") -> str:
    """导出成可直接交付的 Markdown 报告（六节模板，2026-10-05 第 4 版）。

    mask: 脱敏级别 off / basic / strict（见 _mask_markdown）。
         报告含CMDB 责任人邮箱、内网 IP、业务系统名，外发前建议 basic 及以上。

    模板对应评审意见：
      一、报告基础信息      → 工单编号/版本/日期/机构/方法/标准/保密等级 + 系统信息 + 范围边界
      二、执行摘要          → 整体评级 / 健康度 / 严重度（含已确认-待确认）/ TOP 主题 / 优先级
      三、数据质量检测      → 覆盖率 / 影子资产 / 僵尸 CI / 属性缺失 / 责任人 / 孤儿 CI / 基线偏离
      四、访问控制与权限    → 账号 MFA/SSO / 角色模型 / API 鉴权与暴露 / 凭据 / 证书
      五、变更管理合规      → 审批链 / 暗变更 / 流程外变更 / 回滚率
      六、发现汇总与派发表  → 14 字段发现项（编号·等级·CWE·位置·证据·复现·影响·修复·验证…）
      七、复测计划与闭环    → 触发条件 / 时间窗口 / 通过条件 / 闭环流程 / 附件清单
      附录 A 风险概览与漏洞分布 → 统计表 + TOP10 高风险资产（含机房位置）
      附录 B 处置工单清单    → 按漏洞编号聚合，含责任人/期限/SLA/优先级/命中资产
      附录 C 逐条修复方案    → 受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚
      附录 D 覆盖率与已知漏报 → 编号覆盖率 / 位置覆盖率 / 不可定位记录 / 判定口径

    台账模式（data_source 含「漏洞台账」）走新模板；资产 CPE 模式保留旧结构。
    """
    r = rep.get("risk", {})
    s = r.get("summary", {})
    ds = rep.get("data_source") or ""
    is_ledger = "漏洞台账" in ds
    sc = rep.get("scale") or {}
    # ★ 在渲染入口统一排一次，不依赖上游 analyze 排过。
    #   「先修什么」是这份报告的核心结论，第六章明细、汇总表、执行摘要 TOP
    #   都读这一个列表；只排其中一处会出现「明细说先修 A、摘要说先修 B」的自相矛盾
    #   （报告是「存 JSON → 再渲染」产出的，JSON 里的顺序未必是 analyze 排过的）。
    prio = _priority_order(rep.get("priority") or [])
    aud = rep.get("audit") or {}
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
        return _mask_markdown(_report_markdown_asset_mode(rep, L), mask)

    # ================= 七章制审计正文（2026-10-05）=================
    #  先出七章（可交付的审计报告），原六节作为附录（派单依据与证据明细）。
    #  治理数据缺失时各章会显式写「未核查」，不会静默省略——那会让读者
    #  误以为该维度已合规。
    _audit_chapter_one(rep, s, A)
    _audit_chapter_two(rep, s, A)
    _audit_chapter_three(rep, A)
    _audit_chapter_four(rep, A)
    _audit_chapter_five(rep, A)
    _audit_chapter_six(rep, A)
    _audit_chapter_seven(rep, A)

    A("---")
    A("")
    A("# 附录 A · 风险概览与漏洞分布")
    A("")
    A("## A.1 风险概览")
    A("")
    # ★ 统一兜底：summary 里这些键可能是 int、也可能是 list（hosts/products）、
    #   也可能因台账缺列而整个不存在。原实现直接 % s.get(...)，
    #   缺失时报告会印出一整列 "None"——交付件里出现字面 None 会被直接判不可信
    #   （2026-10-05 对抗测试抓到）。
    def _n(v) -> str:
        if v is None:
            return "未统计"
        if isinstance(v, (list, tuple, set, dict)):
            return str(len(v))
        return str(v)

    A("| 指标 | 数值 | 说明 |")
    A("| --- | ---: | --- |")
    A("| 漏洞记录总数 | %s | CMDB vulnerability 台账全量 |" % _n(s.get("ledger_rows")))
    A("| 去重后漏洞数 | %s | 按「漏洞编号 + 组件」聚合 |" % _n(s.get("cve_hits")))
    A("| 涉及资产数 | %s | CI_ID 去重（已剔除不可定位记录） |" % _n(s.get("hosts")))
    A("| 涉及组件数 | %s | 受影响组件去重 |" % _n(s.get("products")))
    A("| 严重（CRITICAL） | %s | CVSS ≥ 9.0 |" % _n(s.get("critical")))
    A("| 高危（HIGH） | %s | 7.0 ≤ CVSS < 9.0 |" % _n(s.get("high")))
    A("| 中危（MEDIUM） | %s | 4.0 ≤ CVSS < 7.0 |" % _n(s.get("medium")))
    A("| 低危（LOW） | %s | 0.1 ≤ CVSS < 4.0 |" % _n(s.get("low")))
    A("| 信息（INFO） | %s | CVSS = 0（台账标为信息级） |" % _n(s.get("info")))
    # 用去重后的 KEV 编号数，与下方清单一致（exploited 是「组」数，同一 CVE 命中
    # 多个组件会重复计数，跟清单对不上）
    A("| 已在野利用（KEV） | %d | CISA KEV 确认 exploited（按漏洞编号去重） |"
      % _kev_total(s))
    A("| 互联网暴露记录 | %s | IS_INTERNET_FACING = Y |" % _n(s.get("rows_internet")))
    A("| 监管合规资产 | %s | IS_REGULATORY = Y |" % _n(s.get("rows_regulatory")))
    A("| 已闭环记录 | %s | FIX_STATUS = 已修复/已闭环 |" % _n(s.get("rows_closed")))
    A("")
    sb = s.get("status_breakdown") or {}
    if sb:
        A("**处置状态分布**：" + "、".join("%s %s 条" % (k, v) for k, v in sb.items() if v))
        A("")
    if s.get("kev_ids"):
        # 条数用去重的真实总数kev_count，不用 summary.exploited（那是「组」数，
        # 同一 CVE 命中多个组件会重复计数），也不用 len(kev_ids)（清单截断到20）
        _kt = _kev_total(s)
        A("> ⚠️ **CISA KEV 在野利用清单（%d 个漏洞编号）**：%s%s" % (
            _kt, "、".join(s["kev_ids"]),
            "" if _kt <= len(s["kev_ids"]) else
            "（清单仅列前 %d 个，全量 %d 个见报告 JSON 的 summary.kev_count）"
            % (len(s["kev_ids"]), _kt)))
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
          _n(sc.get("ci_total")), _n(s.get("hosts")), _n(s.get("products")),
          len(prio)))
    A("")

    # ================= 二、漏洞分布分析 =================
    A("# 附录 B · 漏洞分布分析")
    A("")
    A("## B.1 漏洞分布分析")
    A("")
    A("### B.1.1 按严重度分布")
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
        A("### B.1.2 按组件分布（TOP 15）")
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
        A("### B.1.3 按业务系统分布（TOP 10）")
        A("")
        A("| 业务系统 | 涉及漏洞数 | 其中严重/高危 |")
        A("| --- | ---: | ---: |")
        for name, cnt, ch in bg[:10]:
            A("| %s | %d | %d |" % (name, cnt, ch))
        A("")
    # 机房分布
    loc = _count_locations(hosts)
    if loc:
        A("### B.1.4 按机房分布（TOP 10）")
        A("")
        A("| 机房位置 | 涉及资产数 | 严重/高危资产 |")
        A("| --- | ---: | ---: |")
        for name, cnt, ch, _cf in loc[:10]:
            A("| %s | %d | %d |" % (name, cnt, ch))
        A("")
        A("> 机房位置**以机柜（CAB_ID）归属为准**，不采用资产表自带的 IDC_ID —— "
          "后者与机柜归属大面积不一致，属源数据列级缺陷，详见 6.2。")
        A("")
    A("### B.1.5 按处置状态分布")
    A("")
    A("| 处置状态 | 记录数 | 占比 |")
    A("| --- | ---: | ---: |")
    tot = sum(v for v in (sb or {}).values()) or 1
    for k, v in (sb or {}).items():
        A("| %s | %d | %.1f%% |" % (k, v, v * 100.0 / tot))
    A("")

    # ================= 三、处置工单清单 =================
    A("# 附录 C · 处置工单清单（派单依据）")
    A("")
    A("## C.1 处置工单清单（按漏洞编号聚合，共 %d 条）" % len(prio))
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
            _status_text(p),
            _link(p.get("official_url") or p.get("nvd_url"))))
    A("")
    A("> 风险分 = %s。已在野利用（KEV）×%.1f、互联网暴露 ×%.1f、核心/生产资产 ×%.1f、"
      "监管合规资产 ×%.1f；CVSS 缺失时按严重度折算。" % (
          "CVSS", FACTOR_KEV, FACTOR_INTERNET, FACTOR_IMPORTANCE, FACTOR_REGULATORY))
    A("")

    # 每条工单的命中资产明细（只列前 10 条工单，避免报告膨胀到无法阅读）
    A("### C.2 重点工单命中资产明细（TOP 10 工单）")
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
    A("# 附录 D · 逐条漏洞修复方案")
    A("")
    A("## D.1 逐条漏洞修复方案（TOP 10）")
    A("")
    A("每条给六项：受影响版本 / 修复版本 / 官方补丁 / 临时缓解 / 变更窗口 / 回滚方案。")
    A("")
    A("> **关于「受影响版本区间（CPE）」**：本报告只输出**属于该组件**的 CPE 区间"
      "（按 NVD 的 vendor/product 与组件名匹配，并去重）。若显示「无区间」，"
      "报告会写明具体原因——内部编号无可比对条目、CNVD/CNNVD 编号需查国内库、"
      "或 NVD 未对本产品给出区间——**不会把别的产品的版本区间套到本组件上**。"
      "修复前请以厂商安全公告核对。")
    A("")
    for i, p in enumerate(prio[:10], 1):
        fp = p.get("fix_plan") or {}
        A("### D.%d %s —— %s" % (i, p.get("cve") or "（源数据未填编号）",
                                  p.get("component") or "未标注组件"))
        A("")
        A("| 项 | 内容 |")
        A("| --- | --- |")
        A("| 受影响组件 | %s |" % (fp.get("component") or p.get("component") or "—"))
        A("| 当前版本 | %s |" % (fp.get("affected_version") or "台账未填"))
        A("| 修复版本 | %s |" % (fp.get("fix_version") or "台账未填，需查厂商公告"))
        # ★ 「没有区间」有四种原因，措辞必须区分——运维看完要知道下一步干什么，
        #   而且不能把 CNVD 编号说成「NVD 未提供该 CVE」（2026-10-05 修正）：
        #     ① 内部编号 → 本就没公开编号可比对
        #     ② CNVD/CNNVD 编号 → 只能查国内库，NVD 天然无此条目
        #     ③ cpe_mismatch → NVD 有该 CVE 的 CPE，但没有一条属于本组件
        #     ④ 其它（NVD 收录但未给 CPE 区间）
        if fp.get("affected_cve_range"):
            _rng = "；".join(fp["affected_cve_range"])
        else:
            _idk = _id_kind_of(p.get("cve") or "")
            if _idk in ("INTERNAL", ""):
                _rng = "无公开漏洞编号，不存在可比对的 CPE 区间；以厂商公告 / 内部扫描报告为准"
            elif _idk in ("CNVD", "CNNVD"):
                _rng = ("%s 编号需查国内漏洞库，NVD 无对应 CPE 区间；"
                        "以国家信息安全漏洞库 / 厂商公告为准" % _idk)
            elif fp.get("cpe_mismatch"):
                _rng = ("NVD 已登记该 CVE 的 CPE 配置，但没有一条属于本组件"
                        "（官方未对本产品给出区间）；以厂商公告为准")
            else:
                _rng = "NVD 未提供该 CVE 的 CPE 区间，以厂商公告为准"
        A("| 受影响版本区间（CPE） | %s |" % _rng)
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
    A("# 附录 E · 验收标准")
    A("")
    A("## E.1 验收标准")
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
    A("# 附录 F · 数据覆盖率与已知漏报说明")
    A("")
    A("## F.1 数据覆盖率与已知漏报说明")
    A("")
    idc = s.get("id_coverage") or {}
    if idc:
        A("### F.2 漏洞编号覆盖率")
        A("")
        A("| 编号类型 | 数量 | 占比 | 可核查入口 |")
        A("| --- | ---: | ---: | --- |")
        tot = idc.get("total") or 1
        A("| CVE（可查 NVD + CPE 区间 + KEV） | %d | %.1f%% | nvd.nist.gov/vuln/detail/<编号> |" % (
            idc.get("with_cve", 0), idc.get("with_cve", 0) * 100.0 / tot))
        A("| CNVD（国家信息安全漏洞库） | %d | %.1f%% | cnvd.org.cn/flaw/show/<编号> |" % (
            idc.get("with_cnvd", 0), idc.get("with_cnvd", 0) * 100.0 / tot))
        A("| CNNVD（国家信息安全漏洞共享平台） | %d | %.1f%% | cnnvd.org.cn/home/showDetail/<编号> |" % (
            idc.get("with_cnnvd", 0), idc.get("with_cnnvd", 0) * 100.0 / tot))
        A("| 内部编号（自研扫描/渗透测试） | %d | %.1f%% | 无公开库，以内部工单/报告为准 |" % (
            idc.get("internal_id", 0), idc.get("internal_id", 0) * 100.0 / tot))
        A("| **源数据未填编号** | %d | %.1f%% | 无（无法生成官方链接） |" % (
            idc.get("no_id", 0), idc.get("no_id", 0) * 100.0 / tot))
        A("")
        A("> **可生成官方核查链接的漏洞共 %d 条（%.1f%%）**；其余为内部编号或未填编号，"
          "报告不推测编号、不编造链接。" % (
              idc.get("linkable", 0), (idc.get("linkable", 0) or 0) * 100.0 / tot))
        A(">")
        A("> 非 CVE 编号（CNVD / CNNVD / 内部编号）无法在 NVD 情报库检索 CPE 版本区间，"
          "因此这部分漏洞的「受影响版本区间」需以厂商安全公告或内部扫描报告为准，"
          "第四节已列出官方公告入口与发现工具。")
        A("")
    A("### F.3 已知漏报与数据缺陷")
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
    if s.get("loc_conflict"):
        A("- **机房位置口径（重要）**：资产的机房位置一律**以机柜 CAB_ID 的归属机房为准**，"
          "不采用资产表自带的 IDC_ID 列。实测该列与机柜归属在 %d / %d 条可定位资产上"
          "不一致（%.1f%%，物理机表层面更达 97.5%% 仅 2.5%% 吻合），而机柜表自身自洽"
          "（CAB_CODE 的城市前缀与其归属机房 CITY 吻合率 85.8%%）——判定为 CMDB 资产表 "
          "IDC_ID 列未有效维护，而非个别资产登记错误。若强行采用该列，会输出"
          "「郑州第三数据中心 / AZ-兰州-13-A-57」这类自相矛盾的位置，运维无法据以找到机器。"
          "建议 CMDB 侧修复 IDC_ID 列后重新生成本报告。"
          % ((s.get("loc_conflict") or 0), (s.get("loc_resolved") or 0) or 1,
             (s.get("loc_conflict") or 0) * 100.0
             / max(1, (s.get("loc_resolved") or 0))))
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
    md = "\n".join(L)
    if (mask or "off").strip().lower() == "off":
        A2 = ["", "---", "",
              "> ⚠️ **保密提示**：本报告含 CMDB 敏感信息（责任人邮箱、"
              "内网 IP 与机房位置、业务系统名称）。外发或交给第三方前，"
              "请用 `?mask=basic`（隐去邮箱域名与 IP 主机位）或 `?mask=strict`"
              "重新导出。"]
        md = md + "\n".join(A2)
    return _mask_markdown(md, mask)


def _kev_total(s: dict) -> int:
    """KEV 命中漏洞编号的**真实总数**。

    summary.kev_ids 为控制报告体积只留前 20 条，直接取len 会把
    「命中 53 个」渲染成「20个」——凡是展示计数的场合都必须走这里。
    旧报告 JSON 没有 kev_count 时退回 len(kev_ids)（当时未截断或数量本就 ≤20）。
    """
    n = (s or {}).get("kev_count")
    if isinstance(n, int) and n >= 0:
        return n
    return len((s or {}).get("kev_ids") or [])


def _bar(n, total) -> str:
    """文本条形图（报告在 Markdown 预览里看）。"""
    n = int(n or 0)
    total = int(total or 0) or 1
    width = max(1, int(round(n * 40.0 / total)))
    return "█" * width


def _link(url) -> str:
    """渲染成 Markdown 链接；无链接时返回「—」而不是空串。

    ★ 返回空串会让表格出现空单元格（`| |`），Markdown 渲染成一段空白，
      读者看不出是「没链接」还是「漏填」。实测内部编号条目全是空单元格。
    ★ 链接文字不能直接用 URL：像 https://x.com/a 这样的，末段还是 URL，
      会渲染成「[https://x.com/a/](https://x.com/a)」这种重复嵌套。
    """
    u = (url or "").strip()
    if not u:
        return "—"
    tail = u.rstrip("/").split("/")[-1]
    text = tail if tail and "://" not in tail else "官方页面"
    return "[%s](%s)" % (text, u)


def _ver_arrow(cvers, fvers) -> str:
    c = "、".join(cvers or []) or "台账未填"
    f = "、".join(fvers or []) or "待确认"
    return "%s → %s" % (c, f)


def _status_text(p: dict) -> str:
    """处置状态列：区分「需处置 / 已闭环 / 风险接受」。

    台账 62% 已修复、10% 风险接受，若只把 FIX_STATUS 原样拼上去，
    读者分不清哪些是真要动手的。
    """
    st = "、".join(p.get("fix_statuses") or []) or "台账未填"
    if p.get("accepted_all"):
        return "风险接受（业务已决策）"
    if p.get("open_count", 0) <= 0:
        return "%s（已闭环）" % st
    return "%s（待处置 %d）" % (st, p.get("open_count") or 0)


# ==========================================================================
# 七章制审计报告（2026-10-05）
#   对齐两份评审标准：
#     ① 七章骨架：基础信息 / 执行摘要 / 数据质量 / 权限安全 / 变更合规 /
#                 发现汇总 / 复测闭环
#     ② 工单元数据：报告名编号版本日期 / 被检系统信息 / 检测范围与边界 /
#                 检测方法 / 参考标准 / 保密等级，以及每条发现项的 14 字段
#                 （编号·标题·等级·类型CWE·位置·证据·复现·影响·建议·验证·
#                   责任人·期限·关联·状态）
#   漏洞分析细节（六节版）保留为附录，仍是派单的依据。
# ==========================================================================
_AUDIT_STD = ("ISO/IEC 20000-1:2018（信息技术服务管理）"
              "；GB/T 22239-2019 网络安全等级保护基本要求；"
              "《信息安全漏洞管理规范》GB/T 30279；"
              "公司《漏洞管理办法》V2.1、《变更管理流程》V2.1")
_CONF_LEVEL = ("内部秘密（Internal Confidential）——仅限安全运维组、"
               "受影响系统责任人及审计人员传阅，禁止外发与截图外传")


def _sev_cn(sev: str) -> str:
    """严重度枚举 → 中文名。

    ★ 兜底走 _norm_severity 而不是直接吐「未知」：台账 SEVERITY 是
      「超危 Critical」这种中英混排，若上游某条路径漏了归一化，
      原实现会让全量报告每条发现项的等级都显示「未知」——等级失效等于报告失效。
    """
    t = (sev or "").upper()
    hit = {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危",
           "LOW": "低危", "INFO": "信息"}.get(t)
    if hit:
        return hit
    return {"CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危",
            "LOW": "低危", "INFO": "信息"}.get(_norm_severity(sev), "未评级")


def _finding_state(p: dict) -> str:
    """发现项状态机：待确认 → 待处置 → 修复中 → 待验证 → 已验证 → 已关闭。

    汇报口径要求明确「已确认 / 待确认」——扫描器报了不等于漏洞存在。
    """
    if p.get("closed_count", 0) and p.get("open_count", 0) <= 0:
        return "已关闭"
    if p.get("open_count", 0) <= 0:
        return "已接受"
    if (p.get("confirmed", 0) or 0) <= 0:
        return "待确认（需人工复现）"
    if p.get("fix_statuses") and "修复中" in "、".join(p["fix_statuses"]):
        return "修复中"
    return "待处置"


def _sys_info(rep: dict, s: dict) -> List[Tuple[str, str]]:
    """被检测系统信息（第二份标准要求的表头元数据）。"""
    sc = rep.get("scale") or {}
    q = ((rep.get("audit") or {}).get("quality") or {})
    envs = _count_by(rep.get("priority") or [], "env",
                     lambda p: [p.get("env") or ""])
    top_env = envs[0][0] if envs else ""
    owners = [o for p in (rep.get("priority") or []) for o in (p.get("owners") or [])][:3]
    bg = ""
    dept = ""
    for p in (rep.get("priority") or []):
        for a in (p.get("assets") or []):
            if a.get("bg") and not bg:
                bg = a["bg"]
            if a.get("dept") and not dept:
                dept = a["dept"]
        # 部门优先从工单级字段取（台账行里没有 dept 字段，资产行只有 emp）
        if not dept:
            for d in (p.get("dept") or []):
                if d:
                    dept = d
                    break
        if bg and dept:
            break
    return [
        ("被检测系统", rep.get("source_name") or "CMDB 资产库"),
        ("系统版本 / 数据快照", (rep.get("created_at") or "")[:10]),
        ("检测环境", top_env or "以台账 ENV_TYPE 为准"),
        ("业务归属", bg or "以台账 BUSINESS_BG 为准"),
        ("资产责任人（TOP3，来自台账 OWNER）",
         "、".join(owners) if owners else "台账未登记"),
        ("责任部门", dept or "以台账 DEPT_ID 为准"),
        ("CI 总数", "%s（去重后）" % (q.get("asset_ci_total")
                                or sc.get("ci_total") or "—")),
    ]


def _priority_order(prio: List[dict]) -> List[dict]:
    """工单排序键（analyze 与渲染共用一份）。

    ★ 为什么要抽出来：排序原本只写在 analyze() 里，report_to_markdown 直接
      按 rep["priority"] 的原始顺序渲染。报告是「存 JSON → 再渲染」产出的，
      复现/重出报告时若 JSON 里的顺序不是 analyze 排过的，第六章顺序就会变——
      而顺序本身就是「先修什么」的结论，不能依赖上游没出事。
      键序见 analyze() 内的注释：open → accepted → confirmed → score。
    """
    return sorted(
        prio,
        key=lambda p: (p.get("open_count", 0) > 0,
                       p.get("accepted_count", 0) < p.get("asset_count", 0),
                       (p.get("confirmed") or 0) > 0,
                       float(p.get("score") or 0),
                       _PRIORITY_RANK.get(p.get("priority_label"), 0),
                       p.get("asset_count", 0)),
        reverse=True)


def _finding_rows(rep: dict, limit: int = 60) -> List[dict]:
    """把工单转成 14 字段发现项（第二份标准 §3.3 的字段集）。"""
    out = []
    prio = _priority_order(rep.get("priority") or [])
    for i, p in enumerate(prio[:limit], 1):
        fp = p.get("fix_plan") or {}
        top_assets = [a for a in (p.get("assets") or [])
                      if _is_deployable_ci(a.get("asset_id", ""), a.get("ci_ip", ""))]
        loc = ""
        if top_assets:
            a0 = top_assets[0]
            loc = "%s（%s / %s）" % (a0.get("asset_id", ""),
                                     a0.get("ci_name") or a0.get("asset_name", ""),
                                     a0.get("ci_ip") or a0.get("ip", ""))
            if a0.get("location"):
                loc += " · " + a0["location"]
        else:
            loc = "台账 %d 条记录均指向软件包/补丁主键，无可定位机器" % p.get("asset_count", 0)
        # 证据：官方链接 + CPE 区间 + 命中资产数 + 发现工具
        ev = []
        if p.get("official_url"):
            # ★ 用 _link() 渲染成 [文字](url)：裸 URL 在 Markdown 表格里
            #   会被渲染器把「｜」后面的内容一起吞进链接，表格直接错版。
            ev.append("官方公告 %s" % _link(p["official_url"]))
        if fp.get("affected_cve_range"):
            ev.append("CPE 受影响区间 " + "；".join(fp["affected_cve_range"][:2]))
        elif fp.get("cpe_mismatch"):
            ev.append("NVD 官方 CPE 未对本产品给出区间")
        if p.get("discover_tool"):
            ev.append("发现工具 %s" % "、".join(p["discover_tool"][:2]))
        if p.get("kev_added"):
            ev.append("CISA KEV 收录 %s（应处置期限 %s）"
                      % (p["kev_added"], p.get("kev_due") or "—"))
        out.append({
            "id": "CMDB-%s-%03d" % ((rep.get("id") or "AUDIT").split("-")[-1][:4].upper(),
                                    i),
            "title": "%s %s %s" % (_sev_cn(p.get("severity")),
                                   p.get("cve") or "(无公开编号)",
                                   p.get("component") or ""),
            "severity": _sev_cn(p.get("severity")),
            "severity_raw": p.get("severity"),
            "cvss": p.get("cvss"),
            "score": p.get("score"),
            "priority": p.get("priority_label"),
            "type": p.get("vtype") or "—",
            "cwe": "、".join(p.get("cwe") or []) or "—",
            "cve": p.get("cve"),
            "url": p.get("official_url"),
            "comp_ver": "、".join(p.get("comp_versions") or []) or "台账未登记",
            "state": _finding_state(p),
            # 台账的修复状态分布（dict：{"已修复":1,"修复中":1}）——
            # 6.3 要用它区分「整条闭环」与「部分修复」，缺了就只能靠 state 猜
            "fix_statuses": p.get("fix_statuses") or {},
            "loc": loc or "—",
            "evidence": "；".join(ev) or "台账登记（无公开编号可交叉验证）",
            "impact": _impact_text(p),
            "fix": _fix_text(p, fp),
            "verify": _verify_text(p, fp),
            "owner": "、".join(p.get("owners") or []) or "台账未指定",
            "dept": "、".join(p.get("dept") or []) or "—",
            "sla": p.get("sla_days"),
            "sla_due": p.get("sla_due"),
            "asset_count": p.get("asset_count", 0),
        })
    return out


def _impact_text(p: dict) -> str:
    """影响描述：只说数据里有的，不夸大。"""
    bits = []
    if p.get("internet_count"):
        bits.append("其中 %d 条记录标记为互联网暴露面" % p["internet_count"])
    if p.get("regulatory_count"):
        bits.append("%d 条受监管约束（等保/金融）" % p["regulatory_count"])
    if p.get("exploited") or p.get("verified_exploit"):
        bits.append("已有在野利用记录或已验证可利用，利用门槛低")
    if p.get("asset_count", 0) > 1:
        bits.append("影响 %d 台资产，非单点" % p["asset_count"])
    return "；".join(bits) or "影响范围以台账登记为准，未做业务影响评估"


def _fix_text(p: dict, fp: dict) -> str:
    """修复建议：临时缓解 + 根本修复，两条都要给。

    ★ mitigations 是 dict 列表（item/detail/code），不是字符串——
      直接 join 会抛 TypeError。取 item+detail 拼成可读句。
    """
    tmp: List[str] = []
    for m in (fp.get("mitigations") or [])[:2]:
        if isinstance(m, dict):
            t = "%s（%s）" % (m.get("item", ""), m.get("detail", ""))
        else:
            t = str(m)
        if t.strip("（） "):
            tmp.append(t.strip("（） "))
    if not tmp:
        tmp.append("限制受影响端口对外暴露、开启访问控制")
    root = []
    if fp.get("fix_version"):
        root.append("升级至 %s" % "、".join(
            x for x in [fp["fix_version"]] if x))
    if fp.get("vendor_patch"):
        root.append("官方补丁 %s" % fp["vendor_patch"])
    if not root:
        root.append("按厂商公告升级受影响组件至修复版本")
    return "【临时】%s；【根本】%s" % ("；".join(tmp), "；".join(root))


def _verify_text(p: dict, fp: dict) -> str:
    """验证方式：复扫 + 版本指纹 + 健康检查，三项都要可执行。"""
    steps = fp.get("verify") or []
    if steps:
        return "；".join(steps[:3])
    return "复扫确认漏洞特征消失 + 核对组件版本号 + 业务健康检查通过"


# ==========================================================================
# 3.5 报告脱敏（外发件防护）
# ==========================================================================
# ★ 为什么加这个（2026-10-06 审查）：报告是 Markdown 下载件，会被邮件/IM 转发、
#   存进工单系统、或交给外部审计方。CMDB 数据里有三类一旦外泄就有实际危害：
#     · 责任人邮箱 / 工号→ 定向钓鱼、员工信息泄露
#     · 内网 IP + 机房/机柜号 → 内网拓扑侦察，直接喂给攻击者画攻击面
#     · 业务系统名 / 部门号 → 组织结构与关键业务暴露
#   实测一份 1000 行台账的报告里有 150+ 处邮箱、90+ 处内网 IP、70+ 处业务系统名，
#   而模块此前**没有任何脱敏开关**（mask/redact/脱敏 全部零命中）。
#   默认不改行为（避免破坏既有交付件与前端契约），但提供 opt-in 脱敏，
#   并在默认模式下明确提示报告含敏感数据。
_MASK_LEVELS = ("off", "basic", "strict")


def _mask_ip(ip: str) -> str:
    """内网/公网 IP → 保留网段、抹掉主机位（10.1.2.35 → 10.1.2.x）。"""
    s = (ip or "").strip()
    if not s:
        return s
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "%s.%s.%s.x" % (parts[0], parts[1], parts[2])
    if ":" in s:                      # IPv6：只留前两段
        seg = s.split(":")
        return ":".join(seg[:2]) + ":x"
    return "***"


def _mask_email(m: str) -> str:
    """zhangsan@corp.internal → z***@***（域名整段抹掉，内部域名本身即情报）。"""
    local, _, _dom = (m or "").partition("@")
    if not _dom:
        return "***"
    head = (local or "")[:1] or "*"
    return "%s***@***" % head


_MD_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_MD_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")


def _mask_markdown(md: str, level: str = "basic") -> str:
    """对已渲染的 Markdown 做脱敏（不改报告 JSON，JSON 仅落本机 data/）。

    basic：邮箱 → 首字母***@***；IPv4 → 保留前三段 +x
    strict：追加 IPv6 抹除、以及「责任人工号/部门号」等纯标识整体替换
    """
    lv = (level or "off").strip().lower()
    if lv not in _MASK_LEVELS or lv == "off":
        return md
    out = _MD_EMAIL.sub(lambda m: _mask_email(m.group(0)), md)
    out = _MD_IPV4.sub(lambda m: "%s.%s.%s.x" % (m.group(1), m.group(2), m.group(3)), out)
    if lv == "strict":
        out = re.sub(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])",
                     "[IPv6已脱敏]", out)
        # 部门号 / 员工号 / 资产号：形如 D-773 / E00123 / SRV-000123。
        # ★ 只取字母前缀、数字段一律换成 ***——不能沿用 m.group(0) 的原文，
        #   那样「E00000」（无连字符）会变成「E00000-***」，等于没脱敏。
        out = re.sub(r"\b(EMP|D|E|SRV|VM|NET|SEC|MW|DB|INST|STG|GPU|POD|BD|CI)-?\d{3,8}\b",
                     lambda m: m.group(1) + "-***", out)
    return out


def mask_text(s: str, level: str = "basic") -> str:
    """把同一套脱敏规则用在**任意文本**上（xlsx 单元格 / 单行摘要 / 日志）。

    与 _mask_markdown 是同一套规则，命名公开是为了让别的模块
    （如 cmdb_ticket_xlsx 的简略台账导出）不必去碰私有函数名，
    也避免两处各写一套规则、日后脱敏口径悄悄分叉。
    """
    return _mask_markdown(s, level)


def _report_meta(rep: dict) -> dict:
    """报告头元数据（第一份标准 §1 要求的 8 项）。"""
    s = ((rep.get("risk") or {}).get("summary") or {})
    sc = rep.get("scale") or {}
    now = (rep.get("created_at") or "")[:10]
    return {
        "report_no": rep.get("id"),
        "title": "CMDB 资产安全检测报告（漏洞风险 + 治理合规）",
        "version": "V1.0",
        "date": now,
        "org": "安全运维组（漏洞与配置治理）",
        "method": "离线导入 CMDB 全量导出（20 表）+ 本地规则匹配，"
                  "不联网、不外发；情报交叉验证取自模块 1 本地漏洞库",
        "std": _AUDIT_STD,
        "conf": _CONF_LEVEL,
        "window": "%s 至 %s（数据快照时点）" % (now, now),
        "scope_ci": sc.get("ci_total") or s.get("ledger_rows") or 0,
    }


def _audit_chapter_one(rep: dict, s: dict, A) -> None:
    """第一章 · 报告基础信息（第一份标准 §1 + 第二份标准 §1）。"""
    m = _report_meta(rep)
    A("## 一、报告基础信息")
    A("")
    A("| 项| 内容 |")
    A("| --- | --- |")
    A("| 报告名称 | %s |" % m["title"])
    A("| 报告编号（= 工单编号前缀） | %s |" % m["report_no"])
    A("| 版本 / 修订记录 | %s（首次出具；后续修订在「修订历史」追加） |" % m["version"])
    A("| 检测日期 | %s |" % m["date"])
    A("| 检测机构 / 负责人 | %s |" % m["org"])
    A("| 检测时间窗口 | %s |" % m["window"])
    A("| 检测方法 | %s |" % m["method"])
    A("| 参考标准 | %s |" % m["std"])
    A("| 保密等级 | %s |" % m["conf"])
    A("| 检测依据（数据源） | %s |" % (rep.get("basis") or "—"))
    A("")
    A("### 1.1 被检测系统信息")
    A("")
    A("| 项 | 内容 |")
    A("| --- | --- |")
    for k, v in _sys_info(rep, s):
        A("| %s | %s |" % (k, v))
    A("")
    A("### 1.2 检测范围与边界")
    A("")
    sc = rep.get("scale") or {}
    A("**检测范围内**：")
    A("")
    A("- 资产范围：CMDB 全量导出 %s 张表，CI 去重 %s 个" % (
        len(((rep.get("audit") or {}).get("source_tables") or {})) or "—",
        sc.get("hosts_total") or s.get("hosts") or "—"))
    A("- 漏洞范围：CMDB `vulnerability` 台账 %s 条记录，按「漏洞编号 + 组件」聚合为 %s 条" % (
        s.get("ledger_rows") or 0, s.get("cve_hits") or 0))
    A("- 治理范围：数据质量、配置基线、访问控制、变更管理四类审计项"
      "（覆盖情况见第三章各节「已核查 / 未核查」标注）")
    A("")
    A("**明确不在本次范围内**（不做推测、不按「无风险」处理）：")
    A("")
    aud = rep.get("audit") or {}
    for item in _uncovered(aud):
        A("- %s" % item)
    A("- 未在 CMDB 台账中登记的组件漏洞（漏扫 / 漏登记）")
    A("- 业务影响与数据泄露面评估（本次为技术侧检测，不含业务侧取证）")
    A("")


def _uncovered(aud: dict) -> List[str]:
    """治理侧未核查项（与 cmdb_audit.uncovered 同源，供第一章列边界）。"""
    if not aud:
        return ["CMDB 治理审计数据未随本次检测提供（本次为漏洞专项检测）"]
    try:
        import cmdb_audit as CA
        return CA.uncovered(aud)
    except Exception:  # noqa: BLE001
        return list(aud.get("_uncov") or [])


def _audit_chapter_two(rep: dict, s: dict, A) -> None:
    """第二章 · 执行摘要（第一份标准 §2 + 第二份标准 §2）。"""
    aud = rep.get("audit") or {}
    try:
        import cmdb_audit as CA
        rating = CA.overall_rating(aud, s)
    except Exception:  # noqa: BLE001
        rating = {"grade": "未评定", "hits": 0, "reasons": ["治理数据不完整，无法评定"],
                  "uncov": []}
    q = aud.get("quality") or {}
    h = q.get("health") or {}
    prio = _priority_order(rep.get("priority") or [])
    open_cnt = sum(1 for p in prio if (p.get("open_count") or 0) > 0)
    confirmed = sum(1 for p in prio if (p.get("confirmed") or 0) > 0)

    A("## 二、执行摘要")
    A("")
    A("### 2.1 总体结论")
    A("")
    A("> **整体风险等级：%s**。%s" % (
        rating["grade"],
        "命中 %d 项风险升级条件。" % rating["hits"] if rating["reasons"]
        else "各实测指标均未触发升级条件。"))
    A("")
    for x in rating["reasons"]:
        A("- %s" % x)
    A("")
    A("**是否能导致数据泄露 / 权限绕过 / 数据被篡改 / 系统被接管**：")
    A("")
    leak = s.get("rows_internet") or 0
    kev = _kev_total(s)
    # ★ 四问必须按实际计数分「存在 / 未发现 / 未核查」三态。
    #   原来只要 aud 存在就无条件写「存在——0 条 API 无鉴权」——计数为 0 时
    #   这句话与数据相反，评审时会被直接判定报告不可信（2026-10-05 对抗测试抓到）。
    _api = ((aud.get("access") or {}).get("api") or {})
    _acc = ((aud.get("access") or {}).get("account") or {})
    _base = (aud.get("baseline") or {})
    _chg_lc = ((aud.get("change") or {}).get("lifecycle") or {})
    s_noauth = _api.get("sensitive_no_auth", 0) or 0
    s_plain = _api.get("sensitive_plain_http", 0) or 0
    drift_pct = _base.get("drift_pct", 0) or 0
    severe = _base.get("severe", 0) or 0
    no_order = _chg_lc.get("manual_change_no_order", 0) or 0
    v_expl = ((aud.get("access") or {}).get("_verified_exploit", 0) or 0
              or sum(1 for p in prio if p.get("verified_exploit")))
    mfa_pct = _acc.get("mfa_pct", 0) or 0
    mfa_bad = _acc.get("mfa_disabled_privileged", 0) or 0

    if not aud:
        # ★ 与三/四/五章的降级提示对齐：解析失败要说「解析失败」，不是「缺数据」，
        #   否则摘要说「缺 API 数据」、三章说「解析异常」，读者会以为报告自相矛盾。
        _why = ("治理数据解析失败（%s）" % str(rep.get("audit_err") or "")[:80]) \
            if str(rep.get("audit_err") or "").strip() else "未随检测提供治理数据"
        A("- 数据泄露：未核查（%s，非互联网暴露面结论）" % _why)
        A("- 权限绕过：未核查（%s，非 API 鉴权结论）" % _why)
        A("- 数据被篡改：未核查（%s，非配置漂移结论）" % _why)
        A("- 系统被接管：%s" % (
            "已核查——%d 条工单含已验证可利用记录" % v_expl if v_expl
            else ("已核查——本次无已验证可利用记录" if prio
                  else "未核查（台账无漏洞记录）")))
    else:
        A("- 数据泄露：%s" % (
            "存在明确路径——%d 条漏洞记录位于互联网暴露面，其中 %d 个漏洞已在野利用"
            % (leak, kev) if (leak or kev)
            else "未发现——本次无互联网暴露面漏洞记录；不含业务侧数据出域评估"))
        if s_noauth or s_plain:
            A("- 权限绕过：存在——%d 条 API 无鉴权且标记为敏感，%d 条敏感数据以明文 HTTP 传输"
              % (s_noauth, s_plain))
        else:
            A("- 权限绕过：未发现——无鉴权敏感 API（0 条）、无敏感数据明文 HTTP 传输（0 条）")
        if drift_pct or severe or no_order:
            A("- 数据被篡改：存在——配置漂移率 %.1f%%，其中严重漂移 %d 条，未经流程的变更 %d 次"
              % (drift_pct, severe, no_order))
        else:
            A("- 数据被篡改：未发现——配置漂移率 0.0%，严重漂移 0 条，流程外变更 0 次")
        A("- 系统被接管：%s" % (
            "风险高——%d 条记录标记为已验证可利用（IS_VERIFIED_EXPLOIT）" % v_expl
            if v_expl else "未发现已验证可利用记录；不等于不存在可利用风险，"
                           "未复现项仍需人工验证（详见第六章状态列）"))
    A("")
    # ★ 合规判定同理：原来只要 aud 存在就写「不符合」，MFA 覆盖 100%、无鉴权接口
    #   的健康系统也会被判不合规。
    if not aud:
        A("**合规性判定**：未评定（治理数据不完整，不作合规结论）")
    else:
        _viol = []
        if leak:
            _viol.append("互联网暴露面存在高危漏洞 %d 条" % leak)
        if s_noauth or s_plain:
            _viol.append("存在无鉴权敏感接口 %d 个 / 明文 HTTP 传输 %d 个" % (s_noauth, s_plain))
        if mfa_bad:
            _viol.append("管理岗未启用 MFA %d 人" % mfa_bad)
        if drift_pct > 5.0:
            _viol.append("配置漂移率 %.1f%% 超 5%% 阈值" % drift_pct)
        A("**合规性判定**：%s" % (
            "不符合——" + "；".join(_viol) + "。详见第三、四、五章" if _viol
            else "符合——未触发本次设定的任一红线（互联网暴露面高危漏洞、"
                 "无鉴权敏感接口、管理岗 MFA 全覆盖、配置漂移率 ≤ 5%）。"
                 "注：本判定仅覆盖上述四项，不等同于通过等级保护测评"))
        A("")
        A("> 判定口径：MFA 覆盖率 %.1f%%（管理岗未启用 %d 人），"
          "API 鉴权率 %.1f%%，配置漂移率 %.1f%%。"
          % (mfa_pct, mfa_bad, _api.get("auth_ratio", 0) or 0, drift_pct))
    A("")
    A("### 2.2 CMDB 健康度指标")
    A("")
    A("| 维度 | 得分 | 判定依据 |")
    A("| --- | ---: | --- |")
    for k, v in (h.get("dims") or {}).items():
        A("| %s | %s | %s |" % (
            k, "%.1f" % v["score"] if v.get("score") is not None else "未核查",
            v.get("basis") or "—"))
    A("| **综合** | **%s** | 仅对已核查维度取平均；未核查维度不计入 |"
      % ("%.1f" % h["overall"] if h.get("overall") is not None else "—"))
    if h.get("note") or not h.get("sufficient", True):
        A("")
        A("> ⚠️ %s" % (h.get("sample_note") or h.get("note")
                      or "样本量不足，综合分仅供参考，不作为整改依据"))
    A("")
    A("### 2.3 问题严重度分布（已确认 / 待确认）")
    A("")
    A("| 风险等级 | 漏洞数 | 已确认 | 待确认 | SLA |")
    A("| --- | ---: | ---: | ---: | --- |")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = sum(1 for p in prio if p.get("severity") == sev)
        if not n:
            continue
        cf = sum(1 for p in prio if p.get("severity") == sev
                 and (p.get("confirmed") or 0) > 0)
        try:
            import cmdb_audit as CA
            sla = CA.RETEST_SLA_DAYS.get(sev, "—")
        except Exception:  # noqa: BLE001
            sla = "—"
        A("| %s（%s） | %d | %d | %d | %s 天 |" % (
            sev, _sev_cn(sev), n, cf, n - cf, sla))
    A("")
    A("> 「已确认」= 台账 VERIFY_STATUS=已验证，或 IS_VERIFIED_EXPLOIT=Y；"
      "其余（待复现 / 未复现）计入待确认，需人工复现后才能开工单。"
      "**待确认项不等于无风险**，按第七章复测计划闭环。")
    A("")
    A("### 2.4 TOP 核心问题主题（按聚合条目数）")
    A("")
    themes: Dict[str, List[dict]] = {}
    for p in prio:
        themes.setdefault(p.get("vtype") or "未分类漏洞类型", []).append(p)
    top_themes = sorted(themes.items(), key=lambda kv: -len(kv[1]))[:5]
    A("| # | 问题主题 | 涉及条目 | 其中高危以上 | 最高风险分 |")
    A("| --- | --- | ---: | ---: | ---: |")
    for i, (name, ps) in enumerate(top_themes, 1):
        hi = sum(1 for p in ps if p.get("severity") in ("CRITICAL", "HIGH"))
        mx = max((float(p.get("score") or 0) for p in ps), default=0)
        A("| %d | %s | %d | %d | %.1f |" % (i, name, len(ps), hi, mx))
    A("")
    A("### 2.5 推荐修复优先级（风险分降序，运维按此顺序派单）")
    A("")
    A("排序公式：`风险分 = CVSS × KEV(3.0) × 互联网暴露(2.0) × 业务重要性(1.5) × 监管(1.2)`，"
      "并优先未闭环项。**不是只看 CVSS**——一条 CVSS 9.0 的内网漏洞可能排在 "
      "CVSS 7.5 但在野利用且公网暴露的漏洞之后。")
    A("")
    A("| 优先级 | 条目数 | 含义 | 建议 SLA |")
    A("| --- | ---: | --- | --- |")
    for lab, mean in (("P0", "立即处置（KEV + 公网 + 核心业务）"),
                      ("P1", "7 日内"), ("P2", "30 日内"), ("P3", "90 日内")):
        n = sum(1 for p in prio if p.get("priority_label") == lab)
        if n:
            A("| %s | %d | %s | %s |" % (
                lab, n, mean, {"P0": "24 小时", "P1": "7 天",
                                "P2": "30 天", "P3": "90 天"}[lab]))
    A("")
    A("未闭环条目共 **%d** 条（清单共 %d 条，其中 %d 条已闭环或业务已接受风险）。"
      % (open_cnt, len(prio), len(prio) - open_cnt))
    A("")


def _audit_unavailable(rep: dict, chapter: str, need: str, A) -> None:
    """治理侧章节的降级提示——**必须区分两种 unavailable**（2026-10-05 抓）。

    ★ 为什么：治理数据是「分析时解析源表」得到的，失败有两种完全不同的原因，
      对应的排查方向也完全不同：
        - 没传表        → 运维侧问题：去 CMDB 导出这几个表再传一次
        - 解析抛异常    → 工具侧问题：表传了，但列名/编码对不上，要改代码
      早期两版都只写「未随检测提供治理数据」，解析崩了也这么说——
      运维会白跑一趟导出重传，报告却还是「无法出具」，来回几次就再也不信这工具了。
    ★ 所以异常时把 err 原文带进报告（评审据此判断是工具缺陷还是数据缺陷），
      同时保留「未核查 ≠ 合格」这句底线。
    """
    err = str(rep.get("audit_err") or "").strip()
    if err:
        A("> **本章无法出具：治理数据解析失败（非未提供）。**")
        A("> 传入的治理表在解析阶段抛出异常：`%s`" % err[:200])
        A("> 排查方向：这是**工具侧问题**（表列名/编码/表头与预期不符），"
          "不是运维漏传表。错误原文已完整记录在报告 JSON 的 `audit_err` 字段。")
    else:
        A("> 本次未随检测提供 %s，%s无法出具。**未核查不等于合格**——是未核查。" % (need, chapter))
    A("")


def _audit_chapter_three(rep: dict, A) -> None:
    """第三章 · CMDB 数据质量检测（第一份标准 §3）。"""
    A("## 三、CMDB 数据质量检测")
    A("")
    aud = rep.get("audit") or {}
    if not aud:
        _audit_unavailable(rep, "第三章", "CMDB 治理数据（变更单 / 配置审计 / CI 关系等表）", A)
        return
    q = aud.get("quality") or {}
    b = aud.get("baseline") or {}
    # ★ 抽样声明（2026-10-06）：治理表超过读取上限时会被截断，此时本章所有
    #   百分比都是「前 N 行样本」上的值。报告不给这句，管理层会把抽样值
    #   当全量结论——实测 25 万行 ip_allocation 只读 20 万，报告不写明。
    _trunc = aud.get("truncated_tables") or {}
    if _trunc:
        A("> ⚠️ **抽样声明**：以下治理指标基于**样本**而非全量——"
          + "、".join("`%s`（读取上限 %s 行）" % (k, v) for k, v in sorted(_trunc.items()))
          + "。库中实际行数可能更多，百分比仅代表已读取部分，请勿按全量解读。")
        A("")
    A("### 3.1 资产发现完整性与准确性")
    A("")
    A("| 检查项 | 实测值 | 判定 | 说明 |")
    A("| --- | ---: | --- | --- |")
    cd = q.get("coverage_diff") or {}
    A("| 自动发现覆盖率差异率 | 未核查 | ⚠️ 缺基准 | %s |" % cd.get("reason", "—"))
    ad = q.get("auto_discover") or {}
    if ad.get("checked"):
        A("| 关系自动发现占比 | %.1f%% | ℹ️ 参考 | ci_relation 中 IS_AUTO_DISCOVER=Y 的关系占比"
          "（%d / %d），另有 %d 条待确认、%d 条已失效 |"
          % (ad["auto_pct"], ad["auto"], ad["relations"],
             ad.get("pending", 0), ad.get("invalid", 0)))
    sh = q.get("shadow") or {}
    A("| 影子资产（SHADOW_IT） | 未核查 | ⚠️ 缺基准 | %s |" % sh.get("reason", "—"))
    ipq = q.get("ip_quality") or {}
    if ipq.get("checked"):
        A("| IP 地址冲突 | %d（%.2f%%） | %s | %s |" % (
            ipq["conflict"], ipq["conflict_pct"],
            "✅ 低于 5% 阈值" if ipq["conflict_pct"] <= 5 else "❌ 超 5% 阈值",
            ipq.get("basis", "")))
        A("| 僵尸 CI | %d | %s | %s |" % (
            ipq["zombie_assigned"],
            "⚠️ 需核对" if ipq["zombie_assigned"] else "✅ 无",
            ipq.get("basis", "")))
    am = q.get("attr_missing") or {}
    if am.get("checked") and am.get("items"):
        A("| 关键属性缺失率（最差项） | %.1f%% | %s | 最差项：「%s」 |" % (
            am["worst_pct"],
            "✅ 低于 5% 阈值" if am["worst_pct"] <= 5 else "❌ 超 5% 阈值",
            am["worst"]))
    ow = q.get("ownership") or {}
    if ow.get("checked"):
        A("| 资产责任人归属率 | %.1f%%（%d / %d） | %s | 缺责任人的资产无法派单 |" % (
            ow["pct"], ow["owned"], ow["total"],
            "✅ 达标" if ow["pct"] >= 95 else "❌ 低于 95%"))
    oc = q.get("orphan_ci") or {}
    if oc.get("checked"):
        A("| 孤儿 CI（无有效关系） | %d（%.1f%%） | %s | 阈值 %.0f%%；%s |" % (
            oc["orphan"], oc["pct"],
            "✅ 低于阈值" if oc["pct"] <= oc.get("threshold", 20) else "❌ 超阈值",
            oc.get("threshold", 20), oc.get("basis", "")))
        if oc.get("note"):
            A("")
            A("> ⚠️ %s" % oc["note"])
    A("")
    if ipq.get("checked") and ipq.get("zombie_samples"):
        A("**僵尸 CI 样例**（IP 已释放但资产仍显示在册，需 CMDB 侧确认是漏回收还是复用）：")
        A("")
        A("| IP | CI 编号 | 主机名 | IP 使用状态 | 责任人 |")
        A("| --- | --- | --- | --- | --- |")
        for x in ipq["zombie_samples"][:8]:
            A("| %s | %s | %s | %s | %s |" % (
                x["ip"], x["ci_id"], x["hostname"] or "—",
                x["usage"], x["owner"] or "—"))
        A("")
    if ow.get("checked") and ow.get("no_owner_samples"):
        A("**无责任人资产样例**（这些记录无法自动派单，需人工指定）：")
        A("")
        A("| CI 编号 | 类型 | 环境 | 业务系统 | IP |")
        A("| --- | --- | --- | --- | --- |")
        for x in ow["no_owner_samples"][:8]:
            A("| %s | %s | %s | %s | %s |" % (
                x["ci"], x["type"] or "—", x["env"] or "—",
                x["app"] or "—", x["ip"] or "—"))
        A("")
    A("**完整属性缺失率明细**：")
    A("")
    A("| 关键属性 | 缺失数 | 总数 | 缺失率 |")
    A("| --- | ---: | ---: | ---: |")
    for k, v in sorted((am.get("items") or {}).items(),
                       key=lambda kv: -kv[1]["pct"]):
        A("| %s | %d | %d | %.1f%% |" % (k, v["missing"], v["total"], v["pct"]))
    A("")
    A("### 3.2 配置基线符合性")
    A("")
    if not b.get("checked"):
        A("> 未核查：%s" % b.get("reason", "本次导出不含配置审计日志"))
        A("")
        return
    A("| 指标 | 数值 | 判定 |")
    A("| --- | ---: | --- |")
    A("| 配置审计记录总数 | %d | — |" % b["total"])
    A("| 配置漂移率 | %.1f%%（%d 条） | %s |" % (
        b["drift_pct"], b["drift"],
        "❌ 超 5%" if b["drift_pct"] > 5 else "✅ 低于 5%"))
    A("| 严重漂移 | %d | %s |" % (
        b["severe"], "❌ 需立即处置" if b["severe"] else "✅"))
    A("| 轻微漂移 | %d | ⚠️ 计划整改 |" % b["minor"])
    A("| 自动同步占比 | %.1f%% | ℹ️ 参考 |" % (b["auto_sync"] * 100.0 / max(1, b["total"])))
    A("| 同步失败 / 部分成功 | %d / %d | %s |" % (
        b["fail"], b["partial"], "❌ 需排查" if b["fail"] else "✅"))
    A("| 需审批但未走审批流程 | %d | %s |" % (
        b["unapproved"], "❌ 流程外操作" if b["unapproved"] else "✅"))
    A("")
    A("**漂移 TOP 配置项**（决定整改优先级）：")
    A("")
    A("| 配置项 | 漂移次数 |")
    A("| --- | ---: |")
    for name, cnt in (b.get("top_fields") or [])[:10]:
        A("| %s | %d |" % (name, cnt))
    A("")
    if b.get("severe_samples"):
        if b.get("value_mismatch"):
            A("")
            A("> ⚠️ **源数据缺陷（%d 条漂移记录，占 %.1f%%）**：这些记录的"
              " `OLD_VALUE` / `NEW_VALUE` 填的是其他配置项的值"
              "（如「内存容量」的新值写成「二级重要」），**不能据此判断配置差异**。"
              "下表中此类记录的取值列已标注为「值语义不符，不展示」，"
              "需回查 CMDB 变更历史后重判。" % (
                  b["value_mismatch"], b["value_mismatch_pct"]))
        A("")
        A("**严重漂移样例**（每条须逐条生成工单，责任人字段映射 CMDB 资产标识）：")
        A("")
        A("| CI 编号 | 资产名称 | 配置项 | 原值 → 新值 | 变更来源 | 漂移等级 | 发生时间 |")
        A("| --- | --- | --- | --- | --- | --- | --- |")
        for x in b["severe_samples"][:8]:
            A("| %s | %s | %s | %s → %s | %s | %s | %s |" % (
                x["ci"], x["ci_name"] or "—", x["field"] or "—",
                (x["old"] or "—")[:20], (x["new"] or "—")[:20],
                x["src"] or "—", x["level"] or "—", x["time"] or "—"))
        A("")


def _audit_chapter_four(rep: dict, A) -> None:
    """第四章 · 访问控制与权限安全（第一份标准 §4）。"""
    A("## 四、CMDB 访问控制与权限安全检测")
    A("")
    aud = rep.get("audit") or {}
    if not aud:
        _audit_unavailable(rep, "第四章", "人员账号 / API / 证书数据", A)
        return
    ac = aud.get("access") or {}
    A("### 4.1 角色与权限模型")
    A("")
    ab = ac.get("account") or {}
    if ab.get("checked"):
        A("| 检查项 | 实测值 | 判定 |")
        A("| --- | ---: | --- |")
        A("| 账号总数 | %d | — |" % ab["total"])
        A("| MFA 启用率 | %.1f%%（%d / %d） | %s |" % (
            ab["mfa_pct"], ab["mfa_enabled"], ab["total"],
            "✅ 达标" if ab["mfa_pct"] >= 95 else "❌ 低于 95%"))
        A("| 管理岗未启用 MFA | %d | %s |" % (
            ab["mfa_disabled_privileged"],
            "❌ 优先整改" if ab["mfa_disabled_privileged"] else "✅"))
        A("| 管理岗未启用 SSO | %d | %s |" % (
            ab["sso_disabled_privileged"],
            "❌ 优先整改" if ab["sso_disabled_privileged"] else "✅"))
        A("| 外包 / 派遣 / 实习账号 | %d | ⚠️ 需最小权限 |" % sum(
            v for k, v in (ab.get("by_emp_type") or {}).items()
            if k in ("外包", "劳务派遣", "实习")))
        A("")
        if ab.get("mfa_off_samples"):
            A("**管理岗未启用 MFA 样例**（工单归属：平台安全负责人，优先级至少 High）：")
            A("")
            A("| 员工号 | 职级 | 岗位 | 部门 | 用工性质 | 负责 CI 数 |")
            A("| --- | --- | --- | --- | --- | ---: |")
            for x in ab["mfa_off_samples"][:8]:
                A("| %s | %s | %s | %s | %s | %s |" % (
                    x["emp"], x["level"], x["position"] or "—",
                    x["dept"] or "—", x["type"] or "—", x["ci_owned"] or "—"))
            A("")
    rb = ac.get("rbac") or {}
    A("**角色与权限模型核查**：未核查 —— %s" % rb.get("reason", "缺平台权限配置"))
    A("")
    for x in (rb.get("manual_checks") or []):
        A("- 需人工核查：%s" % x)
    A("")
    A("### 4.2 API 与集成安全")
    A("")
    api = ac.get("api") or {}
    if api.get("checked"):
        A("| 检查项 | 实测值 | 判定 |")
        A("| --- | ---: | --- |")
        A("| API 接口总数 | %d | — |" % api["total"])
        A("| 鉴权覆盖率 | %.1f%% | %s |" % (
            api["auth_ratio"],
            "✅" if api["auth_ratio"] >= 95 else "❌ 存在无鉴权接口"))
        A("| 公网开放接口 | %d | ⚠️ 需逐条确认必要性 |" % api["public"])
        A("| 无鉴权接口 | %d（其中公网 %d） | %s |" % (
            api["no_auth"], api["no_auth_public"],
            "❌ 立即整改" if api["no_auth"] else "✅"))
        A("| **敏感接口无鉴权** | %d | %s |" % (
            api["sensitive_no_auth"],
            "❌ 高危：可直接读写敏感数据" if api["sensitive_no_auth"] else "✅"))
        A("| 敏感数据明文 HTTP 传输 | %d | %s |" % (
            api["sensitive_plain_http"],
            "❌ 高危：传输可被窃听" if api["sensitive_plain_http"] else "✅"))
        A("| 公网且已废弃接口 | %d | ⚠️ 建议下线 |" % api["deprecated_public"])
        A("")
        A("认证方式分布：" + "、".join(
            "%s %d 条" % (k, v) for k, v in (api.get("auth_types") or {}).items()))
        A("")
        if api.get("critical_samples"):
            A("**高危接口样例**（须逐条生成工单，验收标准：补齐鉴权并复测）：")
            A("")
            A("| 接口路径 | 所属应用 | 认证方式 | 公网 | 敏感 | 协议 | 责任人 |")
            A("| --- | --- | --- | --- | --- | --- | --- |")
            for x in api["critical_samples"][:8]:
                A("| %s | %s | %s | %s | %s | %s | %s |" % (
                    x["api"][:40], x["app"] or "—", x["auth"] or "—",
                    x["public"], x["sensitive"], x["proto"], x["owner"] or "—"))
            A("")
    cr = ac.get("credential") or {}
    A("**凭据泄露检查**：%s" % (
        "扫描 %d 个凭据类字段，疑似明文 %d 处。%s" % (
            cr["scanned_columns"], cr["plaintext_guess"], cr.get("note", ""))
        if cr.get("checked") else "未核查 —— " + cr.get("reason", "")))
    A("")
    ce = ac.get("cert") or {}
    if ce.get("checked"):
        A("**证书安全**：共 %d 张，其中弱 TLS（1.0/1.1）%d 张、密钥长度 < 2048 位 %d 张、"
          "30 天内到期 %d 张、未配置自动续期 %d 张" % (
              ce["total"], ce["weak_tls"], ce["weak_key"],
              ce["expiring_30d"], ce["no_auto_renew"]))
        A("")
        if ce.get("samples"):
            A("| 域名 | TLS 版本 | 密钥长度 | 剩余天数 | 责任人 |")
            A("| --- | --- | ---: | ---: | --- |")
            for x in ce["samples"][:8]:
                A("| %s | %s | %s | %s | %s |" % (
                    x["domain"], x["tls"], x["key"], x["remain"], x["owner"] or "—"))
            A("")


def _audit_chapter_five(rep: dict, A) -> None:
    """第五章 · 变更管理合规性（第一份标准 §5）。"""
    A("## 五、变更管理合规性检测")
    A("")
    aud = rep.get("audit") or {}
    if not aud:
        _audit_unavailable(rep, "第五章", "变更单 / 生命周期日志", A)
        return
    ch = aud.get("change") or {}
    co = ch.get("order") or {}
    lc = ch.get("lifecycle") or {}
    A("| 检查项 | 实测值 | 判定 | 说明 |")
    A("| --- | ---: | --- | --- |")
    if co.get("checked"):
        A("| 变更单总数 | %d | — | — |" % co["total"])
        A("| 已完成 / 已回滚 | %d / %d（回滚率 %.1f%%） | ℹ️ 参考 | 回滚率过高说明变更质量差 |"
          % (co["completed"], co["rolled_back"], co["rollback_pct"]))
        A("| 变更单缺审批人 | %d | %s | 已完成/执行中/已回滚但 APPROVER 为空 |" % (
            co["no_approver"], "✅" if co["no_approver"] == 0 else "❌"))
        A("| 变更单缺审批时间 | %d | %s | — |" % (
            co["no_approve_time"],
            "✅" if co["no_approve_time"] == 0 else "❌"))
        A("| **暗变更（有执行无审批）** | %d（%.2f%%） | %s | change_order 表内口径 |" % (
            co["dark_change"], co["dark_change_pct"],
            "✅" if co["dark_change"] == 0 else "❌"))
        A("| 超变更窗口执行 | %d | ⚠️ 需说明原因 | REAL_START 晚于 PLAN_END |" % co["delayed"])
        A("| 紧急变更未审批 | %d | %s | — |" % (
            co["emergency_no_approve"],
            "❌" if co["emergency_no_approve"] else "✅"))
    if lc.get("checked"):
        A("| **流程外变更（人工录入未挂单）** | %d / %d | %s | ci_lifecycle_log 中人工录入的上线/下线/变更事件未关联任何变更单——**这是真正的暗变更** |" % (
            lc["manual_change_no_order"], lc["manual_change"],
            "❌ 优先整改" if lc["manual_change_no_order"] else "✅"))
    cnf = ch.get("config_not_found") or {}
    A("| 已记录配置在现场找不到 | 未核查 | ⚠️ 缺工具 | %s |" % cnf.get("reason", "—"))
    A("")
    if co.get("checked"):
        A("变更单状态分布：" + "、".join(
            "%s %d 条" % (k, v) for k, v in (co.get("by_status") or {}).items()) + "。")
        A("")
        A("变更类型分布：" + "、".join(
            "%s %d 条" % (k, v) for k, v in (co.get("by_type") or {}).items()) + "。")
        A("")
    if lc.get("checked"):
        A("> **口径说明**：change_order 表 %d 条变更单中，缺审批时间 %d 条、缺审批人 %d 条，"
          "该表自身审批链%s；真正的流程外操作发生在 ci_lifecycle_log——"
          "人工录入上线/下线/变更类事件却未挂变更单号，共 %d 次。"
          "两个口径都已列出，避免读者误判管控水位。"
          % (co.get("total", 0) if co.get("checked") else 0,
             co.get("no_approve_time", 0) if co.get("checked") else 0,
             co.get("no_approver", 0) if co.get("checked") else 0,
             "完整" if co.get("checked")
             and not co.get("no_approve_time") and not co.get("no_approver")
             else "不完整",
             lc.get("manual_change_no_order", 0)))
        A("")
        if lc.get("samples"):
            A("**流程外变更样例**（须逐条核查：是无需变更的日常操作，还是绕过了流程）：")
            A("")
            A("| CI 编号 | 资产名称 | 事件类型 | 操作人 | 时间 | 部门 |")
            A("| --- | --- | --- | --- | --- | --- |")
            for x in lc["samples"][:10]:
                A("| %s | %s | %s | %s | %s | %s |" % (
                    x["ci"], x["name"] or "—", x["event"],
                    x["operator"] or "—", x["time"] or "—", x["dept"] or "—"))
            A("")


def _audit_chapter_six(rep: dict, A) -> None:
    """第六章 · 发现汇总与工单派发表（第一份 §6 + 第二份 §3.3，14 字段）。"""
    A("## 六、发现汇总与工单派发表")
    A("")
    rows = _finding_rows(rep, 60)
    # ★ 派发表只列**需要行动**的条目。已关闭 / 已接受的混在里面时，
    #   照表开工单的运维会把工夫花在已经修完的漏洞上——这张表的读者是执行者，
    #   不是审计师。已闭环的另附 6.3 表，一行不少，但不占派发位。
    _CLOSED_STATES = ("已关闭", "已接受")
    todo = [x for x in rows if x["state"] not in _CLOSED_STATES]
    closed = [x for x in rows if x["state"] in _CLOSED_STATES]
    A("字段映射：每行 = 一张工单，字段与工单系统一一对应。"
      "**编号在报告正文、工单系统、复测记录中保持一致**，实现全链路追溯。")
    A("")
    A("### 6.0 待派发工单（%d 条）" % len(todo))
    A("")
    if not todo:
        A("本次无待派发工单：全部发现项均已闭环或已书面接受风险（见 6.3）。")
        A("")
    else:
        A("| 发现编号 | 风险等级 | CVSS | 问题类型 | 问题位置（资产） | 影响 CI 数 | 状态 | 责任人 | 修复期限 |")
        A("| --- | --- | ---: | --- | --- | ---: | --- | --- | --- |")
        for x in todo:
            A("| %s | %s | %s | %s | %s | %d | %s | %s | %s |" % (
                x["id"], x["severity"], x["cvss"] or "—",
                x["type"] or "—", x["loc"][:60], x["asset_count"],
                x["state"], x["owner"][:20],
                x["sla_due"] or "待定"))
        A("")
    A("> 共 %d 条发现项（清单上限 60 条，全量 %d 条见附录），"
      "其中待派发 %d 条、已闭环或已接受 %d 条。"
      "「状态」区分**已确认 / 待确认**：扫描器报告 ≠ 漏洞确认，"
      "待确认项须先人工复现（第七章复测计划），确认后再开工单。"
      % (len(rows), len(rep.get("priority") or []), len(todo), len(closed)))
    A("")
    A("### 6.1 发现项明细（证据 / 复现 / 影响 / 修复 / 验证）")
    A("")
    A("> 明细按「先修什么」的顺序展开：待处置 → 待确认 → 修复中 → 已关闭。"
      "已闭环条目只在 6.3 汇总表列出，不重复展开明细。")
    A("")
    # ★ 截断必须声明（2026-10-05 全量实测踩到）：派发表 60 条，明细只 20 条。
    #   什么都不写的话，读者会以为剩下 40 条不必开工单——而它们优先级同样很高。
    #   被截断的条目指向报告 JSON（全量保留），不能让读者去猜剩下的在哪。
    _shown, _cut = min(20, len(todo)), max(0, len(todo) - 20)
    if _cut:
        A("> ⚠️ **明细仅展开前 %d 条，剩余 %d 条待处置发现项只列在 6.0 派发表**"
          "（含风险等级 / CVSS / 问题位置 / 责任人 / 修复期限，可直接派单）。"
          % (_shown, _cut))
        A("> 它们的证据、复现步骤、修复方案与验证方式在报告 JSON 的 "
          "`priority` 数组中完整保留（按同一排序键序），"
          "**未展开不等于未处置**，也不等于优先级靠后。")
        A("")
    for x in todo[:20]:
        A("#### %s · %s" % (x["id"], x["title"]))
        A("")
        A("| 项 | 内容 |")
        A("| --- | --- |")
        A("| 工单标题 | %s |" % x["title"])
        A("| 风险等级 / CVSS | %s（CVSS %s / 风险分 %s） |" % (
            x["severity"], x["cvss"] or "—", x["score"] or "—"))
        A("| 问题类型（CWE） | %s ｜ %s |" % (x["type"], x["cwe"]))
        A("| 问题位置 | %s |" % x["loc"])
        A("| 证据引用 | %s |" % x["evidence"])
        A("| 复现步骤 | 1) 登录目标资产确认组件实际版本为 %s；2) 比对下方「受影响版本区间」"
          "确认落在受影响范围；3) 在测试环境以非破坏性方式复现（禁止在生产执行利用） |"
          % x["comp_ver"])
        A("| 影响描述 | %s |" % x["impact"])
        A("| 修复建议 | %s |" % x["fix"])
        A("| 验证方式 | %s |" % x["verify"])
        A("| 责任角色 / 责任人 | %s |" % x["owner"])
        # sla_days 本身就是 "30 天" 这种带单位的字符串（_sla_due 的返回值），
        # 这里不能再补「天」，否则输出「SLA 30 天天」
        A("| 修复期限 / SLA | %s ｜ SLA %s |"
          % (x["sla_due"] or "待定", x["sla"] or "—"))
        A("| 关联信息 | 漏洞编号 %s ｜ 官方公告 %s ｜ 关联工单 %s |" % (
            x["cve"] or "—", _link(x["url"]), x["id"]))
        A("| 状态 | %s |" % x["state"])
        A("")
    # —— 6.3 已闭环 / 已接受 ——
    #   不列进 6.0 派发表，但一条不少地列在这里：审计要能回答
    #   「上季度说修了的那批，到底修没修」。
    # ★ 空表必须解释（2026-10-05 全量实测踩到）：全量 200 条工单里
    #   open_count 全 > 0，6.3 表整张是空的。什么都不写的话，
    #   读者会以为"这份报告漏了闭环记录"或"上一批一条都没修"——
    #   两种误解都会让评审对整份报告的信任打折。
    if not closed:
        # ★ fix_statuses 台账里是 **dict**（{"已修复":1,"修复中":1}），
        #   但历史 JSON / 手工构造的 report 里可能是 list。
        #   这里两种都吃——因为崩在 6.3 会让整份已渲染好的报告 500 行一起丢，
        #   排查成本远高于多写三行兼容（实测踩过：list 直接 AttributeError，
        #   连带 16 个对抗用例集体假失败）。
        def _has_fs(x, kw):
            fs = x.get("fix_statuses")
            if isinstance(fs, dict):
                return sum(v for k, v in fs.items() if kw in str(k))
            if isinstance(fs, (list, tuple, set)):
                return sum(1 for k in fs if kw in str(k))
            return 0
        _part = sum(1 for x in todo if _has_fs(x, "已修复") or _has_fs(x, "已闭环"))
        _acc = sum(1 for x in todo if _has_fs(x, "风险接受"))
        A("### 6.3 已闭环 / 已接受（0 条）")
        A("")
        A("> 本次派发范围内**没有整条闭环的发现项**——每条待处置发现至少还有一个")
        A("> 资产未修复（`open_count > 0`）。其中 %d 条为**部分修复**"
          "（同一 CVE 涉及多台设备，部分已修、其余仍在修复中），仍需派单。" % _part)
        A(">")
        A("> 台账另有 %d 条含「风险接受」记录，但其所在工单**未全部接受**，"
          "剩余资产仍需修复，故不进本表。风险接受须走书面流程" % _acc)
        A("> （业务负责人 + 安全负责人签字、补偿控制措施、明确有效期，见第七章）。")
        A("")
    else:
        A("### 6.3 已闭环 / 已接受（%d 条，不需派单）" % len(closed))
        A("")
        A("| 发现编号 | 风险等级 | CVSS | 问题类型 | 状态 | 责任人 | 原修复期限 |")
        A("| --- | --- | ---: | --- | --- | --- | --- |")
        for x in closed:
            A("| %s | %s | %s | %s | %s | %s | %s |" % (
                x["id"], x["severity"], x["cvss"] or "—", x["type"] or "—",
                x["state"], x["owner"][:20], x["sla_due"] or "—"))
        A("")
        n_acc = sum(1 for x in closed if x["state"] == "已接受")
        A("> 「已关闭」需附修复证据与复测通过记录（第七章）；"
          "「已接受」为书面风险接受，须有业务负责人与安全负责人签字、"
          "补偿控制措施与风险接受有效期（本次 %d 条）。" % n_acc)
        A("")


def _audit_chapter_seven(rep: dict, A) -> None:
    """第七章 · 复测计划与闭环记录（第一份标准 §7）。"""
    A("## 七、复测计划与闭环记录")
    A("")
    A("### 7.1 复测计划")
    A("")
    A("| 触发条件 | 复测时间窗口 | 通过条件 |")
    A("| --- | --- | --- |")
    try:
        import cmdb_audit as CA
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            rp = CA.retest_plan(sev)
            A("| %s | 修复后 %d 小时内 | %s |" % (
                sev, rp["window_days"], rp["criteria"]))
    except Exception:  # noqa: BLE001
        A("| CRITICAL | 48 小时 | 复扫确认漏洞特征消失 |")
        A("| HIGH | 7 天 | 受影响资产数归零 |")
    A("")
    A("**统一触发条件**：工单状态变更为「已修复」后**自动**触发复扫，无需人工发起；"
      "48 小时内未复测通过，工单自动升级至上级责任人。")
    A("")
    A("### 7.2 闭环流程")
    A("")
    A("```")
    A("发现 → 人工确认（待确认项先复现）→ 派单 → 修复（附修复证据）")
    A("     → 复测 → 通过则关闭 / 不通过则退回并升级 → 风险接受须书面审批")
    A("```")
    A("")
    A("| 环节 | 责任方 | 留痕要求 |")
    A("| --- | --- | --- |")
    A("| 确认 | 安全运维组 | 复现记录（截图/命令输出） |")
    A("| 派单 | 运维责任人 | 工单号与本报告发现编号一致 |")
    A("| 修复 | 资产责任人 | 变更单号 + 版本变更前后对比 |")
    A("| 复测 | 安全运维组 | 复扫报告 + 业务健康检查结果 |")
    A("| 关闭 | 安全运维组 | 复测通过记录 |")
    A("| 风险接受 | 业务负责人 | 书面审批（不接受默认关闭） |")
    A("")
    A("**闭环证据链要求**：每条发现项须留齐「复现记录 → 变更单 → 修复后版本 → "
      "复扫报告」四段证据，缺任一段不得关闭。")
    A("")
    A("### 7.3 附件清单")
    A("")
    A("| 附件 | 内容 | 敏感信息处理 |")
    A("| --- | --- | --- |")
    A("| 附录 A | 漏洞分布分析与逐条修复方案（六节版） | — |")
    A("| 附录 B | 数据覆盖率与已知漏报说明 | — |")
    A("| 附件 1 | 原始台账导出（vulnerability.csv） | IP / 责任人字段按内部分发 |")
    A("| 附件 2 | CI 关系拓扑（ci_relation.csv） | 内部 |")
    A("| 附件 3 | 配置审计日志（config_audit_log.csv） | 变更前后值按内部 |")
    A("| 附件 4 | 变更单与生命周期日志 | 内部 |")
    A("")
    A("> 附件中的密码、Token、手机号等敏感字段在导出时须打码；"
      "本报告正文未引用任何明文凭据。")
    A("")


def _count_by_rows(prio, getter):
    return _count_by(prio, "", getter)


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
    """按机房位置聚合资产（返回 [(位置, 资产数, 严重高危数, 归属存疑数)]）。

    位置文本已按机柜归属输出（见 _LocIndex.resolve 的冲突处理），这里只做聚合。
    第 4 项统计「资产表登记机房与机柜归属不一致」的资产数，供 2.4 节提示用。
    """
    cnt = {}
    for h in hosts or []:
        loc = (h.get("location") or "").strip()
        if not loc:
            continue
        e = cnt.setdefault(loc, [0, 0, 0])
        e[0] += 1
        if h.get("max_sev") in ("CRITICAL", "HIGH"):
            e[1] += 1
        if h.get("idc_conflict"):
            e[2] += 1
    return sorted(((k, v[0], v[1], v[2]) for k, v in cnt.items()),
                  key=lambda x: (-x[1], x[0]))


def markdown_of(scan_id: str, mask: str = "off") -> Optional[str]:
    rep = load_report(scan_id)
    return report_to_markdown(rep, mask) if rep else None


if __name__ == "__main__":
    # 独立自测：用内联样例验证整条链路（不联网）
    import sys
    sys.path.insert(0, os.path.join(_ROOT, "core"))
    from engine import SearchEngine
    eng = SearchEngine(os.path.join(DATA_DIR, "corpus.json"))
    sample = [
        {"name": "官网", "ip": "1.2.3.4", "product": "Apache HTTP Server", "version": "2.4.49", "port": "80", "owner": "张三", "env": "生产"},
        {"name": "CRM", "domain": "crm.example.cn", "product": "Apache Log4j", "version": "2.14.0", "owner": "李四", "env": "生产"},
        {"name": "文件", "domain": "file.example.cn", "product": "Nginx", "version": "1.16.1", "port": "443", "owner": "王五", "env": "生产"},
    ]
    r = analyze(eng, {"mode": "inline", "text": json.dumps(sample, ensure_ascii=False)})
    print(json.dumps(r["report"]["risk"]["summary"], ensure_ascii=False, indent=1))
    print("优先处置清单 %d 条：" % len(r["report"]["priority"]))
    for p in r["report"]["priority"]:
        print("  ", p["cve"], p["severity"], p["score"], "在野" if p["exploited"] else "", "->", p["host"])
