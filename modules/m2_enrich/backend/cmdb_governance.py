# -*- coding: utf-8 -*-
"""把 cmdb_audit 的治理指标接进 cmdb_scan 主流程。

★ 为什么单独一个桥接层：
  cmdb_scan._cmdb_sheet_filter 会把 ci_relation / change_order / config_audit_log
  这类「没有产品版本字段」的表整表跳过（它们对漏洞分析零贡献）——这是对的，
  但治理审计恰恰要用这些表。所以这里绕过资产解析链路，直接从原始字节
  抽治理表，两条路互不干扰：

    漏洞风险  ← cmdb_scan 资产解析链路（sheet_filter 过滤）
    治理审计  ← 本模块（不过滤，全表扫描）

数据量参考（E:\\cmdb\\csv 实测 20 表）：治理侧要读 700000 行 ci_relation，
约 25s。这是全量审计的固有成本，不是 bug——若某次只需漏洞报告，
调用方可以不传 governance=True 跳过。
"""
from __future__ import annotations

import csv
import io
import os
import re
from typing import Any, Dict, List, Optional

from cmdb_audit import collect, tables_from_records, tables_from_sqlite

# 只在这些扩展名里找治理表（xlsx 走 cmdb_scan 的 doc.rows 通道，见下）
_TEXT_EXT = (".csv", ".tsv", ".txt")


def _rows_from_bytes(name: str, data: bytes) -> List[List[str]]:
    """把上传的字节流解成二维记录（首行为表头）。"""
    if not data:
        return []
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return []
    delim = "\t" if name.lower().endswith(".tsv") else ","
    try:
        return list(csv.reader(io.StringIO(text), delimiter=delim))
    except Exception:  # noqa: BLE001
        return []


def collect_governance(cfg: dict, engine=None) -> Optional[Dict[str, Any]]:
    """按 mode 采集治理表并算出审计指标。返回 None 表示该模式无治理数据源。

    支持：
      file    → cfg["files"]=[{filename,data}]，扫 CSV/TSV；xlsx 走 openpyxl 直读
      sqlite  → cfg["paths"]（多库，2026-10-06）/ cfg["path"]（单库）直读，逐库合并
      inline  → cfg["text"] 多表块
      rest    → 不支持（治理表需一次性全量拉取，REST 分页语义不明）
    """
    mode = (cfg.get("mode") or "inline").strip()
    tables: Dict[str, List[Dict[str, str]]] = {}
    trunc: Dict[str, Any] = {}

    if mode == "sqlite":
        # ★ 多库合并（2026-10-06）：路径来源三选一（paths 列表 / path / db 别名），
        #   逐库抽治理表再合并。分库存放（资产库 / 关系库 / 变更库各自一个文件）
        #   是真实 CMDB 的常态，只读第一个库会让治理指标整片缺失。
        paths: List[str] = []
        raw = cfg.get("paths")
        if isinstance(raw, (list, tuple)):
            paths = [str(p).strip() for p in raw if str(p or "").strip()]
        for key in ("path", "db"):
            p = str(cfg.get(key) or "").strip()
            if p and p not in paths:
                paths.append(p)
        for p in paths:
            for k, v in tables_from_sqlite(p).items():
                if k == "__truncated__":
                    # 截断留痕不能当成一张治理表混进tables（classify/collect 都会当数据）
                    for tk, tv in (v or {}).items():
                        trunc.setdefault(tk, tv)
                    continue
                tables.setdefault(k, []).extend(v)
    elif mode == "file":
        for f in (cfg.get("files") or []):
            name = f.get("filename") or ""
            data = f.get("data") or b""
            if not data:
                continue
            low = name.lower()
            if low.endswith(_TEXT_EXT):
                rows = _rows_from_bytes(name, data)
            elif low.endswith((".xlsx", ".xlsm")):
                rows = _rows_from_xlsx(name, data)
            else:
                continue
            for k, v in tables_from_records(rows).items():
                tables.setdefault(k, []).extend(v)
    elif mode == "inline":
        text = (cfg.get("text") or "").strip()
        if not text:
            return None
        delim = "\t" if "\t" in text.splitlines()[0] else ","
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delim))
        except Exception:  # noqa: BLE001
            return None
        tables = tables_from_records(rows)
    else:
        return None

    if not tables:
        return None
    audit = collect(tables)
    audit["source_tables"] = {k: len(v) for k, v in sorted(tables.items())}
    if trunc:
        # 被limit_rows 截断的表：报告必须写明「以下指标基于前 N 行样本」
        audit["truncated_tables"] = {k: int(v[0]) for k, v in sorted(trunc.items())}
    return audit


def _rows_from_xlsx(name: str, data: bytes, max_rows: int = 200000) -> List[List[str]]:
    """xlsx 直读（**遍历全部 sheet**，不是只读第一个）。

    故意不依赖 cmdb_scan 的 read_upload：那条路带 sheet_filter，
    会把 ci_relation / change_order 整表跳过。

    ★ 2026-10-06 修：原来只取 sheetnames[0]，多 sheet 导出时其余治理表**静默丢失**。
      CMDB 导出成"一个 xlsx 多个 sheet"是极常见的形态（资产/关系/变更/审计各一个 sheet），
      只读第一个等于把治理指标算在残缺数据上，而报告里看不出任何异常。
      openpyxl 已经把整本加载了，多遍历几个 sheet 的成本可以忽略。

    合并策略：按 sheet 顺序读，**跳过看起来是新表头的行**——多 sheet 拼接后
    中间会出现第二份表头，直接按数据行处理会把 "VULN_NO" 之类的字符串当成一条记录。
    """
    try:
        import openpyxl
    except ImportError:
        return []
    try:
        import io as _io
        wb = openpyxl.load_workbook(_io.BytesIO(data), read_only=True,
                                    data_only=True)
        out: List[List[str]] = []
        first_row = True
        for sname in wb.sheetnames:
            ws = wb[sname]
            for i, row in enumerate(ws.iter_rows(values_only=True)):
                if len(out) >= max_rows:
                    break
                cells = ["" if c is None else str(c).strip() for c in row]
                if not any(cells):
                    continue
                if first_row:
                    out.append(cells)      # 第一行是主表头
                    first_row = False
                    continue
                # 后续 sheet 的表头行：非空单元格全是"像列名的短标识"才跳过
                if _looks_like_header(cells):
                    continue
                out.append(cells)
            if len(out) >= max_rows:
                break
        wb.close()
        return out
    except Exception:  # noqa: BLE001
        return []


def _looks_like_header(cells: List[str]) -> bool:
    """判断一行是不是表头（用于跳过多 sheet 拼接时中间的重复表头）。

    判据：非空单元格 ≥2，且全部"看起来像列名"（短、无空格、不是数字、
    不含中文数据特征）。宁可漏跳（多一行脏数据，classify_table 会忽略），
    也不要错跳（把真数据丢了）。
    """
    vals = [c for c in cells if c]
    if len(vals) < 2:
        return False
    for c in vals:
        if len(c) > 32 or " " in c:
            return False
        if c.replace(".", "").isdigit():
            return False
        if len(c) > 2 and re.search(r"[\u4e00-\u9fff]", c) and "_" not in c:
            # 纯中文且不像列名（列名一般是 CI_ID / 责任人 这类）→ 当数据
            return False
    return True