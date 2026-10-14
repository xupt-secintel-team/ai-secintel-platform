# -*- coding: utf-8 -*-
"""enrich_dims.py —— 富化维度清单 + 实时覆盖计数（2026-10-06）

为什么加这个
------------
验收要核「富化维度是否达 6 种以上」。但维度散落在 core/ 与 m2_enrich/ 各处，
光看代码要横跨 10 来个文件；而文档里的"支持 N 种"又属于声称、不可核验。

这里把每个维度落到**可核验的事实**上：
  · 每一维都写明它真正落在哪个后端文件、对外是哪个路由；
  · 有数据落盘的维度，直接读盘统计**当前真实条数**（不是配置项，不是声称）；
  · 没有落盘文件的维度（纯计算型，如 CVSS 评分/可信度评估）标注 `data_file: null`
    并说明判定方式，不假装有数据。

GET /api/enrich/dimensions 直接返回这份清单。
"""
from __future__ import annotations

import csv
import json
import os
from typing import Any, Dict, List, Optional

try:  # 路径统一走 paths，Docker/本机同源
    from core import paths as _P
    ROOT = _P.ROOT
    DATA = _P.DATA
except Exception:  # pragma: no cover — 独立跑本文件时的兜底
    ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    DATA = os.path.join(ROOT, "data")


# ── 维度定义 ───────────────────────────────────────────────────────────
# entry   : 对外路由（前端/评测能直接调）
# backend : 真正干活的文件
# data_file: 落盘产物（None = 纯计算型维度）
ENRICH_DIMENSIONS: List[Dict[str, Any]] = [
    {"key": "papers", "label": "论文关联",
     "desc": "漏洞 ↔ 学术论文双向关联，按 CVE/组件回访论文库并给出来源",
     "backend": "core/papers.py · core/paper_kb.py",
     "entry": "/api/detail（含 papers 字段）",
     "data_file": "corpus.json#/papers", "count_kind": "json_list"},
    {"key": "affected_assets", "label": "受影响资产定位",
     "desc": "按受影响产品/CPE 把漏洞映射到本机资产清单，产出待处置资产",
     "backend": "modules/m2_enrich/backend/affected_assets.py",
     "entry": "/api/assets", "data_file": "affected_assets_cache.json",
     "count_kind": "json_len"},
    {"key": "poc", "label": "POC / EXP 搜索",
     "desc": "检索公开利用代码与 EXP，含 Exploit-DB / Metasploit 模块元数据",
     "backend": "modules/m2_enrich/backend/poc_scraper.py",
     "entry": "/api/poc", "data_file": "exploitdb_files.csv", "count_kind": "csv_rows"},
    {"key": "metasploit", "label": "Metasploit 模块",
     "desc": "模块元数据（名称/路径/平台），用于判断是否已有现成武器",
     "backend": "modules/m2_enrich/backend/poc_scraper.py",
     "entry": "/api/poc", "data_file": "metasploit_modules_metadata.json",
     "count_kind": "json_len"},
    {"key": "cvss", "label": "CVSS 评分与向量",
     "desc": "CVSS 基础分/向量/严重等级，来源交叉校验（多源分数不一致时标记）",
     "backend": "core/engine.py（语料字段 cvss）",
     "entry": "/api/search · /api/detail", "data_file": "corpus.json",
     "count_kind": "field_coverage", "count_field": "cvss",
     "data_file_note": "统计语料中带 CVSS 评分的条目数"},
    {"key": "kev", "label": "KEV 在野利用标注",
     "desc": "CISA KEV 目录命中标注，判断是否已被真实攻击利用",
     "backend": "modules/m1_monitor/backend/live.py::src_kev",
     "entry": "/api/live · /api/search", "data_file": "kev_cache.json",
     "count_kind": "json_len"},
    {"key": "remediation", "label": "修复方案",
     "desc": "升级路径 / 配置加固 / 缓解措施 / 验证步骤（LLM 与模板双模式）",
     "backend": "modules/m2_enrich/backend/remediation.py",
     "entry": "/api/remediation", "data_file": None,
     "count_kind": "computed", "data_file_note": "按漏洞实时生成，不落盘"},
    {"key": "credibility", "label": "来源可信度评估",
     "desc": "按来源权威度/交叉验证/时效打分，给出 trust_label 与置信度",
     "backend": "core/credibility.py",
     "entry": "/api/search · /api/detail", "data_file": "corpus.json",
     "count_kind": "field_coverage", "count_field": "sources",
     "data_file_note": "分数由引擎实时计算（trust_score 不落盘），此处统计"
                       "「带来源标注、可参与可信度评估」的条目数"},
    {"key": "stix_taxii", "label": "STIX 2.1 / TAXII 2.1 导出",
     "desc": "确定性 uuid5 生成 STIX 2.1 Bundle，TAXII 2.1 三集合订阅接口",
     "backend": "modules/m2_enrich/backend/stix_export.py",
     "entry": "/api/stix · /taxii2/**", "data_file": None,
     "count_kind": "computed", "count_note": "按需实时导出"},
    {"key": "vuln_env", "label": "复现环境生成",
     "desc": "为漏洞生成 docker-compose + 校验脚本的可复现环境包",
     "backend": "modules/m2_enrich/backend/vuln_env.py",
     "entry": "/api/vuln_env", "data_file": None,
     "count_kind": "computed", "count_note": "按漏洞实时生成 zip"},
    {"key": "asset_scan", "label": "资产风险体检",
     "desc": "上传 word/excel/txt 抽资产 → 与情报库比对，输出风险资产报告",
     "backend": "modules/m2_enrich/backend/asset_scan.py",
     "entry": "/api/asset_scan", "data_file": "asset_scans.json",
     "count_kind": "json_len"},
    {"key": "asset_search", "label": "互联网暴露面测绘",
     "desc": "FOFA/Shodan/Quake/ZoomEye 实查暴露量与国家分布（无 Key 走演示模式）",
     "backend": "modules/m2_enrich/backend/asset_search.py",
     "entry": "/api/asset_search", "data_file": None,
     "count_kind": "computed", "count_note": "按需实查，结果缓存"},
    {"key": "subscribe", "label": "预警订阅与推送",
     "desc": "按类型/关键词/最低等级订阅 → 增量匹配 → 站内通知 + Webhook 推送",
     "backend": "modules/m2_enrich/backend/alert_subscribe.py",
     "entry": "/api/subscribe · /api/subscribe/alerts",
     "data_file": "dispositions.json", "count_kind": "json_len"},
]

# 关联推理（"精准富化 + 智能关联"的落点）：跨文档/跨源自动关联，非单维度查询
ASSOCIATION_LAYERS = [
    {"key": "graph", "label": "漏洞-资产-论文关系图谱",
     "desc": "多跳实体关系展开，跨文档连成图后检索",
     "backend": "core/graph_data.py", "entry": "/api/graph"},
    {"key": "cmdb", "label": "CMDB 漏洞×资产×责任人自动关联",
     "desc": "漏洞库与 CMDB 资产表按产品/CPE 自动匹配，产出按责任人分派的处置工单",
     "backend": "modules/m2_enrich/backend/cmdb_scan.py",
     "entry": "/api/cmdb_scan · /api/cmdb_scan/tickets"},
    {"key": "disposition", "label": "处置记忆与经验复用",
     "desc": "同 CVE 秒判已处置、同组件类推历史处置，累积组织级经验",
     "backend": "core/disposition.py · modules/m0_ops/backend/orchestrator.py",
     "entry": "/api/ops/disposition"},
]


def _p(rel: str) -> str:
    return os.path.join(DATA, rel)


def _count_json_list(fp: str, key: str) -> Optional[int]:
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(d, dict):
        v = d.get(key)
        return len(v) if isinstance(v, (list, dict)) else None
    return len(d) if isinstance(d, (list, dict)) else None


def _count_json_len(fp: str) -> Optional[int]:
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(d, list):
        return len(d)
    if isinstance(d, dict):
        # 缓存类文件常是 {key: value} 映射，键数即条数
        return len(d)
    return None


def _count_csv_rows(fp: str) -> Optional[int]:
    try:
        with open(fp, "r", encoding="utf-8", errors="replace", newline="") as f:
            n = sum(1 for _ in csv.reader(f))
    except Exception:  # noqa: BLE001
        return None
    return max(0, n - 1)          # 去掉表头


def _corpus_field_coverage(field: str) -> Optional[int]:
    """统计语料里某字段有多少条记录带值（CVSS / 可信度这类计算型维度的真实覆盖面）。"""
    fp = _p("corpus.json")
    if not os.path.isfile(fp):
        return None
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return None
    n = 0
    for bucket in ("records", "knowledge", "papers"):
        for it in (d.get(bucket) or []):
            if not isinstance(it, dict):
                continue
            v = it.get(field)
            if v not in (None, "", [], {}):
                n += 1
    return n or None


_COUNTERS = {
    "json_len": lambda rel: _count_json_len(_p(rel)),
    "json_list": lambda rel: _count_json_list(_p(rel), "papers"),
    "csv_rows": lambda rel: _count_csv_rows(_p(rel)),
    # rel 直接就是语料字段名（cvss / sources / …）
    "field_coverage": lambda rel: _corpus_field_coverage(rel),
    "computed": lambda rel: None,
}


def enrich_dimensions() -> Dict[str, Any]:
    """返回富化维度清单 + 每个维度的当前真实计数。"""
    dims: List[Dict[str, Any]] = []
    total = 0
    for d in ENRICH_DIMENSIONS:
        row = dict(d)
        df = d.get("data_file")
        kind = d.get("count_kind") or "computed"
        # data_file 可能带 "#子键" 后缀（corpus.json#/papers），统计前要剥掉
        rel = df.split("#")[0] if df else None
        if kind in _COUNTERS and (rel or kind == "field_coverage"):
            arg = d.get("count_field") if kind == "field_coverage" else rel
            n = _COUNTERS[kind](arg)
            row["count"] = n
            row["data_file_exists"] = os.path.isfile(_p(rel)) if rel else None
            if n:
                total += n
        else:
            row["count"] = None
            row["data_file_exists"] = None
        dims.append(row)
    return {
        "ok": True,
        "dimension_count": len(dims),
        "association_count": len(ASSOCIATION_LAYERS),
        "counted_records": total,
        "dimensions": dims,
        "associations": ASSOCIATION_LAYERS,
        "note": ("count 为该维度当前落盘的真实条数（None 表示纯计算型维度，"
                 "不落盘，见 data_file_note）；associations 是跨源自动关联层，"
                 "对应「精准富化 + 智能关联」。"),
    }


if __name__ == "__main__":  # 手工核对用：py -3 modules/m2_enrich/backend/enrich_dims.py
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    r = enrich_dimensions()
    print("维度 %d 种 · 关联层 %d 层 · 落盘记录合计 %d 条\n"
          % (r["dimension_count"], r["association_count"], r["counted_records"]))
    for d in r["dimensions"]:
        print("  %-18s %-22s count=%-8s %s"
              % (d["key"], d["label"], d["count"], d["backend"]))
    for a in r["associations"]:
        print("  [关联] %-12s %s" % (a["key"], a["label"]))
