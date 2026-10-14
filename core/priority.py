# -*- coding: utf-8 -*-
"""
priority.py —— 漏洞优先级四元组（P0-2 · 核心层）
================================================
为什么加这个
------------
行业实证（Berkeley《Agentic Vulnerability Coverage Map》2026-07）：agentic CVE 集内
CVSS 与 EPSS 的 Spearman 相关仅 **0.17**（非 agentic 0.30、2025 基线 0.40）——
**CVSS 单信号在 AI 漏洞上尤其失真**。行业共识是「CVSS + EPSS + KEV + 可达性」
四元组一起看。本项目此前只有 CVSS + KEV，缺 EPSS 与可达性，也无法给出"该先修谁"。

本模块把四元组算成一个**可解释的优先级分**，并在 `/api/detail` 挂载。

分层与数据来源（架构裁决 C）
-----------------------------
  · EPSS **不落进 corpus**（硬约束 C3）：本模块 `attach_epss(engine)` 从
    `data/epss_cache.json`（由 m2_enrich/backend/epss.py 抓取）读值，写入内存文档字段
    `doc["epss"]`（与 `ensure_credibility` 挂 `trust_score` 同范式）。
  · priority 的计算放在 core（core↔core），EPSS 抓取留在 m2，两者以缓存文件解耦。

四元组键固定：``cvss / epss / kev / reachability``（**键必须齐全**，缺失用 null +
``missing[]`` 显式标注，不得静默省略 —— AC-2）。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):  # type: ignore
            pass

EPSS_CACHE_FP = paths.data_path("epss_cache.json")

# 可达性枚举（§7.2）
REACH_ENUM = ("internet-facing", "internal", "unknown")


def load_epss_cache() -> Dict[str, Any]:
    """读 EPSS 缓存；缺失/损坏返回空结构（不抛）。"""
    try:
        with open(EPSS_CACHE_FP, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            return d
    except (OSError, ValueError) as e:
        _swallow("core/priority.py:load_epss_cache", e)
    return {"meta": {}, "scores": {}}


def attach_epss(engine) -> int:
    """把 EPSS 缓存值写入内存文档字段 doc["epss"]。返回被挂载的文档数。"""
    if engine is None:
        return 0
    cache = load_epss_cache()
    scores = cache.get("scores") or {}
    if not scores:
        return 0
    up = {str(k).upper(): v for k, v in scores.items()}
    n = 0
    for d in getattr(engine, "docs", []) or []:
        did = str(d.get("id") or "").upper()
        rec = up.get(did)
        if not rec:
            continue
        try:
            val = rec.get("epss") if isinstance(rec, dict) else rec
            d["epss"] = float(val)
            n += 1
        except (TypeError, ValueError):
            continue
    return n


# --------------------------------------------------------------------------
# 可达性（Q8：复用既有 /api/assets + 暴露面测绘语义；无测绘结果时 unknown）
# --------------------------------------------------------------------------
_ASSET_CACHE: Dict[str, Any] = {"loaded": False, "map": {}}


def _load_asset_map() -> Dict[str, Any]:
    """惰性加载受影响资产缓存（受影响资产定位产物），把 CVE → 是否互联网暴露。"""
    if _ASSET_CACHE["loaded"]:
        return _ASSET_CACHE["map"]
    _ASSET_CACHE["loaded"] = True
    fp = paths.data_path("affected_assets_cache.json")
    m: Dict[str, Any] = {}
    try:
        with open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
        rows = d.get("items") if isinstance(d, dict) else d
        for it in (rows or []):
            if not isinstance(it, dict):
                continue
            cid = str(it.get("id") or it.get("cve") or "").upper()
            if not cid:
                continue
            flag = it.get("internet_facing") or it.get("exposed") or it.get("public")
            m[cid] = bool(flag)
    except (OSError, ValueError) as e:
        _swallow("core/priority.py:_load_asset_map", e)
    _ASSET_CACHE["map"] = m
    return m


def _reachability(record: Dict[str, Any]) -> str:
    """判定可达性：显式字段优先，其次受影响资产缓存，否则 unknown。"""
    for k in ("reachability", "exposure", "exposure_level"):
        v = record.get(k)
        if v in REACH_ENUM:
            return v
    cid = str(record.get("id") or "").upper()
    amap = _load_asset_map()
    if cid in amap:
        return "internet-facing" if amap[cid] else "internal"
    return "unknown"


# --------------------------------------------------------------------------
# 优先级分与档位
# --------------------------------------------------------------------------
def priority_level(score: int) -> str:
    """0~100 归一化分 → P0/P1/P2/P3。"""
    try:
        s = int(score)
    except (TypeError, ValueError):
        s = 0
    if s >= 80:
        return "P0"
    if s >= 60:
        return "P1"
    if s >= 40:
        return "P2"
    return "P3"


def build(record: Dict[str, Any]) -> Dict[str, Any]:
    """计算优先级四元组 + 归一化分 + 档位 + 可解释理由。

    返回键：cvss / epss / kev / reachability / score / level / reason / status /
    missing[]（**四元组键必齐**，缺失用 null 并进 missing）。
    """
    record = record if isinstance(record, dict) else {}
    cvss_obj = record.get("cvss") or {}
    cvss = cvss_obj.get("score") if isinstance(cvss_obj, dict) else None
    if isinstance(cvss, bool) or not isinstance(cvss, (int, float)):
        cvss = None
    epss = record.get("epss")
    if isinstance(epss, bool) or not isinstance(epss, (int, float)):
        epss = None
    kev = bool(record.get("kev"))
    reach = _reachability(record)

    missing: List[Dict[str, str]] = []
    if cvss is None:
        missing.append({"field": "cvss", "why": "该条情报无 CVSS 评分"})
    if epss is None:
        why = "无网且无缓存" if not os.path.isfile(EPSS_CACHE_FP) else "EPSS 缓存中无该 CVE"
        missing.append({"field": "epss", "why": why})
    if reach == "unknown":
        missing.append({"field": "reachability", "why": "无暴露面测绘结果"})

    # —— 归一化打分（0~100）——
    score = 0.0
    if cvss is not None:
        score += max(0.0, min(10.0, float(cvss))) / 10.0 * 40.0
    if epss is not None:
        score += max(0.0, min(1.0, float(epss))) * 40.0
    if kev:
        score += 15.0
    score += {"internet-facing": 5.0, "internal": 2.0}.get(reach, 0.0)
    score_i = int(round(max(0.0, min(100.0, score))))

    level = priority_level(score_i)
    # KEV=yes ⇒ 不低于最高档（AC-3：处置优先级不得与「KEV 命中⇒最高档」矛盾）
    if kev:
        level = "P0"

    # —— 可解释理由串 ——
    parts = []
    parts.append("CVSS %s" % (("%.1f" % cvss) if cvss is not None else "未知"))
    parts.append("EPSS %s" % (("%.2f" % epss) if epss is not None else "无"))
    parts.append("已入 KEV" if kev else "未入 KEV")
    parts.append("可达性 %s" % reach)
    tail = " ⇒ 立即处置" if level == "P0" else (
        " ⇒ 优先处置" if level == "P1" else (
            " ⇒ 计划处置" if level == "P2" else " ⇒ 观察"))
    reason = " + ".join(parts) + ("（%d/100）/ %s%s" % (score_i, level, tail))
    if kev:
        reason += "；KEV 命中强制提升至 P0"

    status = "ok" if (cvss is not None or epss is not None) else "degraded"

    return {
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "reachability": reach,
        "score": score_i,
        "level": level,
        "reason": reason,
        "status": status,
        "missing": missing,
    }
