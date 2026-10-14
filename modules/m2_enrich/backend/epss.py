# -*- coding: utf-8 -*-
"""
epss.py —— FIRST EPSS 利用概率抓取与本地缓存（P0-2 · 模块2 后端）
==================================================================
为什么加这个
------------
行业实证（Berkeley《Agentic Vulnerability Coverage Map》2026-07）：agentic CVE 集内
CVSS 与 EPSS 的 Spearman 相关仅 **0.17**（非 agentic 0.30、2025 基线 0.40）——
**CVSS 单信号在 AI 漏洞上尤其失真**。行业共识是把「CVSS + EPSS + KEV + 可达性」
四元组一起看，而本项目此前只有 CVSS + KEV，缺 EPSS。

本模块负责：
  · 走 `core/httpcompat.py`（**不直接 import requests**，硬约束 C2/零依赖降级）
    抓 FIRST EPSS 公开 API（无 Key）；
  · 落本地缓存 `data/epss_cache.json`（字段固定 `epss/percentile/date/fetched_at`）；
  · 陈旧阈值（`config.json` 的 `epss_stale_days`，默认 7 天）；
  · **无网/失败时必须降级**：返回 `status="degraded"`、HTTP 仍 200、**缓存不清空**。

关键约定（设计 §7.2）
--------------------
  · 接口：``https://api.first.org/data/v1/epss?cve=CVE-x,CVE-y&limit=N``（公开无 Key），
    返回 ``{"data":[{"cve","epss","percentile","date"}]}``；
  · ``epss`` / ``percentile`` 是 **0~1 的字符串**，这里统一转 **0~1 浮点**（不乘 100）；
  · 判定成功用 **2xx**（含 202/206），**绝不写 == 200**；
  · 缓存结构：``{"meta":{fetched_at,source,count}, "scores":{CVE:{epss,percentile,date,fetched_at}}}``。

落点分工（架构裁决 C）：EPSS 值由 `core/priority.attach_epss` 从本缓存读入内存文档
``doc["epss"]``，供 ``epss>=N`` 算子与四元组用；本模块只负责"抓 + 存"。
"""
from __future__ import annotations

import json
import os
import time
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

# 网络一律走 httpcompat（有 requests 用 requests，无则 urllib 兜底）——硬约束 C2。
# 注意：**绝不直接 import requests**（连兜底也不 import），避免"没装 requests
# 就整接口 500"；httpcompat 不可得时直接降级为 None，抓取走 degraded 分支。
try:
    import httpcompat as _http
except Exception:  # pragma: no cover —— 极端情况下不可得则降级（不退回 requests）
    _http = None  # type: ignore

EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_FP = paths.data_path("epss_cache.json")
UA = "AI-SecIntel/2.3 (EPSS enrichment; contact: local)"
_BATCH = 100                      # 单次请求携带的 CVE 数（避免 URL 过长被拒）
_SLEEP_BETWEEN = 1.5             # 分批之间睡眠 1~2s，避免被 first.org 限速（返修 F1）
_BATCH_RETRY = 1                  # 失败批重试次数（重试 1 次仍失败则跳过并记入降级统计）
_DEFAULT_STALE_DAYS = 7
_KEV_FP = paths.data_path("kev_cache.json")
# KEV 来源之二（返修 F1）：实时快照，结构为 {"ts":..., "kev":{CVE:{...}}}。
# 语料里带 kev=True 的 CVE 来自**实时快照**；它比 kev_cache 多 18 个 CVE，
# 只取 kev_cache 会让这 18 个（其中 10 个在语料中）永远拿不到 EPSS。
_KEV_SNAPSHOT_FP = paths.data_path("kev_snapshot.json")


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def stale_days() -> int:
    """陈旧阈值（天）：读 config.json 的 epss_stale_days，非法值回落默认 7。"""
    try:
        cfg = paths.load_config()
        v = int(str(cfg.get("epss_stale_days", _DEFAULT_STALE_DAYS)).strip())
        if v > 0:
            return v
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m2_enrich/backend/epss.py:stale_days", e)
    return _DEFAULT_STALE_DAYS


# --------------------------------------------------------------------------
# 缓存读写（原子写，对齐 circuit.py::_save_state）
# --------------------------------------------------------------------------
def load_cache() -> Dict[str, Any]:
    """读缓存；缺失/损坏返回空结构（不抛）。"""
    try:
        with open(CACHE_FP, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("meta", {})
            d.setdefault("scores", {})
            return d
    except (OSError, ValueError) as e:
        _swallow("modules/m2_enrich/backend/epss.py:load_cache", e)
    return {"meta": {}, "scores": {}}


def save_cache(cache: Dict[str, Any]) -> None:
    """原子写缓存：先写 .tmp 再 os.replace。"""
    tmp = CACHE_FP + ".tmp"
    try:
        os.makedirs(os.path.dirname(CACHE_FP), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.replace(tmp, CACHE_FP)
    except OSError as e:
        _swallow("modules/m2_enrich/backend/epss.py:save_cache", e)
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def get_epss(cve: str) -> Optional[float]:
    """取单个 CVE 的 EPSS 值（0~1 浮点）；无缓存返回 None。"""
    cid = str(cve or "").upper()
    if not cid:
        return None
    rec = (load_cache().get("scores") or {}).get(cid)
    if isinstance(rec, dict):
        try:
            return float(rec.get("epss"))
        except (TypeError, ValueError):
            return None
    return None


# --------------------------------------------------------------------------
# CVE 来源（从语料的 KEV 命中里取，几百条量级 —— 不试图一次拉全量 30 万条）
# --------------------------------------------------------------------------
def _kev_keys() -> List[str]:
    """KEV CVE 键全集：``kev_cache.json`` ∪ ``kev_snapshot.json``（后者嵌套在 "kev" 键下）。

    去重保序（kev_cache 优先）。两个文件都是本项目自己的 KEV 源，不读 291MB 的 corpus.json。
    """
    out: List[str] = []
    seen: set = set()

    def _add(keys) -> None:
        for k in keys:
            s = str(k or "").upper()
            if s.startswith("CVE-") and s not in seen:
                seen.add(s)
                out.append(s)

    for fp, sub in ((_KEV_FP, None), (_KEV_SNAPSHOT_FP, "kev")):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError) as e:
            _swallow("modules/m2_enrich/backend/epss.py:_kev_keys:"
                     + os.path.basename(fp), e)
            continue
        if sub and isinstance(d, dict) and isinstance(d.get(sub), (dict, list)):
            d = d[sub]
        if isinstance(d, dict):
            _add(d.keys())
        elif isinstance(d, list):
            _add([(x.get("cveID") or x.get("cve") or x.get("id"))
                  if isinstance(x, dict) else x for x in d])
    return out


def default_cves(maxn: int = 2000) -> List[str]:
    """默认待抓 CVE 列表：**KEV 源全集**（kev_cache ∪ kev_snapshot）的前 ``maxn`` 个。

    为什么取 KEV 全集（返修 F1）：
      · 语料里带 KEV 标记的 CVE 来自 KEV 源，只有把 **KEV 源的全部键**纳入待抓集，
        才能让语料 KEV CVE 被全覆盖 —— 早前 `maxn=800` 硬顶，`kev_cache`(1721) 只取
        前 800，与语料 KEV(536) 的交集仅 214，覆盖率被压到 39.9%（AC-2 要求 ≥80%）。
      · 并集 `kev_snapshot`（实时快照，1739）后，语料里 536 个 KEV CVE 全部在内 → ~100%。
      · `maxn` 默认 2000（> 全部键）保证覆盖全量；仍保留上限以防源异常膨胀。
      · **不加载 291MB 的 corpus.json** 去找 CVE 列表 —— 直接用 KEV 源的键即可。
    """
    keys = _kev_keys()
    if maxn and maxn > 0:
        return keys[:maxn]
    return keys


# --------------------------------------------------------------------------
# 抓取（2xx 判定；无网/失败降级）
# --------------------------------------------------------------------------
def fetch(cves: List[str], limit: int = 1000) -> Dict[str, Any]:
    """抓一批 CVE 的 EPSS 值。

    返回 ``{"status": "ok"|"degraded", "fetched": int, "scores": {...},
    "checked": int, "errors": [...]}``。**任一批 2xx 即视为整体 ok**；
    全部失败才 degraded（无网/被限速时缓存不动、条目不减）。
    """
    if _http is None:
        return {"status": "degraded", "fetched": 0, "scores": {},
                "checked": 0, "errors": ["httpcompat/requests 均不可用"]}
    # 去重且保序
    seen = set()
    uniq = []
    for c in (cves or []):
        s = str(c or "").strip().upper()
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    scores: Dict[str, Any] = {}
    errors: List[str] = []
    ok_any = False
    for i in range(0, len(uniq), _BATCH):
        chunk = uniq[i:i + _BATCH]
        rows: List[Any] = []
        last_err = ""
        # 失败批**重试 1 次**；仍失败则记入降级统计并跳过，**绝不中断整体**（返修 F1）。
        for attempt in range(_BATCH_RETRY + 1):
            try:
                r = _http.get(EPSS_API, params={"cve": ",".join(chunk), "limit": len(chunk)},
                              headers={"User-Agent": UA}, timeout=20)
                code = int(getattr(r, "status_code", 0) or 0)
            except Exception as e:  # noqa: BLE001 —— 网络异常 = 不可达，如实降级
                last_err = "batch@%d(n=%d): %s" % (i, len(chunk), str(e)[:60])
                if attempt < _BATCH_RETRY:
                    time.sleep(_SLEEP_BETWEEN)
                continue
            # ★ 判定成功用 2xx（含 202/206），不要写 == 200
            if not (200 <= code < 300):
                last_err = "batch@%d(n=%d): HTTP %s" % (i, len(chunk), code)
                if attempt < _BATCH_RETRY:
                    time.sleep(_SLEEP_BETWEEN)
                continue
            try:
                rows = (r.json() or {}).get("data") or []
            except Exception as e:  # noqa: BLE001
                last_err = "batch@%d(n=%d): bad json (%s)" % (i, len(chunk), str(e)[:40])
                if attempt < _BATCH_RETRY:
                    time.sleep(_SLEEP_BETWEEN)
                continue
            last_err = ""
            break                      # HTTP 2xx 且可解析 → 本批成功（rows 允许为空）
        if last_err:
            errors.append(last_err)    # 重试后仍失败：跳过本批，继续后续批
            time.sleep(_SLEEP_BETWEEN)
            continue
        ok_any = True
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve") or "").upper()
            if not cve:
                continue
            try:
                epss = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            pct: Optional[float]
            try:
                pct = float(row.get("percentile")) if row.get("percentile") is not None else None
            except (TypeError, ValueError):
                pct = None
            scores[cve] = {"epss": epss, "percentile": pct, "date": row.get("date") or ""}
        time.sleep(_SLEEP_BETWEEN)
    return {
        "status": "ok" if ok_any else "degraded",
        "fetched": len(scores),
        "scores": scores,
        "checked": len(uniq),
        "errors": errors[:20],
    }


def refresh(cves: Optional[List[str]] = None, limit: int = 1000) -> Dict[str, Any]:
    """抓取并合并进缓存（供 POST /api/enrich/epss/refresh）。

    返回 ``{"ok", "status", "fetched", "cached", "count", "fetched_at", "errors"}``。
    **降级时缓存不清空**：只有抓到（status=ok）才写盘，失败保留旧缓存。
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    base = load_cache()
    scores: Dict[str, Any] = dict(base.get("scores") or {})
    targets = list(cves) if cves else default_cves()
    res = fetch(targets, limit=limit)
    merged = 0
    for cve, rec in (res.get("scores") or {}).items():
        r2 = dict(rec)
        r2["fetched_at"] = now
        scores[cve] = r2
        merged += 1
    if res["status"] == "ok":
        save_cache({
            "meta": {"fetched_at": now, "source": "FIRST EPSS", "count": len(scores)},
            "scores": scores,
        })
        cached = len(scores)
    else:
        # 降级：保留旧缓存（不清空），cached 取旧缓存的条数
        cached = len(scores)
    return {
        "ok": True,
        "status": res["status"],
        "fetched": res["fetched"],
        "merged": merged,
        "cached": cached,
        "count": cached,
        "checked": res["checked"],
        "fetched_at": now,
        "errors": res["errors"],
        "note": ("first.org EPSS 公开 API；epss/percentile 为 0~1 浮点。"
                 "降级（无网/失败）时保留旧缓存、不清空，接口仍返回 200。"),
    }


def status() -> Dict[str, Any]:
    """返回缓存状态：条数 / 最近抓取时间 / 是否陈旧。"""
    c = load_cache()
    meta = c.get("meta") or {}
    scores = c.get("scores") or {}
    fa = meta.get("fetched_at")
    age_days: Optional[float] = None
    if fa:
        try:
            age_days = round(
                (time.time() - time.mktime(time.strptime(fa, "%Y-%m-%dT%H:%M:%S"))) / 86400.0, 2)
        except (ValueError, OverflowError):
            age_days = None
    sd = stale_days()
    stale = (age_days is None) or (age_days > sd)
    return {
        "source": meta.get("source", "FIRST EPSS"),
        "count": len(scores),
        "fetched_at": fa,
        "age_days": age_days,
        "stale_days": sd,
        "stale": stale,
        "status": "degraded" if stale else "ok",
    }


if __name__ == "__main__":  # 手工核对用
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    r = refresh(cves=["CVE-2021-44228", "CVE-2024-37032"], limit=10)
    print("refresh:", {k: r[k] for k in ("status", "fetched", "cached", "count")})
    print("status:", status())
