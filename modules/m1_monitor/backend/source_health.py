# -*- coding: utf-8 -*-
"""
source_health.py —— 情报源跨轮健康记账与"缺失"判定（P0-3 · 模块1 后端）
======================================================================
为什么加这个
------------
产业实证（CSA《The Dual Visibility Crisis》2026-05）：NVD 富化自 2024-02 起崩塌、
2026-04 后约 **80% 新 CVE 不再获得 NVD 富化**，而 "most detection logic responds to
anomalous data rather than **absent data**" —— **缺失数据不会触发任何告警**。
本项目自有台账也如实记录：`m1_monitor` 从 10-07 起停产，直到测试失败才暴露。

本次增量正是要把"沉默失败"变成"可见 + 可告警"：
  · 既有 `live.py::src_health()`（本轮 ok/err）**当作"本轮输入"复用**（不改它本体）；
  · 本模块做**跨轮持久化**（`data/source_health.json`）与**缺失判定**；
  · 判定的是"**缺失数据**"而不是"异常数据"（异常数据由既有 `core/circuit.py` 熔断负责）。

判定规则（默认 k=3，`config.json` 的 `source_health_stale_k`）
------------------------------------------------------------
  · `now - last_item_at > k × expected_interval` 或 `items_24h==0 且 items_7d_avg>0` ⇒ **stale（停产）**
  · `items_24h < 0.3 × items_7d_avg` ⇒ **degraded（缩水）**
  · 首轮轮询完成前 ⇒ 全部 `unknown`（源清单来自静态定义表，**不依赖瞬时 `feed_total`**）

源清单来源（设计 §3.3②）
------------------------
  · `live.BLOG_FEEDS` + `live.BLOG_FEEDS_PROXY_ONLY`（RSS/公告源，channel="blogs"）
  · `live.ARXIV_RSS`（论文源，channel="arxiv"）
  · `live.SOURCES`（快车道调度表：csdn / blogs / anquanke / xz / nvd / kev / arxiv）
  `total` = 上述定义表条目数（**不读 `/api/live` 的 `feed_total`**，首轮前它是 0）。

告警去重
--------
同源**同状态只在状态变化时写一条**到 `data/alerts.jsonl`（经 `core/alert_log.py`），
否则 15s 一轮会把告警刷屏 —— 那正是 P0-3 要治的"告警疲劳"病根。
"""
from __future__ import annotations

import json
import os
import re
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

# 告警落盘通道（core/alert_log.py，与 P1-2 探活共用同一条 JSONL）
try:
    import alert_log as AL
except Exception:  # pragma: no cover
    try:
        from core import alert_log as AL  # type: ignore
    except Exception:
        AL = None  # type: ignore

LEDGER_FP = paths.data_path("source_health.json")
STATES = ("ok", "degraded", "stale", "disabled", "unknown")
_DEFAULT_K = 3.0
_EVENT_KEEP = 400          # 每源保留的"有新增"事件时间戳上限（够算 7 日）


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def _stale_k() -> float:
    """停产判定系数：读 config.json 的 source_health_stale_k，非法回落 3。"""
    try:
        cfg = paths.load_config()
        v = float(str(cfg.get("source_health_stale_k", _DEFAULT_K)).strip())
        return v if v > 0 else _DEFAULT_K
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/source_health.py:_stale_k", e)
        return _DEFAULT_K


# --------------------------------------------------------------------------
# 静态源定义表（源清单的唯一来源）
# --------------------------------------------------------------------------
def _static_index() -> Dict[str, Dict[str, Any]]:
    """从 live.py 的静态源表构建 {source: {channel, category, expected_interval}}。

    保持定义顺序（dict 在 py3.7+ 有序），便于稳定输出。

    ★ expected_interval 的口径（重要取舍）：它是**源的自然发布节拍**，不是轮询节拍。
      SOURCES 里的 gap 是"多久轮询一次"（15~300s），若直接当作发布节拍，任何按天更新的
      RSS 源都会在启动几分钟后就被判 stale —— 正是设计 §8 警示的"误判停产（快源本就常空）"。
      因此这里按源类型给**发布节拍**：RSS/公告与 KEV/arXiv 按天（86400s），
      高频社区源（CSDN/安全客/先知）与 NVD 按小时（3600s）。k=3 时：
      RSS 源连续 3 天无成功抓取才判 stale（与磁盘缓存 mtime 台账一致）。
    """
    idx: Dict[str, Dict[str, Any]] = {}
    try:
        import live as L
    except Exception:  # pragma: no cover
        try:
            from modules.m1_monitor.backend import live as L  # type: ignore
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/source_health.py:_static_index", e)
            return idx

    BLOG_INTERVAL = 86400      # RSS/厂商公告：按天发布
    FAST_INTERVAL = 3600       # 高频社区源 / NVD：按小时
    SLOW_INTERVAL = 86400      # KEV / arXiv：按天

    blog = list(getattr(L, "BLOG_FEEDS", []) or [])
    proxy = list(getattr(L, "BLOG_FEEDS_PROXY_ONLY", []) or [])
    cats = getattr(L, "BLOG_FEED_CATEGORIES", {}) or {}
    for name, _url in blog + proxy:
        idx[name] = {"channel": "blogs", "category": cats.get(name, "other"),
                     "expected_interval": BLOG_INTERVAL}
    for name, _url in (getattr(L, "ARXIV_RSS", []) or []):
        idx[name] = {"channel": "arxiv", "category": "paper",
                     "expected_interval": SLOW_INTERVAL}
    src_cats = getattr(L, "SOURCE_CATEGORIES", {}) or {}
    src_cadence = {"nvd": FAST_INTERVAL, "kev": SLOW_INTERVAL, "arxiv": SLOW_INTERVAL,
                   "csdn": FAST_INTERVAL, "anquanke": FAST_INTERVAL, "xz": FAST_INTERVAL,
                   "blogs": BLOG_INTERVAL}
    for name, _fn, _gap in (getattr(L, "SOURCES", []) or []):
        # 快车道调度表（csdn / blogs / anquanke / xz / nvd / kev / arxiv）
        idx.setdefault(name, {
            "channel": name,
            "category": src_cats.get(name, name),
            "expected_interval": src_cadence.get(name, FAST_INTERVAL),
        })
    return idx


def static_sources() -> List[Dict[str, Any]]:
    """静态源定义表条目（源清单；total = len）。"""
    return [{"source": k, **v} for k, v in _static_index().items()]


# --------------------------------------------------------------------------
# 账本读写（原子写）
# --------------------------------------------------------------------------
def _load() -> Dict[str, Any]:
    try:
        with open(LEDGER_FP, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("sources", {})
            return d
    except (OSError, ValueError) as e:
        _swallow("modules/m1_monitor/backend/source_health.py:_load", e)
    return {"sources": {}, "rounds": 0}


def _save(ledger: Dict[str, Any]) -> None:
    tmp = LEDGER_FP + ".tmp"
    try:
        os.makedirs(os.path.dirname(LEDGER_FP), exist_ok=True)
        ledger["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(ledger, f, ensure_ascii=False)
        os.replace(tmp, LEDGER_FP)
    except OSError as e:
        _swallow("modules/m1_monitor/backend/source_health.py:_save", e)
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _new_rec(name: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    meta = meta or {}
    return {
        "source": name,
        "channel": meta.get("channel", ""),
        "category": meta.get("category", "other"),
        "expected_interval": int(meta.get("expected_interval") or 300),
        "last_success_at": None,
        "last_item_at": None,
        "consecutive_failures": 0,
        "items_24h": 0,
        "items_7d_avg": 0.0,
        "state": "unknown",
        "last_state": "",
        "stale_for_sec": 0,
        "alerts_total": 0,
        "last_error": "",
        "item_events": [],
    }


def _cache_mtime(name: str) -> Optional[float]:
    """RSS 源的『上一轮成功快照』落盘时间（作为停产判定的台账种子）。

    为什么不依赖内存 `_FEED_LAST`：重启即丢。磁盘上的 `live_cache/<source>.xml`
    是**每轮成功抓取都会覆盖**的持久台账，正好可作 last_success_at/last_item_at 的种子。
    """
    try:
        import live as L
        fp = L._cache_fp(name)  # noqa: SLF001 —— 复用既有缓存路径解析，避免规则漂移
        if os.path.isfile(fp):
            return os.path.getmtime(fp)
    except Exception as e:  # noqa: BLE001
        # 兜底：自行拼一个（与 live._cache_fp 同规则）
        try:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
            fp = os.path.join(paths.data_path("live_cache"), safe + ".xml")
            if os.path.isfile(fp):
                return os.path.getmtime(fp)
        except Exception as e2:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/source_health.py:_cache_mtime", e2)
    return None


def _ensure_seeded(ledger: Dict[str, Any]) -> None:
    """首次调用：按静态定义表建齐所有源的记录，并用缓存 mtime 种子回填。"""
    if ledger.get("seeded"):
        return
    ledger.setdefault("sources", {})
    for name, meta in _static_index().items():
        rec = ledger["sources"].get(name)
        if rec is None:
            rec = _new_rec(name, meta)
            ledger["sources"][name] = rec
        if meta.get("channel") == "blogs":
            mt = _cache_mtime(name)
            if mt:
                if not rec.get("last_success_at"):
                    rec["last_success_at"] = mt
                if not rec.get("last_item_at"):
                    rec["last_item_at"] = mt
    ledger["seeded"] = True


def _ensure_rec(ledger: Dict[str, Any], name: str) -> Dict[str, Any]:
    idx = _static_index()
    rec = ledger["sources"].get(name)
    if rec is None:
        rec = _new_rec(name, idx.get(name))
        ledger["sources"][name] = rec
    return rec


# --------------------------------------------------------------------------
# 判定
# --------------------------------------------------------------------------
def judge_state(rec: Dict[str, Any], now: float, k: float,
                first_round_done: bool = True) -> str:
    """按设计规则判定单源状态（见模块 docstring）。"""
    if rec.get("disabled"):
        return "disabled"
    if not first_round_done:
        return "unknown"
    ref = rec.get("last_item_at") or rec.get("last_success_at")
    if ref is None:
        return "unknown"
    interval = int(rec.get("expected_interval") or 300)
    items24 = int(rec.get("items_24h") or 0)
    avg7 = float(rec.get("items_7d_avg") or 0.0)
    if now - float(ref) > k * interval:
        return "stale"
    if items24 == 0 and avg7 > 0:
        return "stale"
    if avg7 > 0 and items24 < 0.3 * avg7:
        return "degraded"
    return "ok"


def _recompute_items(rec: Dict[str, Any], now: float) -> None:
    """按 item_events 重算 items_24h / items_7d_avg。"""
    ev = [float(t) for t in (rec.get("item_events") or []) if isinstance(t, (int, float))]
    ev = ev[-_EVENT_KEEP:]
    rec["item_events"] = ev
    items24 = sum(1 for t in ev if now - t <= 86400)
    items7d = sum(1 for t in ev if now - t <= 7 * 86400)
    rec["items_24h"] = items24
    rec["items_7d_avg"] = round(items7d / 7.0, 3)


# --------------------------------------------------------------------------
# 跨轮记账（live.py 每轮轮询后调用）
# --------------------------------------------------------------------------
def record_poll(ok: Any, err: Any, per_source: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """把本轮 `src_health()` 的结果喂进跨轮账本并判定状态。

    参数
    ----
    ok         : 本轮成功的源名列表（`live.src_health()` 的第一个返回值）
    err        : 本轮失败的源 → 原因（第二个返回值）
    per_source : 可选，{通道: 本轮新增条数}（`LAST_META["per_source"]`）；>0 记为一次"有新增"
    """
    ledger = _load()
    _ensure_seeded(ledger)
    now = time.time()
    # ① 成功的源：更新 last_success_at / last_item_at，清零连续失败
    for name in (ok or []):
        if not name:
            continue
        rec = _ensure_rec(ledger, name)
        rec["last_success_at"] = now
        rec["last_item_at"] = now          # 成功抓取视为"该源在线产出"（RSS 语义）
        rec["consecutive_failures"] = 0
        rec["last_error"] = ""
    # ② 失败的源：累计连续失败（**不改 last_item_at**，缺数据才是产出停的信号）
    for name, reason in (err or {}).items():
        if not name:
            continue
        rec = _ensure_rec(ledger, name)
        rec["consecutive_failures"] = int(rec.get("consecutive_failures") or 0) + 1
        rec["last_error"] = str(reason or "")[:160]
    # ③ 通道级新增计数 → 记录"有新增"事件（用于 items_24h / items_7d_avg）
    for ch, n in (per_source or {}).items():
        try:
            nn = int(n)
        except (TypeError, ValueError):
            nn = 0
        if nn > 0:
            rec = _ensure_rec(ledger, ch)
            rec["last_item_at"] = now
            if not rec.get("last_success_at"):
                rec["last_success_at"] = now
            ev = rec.setdefault("item_events", [])
            ev.append(now)
            rec["item_events"] = ev[-_EVENT_KEEP:]

    ledger["rounds"] = int(ledger.get("rounds") or 0) + 1
    first = ledger["rounds"] >= 1
    k = _stale_k()

    # ④ 重算 items_*，判定状态，状态变化时落一条告警（去重）
    for name, rec in ledger["sources"].items():
        _recompute_items(rec, now)
        st = judge_state(rec, now, k, first_round_done=first)
        prev = rec.get("last_state") or ""
        rec["state"] = st
        rec["stale_for_sec"] = int(now - (rec.get("last_item_at") or rec.get("last_success_at") or now)) \
            if st == "stale" else 0
        if st != prev:
            if st in ("stale", "degraded"):
                _file_alert(name, rec, st, now)
            rec["last_state"] = st

    _save(ledger)
    return snapshot(_ledger=ledger)


def mark_success(names, items: int = 0, note: str = "") -> Dict[str, Any]:
    """外部通道（6h 深度同步）成功时回写账本：清零失败、刷新时间戳。

    为什么需要（2026-10-26）：快车道只轮询 RSS / 社区；NVD、KEV、arXiv 由
    monitor.refresh 的 6h 深同步负责。此前账本**只记快车道轮询结果**，
    深度同步的实际产出完全没进账本 → 看板上 NVD/KEV/arXiv 长期显示
    「熔断中（连续失败 735/731/718 次）」，而同一时刻语料的 meta 明明写着
    「nvd_new=1 / nvd_updated=18」。这既是误导评委的风险，也让"源健康"
    这个本该最可信的页面变得不可信。深度同步成功必须回写。
    """
    ledger = _load()
    _ensure_seeded(ledger)
    now = time.time()
    hit = []
    for name in (names or []):
        n = str(name or "").strip()
        if not n:
            continue
        rec = _ensure_rec(ledger, n)
        rec["last_success_at"] = now
        if items:
            rec["last_item_at"] = now
            ev = rec.setdefault("item_events", [])
            ev.append(now)
            rec["item_events"] = ev[-_EVENT_KEEP:]
        rec["consecutive_failures"] = 0
        rec["last_error"] = ""
        if note:
            rec["channel_note"] = note
        hit.append(n)
    if hit:
        k = _stale_k()
        for name in hit:
            rec = ledger["sources"].get(name) or {}
            _recompute_items(rec, now)
            st = judge_state(rec, now, k, first_round_done=True)
            rec["state"] = st
            rec["last_state"] = st
            if st == "stale":
                rec["stale_for_sec"] = int(now - (rec.get("last_item_at") or now))
            else:
                rec["stale_for_sec"] = 0
        _save(ledger)
    return snapshot(_ledger=ledger)


def _file_alert(name: str, rec: Dict[str, Any], state: str, now: float) -> None:
    """状态变化时写一条告警（同源同状态不重复写）。"""
    if AL is None:
        return
    interval = int(rec.get("expected_interval") or 300)
    if state == "stale":
        level = "critical" if rec.get("stale_for_sec", 0) > 6 * interval else "warn"
        reason = "情报源疑似停产：已 %d 秒无新增（期望节拍 %d 秒，连续失败 %d 次）" % (
            int(now - (rec.get("last_item_at") or now)), interval,
            int(rec.get("consecutive_failures") or 0))
    else:
        level = "warn"
        reason = "情报源产出缩水：近 24h 新增 %d 条 < 历史日均 %.2f 条的 30%%" % (
            int(rec.get("items_24h") or 0), float(rec.get("items_7d_avg") or 0.0))
    evidence = {
        "state": state,
        "items_24h": int(rec.get("items_24h") or 0),
        "items_7d_avg": float(rec.get("items_7d_avg") or 0.0),
        "consecutive_failures": int(rec.get("consecutive_failures") or 0),
        "last_item_at": _fmt_epoch(rec.get("last_item_at")),
        "last_error": rec.get("last_error", ""),
    }
    try:
        AL.append_alert(level, name, reason, evidence=evidence, state=state,
                        kind="source_missing")
        rec["alerts_total"] = int(rec.get("alerts_total") or 0) + 1
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/source_health.py:_file_alert", e)


def _fmt_epoch(t: Any) -> Optional[str]:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(float(t)))
    except (TypeError, ValueError, OverflowError):
        return None


# --------------------------------------------------------------------------
# 快照 / 缺失清单（供 GET /api/source_health · /api/coverage_gaps）
# --------------------------------------------------------------------------
def snapshot(_ledger: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """逐源健康表 + 汇总计数。首轮未完成时全部 state="unknown"。"""
    ledger = _ledger if _ledger is not None else _load()
    _ensure_seeded(ledger)
    now = time.time()
    k = _stale_k()
    first = int(ledger.get("rounds") or 0) >= 1

    order = list(_static_index().keys())
    for name in ledger.get("sources", {}):
        if name not in order:
            order.append(name)

    summary = {"ok": 0, "degraded": 0, "stale": 0, "disabled": 0, "unknown": 0,
               "alerts_total": 0}
    rows: List[Dict[str, Any]] = []
    for name in order:
        rec = ledger["sources"].get(name)
        if rec is None:
            rec = _new_rec(name, _static_index().get(name))
        st = judge_state(rec, now, k, first_round_done=first)
        ref = rec.get("last_item_at") or rec.get("last_success_at")
        stale_for = int(now - float(ref)) if (st == "stale" and ref) else 0
        row = {
            "source": name,
            "channel": rec.get("channel", ""),
            "category": rec.get("category", "other"),
            "expected_interval": int(rec.get("expected_interval") or 300),
            "last_success_at": _fmt_epoch(rec.get("last_success_at")),
            "last_item_at": _fmt_epoch(rec.get("last_item_at")),
            "consecutive_failures": int(rec.get("consecutive_failures") or 0),
            "items_24h": int(rec.get("items_24h") or 0),
            "items_7d_avg": float(rec.get("items_7d_avg") or 0.0),
            "state": st,
            "stale_for_sec": stale_for,
            "alerts_total": int(rec.get("alerts_total") or 0),
            "last_error": rec.get("last_error", ""),
        }
        rows.append(row)
        summary[st] = summary.get(st, 0) + 1
        summary["alerts_total"] += row["alerts_total"]

    return {
        "ok": True,
        "total": len(rows),
        "rounds": int(ledger.get("rounds") or 0),
        "first_round_done": first,
        "summary": summary,
        "sources": rows,
        "updated_at": ledger.get("updated_at") or time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": ("源清单来自 live.py 静态源定义表（BLOG_FEEDS + 代理源 + ARXIV_RSS + "
                 "SOURCES 调度表），不依赖瞬时 feed_total；首轮轮询完成前全部 unknown。"
                 "stale=停产（缺失数据），degraded=缩水。"),
    }


def coverage_gaps() -> Dict[str, Any]:
    """缺失清单：state ∈ {stale, degraded} 的源（供 GET /api/coverage_gaps）。"""
    snap = snapshot()
    gaps = []
    for s in snap["sources"]:
        if s["state"] not in ("stale", "degraded"):
            continue
        if s["state"] == "stale":
            reason = ("疑似停产：已 %d 秒无新增（期望节拍 %d 秒）"
                      % (s["stale_for_sec"], s["expected_interval"]))
        else:
            reason = ("产出缩水：近 24h 新增 %d 条 < 历史日均 %.2f 条的 30%%"
                      % (s["items_24h"], s["items_7d_avg"]))
        gaps.append({
            "source": s["source"],
            "channel": s["channel"],
            "category": s["category"],
            "reason": reason,
            "state": s["state"],
            "stale_for_sec": s["stale_for_sec"],
            "evidence": {
                "last_item_at": s["last_item_at"],
                "items_24h": s["items_24h"],
                "items_7d_avg": s["items_7d_avg"],
                "consecutive_failures": s["consecutive_failures"],
                "last_error": s["last_error"],
            },
        })
    return {"ok": True, "count": len(gaps), "gaps": gaps,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S")}


def stale_sources() -> List[str]:
    """停产源名列表（供 /api/live 的 stale_sources[]）。"""
    try:
        snap = snapshot()
        return [s["source"] for s in snap["sources"] if s["state"] == "stale"]
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/source_health.py:stale_sources", e)
        return []


if __name__ == "__main__":  # 手工核对用
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    s = snapshot()
    print("源数:", s["total"], "| rounds:", s["rounds"], "| summary:", s["summary"])
    for r in s["sources"][:8]:
        print("  %-22s %-9s %s" % (r["source"], r["state"], r["category"]))
