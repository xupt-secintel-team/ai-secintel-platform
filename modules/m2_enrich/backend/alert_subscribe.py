# -*- coding: utf-8 -*-
"""
alert_subscribe.py —— 漏洞预警订阅与推送
============================================================
把「用户主动来查」升级成「系统主动告诉用户」：

    input : 订阅条件（产品 / 厂商 / CVE / 关键词 / 仅 KEV）+ 过滤器（最低严重度、AI 分、仅在野）
    match : 对模块 1 情报库做增量匹配（按时间水位 + 去重，绝不每次全量扫 10 万条）
    push  : ① 前端通知栏（GET /api/subscribe/alerts 轮询 + 未读角标）
            ② Webhook（环境变量 AISEC_WEBHOOK_URL 或订阅级 webhook，对接企微/钉钉/飞书群机器人）

设计要点
--------
1. **增量**：水位 state.last_check 之前的文档不重扫；每条订阅命中过的 (sub, doc) 记 seen，
   双保险防重复告警。首跑回看 48h（可配 AISEC_SUB_BACKFILL_HOURS）。
2. **后台巡检**：ctx.on_start 拉起 daemon 线程（有启用订阅才干活，间隔
   AISEC_SUB_INTERVAL 秒，默认 120s），同时暴露 check(force) 供手动「立即巡检」。
3. **数据落盘** data/subscriptions.json：subs + alerts（上限 300 条，新的在前）+ 水位/seen。
4. **邮件/群通知口径**：不内置 SMTP，统一走 Webhook（群机器人 / 邮件网关都是 HTTP 端点），
   避免在代码里存邮箱密码。

统一入口::

    list_subs() / add_sub(d) / update_sub(d) / delete_sub(id)
    match_once(engine, force=False) -> {"new": n, "alerts": [...]}
    alerts(since=0, limit=50, unread=False) -> [...]
    mark_read(ids=None) -> n
    status(engine) -> dict          供前端角标
    start_daemon(engine_getter)     服务启动时调用
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402

try:
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

STORE_PATH = os.path.join(paths.DATA_DIR, "subscriptions.json")
_LOCK = threading.Lock()

MAX_ALERTS = 300
MAX_SEEN = 6000
CHECK_INTERVAL = int(os.environ.get("AISEC_SUB_INTERVAL") or 120)
BACKFILL_HOURS = float(os.environ.get("AISEC_SUB_BACKFILL_HOURS") or 48)
_SEVS = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_KINDS = ("product", "vendor", "cve", "keyword", "kev")

try:
    import requests
except ImportError:  # pragma: no cover
    import httpcompat as requests  # noqa: F401


# ==========================================================================
# 存储
# ==========================================================================
def _load() -> dict:
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            d.setdefault("subs", [])
            d.setdefault("alerts", [])
            d.setdefault("state", {})
            return d
    except (OSError, ValueError):
        pass
    return {"subs": [], "alerts": [], "state": {}}


def _save(d: dict) -> None:
    tmp = "%s.%d.tmp" % (STORE_PATH, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        os.replace(tmp, STORE_PATH)
    except OSError as e:  # noqa: BLE001
        _swallow("alert_subscribe._save", e)


# ==========================================================================
# 订阅 CRUD
# ==========================================================================
def _norm_sub(d: dict) -> Optional[dict]:
    kind = str(d.get("kind") or "").strip().lower()
    value = str(d.get("value") or "").strip()
    if kind not in _KINDS:
        return None
    if kind != "kev" and not value:
        return None
    if kind == "cve":
        value = value.upper()
        import re
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            return None
    sev = str(d.get("min_severity") or "").upper() or ""
    if sev and sev not in _SEVS:
        sev = ""
    try:
        ai_min = float(d.get("ai_min") or 0)
    except (TypeError, ValueError):
        ai_min = 0
    return {
        "id": str(d.get("id") or ("SUB-%s-%s" % (time.strftime("%Y%m%d%H%M%S"),
                                                 os.urandom(2).hex()))),
        "name": str(d.get("name") or "").strip()[:60] or value or kind,
        "kind": kind, "value": value,
        "min_severity": sev, "ai_min": min(max(ai_min, 0.0), 1.0),
        "kev_only": bool(d.get("kev_only")),
        "webhook": str(d.get("webhook") or "").strip(),
        "enabled": bool(d.get("enabled", True)),
        "created_at": str(d.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S")),
        # born：订阅的出生时刻（epoch）。后建的订阅要在下一轮巡检拿到自己的回看窗口。
        "born": float(d.get("born") or time.time()),
    }


def list_subs() -> List[dict]:
    return _load()["subs"]


def add_sub(d: dict) -> Dict[str, Any]:
    s = _norm_sub(d)
    if not s:
        return {"ok": False, "error": "订阅参数不合法（kind 须为 %s，value 不能为空）"
                                      % "/".join(_KINDS)}
    with _LOCK:
        store = _load()
        for x in store["subs"]:
            if x["kind"] == s["kind"] and x["value"] == s["value"]:
                return {"ok": False, "error": "已存在相同条件的订阅", "id": x["id"]}
        store["subs"].insert(0, s)
        _save(store)
    return {"ok": True, "sub": s}


def update_sub(d: dict) -> Dict[str, Any]:
    sid = str(d.get("id") or "")
    with _LOCK:
        store = _load()
        for i, x in enumerate(store["subs"]):
            if x["id"] == sid:
                merged = dict(x)
                merged.update({k: v for k, v in d.items()
                               if k in ("name", "min_severity", "ai_min", "kev_only",
                                        "webhook", "enabled")})
                s = _norm_sub(merged)
                if not s:
                    return {"ok": False, "error": "更新后的参数不合法"}
                s["id"] = sid
                s["born"] = float(merged.get("born") or 0) or s["born"]  # 保留出生时刻
                s["created_at"] = merged.get("created_at") or s["created_at"]
                store["subs"][i] = s
                _save(store)
                return {"ok": True, "sub": s}
    return {"ok": False, "error": "订阅不存在", "id": sid}


def delete_sub(sid: str) -> Dict[str, Any]:
    with _LOCK:
        store = _load()
        n = len(store["subs"])
        store["subs"] = [x for x in store["subs"] if x["id"] != sid]
        _save(store)
        return {"ok": True, "deleted": n - len(store["subs"])}


# ==========================================================================
# 匹配
# ==========================================================================
def _kw_match(text: str, word: str) -> bool:
    """ASCII 词边界、非 ASCII 子串（与 affected_assets 口径一致）。"""
    word = (word or "").strip().lower()
    if not word or not text:
        return False
    if word.isascii():
        return re.search(r"\b%s\b" % re.escape(word), text) is not None
    return word in text


def _doc_ts(doc: dict) -> float:
    """文档时间戳：modified > published > fetched_at；解析失败 0。"""
    import calendar
    for k in ("modified", "published", "fetched_at"):
        v = str(doc.get(k) or "").strip()
        if not v:
            continue
        try:
            base = v[:19].replace("T", " ")
            t = time.strptime(base, "%Y-%m-%d %H:%M:%S")
            return calendar.timegm(t)          # 情报时间多为 UTC，统一按 UTC 比大小
        except ValueError:
            continue
    return 0.0


def _iso_to_epoch(s: str) -> float:
    import calendar
    try:
        return calendar.timegm(time.strptime(s[:19].replace("T", " "),
                                             "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return 0.0


def _match_doc(doc: dict, sub: dict) -> bool:
    kind, val = sub["kind"], sub["value"]
    if kind == "kev":
        hit = bool((doc.get("kev") or {}).get("exploited"))
    elif kind == "cve":
        hit = str(doc.get("id") or "").upper() == val
    elif kind == "product":
        prods = [str(p).lower() for p in (doc.get("products") or [])]
        hit = val.lower() in prods
        if not hit:  # products 字段缺失的社区条目退回标题/描述关键词（词边界）
            blob = (str(doc.get("title") or "") + " " + str(doc.get("desc") or ""))[:800].lower()
            hit = _kw_match(blob, val)
    elif kind == "vendor":
        vs = [str(v).lower() for v in (doc.get("vendors") or [])]
        hit = val.lower() in vs
    else:  # keyword
        blob = (str(doc.get("title") or "") + " " + str(doc.get("desc") or ""))[:800].lower()
        hit = _kw_match(blob, val)
    if not hit:
        return False
    if sub.get("kev_only") and not (doc.get("kev") or {}).get("exploited"):
        return False
    if sub.get("min_severity"):
        sev = str((doc.get("cvss") or {}).get("severity") or "UNKNOWN").upper()
        if _SEVS.index(sev if sev in _SEVS else "UNKNOWN") < _SEVS.index(sub["min_severity"]):
            return False
    if sub.get("ai_min"):
        try:
            if float(doc.get("ai_score") or 0) < float(sub["ai_min"]):
                return False
        except (TypeError, ValueError):
            return False
    return True


def _push_webhook(url: str, payload: dict) -> bool:
    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code < 300
    except Exception as e:  # noqa: BLE001
        _swallow("alert_subscribe._push_webhook", e)
        return False


def match_once(engine, force: bool = False) -> Dict[str, Any]:
    """扫一轮情报库，产出新告警并推送。返回 {"new": n, "alerts": [...]}。"""
    subs = [s for s in list_subs() if s.get("enabled")]
    if not subs:
        with _LOCK:
            store = _load()
            store.setdefault("state", {})["last_check"] = time.strftime(
                "%Y-%m-%d %H:%M:%S")
            _save(store)
        return {"new": 0, "alerts": []}

    with _LOCK:
        store = _load()
        state = store.setdefault("state", {})
        seen: Dict[str, float] = state.get("seen") or {}
    now = time.time()
    # 窗口起点 = 全局水位；但「上次巡检之后新建的订阅」要拿到自己的回看窗口
    # （born - 回看时长）。窗口放宽永远安全 —— seen 集合按 (sub, doc) 去重兜底。
    # 注意：born 是真实 epoch，这里也必须用真实 epoch 的 watermark_epoch 比较；
    # 若去解析 last_check（本地时间字符串）会差出时区偏移，新订阅永远拿不到回看窗口。
    last_epoch = float(state.get("watermark_epoch") or 0)
    wm = last_epoch or (now - BACKFILL_HOURS * 3600)
    starts = [wm] + [float(s.get("born") or 0) - BACKFILL_HOURS * 3600
                     for s in subs if float(s.get("born") or 0) > last_epoch]
    start = min(starts)
    if not force:
        start = max(start, now - 30 * 24 * 3600)       # 常规巡检最多回看 30 天
    # force=1（手动"立即巡检"）：不设下限，全量回看；seen 去重保证不重复告警

    docs = getattr(engine, "docs", None) or []
    # 宽限 1 秒：语料时间常被截断到整秒，水位用浮点秒，同秒落盘的新文档不能漏
    window = [d for d in docs if isinstance(d, dict) and _doc_ts(d) >= start - 1.0]
    # 注意：窗口为空就是空 —— 不做"最后 2000 条"兜底，否则水位外的老文档会借兜底复活；
    # 需要全量回看时用 force=1（start 不设下限），seen 去重保证不重复告警。
    window.sort(key=_doc_ts, reverse=True)
    window = window[:4000]

    new_alerts: List[dict] = []
    for doc in window:
        if not isinstance(doc, dict):
            continue
        for s in subs:
            if not _match_doc(doc, s):
                continue
            key = "%s|%s" % (s["id"], doc.get("id"))
            if key in seen:
                continue
            seen[key] = now
            cvss = doc.get("cvss") or {}
            new_alerts.append({
                "id": "AL-%s-%s" % (time.strftime("%Y%m%d%H%M%S"),
                                    hashlib.md5(key.encode()).hexdigest()[:6]),
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "sub_id": s["id"], "sub_name": s.get("name") or s["value"],
                "doc_id": doc.get("id"), "title": str(doc.get("title") or "")[:160],
                "severity": str(cvss.get("severity") or "UNKNOWN").upper(),
                "score": cvss.get("score"),
                "kev": bool((doc.get("kev") or {}).get("exploited")),
                "ai_score": doc.get("ai_score"),
                "published": doc.get("published") or doc.get("modified") or "",
                "read": False, "pushed": False,
            })

    # webhooks：全局 AISEC_WEBHOOK_URL + 订阅级
    global_hook = os.environ.get("AISEC_WEBHOOK_URL") or ""
    hooks: Dict[str, str] = {}
    for s in subs:
        u = s.get("webhook") or global_hook
        if u:
            hooks[s["id"]] = u
    for a in new_alerts:
        u = hooks.get(a["sub_id"])
        if u and _push_webhook(u, {"type": "aisec_alert", "alert": a}):
            a["pushed"] = True

    with _LOCK:
        store = _load()
        st = store.setdefault("state", {})
        merged_seen = dict(st.get("seen") or {})
        for a in new_alerts:
            merged_seen["%s|%s" % (a["sub_id"], a["doc_id"])] = now
        if len(merged_seen) > MAX_SEEN:                  # 只留最近的
            keep = sorted(merged_seen.items(), key=lambda kv: -kv[1])[:MAX_SEEN]
            merged_seen = dict(keep)
        st["seen"] = merged_seen
        st["watermark_epoch"] = now
        st["last_check"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if new_alerts:
            store["alerts"] = (new_alerts + store.get("alerts", []))[:MAX_ALERTS]
        _save(store)
    return {"new": len(new_alerts), "alerts": new_alerts[:50]}


def alerts(since_id: str = "", limit: int = 50, unread_only: bool = False) -> List[dict]:
    with _LOCK:
        store = _load()
    out = []
    for a in store["alerts"]:
        if unread_only and a.get("read"):
            continue
        if since_id and a["id"] == since_id:   # 支持“取这条之后的”
            break
        out.append(a)
        if len(out) >= max(1, min(limit, 200)):
            break
    return out


def mark_read(ids: Optional[List[str]] = None) -> int:
    with _LOCK:
        store = _load()
        n = 0
        for a in store["alerts"]:
            if ids is None or a["id"] in ids:
                if not a.get("read"):
                    a["read"] = True
                    n += 1
        _save(store)
        return n


def status() -> dict:
    with _LOCK:
        store = _load()
    subs = store["subs"]
    unread = sum(1 for a in store["alerts"] if not a.get("read"))
    return {
        "subs": len(subs), "enabled": sum(1 for s in subs if s.get("enabled")),
        "alerts": len(store["alerts"]), "unread": unread,
        "last_check": store.get("state", {}).get("last_check") or "",
        "webhook": bool(os.environ.get("AISEC_WEBHOOK_URL")),
        "daemon": _DAEMON["running"],
        "interval": CHECK_INTERVAL,
    }


# ==========================================================================
# 后台巡检线程
# ==========================================================================
_DAEMON = {"running": False, "started": False}


def start_daemon(engine_getter) -> None:
    """服务启动钩子：有启用订阅时周期性巡检。"""
    if _DAEMON["started"]:
        return
    _DAEMON["started"] = True

    def _loop():
        while True:
            try:
                if any(s.get("enabled") for s in list_subs()):
                    eng = engine_getter()
                    if eng is not None:
                        r = match_once(eng)
                        if r["new"]:
                            print("[m2_enrich] 预警巡检：%d 条新告警" % r["new"],
                                  flush=True)
            except Exception as e:  # noqa: BLE001
                _swallow("alert_subscribe.daemon", e)
            time.sleep(CHECK_INTERVAL)

    t = threading.Thread(target=_loop, daemon=True, name="subscribe-daemon")
    t.start()
    _DAEMON["running"] = True
