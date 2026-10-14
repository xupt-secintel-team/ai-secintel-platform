# -*- coding: utf-8 -*-
"""
api.py —— 模块1「情报监测」后端入口
============================================================
负责人：成员A
职责：7×24 盯梢抓漏洞 —— 多源定时增量采集、快车道实时监测、归档体量。

本模块对外接口（启动时自动注册进主体，无需改 core/server.py）：
    GET  /api/live             快车道实时监测状态（15s 一轮）
    GET  /api/sources          多源归档体量
    GET  /api/refresh          增量同步任务状态
    POST /api/refresh          触发一次实时增量同步（?hours=时间窗&github=0）
    GET  /api/daily_reports    每日按类情报报告列表（日期 + 每类计数 + 保留期）
    GET  /api/daily_report     某天报告详情（?date=YYYY-MM-DD）
    GET  /api/daily_report     下载某天报告（?date=&fmt=md|json|xlsx）
    POST /api/daily_report/generate   手动生成并落盘（{"date": "..."} 缺省为今天）
    POST /api/daily_report/cleanup    手动清理超期报告（{"dry_run": true/false}）

后台线程：live.py 快车道轮询（默认 15s，config.json 的 fast_interval 可调）、monitor.py 定时增量（config.json 可选）。
数据/缓存：一律走 paths.DATA_DIR（共享数据目录），不要再用 HERE/data。
"""
from __future__ import annotations

import json
import os
import threading
import time

import paths                                   # noqa: F401  —— 强调：数据目录统一从这里取
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# ---- 由 registry 在启动时注入 ----
_CORE = None
_INTERVAL = 15


# ======================================================================
# 实时增量同步状态（monitor.py 后台任务）
# ======================================================================
REFRESH = {"running": False, "stage": "", "detail": "", "pct": 0,
           "started_at": None, "finished_at": None, "error": None,
           "summary": None}
REFRESH_LOCK = threading.Lock()


# ======================================================================
# 快车道实时监测（live.py，每 15s 一轮）
# ======================================================================
LIVE = {
    "enabled": False, "interval": 15, "running": False,
    "last_poll": None, "last_ms": None, "added_total": 0,
    "last_batch": 0, "per_source": {}, "history": [],
    "recent": [],                    # 最近新增条目（feed 用）
    "error": None,
}
LIVE_LOCK = threading.Lock()
LIVE_INTERVAL = 15                  # 秒；15s 一轮抓取，新信息公开后约 15s 内可见（v2.1 由 30s 收紧）
_LIVE_DOCS_CACHE = {"key": None, "n": 0}   # /api/live 的「实时条目数」缓存（避免每次全库扫描）


def live_status():
    with LIVE_LOCK:
        st = {k: v for k, v in LIVE.items() if k != "recent"}
        st["recent"] = LIVE["recent"][:40]
    # 源健康度：直接读 live 模块的当前状态（首轮还没跑完时也要有值，不能是 None）
    try:
        import live as _L
        lm = getattr(_L, "LAST_META", {}) or {}
        ok = len(getattr(_L, "_SRC_OK", []) or []) or int(lm.get("feed_ok") or 0)
        bad = dict(lm.get("feed_fail") or getattr(_L, "_SRC_ERR", {}) or {})
        st["feed_ok"] = int(ok)
        st["feed_fail"] = bad
        st["feed_total"] = int(lm.get("feed_total") or (int(ok) + len(bad)))
    except Exception:  # noqa: BLE001
        st.setdefault("feed_ok", 0)
        st.setdefault("feed_fail", {})
        st.setdefault("feed_total", 0)
    # P0-3：停产源列表（键必须存在，可为空数组；停产时非空，供前端打 STALE 红标）
    try:
        import source_health as _SH
        st["stale_sources"] = _SH.stale_sources()
    except Exception as _sw_ss:  # noqa: BLE001 —— 源健康是增强项，绝不阻断 /api/live
        _swallow("modules/m1_monitor/api.py:live_status.stale_sources", _sw_ss)
        st["stale_sources"] = []
    try:
        st["age_sec"] = int(time.time() - LIVE["last_ts"]) if LIVE.get("last_ts") else None
    except Exception:  # noqa: BLE001
        st["age_sec"] = None
    # 实时情报实际入索引条数（跨重启累计，避免会话计数器重启归零让用户误以为"没数据"）
    # 性能：前端每 30s 轮询一次 /api/live，旧实现每次都要全库扫 8.8 万条（约 40ms）——
    # 按 (引擎对象, 文档数) 缓存，只在语料真的变了时才重算（2026-09-28）
    try:
        eng = _CORE.get_engine()
        key = (id(eng), len(eng.docs))
        if _LIVE_DOCS_CACHE["key"] != key:
            _LIVE_DOCS_CACHE["n"] = sum(
                1 for d in eng.docs if str(d.get("id") or "").startswith("LIVE:"))
            _LIVE_DOCS_CACHE["key"] = key
        st["live_docs"] = _LIVE_DOCS_CACHE["n"]
    except Exception:  # noqa: BLE001
        st.setdefault("live_docs", None)
    return st


# ======================================================================
# 多源归档体量（原始数据仓库，默认 <项目>/data/ai_sec_raw，可用 AI_RAW_DIR 覆盖）
# ======================================================================
RAW_DIR = os.environ.get("AI_RAW_DIR") or os.path.join(paths.DATA_DIR, "ai_sec_raw")
_SOURCES_CACHE = {"t": 0.0, "v": None}
SOURCE_LABELS = {
    "arxiv": "AI 安全论文（arXiv，元数据 + PDF 全文）",
    "blogs": "厂商公告 / 安全博客（Trail of Bits·Wiz·Snyk·Unit42·CISA·微软·AWS 等）",
    "nvd": "NVD 中 AI 相关 CVE（完整记录）",
    "ghsa": "GHSA / OSV 中 AI 组件公告",
    "hf": "HuggingFace 安全相关模型 / 数据集卡片",
    "cn": "中文 AI 安全文章",
}


def _dir_size(p):
    total = 0
    for root, _d, files in os.walk(p):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(root, fn))
            except OSError as _sw_e:
                _swallow("modules/m1_monitor/api.py:112", _sw_e)
    return total


def sources_status():
    """归档体量 + 已入索引语料规模（60s 缓存，避免每次请求遍历磁盘）"""
    now = time.time()
    if _SOURCES_CACHE["v"] and now - _SOURCES_CACHE["t"] < 60:
        return _SOURCES_CACHE["v"]
    items, total = [], 0
    if os.path.isdir(RAW_DIR):
        for sub in sorted(os.listdir(RAW_DIR)):
            p = os.path.join(RAW_DIR, sub)
            if not os.path.isdir(p):
                continue
            sz = _dir_size(p)
            total += sz
            items.append({"key": sub, "label": SOURCE_LABELS.get(sub, sub),
                          "bytes": sz, "gb": round(sz / 1024 / 1024 / 1024, 3)})
    eng = _CORE.get_engine()
    out = {
        "archive_dir": RAW_DIR,
        "archive_total_gb": round(total / 1024 / 1024 / 1024, 2),
        "target_gb": 10,
        "channels": items,
        "corpus": {"documents": len(eng.docs), "terms": len(eng.df)},
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    # 采集覆盖度：类别清单 + 各类源数量（验收「多源 7 类以上」的直接依据）
    try:
        import live as L
        out["coverage"] = L.source_categories()
    except Exception as e:  # noqa: BLE001 —— 覆盖度统计不该拖垮整个源清单接口
        out["coverage"] = {"error": str(e)[:120]}
    _SOURCES_CACHE.update(t=now, v=out)
    return out


# ======================================================================
# 快车道：回放 → 轮询 → 入索引
# ======================================================================
def _live_replay():
    """启动时把已落盘的最新情报（live_feed.jsonl）灌回引擎，重启不丢最新条目"""
    import json

    import live as L
    if not os.path.isfile(L.FEED_FP):
        return 0
    eng = _CORE.get_engine()
    recs, seen = [], set()
    try:
        with open(L.FEED_FP, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                rid = r.get("id")
                if rid and rid not in seen:
                    seen.add(rid)
                    recs.append(r)
    except OSError:
        return 0
    _CORE.enrich_all(recs)       # 快车道条目同样挂载可信度字段，卡片字段通路不缺
    n = eng.add_documents(recs)
    # ★ 2026-10-08 实测补 —— `recent` 也要回填：
    #   原实现只把条目灌进引擎，`LIVE["recent"]` 仍为空，于是「刚重启就演示」
    #   的实时区是一个空列表（用户看到 recent=0），必须等下一轮轮询**且恰好有新增**
    #   才会出现条目 —— 而轮询常态 added=0，可能空很久，看着像功能坏了。
    #   这里用已落盘 feed 的最新 40 条回填，标注 `replay:true` 以便与实时新增区分。
    try:
        _tail = recs[-40:]
        with LIVE_LOCK:
            if not LIVE.get("recent"):
                LIVE["recent"] = [{
                    "id": r.get("id"), "title": r.get("title", ""),
                    "source": ((r.get("sources") or [""])[0] if r.get("sources") else ""),
                    "category": r.get("category", ""),
                    "published": (r.get("published") or "")[:10],
                    "kind": r.get("kind", ""),
                    "ts": time.strftime("%H:%M:%S"),
                    "replay": True,
                } for r in reversed(_tail)]
    except Exception as _sw_re:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:_live_replay/recent", _sw_re)
    return n


def _live_poll_once():
    """一轮快车道：抓取 → 增量入引擎 → 更新状态"""
    import live as L
    t0 = time.time()
    try:
        fresh = L.poll_once(verbose=False)
    except Exception as e:  # noqa: BLE001
        with LIVE_LOCK:
            LIVE["error"] = str(e)[:200]
        return 0
    added = 0
    if fresh:
        _CORE.enrich_all(fresh)  # 先富化再入索引，保证 /api/search 卡片可信度字段完整
        eng = _CORE.get_engine()
        added = eng.add_documents(fresh)
        _CORE.clear_stats_cache()
    ts = time.strftime("%H:%M:%S")
    with LIVE_LOCK:
        LIVE["last_poll"] = ts
        LIVE["last_ts"] = time.time()
        LIVE["last_ms"] = int((time.time() - t0) * 1000)
        LIVE["last_batch"] = added
        LIVE["added_total"] += added
        LIVE["per_source"] = dict(getattr(L, "LAST_META", {}).get("per_source") or {})
        # 源健康度：本轮哪些源没盯上（前端可提示"换代理/稍后重试"）
        try:                       # 含后台博客线程的结果，避免源健康度在 0/48 之间跳
            _ok, _err = L.src_health()
        except Exception:  # noqa: BLE001
            _ok, _err = getattr(L, "_SRC_OK", []) or [], dict(getattr(L, "_SRC_ERR", {}) or {})
        LIVE["feed_ok"] = len(_ok)
        LIVE["feed_fail"] = dict(_err)
        LIVE["feed_total"] = LIVE["feed_ok"] + len(LIVE["feed_fail"])
        LIVE["error"] = None
        if fresh:
            LIVE["recent"] = [{
                "id": r.get("id"), "title": r.get("title", ""), "source": (r.get("sources") or [""])[0],
                "category": r.get("category", ""), "published": (r.get("published") or "")[:10],
                "kind": r.get("kind", ""), "ts": ts,
            } for r in fresh[:40]] + LIVE["recent"]
            LIVE["recent"] = LIVE["recent"][:120]
        LIVE["history"].append({"t": ts, "ms": LIVE["last_ms"], "added": added})
        LIVE["history"] = LIVE["history"][-60:]
    # 当日按类报告：轮询有新增就顺手更新一次日报（内部有 1 小时节流 + 每日清理）
    if added:
        _daily_maybe_generate()
    return added


def _live_loop():
    with LIVE_LOCK:
        LIVE["enabled"] = True
        LIVE["running"] = True
    try:
        added = _live_replay()
        if added:
            print(f"[live] 启动回放最新情报 {added} 条", flush=True)
    except Exception as e:  # noqa: BLE001
        print("[live] 回放失败:", str(e)[:120], flush=True)
    while True:
        try:
            n = _live_poll_once()
            if n:
                print(f"[live] +{n} 条（{LIVE['last_poll']}，{LIVE['last_ms']}ms）", flush=True)
        except Exception as e:  # noqa: BLE001
            print("[live] 轮询异常:", str(e)[:150], flush=True)
        time.sleep(LIVE_INTERVAL)


# ======================================================================
# 深度增量同步（monitor.py 全源对账）
# ======================================================================
def refresh_status():
    with REFRESH_LOCK:
        st = dict(REFRESH)
    try:
        # 优先复用已加载引擎的 meta（O(1)）；未就绪时才回落到读文件，
        # 避免每次查询状态都整读上百 MB 的 corpus.json（旧实现耗时约 2s）
        eng = _CORE.current_engine()
        meta = eng.corpus.get("meta", {}) if eng is not None else None
        if meta is None:
            import json
            with open(_CORE.corpus_path, "r", encoding="utf-8") as f:
                meta = json.load(f).get("meta", {})
        st["last_sync"] = (meta.get("monitor") or {}).get("last_sync")
        st["monitored_at"] = meta.get("monitored_at")
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:256", _sw_e)
    return st


def _run_refresh(window_hours=None, skip_github=False, light=False):
    import monitor
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    _t0 = time.time()

    def cb(stage, detail, pct):
        with REFRESH_LOCK:
            REFRESH.update(stage=stage, detail=detail, pct=pct)

    try:
        summary = monitor.refresh(progress=cb, window_hours=window_hours,
                                  skip_github=skip_github, light=light)
        # 轻量轮没写盘（本轮无新增）→ 语料没变，**不动引擎**。
        # 否则 5 分钟一次全量重建索引（99k 文档，分钟级）会把服务拖死。
        if light and not summary.get("saved"):
            with REFRESH_LOCK:
                REFRESH.update(running=False, pct=100, stage="done",
                               detail="轻量轮：无新增，引擎未重建",
                               finished_at=now, summary=summary)
            print(f"[refresh] 轻量轮：无新增，未写盘、未重建引擎"
                  f"（{time.time() - _t0:.1f}s）", flush=True)
            return
        if light:
            # 轻量轮有新增：增量并入引擎（毫秒级）+ 同步刷新 .idxcache，
            # 避免每轮写 corpus 都让索引缓存失效、下次启动要 6 分钟重建。
            added = -1
            docs = summary.get("new_docs") or []
            try:
                # 富化（可信度 / 交叉验证）：全量轮走 reload_engine→ensure_credibility，
                # 快车道走 enrich_all，唯独轻量轮此前漏了这一步 —— 结果是这批新增
                # 文档 trust_score 为 None，卡片可信度区空白，按可信度排序时全沉底。
                _CORE.enrich_all(docs)
            except Exception as _sw_e:  # noqa: BLE001 —— 富化失败不影响入库
                _swallow("modules/m1_monitor/api.py:293", _sw_e)
            try:
                added = _CORE.apply_new_docs(docs)
            except Exception:  # noqa: BLE001
                added = -1
            if added <= 0:                     # 0 也可能是"磁盘已变、引擎没吃下"，同样兜底
                _CORE.reload_engine()
            _nn = len(summary.get("new_ids") or [])
            _nu = len(summary.get("updated_ids") or [])
            with REFRESH_LOCK:
                REFRESH.update(running=False, pct=100, stage="done",
                               detail=f"轻量轮：新增 {_nn} 条 / 更新 {_nu} 条已增量入库",
                               finished_at=now, summary=summary)
            print(f"[refresh] 轻量轮：新增 {_nn} 条 / 更新 {_nu} 条"
                  f"（并入引擎 {added} 条，未全量重建，{time.time() - _t0:.1f}s）", flush=True)
            return
        # 原子热切换：新引擎构建成功后再整体替换，检索全程不中断
        # （引擎构建 + 可信度挂载 + STATS_CACHE 清空都由 core 提供）
        eng = _CORE.reload_engine()
        try:                                   # 全量轮后同步落缓存：下次启动不用重建索引
            eng._save_index_cache(_CORE.corpus_path)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/api.py:315", _sw_e)
        with REFRESH_LOCK:
            REFRESH.update(running=False, pct=100, stage="done",
                           detail="同步完成", finished_at=now, summary=summary)
        print(f"[refresh] 完成：{summary.get('nvd_new', 0)} 新CVE / "
              f"{summary.get('articles_new', 0)} 新文章 / 文档 {len(eng.docs)} 条"
              f"（全量轮 {time.time() - _t0:.1f}s）", flush=True)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        with REFRESH_LOCK:
            REFRESH.update(running=False, error=str(e), finished_at=now)


# ======================================================================
# 每日按类情报报告（core/daily_report.py）
# ======================================================================
# 为什么不放在 core/server.py：报告的数据源就是本模块的实时流
# （live_feed.jsonl）和 KEV 缓存，跟采集逻辑绑在一起；放 core 会让
# server.py 变成"什么都往里塞"的垃圾桶。
#
# 自动生成策略（实测 collect 72ms + xlsx 753ms，约 0.5s/次）：
#   每轮快车道轮询后检查一次 —— 今天还没生成、或上次生成超过 1 小时
#   就重算一次（这样上午打开页面看到的是"到目前为止"的当日报告，
#   而不是早上 8 点的快照）。判断只看一次 os.stat，不读文件。
#   清理（30 天保留）每天只做一次。
_DAILY = {"last_gen": None, "last_gen_day": "", "last_cleanup": ""}
_DAILY_LOCK = threading.Lock()
_REPORT_LIST_CACHE = {"t": 0.0, "v": None}
_GEN_MIN_GAP = 3600          # 秒：同一天最多每小时重算一次日报


def _dr():
    """取 daily_report 模块（core 已在 sys.path 里）。"""
    import daily_report
    return daily_report


def _day_summary(data):
    """从一份报告里抽出"列表页要的那几项"，把 items 丢掉。

    为什么要抽：单日 json 约 24KB，30 天全量返回就是 700KB+，
    而列表页真正需要的只是每类几条、几个严重度计数。
    """
    if not data:
        return None
    cats = []
    for c in (data.get("categories") or []):
        bs = c.get("by_sev") or {}
        cats.append({
            "key": c.get("key"), "label": c.get("label") or c.get("key"),
            "color": c.get("color"), "count": c.get("count") or 0,
            "critical": bs.get("critical", 0), "high": bs.get("high", 0),
            "medium": bs.get("medium", 0), "low": bs.get("low", 0),
            "info": bs.get("info", 0),
        })
    return {
        "date": data.get("date"),
        "generated_at": data.get("generated_at"),
        "total": data.get("total") or 0,
        "category_count": data.get("category_count") or 0,
        "by_sev": data.get("by_sev") or {},
        "kev": data.get("kev") or 0,
        "poc": data.get("poc") or 0,
        "categories": cats,
    }


def daily_list(force=False):
    """日报列表：每天一格，含每类计数。60s 缓存 —— 列表页会被前端轮询。"""
    now = time.time()
    if (not force and _REPORT_LIST_CACHE["v"]
            and now - _REPORT_LIST_CACHE["t"] < 60):
        return _REPORT_LIST_CACHE["v"]
    D = _dr()
    dates = D.available_dates(limit=D.RETENTION_DAYS + 5)
    days = []
    for ent in dates:
        s = _day_summary(D.load_saved(ent["date"])) or {
            "date": ent["date"], "total": 0, "categories": [],
            "by_sev": {}, "kev": 0, "poc": 0, "category_count": 0,
        }
        s["formats"] = ent["formats"]
        days.append(s)
    today = D.today()
    # 今天还没落盘 → 现场算一份给页面（用户不必等定时任务）。
    # 否则会出现"今天明明有新情报，日报页却是空的"这种误解。
    if not any(d["date"] == today for d in days):
        try:
            with _DAILY_LOCK:
                live = D.collect(today)
            s = _day_summary(D._json_public(live))
            s["formats"] = []
            s["pending"] = True          # 尚未落盘
            days.insert(0, s)
        except Exception as e:  # noqa: BLE001
            days.insert(0, {"date": today, "total": 0, "categories": [],
                            "by_sev": {}, "kev": 0, "poc": 0,
                            "category_count": 0, "formats": [],
                            "pending": True, "error": str(e)[:160]})
    out = {
        "days": days,
        "today": today,
        "retention_days": D.RETENTION_DAYS,
        "expired_days": D.expired_days()[:60],
        "dir": D.report_dir(),
        "stats": D.stats(),
        "server_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _REPORT_LIST_CACHE.update(t=now, v=out)
    return out


def _daily_maybe_generate(force=False):
    """快车道轮询后调用：该算的时候算一份，并顺带做超期清理。"""
    try:
        D = _dr()
        today = D.today()
        # --- 清理：每天一次 ---
        if _DAILY["last_cleanup"] != today:
            r = D.cleanup()
            _DAILY["last_cleanup"] = today
            if r.get("removed_count"):
                print(f"[daily] 清理超期日报 {r['removed_count']} 个文件"
                      f"（保留 {r['retention_days']} 天）", flush=True)
        # --- 生成 ---
        need = force
        if not need:
            if _DAILY["last_gen_day"] == today:
                need = (time.time() - (_DAILY["last_gen"] or 0)) >= _GEN_MIN_GAP
            else:
                need = True
        if not need or not _DAILY_LOCK.acquire(blocking=False):
            return None
        try:
            t0 = time.time()
            data = D.collect(today)
            paths = D.save(data)
            _DAILY["last_gen"] = time.time()
            _DAILY["last_gen_day"] = today
            _REPORT_LIST_CACHE["t"] = 0.0        # 让列表页下一轮拿到新数据
            print(f"[daily] {today} 报告已生成：{data['total']} 条 / "
                  f"{data['category_count']} 类"
                  f"{'（缺 openpyxl，无 xlsx）' if paths.get('xlsx_error') else ''}"
                  f"（{time.time() - t0:.1f}s）", flush=True)
            return {"date": today, "total": data["total"],
                    "category_count": data["category_count"],
                    "by_sev": data["by_sev"], "kev": data["kev"],
                    "paths": paths, "seconds": round(time.time() - t0, 2)}
        finally:
            _DAILY_LOCK.release()
    except Exception as e:  # noqa: BLE001 —— 日报失败绝不能拖垮采集主循环
        _swallow("modules/m1_monitor/api.py:daily", e)
        return None


# ======================================================================
# HTTP 处理
# ======================================================================
def handle_live(req):
    return req.json(live_status())


def handle_sources(req):
    return req.json(sources_status())


def handle_refresh_get(req):
    return req.json(refresh_status())


# ---------------------------------------------------------------- 源健康（P0-3）
def handle_source_health(req):
    """GET /api/source_health —— 逐源健康表 + 汇总计数（源清单来自静态定义表）。"""
    try:
        import source_health as SH
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)[:200]}, 500)
    return req.json(SH.snapshot())


def handle_coverage_gaps(req):
    """GET /api/coverage_gaps —— 缺失清单（停产/缩水源）。"""
    try:
        import source_health as SH
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)[:200]}, 500)
    return req.json(SH.coverage_gaps())


# ---------------------------------------------------------------- 标准/法规（P0-1）
def _standards_kb():
    try:
        import standards_kb as SKB
    except Exception:  # pragma: no cover
        from core import standards_kb as SKB  # type: ignore
    return SKB


def handle_standards(req):
    """GET /api/standards —— 标准/法规结构化条目（支持 q / kind / region / status / size）。"""
    SKB = _standards_kb()
    try:
        size = int(str(req.q("size") or "60").strip())
    except (TypeError, ValueError):
        size = 60
    return req.json(SKB.query(q=req.q("q"), kind=req.q("kind"),
                              region=req.q("region"), status=req.q("status"),
                              size=size))


def handle_standards_refresh(req):
    """POST /api/standards/refresh —— 增量比对 + 运行期注入（离线降级、HTTP 仍 200）。"""
    SKB = _standards_kb()
    res = SKB.refresh()
    # 刷新后做一次运行期合并注入（**绝不写 corpus.json**）
    try:
        eng = _CORE.get_engine()
        res["injected"] = SKB.inject(eng, clear_cache=_CORE.clear_search_cache)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:standards_refresh.inject", _sw_e)
        res["injected"] = 0
    return req.json(res)


# ---------------------------------------------------------------- 每日报告
_MIME = {
    "md": "text/markdown; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def _report_payload(date, limit=None):
    """取某天的报告数据：优先读已落盘的 JSON，没有（或 force）就现场算。

    返回 (data, err)。err 非空时 data 为 None。
    """
    D = _dr()
    day = D.valid_date(date)
    if not day:
        return None, "日期格式应为 YYYY-MM-DD"
    data = D.load_saved(day)
    if data is None:
        data = D._json_public(D.collect(day))
    if limit:
        n = max(1, min(300, int(limit)))
        data = dict(data)
        cats = []
        for c in (data.get("categories") or []):
            c = dict(c)
            c["items"] = (c.get("items") or [])[:n]
            c["truncated"] = max(0, (c.get("count") or 0) - len(c["items"]))
            cats.append(c)
        data["categories"] = cats
    return data, None


def handle_daily_reports(req):
    """列表：每天一格 + 每类计数 + 保留期。"""
    try:
        return req.json(daily_list(force=req.q("refresh") in ("1", "true")))
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"error": str(e)[:200], "days": [],
                         "retention_days": 30}, 500)


def handle_daily_report(req):
    """详情 / 下载。

    fmt=md|json|xlsx → 走 attachment 下载（浏览器直接落盘）；
    不带 fmt → 返回 JSON 给页面渲染。
    """
    try:
        date = req.q("date")
        fmt = (req.q("fmt") or "").lower().strip()
        if fmt and fmt not in _MIME:
            return req.json({"error": "fmt 只支持 md / json / xlsx"}, 400)
        D = _dr()
        if not D.valid_date(date):
            return req.json({"error": "缺少或非法的 date 参数（应为 YYYY-MM-DD）"}, 400)
        data, err = _report_payload(date, limit=req.q("limit") or None)
        if err:
            return req.json({"error": err}, 400)
        _saved = [f for f in ("md", "json", "xlsx")
                  if os.path.isfile(D._path(data["date"], f))]
        # 这天"没有可下载的东西"有两种原因，必须区分：
        #   expired = 已过保留期被清理（正常行为，数据没丢）
        #   no_data = 那天系统确实没采到东西
        _reason = ("expired" if data["date"] in set(D.expired_days())
                   else "no_data")
        if not fmt:
            data = dict(data)
            data["available_formats"] = _saved
            data["retention_days"] = D.RETENTION_DAYS
            data["empty_reason"] = _reason
            return req.json(data)

        # ── 下载 ──
        # ★ 不能对"没有报告的日期"现场渲染一份空报告下载。
        #   实测踩过：date=1999-01-01&fmt=md 会返回一份标题写着
        #   「AI 安全风险日报 · 1999-01-01」、生成时间是**当前时刻**的
        #   空报告 —— 落盘与否对用户没区别，拿到手就是一份像样的假报告，
        #   等于「这天有报告」的误导。这与"不造占位假报告"的设计相悖。
        #   正确行为：只有确实采集到条目的日期才允许下载。
        # ① 已过期：即使现场还能从 feed 里算出条目，也不允许"复活"。
        #    否则清理掉的报告会被一次下载请求重新写回磁盘，
        #    保留期管理形同虚设（实测这个分支很容易漏）。
        if _reason == "expired":
            return req.json({
                "error": "该日期的报告已超过保留期并被清理",
                "date": data["date"],
                "empty_reason": "expired",
                "retention_days": D.RETENTION_DAYS,
                "hint": "如需该日数据，请调整 AISEC_REPORT_KEEP_DAYS 后重新采集",
            }, 404)
        # ② 根本没有条目：不造空报告
        if not data.get("total") and not _saved:
            return req.json({
                "error": "该日期没有可下载的报告",
                "date": data["date"],
                "empty_reason": "no_data",
                "hint": "该日未采集到任何情报条目",
            }, 404)
        # ③ 有数据但还没落盘（例如今天首次访问、自动生成的 8s 延迟还没到）：
        #    先落盘再下载，保证用户拿到的是与列表一致的产物
        if not _saved:
            try:
                D.save(data)
            except Exception as _e:  # noqa: BLE001
                # 落盘失败不阻断下载——内容已经在内存里，直接渲染即可
                print("[daily] 落盘失败，仍直接下载：%s" % _e)

        if fmt == "md":
            payload = D.render_markdown(data).encode("utf-8")
        elif fmt == "json":
            payload = json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8")
        else:
            try:
                payload = D.render_xlsx(data)
            except Exception as e:  # noqa: BLE001
                return req.json({"error": "生成 xlsx 失败（缺 openpyxl？）：" + str(e)[:160]},
                                500)
        fname = "AI安全风险日报_%s.%s" % (data["date"], fmt)
        return req.send(200, payload, _MIME[fmt], filename=fname,
                        cache="no-store")
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"error": str(e)[:200]}, 500)


def handle_daily_generate(req):
    """手动生成并落盘（默认今天）。"""
    body = req.json_body() or {}
    if not isinstance(body, dict):
        body = {}
    date = (body.get("date") or req.q("date") or "").strip()
    D = _dr()
    if date and not D.valid_date(date):
        return req.json({"ok": False, "error": "日期格式应为 YYYY-MM-DD"}, 400)
    day = D.valid_date(date) or D.today()
    t0 = time.time()
    try:
        with _DAILY_LOCK:
            data = D.collect(day)
            paths = D.save(data)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"ok": False, "error": str(e)[:200]}, 500)
    _DAILY["last_gen"] = time.time()
    _DAILY["last_gen_day"] = day
    _REPORT_LIST_CACHE["t"] = 0.0
    return req.json({
        "ok": True, "date": day, "total": data["total"],
        "category_count": data["category_count"], "by_sev": data["by_sev"],
        "kev": data["kev"], "poc": data["poc"],
        "retention_days": D.RETENTION_DAYS,
        "paths": paths, "seconds": round(time.time() - t0, 2),
        "note": ("xlsx 未生成：" + str(paths.get("xlsx_error"))[:120])
                if paths.get("xlsx_error") else "",
    })


def handle_daily_cleanup(req):
    """清理超期报告。默认 dry_run=true —— 删文件是不可逆操作，先看清单。"""
    body = req.json_body() or {}
    if not isinstance(body, dict):
        body = {}
    raw = body.get("dry_run", req.q("dry_run", "true"))
    dry = str(raw).lower() not in ("0", "false", "no")
    try:
        D = _dr()
        keep = body.get("retention_days") or req.q("retention_days") or None
        r = D.cleanup(retention_days=keep, dry_run=dry)
        r["dry_run"] = dry
        r["dir"] = D.report_dir()
        if not dry:
            _REPORT_LIST_CACHE["t"] = 0.0
        return req.json(r)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"error": str(e)[:200]}, 500)


def handle_submit_article(req):
    """提交链接即时收录：用户粘贴任意平台文章链接 → 秒级抓取正文 → 入库 → 显示。

    入参（JSON body）：{ "url": "https://...", "force": false }
    出参：{ ok, id, title, added, message, info }；重复/已收录会返回 duplicated。
    """
    body = req.json_body() or {}
    url = (body.get("url") or "").strip()
    force = bool(body.get("force"))
    if not url:
        return req.json({"ok": False, "error": "缺少 url 参数"}, 400)
    # 1) 抓取 + 解析 + 质量分类（live.submit_article 不直接落盘，等过滤判定后再落盘）
    try:
        import live as L
        rec, info = L.submit_article(url, force=force, persist=False)
    except ValueError as e:
        return req.json({"ok": False, "error": str(e)}, 400)
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": "抓取/解析失败：" + str(e)[:200]}, 502)
    # 2) 去重：同链接若已在引擎（自动采集命中或重复提交），不重复入索引。
    #    用引擎的 find_id_by_link（内部加 _WRITE_LOCK）而非裸迭代 eng.docs：
    #    快车道每 15s 与并发提交会同时改 docs 列表，裸迭代会撞 RuntimeError。
    eng = _CORE.get_engine()
    existing = eng.find_id_by_link(url)
    if existing:
        return req.json({"ok": True, "duplicated": True, "id": existing,
                         "title": rec.get("title"),
                         "message": "该链接已被收录（可能由自动采集命中或重复提交）",
                         "info": info})
    # 3) 质量 + 近重 过滤（force=True 由调用方用于强制收录，跳过本步）
    if not force:
        q = info.get("quality") or {}
        if q.get("extremely_poor"):
            return req.json({"ok": True, "filtered": True, "filter": "quality",
                             "id": rec.get("id"), "title": rec.get("title"),
                             "reason": "文章质量极差（篇幅过短/重度广告/内容空洞），已过滤不收录",
                             "quality": q, "info": info})
        try:
            sim = eng.similarity_to_existing(rec)
        except Exception:  # noqa: BLE001
            sim = {"content_containment": 0.0, "title_sim": 0.0,
                   "similar_id": None, "similar_title": None}
        cont = sim.get("content_containment") or 0.0
        tsim = sim.get("title_sim") or 0.0
        # 过分相同：标题高度雷同 或 正文词项被已有文档大量覆盖 → 视为转载/雷同
        # （阈值可调：标题相似 0.9 / 正文包含率 0.6）
        if tsim >= 0.9 or cont >= 0.6:
            return req.json({"ok": True, "filtered": True, "filter": "duplicate",
                             "id": rec.get("id"), "title": rec.get("title"),
                             "reason": "与已有文章过分相同（疑似转载/高度雷同），已过滤不收录",
                             "similar": {"title_sim": round(tsim, 3),
                                         "content_containment": round(cont, 3),
                                         "similar_id": sim.get("similar_id"),
                                         "similar_title": sim.get("similar_title")},
                             "quality": q, "info": info})
    # 4) 过滤通过 → 落盘 data/cn + 富化 + 增量入引擎（秒级可见，不写 .idxcache）。
    #    用 eng.add_documents 而非 apply_new_docs：后者会写 .idxcache，而本记录尚未
    #    落盘进 corpus.json（仅暂存 data/cn 供离线合并），若写缓存会把"未落盘文档"
    #    指纹带进去，下次启动 .idxcache 判失效 → 全量重建索引（数分钟）。
    try:
        L.persist_submission([rec])
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:406", _sw_e)
    try:
        _CORE.enrich_all([rec])
    except Exception as _sw_e:  # noqa: BLE001 —— 富化失败不影响入库
        _swallow("modules/m1_monitor/api.py:410", _sw_e)
    eng = _CORE.get_engine()
    added = eng.add_documents([rec])
    if not added:
        # id 已在引擎（极少数：URL 去重漏判 / 并发）→ 退回全量热切换确保可见
        try:
            _CORE.reload_engine()
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/api.py:418", _sw_e)
        return req.json({"ok": True, "reloaded": True, "id": rec.get("id"),
                         "title": rec.get("title"),
                         "message": "该链接已在引擎中（可能已收录）", "info": info})
    # 5) 持久化实时流（重启由 _live_replay 回放，投稿文章不丢）+ 清检索缓存（立即可搜）
    try:
        L.append_feed([rec])
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:426", _sw_e)
    try:
        _CORE.clear_search_cache()
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:430", _sw_e)
    # 6) 同步进「实时监测」recent 条（前端指示灯/最近条目可见），与快车道同口径
    with LIVE_LOCK:
        LIVE["recent"] = [{
            "id": rec.get("id"), "title": rec.get("title", ""),
            "source": (rec.get("sources") or [""])[0],
            "category": rec.get("category", ""), "published": (rec.get("published") or "")[:10],
            "kind": rec.get("kind", ""), "ts": time.strftime("%H:%M:%S"),
            "submitted": True, "quality_tier": rec.get("quality_tier", ""),
        }] + LIVE["recent"]
        LIVE["recent"] = LIVE["recent"][:120]
        LIVE["added_total"] += 1
    return req.json({"ok": True, "id": rec.get("id"), "title": rec.get("title"),
                     "added": added,
                     "quality": {"tier": rec.get("quality_tier", ""),
                                 "score": (info.get("quality") or {}).get("score")},
                     "message": "已秒级收录并显示在最新情报（质量分级：%s）"
                                % rec.get("quality_tier", ""),
                     "info": info})


def handle_refresh_post(req):
    with REFRESH_LOCK:
        if REFRESH["running"]:
            return req.json({"started": False, "running": True,
                             "status": dict(REFRESH)}, 409)
        REFRESH.update(running=True, stage="init", detail="启动增量同步",
                       pct=0, started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       finished_at=None, error=None, summary=None)
    hours = req.q_float("hours") or None      # 旧写法 float(hours) 会把 ?hours=abc 打成 500
    skip_gh = req.qs.get("github", ["1"])[0] in ("0", "false")
    threading.Thread(
        target=_run_refresh, kwargs={"window_hours": hours, "skip_github": skip_gh},
        daemon=True, name="refresh").start()
    return req.json({"started": True, "running": True, "status": refresh_status()})


# ======================================================================
# 启动钩子：注册路由 + 拉起后台线程
# ======================================================================
def start(core):
    """主体启动完成后调用：起快车道轮询线程 + 可选定时同步"""
    global _INTERVAL, LIVE_INTERVAL
    fast_interval = int((core.args or {}).get("fast_interval") or 30)
    auto_hours = float((core.args or {}).get("auto_refresh_hours") or 0)
    auto_sec = float((core.args or {}).get("auto_refresh_sec") or 0)
    no_live = bool((core.args or {}).get("no_live"))

    _INTERVAL = fast_interval
    LIVE_INTERVAL = fast_interval
    LIVE["interval"] = fast_interval

    if not no_live:
        threading.Thread(target=_live_loop, daemon=True, name="live").start()

        # ★ 2026-10-07 启动耗时修复：原来这里**主线程同步**调 blog_feeds()，
        #   它内部要先 detect_proxy() —— 而 detect_proxy 会逐个试 PROBE_URLS
        #   探测本机所有监听端口（第一个探测目标是 google.com，国内必然超时，
        #   单次 4s × 2 个 URL）。8 线程并发扫完最坏几十秒。
        #   后果：主线程被堵住 → core/server.py 走不到 ThreadingHTTPServer
        #   → **端口永远不绑定**，表现为"双击后长时间打不开"（实测卡 >100s）。
        #   这类"和网络打交道的事"一律不能挡启动：改成后台线程做，
        #   端口先绑上，抓取结果稍后打印。
        def _fastlane_probe():
            try:
                import live as _L
                _n, _px = len(_L.blog_feeds()), _L._proxy()
                print(f"  快车道实时监测：每 {fast_interval}s 轮询 · {_n} 个博客/公告源"
                      f"{'（走代理 ' + _px + '）' if _px else '（直连；境外源抓不到就设 AISEC_PROXY）'}"
                      f" · 新信息约 {fast_interval}s 内可见", flush=True)
            except Exception:  # noqa: BLE001
                print(f"  快车道实时监测：每 {fast_interval}s 轮询"
                      f"（新信息约 {fast_interval}s 内可见）", flush=True)

        print(f"  快车道实时监测：每 {fast_interval}s 轮询"
              f"（源探测在后台进行，服务立即可用）", flush=True)
        threading.Thread(target=_fastlane_probe, daemon=True, name="fastlane").start()

    # 每日按类报告：启动后先出一份（--no-live 时没有轮询，否则今天永远没日报）。
    # 延后 8s 起，避开引擎加载高峰，别跟首轮采集抢 CPU。
    def _daily_boot():
        time.sleep(8)
        r = _daily_maybe_generate()
        if r:
            print(f"  每日按类情报报告：已生成 {r['date']}（{r['total']} 条 / "
                  f"{r['category_count']} 类，保留 {(_dr().RETENTION_DAYS)} 天）", flush=True)
        else:
            print(f"  每日按类情报报告：目录 {_dr().report_dir()}"
                  f"（保留 {_dr().RETENTION_DAYS} 天）", flush=True)

    threading.Thread(target=_daily_boot, daemon=True, name="daily-boot").start()

    def _claim(detail):
        """抢占同步锁：上一轮没跑完就跳过本轮（15s 节拍下必须防重叠）。"""
        with REFRESH_LOCK:
            if REFRESH["running"]:
                return False
            REFRESH.update(running=True, stage="init", detail=detail, pct=0,
                           started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                           finished_at=None, error=None, summary=None)
        return True

    if auto_sec > 0:
        def _quick_loop():
            time.sleep(20)                 # 先让服务起来、快车道跑一轮
            while True:
                time.sleep(auto_sec)
                if not _claim("定时轻量同步"):
                    continue
                t0 = time.time()
                _run_refresh(light=True)
                # 自适应退让：单轮实测 ~19-29s（光加载 267MB 语料就要 10s）。
                # 若间隔设得比单轮还短（比如 15s），这里自动把节拍拉长到
                # 「单轮耗时 ×1.5」，避免永远追不上、CPU/内存被持续占用。
                cost = time.time() - t0
                extra = max(0.0, cost * 1.5 - auto_sec)
                if extra:
                    time.sleep(extra)
        threading.Thread(target=_quick_loop, daemon=True, name="quick-refresh").start()
        print(f"  定时增量同步（轻量）：每 {int(auto_sec)} 秒一轮"
              f"（NVD 单关键词轮转 + KEV 缓存 + CSDN 快抓；无新增不写盘、不重建引擎）", flush=True)

    if auto_hours > 0:
        def _auto_loop():
            while True:
                time.sleep(auto_hours * 3600)
                if not _claim("定时全量同步"):
                    continue
                print(f"[auto-refresh] 周期到，开始全量增量同步（每 {auto_hours}h）", flush=True)
                _run_refresh(light=False)
        threading.Thread(target=_auto_loop, daemon=True, name="auto-refresh").start()
        print(f"  定时全量同步：每 {auto_hours} 小时一轮（arXiv 论文 / GitHub / 全关键词 NVD）"
              f"（config.json 的 auto_refresh_hours 可调，0=关闭）", flush=True)

    # ── P0-1：标准/法规知识底座 —— 启动运行期注入 + 后台低频刷新（不阻塞启动）──
    try:
        _start_standards(core)
    except Exception as _sw_e:  # noqa: BLE001 —— 标准底座是增强项，不影响主服务
        _swallow("modules/m1_monitor/api.py:start.standards", _sw_e)


def _start_standards(core):
    """标准/法规运行期注入 + 后台刷新线程（P0-1）。

    · 注入：启动后立刻把 data/standards_kb.json 的条目经 engine.add_documents 合并进索引
      （与快车道 _live_replay 同机制），**绝不写 data/corpus.json**（硬约束 C3）。
    · 刷新：后台线程，**首次延迟 ≥60s**、之后每 standards_auto_refresh_hours 小时一轮，
      不阻塞启动（对齐设计 §4.1）。
    · config.standards_enabled=false 时整体跳过（回滚开关之一）。
    """
    cfg = paths.load_config()
    if not bool(cfg.get("standards_enabled", True)):
        print("  标准/法规知识底座：standards_enabled=false，已跳过注入与刷新", flush=True)
        return
    try:
        hrs = float(str(cfg.get("standards_auto_refresh_hours", 24)).strip())
    except (TypeError, ValueError):
        hrs = 24.0
    try:
        SKB = _standards_kb()
        eng = core.get_engine()
        n = SKB.inject(eng, clear_cache=core.clear_search_cache)
        print(f"  标准/法规知识底座：运行期注入 {n} 条（{SKB.STD_FILE}；未写 corpus.json）",
              flush=True)
    except Exception as e:  # noqa: BLE001
        _swallow("modules/m1_monitor/api.py:_start_standards.inject", e)
        print("  标准/法规知识底座：注入失败（不影响主服务）", flush=True)

    if hrs <= 0:
        return

    def _loop():
        time.sleep(max(60, 60))          # 首次延迟 ≥60s：避开启动高峰、不与首轮采集抢资源
        while True:
            try:
                SKB = _standards_kb()
                SKB.refresh()
                SKB.inject(core.get_engine(), clear_cache=core.clear_search_cache)
            except Exception as _e:  # noqa: BLE001
                _swallow("modules/m1_monitor/api.py:_start_standards.loop", _e)
            time.sleep(max(3600.0, hrs * 3600.0))

    threading.Thread(target=_loop, daemon=True, name="standards-refresh").start()
    print(f"  标准/法规采集：每 {int(hrs)} 小时一轮增量比对（后台低频，首次延迟 ≥60s）",
          flush=True)


def register(ctx):
    global _CORE
    _CORE = ctx.core
    ctx.route("GET", "/api/live", handle_live)
    ctx.route("GET", "/api/sources", handle_sources)
    ctx.route("GET", "/api/refresh", handle_refresh_get)
    ctx.route("POST", "/api/refresh", handle_refresh_post)
    ctx.route("POST", "/api/m1/submit_article", handle_submit_article)
    ctx.route("GET", "/api/daily_reports", handle_daily_reports)
    ctx.route("GET", "/api/daily_report", handle_daily_report)
    ctx.route("POST", "/api/daily_report/generate", handle_daily_generate)
    ctx.route("POST", "/api/daily_report/cleanup", handle_daily_cleanup)
    # 高频漏洞周期统计（周/月/年，图表 + 报告）
    ctx.route("GET", "/api/trend_stats", handle_trend_stats)
    # —— P0-3 源健康与缺失告警 ——
    ctx.route("GET", "/api/source_health", handle_source_health)
    ctx.route("GET", "/api/coverage_gaps", handle_coverage_gaps)
    # —— P0-1 标准/法规知识底座 ——
    ctx.route("GET", "/api/standards", handle_standards)
    ctx.route("POST", "/api/standards/refresh", handle_standards_refresh)
    ctx.on_start(start)


def handle_trend_stats(req):
    """GET /api/trend_stats?period=weekly|monthly|yearly[&md=1]

    高频漏洞周期统计：返回聚合数据（供前端图表）；md=1 直接下载 Markdown 报告。
    """
    import trend_stats as TS
    period = (req.q("period") or "weekly").strip().lower()
    if period not in ("weekly", "monthly", "yearly"):
        return req.json({"error": "period 只支持 weekly / monthly / yearly"}, 400)
    try:
        data = TS.aggregate(period)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        return req.json({"error": "周期统计失败：%s" % str(e)[:200]}, 500)
    if data.get("error"):
        return req.json(data, 400)
    if req.q("md") not in ("", "0", "false"):
        md = TS.report_markdown(data)
        fname = "高频漏洞%s_%s_%s.md" % (TS._PERIOD_LABEL[period], data["start"], data["end"])
        return req.send(200, md.encode("utf-8"), "text/markdown; charset=utf-8",
                        filename=fname, cache="no-store")
    return req.json(data)
