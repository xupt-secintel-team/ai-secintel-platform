# -*- coding: utf-8 -*-
"""
评测时效性.py —— 「漏洞情报从发布到被系统采集」的端到端延迟实测
================================================================
评分细则·性能指标 1：监测时效性（延迟 ≤24h 合格 / ≤12h 良好 / ≤6h 优秀）。

此前系统只有"机制证据"（快车道 15s 轮询、NVD 2h 时间窗），没有测量证据。
本脚本给出三组可复跑的**测量**证据：

  A. 轮询节拍实测：解析 data/live_seen.json 的 meta 历史（每次轮询都记录
     last_poll 与 per_source 新增数），统计真实轮询间隔分布 —— 回答
     「15s 节拍在实际运行中是否兑现」。

  B. 受控采集延迟实测（--watch N）：在实时监测开启的服务上，每 15s 抓取
     /api/live 快照；对新出现的条目，记录本机首次观测时间，与条目自带的
     发布时间（源站 RSS/公告时间戳）对比，得到「源站发布 → 系统可见」的
     真实延迟样本。同时对该条目立即请求 /api/search，测量
     「可见 → 可检索」的管道内延迟（热切换是否即时生效）。

  C. 机制上界：由配置推导出最坏情况延迟上界（快车道间隔 + NVD 时间窗），
     与实测对照。

用法：
  py -3 tools/评测时效性.py                      # 只做 A + C（离线，秒出）
  py -3 tools/评测时效性.py --watch 20 --base http://127.0.0.1:8848
                                                    # A+B+C：观测 20 分钟
  py -3 tools/评测时效性.py --report-only        # 用已有观测 JSON 重出报告

输出：测试报告/时效性实测.md + 测试报告/时效性实测.json
"""
import argparse
import datetime as dt
import json
import os
import re
import statistics
import sys
import time
import urllib.request
from email.utils import parsedate_to_datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 目标服务：逐级回落 AISEC_EVAL_BASE → AISEC_MAIN_SERVER → 8848（服务真实默认端口）。
# 原来 argparse 里写死 8899，那个端口上通常什么都没有 → 评测全线 502。
BASE = (os.environ.get("AISEC_EVAL_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")
# 本机回环请求强制不走系统代理：设过 HTTP_PROXY 的机器上，
# 打 127.0.0.1 会被发给代理 → 502，症状像"服务坏了"。
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

DATA = paths.DATA_DIR
REPORT_DIR = os.path.join(ROOT, "测试报告")
OBS_FP = os.path.join(REPORT_DIR, "时效性实测.json")
MD_FP = os.path.join(REPORT_DIR, "时效性实测.md")


def log(*a):
    print("[时效]", *a, flush=True)


# ── A. 轮询节拍实测 ─────────────────────────────────────────────
def measure_poll_cadence():
    fp = os.path.join(DATA, "live_seen.json")
    if not os.path.isfile(fp):
        return None
    with open(fp, encoding="utf-8") as f:
        seen = json.load(f)
    metas = []
    def walk(obj):
        if isinstance(obj, dict):
            if "last_poll" in obj and "per_source" in obj:
                metas.append(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
    walk(seen)
    if len(metas) < 3:
        return None
    ts = []
    for m in metas:
        try:
            ts.append(dt.datetime.fromisoformat(m["last_poll"]))
        except Exception as _sw_e:
            _swallow("tools/评测时效性.py:81", _sw_e)
    ts = sorted(set(ts))
    intervals = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
    intervals = [x for x in intervals if 1 <= x <= 7200]  # 排除跨天停机造成的巨间隔
    if not intervals:
        return None
    polls_with_news = sum(1 for m in metas if any((m.get("per_source") or {}).values()))
    return {
        "样本轮次数": len(metas),
        "有效间隔数": len(intervals),
        "中位间隔s": round(statistics.median(intervals), 1),
        "均值间隔s": round(statistics.mean(intervals), 1),
        "P95间隔s": round(sorted(intervals)[int(len(intervals) * 0.95) - 1], 1),
        "≤120s占比": round(sum(1 for x in intervals if x <= 120) / len(intervals) * 100, 1),
        "有新增的轮次": polls_with_news,
    }


# ── B0. 直测：fetched_at 采集时间戳（v2.2 起 live.py 入库即打戳）──────────
_DATE_ONLY_RE = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}$")


def _parse_published_mid(s):
    """只给到**日期**的时间戳按当天 12:00 取中点。

    为什么：博客 RSS 普遍只给 YYYY-MM-DD，真实发布时刻落在当天 00:00~23:59。
    按 00:00 算会把延迟**系统性多算最多 24 小时** —— 实测里那些"17~18h 延迟"
    多数就是这个口径误差造成的，而不是系统真的慢了 18 小时。取中点后误差 ±12h。
    """
    s0 = str(s or "").strip()
    if _DATE_ONLY_RE.match(s0):
        base = _parse_published(s0)
        return (base + 43200) if base else None      # +12h
    return _parse_published(s0)


def measure_direct():
    """live_feed.jsonl 中带 fetched_at 的条目：延迟 = fetched_at − published。

    两条口径上的修正（2026-10-06）：

    ① **稳态 vs 补采**。某个源的第一批记录，是系统首次接入时把对方 RSS 现有
       列表整体抓下来的，里面混着几周前的旧文（实测最大 42048h ≈ 4.8 年，
       那是源站归档文章，不是"采集慢"）。只有**发布时间晚于该源首次采集时间**
       的条目才反映系统真实采集能力。两者必须分开报，混在一起会得出
       "≤6h 占比 0%" 这种既不真实也无意义的结论。
    ② **日期精度取中点**，见 _parse_published_mid。
    """
    fp = os.path.join(DATA, "live_feed.jsonl")
    rows = []
    if not os.path.isfile(fp):
        return rows
    with open(fp, encoding="utf-8") as f:
        for line in f:
            try:
                d = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            fa = d.get("fetched_at")
            if not fa:
                continue
            # 2026-10-06：采集侧新增 published_at（保留源站真实时刻）。
            # 优先用它 —— published 只到日期，取中点会有 ±12h 误差，
            # 比中位延迟本身还大，压根没法判「≤3h」。
            pub_at_raw = str(d.get("published_at") or "").strip()
            pub_raw = str(d.get("published") or "")
            if len(pub_at_raw) >= 19:
                pub = _parse_published(pub_at_raw[:19])
                prec = "sec"
            else:
                pub = _parse_published_mid(pub_raw)
                prec = "date" if _DATE_ONLY_RE.match(pub_raw.strip()) else "sec"
            try:
                fa_ts = dt.datetime.fromisoformat(fa).timestamp()
            except Exception:  # noqa: BLE001
                continue
            rows.append({
                "id": d.get("id", "")[:60], "kind": d.get("kind") or "",
                "published_raw": (pub_at_raw or pub_raw)[:30],
                "published_precision": prec,
                "采集延迟s": round(fa_ts - pub, 1) if pub else None,
                "fetched_ts": fa_ts, "published_ts": pub,
            })
    # 每个源的首次采集时刻 → 用来判定该条目是稳态采集还是接入补采
    first_by_kind = {}
    for r in rows:
        k = r["kind"] or "?"
        ff = r["fetched_ts"]
        if k not in first_by_kind or ff < first_by_kind[k]:
            first_by_kind[k] = ff
    for r in rows:
        ff = first_by_kind.get(r["kind"] or "?")
        pt = r["published_ts"]
        r["mode"] = "steady" if (ff and pt and pt >= ff) else "backfill"
    return rows


def measure_ops_briefs():
    """处置时效：m0_ops 编排链「事件披露 → 简报生成」的实测（ops_briefs.json）。"""
    fp = os.path.join(DATA, "ops_briefs.json")
    out = []
    if not os.path.isfile(fp):
        return out
    try:
        with open(fp, encoding="utf-8") as f:
            for rec in json.load(f):
                ev = rec.get("event") or {}
                pub = _parse_published(ev.get("published"))
                try:
                    ts = dt.datetime.fromisoformat(rec.get("ts", "")).timestamp()
                except Exception:  # noqa: BLE001
                    continue
                out.append({"id": ev.get("id", ""), "kev": bool(ev.get("kev")),
                            "处置延迟s": round(ts - pub, 1) if pub else None,
                            "brief_mode": rec.get("brief_mode")})
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("tools/评测时效性.py:146", _sw_e)
    return out



def _get(base, path, timeout=30):
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=timeout) as r:
        return json.load(r)


def _parse_published(s):
    if not s:
        return None
    s = str(s).strip()
    try:
        d = parsedate_to_datetime(s)  # RFC822 (RSS)
        return d.timestamp()
    except Exception as _sw_e:
        _swallow("tools/评测时效性.py:164", _sw_e)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s[:26], fmt).timestamp()
        except Exception as _sw_e:
            _swallow("tools/评测时效性.py:169", _sw_e)
    m = re.search(r"(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})", s)
    if m:
        try:
            return dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).timestamp()
        except Exception as _sw_e:
            _swallow("tools/评测时效性.py:175", _sw_e)
    return None


def watch_session(base, minutes):
    """每 15s 抓 /api/live，记录新条目的首次观测时间，并测管道内可检索延迟。"""
    log(f"开始受控观测 {minutes} 分钟（每 15s 一次快照）→ {base}")
    known = set()
    samples = []
    t_end = time.time() + minutes * 60
    first = True
    while time.time() < t_end:
        try:
            d = _get(base, "/api/live", timeout=30)
        except Exception as e:
            log("快照失败（跳过本轮）:", e)
            time.sleep(15)
            continue
        items = d.get("recent") or d.get("items") or d.get("feed") or d.get("results") or []
        now = time.time()
        for it in items:
            iid = it.get("id")
            if not iid or iid in known:
                continue
            known.add(iid)
            if first:
                continue  # 首轮只建立基线，不计样本（无法区分"新到"与"存量"）
            pub = _parse_published(it.get("published"))
            # 管道内延迟：该条目从"在 /api/live 可见"到"可被搜索命中"
            t0 = time.time()
            searchable = None
            for _ in range(8):  # 最多等 40s
                try:
                    q = urllib.parse.quote(iid)
                    sd = _get(base, f"/api/search?q={q}&size=5", timeout=20)
                    hits = sd.get("results") or sd.get("items") or []
                    if any(h.get("id") == iid for h in hits):
                        searchable = time.time() - t0
                        break
                except Exception as _sw_e:
                    _swallow("tools/评测时效性.py:215", _sw_e)
                time.sleep(5)
            samples.append({
                "id": iid,
                "kind": it.get("kind") or it.get("source") or "",
                "published_raw": str(it.get("published"))[:40],
                "published_ts": pub,
                "first_seen_ts": now,
                "采集延迟s": round(now - pub, 1) if pub else None,
                "可检索延迟s": round(searchable, 2) if searchable is not None else None,
            })
            log(f"新条目 {iid[:60]} 延迟={samples[-1]['采集延迟s']}s 可检索={samples[-1]['可检索延迟s']}s")
        first = False
        time.sleep(15)
    return samples


# ── C. 机制上界 ─────────────────────────────────────────────────
def mechanism_bound():
    cfg_fp = os.path.join(ROOT, "config.json")
    fast = 15
    try:
        with open(cfg_fp, encoding="utf-8") as f:
            cfg = json.load(f)
        fast = cfg.get("fast_interval", 15)
    except Exception as _sw_e:
        _swallow("tools/评测时效性.py:241", _sw_e)
    return {
        "快车道轮询间隔s": fast,
        "NVD回看窗口h": 2,
        "上界说明": "KEV/RSS 类快源最坏 ≈ 一个轮询周期；NVD 新 CVE 最坏 ≈ 轮询周期（2h 重叠窗口兜底边界丢失）；源站自身发布滞后不计入系统延迟",
    }


def fmt_h(seconds):
    if seconds is None:
        return "—"
    return f"{seconds/3600:.2f}h" if seconds >= 3600 else f"{seconds/60:.1f}min" if seconds >= 60 else f"{seconds:.0f}s"


def render(cadence, samples, bound, watch_minutes, direct=None, briefs=None):
    direct = direct or []
    briefs = briefs or []
    L = []
    L.append("# 时效性实测 —— 漏洞情报「发布 → 系统采集」端到端延迟\n")
    L.append(f"- 实测时间：{dt.datetime.now():%Y-%m-%d %H:%M}")
    L.append("- 工具：`tools/评测时效性.py`（可复跑；`--watch N` 为受控观测时长，分钟）")
    L.append("- 判据：延迟只认**测量值**，机制参数只作对照，不以机制代替测量\n")

    L.append("\n## 一、直测：采集时间戳（live.py v2.2 起入库即打 `fetched_at`）\n")

    def _stats(tag, rows):
        """给一组样本出延迟分位表；返回是否出数。"""
        vals = sorted(s["采集延迟s"] for s in rows
                      if s.get("采集延迟s") is not None and s["采集延迟s"] >= 0)
        if not vals:
            L.append(f"\n### {tag}\n\n（该口径下暂无有效样本）\n")
            return False
        L.append(f"\n### {tag}\n")
        L.append("| 指标 | 实测 |")
        L.append("|---|---|")
        L.append(f"| 有效样本数 | {len(vals)} |")
        L.append(f"| 中位延迟 | {fmt_h(statistics.median(vals))} |")
        L.append(f"| 平均延迟 | {fmt_h(statistics.mean(vals))} |")
        L.append(f"| P95 延迟 | {fmt_h(vals[min(len(vals) - 1, int(len(vals) * 0.95))])} |")
        L.append(f"| 最大延迟 | {fmt_h(vals[-1])} |")
        L.append(f"| **≤3h 占比（达标线）** | **{sum(1 for x in vals if x <= 10800) / len(vals) * 100:.1f}%** |")
        L.append(f"| ≤6h 占比（优秀线） | {sum(1 for x in vals if x <= 21600) / len(vals) * 100:.1f}% |")
        return True

    timed_d = [s for s in direct if s.get("采集延迟s") is not None and s["采集延迟s"] >= 0]
    steady = [s for s in timed_d if s.get("mode") == "steady"]
    backfill = [s for s in timed_d if s.get("mode") != "steady"]

    if not timed_d:
        L.append("（尚无带 `fetched_at` 的条目——该字段从 v2.2 开始打点，"
                 "实时监测运行后自动累积；可用 `--watch` 受控观测或历史轮询重构补充）")
    else:
        n_date = sum(1 for s in timed_d if s.get("published_precision") == "date")
        n_sec = len(timed_d) - n_date
        L.append(f"共 {len(direct)} 条带采集时间戳的记录，其中 {len(timed_d)} 条延迟为正"
                 f"（秒级时刻 {n_sec} 条 / 仅日期 {n_date} 条）。")
        L.append("\n> **口径说明**")
        L.append("> 1. **接入补采 ≠ 采集慢**。某个源的第一批记录是系统首次接入时把对方 RSS "
                 "现有列表整体抓下来的历史文章（含源站归档内容，最大可到数年前），"
                 "那是「接入之前就发布了」，故单列不计入达标线。")
        L.append("> 2. **精度分层**。`published_at` 字段（2026-10-06 上线）保留源站真实时刻，"
                 "延迟为精确值；上线之前入库的历史记录只有日期，延迟按当天 12:00 取中点，"
                 "误差 ±12h —— 该误差大于中位延迟本身，故这两类必须分开看。")
        _stats("① 稳态采集 · 秒级时刻（发布时间晚于本系统首次抓到该源 → 真实采集延迟，可直接对达标线）",
               [s for s in steady if s.get("published_precision") != "date"])
        _stats("② 稳态采集 · 仅日期（中点估计，误差 ±12h，仅供参考）",
               [s for s in steady if s.get("published_precision") == "date"])
        _stats("③ 稳态采集 · 合计", steady)
        _stats("④ 接入补采（系统接入前源站就已发布 → 仅作留痕，不计入达标线）", backfill)

        # ★ 2026-10-08 实测补 —— 双口径差异的**成因分解**：
        #   口径①（秒级）与口径②（仅日期）的样本**来源构成完全不同**，直接并列
        #   会得出「差 20 倍」的困惑结论，答辩被追问时无法自证。实测：口径② 有
        #   92% 是 arXiv 论文（高频源、天天更新、抓得勤，中位 1.4h），口径① 则
        #   几乎全是安全博客（低频源、更新间隔以天计，中位 30h）。按来源类型拆开
        #   列，「延迟到底多少」才有一个经得起追问的答案。
        def _srckind(s):
            _k = str(s.get("kind") or "")
            if "论文" in _k or str(s.get("id") or "").startswith("ARXIV:"):
                return "学术论文（arXiv）"
            if "博客" in _k:
                return "安全博客"
            return "其他来源"

        L.append("\n### 双口径差异的成因分解（按来源类型 × 精度分层）\n")
        L.append("> 两个口径的**样本来源构成完全不同**，不是系统在两种口径下表现不同：")
        L.append("> 「仅日期」样本绝大多数是 arXiv 论文（高频源），「秒级」样本几乎全是安全博客（低频源）。")
        L.append("> 因此单看任何一个中位数都会误导 —— 引用时必须声明它代表哪一类源。\n")
        L.append("| 来源类型 | 精度口径 | 样本数 | 中位延迟 | ≤3h 占比 |")
        L.append("|---|---|---:|---:|---:|")
        for _kind in ("学术论文（arXiv）", "安全博客", "其他来源"):
            for _ptag, _psel in (("秒级", lambda s: s.get("published_precision") != "date"),
                                 ("仅日期", lambda s: s.get("published_precision") == "date")):
                _sub = [s["采集延迟s"] for s in steady
                        if _srckind(s) == _kind and _psel(s)
                        and s.get("采集延迟s") is not None]
                if not _sub:
                    continue
                _sub.sort()
                L.append(f"| {_kind} | {_ptag} | {len(_sub)} "
                         f"| {fmt_h(statistics.median(_sub))} "
                         f"| {sum(1 for x in _sub if x <= 10800) / len(_sub) * 100:.1f}% |")

    if timed_d:
        L.append("\n### 逐条样本（按采集时间倒序，最近 20 条）\n")
        L.append("| 条目 | 来源 | 发布时间 | 精度 | 口径 | 采集延迟 |")
        L.append("|---|---|---|---|---|---|")
        for s in direct[-20:]:
            L.append(f"| {s['id'][:48]} | {s['kind'][:14]} | {s['published_raw'][:16]} "
                     f"| {'日期' if s.get('published_precision') == 'date' else '秒级'} "
                     f"| {'稳态' if s.get('mode') == 'steady' else '补采'} "
                     f"| {fmt_h(s['采集延迟s']) if s['采集延迟s'] is not None else '—'} |")

    L.append("\n## 二、处置时效（m0_ops 编排链「事件披露 → 简报生成」）\n")
    timed_b = [b for b in briefs if b.get("处置延迟s") is not None]
    if timed_b:
        L.append("| 事件 | KEV | 处置延迟 | 简报模式 |")
        L.append("|---|---|---|---|")
        for b in timed_b:
            L.append(f"| {b['id']} | {'是' if b['kev'] else '否'} "
                     f"| {fmt_h(b['处置延迟s'])} | {b['brief_mode']} |")
        L.append(f"\n> 处置延迟 = 简报落盘时间 − 事件披露时间；编排节拍（默认 60s）是其主要构成。")
    else:
        L.append("（尚无编排简报——m0_ops 运行后自动产生）")

    L.append("\n## 三、轮询节拍实测（data/live_seen.json 历史轮询记录）\n")
    if cadence:
        L.append("| 指标 | 实测 |")
        L.append("|---|---|")
        for k, v in cadence.items():
            L.append(f"| {k} | {v} |")
        L.append("\n> 说明：间隔含单轮抓取耗时（46 源串行抓取一轮约 60~90s），"
                 "故实际节拍 = 抓取耗时 + 配置的 15s 休眠；≤120s 占比反映节拍稳定性。")
    else:
        L.append("（无足够历史轮询记录）")

    L.append(f"\n## 四、受控采集延迟观测（观测 {watch_minutes} 分钟，服务实时监测开启）\n")
    timed = [s for s in samples if s.get("采集延迟s") is not None and s["采集延迟s"] >= 0]
    skew = [s for s in samples if s.get("采集延迟s") is not None and s["采集延迟s"] < 0]
    if timed:
        lat = sorted(s["采集延迟s"] for s in timed)
        L.append("| 指标 | 实测 |")
        L.append("|---|---|")
        L.append(f"| 有效样本数 | {len(timed)} |")
        L.append(f"| 最小延迟 | {fmt_h(lat[0])} |")
        L.append(f"| 中位延迟 | {fmt_h(statistics.median(lat))} |")
        L.append(f"| 平均延迟 | {fmt_h(statistics.mean(lat))} |")
        L.append(f"| P95 延迟 | {fmt_h(lat[int(len(lat)*0.95)-1])} |")
        L.append(f"| 最大延迟 | {fmt_h(lat[-1])} |")
        L.append(f"| ≤6h 占比（优秀线） | {sum(1 for x in lat if x <= 21600)/len(lat)*100:.0f}% |")
        L.append(f"| ≤12h 占比（良好线） | {sum(1 for x in lat if x <= 43200)/len(lat)*100:.0f}% |")
        L.append(f"| ≤24h 占比（合格线） | {sum(1 for x in lat if x <= 86400)/len(lat)*100:.0f}% |")
        L.append("\n逐条样本：\n")
        L.append("| 条目 | 来源 | 发布时间 | 采集延迟 | 入库→可检索 |")
        L.append("|---|---|---|---|---|")
        for s in samples:
            L.append(f"| {s['id'][:52]} | {s['kind'][:18]} | {s['published_raw'][:22]} "
                     f"| {fmt_h(s['采集延迟s']) if s['采集延迟s'] is not None else '—'} "
                     f"| {fmt_h(s['可检索延迟s']) if s['可检索延迟s'] is not None else '—'} |")
    else:
        L.append("（观测窗口内无新条目入库——延长 `--watch` 分钟数复跑即可累积样本）")
    if skew:
        L.append(f"\n> 注：{len(skew)} 条样本源站时间戳晚于本机观测时间（源站时区/未来日期标注问题），"
                 "已从延迟统计中剔除并单独列出，不倒灌进分位数。")

    L.append("\n## 五、机制上界（对照，不计入测量）\n")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    L.append(f"| 快车道轮询间隔 | {bound['快车道轮询间隔s']}s |")
    L.append(f"| NVD 回看窗口 | {bound['NVD回看窗口h']}h（重叠覆盖防边界丢失） |")
    L.append(f"| 说明 | {bound['上界说明']} |")

    L.append("\n## 六、口径与局限\n")
    L.append("- 「采集延迟」= 本机首次在 `/api/live` 观测到条目的时间 − 条目自带发布时间；"
             "源站 RSS 时间戳本身的滞后（先上网页后上 feed）属于源站侧，不归系统。")
    L.append("- 「入库→可检索」测的是热切换即时性：新条目进入 `/api/live` 后多久能被 `/api/search` 命中。")
    L.append("- 样本随观测窗口累积：每次 `--watch` 运行把新样本并入 `测试报告/时效性实测.json`，"
             "报告用全量累积样本出数，窗口越长分位数越稳。")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", type=int, default=0, help="受控观测时长（分钟），0=不观测")
    # 默认取 BASE（已按 AISEC_EVAL_BASE / AISEC_MAIN_SERVER / 8848 逐级回落）
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--report-only", action="store_true")
    args = ap.parse_args()

    os.makedirs(REPORT_DIR, exist_ok=True)
    old = {"samples": []}
    if os.path.isfile(OBS_FP):
        try:
            with open(OBS_FP, encoding="utf-8") as f:
                old = json.load(f)
        except Exception as _sw_e:
            _swallow("tools/评测时效性.py:367", _sw_e)

    new_samples = []
    if args.watch > 0 and not args.report_only:
        import urllib.parse  # noqa: F401  (watch_session 内使用)
        new_samples = watch_session(args.base, args.watch)

    seen_ids = {s["id"] for s in old.get("samples", [])}
    samples = old.get("samples", []) + [s for s in new_samples if s["id"] not in seen_ids]
    cadence = measure_poll_cadence()
    bound = mechanism_bound()
    direct = measure_direct()
    briefs = measure_ops_briefs()

    with open(OBS_FP, "w", encoding="utf-8") as f:
        json.dump({"samples": samples, "cadence": cadence, "bound": bound,
                   "direct": direct, "ops_briefs": briefs,
                   "updated": dt.datetime.now().isoformat()}, f, ensure_ascii=False, indent=1)
    md = render(cadence, samples, bound, args.watch, direct, briefs)
    with open(MD_FP, "w", encoding="utf-8") as f:
        f.write(md)
    log(f"报告已写出：{MD_FP}（样本 {len(samples)} 条）")


if __name__ == "__main__":
    import urllib.parse  # noqa: F401
    main()
