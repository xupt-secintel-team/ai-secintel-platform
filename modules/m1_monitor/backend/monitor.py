# -*- coding: utf-8 -*-
"""
monitor.py —— 情报实时监测与增量更新（赛题「情报监测」模块）
====================================================================
对 data/corpus.json 做不停机的增量同步，覆盖 8 个数据源：

  · NVD        —— lastModStartDate 时间窗增量（新披露 + 有更新的 CVE）
  · CISA KEV   —— 全量重取（小文件），新在野利用条目标记并回捞
  · arXiv      —— 精选方向按提交时间取最新（去重后并入论文池）
  · GitHub     —— Advisory / 工具仓库 重查（配额不足自动跳过）
                  仓库 stars/描述原地更新，新仓库/新公告并入知识底座
  · CSDN       —— 中文文章重查（翻两页扩覆盖），按文章 ID 增量、阅读数原地更新

合并策略：
  · 新 CVE → 走与全量一致的富化流水线（classify → 组件推断 → ATLAS 映射
    → 论文关联 → 修复建议）
  · 已有 CVE 若在时间窗内被 NVD 更新 → 刷新核心字段（CVSS/CWE/引用/POC），
    保留已有富化结果
  · 全程按 ID/URL 去重，结果原子写回（临时文件 + os.replace），失败不落盘

状态文件：data/monitor_state.json（上次同步时间 / 各源新增计数历史）
可独立运行（python monitor.py），也可被 server.py 作为后台任务调用。
"""

import json
import os
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fetch_corpus as F      # noqa: E402
import papers as P            # noqa: E402
import extra_sources as X     # noqa: E402
from atlas import AtlasKB     # noqa: E402
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = paths.data_path("corpus.json")
STATE = paths.data_path("monitor_state.json")
PAPER_CACHE = paths.data_path("papers.json")

# 刷新时抓取的论文方向（精选，arXiv 按提交时间倒序，天然取到最新）
REFRESH_PAPER_QUERIES = [
    'all:"prompt injection"',
    'all:"LLM agent" AND all:"security"',
    'all:"jailbreak" AND all:"language model"',
    'all:"model context protocol" AND all:"security"',
    'all:"retrieval augmented generation" AND all:"attack"',
    'all:"large language model" AND all:"vulnerability"',
]

# CSDN 刷新时的翻页深度（默认只抓第 1 页，刷新抓 2 页扩覆盖）
CSDN_PAGES = 2
GH_MIN_QUOTA = 36      # GitHub 匿名配额低于该值时本轮跳过（60/h）


def _utc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def now_local_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# 状态
# --------------------------------------------------------------------------
def load_state():
    st = {"last_sync": None, "window_hours": 120, "history": []}
    if os.path.isfile(STATE):
        try:
            with open(STATE, "r", encoding="utf-8") as f:
                st.update(json.load(f))
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/monitor.py:85", _sw_e)
    return st


def save_state(st):
    """原子写：进程被强杀时不会留下半截 JSON（window_hours / NVD 轮转游标会丢）。"""
    try:
        tmp = STATE + ".tmp"
        # 紧凑写（与 corpus 一致）：history[*].summary.new_docs 是完整文档对象，
        # indent=1 会让 15MB+ 的状态文件平白多出 30%~40% 的空白，拖慢每个
        # json.load 读者（load_state / _read_intake / _peek_last_sync / qa coverage）。
        # 状态文件由机器消费，不需要人类可读。
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, STATE)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/monitor.py:97", _sw_e)


# --------------------------------------------------------------------------
# 各源增量
# --------------------------------------------------------------------------
def fetch_nvd_window(keyword, start_iso, end_iso, limit=500, tries=5, timeout=None,
                     start_index=0):
    """NVD 增量：keyword + lastMod 时间窗（新披露或有更新的 CVE）。
    keyword 为空则表示不限关键词（整窗拉取，再本地做关键词过滤）。

    tries / timeout 可按调用场景收紧：全量同步用默认的 5 次重试 + 长超时（退避
    8/16/24/32/40s，容忍 NVD 匿名限速）；30s 节拍的实时快车道则传 tries=1、
    较短超时——被限速时本轮直接跳过，下一轮再试，绝不让单个源拖垮整轮节拍。

    start_index：NVD 2.0 分页游标（resultsPerPage 上限 2000），整窗拉取时用。"""
    kw = f"&keywordSearch={urllib.parse.quote(keyword)}" if keyword else ""
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?lastModStartDate={urllib.parse.quote(start_iso, safe='')}"
           f"&lastModEndDate={urllib.parse.quote(end_iso, safe='')}"
           f"{kw}"
           f"&resultsPerPage={limit}&startIndex={int(start_index)}&noRejected=")
    # 增量窗口突发查询多，NVD 匿名限速严格 → 默认更多重试次数（退避 8/16/24/32/40s）
    return json.loads(F.http_get(url, tries=tries, timeout=timeout).decode("utf-8"))


def _fetch_nvd_window_all(start_iso, end_iso, tries=3, timeout=20):
    """整窗拉取时间窗内**全部** CVE（无 keyword），返回 {cid: cve} 映射。

    为什么这样改（2026-10-18）：原来全量同步把 107 个关键词逐个发给 NVD，
    每个还受匿名限速 5req/30s（NVD_SLEEP=6.5s）——107 × 6.5s ≈ 12 分钟起步，
    无代理时每个关键词 45s 超时 × 5 次重试就是小时级。改为「整窗 1~2 次请求
    拉回全部 + 本地关键词过滤」后，无论有没有代理都秒级完成。
    分页上限 10 页（2 万条）防御性封顶，正常 5~7 天窗口远到不了。"""
    out = {}
    idx = 0
    for _ in range(10):
        d = fetch_nvd_window("", start_iso, end_iso, limit=2000,
                             tries=tries, timeout=timeout, start_index=idx)
        vs = d.get("vulnerabilities", [])
        for v in vs:
            c = v.get("cve", {})
            cid = (c.get("id") or "").upper()
            if cid:
                out[cid] = c
        total = int(d.get("totalResults") or 0)
        idx += len(vs)
        if idx >= total or not vs:
            break
    return out


def _nvd_haystack(c):
    """CVE 的本地可检索文本（英文描述 + 弱点描述 + 受影响 CPE 串），供关键词过滤。"""
    parts = []
    for d in c.get("descriptions", []):
        if isinstance(d, dict) and d.get("lang") in (None, "", "en"):
            parts.append(d.get("value") or "")
    for w in c.get("weaknesses", []):
        for wd in (w or {}).get("description", []):
            if isinstance(wd, dict):
                parts.append(wd.get("value") or "")
    for conf in c.get("configurations", []):
        for node in (conf or {}).get("nodes", []):
            for cpe in (node or {}).get("cpeMatch", []):
                parts.append((cpe or {}).get("criteria") or "")
    return " ".join(parts).lower()


def _nvd_matches(c, keywords):
    """本地关键词过滤：与 NVD keywordSearch 近似（大小写不敏感子串匹配）。
    无正文可匹配时「宁收勿漏」返回 True。keywords 需已是小写（见 _NVD_KW_LOWER）。"""
    hay = _nvd_haystack(c)
    if not hay:
        return True
    return any(k in hay for k in keywords)


# 预小写一次：整窗拉回后要逐条 CVE × 107 关键词做子串匹配，
# 每次现算 list(F.NVD_QUERIES) + k.lower() 会白做几十万次小写，无谓消耗。
_NVD_KW_LOWER = [k.lower() for k in F.NVD_QUERIES]


def gh_quota():
    """GitHub 匿名 API 剩余配额（rate_limit 端点不计入配额）"""
    try:
        d = X.get_json("https://api.github.com/rate_limit", tries=1)
        return (d.get("resources", {}).get("core", {}) or {}).get("remaining", 0)
    except Exception:  # noqa: BLE001
        return 0


def _collect_csdn_pages():
    """CSDN：固定检索词 × 翻 2 页（比 extra_sources 多一页覆盖）"""
    queries = [(q, p) for q in X.CSDN_QUERIES for p in range(1, CSDN_PAGES + 1)]
    out = []

    def _one(args):
        q, page = args
        url = ("https://so.csdn.net/api/v3/search?q=" + urllib.parse.quote(q) +
               f"&t=blog&p={page}")
        try:
            d = X.get_json(url, tries=2)
            return d.get("result_vos") or []
        except Exception:  # noqa: BLE001
            return []

    for chunk in range(0, len(queries), 6):
        for items in X.par_map(_one, queries[chunk:chunk + 6], workers=4, desc="CSDN"):
            out.extend(items)
    return out


def _csdn_items_to_records(items):
    """与 extra_sources.collect_csdn 相同的质量门控，但不按阅读数截断"""
    seen, out = set(), []
    for it in items:
        if (it.get("type") or "") != "blog":
            continue
        url = (it.get("url") or "").split("?")[0]
        title = X._clean(it.get("title"))
        desc = X._clean(it.get("description") or it.get("digest"))
        if not title or not url or url in seen:
            continue
        blob = title + " " + desc
        if not X.CSDN_GATE.search(blob) or X.CSDN_BAD_TITLE.search(title):
            continue
        if len(desc) < 60:
            continue
        created = X._clean(str(it.get("created_at") or ""))[:10] or "2024-01-01"
        if created < "2023-01-01":
            continue
        seen.add(url)
        aid = it.get("articleid") or str(abs(hash(url)))
        rec = X._skeleton(
            rid="CSDN:" + str(aid), rtype="article", kind="CSDN 社区文章",
            title=title, desc=title + "。" + desc, published=created,
            sources=["CSDN"], category=X._guess_category(blob),
            reason="中文社区技术文章（CSDN 检索 + AI 安全关键词门控通过）",
            tags=["社区文章"],
        )
        rec["author"] = X._clean(it.get("nickname") or it.get("username") or "")
        rec["views"] = X._to_int(it.get("view") if it.get("view") is not None
                                 else it.get("view_num"))
        rec["article_url"] = url
        rec["advisory_links"] = [url]
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 轻量轮（15 秒级）辅助：KEV 快照缓存 + NVD 关键词轮转
# --------------------------------------------------------------------------
KEV_SNAP = paths.data_path("kev_snapshot.json")
_KEV_TTL = 1800         # 轻量轮内 KEV 只每 30 分钟真取一次（代理下实测 125s，绝不能每轮同步取）
_RR_FP = paths.data_path("nvd_rr.json")


_KEV_REFRESHING = {"on": False}


_KEV_LOCK = threading.Lock()


def _kev_write(kev):
    """原子写：先落 .tmp 再 os.replace。

    轻量轮会另起线程后台刷 KEV（实测 125s），主线程的全量轮也可能同时写。
    open(w) 直接写的话，另一个线程恰好在读就会拿到半截 JSON —— 表现为
    「KEV 突然全空」且难以复现。tmp + replace 在 Windows 上也是原子的。
    """
    with _KEV_LOCK:
        try:
            tmp = KEV_SNAP + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "kev": kev}, f, ensure_ascii=False)
            os.replace(tmp, KEV_SNAP)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/monitor.py:218", _sw_e)


def _kev_read():
    for _ in range(2):          # 撞上写入窗口时读一次再试一次，别直接返回空
        try:
            with _KEV_LOCK:
                with open(KEV_SNAP, "r", encoding="utf-8") as f:
                    d = json.load(f)
            return float(d.get("ts") or 0), (d.get("kev") or {})
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    return 0.0, {}


def _kev_refresh_bg():
    """后台刷新 KEV 快照（轻量轮绝不等它 —— 实测代理下 fetch_kev 要 125s）。"""
    if _KEV_REFRESHING["on"]:
        return
    _KEV_REFRESHING["on"] = True

    def _run():
        try:
            _kev_write(F.fetch_kev())
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/monitor.py:243", _sw_e)
        finally:
            _KEV_REFRESHING["on"] = False

    threading.Thread(target=_run, daemon=True, name="kev-bg").start()


def _kev_cached(light):
    """KEV 快照：轻量轮用缓存（过期就后台刷新，本轮先用旧的）；全量轮同步取。"""
    if not light:
        kev = F.fetch_kev()
        _kev_write(kev)
        return kev
    ts, kev = _kev_read()
    fresh = ts and (time.time() - ts < _KEV_TTL)
    if not fresh:
        _kev_refresh_bg()      # 过期：另起线程慢慢刷，本轮继续用旧快照
    return kev


def _rec_sig(r):
    """记录的关键字段指纹：用来判断"NVD 这条更新到底有没有改动我们库里的条目"。

    每轮轻量同步都会捞回时间窗内几百条已收录 CVE，若不做判断就把它们全塞进
    增量通道，引擎会被无意义的写入淹没。只有指纹变了才回传。
    """
    return (
        r.get("desc") or "",
        r.get("status") or "",
        r.get("modified") or "",
        r.get("cvss") if isinstance(r.get("cvss"), (int, float)) else
        (r.get("cvss") or {}).get("score") if isinstance(r.get("cvss"), dict) else None,
        len(r.get("cwe") or []),
        len(r.get("poc_links") or []),
        len(r.get("patch_links") or []),
        len(r.get("advisory_links") or []),
        bool(r.get("kev")),
    )


def _nvd_round_robin(n):
    """轻量轮只查 n 个关键词，按轮转游标覆盖全部关键词（避免每 15s 打满 NVD 配额）。"""
    try:
        fp = os.path.abspath(_RR_FP)
        idx = 0
        if os.path.isfile(fp):
            with open(fp, "r", encoding="utf-8") as f:
                idx = int((json.load(f) or {}).get("idx") or 0)
        keys, total = F.NVD_QUERIES, len(F.NVD_QUERIES)
        picked = [keys[(idx + i) % total] for i in range(min(n, total))]
        _tmp = fp + ".tmp"
        with open(_tmp, "w", encoding="utf-8") as f:
            json.dump({"idx": (idx + len(picked)) % total}, f)
        os.replace(_tmp, fp)
        return picked
    except Exception:  # noqa: BLE001
        return F.NVD_QUERIES[:n]


def _mark_sources_ok(summary):
    """深度同步成功后回写源健康账本（2026-10-26）。

    快车道只覆盖 RSS/社区，NVD/KEV/arXiv 靠本函数所在的 6h 深同步。
    不回写的话，看板会把它们显示成"熔断中"，与真实产出矛盾。
    只标记**本轮确实成功**的源：被 skipped 记名的（限速/网络失败）不标记。
    """
    try:
        import source_health as SH
    except Exception:  # noqa: BLE001
        return
    skipped = summary.get("skipped") or []
    names = []
    if not any(str(s).startswith("NVD[") or str(s).startswith("NVD[整窗]") for s in skipped):
        names.append("nvd")
    if not any(str(s).startswith("KEV") for s in skipped):
        names.append("kev")
    arx_skipped = [str(s) for s in skipped if str(s).startswith("arXiv")]
    if not arx_skipped:
        names.append("arxiv")
    if not names:
        return
    new_n = len(summary.get("new_docs") or [])
    try:
        SH.mark_success(names, items=new_n,
                        note="6h 深度同步（monitor.refresh）")
    except Exception as e:  # noqa: BLE001
        print("[monitor] 源健康回写失败（不影响同步）: %s" % e)

def refresh(progress=None, window_hours=None, skip_github=False, light=False):
    """增量刷新。progress(stage, detail, pct) 用于 UI 进度回报。

    light=True —— 轻量轮（15 秒级定时同步用）：
      只做「KEV(缓存) + NVD 单关键词轮转 + CSDN 快抓」，跳过 arXiv 论文、
      GitHub（配额敏感）与新增富化；**本轮无新增就不写 corpus**（267MB 落盘
      每 15 秒一次会把磁盘 IO 打满）。重量部分仍由 auto_refresh_hours 的全量轮负责。


    返回 summary：{nvd_new, nvd_updated, kev_new, kev_backfill, papers_new,
                   advisories_new, repos_new, repos_updated, articles_new,
                   articles_updated, elapsed_sec, skipped, new_ids}
    """
    t0 = time.time()

    def cb(stage, detail, pct):
        if progress:
            try:
                progress(stage, detail, pct)
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("modules/m1_monitor/backend/monitor.py:322", _sw_e)

    st = load_state()
    if window_hours is None:
        window_hours = st.get("window_hours") or 120
    base_window = st.get("base_window_hours") or 120  # 基准窗口（不受补抓加宽影响）
    start_dt = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    start_iso, end_iso = _utc(start_dt), _utc(datetime.now(timezone.utc))

    with open(CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    records = corpus["records"]
    knowledge = corpus.get("knowledge", [])
    papers = corpus.get("papers", [])
    rec_by_id = {r["id"].upper(): r for r in records}
    kn_by_id = {k["id"]: k for k in knowledge}
    summary = {"nvd_new": 0, "nvd_updated": 0, "kev_new": 0, "kev_backfill": 0,
               "papers_new": 0, "advisories_new": 0, "repos_new": 0,
               "repos_updated": 0, "articles_new": 0, "articles_updated": 0,
               "skipped": [], "new_ids": [], "updated_ids": [],
               "new_docs": []}          # 新增/变更文档对象本体：供引擎增量并入（免全量重建）

    # ---------------- 1. CISA KEV（小文件全量重取） ----------------
    cb("kev", "同步 CISA KEV 在野利用目录 ...", 3)
    kev = {}
    try:
        kev = _kev_cached(light)
    except Exception as e:  # noqa: BLE001
        summary["skipped"].append("KEV: " + str(e)[:80])
    if kev:
        for cid, ent in kev.items():
            r = rec_by_id.get(cid.upper())
            if not r:
                continue
            if not r.get("kev"):
                r["kev"] = ent
                r["sources"] = sorted(set(r["sources"] + ["CISA KEV"]))
                if "在野利用" not in r["tags"]:
                    r["tags"].append("在野利用")
                summary["kev_new"] += 1
                summary["updated_ids"].append(cid)   # KEV 标记变了，回传引擎刷新
                summary["new_docs"].append(r)

    # ---------------- 2. NVD 增量（时间窗） ----------------
    cand = {}
    if light:
        # 轻量轮：单关键词轮转（5 分钟节拍内只查 1 个，下一轮换下一个）
        keys = _nvd_round_robin(1)
        nq = len(keys)
        for i, kw in enumerate(keys, 1):
            cb("nvd", f"NVD 增量检索 [{i}/{nq}] {kw}", 5 + 45.0 * i / max(1, nq))
            try:
                d = fetch_nvd_window(kw, start_iso, end_iso, tries=2, timeout=12)
                for v in d.get("vulnerabilities", []):
                    c = v.get("cve", {})
                    cid = (c.get("id") or "").upper()
                    if cid and cid not in cand:
                        cand[cid] = c
            except Exception as e:  # noqa: BLE001
                summary["skipped"].append(f"NVD[{kw}]: " + str(e)[:60])
    else:
        # 全量轮：整窗一次拉回（分页）+ 本地关键词过滤（2026-10-18 重构）。
        # 原来 107 个关键词逐个发请求 × 匿名限速 6.5s = 12 分钟起步、无代理时
        # 小时级；整窗 1~2 次请求秒级完成，无论有没有代理都快。过滤用
        # _nvd_matches 近似 NVD keywordSearch（子串匹配），宁收勿漏。
        cb("nvd", f"NVD 整窗拉取（近 {window_hours}h 全部 CVE，一次拉回后本地过滤）", 5)
        try:
            _window = _fetch_nvd_window_all(start_iso, end_iso)
            for cid, c in _window.items():
                if _nvd_matches(c, _NVD_KW_LOWER):
                    cand[cid] = c
            cb("nvd", f"NVD 整窗完成：{len(_window)} 条 → 命中 {len(cand)} 条", 50)
        except Exception as e:  # noqa: BLE001
            summary["skipped"].append("NVD[整窗]: " + str(e)[:80])
            cb("nvd", f"NVD 整窗拉取失败（{str(e)[:40]}），本轮跳过", 50)

    # 时间窗内的 CVE 分两类：全新 → 走富化流水线；已有 → 刷新核心字段
    for cid, c in cand.items():
        if cid not in rec_by_id:
            rec = F.build_record(c, kev, {}, papers)
            if rec is None:
                continue
            rec["intake"] = f"实时监测增量采集（时间窗 {window_hours}h）"
            rec["tags"].append("实时新增")
            # 组件推断（新披露 CVE 常无 CPE）
            if not rec["products"]:
                from augment import infer_products  # 延迟导入，避免模块级副作用
                got = infer_products(rec)
                if got:
                    rec["products"] = got
                    rec["product_source"] = "描述文本推断"
            records.append(rec)
            rec_by_id[cid] = rec
            summary["nvd_new"] += 1
            summary["new_ids"].append(cid)
            summary["new_docs"].append(rec)
        else:
            # 已有条目被 NVD 更新：刷新核心字段，保留富化结果
            r = rec_by_id[cid]
            _sig0 = _rec_sig(r)
            desc = F.extract_desc(c)
            if desc and desc != r.get("desc"):
                r["desc"] = " ".join(desc.split())
            r["modified"] = c.get("lastModified", r.get("modified", ""))
            r["status"] = c.get("vulnStatus", r.get("status", ""))
            r["cvss"] = F.parse_cvss(c)
            new_cwe = F.parse_cwe(c)
            if new_cwe:
                # r["cwe"] 可能整体缺失（外部语料/旧版本记录），先建列表再 append
                if not isinstance(r.get("cwe"), list):
                    r["cwe"] = []
                have = {w["id"] for w in r["cwe"]}
                for w in new_cwe:
                    if w["id"] not in have:
                        w["name"] = w["name"] or F.CWE_NAMES.get(w["id"], "")
                        r["cwe"].append(w)
            refs, poc, patch, adv = F.parse_refs(c)
            if poc:
                r["poc_links"] = sorted(set(r.get("poc_links", []) + poc))[:8]
                if "存在POC" not in r["tags"]:
                    r["tags"].append("存在POC")
            if patch:
                r["patch_links"] = sorted(set(r.get("patch_links", []) + patch))[:8]
            if adv:
                r["advisory_links"] = sorted(set(r.get("advisory_links", []) + adv))[:8]
            summary["nvd_updated"] += 1
            # 字段真的变了才回传引擎：否则每轮都会把时间窗内几百条已有 CVE
            # 白白塞进增量通道。引擎侧是就地覆盖（update_documents），不新增文档。
            if _rec_sig(r) != _sig0:
                summary["updated_ids"].append(cid)
                summary["new_docs"].append(r)

    # ---------------- 3. arXiv 最新论文 ----------------
    if light:
        summary["skipped"].append("arXiv: 轻量轮跳过（由 6h 全量轮负责）")
        cb("papers", "轻量轮跳过 arXiv", 55)
    else:
        cb("papers", "同步 arXiv 最新论文 ...", 55)
        seen_titles = {p["title"].lower()[:180] for p in papers}
        for i, q in enumerate(REFRESH_PAPER_QUERIES, 1):
            cb("papers", f"arXiv [{i}/{len(REFRESH_PAPER_QUERIES)}] {q[:40]}",
               55 + 8.0 * i / len(REFRESH_PAPER_QUERIES))
            try:
                for p in P.fetch_arxiv(q, 25):
                    k = p["title"].lower()[:180]
                    if k and k not in seen_titles:
                        seen_titles.add(k)
                        papers.append(p)
                        summary["papers_new"] += 1
            except Exception as e:  # noqa: BLE001
                summary["skipped"].append(f"arXiv[{q[:24]}]: " + str(e)[:60])
            time.sleep(3.0)
        if os.path.isfile(PAPER_CACHE) and summary["papers_new"]:
            with open(PAPER_CACHE, "w", encoding="utf-8") as f:
                json.dump(papers, f, ensure_ascii=False, indent=1)

    # ---------------- 4. GitHub（Advisory + 仓库，配额保护） ----------------
    quota = 0 if light else gh_quota()
    if skip_github or light or quota < GH_MIN_QUOTA:
        why = "轻量轮跳过" if light else ("手动跳过" if skip_github else f"配额不足（剩余 {quota}）")
        summary["skipped"].append("GitHub: " + why)
        cb("github", f"GitHub 本轮跳过（{why}）", 66)
    else:
        cb("github", "同步 GitHub Security Advisories ...", 66)
        try:
            ghsa_standalone, ghsa_by_cve = X.collect_ghsa()
            # 并回已有 CVE（与 augment 相同的合并策略）
            for cve, advisories in (ghsa_by_cve or {}).items():
                r = rec_by_id.get(cve.upper())
                if not r:
                    continue
                for a in advisories:
                    if "GitHub Advisory" not in r["sources"]:
                        r["sources"].append("GitHub Advisory")
                    for u in a.get("advisory_links", []):
                        if u not in r["advisory_links"]:
                            r["advisory_links"].append(u)
                    for pkg in a.get("products", []):
                        if pkg and pkg not in r["osv_packages"] and pkg not in r["products"]:
                            r["osv_packages"].append(pkg)
                    if a.get("desc") and a["desc"][:300] not in " ".join(r.get("osv_summaries", [])):
                        r.setdefault("osv_summaries", []).append(
                            "GitHub Advisory " + a["id"] + "：" + a["desc"][:300])
                    if "供应链公告" not in r["tags"]:
                        r["tags"].append("供应链公告")
            for a in ghsa_standalone:
                if a["id"] not in kn_by_id:
                    a["tags"].append("实时新增")
                    knowledge.append(a)
                    kn_by_id[a["id"]] = a
                    summary["advisories_new"] += 1
                    summary["new_ids"].append(a["id"])
        except Exception as e:  # noqa: BLE001
            summary["skipped"].append("GHSA: " + str(e)[:80])

        cb("github", "同步 GitHub AI 安全工具仓库 ...", 72)
        try:
            all_items = []
            for j, q in enumerate(X.GH_REPO_QUERIES, 1):
                all_items += X._fetch_repos(q)
                time.sleep(7)
            dedup, seen = [], set()
            for r in all_items:
                key = r.get("full_name")
                if key and key not in seen:
                    seen.add(key)
                    dedup.append(r)
            for r in dedup:
                rid = "GH:" + (r.get("full_name") or "")
                stars = r.get("stargazers_count") or 0
                if rid in kn_by_id:
                    k = kn_by_id[rid]
                    k["stars"] = stars
                    k["modified"] = (r.get("pushed_at") or "")[:10]
                    summary["repos_updated"] += 1
                elif stars >= X.MIN_STARS:
                    topics = r.get("topics") or []
                    desc = " ".join((r.get("description") or "AI security repository").split())
                    k = X._skeleton(
                        rid=rid, rtype="repo", kind="GitHub 安全工具仓库",
                        title=r["full_name"], desc=desc,
                        published=(r.get("created_at") or "")[:10],
                        sources=["GitHub"],
                        category=X._guess_category(desc + " " + " ".join(topics)),
                        reason="GitHub topic 检索 + star 门控（实时监测新增）",
                        tags=["安全工具", "实时新增"] + [f"topic:{t}" for t in topics[:4]],
                    )
                    k["stars"] = stars
                    k["language"] = r.get("language") or ""
                    k["repo_url"] = r.get("html_url") or ""
                    k["modified"] = (r.get("pushed_at") or "")[:10]
                    knowledge.append(k)
                    kn_by_id[rid] = k
                    summary["repos_new"] += 1
                    summary["new_ids"].append(rid)
        except Exception as e:  # noqa: BLE001
            summary["skipped"].append("repos: " + str(e)[:80])

    # ---------------- 5. CSDN 中文文章 ----------------
    # 轻量轮跳过：_collect_csdn_pages() 会翻很多页（分钟级），15s 节拍扛不住；
    # CSDN 新文章本来就由快车道 15s 的「作者主页 API」通道负责，这里再抓是重复劳动。
    if light:
        summary["skipped"].append("CSDN: 轻量轮跳过（快车道作者通道已覆盖）")
        cb("csdn", "轻量轮跳过 CSDN 翻页", 78)
    else:
        cb("csdn", "同步 CSDN 最新技术文章 ...", 78)
        try:
            items = _collect_csdn_pages()
            for rec in _csdn_items_to_records(items):
                if rec["id"] in kn_by_id:
                    k = kn_by_id[rec["id"]]
                    k["views"] = max(k.get("views") or 0, rec.get("views") or 0)
                    summary["articles_updated"] += 1
                else:
                    rec["tags"].append("实时新增")
                    knowledge.append(rec)
                    kn_by_id[rec["id"]] = rec
                    summary["articles_new"] += 1
                    summary["new_ids"].append(rec["id"])
                    summary["new_docs"].append(rec)
        except Exception as e:  # noqa: BLE001
            summary["skipped"].append("CSDN: " + str(e)[:80])

    # ---------------- 6. 新增 CVE 富化（ATLAS 映射 + 论文关联 + 修复建议） ----------------
    cb("enrich", "富化新增情报（ATLAS 映射 / 论文关联 / 修复建议）...", 88)
    # 轻量轮也富化：新增 CVE 若不带 ATLAS/修复建议，检索与问答质量会掉档。
    #
    # 但只富化**本轮**新增的：原实现筛的是全库带「实时新增」tag 的记录，而该 tag
    # 会随 corpus 一起落盘、永不清除 —— 实测已累积 5914 条，于是每 5 分钟一轮的
    # 轻量同步都要把几千条历史记录重跑一遍 ATLAS 映射 + 论文关联 + 修复建议
    # （实测某轮 377s 就是它吃掉的），且集合只增不减。
    # 富化结果本就存在记录里，重跑纯属浪费。
    _this_ids = set(summary["new_ids"]) | {
        str(d.get("id")) for d in summary["new_docs"]}
    new_records = [r for r in records
                   if str(r.get("id", "")).startswith("CVE")
                   and str(r.get("id")) in _this_ids]
    kb = None
    try:
        kb = AtlasKB()
    except Exception as e:  # noqa: BLE001
        summary["skipped"].append("ATLAS: " + str(e)[:80])
    for r in new_records:
        if kb is not None:
            techs, why = kb.map_record(r)
            r["atlas"] = techs
            r["atlas_evidence"] = why
            r["atlas_mitigations"] = kb.mitigations_for([t["id"] for t in techs]) if techs else []
        else:
            r["atlas"], r["atlas_evidence"], r["atlas_mitigations"] = [], [], []
        r["papers"] = F.link_papers(r, papers)
        if r["papers"] and "arXiv" not in r["sources"]:
            r["sources"].append("arXiv")
        r["remediation"] = F.remediation(r)

    # ---------------- 7. 落盘（原子写） ----------------
    summary["elapsed_sec"] = round(time.time() - t0, 1)
    # 同一条记录可能被多处回传（例如某 CVE 既"首次被 KEV 收录"又"NVD 字段有更新"），
    # 去重后再交给引擎，否则会被索引两遍、计数也虚高。
    _seen_doc, _uniq = set(), []
    for d in summary["new_docs"]:
        k = str(d.get("id") or "")
        if not k or k in _seen_doc:
            continue
        _seen_doc.add(k)
        # 统一补采集时间戳：快车道条目在 live.py 里打戳，轻量同步进库的没有，
        # tools/评测时效性.py 消费该字段，缺了会把这批算成"无采集时间"而失真。
        d.setdefault("fetched_at", now_local_iso())
        _uniq.append(d)
    summary["new_docs"] = _uniq
    summary["updated_ids"] = list(dict.fromkeys(summary["updated_ids"]))

    # 轻量轮（15s 级）无新增时**不重写 267MB 语料**：只更新状态文件。
    # 否则每 15 秒一次全量 dump，磁盘 IO 与服务响应都会被拖垮。
    # 判定口径必须是「有没有文档真的变了」，而不是「扫到多少条 NVD 更新」：
    # NVD 时间窗里往往有上百条已收录 CVE，若只因它们被扫到就写 267MB 语料，
    # 每 5 分钟一次无谓 dump，还会让 .idxcache 失效（下次启动要 6 分钟重建索引）。
    _changed = (bool(summary["new_ids"]) or bool(summary["updated_ids"])
                or bool(summary["new_docs"]) or summary["kev_new"]
                or summary["articles_updated"] or summary["repos_updated"])
    _mark_sources_ok(summary)
    if light and not _changed:
        summary["saved"] = False
        st["last_sync"] = now_local_iso()
        save_state(st)
        cb("done", f"轻量轮完成（无新增，未重写语料库，{summary['elapsed_sec']}s）", 100)
        return summary

    cb("save", "重建排序并原子写回语料库 ...", 96)
    summary["saved"] = True
    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    knowledge.sort(key=lambda k: k.get("published", ""), reverse=True)
    summary["elapsed_sec"] = round(time.time() - t0, 1)
    m = corpus.setdefault("meta", {})
    m["monitor"] = {
        "last_sync": now_local_iso(),
        "window_hours": window_hours,
        "new_counts": {k: v for k, v in summary.items()
                       if isinstance(v, int) and k not in ("elapsed_sec",)},
        "elapsed_sec": summary["elapsed_sec"],
    }
    m["records"] = len(records)
    m["papers"] = len(papers)
    m["monitored_at"] = now_local_iso()

    # 紧凑写（去掉 indent=1）：10 万条记录的语料多一层缩进就是几十 MB，
    # 而轻量同步 5 分钟一轮，写 342MB 和写 250MB 在机械盘上是分钟级的差别。
    # corpus 是机器消费的数据文件，不需要人类可读。
    tmp = CORPUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CORPUS)

    st["last_sync"] = now_local_iso()
    # 若本轮有 NVD 查询失败（限速/网络），把下一轮窗口扩大 48h，
    # 确保失败关键词在本窗口内可能漏掉的 CVE 下次能补抓回来；成功后回到基准窗口
    nvd_failed = any(s.startswith("NVD[") for s in summary["skipped"])
    st["base_window_hours"] = base_window
    st["window_hours"] = base_window + 48 if nvd_failed else base_window
    # history 只记全量轮：轻量轮 5 分钟一条，一天 288 条，只留 20 条的话
    # 会把 nvd_new=1095 那种全量轮记录全挤掉，排查时反而看不到真正的大同步。
    if not light:
        st["history"] = (st.get("history") or [])[-19:] + [{
            "at": st["last_sync"], "summary": {k: v for k, v in summary.items()
                                               if k != "new_ids"}}]
    save_state(st)
    cb("done", "同步完成", 100)
    return summary


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=None, help="增量时间窗（小时），默认用状态文件记忆值")
    ap.add_argument("--skip-github", action="store_true", help="跳过 GitHub（配额保护）")
    args = ap.parse_args()

    def _p(stage, detail, pct):
        print(f"  [{pct:5.1f}%] {stage:8s} {detail}", flush=True)

    s = refresh(progress=_p, window_hours=args.hours, skip_github=args.skip_github)
    print("\n===== 增量同步结果 =====")
    for k, v in s.items():
        if k != "new_ids":
            print(f"  {k:18s} {v}")
    if s["new_ids"]:
        print("  新增条目示例：", ", ".join(s["new_ids"][:10]))
    if s["skipped"]:
        print("  跳过/降级：")
        for x in s["skipped"]:
            print("    -", x)
