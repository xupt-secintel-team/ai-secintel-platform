# -*- coding: utf-8 -*-
"""daily_report.py —— 每日 AI 安全风险分类报告（2026-10-06 新增）

为什么做这个（代码核查结论，不是文档声称）：
  此前 `/api/live` 只给最近 5 条，检索页的导出是"当前查询结果的快照"，
  **没有任何"把今天看到的风险按类整理成一份可归档报告"的能力**。
  评审要看的是"你们今天查出了什么、分别属于哪一类风险"，现在这个答案
  散落在 jsonl 里，得自己拉数据自己分。

三个设计决定（都是踩过才知道的）：

1. **按"系统检测到的日期"分组，不按源站 `published` 分组。**
   `published` 是源站写稿时间，可能是三个月前；而日报的组织维度必须是
   "这一天我们的系统发现了什么"。用 `fetched_at`（入库打戳）为主，
   `published` 只作为条目自身的属性展示。混用会导致"今天没有日报"
   （因为今天的源站可能没发新东西，但系统补采到了一批历史条目）。

2. **分类用引擎已算好的 `category`，不在这里重新实现分类逻辑。**
   `core/taxonomy.py: classify()` 是全项目唯一的分类入口（检索、
   富化、CMDB 台账都用它）。日报重新实现一套必然漂移 —— 同一漏洞在
   检索页显示"② 模型与数据层"、日报却显示"① 基础设施"，评审一眼看穿。
   所以：能拿到 category 就用，拿不到才走一个**保守兜底**并标注来源。

3. **报告保留一个月；清理只删日报目录里的日报文件，且留一份过期日期清单。**
   `data/daily_reports/` 下按 `YYYY-MM-DD.{md,json,xlsx}` 平铺。
   删除只认这一个文件名正则，绝不做目录级递归删除（不可逆，
   且这个目录可能被人手工放过别的东西）。
   被删掉的日期记进 `_expired.json` —— 否则页面查 40 天前只会显示
   "没有报告"，分不清是"那天系统没跑"还是"已过保留期被清了"。
   不造占位的假报告文件（那会让"这天有报告"变成误导）。
"""
from __future__ import annotations

import io
import json
import os
import re
import time

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import paths
try:
    from taxonomy import RISK_CATEGORIES
except Exception:  # pragma: no cover
    try:
        from core.taxonomy import RISK_CATEGORIES
    except Exception:
        RISK_CATEGORIES = {}
# ★ 原文页推导（2026-10-13）：与检索卡片、详情面板、检索报告共用同一个口径。
#   快车道 news API 通道偶发不返回 url（实测 32 条 AQ:/XZ: 记录 link 为空），
#   没有 canonical_url 兜底时日报这些条目就没有"原文"链接。
try:
    from engine import canonical_url as _canonical_url
except Exception:  # pragma: no cover —— 独立调用/导入路径未就绪时安全降级
    try:
        from core.engine import canonical_url as _canonical_url
    except Exception:
        def _canonical_url(_d):
            return ""

# 报告保留期：一个月。改成 30 天是明确的整数，避免 "month" 的歧义。
RETENTION_DAYS = int(os.environ.get("AISEC_REPORT_KEEP_DAYS", "30") or 30)

# 分类展示顺序：AI 四大类（评审重点）。
# 2026-10-07 起日报**只展示 AI 四大类**：通用七类（Web/系统/网络/云/身份/恶意/数据）
# 不再单独列类，其条目数汇总到 `general_count`（数据不丢，只是不展开）。
# 顺序即报告里的章节顺序，必须稳定 —— 每天的日报要能逐日对照。
_CAT_ORDER = [
    "① AI基础设施与推理框架",
    "② 模型与数据层",
    "③ AI应用与智能体",
    "④ AI供应链与平台",
]
# 通用网络安全分类：仍参与分类（条目不会凭空消失），只是不单独展示
_GEN_ORDER = [
    "⑤ Web应用与API安全",
    "⑥ 系统与二进制安全",
    "⑦ 网络与协议安全",
    "⑧ 云原生与容器安全",
    "⑨ 身份与访问管理",
    "⑩ 恶意代码与威胁活动",
    "⑪ 数据安全与密码学",
]

# 兜底分类用：只在拿不到 category 时才用，且会在条目上标 classified_by。
_FALLBACK = "⑩ 恶意代码与威胁活动"

# 引擎分类函数：core/fetch_corpus.py:classify(rec) -> (ok, score, cat, reason, tags)
# 全项目唯一分类入口（实时采集 / 语料构建都调它）。日报对"没有 category 字段"
# 的条目（如 KEV 缓存、GHSA 增量）也走这里，而不是自己再写一套规则 ——
# 两套规则必然漂移，表现为"同一条漏洞在检索页和日报里分类不同"。
_CLASSIFY = None


def _classify(rec):
    """返回 (category, reason, tags)。拿不到分类器就退回 None。"""
    global _CLASSIFY
    if _CLASSIFY is None:
        try:
            import fetch_corpus as F
            _CLASSIFY = getattr(F, "classify", False)
        except Exception:  # noqa: BLE001
            _CLASSIFY = False
    if not _CLASSIFY:
        return None, "", []
    try:
        ok, score, cat, reason, tags = _CLASSIFY(rec)
        return (cat if ok else None), str(reason or ""), list(tags or [])
    except Exception:  # noqa: BLE001
        return None, "", []


# ── 路径 ────────────────────────────────────────────────────────────
def report_dir():
    """日报目录。放 data/ 下而不是"测试报告/" —— 那是评测产物目录，
    混在一起既容易被评测脚本清掉，也会让人误以为日报是测试输出。"""
    d = os.path.join(paths.DATA_DIR, "daily_reports")
    os.makedirs(d, exist_ok=True)
    return d


def _path(date, fmt):
    return os.path.join(report_dir(), "%s.%s" % (date, fmt))


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# 日报正文文件名。**全模块只此一份正则**：available_dates / cleanup / stats
# 都要认它。此前三处各写一遍 literal，改一处忘另一处就会出现
# "清理把别的文件删了" 或 "stats 多报一份报告"。
_DAY_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.(md|json|xlsx)$")


def valid_date(s):
    if not s or not _DATE_RE.match(str(s)):
        return None
    y, m, d = (int(x) for x in str(s).split("-"))
    if not (1970 <= y <= 2100 and 1 <= m <= 12 and 1 <= d <= 31):
        return None
    return str(s)


def today():
    return time.strftime("%Y-%m-%d")


# ── 取数 ────────────────────────────────────────────────────────────
_INTAKE_CACHE = {"sig": None, "rows": []}
_INTAKE_CAP = 4000      # 单文件最多缓存多少条入库记录（防 monitor_state 越滚越大吃内存）


def _read_intake(day):
    """读"深度增量同步"当天入库的记录（`data/monitor_state.json` 的 history）。

    ## 为什么必须加这个数据源（2026-10-07 实测）

    日报原本只读 `live_feed.jsonl`（快车道 15s 轮询那一条线）+ KEV 缓存。
    但**新 CVE 是定时增量同步（monitor.refresh）并进 `corpus.json` 的**，
    那条线不写 live_feed。实测同一天：

        live_feed 当天入库   36 条  → 日报收 31 条（去重后）
        corpus   当天入库  380 条（一次同步就 new_docs=925）

    也就是说日报漏掉了当天 **97%** 的情报，而且漏的恰恰是 CVE —— 日报最该
    突出的一类。表现是"日报里全是厂商博客的资讯，一条漏洞都没有"。

    `monitor_state.json` 的 `history[*].summary.new_docs` 正好是逐次同步的
    **完整入库记录**（含 id / title / desc / cvss / category / fetched_at），
    直接按运行日期 `at` 取当天那几轮即可，不必去扫 268MB 的 corpus.json。

    代价与对策：文件目前 ~8MB，加 mtime 缓存；历史只保留最近若干轮，
    所以"很早以前某天"若同步记录已被滚动掉，仍会缺 —— 那种情况由
    `available_dates()` 里的既有报告兜底，不会凭空造数据。
    """
    fp = os.path.join(paths.DATA_DIR, "monitor_state.json")
    if not os.path.isfile(fp):
        return []
    try:
        sig = (os.path.getmtime(fp), os.path.getsize(fp))
    except OSError:
        return []
    if _INTAKE_CACHE["sig"] != sig:
        rows = []
        try:
            with io.open(fp, "r", encoding="utf-8") as f:
                st = json.load(f)
            for ent in (st.get("history") or [])[-40:]:
                at = str(ent.get("at") or "")[:10]
                if not at:
                    continue
                for rec in ((ent.get("summary") or {}).get("new_docs") or [])[:_INTAKE_CAP]:
                    if isinstance(rec, dict):
                        rows.append((at, rec))
        except Exception as e:  # noqa: BLE001
            try:
                from errlog import swallow as _swallow
                _swallow("core/daily_report.py:_read_intake", e)
            except Exception:  # noqa: BLE001
                pass
            rows = []
        _INTAKE_CACHE.update(sig=sig, rows=rows)
    return [r for at, r in _INTAKE_CACHE["rows"] if at == day]


def _read_feed():
    """读实时流 jsonl。逐行 try —— 采集进程正在写时最后一行可能不完整，
    不能因为一行坏 JSON 就丢掉整份报告。"""
    fp = os.path.join(paths.DATA_DIR, "live_feed.jsonl")
    if not os.path.exists(fp):
        return []
    out = []
    bad = 0
    try:
        with io.open(fp, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:  # noqa: BLE001
                    bad += 1
                    continue
                if isinstance(d, dict):
                    out.append(d)
    except Exception:  # noqa: BLE001
        return []
    if bad:
        try:
            from errlog import swallow as _swallow
            _swallow("core/daily_report.py:_read_feed", None, note="%d 行解析失败" % bad)
        except Exception:  # noqa: BLE001
            pass
    return out


def _read_kev(day):
    """读 KEV（已知在野利用漏洞）缓存，取 date_added == day 的条目。

    为什么必收 KEV：日报最该突出的是"今天确认了哪些漏洞已被在野利用"。
    这个信息在 `live_feed.jsonl` 里基本没有（博客文章多、KEV 条目少），
    只靠实时流会让日报漏掉最关键的那一类。
    KEV 缓存只有 1700 多条、不到 1MB，按需读取成本可忽略。
    """
    fp = os.path.join(paths.DATA_DIR, "kev_cache.json")
    if not os.path.exists(fp):
        return []
    try:
        with io.open(fp, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(d, dict):
        return []
    out = []
    for cid, v in d.items():
        if not isinstance(v, dict):
            continue
        if str(v.get("date_added") or "")[:10] != day:
            continue
        out.append({
            "id": cid,
            "type": "kev",
            "kind": "CISA KEV 在野利用",
            "title": "%s %s" % (cid, str(v.get("short_desc") or "").strip()[:180]),
            "desc": str(v.get("short_desc") or "")[:400],
            "source": "CISA KEV",
            "category": None,          # 交给引擎分类
            "cvss": None,              # KEV 不一定有 CVSS，但因在野利用一律严重
            "kev": True,
            "poc_links": [],
            "published": str(v.get("date_added") or "")[:10],
            "detected_day": day,
            "products": ([str(v.get("vendor") or "")] if v.get("vendor") else []),
            "risk_tags": ["在野利用"] + (["勒索软件"] if v.get("ransomware") else []),
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    if not str(cid).startswith("CVE") else
                    "https://nvd.nist.gov/vuln/detail/%s" % cid,
            "remediation": str(v.get("required_action") or "")[:400],
            "live": True,
        })
    return out


def _detected_day(rec):
    """条目"被系统检测到"的日期。

    优先 `fetched_at`（采集打戳，v2.2 起才有）；没有就退到 `published`。
    两者都没有则返回 None（不硬塞当天 —— 那样日报会凭空多出无主条目）。
    """
    fa = str(rec.get("fetched_at") or "").strip()
    if fa:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", fa)
        if m:
            return m.group(1)
    pub = str(rec.get("published") or "").strip()
    if pub:
        m = re.match(r"(\d{4}-\d{2}-\d{2})", pub)
        if m:
            return m.group(1)
    return None


def _to_int(v, default=0):
    """安全转 int。真实数据里 cvss 有时是 "9.8"、有时是 9.8、有时是 None，
    还有时是带单位的脏字符串（见记忆：本项目真实数据字段类型不统一）。"""
    try:
        if v is None or v == "":
            return default
        if isinstance(v, bool):
            return default
        f = float(v)
        return int(f)
    except (TypeError, ValueError):
        m = re.search(r"-?\d+(?:\.\d+)?", str(v))
        if m:
            try:
                return int(float(m.group(0)))
            except Exception:  # noqa: BLE001
                return default
        return default


def _sev(cvss, kev=False, has_score=True):
    """统一严重度：KEV 直接顶到 critical（有在野利用的还讨论分数没意义）。

    `has_score=False` 表示这条**根本没有 CVSS**（多为安全博客/研究文章，
    不是漏洞条目）。这种情况不能塞进"低危" —— 那会让日报的等级分布
    失真（实测未处理前当日 61 条全是"低危"，看着像"今天全是小问题"，
    实际上其中相当篇幅是高价值情报）。统一标成"资讯"。
    """
    if kev:
        return "critical"
    if not has_score:
        return "info"
    c = _to_int(cvss, 0)
    if c >= 9:
        return "critical"
    if c >= 7:
        return "high"
    if c >= 4:
        return "medium"
    return "low"


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危",
             "low": "低危", "info": "资讯"}


def _cvss_score(rec):
    """取 CVSS 分值。**语料里 cvss 是一个 dict**（{"score":…, "severity":…}），
    不是数字 —— 这是全项目的统一结构（`core/engine.py` 也按 dict 读）。

    实测踩过的坑：日报早期直接把 `rec["cvss"]` 丢给 `_to_int()`，
    而 `_to_int` 对 dict 会走到 `re.search(数字, str(dict))` 这条兜底 ——
    `{'score': None, 'severity': 'LOW', 'vector': 'CVSS:3.1/…'}` 里第一个数字
    是向量串里的 "3.1"，于是这条被记成 **CVSS 3 / 低危**，而它根本没有分数。
    结果当天 31 条全部显示"资讯"、严重度分布全空，看起来像"今天什么也没查到"。
    """
    cv = rec.get("cvss")
    if isinstance(cv, dict):
        return cv.get("score")
    return cv


def _item(rec, day):
    """把原始记录压成报告条目（只留报告要用的字段，顺带做脏数据兜底）。"""
    cvss = _cvss_score(rec)
    kev = bool(rec.get("kev"))
    # CVSS 可能是 0 / None / "" / "9.8" / 非法串 —— 一律归一
    cvss_v = _to_int(cvss, 0)
    has_score = cvss_v > 0
    cat = rec.get("category")
    reason = str(rec.get("category_reason") or "")
    tags_extra = []
    if cat not in RISK_CATEGORIES:
        # 走引擎分类器（KEV 缓存、GHSA 增量等没有 category 字段的来源）
        cat2, reason2, tags2 = _classify(rec)
        if cat2 in RISK_CATEGORIES:
            cat, reason = cat2, reason2
            tags_extra = tags2
        else:
            cat = _FALLBACK
    by = "engine" if cat in RISK_CATEGORIES else "fallback"
    sev = _sev(cvss_v, kev, has_score)
    tags = rec.get("risk_tags") or rec.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    elif not isinstance(tags, list):
        tags = []
    # 引擎分类顺带产出的标签要一并带上（比原文 tags 更准）
    for t in tags_extra:
        if t and t not in tags:
            tags.append(t)
    title = str(rec.get("title") or "").strip() or "(无标题)"
    return {
        "id": str(rec.get("id") or ""),
        "title": title[:300],
        "category": cat,
        "classified_by": by,
        "category_reason": reason[:200],
        "severity": sev,
        "severity_label": SEV_LABEL[sev],
        "cvss": cvss_v,
        "has_cvss": has_score,
        "kev": kev,
        "poc": bool(rec.get("poc_links") or rec.get("poc")),
        "published": str(rec.get("published") or "")[:10],
        "detected_day": day,
        "source": str(rec.get("source") or (rec.get("sources") or [None])[0] or "")[:80],
        "kind": str(rec.get("kind") or "")[:60],
        "products": (rec.get("products") if isinstance(rec.get("products"), list) else [])[:6],
        "risk_tags": [str(x)[:40] for x in tags[:6]],
        # link 为空时按 id 规则兜底推导原文页（canonical_url 与检索/详情同口径）；
        # 推导不出才留空 —— 前端对空链接本就不渲染"原文"入口。
        "link": (str(rec.get("link") or "")[:500] or _canonical_url(rec))[:500],
        "desc": str(rec.get("desc") or "")[:400],
        "remediation": str(rec.get("remediation") or "")[:400],
    }


def _dedup_key(it):
    """去重键：标题优先，其次链接，最后 id。

    为什么不能只用 id —— 实测 `data/live_feed.jsonl` 里同一个 CrowdStrike
    标题出现了 **162 次**（分页抓取导致 URL 带不同后缀，id 也就不同）。
    按 id 去重完全拦不住，日报会出现"162 条一模一样的文章"。
    标题归一（去空白、转小写）后才能真正挡住。
    """
    t = re.sub(r"\s+", " ", str(it.get("title") or "")).strip().lower()
    if t:
        return ("t", t[:200])
    link = str(it.get("link") or "").strip()
    if link:
        return ("l", link[:300])
    return ("i", str(it.get("id") or ""))


def collect(date=None, limit_per_cat=60):
    """取某天的条目并按类分桶。

    date 缺省为今天。返回 {date, total, categories:[{key,label,desc,color,
    count, by_sev:{...}, items:[...]}]}
    """
    day = valid_date(date) or today()
    rows = []
    # 数据源1：实时流（live_feed.jsonl）—— 快车道 15s 轮询抓到的博客/公告/投稿
    for rec in _read_feed():
        if _detected_day(rec) != day:
            continue
        rows.append(_item(rec, day))
    # 数据源2：深度增量同步当天入库（monitor_state.history[].new_docs）——
    # 新 CVE 走的是这条线，不收就等于日报漏掉当天绝大部分情报（实测漏 97%）。
    for rec in _read_intake(day):
        rows.append(_item(rec, day))
    # 数据源3：KEV（当天新增的在野利用漏洞）—— 实时流里几乎没有这类条目，
    # 但它恰恰是日报最该突出的一类。不收的话日报会退化成"文章摘要汇编"。
    rows.extend(_item(r, day) for r in _read_kev(day))
    # 去重：同一条目可能既有多次抓取（id 不同）又有多天补采。
    # 合并时不是简单丢弃 —— 取信息最全的一条（有 CVSS / POC / 链接的优先）。
    uniq = {}
    for it in rows:
        k = _dedup_key(it)
        prev = uniq.get(k)
        if prev is None:
            uniq[k] = it
            continue
        # 补位：谁有值用谁的
        for f in ("id", "link", "desc", "published", "source", "kind"):
            if not prev.get(f) and it.get(f):
                prev[f] = it[f]
        if it.get("poc"):
            prev["poc"] = True
        # CVSS 取大值（同一漏洞不同源给的分数可能不同）
        if _to_int(it.get("cvss")) > _to_int(prev.get("cvss")):
            prev["cvss"] = _to_int(it["cvss"])
        if it.get("kev"):
            prev["kev"] = True
        prev["severity"] = _sev(prev.get("cvss"), prev.get("kev"),
                                 prev.get("has_cvss", bool(prev.get("cvss"))))
        prev["severity_label"] = SEV_LABEL[prev["severity"]]
        # 标签取并集
        merged = list(prev.get("risk_tags") or [])
        for t in (it.get("risk_tags") or []):
            if t not in merged:
                merged.append(t)
        prev["risk_tags"] = merged[:8]
    rows = list(uniq.values())

    buckets = {k: [] for k in _CAT_ORDER + _GEN_ORDER}
    for it in rows:
        buckets.setdefault(it["category"], []).append(it)

    # 只展示 AI 四大类；通用七类条目数归到 general_count（数据不丢，只是不展开）。
    cats = []
    for key in _CAT_ORDER:
        items = buckets.get(key) or []
        if not items:
            continue
        items.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                  -(x.get("cvss") or 0), x["published"] or ""),
                   reverse=False)
        by_sev = {s: 0 for s in SEV_ORDER}
        for it in items:
            by_sev[it["severity"]] = by_sev.get(it["severity"], 0) + 1
        meta = RISK_CATEGORIES.get(key, {})
        cats.append({
            "key": key,
            "label": meta.get("short") or key,
            "full": key,
            "desc": meta.get("desc") or "",
            "color": meta.get("color") or "#888780",
        "count": len(items),
        "by_sev": by_sev,
        # 每分类的 KEV/POC 计数也按**全量条目**统计（不是截断后的 items）——
        # 「模块每日报告」的四方向卡片直接引用这两个数，截断样本会低估。
        "kev": sum(1 for it in items if it.get("kev")),
        "poc": sum(1 for it in items if it.get("poc")),
        "items": items[:limit_per_cat],
        "truncated": max(0, len(items) - limit_per_cat),
            "fallback_count": sum(1 for x in items if x["classified_by"] == "fallback"),
        })

    # 通用七类：计数 + 折叠提示，不进 categories（用户要求只显示四大类）
    general_count = sum(len(buckets.get(k) or []) for k in _GEN_ORDER)

    total_sev = {s: 0 for s in SEV_ORDER}
    for c in cats:
        for s, n in c["by_sev"].items():
            total_sev[s] = total_sev.get(s, 0) + n
    # 通用类的严重度也要计入总分布（total 是"情报条目总数"的口径）
    for key in _GEN_ORDER:
        for it in (buckets.get(key) or []):
            total_sev[it["severity"]] = total_sev.get(it["severity"], 0) + 1

    return {
        "date": day,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total": sum(c["count"] for c in cats) + general_count,
        "category_count": len(cats),
        "general_count": general_count,
        "by_sev": total_sev,
        "kev": sum(1 for it in rows if it.get("kev")),
        "poc": sum(1 for it in rows if it.get("poc")),
        "retention_days": RETENTION_DAYS,
        "categories": cats,
        "_rows": rows,      # 内部用，渲染前会被剔除
    }


# ── 渲染 ────────────────────────────────────────────────────────────
def _md_esc(s):
    """Markdown 转义：竖线会破表格，换行会破结构。"""
    s = str(s or "")
    return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_markdown(data):
    """七章制精简版：分类结论 / 当日概览 / 分类明细 / 处置建议 / 分类口径。"""
    L = []
    d = data
    L.append("# AI 安全风险日报 · %s" % d["date"])
    L.append("")
    L.append("> 生成时间：%s ｜ 报告保留 %d 天 ｜ 分类口径：引擎 `category` 字段"
             % (d["generated_at"], d["retention_days"]))
    L.append("")

    # 一、当日概览
    L.append("## 一、当日概览")
    L.append("")
    bs = d["by_sev"]
    L.append("| 指标 | 数值 |")
    L.append("|---|---|")
    L.append("| 情报条目总数 | **%d** |" % d["total"])
    L.append("| 覆盖风险分类 | %d 类（AI 四大类）" % d["category_count"])
    L.append("| 严重（CVSS≥9） | %d |" % bs.get("critical", 0))
    L.append("| 高危（CVSS≥7） | %d |" % bs.get("high", 0))
    L.append("| 中危（CVSS≥4） | %d |" % bs.get("medium", 0))
    L.append("| 低危 | %d |" % bs.get("low", 0))
    L.append("| 资讯（无 CVSS 的研究/博客） | %d |" % bs.get("info", 0))
    L.append("| 在野利用（KEV） | %d |" % d["kev"])
    L.append("| 含公开 POC | %d |" % d["poc"])
    L.append("")

    # 二、分类结论（评审先看这段）
    L.append("## 二、分类结论")
    L.append("")
    if not d["categories"]:
        L.append("当日无新增情报。")
        L.append("")
    else:
        L.append("| 风险分类 | 条目 | 严重 | 高危 | 中危 | 低危 | 资讯 | 说明 |")
        L.append("|---|---:|---:|---:|---:|---:|---:|---|")
        for c in d["categories"]:
            b = c["by_sev"]
            L.append("| **%s** | %d | %d | %d | %d | %d | %d | %s |"
                     % (c["full"], c["count"], b.get("critical", 0), b.get("high", 0),
                        b.get("medium", 0), b.get("low", 0), b.get("info", 0),
                        _md_esc(c["desc"])))
        L.append("")

    # 三、分类明细
    L.append("## 三、分类明细")
    L.append("")
    for c in d["categories"]:
        L.append("### %s · %s（%d 条）" % (c["full"], c["label"], c["count"]))
        L.append("")
        L.append("> %s" % (_md_esc(c["desc"]) or "—"))
        L.append("")
        L.append("| 严重度 | CVSS | 标题 | 来源 | 发布日期 | KEV | POC |")
        L.append("|---|---|---|---|---|:--:|:--:|")
        for it in c["items"]:
            L.append("| %s | %s | %s | %s | %s | %s | %s |"
                     % (it["severity_label"],
                        it["cvss"] or "—",
                        _md_esc(it["title"]) or "—",
                        _md_esc(it["source"]) or "—",
                        it["published"] or "—",
                        "✓" if it["kev"] else "",
                        "✓" if it["poc"] else ""))
        if c["truncated"]:
            L.append("")
            L.append("> 另有 %d 条同类条目未列出（可在 JSON/xlsx 版查看全部）。" % c["truncated"])
        L.append("")

    # 四、处置建议：按严重度给动作，不写空话
    L.append("## 四、处置建议")
    L.append("")
    n = 0
    for c in d["categories"]:
        for it in c["items"]:
            if it["severity"] not in ("critical", "high"):
                continue
            n += 1
            act = []
            if it["kev"]:
                act.append("**已在野利用**，按应急预案立即处置")
            if it["cvss"] >= 9:
                act.append("CVSS %.1f，建议 24h 内出修复方案" % it["cvss"])
            elif it["cvss"] >= 7:
                act.append("CVSS %.1f，建议 7 天内纳入版本迭代" % it["cvss"])
            if it["poc"]:
                act.append("已有公开 POC，需核查自身资产是否受影响")
            if it["products"]:
                act.append("受影响产品：%s（对照自有资产核查）" % "、".join(it["products"][:3]))
            if not act:
                act.append("列入常规跟踪")
            L.append("%d. [%s] %s —— %s" % (n, it["severity_label"], it["title"], "；".join(act)))
    if not n:
        L.append("当日无严重/高危条目，无需紧急处置。")
    L.append("")

    # 五、分类口径（把判定依据写清楚，避免"分类怎么来的"成为争议点）
    L.append("## 五、分类口径")
    L.append("")
    L.append("- 本报告**聚焦 AI 安全四大类**：AI基础设施与推理框架 / 模型与数据层 / "
             "AI应用与智能体 / AI供应链与平台。")
    gc = d.get("general_count", 0)
    if gc:
        L.append("- 另有 **%d 条通用网络安全情报**（Web/系统/网络/云原生/身份/恶意代码/数据）"
                 "未单独列类，仅计入总数 —— 报告主体聚焦 AI 风险。" % gc)
    L.append("- 分类直接取用检索引擎写好的 `category` 字段（与检索页、CMDB 台账同一套判定），"
             "不在日报里重复实现分类逻辑。")
    if any(c["fallback_count"] for c in d["categories"]):
        fb = sum(c["fallback_count"] for c in d["categories"])
        L.append("- 其中 %d 条缺少可识别分类，已保守归入「%s」，请人工复核。" % (fb, _FALLBACK))
    else:
        L.append("- 当日全部条目均有可识别分类，无兜底归类。")
    L.append("- 严重度：CVSS≥9 严重、≥7 高危、≥4 中危、其余低危；"
             "KEV 条目一律计为严重（在野利用优先于分数）；"
             "**无 CVSS 的条目（多为安全博客/研究文章）标为「资讯」而非「低危」**"
             " —— 否则等级分布会失真，看着像今天全是小问题。")
    L.append("- 分组日期按**系统检测到该情报的日期**（`fetched_at`），"
             "而非源站 `published`；后者只作为条目属性展示。")
    L.append("- 同一标题的多条抓取记录（部分源分页重复）已按标题+链接去重，"
             "重复条目取信息最全的一条（CVSS 取大值）。")
    L.append("")
    return "\n".join(L)


def render_xlsx(data):
    """xlsx 台账：一个总览 sheet + 每个非空分类一个 sheet。"""
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.utils import get_column_letter
    except Exception as e:  # noqa: BLE001
        raise RuntimeError("缺 openpyxl，无法导出 xlsx：%s（pip install openpyxl）" % e)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "当日概览"
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill("solid", fgColor="2F3B52")

    ws.append(["AI 安全风险日报"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["日期", data["date"]])
    ws.append(["生成时间", data["generated_at"]])
    ws.append(["保留期", "%d 天" % data["retention_days"]])
    ws.append(["条目总数", data["total"]])
    ws.append(["在野利用 KEV", data["kev"]])
    ws.append(["含公开 POC", data["poc"]])
    ws.append([])
    ws.append(["风险分类", "条目", "严重", "高危", "中危", "低危", "资讯", "说明"])
    for cell in ws[ws.max_row]:
        cell.font = hdr_font
        cell.fill = hdr_fill
    for c in data["categories"]:
        b = c["by_sev"]
        ws.append([c["full"], c["count"], b.get("critical", 0), b.get("high", 0),
                   b.get("medium", 0), b.get("low", 0), b.get("info", 0), c["desc"]])
    for i, w in enumerate([26, 8, 8, 8, 8, 8, 8, 60], start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

    cols = ["严重度", "CVSS", "标题", "来源", "发布日期", "KEV", "POC",
            "受影响产品", "风险标签", "链接", "说明"]
    widths = [8, 7, 60, 16, 12, 6, 6, 30, 26, 50, 50]
    for c in data["categories"]:
        # Excel sheet 名不能含 : \ / ? * [ ]，且 ≤31 字符
        name = re.sub(r"[:\\/?*\[\]]", "_", "%s %s" % (c["full"], c["label"]))[:31]
        sh = wb.create_sheet(name)
        sh.append(cols)
        for cell in sh[1]:
            cell.font = hdr_font
            cell.fill = hdr_fill
            cell.alignment = Alignment(vertical="center")
        for it in c["items"]:
            sh.append([it["severity_label"], it["cvss"] or "", it["title"],
                       it["source"], it["published"],
                       "是" if it["kev"] else "", "是" if it["poc"] else "",
                       "、".join(it["products"]), "、".join(it["risk_tags"]),
                       it["link"], it["desc"]])
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(cols)), max(1, sh.max_row))
        for i, w in enumerate(widths, start=1):
            sh.column_dimensions[get_column_letter(i)].width = w
        for row in sh.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical="top", wrap_text=True)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _json_public(data):
    """对外 JSON：剔掉内部用的 _rows（几百条重复数据，白白撑大响应）。"""
    return {k: v for k, v in data.items() if not k.startswith("_")}


# ── 落盘 / 读取 / 清理 ──────────────────────────────────────────────
def save(data):
    """把当天报告落盘三种格式，返回路径字典。"""
    d = data["date"]
    pub = _json_public(data)
    paths = {}
    md = os.path.join(report_dir(), "%s.md" % d)
    js = os.path.join(report_dir(), "%s.json" % d)
    xl = os.path.join(report_dir(), "%s.xlsx" % d)
    try:
        with io.open(md, "w", encoding="utf-8") as f:
            f.write(render_markdown(pub))
        paths["md"] = md
        with io.open(js, "w", encoding="utf-8") as f:
            json.dump(pub, f, ensure_ascii=False, indent=1)
        paths["json"] = js
        try:
            with open(xl, "wb") as f:
                f.write(render_xlsx(pub))
            paths["xlsx"] = xl
        except Exception as e:  # noqa: BLE001
            # 缺 openpyxl 不该让 md/json 一起失败 —— 那两个才是主产物
            paths["xlsx_error"] = str(e)[:160]
    except Exception:  # noqa: BLE001
        raise
    return paths


def available_dates(limit=60):
    """有报告的日期列表（新的在前）。从文件名读，不解内容 —— 列表页不该
    为了排序去把 30 份 xlsx 全 load 一遍。"""
    d = report_dir()
    found = {}
    try:
        for fn in os.listdir(d):
            m = _DAY_FILE_RE.match(fn)
            if not m:
                continue
            day = m.group(1)
            ent = found.setdefault(day, {"date": day, "formats": []})
            ent["formats"].append(m.group(2))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for day in sorted(found, reverse=True)[:limit]:
        ent = found[day]
        ent["formats"] = sorted(ent["formats"])
        out.append(ent)
    return out


def load_saved(date):
    """读已落盘的报告 JSON（供页面快速渲染，不必重算）。"""
    fp = _path(valid_date(date) or "", "json")
    if not os.path.exists(fp):
        return None
    try:
        with io.open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


def cleanup(retention_days=None, dry_run=False):
    """删除超过保留期的日报。

    只动 `data/daily_reports/` 下匹配 `YYYY-MM-DD.<ext>` 的文件 ——
    绝不做目录级递归删除（那是不可逆操作，且这个目录可能被人手工放过东西）。

    被删掉的日期记进 `_expired.json`。为什么记：光删文件的话，
    页面查 40 天前那天只会看到"没有报告"，用户分不清是"那天系统没跑"
    还是"报告已过保留期被清了" —— 后者其实是正常行为，不该让人以为丢了数据。
    不造占位的假报告文件（那会让"这天有报告"变成误导），只留一行日期记录。
    """
    keep = int(retention_days or RETENTION_DAYS)
    if keep < 1:
        keep = 1
    cutoff = time.localtime(time.time() - keep * 86400)
    cutoff_s = time.strftime("%Y-%m-%d", cutoff)
    d = report_dir()
    removed, kept = [], 0
    try:
        names = os.listdir(d)
    except Exception:  # noqa: BLE001
        return {"removed": [], "removed_count": 0, "kept": 0,
                "freed_bytes": 0, "freed_mb": 0,
                "cutoff": cutoff_s, "retention_days": keep}
    for fn in names:
        m = _DAY_FILE_RE.match(fn)
        if not m:
            continue                       # 不是日报文件，碰都不碰
        day = m.group(1)
        if day >= cutoff_s:
            kept += 1
            continue
        fp = os.path.join(d, fn)
        # 先量体积再删：反过来的话 getsize 必然抛 FileNotFoundError，
        # 报出来的 bytes 恒为 0，用户看不到"到底释放了多少空间"。
        sz = _size(fp)
        if dry_run:
            removed.append({"date": day, "file": fn, "bytes": sz})
            continue
        try:
            os.remove(fp)
            removed.append({"date": day, "file": fn, "bytes": sz})
        except Exception:  # noqa: BLE001
            kept += 1
    removed.sort(key=lambda x: (x["date"], x["file"]))
    freed = sum(x["bytes"] for x in removed)
    if removed and not dry_run:
        _remember_expired([x["date"] for x in removed])
    return {"removed": removed, "removed_count": len(removed), "kept": kept,
            "freed_bytes": freed, "freed_mb": round(freed / 1048576.0, 2),
            "cutoff": cutoff_s, "retention_days": keep}


_EXPIRED_CAP = 400          # 过期清单最多留 400 个日期，超了从旧往新砍


def _expired_path():
    return os.path.join(report_dir(), "_expired.json")


def _load_expired():
    try:
        with io.open(_expired_path(), "r", encoding="utf-8") as f:
            v = json.load(f)
        days = v.get("days") if isinstance(v, dict) else v
        return sorted({str(x)[:10] for x in (days or [])})
    except Exception:  # noqa: BLE001
        return []


def _remember_expired(days):
    all_days = sorted(set(_load_expired()) | {str(d)[:10] for d in days})
    if len(all_days) > _EXPIRED_CAP:
        all_days = all_days[-_EXPIRED_CAP:]
    try:
        with io.open(_expired_path(), "w", encoding="utf-8") as f:
            json.dump({"updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "days": all_days}, f, ensure_ascii=False, indent=1)
    except Exception:  # noqa: BLE001 —— 记不住不影响主流程（删都删完了）
        pass


def expired_days():
    """已被保留期清理掉的日期（新的在前）。给页面区分"没数据"与"已过期"。"""
    return sorted(_load_expired(), reverse=True)


def _size(fp):
    try:
        return os.path.getsize(fp)
    except OSError:
        return 0


def stats():
    """日报目录概况：给运维面板看"报告占了多少磁盘"。"""
    d = report_dir()
    total, files = 0, 0
    by_ext = {}
    other_bytes = 0
    try:
        for fn in os.listdir(d):
            fp = os.path.join(d, fn)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            # 只统计日报正文（匹配 YYYY-MM-DD.<ext>）；_expired.json 这类
            # 内部清单不能算进"报告份数"，否则面板会多报一份不存在的东西。
            if not _DAY_FILE_RE.match(fn):
                other_bytes += sz
                continue
            total += sz
            files += 1
            ext = fn.rsplit(".", 1)[-1]
            by_ext[ext] = by_ext.get(ext, 0) + sz
    except Exception:  # noqa: BLE001
        pass
    dates = available_dates(limit=400)
    return {
        "dir": d,
        "files": files,
        "total_bytes": total,
        "total_mb": round(total / 1048576.0, 2),
        "by_ext": by_ext,
        "other_bytes": other_bytes,
        "expired_days": len(_load_expired()),
        "date_count": len(dates),
        "retention_days": RETENTION_DAYS,
        "oldest": dates[-1]["date"] if dates else None,
        "newest": dates[0]["date"] if dates else None,
    }


if __name__ == "__main__":
    d = collect()
    print(json.dumps(_json_public(d), ensure_ascii=False, indent=1)[:2000])
    print("\n--- markdown 预览 ---")
    print(render_markdown(_json_public(d))[:1500])
    print("\n--- 可用日期 ---", available_dates())
    print("--- 目录概况 ---", json.dumps(stats(), ensure_ascii=False))
    print("--- 清理 dry-run ---", json.dumps(cleanup(dry_run=True), ensure_ascii=False))