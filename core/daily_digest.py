# -*- coding: utf-8 -*-
"""daily_digest.py —— 每日报告统一框架：AI 安全四方向 + 四模块台账（2026-10-07）

## 要解决什么

此前只有情报监测（m1_monitor）有日报（`core/daily_report.py`，按 AI 四分类 +
通用七类归档）。另外三个模块当天的产出**没有任何可归档的东西**：
智能编排跑了几轮编排、研判简报出了几条、处置回填了几条；情报富化做了几次
CMDB 扫描、命中多少资产风险；问答模块被问了几次、命中与耗时如何 ——
全在内存里，重启即丢，评审也看不到。

本模块把这些「当日台账」统一成同一套产物：

    data/daily_digests/<条目id>/<YYYY-MM-DD>.{md,json}

条目（2026-10-07 起）只有 **AI 安全四方向**（页面四张主卡）：
   ① 基础设施/推理框架 ② 模型与数据层 ③ 应用与智能体 ④ 供应链。
   方向报告**不重新分类**，直接取当日日报里已分好类的桶
   （DIR_CATEGORY 一一映射），分类口径全项目只有 taxonomy 一份。
   四个功能模块的运行台账已按用户要求去掉（MODULES/builders 保留为
   可复用口径函数，历史文件与直链兼容）。

并提供三件此前没有的能力：

1. **定时生成**：每天固定时刻（默认 23:30，`AISEC_DAILY_AT` 可改）出当天报告。
   用户原话是"当天晚上 12:30 出"，中文语境里 12:30 既可能指 23:30 也可能指
   00:30，所以两种都支持：配 `00:30` 时，凌晨那次调度**归属前一天**
   （`_target_date()` 里有明确注释），不需要改代码。
2. **出报告即提醒**：写站内通知（`data/notifications.json` → `/api/notifications`，
   前端自动弹条），配了 SMTP 再额外发一封邮件提醒。两者都失败也不影响报告本身。
3. **缺失补全**：启动时扫近 3 天窗口，缺哪天的方向报告就补哪天的
   （`catch_up()`）。服务没开过、机器关了一夜，都会自动补齐。
   ★ 只看近 3 天：方向报告的源（monitor_state 近 40 轮）老日期会被
   滚动掉，硬补会写出"当日无新增"的假话（见 catch_up 注释）。

## 为什么方向报告直接用日报的分类桶

分类口径必须全项目一份（`core/taxonomy.py:RISK_CATEGORIES`）。日报已经有
「按 AI 四分类 + 通用七类 + 严重度五档 + KEV/POC」这套完整口径，
在这里另写一套必然漂移 —— 同一页上两份报告对同一条漏洞给出不同分类，
评审一眼看穿。所以四方向 = 日报四个 AI 分类的按日切片 + 处置建议。

## 依赖方向

本模块**只读**各模块已落盘的产物（ops_briefs / cmdb_scans / qa_log …），
不 import 任何模块代码：模块可能没加载（config.json 里可以关），
日报不能因为某个模块缺席就整体失败 —— 缺席时该模块当天记 `empty_reason=no_module`。
"""
from __future__ import annotations

import datetime
import io
import json
import os
import re
import threading
import time
import zipfile

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import paths

try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None, note=""):
            pass


# --------------------------------------------------------------------------
# 模块注册表（2026-10-07 起不再作为每日报告条目）
# --------------------------------------------------------------------------
# 页面主视图改为 AI 安全四方向、模块台账已按用户要求去掉 —— 但四个
# builder（_build_m0/m1/m2/m3）**保留**：它们各自封装的口径（m2 的重复
# 扫描折叠、m3 的问答台账统计）仍有复用价值，回归测试也直接调用函数本体。
# 历史上落盘过的模块报告不删除，旧链接仍可按 id 直链下载（ENTRY_NAME 兼容）。
MODULES = [
    ("m1_monitor", "情报监测", "当日新增情报按 AI 四分类 + 通用七类归档，含在野利用与公开 POC"),
    ("m0_ops", "智能编排", "感知→研判→编排→处置四智能体的当日运行台账与决策留痕"),
    ("m2_enrich", "情报富化", "CMDB / 资产扫描 / 处置建议 / POC 的当日产出与风险命中"),
    ("m3_qa", "情报问答", "当日问答量、证据命中、耗时，以及语义检索与本地翻译能力状态"),
]
MODULE_IDS = [m[0] for m in MODULES]
MODULE_NAME = {m[0]: m[1] for m in MODULES}

# --------------------------------------------------------------------------
# AI 安全四方向（2026-10-07 新增，用户指定的四分类口径）
# --------------------------------------------------------------------------
# 页面的四张主卡片 = 这四个方向；四个功能模块（上面 MODULES）降级为
# 「产出台账」折叠区。方向报告**不是第四套分类**：直接取当日日报
# （core/daily_report.py）里已分好类的那个桶 —— 分类口径全项目只有一份
# （core/taxonomy.py:RISK_CATEGORIES），在这里重新分类必然漂移
# （同一条漏洞在检索页、日报、方向卡上会各说各话，评审一眼看穿）。
DIRECTIONS = [
    ("dir_infra", "① AI基础设施/推理框架风险",
     "Ollama、vLLM、Triton 等推理框架与 AI 基础设施组件的漏洞"),
    ("dir_model", "② 模型与数据层风险",
     "提示词注入、系统提示词泄漏、训练数据投毒等模型与数据层风险"),
    ("dir_appagent", "③ AI应用与智能体风险",
     "AI 应用、智能体（Agent）及其编排工具链的滥用与漏洞风险"),
    ("dir_supply", "④ 供应链风险",
     "模型仓库、AI 组件依赖、ML 平台与 CI/CD 引入的供应链风险"),
]
DIR_IDS = [d[0] for d in DIRECTIONS]
DIR_NAME = {d[0]: d[1] for d in DIRECTIONS}
# 方向 → 日报分类键（与 core/daily_report.py:_CAT_ORDER 同一份口径）
DIR_CATEGORY = {
    "dir_infra": "① AI基础设施与推理框架",
    "dir_model": "② 模型与数据层",
    "dir_appagent": "③ AI应用与智能体",
    "dir_supply": "④ AI供应链与平台",
}
# 方向卡片强调色：与分类色一致（taxonomy 的 color），兜底值与其保持同步
_DIR_COLOR_FALLBACK = {
    "dir_infra": "#e3b04b", "dir_model": "#2fbf9e",
    "dir_appagent": "#e8913c", "dir_supply": "#f2c94c",
}


def _dir_color(did):
    try:
        from taxonomy import RISK_CATEGORIES
        c = (RISK_CATEGORIES.get(DIR_CATEGORY.get(did, "")) or {}).get("color")
        if c:
            return c
    except Exception:  # noqa: BLE001
        pass
    return _DIR_COLOR_FALLBACK.get(did, "#b9a284")


# 模块 + 方向 的合并名称表：server 的 module 参数校验、build() 的名称
# 填充都用它。模块 id 保留进表是**历史兼容** —— 台账去掉之前落盘的
# 模块报告，旧直链仍能下载；新生成只产方向（见 generate_all）。
ENTRY_NAME = dict(MODULE_NAME)
ENTRY_NAME.update(DIR_NAME)

RETENTION_DAYS = int(os.environ.get("AISEC_DIGEST_KEEP_DAYS", "30") or 30)

# 每天几点出当天报告。默认 23:30（当天采集基本结束，出的是"今天这一天"）。
# 配 "00:30" 表示"当天晚上 12:30"= 次日零点那一刻出，归属日按前一天算。
DAILY_AT = (os.environ.get("AISEC_DAILY_AT") or "23:30").strip()

_LOCK = threading.Lock()
_DAY_FILE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.(md|json)$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_NOTIFY_CAP = 60


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def today():
    return time.strftime("%Y-%m-%d")


def valid_date(s):
    """合法日期。**必须用 datetime 校真实日历**，不能只判 d<=31 ——
    2026-02-30 / 2026-13-01 都会先被范围检查放过去，然后当成真日期
    落盘成文件名（`2026-02-30.json`），列表页看着像有数据，实际永远
    等不到那一天。"""
    s = str(s or "")
    if not _DATE_RE.match(s):
        return None
    try:
        y, m, d = (int(x) for x in s.split("-"))
        if not (1970 <= y <= 2100):
            return None
        datetime.date(y, m, d)          # 真实日历校验：2/30、13/1 会抛
    except (ValueError, TypeError):
        return None
    return s


def root():
    d = os.path.join(paths.DATA_DIR, "daily_digests")
    os.makedirs(d, exist_ok=True)
    return d


def module_dir(mid):
    d = os.path.join(root(), mid)
    os.makedirs(d, exist_ok=True)
    return d


def _path(mid, day, fmt="json"):
    return os.path.join(module_dir(mid), "%s.%s" % (day, fmt))


def _read_json(fp, default):
    try:
        with io.open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def _day_of(rec, *keys):
    """从记录里取日期：优先 created_at / ts / at / date（前 10 位）。"""
    for k in keys:
        v = str((rec or {}).get(k) or "")[:10]
        if _DATE_RE.match(v):
            return v
    return ""


def _num(v, default=0):
    try:
        if v is None or v == "" or isinstance(v, bool):
            return default
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _fmt_num(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return str(v)
    return "{:,}".format(n)


# --------------------------------------------------------------------------
# 各模块 provider —— 全部只读已落盘产物，绝不编造数字
# --------------------------------------------------------------------------
def _build_m1(day, coll=None):
    """情报监测：直接复用 core/daily_report（分类口径唯一来源）。

    coll：调用方（generate_all）预取好的日报 collect 结果。m1 与四方向
    共用同一份 —— 不传就自己取（单报告路径），传了就不再读一遍
    live_feed / monitor_state / kev 三个源。
    """
    try:
        import daily_report as D
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:m1", e)
        return _empty("m1_monitor", day, "no_module", "日报引擎未加载")
    try:
        d = D._json_public(coll if coll is not None else D.collect(day))
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:m1.collect", e)
        return _empty("m1_monitor", day, "error", str(e)[:160])
    bs = d.get("by_sev") or {}
    total = _num(d.get("total"))
    metrics = [
        {"k": "新增情报", "v": "%s 条" % _fmt_num(total), "hint": "快车道实时流 + 定时增量同步当天入库 + KEV"},
        {"k": "覆盖分类", "v": "%s 类" % d.get("category_count", 0), "hint": "AI 四大类（基础设施/模型数据/应用智能体/供应链）"},
        {"k": "严重 / 高危", "v": "%s / %s" % (_fmt_num(bs.get("critical")),
                                              _fmt_num(bs.get("high"))),
         "hint": "CVSS≥9 严重、≥7 高危；KEV 一律计严重"},
        {"k": "在野利用 KEV", "v": "%s 条" % _num(d.get("kev")), "hint": "CISA KEV 当天新增"},
        {"k": "含公开 POC", "v": "%s 条" % _num(d.get("poc")), "hint": "存在可直接利用的公开代码"},
    ]
    rows = []
    for c in (d.get("categories") or []):
        b = c.get("by_sev") or {}
        rows.append([c.get("full") or c.get("key"), _fmt_num(c.get("count", 0)),
                     _fmt_num(b.get("critical")), _fmt_num(b.get("high")),
                     _fmt_num(b.get("medium")), _fmt_num(b.get("low")),
                     _fmt_num(b.get("info"))])
    rows.sort(key=lambda r: -_num(r[1]))
    headline = ("当日无新增情报。" if not total else
                "当日入库 %s 条，其中严重 %s、高危 %s、在野利用 %s 条。"
                % (_fmt_num(total), _fmt_num(bs.get("critical")),
                   _fmt_num(bs.get("high")), _fmt_num(d.get("kev"))))
    # 通用网络安全情报数（只计入总数、不单独列类）
    gcnt = _num(d.get("general_count"))
    if gcnt:
        headline += "（其中通用网络安全情报 %s 条未列入 AI 四大类）" % _fmt_num(gcnt)
    # ★ 这天一条都没收到 → 标 no_data，generate_all 会跳过落盘
    return {
        "headline": headline,
        "metrics": metrics,
        "empty_reason": "" if total else "no_data",
        "empty_note": "" if total else "当天未采集到任何情报条目",
        "sections": [{
            "title": "按风险分类明细",
            "type": "table",
            "cols": ["风险分类", "条目", "严重", "高危", "中危", "低危", "资讯"],
            "rows": rows,
        }],
        "extra": {"risk_report_date": day,
                  "risk_categories": d.get("category_count", 0),
                  "general_count": _num(d.get("general_count")),
                  "retention_days": D.RETENTION_DAYS},
    }


def _action_for(it):
    """处置建议：口径与 daily_report 渲染的「处置建议」段保持一致
    （KEV 优先于分数、有 POC 提示核查资产）。方向卡上是同一套话术，
    避免两处给评审两种说法。"""
    act = []
    if it.get("kev"):
        act.append("**已在野利用**，按应急预案立即处置")
    cv = _num(it.get("cvss"))
    if cv >= 9:
        act.append("CVSS %.1f，建议 24h 内出修复方案" % cv)
    elif cv >= 7:
        act.append("CVSS %.1f，建议 7 天内纳入版本迭代" % cv)
    if it.get("poc"):
        act.append("已有公开 POC，需核查自身资产是否受影响")
    prods = it.get("products") or []
    if prods:
        act.append("受影响产品：%s（对照自有资产核查）" % "、".join(str(p) for p in prods[:3]))
    return "；".join(act) or "列入常规跟踪"


def _build_direction(day, did, coll=None):
    """AI 安全四方向报告：取当日日报里该方向已分好类的桶。

    为什么不复述一套分类：方向 ↔ 日报分类是一一映射（DIR_CATEGORY），
    条目的 category 字段由引擎写好、日报按它分桶 —— 这里只做"切片 +
    换个组织视角"，分类判定零重复。这样检索页、m1 日报、方向卡三处
    对同一条漏洞给出同一个分类，评审核不出矛盾。

    当天该方向 0 条 → **照常落盘**、如实写「当日无新增」
    （单方向无产出是正常状态，跳过会让页面凭空少一张卡 —— 与模块
    台账同一原则，见 generate_all 注释）。
    """
    try:
        import daily_report as D
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:dir", e)
        return _empty(did, day, "no_module", "日报引擎未加载")
    try:
        if coll is None:
            coll = D.collect(day)
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:dir.collect", e)
        return _empty(did, day, "error", str(e)[:160])
    cat_key = DIR_CATEGORY.get(did, "")
    cat = next((c for c in (coll.get("categories") or [])
                if c.get("key") == cat_key), None)
    items = (cat or {}).get("items") or []
    count = _num((cat or {}).get("count"))
    bs = (cat or {}).get("by_sev") or {}
    kev = _num((cat or {}).get("kev"))
    poc = _num((cat or {}).get("poc"))
    # 高频受影响产品（条目里 products 的出现次数 Top3）
    pc = {}
    for it in items:
        for p in (it.get("products") or []):
            p = str(p).strip()
            if p:
                pc[p] = pc.get(p, 0) + 1
    top_p = sorted(pc.items(), key=lambda kv: -kv[1])[:3]
    metrics = [
        {"k": "当日条目", "v": "%s 条" % _fmt_num(count),
         "hint": "该方向当天新增（按系统检测日归日，与日报同一口径）"},
        {"k": "严重 / 高危", "v": "%s / %s" % (_fmt_num(bs.get("critical")),
                                              _fmt_num(bs.get("high"))),
         "hint": "CVSS≥9 严重、≥7 高危；KEV 一律计严重"},
        {"k": "在野利用 KEV", "v": "%s 条" % _fmt_num(kev),
         "hint": "当天新增且属于该方向的 CISA KEV"},
        {"k": "含公开 POC", "v": "%s 条" % _fmt_num(poc),
         "hint": "存在可直接利用的公开代码"},
        {"k": "中危 / 低危 / 资讯",
         "v": "%s / %s / %s" % (_fmt_num(bs.get("medium")), _fmt_num(bs.get("low")),
                                _fmt_num(bs.get("info"))),
         "hint": "资讯=无 CVSS 的研究/博客条目，不当低危计"},
    ]
    if top_p:
        metrics.append({"k": "高频受影响产品",
                        "v": "、".join(p for p, _ in top_p) or "—",
                        "hint": "按该方向条目的受影响产品出现次数 Top3"})
    # 明细表：severity 已在日报里排好序（严重在前），照单切片
    rows = [[it.get("severity_label") or "—", it.get("cvss") or "—",
             str(it.get("title") or "")[:70], str(it.get("source") or "")[:24],
             it.get("published") or "—", "✓" if it.get("kev") else "",
             "✓" if it.get("poc") else "",
             "、".join(str(p) for p in (it.get("products") or [])[:3]) or "—"]
            for it in items[:60]]
    sections = []
    if rows:
        sections.append({"title": "当日明细（按严重度排序，最多 60 条）",
                         "type": "table",
                         "cols": ["严重度", "CVSS", "标题", "来源", "发布",
                                  "KEV", "POC", "受影响产品"],
                         "rows": rows})
    act_rows = [[it.get("severity_label") or "—", str(it.get("title") or "")[:60],
                 _action_for(it)]
                for it in items if it.get("severity") in ("critical", "high")][:10]
    if act_rows:
        sections.append({"title": "处置建议（严重 / 高危）", "type": "table",
                         "cols": ["严重度", "条目", "建议行动"], "rows": act_rows})
    headline = ("当日该方向无新增情报。"
                if not count else
                "当日该方向新增 %s 条：严重 %s、高危 %s、在野利用 %s、含公开 POC %s。"
                % (_fmt_num(count), _fmt_num(bs.get("critical")),
                   _fmt_num(bs.get("high")), _fmt_num(kev), _fmt_num(poc)))
    return {"headline": headline, "metrics": metrics, "sections": sections,
            "color": _dir_color(did),
            "empty_reason": "" if count else "no_data",
            "empty_note": "" if count else "当天该方向没有新增情报条目"}


def _build_m0(day):
    """智能编排：简报 / 决策 / 事件 / 处置回填的当日条数。"""
    briefs = _read_json(os.path.join(paths.DATA_DIR, "ops_briefs.json"), []) or []
    events = _read_json(os.path.join(paths.DATA_DIR, "ops_events.json"), []) or []
    disp = _read_json(os.path.join(paths.DATA_DIR, "dispositions.json"), []) or []

    def of_day(rows, keys):
        return [r for r in (rows if isinstance(rows, list) else [])
                if isinstance(r, dict) and _day_of(r, *keys) == day]

    b_d = of_day(briefs, ("ts", "at", "created_at"))
    e_d = of_day(events, ("ts", "at", "created_at"))
    d_d = of_day(disp, ("ts", "at", "created_at"))
    prio = {}
    for r in b_d:
        dec = (r.get("decision") or {}) if isinstance(r.get("decision"), dict) else {}
        p = str(dec.get("priority") or "").strip() or "未标注"
        prio[p] = prio.get(p, 0) + 1
    metrics = [
        {"k": "编排轮次产出（简报）", "v": "%s 条" % len(b_d), "hint": "研判智能体为事件出具的简报"},
        {"k": "事件流水", "v": "%s 条" % len(e_d), "hint": "感知智能体发现 / 处置 / 失败事件"},
        {"k": "处置回填", "v": "%s 条" % len(d_d), "hint": "人工回填处置结果（闭环·自我进化入口）"},
        {"k": "决策优先级分布", "v": "、".join("%s×%s" % (k, v)
                                             for k, v in sorted(prio.items())) or "—",
         "hint": "编排智能体给出的优先级"},
    ]
    rows = []
    for r in b_d[:20]:
        ev = (r.get("event") or {}) if isinstance(r.get("event"), dict) else {}
        dec = (r.get("decision") or {}) if isinstance(r.get("decision"), dict) else {}
        rows.append([str(r.get("ts") or "")[11:16] or "—",
                     str(ev.get("id") or "—")[:28],
                     str(dec.get("priority") or "—"),
                     str(r.get("brief_mode") or r.get("decision_mode") or "—"),
                     str(ev.get("title") or ev.get("reason") or "")[:60]])
    headline = ("当日编排智能体未产出简报（编排器可能未启用或没有新事件）。" if not b_d
                else "当日产出研判简报 %s 条、事件流水 %s 条、处置回填 %s 条。"
                     % (len(b_d), len(e_d), len(d_d)))
    return {"headline": headline, "metrics": metrics,
            "empty_reason": "" if (b_d or e_d or d_d) else "no_data",
            "empty_note": "" if (b_d or e_d or d_d) else "当天无编排事件与简报记录",
            "sections": ([{"title": "简报与决策留痕（最近 20 条）", "type": "table",
                           "cols": ["时间", "事件", "优先级", "模式", "摘要"], "rows": rows}]
                         if rows else [])}


def _build_m2(day):
    """情报富化：CMDB 审计 / 资产扫描的当日产出与风险命中。"""
    cmdb = _read_json(os.path.join(paths.DATA_DIR, "cmdb_scans.json"), []) or []
    asset = _read_json(os.path.join(paths.DATA_DIR, "asset_scans.json"), []) or []

    def of_day(rows):
        return [r for r in (rows if isinstance(rows, list) else [])
                if isinstance(r, dict) and _day_of(r, "created_at", "ts", "at") == day]

    c_d, a_d = of_day(cmdb), of_day(asset)

    def _src_key(r):
        """一次扫描的"数据源"标识。同一个源当天被反复扫（改完再扫、自检、
        压测都会），累加会把同一批资产数加好几遍 —— 日报里的数字必须先按源去重。"""
        for k in ("source_name", "source", "file", "filename", "cmdb_id"):
            v = str(r.get(k) or "").strip()
            if v:
                return v
        return str(r.get("id") or "")

    def dedup(rows):
        """同一数据源只留当天最后一次扫描；顺带如实报出重复了几次。"""
        latest = {}
        for r in rows:
            k = _src_key(r)
            cur = latest.get(k)
            if cur is None or str(r.get("created_at") or "") >= str(cur.get("created_at") or ""):
                latest[k] = r
        uniq = sorted(latest.values(),
                      key=lambda r: str(r.get("created_at") or ""), reverse=True)
        return uniq, len(rows) - len(uniq)

    def agg(rows):
        out = {"scans": len(rows), "hosts": 0, "cve_hits": 0, "critical": 0,
               "high": 0, "medium": 0, "low": 0, "exploited": 0, "products": 0,
               "risk_hosts": 0}
        for r in rows:
            s = r.get("summary") or {}
            if not isinstance(s, dict):
                continue
            for k in ("hosts", "cve_hits", "critical", "high", "medium", "low",
                      "exploited", "products", "risk_hosts"):
                out[k] += _num(s.get(k))
        return out

    c_u, c_rep = dedup(c_d)          # 去重后的当日扫描
    a_u, a_rep = dedup(a_d)
    ca, aa = agg(c_u), agg(a_u)
    n_scan = len(c_d) + len(a_d)
    n_rep = c_rep + a_rep
    metrics = [
        {"k": "CMDB 审计", "v": "%s 次" % len(c_u), "hint": "按漏洞台账对账 CMDB 受影响资产"},
        {"k": "CMDB 风险命中", "v": "%s 条" % _fmt_num(ca["cve_hits"]),
         "hint": "严重 %s / 高危 %s / 在野 %s"
                 % (_fmt_num(ca["critical"]), _fmt_num(ca["high"]), ca["exploited"])},
        {"k": "资产扫描", "v": "%s 次" % len(a_u), "hint": "上传资产清单（xlsx）扫描"},
        {"k": "资产风险命中", "v": "%s 条" % _fmt_num(aa["cve_hits"]),
         "hint": "严重 %s / 高危 %s / 在野 %s"
                 % (_fmt_num(aa["critical"]), _fmt_num(aa["high"]), aa["exploited"])},
        {"k": "风险主机", "v": "%s 台" % _fmt_num(ca["risk_hosts"] + aa["risk_hosts"]),
         "hint": "命中风险的去重主机数"},
        {"k": "覆盖主机 / 组件", "v": "%s / %s" % (_fmt_num(ca["hosts"] + aa["hosts"]),
                                                  _fmt_num(ca["products"] + aa["products"])),
         "hint": "CMDB + 资产清单合计"},
    ]
    if n_rep:
        metrics.append({"k": "重复扫描已折叠", "v": "%s 次" % n_rep,
                        "hint": "同一数据源当天被重复扫描，只计最后一次，避免数字虚高"})
    rows = []
    for r, kind in ([(x, "CMDB 审计") for x in c_u] + [(x, "资产扫描") for x in a_u])[:20]:
        s = r.get("summary") or {}
        rows.append([str(r.get("id") or "—")[:26], kind,
                     _fmt_num(s.get("hosts")), _fmt_num(s.get("cve_hits")),
                     _fmt_num(s.get("critical")), _fmt_num(s.get("high")),
                     _fmt_num(s.get("exploited"))])
    headline = ("当日没有 CMDB / 资产扫描产出（未上传台账或未触发扫描）。"
                if not (c_u or a_u) else
                "当日 CMDB 审计 %s 次、资产扫描 %s 次，命中风险 %s 条（严重 %s、高危 %s、在野 %s）。"
                % (len(c_u), len(a_u), _fmt_num(ca["cve_hits"] + aa["cve_hits"]),
                   _fmt_num(ca["critical"] + aa["critical"]),
                   _fmt_num(ca["high"] + aa["high"]),
                   ca["exploited"] + aa["exploited"]))
    if n_rep:
        headline += "（另有 %s 次为同一数据源的重复扫描，未计入）" % n_rep
    return {"headline": headline, "metrics": metrics,
            "empty_reason": "" if (c_u or a_u) else "no_data",
            "empty_note": "" if (c_u or a_u) else "当天没有 CMDB / 资产扫描记录",
            "sections": ([{"title": "当日扫描明细（按数据源去重，最近 20 次）",
                           "type": "table",
                           "cols": ["报告号", "类型", "主机", "命中", "严重", "高危", "在野"],
                           "rows": rows}] if rows else [])}


def _build_m3(day):
    """情报问答：当日问答台账（data/qa_log.jsonl）+ 能力状态。

    问答台账是本轮新加的（`modules/m3_qa/api.py:_log_qa`）：此前问答只在内存里
    走一圈就丢，"今天被问了几次 / 命中率如何"根本查不到。这里只统计真实记录，
    没有记录就如实写 0 —— 不用"预计""估算"糊弄。
    """
    fp = os.path.join(paths.DATA_DIR, "qa_log.jsonl")
    rows_all = []
    try:
        if os.path.isfile(fp):
            with io.open(fp, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        o = json.loads(s)
                    except Exception:  # noqa: BLE001
                        continue
                    if isinstance(o, dict) and str(o.get("ts") or "")[:10] == day:
                        rows_all.append(o)
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:m3", e)

    n = len(rows_all)
    hit = sum(1 for o in rows_all if _num(o.get("sources")) > 0)
    err = sum(1 for o in rows_all if o.get("error"))
    lats = sorted(_num(o.get("ms")) for o in rows_all if _num(o.get("ms")) > 0)
    med = lats[len(lats) // 2] if lats else 0
    llm = sum(1 for o in rows_all if o.get("used_llm"))

    # 能力状态：只报"就绪/未就绪"，不猜
    caps = []
    try:
        import sys as _sys
        if paths.DATA_DIR not in _sys.path:
            pass
        base = os.path.join(paths.DATA_DIR, "..", "modules", "m3_qa", "backend")
        if base not in _sys.path:
            _sys.path.insert(0, base)
        from qa.translator import runtime_deps  # type: ignore
        from qa.translator import find_local_dir  # type: ignore
        deps = runtime_deps()
        mdir = find_local_dir()
        caps.append(("本地翻译模型", "就绪" if (deps.get("ok") and mdir) else "未就绪",
                     deps.get("hint") or ("模型目录 " + mdir if mdir else "未下载")))
    except Exception:  # noqa: BLE001
        caps.append(("本地翻译模型", "未知", "qa 包不可用"))
    try:
        from qa.local_embedder import local_embedder  # type: ignore
        st = local_embedder.status()
        caps.append(("语义嵌入模型", "就绪" if st.get("ready") else "未就绪",
                     str(st.get("dir") or "未下载")))
    except Exception:  # noqa: BLE001
        caps.append(("语义嵌入模型", "未知", "qa 包不可用"))

    metrics = [
        {"k": "当日问答", "v": "%s 次" % n, "hint": "来自 data/qa_log.jsonl 的真实请求记录"},
        {"k": "证据命中", "v": "%s 次（%.0f%%）" % (hit, (hit / n * 100) if n else 0),
         "hint": "检索到至少一条证据的问答占比"},
        {"k": "中位耗时", "v": ("%s ms" % med) if med else "—", "hint": "问答端到端耗时中位数"},
        {"k": "走大模型", "v": "%s 次" % llm, "hint": "未配 Key 时走检索证据模板"},
        {"k": "异常", "v": "%s 次" % err, "hint": "问答服务返回 error 的次数"},
    ]
    top = {}
    for o in rows_all:
        q = str(o.get("q") or "").strip()
        if q:
            top[q[:60]] = top.get(q[:60], 0) + 1
    hot = sorted(top.items(), key=lambda kv: -kv[1])[:8]
    sections = []
    if hot:
        sections.append({"title": "当日高频问题（Top 8）", "type": "table",
                         "cols": ["问题", "次数"], "rows": [[k, v] for k, v in hot]})
    sections.append({"title": "能力状态", "type": "table",
                     "cols": ["能力", "状态", "说明"],
                     "rows": [[a, b, c] for a, b, c in caps]})
    headline = ("当日没有问答记录。" if not n else
                "当日问答 %s 次，证据命中 %s 次（%.0f%%），中位耗时 %s ms。"
                % (n, hit, (hit / n * 100) if n else 0, med or "—"))
    return {"headline": headline, "metrics": metrics, "sections": sections,
            "empty_reason": "" if n else "no_data",
            "empty_note": "" if n else "当天 data/qa_log.jsonl 无问答记录"}


def _empty(mid, day, reason, note=""):
    return {"headline": "当日无可归档的产出。", "metrics": [], "sections": [],
            "empty_reason": reason, "empty_note": note}


_BUILDERS = {
    "m1_monitor": _build_m1,
    "m0_ops": _build_m0,
    "m2_enrich": _build_m2,
    "m3_qa": _build_m3,
}


def build(eid, date=None, coll=None):
    """生成某条目（模块或方向）某天的报告数据（不落盘）。

    coll：预取好的日报 collect 结果（generate_all 传入，m1 + 四方向共用）。
    """
    day = valid_date(date) or today()
    if eid in DIR_IDS:
        kind = "direction"
    elif eid in _BUILDERS:
        kind = "module"
    else:
        return None
    t0 = time.time()
    try:
        if kind == "direction":
            part = _build_direction(day, eid, coll) or {}
        elif eid == "m1_monitor":            # 唯一吃 coll 的模块 builder
            part = _BUILDERS[eid](day, coll) or {}
        else:
            part = _BUILDERS[eid](day) or {}
    except Exception as e:  # noqa: BLE001 —— 单条失败不能带塌整份日报
        _swallow("core/daily_digest.py:build:%s" % eid, e)
        part = _empty(eid, day, "error", str(e)[:160])
    rep = {
        "module": eid,
        "module_name": ENTRY_NAME.get(eid, eid),
        "kind": kind,
        "date": day,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seconds": round(time.time() - t0, 2),
    }
    if kind == "direction":
        rep["category"] = DIR_CATEGORY.get(eid, "")
    rep.update(part)
    rep.setdefault("empty_reason", "")
    rep.setdefault("empty_note", "")
    return rep


# --------------------------------------------------------------------------
# 渲染
# --------------------------------------------------------------------------
def _md_esc(s):
    return str(s or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def render_markdown(rep):
    L = ["# %s · 每日报告 · %s" % (rep.get("module_name") or rep.get("module"), rep.get("date")),
         "",
         "> 生成时间：%s ｜ 耗时 %.2fs" % (rep.get("generated_at"), float(rep.get("seconds") or 0)),
         ""]
    if rep.get("empty_reason") == "no_module":
        L += ["> 该模块当前未加载（config.json 的 modules 开关）。", ""]
    if rep.get("empty_reason") == "error":
        L += ["> 生成出错：%s" % _md_esc(rep.get("empty_note")), ""]
    L += ["## 一、当日结论", "", rep.get("headline") or "—", ""]
    if rep.get("metrics"):
        L += ["## 二、关键指标", "", "| 指标 | 数值 | 说明 |", "|---|---:|---|"]
        for m in rep["metrics"]:
            L.append("| %s | **%s** | %s |" % (_md_esc(m.get("k")), _md_esc(m.get("v")),
                                              _md_esc(m.get("hint"))))
        L.append("")
    if rep.get("sections"):
        L.append("## 三、明细")
        L.append("")
        for i, sec in enumerate(rep["sections"], 1):
            L.append("### 3.%d %s" % (i, _md_esc(sec.get("title"))))
            L.append("")
            cols = sec.get("cols") or []
            rows = sec.get("rows") or []
            if not rows:
                L += ["（无数据）", ""]
                continue
            L.append("| " + " | ".join(_md_esc(c) for c in cols) + " |")
            L.append("|" + "|".join(["---"] * len(cols)) + "|")
            for r in rows[:200]:
                r = list(r) + [""] * (len(cols) - len(r))
                L.append("| " + " | ".join(_md_esc(x) for x in r[:len(cols)]) + " |")
            if len(rows) > 200:
                L.append("")
                L.append("> 另有 %d 行未列出（见 JSON 版）。" % (len(rows) - 200))
            L.append("")
    L += ["## 四、口径说明", "",
          "- 本报告由 `core/daily_digest.py` 于每日定点自动生成，"
          "数据全部来自各模块已落盘的产物，不含人工估算。"]
    if rep.get("kind") == "direction":
        L += ["- 本报告是「AI 安全四方向」按日归档的一份：条目直接取自当日日报"
              "（`core/daily_report.py`）中「%s」分类桶，"
              "分类判定与检索页 / 日报同源（`core/taxonomy.py`），此处不重复分类。"
              % rep.get("category", "")]
    L += ["- 生成时刻：`AISEC_DAILY_AT`（当前 %s）；保留 %d 天。"
          % (DAILY_AT, RETENTION_DAYS),
          "- 某模块当天没有产出时，如实写 0 / 「当日无可归档的产出」，"
          "**不用上一日的数字顶替**。", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# 落盘 / 读取 / 清理
# --------------------------------------------------------------------------
def save(rep):
    mid, day = rep.get("module"), rep.get("date")
    if not mid or not day:
        return {}
    md = _path(mid, day, "md")
    js = _path(mid, day, "json")
    out = {}
    try:
        with io.open(md, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_markdown(rep))
        out["md"] = md
        with io.open(js, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        out["json"] = js
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:save", e)
        out["error"] = str(e)[:160]
    return out


# --------------------------------------------------------------------------
# 打包下载（当天四份一次拿走）
# --------------------------------------------------------------------------
def build_zip(day=None, fmts=("md", "json")):
    """把某天**实际存在**的方向报告打成一个 zip，返回 (bytes, 文件名列表)。

    为什么要有「打包」：四份报告要点四次才下全，用户会以为只下了一份。
    `zipfile` 是标准库，不需要新增依赖。

    **只打真实存在的文件**，不存在的条目直接跳过并在清单里注明 ——
    打出一个空文件名的条目会让解压软件报错。
    2026-10-07 起只打四方向（模块台账已去掉，历史模块文件不进包）。
    """
    d = valid_date(day) or target_date()
    if not d:
        return None, []
    buf = io.BytesIO()
    included = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for did, name, _desc in DIRECTIONS:
            rep = load(did, d)
            if not isinstance(rep, dict):
                continue
            got = []
            for fmt in fmts:
                fp = _path(did, d, fmt)
                if not os.path.isfile(fp):
                    continue
                try:
                    with open(fp, "rb") as f:
                        z.writestr("%s_%s.%s" % (did, d, fmt), f.read())
                    got.append(fmt)
                except Exception as e:  # noqa: BLE001
                    _swallow("core/daily_digest.py:zip:%s" % did, e)
            if got:
                included.append("%s（%s）" % (name, "/".join(got)))
            else:
                # 没有落盘文件：现生成一份 md 进包，至少让用户拿到可读内容
                try:
                    z.writestr("%s_%s.md" % (did, d),
                               render_markdown(rep).encode("utf-8"))
                    included.append("%s（md·现场生成）" % name)
                except Exception as e:  # noqa: BLE001
                    _swallow("core/daily_digest.py:zip-gen:%s" % did, e)
        # 放一份清单，收到压缩包的人不看代码也知道里面有什么
        readme = ["# %s AI 安全四方向每日报告" % d, "",
                  "生成时刻：%s" % time.strftime("%Y-%m-%d %H:%M:%S"), "",
                  "## 本包内容" if included else "## 本包内容", ""]
        readme += ["- %s" % x for x in (included or ["（当天没有任何方向产出）"])] or []
        readme += ["", "---", "",
                   "由 AI-SecIntel 2.0 `core/daily_digest.py` 自动生成。",
                   "四方向条目取自当日日报的 AI 四分类桶（口径同检索页），",
                   "数据不含人工估算。"]
        z.writestr("README.txt", "\n".join(readme).encode("utf-8"))
    return buf.getvalue(), included


def load(mid, date):
    day = valid_date(date)
    if not day:
        return None
    return _read_json(_path(mid, day, "json"), None)


def available_dates(mid, limit=RETENTION_DAYS + 5):
    try:
        names = os.listdir(module_dir(mid))
    except Exception:  # noqa: BLE001
        return []
    days = {m.group(1) for fn in names if (m := _DAY_FILE_RE.match(fn))}
    return sorted(days, reverse=True)[:limit]


def has(mid, date):
    day = valid_date(date)
    return bool(day) and os.path.isfile(_path(mid, day, "json"))


MIME = {
    "md": "text/markdown; charset=utf-8",
    "json": "application/json; charset=utf-8",
}


def list_all(days=None):
    """四方向 × 每天 的格子表，供页面渲染日历/矩阵。

    每格只放「一句话摘要 + 前 6 个指标」，**不放 sections** —— 30 天 × 4
    方向的完整报告会轻易上兆，前端一次拉全量必卡。

    2026-10-07 起只返回方向（模块台账已按用户要求去掉）；
    grid 里也只放方向格。
    """
    n = max(1, min(int(days or (RETENTION_DAYS + 5)), RETENTION_DAYS + 30))
    per = {}
    for did, name, _desc in DIRECTIONS:
        for d in available_dates(did, n):
            rep = load(did, d)
            if not isinstance(rep, dict):
                continue
            per.setdefault(d, {})[did] = {
                "module": did, "module_name": name, "kind": "direction",
                "color": rep.get("color") or "",
                "headline": rep.get("headline") or "",
                "metrics": (rep.get("metrics") or [])[:6],
                "has_md": os.path.isfile(_path(did, d, "md")),
                "empty_reason": rep.get("empty_reason") or "",
            }
    days_sorted = sorted(per.keys(), reverse=True)[:n]
    return {"days": days_sorted, "retention_days": RETENTION_DAYS,
            "daily_at": DAILY_AT,
            "directions": [{"id": i, "name": nm, "desc": ds,
                            "color": _dir_color(i)} for i, nm, ds in DIRECTIONS],
            "grid": [{"date": d, "modules": per[d]} for d in days_sorted],
            "missing": missing_days(RETENTION_DAYS)}


def summary_of(rep):
    """列表页要的那几项（丢掉 sections，避免 30 天 × 4 模块把响应撑爆）。"""
    if not rep:
        return None
    return {"module": rep.get("module"), "module_name": rep.get("module_name"),
            "date": rep.get("date"), "generated_at": rep.get("generated_at"),
            "headline": rep.get("headline"),
            "metrics": rep.get("metrics") or [],
            "empty_reason": rep.get("empty_reason") or ""}


def cleanup(retention_days=None, dry_run=False):
    keep = int(retention_days or RETENTION_DAYS)
    if keep < 1:
        keep = 1
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - keep * 86400))
    removed, kept = [], 0
    for eid in MODULE_IDS + DIR_IDS:      # 方向报告与模块报告同一保留期
        try:
            names = os.listdir(module_dir(eid))
        except Exception:  # noqa: BLE001
            continue
        for fn in names:
            m = _DAY_FILE_RE.match(fn)
            if not m:
                continue                       # 不是日报文件，碰都不碰
            if m.group(1) >= cutoff:
                kept += 1
                continue
            fp = os.path.join(module_dir(eid), fn)
            if dry_run:
                removed.append({"module": eid, "date": m.group(1), "file": fn})
                continue
            try:
                os.remove(fp)
                removed.append({"module": eid, "date": m.group(1), "file": fn})
            except Exception:  # noqa: BLE001
                kept += 1
    removed.sort(key=lambda x: (x["date"], x["module"]))
    return {"removed": removed, "removed_count": len(removed), "kept": kept,
            "cutoff": cutoff, "retention_days": keep, "dry_run": bool(dry_run)}


# --------------------------------------------------------------------------
# 生成 / 补全 / 提醒
# --------------------------------------------------------------------------
def generate_all(date=None, only_missing=False, notify=True):
    """生成某天 AI 安全四方向的报告。only_missing=True 时只补缺的。

    ★ 整日全空才不产出、不落盘（见下）。
    单个方向当天没产出**照常落盘**，内容如实写「当日无新增」——
    这两件事必须分开：
      · "该方向今天无新增"是**正常的系统状态**，跳过会让页面凭空
        少一张卡，用户以为报告没生成出来；
      · "1999-01-01 四份全空" 才是这天真的不存在。
    实测踩过：早先按单条目 no_data 跳过，列表上会凭空少格。

    2026-10-07 起只生成四方向（模块台账已按用户要求去掉；
    _build_m0/m1/m2/m3 保留为可复用的口径函数，见 MODULES 注释）。
    四方向共用**同一份**日报 collect 结果：collect 要读 live_feed /
    monitor_state / kev 三个源，不共享的话一次生成把同样的文件读 4 遍。
    """
    day = valid_date(date) or today()
    coll = None
    try:
        import daily_report as _D
        coll = _D.collect(day)
    except Exception as e:  # noqa: BLE001 —— collect 失败时各 builder 自行兜底重取
        _swallow("core/daily_digest.py:generate_all.collect", e)
        coll = None
    out = []
    for did in DIR_IDS:
        if only_missing and has(did, day):
            continue
        try:
            rep = build(did, day, coll=coll)
        except Exception as e:  # noqa: BLE001
            _swallow("core/daily_digest.py:generate_all:%s" % did, e)
            continue
        if not rep or rep.get("empty_reason") == "error":
            continue
        out.append(rep)
    # 整日全空 → 一份都不落盘（这天才算"不存在"）
    if out and all(r.get("empty_reason") == "no_data" for r in out):
        return {"date": day, "generated": [], "reports": [],
                "note": "该日四方向均无产出，不生成空报告"}
    kept = []
    for rep in out:
        paths_ = save(rep)
        if not paths_.get("error"):
            kept.append(rep)
    if kept and notify:
        try:
            push_notification(kept)
        except Exception as e:  # noqa: BLE001 —— 提醒失败不影响报告
            _swallow("core/daily_digest.py:notify", e)
    return {"date": day, "generated": [r["module"] for r in kept],
            "reports": [summary_of(r) for r in kept]}


def missing_days(days=None):
    """保留期窗口内缺哪些天（任一**方向**没有即算缺）。返回升序日期列表。

    只做**展示口径**（status / 列表元信息），不再驱动「补齐缺失」按钮 ——
    该按钮随模块台账一起去掉了（2026-10-07）。方向报告能不能补，
    取决于 monitor_state 的入库明细是否还在（只留近 40 轮），
    老日期往往补不出来，所以自动补全只看很近的窗口（catch_up，默认 3 天）。
    """
    n = max(1, min(int(days or RETENTION_DAYS), RETENTION_DAYS))
    out = []
    for i in range(n):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        if not all(has(did, day) for did in DIR_IDS):
            out.append(day)
    return sorted(out)


def catch_up(days=None, notify=False):
    """补齐缺失日期的方向报告。只补到"真的有数据"的日子 —— 全为空的日期
    补出来只会制造四份"当日无新增"的空报告文件，反而污染列表
    （与日报「不造占位假报告」的既有原则一致）。

    ★ 窗口默认 **3 天**（不再是被删掉的模块台账时代的 30 天）：
    方向报告的源（monitor_state 近 40 轮同步明细）老日期会被滚动掉，
    窗口拉满 30 天只会天天空跑 + 拖慢启动。服务关一两天的场景 3 天足够。
    """
    n = max(1, min(int(days or 3), RETENTION_DAYS))
    filled, skipped = [], []
    for i in range(n):
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - i * 86400))
        if all(has(did, day) for did in DIR_IDS):
            continue
        r = generate_all(day, only_missing=True, notify=notify)
        if r["generated"]:
            filled.append(day)
        else:
            skipped.append(day)
    return {"filled": filled, "filled_count": len(filled),
            "empty": skipped, "empty_count": len(skipped)}


# ── 站内通知 ───────────────────────────────────────────────────────────
_NOTIFY_FP = os.path.join(paths.DATA_DIR, "notifications.json")


def _load_notifications():
    d = _read_json(_NOTIFY_FP, [])
    return d if isinstance(d, list) else []


def _save_notifications(rows):
    tmp = _NOTIFY_FP + ".tmp"
    try:
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows[-_NOTIFY_CAP:], f, ensure_ascii=False, indent=1)
        os.replace(tmp, _NOTIFY_FP)
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:_save_notifications", e)


def push_notification(reports, title=None):
    """写一条站内通知（报告出了 → 提醒）。

    空报告列表表示"这天什么都没产出" —— 不发通知是对的，但**不能返回
    None**：调用方（generate_all / catch_up / POST 处理器）普遍会直接
    `note.get("id")`，返回 None 会把整条链路打断在 AttributeError 上。
    这里统一返回 {"ok": bool, "pushed": note|None}。

    ★ 同一天**只保留一条**：补齐会一天调一次、用户也能手动反复点
    「立即生成」，不合并的话通知列表会被同一天的副本刷屏
    （实测 8 条里 5 条是同一天的）。规则是"**日期相同就就地更新**，
    并把已读状态重置为未读" —— 报告内容变了就该重新看一眼，
    但不该在列表里堆成一行行重复。
    """
    reports = [r for r in (reports or []) if isinstance(r, dict)]
    if not reports:
        return {"ok": False, "pushed": None, "reason": "no_reports"}
    day = reports[0].get("date")
    mods = [{"module": r.get("module"), "module_name": r.get("module_name"),
             "headline": r.get("headline")} for r in reports]
    # 标题按条目构成写：全量是「4 方向 + 4 模块」，单推模块台账时不冒充方向
    n_dir = sum(1 for r in reports if r.get("kind") == "direction")
    span = ("%d 方向 + %d 模块" % (n_dir, len(reports) - n_dir)
            if n_dir and len(reports) > n_dir else "%d 份" % len(reports))
    default_title = "%s 每日报告已生成（%s）" % (day, span)
    with _LOCK:
        rows = _load_notifications()
        # 找当天已有的日报类通知（只合并 kind=daily_report，别动别的类型）
        hit = None
        for r in rows:
            if isinstance(r, dict) and r.get("kind") == "daily_report" \
                    and r.get("date") == day:
                hit = r
                break
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        if hit is not None:
            hit["ts"] = stamp
            hit["title"] = title or default_title
            hit["modules"] = mods
            # 内容变了就重新提醒（未读），没变就别把已读状态翻回去
            sig = json.dumps(mods, ensure_ascii=False, sort_keys=True)
            if hit.get("_sig") != sig:
                hit["read"] = False
                hit["_sig"] = sig
            note = hit
            replaced = True
        else:
            note = {"id": "daily-%s-%d" % (day, int(time.time() * 1000) % 100000),
                    "ts": stamp, "kind": "daily_report",
                    "title": title or default_title,
                    "date": day, "modules": mods, "read": False,
                    "_sig": json.dumps(mods, ensure_ascii=False, sort_keys=True)}
            rows.append(note)
            replaced = False
        _save_notifications(rows)
    mail = _mail_notify(note, reports)
    return {"ok": True, "pushed": note, "replaced": replaced, "mail": mail}


def notifications(limit=20, unread_only=False):
    rows = _load_notifications()
    # 读的时候也去一次重：合并规则是后加的，历史文件里可能已经堆着重复
    rows = _dedup_notifications(rows)
    if unread_only:
        rows = [r for r in rows if not r.get("read")]
    return {"items": list(reversed(rows))[:max(1, min(60, int(limit or 20)))],
            "unread": sum(1 for r in rows if not r.get("read"))}


def _dedup_notifications(rows):
    """同一个 (kind, date) 只留最后一条（其它类型不合并）。"""
    out, seen = [], set()
    for r in reversed(rows or []):
        if not isinstance(r, dict):
            continue
        key = (r.get("kind"), r.get("date"))
        if r.get("kind") == "daily_report" and key in seen:
            continue
        seen.add(key)
        out.append(r)
    return list(reversed(out))


def mark_read(ids=None):
    with _LOCK:
        rows = _load_notifications()
        n = 0
        for r in rows:
            if ids and r.get("id") not in ids:
                continue
            if not r.get("read"):
                r["read"] = True
                n += 1
        _save_notifications(rows)
    return {"ok": True, "marked": n, "unread": sum(1 for r in rows if not r.get("read"))}


def _mail_notify(note, reports):
    """可选：配了 SMTP 就再发一封提醒邮件。没配 / 发送失败一律静默跳过。"""
    try:
        sysroot = os.path.join(paths.DATA_DIR, "..", "modules", "m2_enrich", "backend")
        if os.path.isdir(sysroot) and sysroot not in os.sys.path:
            os.sys.path.insert(0, sysroot)
        import mailer  # type: ignore
        if not mailer.configured():
            return {"ok": False, "reason": "not_configured"}
        to = [r for r in _read_json(os.path.join(paths.DATA_DIR, "alert_subscribers.json"), []) or []
              if isinstance(r, dict) and r.get("enabled", True) and r.get("email")]
        addrs = [str(r.get("email")) for r in to]
        if not addrs:
            return {"ok": False, "reason": "no_subscriber"}
        lines = ["%s 每日报告已生成：" % note.get("date"), ""]
        for r in reports:
            lines.append("· %s：%s" % (r.get("module_name"), r.get("headline")))
        return mailer.send_simple_mail(addrs, note.get("title"), "\n".join(lines))
    except Exception as e:  # noqa: BLE001
        _swallow("core/daily_digest.py:_mail_notify", e)
        return {"ok": False, "error": str(e)[:120]}


# --------------------------------------------------------------------------
# 调度
# --------------------------------------------------------------------------
def parse_hhmm(s):
    m = re.match(r"^(\d{1,2}):(\d{2})$", str(s or "").strip())
    if not m:
        return None
    h, mi = int(m.group(1)), int(m.group(2))
    if not (0 <= h <= 23 and 0 <= mi <= 59):
        return None
    return h, mi


def target_date(now=None):
    """当前这次调度该出"哪一天"的报告。

    「当天晚上 12:30 出」有两种读法，都支持：
      · 23:30（默认）→ 出的就是**当天**这一天；
      · 00:30         → 那一刻已经跨日了，出的是**前一天**（否则会把
                       刚过 0 点的当天算进去，而那时当天几乎还没采到东西）。
    """
    hhmm = parse_hhmm(DAILY_AT) or (23, 30)
    t = time.localtime(now if now is not None else time.time())
    day = time.strftime("%Y-%m-%d", t)
    if hhmm[0] < 6:                       # 凌晨时段 → 归属前一天
        day = time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))
    return day


_STATE = {"last_run": "", "last_notified": "", "runs": 0, "filled": 0, "error": ""}
SCHED_LOCK = threading.Lock()


def _tick():
    """调度线程的一轮：到点了就出报告 + 提醒 + 清理 + 补全。"""
    hhmm = parse_hhmm(DAILY_AT) or (23, 30)
    day = target_date()
    now_hm = time.strftime("%H:%M")
    if now_hm < "%02d:%02d" % hhmm:
        return None
    if _STATE["last_run"] == day:                  # 一天只出一次
        return None
    with SCHED_LOCK:
        if _STATE["last_run"] == day:
            return None
        _STATE["last_run"] = day
    try:
        # 到了点先把前几天的缺口补上（机器关机 / 服务没开的情况），再出当天的
        try:
            cu = catch_up(notify=False)
            if cu.get("filled_count"):
                _STATE["filled"] += cu["filled_count"]
                print("[daily-digest] 补齐缺失日报 %d 天：%s"
                      % (cu["filled_count"], "、".join(cu["filled"][:6])), flush=True)
        except Exception as e:  # noqa: BLE001
            _swallow("core/daily_digest.py:catch_up", e)
        r = generate_all(day, notify=True)
        _STATE["runs"] += 1
        if r["generated"]:
            print("[daily-digest] %s 每日报告已生成：%s（已提醒）"
                  % (day, "、".join(ENTRY_NAME.get(m, m) for m in r["generated"])), flush=True)
        else:
            print("[daily-digest] %s 无可归档产出，未生成报告" % day, flush=True)
        _STATE["error"] = ""
        try:
            cleanup()
        except Exception as e:  # noqa: BLE001
            _swallow("core/daily_digest.py:cleanup", e)
        return r
    except Exception as e:  # noqa: BLE001
        _STATE["error"] = str(e)[:200]
        _swallow("core/daily_digest.py:_tick", e)
        _STATE["last_run"] = ""                    # 出错就允许下一轮重试
        return None


def start_scheduler(boot_delay=20):
    """启动调度线程。服务起来后先补缺失日期，再进入定点轮询。"""
    hhmm = parse_hhmm(DAILY_AT) or (23, 30)
    print("  每日报告（AI 安全四方向）：每天 %02d:%02d 自动出（%s）；近 3 天缺失自动补齐"
          % (hhmm[0], hhmm[1], DAILY_AT), flush=True)

    def _loop():
        time.sleep(boot_delay)
        try:
            cu = catch_up(notify=False)
            if cu.get("filled_count"):
                _STATE["filled"] += cu["filled_count"]
                print("[daily-digest] 启动补齐：%d 天（%s）"
                      % (cu["filled_count"], "、".join(cu["filled"][:6])), flush=True)
        except Exception as e:  # noqa: BLE001
            _swallow("core/daily_digest.py:boot_catch_up", e)
        while True:
            try:
                _tick()
            except Exception as e:  # noqa: BLE001
                _swallow("core/daily_digest.py:sched", e)
            time.sleep(60)

    threading.Thread(target=_loop, daemon=True, name="daily-digest").start()
    return _STATE


def status():
    hhmm = parse_hhmm(DAILY_AT) or (23, 30)
    return {"at": DAILY_AT, "at_hm": "%02d:%02d" % hhmm,
            "next_target_date": target_date(),
            "directions": [{"id": i, "name": n, "desc": d,
                            "days": len(available_dates(i))}
                           for i, n, d in DIRECTIONS],
            "missing": missing_days(),
            "retention_days": RETENTION_DAYS,
            "dir": root(),
            "state": dict(_STATE),
            "server_time": time.strftime("%Y-%m-%dT%H:%M:%S")}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        print(json.dumps(status(), ensure_ascii=False, indent=1))
    elif cmd == "gen":
        print(json.dumps(generate_all(sys.argv[2] if len(sys.argv) > 2 else None),
                         ensure_ascii=False, indent=1)[:2000])
    elif cmd == "catchup":
        print(json.dumps(catch_up(), ensure_ascii=False, indent=1))
    elif cmd == "show":
        mid = sys.argv[2]
        day = sys.argv[3] if len(sys.argv) > 3 else today()
        rep = load(mid, day)
        print(render_markdown(rep) if rep else "（无）")
