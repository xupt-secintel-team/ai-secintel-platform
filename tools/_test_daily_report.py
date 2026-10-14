# -*- coding: utf-8 -*-
"""_test_daily_report.py —— 每日按类 AI 安全风险报告回归（2026-10-06 新增）

钉死六件事，每一条都对应一个**已经踩过或能想出来的坑**：

  ① AI 四分类必须真的分出来（不是所有条目都糊在一个桶里）
  ② 去重：同一篇文章分页抓取来 162 次也只算 1 条
  ③ 严重度：无 CVSS 的博客是「资讯」，不是「低危」（否则每天看着都像没大事）
  ④ 报告保留一个月 + 清理只删日报文件（不误删目录里别的东西）
  ⑤ 三格式导出（md / json / xlsx）真的能打开、内容自洽
  ⑥ API 层：路由注册、参数白名单（防路径穿越）、脏数据不 500

直接执行： py tools/_test_daily_report.py
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
for p in (ROOT, os.path.join(ROOT, "core"),
          os.path.join(ROOT, "modules", "m1_monitor"),
          os.path.join(ROOT, "modules", "m1_monitor", "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

RESULTS = []


def ok(name, cond, detail=""):
    good = bool(cond)
    RESULTS.append((good, name, str(detail)[:90]))
    print("  [%s] %-48s %s" % ("OK" if good else "!!", name, str(detail)[:90]))


def show():
    bad = sum(1 for g, _, _ in RESULTS if not g)
    print("\n结果：通过 %d / 失败 %d" % (len(RESULTS) - bad, bad))
    return 0 if bad == 0 else 1


# ======================================================================
# ① AI 四分类
# ======================================================================
print("\n=== ① AI 安全风险四分类（用户指定的分类口径）===")
import daily_report as DR            # noqa: E402
from taxonomy import RISK_CATEGORIES  # noqa: E402

AI4 = ["① AI基础设施与推理框架", "② 模型与数据层",
       "③ AI应用与智能体", "④ AI供应链与平台"]

for c in AI4:
    ok("分类「%s」在 RISK_CATEGORIES 中存在" % c, c in RISK_CATEGORIES,
       (RISK_CATEGORIES.get(c) or {}).get("desc", "")[:56])
ok("AI 四分类都在日报的展示顺序里",
   all(c in DR._CAT_ORDER for c in AI4),
   "共 %d 类（AI4 + 通用 %d）" % (len(DR._CAT_ORDER), len(DR._GEN_ORDER)))
ok("通用分类紧跟 AI 四类之后（报告章节顺序稳定）",
   DR._CAT_ORDER[-1] == AI4[-1] and DR._GEN_ORDER[0] not in DR._CAT_ORDER,
   "AI4 → %s" % DR._GEN_ORDER[0])
ok("不存在重复分类", len(set(DR._CAT_ORDER + DR._GEN_ORDER)) ==
   len(DR._CAT_ORDER + DR._GEN_ORDER))
ok("兜底分类也是合法分类", DR._FALLBACK in RISK_CATEGORIES, DR._FALLBACK)

# 四分类必须**真的**能分开。样本用**真实数据形态**：
# AI_PRODUCTS 只扫 products/vendors/osv_packages 字段，不扫正文，
# 只给 title+desc 的英文样本是判不出来的（那是分类器的口径，不是 bug）。
SAMPLES = [
    ({"title": "Ollama 远程代码执行", "products": ["ollama"]},
     "① AI基础设施与推理框架"),
    ({"title": "vLLM 拒绝服务", "products": ["vllm"]},
     "① AI基础设施与推理框架"),
    ({"title": "Triton 推理服务器漏洞", "products": ["triton"]},
     "① AI基础设施与推理框架"),
    ({"title": "LangChain 任意代码执行", "products": ["langchain"]},
     "③ AI应用与智能体"),
    ({"title": "Dify 工作流越权", "products": ["dify"]},
     "③ AI应用与智能体"),
]
mis = []
for rec, want in SAMPLES:
    got = DR._classify(rec)[0]
    if got != want:
        mis.append((rec["title"], want, got))
ok("五个框架/应用样本都归到正确的 AI 分类", not mis, str(mis[:2]))

# 中文情报：采集源里有大量 data/cn、CSDN 快抓、公众号转载。
# 这一组是 2026-10-06 补的 —— 补之前中文"数据投毒""系统提示词泄漏"一个都判不出来。
CN_SAMPLES = [
    ("训练数据投毒导致模型后门", "② 模型与数据层"),
    ("本文讨论提示词注入攻击", "② 模型与数据层"),
    ("系统提示词泄漏导致角色越狱", "② 模型与数据层"),
]
cmis = []
for title, want in CN_SAMPLES:
    got = DR._classify({"title": title, "desc": title})[0]
    if got != want:
        cmis.append((title, want, got))
ok("中文模型层风险词能分类（数据投毒/提示词注入/系统提示词）",
   not cmis, str(cmis[:2]))

# 反向：不能因为补了中文词就把普通新闻也判成 AI 风险（误报比漏报更伤）
for noise in ("某普通网站改版公告", "本周市场回顾与行业动态"):
    got = DR._classify({"title": noise, "desc": noise})[0]
    ok("非 AI 文本不被误判 %-14s" % noise, got is None, str(got))

# 引擎分类（带 category 字段）必须优先于兜底
got = DR._item({"title": "x", "category": "② 模型与数据层",
                "fetched_at": "2026-10-06T00:00:00"}, "2026-10-06")
ok("条目自带 category 时直接采用（不重跑分类器）",
   got["category"] == "② 模型与数据层" and got["classified_by"] == "engine",
   "%s / %s" % (got["category"], got["classified_by"]))
got2 = DR._item({"title": "y", "fetched_at": "2026-10-06T00:00:00"},
                "2026-10-06")
ok("无 category 时走引擎分类器", got2["classified_by"] in ("engine", "fallback"),
   "%s / %s" % (got2["category"], got2["classified_by"]))
ok("兜底条目会被标注来源（页面能提示口径不确定）",
   got2["classified_by"] == "engine" or got2["category"] == DR._FALLBACK)

# ======================================================================
# ② 去重
# ======================================================================
print("\n=== ② 去重（分页抓取会重复来同一篇文章）===")
same = "CrowdStrike Global Threat Report 2026"
items = [DR._item({"title": same, "link": "https://x/page/%d" % i,
                   "id": "ID%d" % i, "fetched_at": "2026-10-06T01:00:00"},
                  "2026-10-06") for i in range(20)]
keys = {DR._dedup_key(x) for x in items}
ok("同一标题的 20 条只产生 1 个去重键", len(keys) == 1, str(list(keys)[:1]))

k1 = DR._dedup_key({"title": "  Hello   World  "})
k2 = DR._dedup_key({"title": "hello world"})
ok("标题归一：空白/大小写差异也算重复", k1 == k2, "%s == %s" % (k1, k2))

k3 = DR._dedup_key({"title": "", "link": "https://a/b"})
k4 = DR._dedup_key({"title": "", "link": "https://a/b"})
ok("无标题时退回按链接去重", k3 == k4 and k3[0] == "l", str(k3))
k5 = DR._dedup_key({"title": "", "link": "", "id": "abc"})
ok("标题链接都没有时退回按 id", k5[0] == "i" and k5[1] == "abc", str(k5))

# ======================================================================
# ③ 严重度分档
# ======================================================================
print("\n=== ③ 严重度：资讯不是低危 ====")
ok("CVSS 9.8 → 严重", DR._sev(9.8, False, True) == "critical")
ok("CVSS 7.5 → 高危", DR._sev(7.5, False, True) == "high")
ok("CVSS 5.0 → 中危", DR._sev(5.0, False, True) == "medium")
ok("CVSS 2.0 → 低危", DR._sev(2.0, False, True) == "low")
ok("无 CVSS → 资讯（不是低危）", DR._sev(0, False, False) == "info")
ok("KEV 一律严重（哪怕没 CVSS）", DR._sev(0, True, False) == "critical")
ok("CVSS 0 但显式 has_score=True → 低危", DR._sev(0, False, True) == "low")
ok("五档齐全", set(DR.SEV_ORDER) ==
   {"critical", "high", "medium", "low", "info"}, str(sorted(DR.SEV_ORDER)))
ok("每档都有中文标签", set(DR.SEV_LABEL) == set(DR.SEV_ORDER),
   str(list(DR.SEV_LABEL.values())))

# CVSS 脏数据（真实数据里出现过 "8 天" 这种带单位字符串）
for raw, want in ((9.8, 9), ("9.8", 9), (9, 9), (None, 0), ("", 0),
                  ("待评估", 0), ("7分", 7)):
    got = DR._to_int(raw)
    ok("CVSS 归一 %-8r → %s" % (raw, want), got == want, "得到 %s" % got)

it = DR._item({"title": "博客文章", "cvss": None,
               "fetched_at": "2026-10-06T01:00:00"}, "2026-10-06")
ok("条目上带 has_cvss=false，前端据此显示「资讯」",
   it["has_cvss"] is False and it["severity"] == "info",
   "%s / %s" % (it["severity_label"], it["has_cvss"]))

# ★ cvss 在真实数据里是 **dict**，不是数字（core/engine.py:2265 就按 dict 读）。
#   踩过的坑：把整个 dict 丢给 _to_int → 走 re.search 数字的兜底 →
#   在 "{'score': None, 'vector': 'CVSS:3.1/...'}" 里抓到向量串的 "3.1"
#   当成分数，于是当天 31 条全部显示成「资讯 / 低危」。
ok("_cvss_score 读 dict 的 score",
   DR._cvss_score({"cvss": {"score": 9.8, "severity": "CRITICAL"}}) == 9.8,
   DR._cvss_score({"cvss": {"score": 9.8}}))
ok("_cvss_score 兼容字符串（取原值，归一化交给 _to_int）",
   DR._cvss_score({"cvss": "6.1"}) == "6.1")
ok("_cvss_score 兼容裸数字",
   DR._cvss_score({"cvss": 7.5}) == 7.5)
ok("_cvss_score 缺 cvss 返回 None",
   DR._cvss_score({}) is None)
ok("_cvss_score：score 为 None 时返回 None（不退回抓向量串）",
   DR._cvss_score({"cvss": {"score": None,
                             "vector": "CVSS:3.1/AV:N/AC:L"}}) is None,
   DR._cvss_score({"cvss": {"score": None, "vector": "CVSS:3.1/AV:N"}}))

# 用真实 dict 形态的条目验证：不能被向量串里的 "3.1" 带偏
_d = {"title": "提示词注入", "cvss": {"score": 8.1, "severity": "HIGH",
                                     "vector": "CVSS:3.1/AV:N/AC:L",
                                     "version": "3.1"},
      "fetched_at": "2026-10-06T01:00:00"}
_it = DR._item(_d, "2026-10-06")
ok("dict 形态 cvss 读出真实分数 8.1",
   _it.get("cvss") == 8 or _it.get("cvss") == 8.1, _it.get("cvss"))
ok("dict 形态 cvss 判为高危而非低危",
   _it["severity"] in ("high", "critical"), _it["severity"])
ok("dict 形态 cvss 的 has_cvss 为 True", _it["has_cvss"] is True)

# score=None 但有向量串：绝不能把 3.1 当分数（这是踩过的那个坑）
_d2 = {"title": "某安全博客", "cvss": {"score": None, "severity": "LOW",
                                       "vector": "CVSS:3.1/AV:N/AC:H"},
       "fetched_at": "2026-10-06T01:00:00"}
_it2 = DR._item(_d2, "2026-10-06")
ok("score=None 时不当成 3.1 低危", _it2["severity"] == "info",
   "%s / has_cvss=%s" % (_it2["severity"], _it2.get("has_cvss")))

# ★ 入库口径：定时增量同步的 CVE 走 corpus，不写 live_feed。
#   只读 live_feed 时当天会漏掉 97%（实测 36 → 漏采，只收到 31 条）。
ok("_read_intake 函数存在", callable(getattr(DR, "_read_intake", None)))
if callable(getattr(DR, "_read_intake", None)):
    _today = DR.valid_date(DR.today()) or "2026-10-07"
    _got = DR._read_intake(_today)
    ok("_read_intake 返回 list", isinstance(_got, list), type(_got))
    # ★ 2026-10-08 修：原断言硬要求"当天必须有条目"，但**当天尚未采集**
    #   （或换台机器没跑过采集）时必然为 0 → CI 变红，功能却完全正常。
    #   改成"能读到就验证结构，读不到就如实跳过" —— 断言的是函数行为，
    #   不是"运行环境恰好有今天的采集数据"。
    if _got:
        ok("_read_intake 当天有条目，且条目结构正确", True, "读到 %d 条" % len(_got))
        _s0 = _got[0]
        ok("intake 条目是 dict", isinstance(_s0, dict))
        ok("intake 条目有标题", bool(_s0.get("title")))
        ok("intake 条目有入库时间字段",
           bool(_s0.get("fetched_at") or _s0.get("published") or _s0.get("ts")))
    else:
        print("  [SKIP] _read_intake 当天无入库记录（%s 尚未采集），"
              "跳过结构断言 —— 不影响功能判定" % _today)
    # 不存在的日期必须返回空，且不能抛
    ok("_read_intake 对无数据日期返回空",
       DR._read_intake("1999-01-01") == [])

# ======================================================================
# ④ 日期口径与保留期
# ======================================================================
print("\n=== ④ 日期口径与一个月保留 ====")
ok("保留期默认 30 天", DR.RETENTION_DAYS == 30, "%s 天" % DR.RETENTION_DAYS)
ok("合法日期通过", DR.valid_date("2026-10-06") == "2026-10-06")
for bad_d in ("", "abc", "2026-13-01", "2026-10-32", "../../etc/passwd",
              "2026-1-1", "2026/10/06", None, "2026-10-06; rm -rf /"):
    ok("非法日期被拒 %-22r" % (bad_d,), DR.valid_date(bad_d) is None)

ok("优先按 fetched_at 分组（系统检测到的日期）",
   DR._detected_day({"fetched_at": "2026-10-06T05:00:00",
                     "published": "2026-07-01"}) == "2026-10-06")
ok("无 fetched_at 时退回 published",
   DR._detected_day({"published": "2026-07-01"}) == "2026-07-01")
ok("两者都没有时返回 None（不硬塞当天）",
   DR._detected_day({"title": "x"}) is None)

# --- 清理：真删 + 只删日报文件 + 记录过期 ---
tmp_reports = tempfile.mkdtemp(prefix="aisec_dr_")
orig_dir = DR.report_dir
DR.report_dir = lambda: (os.makedirs(tmp_reports, exist_ok=True), tmp_reports)[1]
try:
    for day in ("2026-01-01", "2026-01-02"):
        for ext in ("md", "json", "xlsx"):
            with io.open(os.path.join(tmp_reports, "%s.%s" % (day, ext)),
                         "w", encoding="utf-8") as f:
                f.write("x" * 1000)
    # 非日报文件：清理绝不能碰
    keep_fp = os.path.join(tmp_reports, "我的笔记.txt")
    with io.open(keep_fp, "w", encoding="utf-8") as f:
        f.write("手工放的东西")
    exp_fp = os.path.join(tmp_reports, "_expired.json")

    r = DR.cleanup(retention_days=1, dry_run=True)
    ok("dry-run 报告 6 个待删文件", r["removed_count"] == 6, str(r["removed_count"]))
    ok("dry-run 给出预计释放体积", r["freed_bytes"] == 6000,
       "%d 字节" % r["freed_bytes"])
    ok("dry-run 不真的删文件",
       os.path.isfile(os.path.join(tmp_reports, "2026-01-01.md")))
    ok("dry-run 不写过期清单", not os.path.isfile(exp_fp))

    r2 = DR.cleanup(retention_days=1, dry_run=False)
    ok("真删后文件确实没了", r2["removed_count"] == 6 and
       not os.path.isfile(os.path.join(tmp_reports, "2026-01-01.md")))
    ok("真删给出实释放体积（不是 0）", r2["freed_bytes"] == 6000,
       "%d 字节" % r2["freed_bytes"])
    ok("目录里非日报文件被保留", os.path.isfile(keep_fp))
    ok("过期日期被记录（区分「已过期」与「无数据」）",
       sorted(DR.expired_days()) == ["2026-01-01", "2026-01-02"],
       str(DR.expired_days()))

    st = DR.stats()
    ok("stats 不把过期清单算成报告",
       st["files"] == 0 and st["other_bytes"] > 0,
       "报告 %d 个 / 其他 %d 字节" % (st["files"], st["other_bytes"]))
    ok("stats 报出已过期天数", st["expired_days"] == 2, st["expired_days"])
    ok("保留期非法值被夹到 ≥1（不会出现负数天）",
       DR.cleanup(retention_days=-5, dry_run=True)["retention_days"] == 1)

    # 保留期内的报告不删
    today = DR.today()
    for ext in ("md", "json", "xlsx"):
        with io.open(os.path.join(tmp_reports, "%s.%s" % (today, ext)),
                     "w", encoding="utf-8") as f:
            f.write("今天")
    r3 = DR.cleanup(dry_run=True)
    ok("保留期内的今天不删", r3["removed_count"] == 0, str(r3["removed_count"]))
    ok("可下载格式识别出今天的三种",
       sorted(DR.available_dates()[0]["formats"]) == ["json", "md", "xlsx"])
finally:
    DR.report_dir = orig_dir
    shutil.rmtree(tmp_reports, ignore_errors=True)

# ======================================================================
# ⑤ 导出三格式
# ======================================================================
print("\n=== ⑤ 报告导出（md / json / xlsx）===")
d = DR.collect()
pub = DR._json_public(d)
ok("对外 JSON 剔掉内部 _rows（否则响应翻几倍）", "_rows" not in pub)


def _sorted_ok(cat):
    """分类内条目是否按严重度升序（最严重在前）。"""
    its = cat["items"]
    return all(DR.SEV_ORDER.get(its[i]["severity"], 9)
               <= DR.SEV_ORDER.get(its[i + 1]["severity"], 9)
               for i in range(len(its) - 1))


ok("条目按严重度排序（最严重的在前）",
   all(_sorted_ok(c) for c in pub["categories"] if len(c["items"]) > 1))
ok("by_sev 之和 == total",
   sum(pub["by_sev"].values()) == pub["total"],
   "%s vs %d" % (sum(pub["by_sev"].values()), pub["total"]))
ok("各分类 count 之和 + 通用类 == total",
   sum(c["count"] for c in pub["categories"]) + pub.get("general_count", 0)
   == pub["total"],
   "%d + %d vs %d" % (sum(c["count"] for c in pub["categories"]),
                      pub.get("general_count", 0), pub["total"]))
# 2026-10-07：日报只展示 AI 四大类，通用七类归入 general_count
ok("categories 只含 AI 四大类",
   all(c["key"].startswith(("①", "②", "③", "④")) for c in pub["categories"]),
   [c["key"] for c in pub["categories"]])

md = DR.render_markdown(pub)
ok("markdown 非空", len(md) > 200, "%d 字节" % len(md.encode("utf-8")))
ok("markdown 含标题日期", pub["date"] in md)
ok("markdown 含保留期说明", "保留" in md and str(DR.RETENTION_DAYS) in md)
ok("markdown 表格竖线被转义（否则表格破）",
   "| 情报条目总数 |" in md and "\\|" not in md.split("\n")[0],
   "首行=%r" % md.split("\n")[0][:40])

js = json.dumps(pub, ensure_ascii=False)
ok("json 可序列化且能读回", json.loads(js)["total"] == pub["total"],
   "%d 字节" % len(js.encode("utf-8")))

try:
    import openpyxl
    xb = DR.render_xlsx(pub)
    ok("xlsx 生成成功", len(xb) > 1000, "%d 字节" % len(xb))
    tmp_x = os.path.join(tempfile.mkdtemp(prefix="aisec_xl_"), "r.xlsx")
    with open(tmp_x, "wb") as f:
        f.write(xb)
    wb = openpyxl.load_workbook(tmp_x)
    ok("xlsx 能被 openpyxl 打开", len(wb.sheetnames) >= 1, str(wb.sheetnames))
    ok("xlsx 有概览 sheet", wb.sheetnames[0].startswith("当日概览"),
       wb.sheetnames[0])
    ok("xlsx 每个非空分类一个 sheet",
       len(wb.sheetnames) == 1 + len(pub["categories"]),
       "%d 个 sheet / %d 个分类" % (len(wb.sheetnames), len(pub["categories"])))
    # sheet 名必须合法（Excel 不允许 : \ / ? * [ ]，且 ≤31 字符）
    bad_sheet = [s for s in wb.sheetnames
                 if len(s) > 31 or re.search(r"[:\\/?*\[\]]", s)]
    ok("sheet 名符合 Excel 限制", not bad_sheet, str(bad_sheet[:2]))
    shutil.rmtree(os.path.dirname(tmp_x), ignore_errors=True)
except ImportError:
    ok("xlsx 生成成功", False, "缺 openpyxl")

# ======================================================================
# ⑥ API 层
# ======================================================================
print("\n=== ⑥ API 接线与参数白名单 ====")
import api as M1                        # noqa: E402

SRC = io.open(os.path.join(ROOT, "modules", "m1_monitor", "api.py"),
              encoding="utf-8").read()
for r in ("/api/daily_reports", "/api/daily_report",
          "/api/daily_report/generate", "/api/daily_report/cleanup"):
    ok("register() 注册了 %s" % r, ('"%s"' % r) in SRC)

man = json.load(io.open(os.path.join(ROOT, "modules", "m1_monitor",
                                     "module.json"), encoding="utf-8"))
WANT_ROUTES = {
    "GET /api/daily_reports", "GET /api/daily_report",
    "POST /api/daily_report/generate", "POST /api/daily_report/cleanup",
}
# 精确比对，不玩 endswith 后缀匹配 —— "/api/daily_report" 恰好也是
# "/api/daily_report/generate" 的后缀，用 endswith 会得出错误结论。
ok("module.json 的 routes 覆盖全部日报接口",
   WANT_ROUTES <= set(man["routes"]),
   str(sorted(set(man["routes"]) ^ WANT_ROUTES)) if
   not WANT_ROUTES <= set(man["routes"]) else "4/4")
ok("module.json 里没有多写的日报路由",
   len([r for r in man["routes"] if "daily_report" in r]) == 4,
   str([r for r in man["routes"] if "daily_report" in r]))

# _day_summary 抽取：列表页不该把 30 份完整报告全吐出去
#
# ★ 2026-10-08 修：原断言直接取 `s["categories"][0]`，**当天没有采集到任何数据时
#   报告是 0 个分类** → IndexError，整个 CI 变红，但功能其实完全正常。
#   这是"测试依赖当天恰好有数据"的脆弱写法（本地跑绿、隔天/别人机器上炸）。
#   改为：**没有分类时用构造出的最小样本**验同一件事 ——
#   断言的是 `_day_summary` 的行为（剔 items / 留计数），不是"今天有数据"。
data, err = M1._report_payload(DR.today(), limit=2)
ok("_report_payload 取到数据且无错", data and not err, err or "ok")
lim = M1._report_payload(DR.today(), limit=2)[0]
ok("limit 生效（每类最多 N 条）",
   all(len(c["items"]) <= 2 for c in lim["categories"]),
   str([len(c["items"]) for c in lim["categories"]]))
ok("limit 后 truncated 反映被截掉的条数",
   all(c["truncated"] == max(0, c["count"] - len(c["items"]))
       for c in lim["categories"]))
ok("limit 不改动原始数据（不能被就地截断污染）",
   all(len(c["items"]) > 2 or c["count"] <= 2
       for c in M1._report_payload(DR.today())[0]["categories"]))
# 有真实分类就用真实的；没有（当天零采集）就用最小样本，保证断言可执行
if (d or {}).get("categories"):
    sample = d
    src_note = "真实报告"
else:
    sample = {"date": DR.today(), "categories": [
        {"name": "漏洞与攻击面", "count": 3, "critical": 1, "high": 2, "info": 0,
         "truncated": 0, "items": [{"id": "CVE-0000-0000"}] * 3}]}
    src_note = "构造样本（今天零采集）"
s = M1._day_summary(sample)
ok("_day_summary 剔掉 items（列表页体积可控）",
   s and s.get("categories") and "items" not in s["categories"][0],
   "%s / 顶层键 %s" % (src_note, sorted((s or {}).keys())))
ok("_day_summary 保留每类计数与严重度",
   bool(s and s.get("categories")) and
   all(k in s["categories"][0] for k in ("count", "critical", "high", "info")),
   src_note)
ok("_day_summary 对空输入不炸", M1._day_summary(None) is None)

lst = M1.daily_list(force=True)
ok("列表含今天", any(x["date"] == lst["today"] for x in lst["days"]),
   "今天=%s 共 %d 天" % (lst["today"], len(lst["days"])))
ok("列表带保留期", lst["retention_days"] == DR.RETENTION_DAYS)
ok("列表带过期日期清单", isinstance(lst.get("expired_days"), list))
ok("列表里没有完整 items（否则 30 天 = 上兆响应）",
   all("items" not in c for x in lst["days"] for c in x["categories"]))
ok("列表有 60s 缓存（前端会轮询）",
   M1.daily_list() is lst or M1._REPORT_LIST_CACHE["v"] is lst)

ok("非法日期被拦下（防路径穿越）",
   M1._report_payload("../../secret") [1] is not None)
ok("limit 上限被夹住（不能一次拉爆）",
   all(len(c["items"]) <= 300
       for c in M1._report_payload(DR.today(), limit=99999)[0]["categories"]))

# 自动生成节流：不能每 15s 轮询就重算一次
ok("自动生成有 1 小时节流", M1._GEN_MIN_GAP >= 1800,
   "%s 秒" % M1._GEN_MIN_GAP)
ok("自动生成走非阻塞锁（抢不到就跳过，不排队堆积）",
   "blocking=False" in SRC)
ok("日报失败不会拖垮采集主循环",
   "except Exception" in SRC.split("def _daily_maybe_generate")[1][:2000])
ok("启动时也会生成一份（--no-live 时否则今天永远没日报）",
   "_daily_boot" in SRC)

# ── ⑦ 下载不能"造"报告（实测踩过：1999-01-01&fmt=md 会返回一份
#      标题写着该日期、生成时间却是当前时刻的空报告）
print("\n=== ⑦ 下载不造假报告 ===")
# ★ 必须按行首精确匹配：函数名也出现在文件的接口声明注释里，
#   直接 split("def handle_daily_report") 会切到 handle_daily_reports 的尾部
_hd = re.split(r"(?m)^def handle_daily_report\(", SRC)[1]
_hd = re.split(r"(?m)^def handle_daily_generate\(", _hd)[0]
ok("无数据日期下载返回 404（不是空报告）", "404" in _hd)
ok("区分 expired 与 no_data 两种空",
   'empty_reason": "expired"' in _hd and 'empty_reason": "no_data"' in _hd)
ok("过期日期不允许复活（不能被下载请求重新落盘）",
   _hd.index("_reason == \"expired\"") < _hd.index("D.save(data)"))
ok("有数据但未落盘时先落盘再下载",
   "if not _saved:" in _hd and "D.save(data)" in _hd)

if __name__ == "__main__":
    sys.exit(show())