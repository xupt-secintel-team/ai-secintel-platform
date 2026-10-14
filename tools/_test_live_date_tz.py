# -*- coding: utf-8 -*-
"""
_test_live_date_tz.py —— 实时流日期「时区口径」回归（2026-10-08）
================================================================
背景（真实现象）：
  「实时监测」面板最新只到昨天，"没有今天的文章"；而「每日报告」按 fetched_at
  分组却列出了当天内容 —— 两个视图看起来自相矛盾。
根因：
  live.py 的 `_norm_date`（写 published）对带时区的日期只取**原时区(UTC)的日期**，
  而同一原始串经 `_norm_datetime`（写 published_at）会换算到**本机时区(UTC+8)**。
  源站在 UTC 16:00~24:00 发布（= 北京时间次日 00:00~08:00）时，两个字段差 1 天。
断言：
  A. 函数级不变量  `_norm_date(x) == _norm_datetime(x)[:10]`
  B. 关键回归用例（UTC 深夜发布 → 本机次日）
  C. 数据级不变量  live_feed.jsonl 里 published == published_at[:10]
  D. 静态：live.py 的 _norm_date 真的做了时区换算
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))
sys.path.insert(0, os.path.join(ROOT, "core"))

PASS = FAIL = 0


def same_date(a, b):
    """按「日期语义」比较，容忍 ISO 单位数月/日（2026-9-8 ≡ 2026-09-08）。

    published 允许保留源站原始写法（引擎 _ISO_DATE_RE 容忍 1 位月/日），
    所以这里只要求**日期相同**，不要求字符串逐字一致。
    """
    def pad(x):
        m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})$", x or "")
        return "%s-%02d-%02d" % (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else x
    return pad(a) == pad(b)


def ok(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [OK] %s" % msg)
    else:
        FAIL += 1
        print("  [!!] %s" % msg)


print("=== A. 函数级不变量 _norm_date(x) == _norm_datetime(x)[:10] ===")
import live as L  # noqa: E402

BATTERY = [
    "Tue, 07 Oct 2026 20:34:44 GMT",
    "Tue, 07 Oct 2026 18:34:44 GMT",
    "Wed, 08 Oct 2026 01:00:00 GMT",
    "Wed, 29 Jul 2026 05:00:00 GMT",
    "2026-10-08T02:34:44Z",
    "2026-10-07T20:00:00+00:00",
    "2026-10-08T20:30:00Z",
    "2026-10-08T08:15:00+08:00",
    "2026-10-08",
    "2026-9-8",
    "2026年9月24日",
    "2026/09/24",
    "",
    "   ",
    "Fri, 18 Se",              # 截断残骸：两个函数都应给不出东西
    "not a date at all",
]
bad = []
for s in BATTERY:
    a, b = L._norm_date(s), L._norm_datetime(s)
    want = b[:10] if b else a
    if not same_date(a, want):
        bad.append((s, a, b))
ok(not bad, "全部 %d 个用例满足不变量（违例 %d）" % (len(BATTERY), len(bad)))
for s, a, b in bad:
    print("      ✗ %r → _norm_date=%r  _norm_datetime=%r" % (s, a, b))

print("\n=== B. 关键回归用例（UTC 深夜 → 本机次日）===")
CASES = [
    # (原始串, 期望 published)  —— 期望值 = 本机(UTC+8)日期
    ("Tue, 07 Oct 2026 20:34:44 GMT", "2026-10-08"),   # 旧版错成 2026-10-07
    ("Tue, 07 Oct 2026 18:34:44 GMT", "2026-10-08"),   # 旧版错成 2026-10-07
    ("2026-10-07T20:00:00+00:00",     "2026-10-08"),   # 旧版错成 2026-10-07
    ("2026-10-08T02:34:44Z",          "2026-10-08"),
    ("Wed, 08 Oct 2026 01:00:00 GMT", "2026-10-08"),
    ("Wed, 29 Jul 2026 05:00:00 GMT", "2026-07-29"),   # 既有验收断言须保持
    ("2026-10-08",                    "2026-10-08"),   # 纯日期不动
    ("2026-9-8",                      "2026-9-8"),
    ("2026年9月24日",                  "2026-09-24"),
]
for raw, want in CASES:
    got = L._norm_date(raw)
    ok(got == want, "_norm_date(%r) = %r（期望 %r）" % (raw, got, want))

# 同源的 published / published_at 必须自洽
for raw, _ in CASES:
    a, b = L._norm_date(raw), L._norm_datetime(raw)
    if b:
        ok(same_date(a, b[:10]), "%r: published(%s) ≍ published_at(%s)[:10]" % (raw, a, b))

print("\n=== C. 数据级不变量：live_feed.jsonl ===")
FEED = L.FEED_FP
if os.path.isfile(FEED):
    rows = []
    with io.open(FEED, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    withpa = [r for r in rows if r.get("published_at")]
    mism = [r for r in withpa
            if str(r.get("published") or "")[:10] != str(r.get("published_at") or "")[:10]]
    ok(True, "live_feed %d 条，其中带 published_at 的 %d 条" % (len(rows), len(withpa)))
    ok(not mism, "published 与 published_at 日期一致（不一致 %d 条，应为 0）" % len(mism))
    for r in mism[:5]:
        print("      ✗ %s pub=%s pa=%s" % (str(r.get("id"))[:36], r.get("published"), r.get("published_at")))
    # 今天的条目应能正确落到「本机今天」
    import datetime as _dt
    today = _dt.datetime.now().strftime("%Y-%m-%d")
    t_items = [r for r in withpa if str(r.get("published_at"))[:10] == today]
    t_pub = [r for r in t_items if str(r.get("published"))[:10] == today]
    ok(len(t_items) == len(t_pub),
       "今天(published_at=%s)的 %d 条，其 published 也都=今天（%d 条）" % (today, len(t_items), len(t_pub)))
else:
    ok(False, "找不到 live_feed.jsonl: %s" % FEED)

print("\n=== D. 静态：_norm_date 真的做了时区换算 ===")
src = io.open(os.path.join(ROOT, "modules", "m1_monitor", "backend", "live.py"),
              encoding="utf-8").read()
i = src.find("def _norm_date(")
seg = src[i: src.find("\ndef ", i + 1)]
ok("astimezone()" in seg, "_norm_date 内含 astimezone()（本机时区换算）")
ok("def _norm_date(s):" in src, "函数签名未变")

print("\n=== 结果：%d 通过 / %d 失败 ===" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
