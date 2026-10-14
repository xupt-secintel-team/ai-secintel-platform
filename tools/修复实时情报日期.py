# -*- coding: utf-8 -*-
"""
修复实时情报日期.py —— 修复 data/live_feed.jsonl（及 data/corpus.json）里的日期问题
================================================================================
两类历史问题、两遍修复（先后顺序固定）：

  【Pass A｜时区口径对齐】★ 2026-10-08 新增
    live.py 旧版 `_norm_date` 对带时区的日期只取**原时区（UTC）的日期**，而同一
    原始串经 `_norm_datetime` 会换算到**本机时区（UTC+8）**。于是源站在 UTC
    16:00~24:00 发布（= 北京时间次日 00:00~08:00）时，`published` 记成前一天、
    `published_at` 记成当天 —— 实测 4129 条里 172 条系统性差 1 天。
    症状：界面「实时监测」最新只到昨天，"没有今天的文章"；而「每日报告」按
    `fetched_at` 分组却能列出当天内容，两边看起来自相矛盾。
    修法：凡有 `published_at`（本机时区完整时刻）的条目，`published := published_at[:10]`。
    （代码根因已在 live.py::_norm_date 修掉，本遍只回填历史数据。）

  【Pass B｜截断残骸修复】原逻辑
    live.py 更早版本把 RFC 2822 日期（Wed, 29 Jul 2026 …）直接 [:10] 截成
    'Wed, 29 Ju'。逐级回退：① live_cache/*.xml 原始快照按 guid 找回；② guid/link
    内嵌日期；③ 唯一月份前缀推断（Se→Sep 敢修，Ju→Jun/Jul 不敢）；④ 置空串。

  【Pass C｜同步 corpus.json】
    引擎启动先加载 corpus.json，`add_documents` **跳过已存在 id** → 对同时存在于
    corpus 与 live_feed 的条目，corpus 的旧值胜出。monitor.py 的文章同步来源是
    远程 `created_at`，**不会**用 live_feed 回填，故需一并按 id 覆盖。

用法：
    python tools/修复实时情报日期.py            # 修 live_feed + corpus
    python tools/修复实时情报日期.py --no-corpus  # 只修 live_feed（快）
    python tools/修复实时情报日期.py --check      # 只报告，不写盘
修复后重启服务（启动服务.bat）生效。
"""
import gc
import io
import json
import os
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))
sys.path.insert(0, os.path.join(ROOT, "core"))

import live as L                      # noqa: E402  —— 复用 _norm_date
from engine import _fix_bad_date      # noqa: E402

FEED_FP = L.FEED_FP
CACHE_DIR = L.CACHE_DIR
CORPUS_FP = os.path.join(ROOT, "data", "corpus.json")
STAMP = time.strftime("%Y%m%d")


def _cache_date_map():
    """扫一遍 live_cache/*.xml：guid → 规范化日期（取 pubDate/published/updated 原文再修）。"""
    out = {}
    if not os.path.isdir(CACHE_DIR):
        return out
    for fn in os.listdir(CACHE_DIR):
        if not fn.endswith(".xml"):
            continue
        fp = os.path.join(CACHE_DIR, fn)
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as f:
                xml = f.read()
        except OSError:
            continue
        for m in re.finditer(r"<(item|entry)\b.*?</\1>", xml, re.S):
            b = m.group(0)
            g = lambda p: (re.search(p, b, re.S).group(1).strip() if re.search(p, b, re.S) else "")
            guid = g(r"<guid[^>]*>([^<]+)</guid>") or g(r"<id[^>]*>([^<]+)</id>")
            raw = g(r"<(?:pubDate|published|updated|dc:date)[^>]*>([^<]+)</")
            if not guid:
                continue
            d = L._norm_date(raw)
            if d:
                out.setdefault(guid.strip(), d)
    return out


def _url_date(*texts):
    for t in texts:
        m = re.search(r"(20\d{2})[/-](\d{1,2})[/-](\d{1,2})", t or "")
        if m:
            return "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3)))
    return ""


def _backup(fp):
    """首次修复前留一份带日期的备份，避免二次运行覆盖上一次的良好状态。"""
    if not os.path.isfile(fp):
        return None
    bak = "%s.bak-datetz-%s" % (fp, STAMP)
    if not os.path.isfile(bak):
        shutil.copy2(fp, bak)
    return bak


def _patch_corpus(fixmap, dry=False):
    """按 id 覆盖 corpus.json 中这些条目的 published。写入前校验 tmp 是合法 JSON。"""
    if not os.path.isfile(CORPUS_FP):
        print("找不到", CORPUS_FP)
        return 0
    if not fixmap:
        print("corpus：无待修 id")
        return 0
    t0 = time.time()
    with open(CORPUS_FP, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    upper = {str(k).upper(): v for k, v in fixmap.items()}
    n = 0
    for key in ("records", "knowledge", "papers"):
        arr = corpus.get(key)
        if not isinstance(arr, list):
            continue
        for r in arr:
            if not isinstance(r, dict):
                continue
            want = upper.get(str(r.get("id") or "").upper())
            if want and str(r.get("published") or "")[:10] != want:
                r["published"] = want
                n += 1
    if not n:
        print("corpus：无需修复（已一致）")
        return 0
    if dry:
        print("corpus：dry-run 将修 %d 条（未写盘）" % n)
        return n
    _backup(CORPUS_FP)
    tmp = CORPUS_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    del corpus
    gc.collect()
    # 校验 tmp 合法后再原子替换（corpus 是引擎的加载源，写坏=服务起不来）
    with open(tmp, "r", encoding="utf-8") as f:
        json.load(f)
    os.replace(tmp, CORPUS_FP)
    print("corpus：已修 %d 条 · %.1fs" % (n, time.time() - t0))
    return n


def main():
    args = sys.argv[1:]
    dry = "--check" in args
    do_corpus = "--no-corpus" not in args

    if not os.path.isfile(FEED_FP):
        print("找不到", FEED_FP)
        return
    cache = _cache_date_map()
    rows = []
    with open(FEED_FP, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue

    # ---------- Pass A：时区口径对齐 ----------
    tz_fix, tz_map = 0, {}
    for r in rows:
        pa = str(r.get("published_at") or "").strip()
        if not pa:
            continue
        want, cur = pa[:10], str(r.get("published") or "").strip()[:10]
        if want and cur != want:
            r["published"] = want
            tz_fix += 1
            if cur:
                tz_map[str(r.get("id") or "")] = want

    # ---------- Pass B：截断残骸修复（原逻辑） ----------
    ISO = re.compile(r"^\d{4}-\d{1,2}-\d{1,2}")
    fixed, still_bad = 0, 0
    for r in rows:
        pub = str(r.get("published") or "").strip()
        if pub and ISO.match(pub):
            continue
        new = ""
        guid = str(r.get("guid") or r.get("id") or "")
        if guid:
            new = cache.get(guid.strip(), "")
        if not new:
            new = _url_date(guid, r.get("link") or "", r.get("id") or "")
        if not new:
            new = _fix_bad_date(pub)
        if new and new != pub:
            fixed += 1
        if not new:
            still_bad += 1
        r["published"] = new
        if new and str(r.get("id") or ""):
            tz_map[str(r.get("id") or "")] = new

    print("live_feed %d 条：Pass A 时区对齐 %d 条 · Pass B 截断修复 %d 条 · 仍无法恢复(置空) %d 条"
          % (len(rows), tz_fix, fixed, still_bad))

    if dry:
        print("--check：未写盘。")
        if do_corpus:
            _patch_corpus(tz_map, dry=True)
        return

    _backup(FEED_FP)
    tmp = FEED_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, FEED_FP)
    print("live_feed：已写回", FEED_FP)

    if do_corpus:
        want = {k: v for k, v in tz_map.items() if k}
        _patch_corpus(want)
    print("重启服务（启动服务.bat）后生效。")


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
