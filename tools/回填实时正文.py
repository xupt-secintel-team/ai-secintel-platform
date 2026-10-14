# -*- coding: utf-8 -*-
"""
回填实时正文.py —— 用缓存快照补齐「正文缺失/退化」的实时条目
====================================================================
背景（2026-10-08 实测）：
  实时监测里"Ollama / vLLM 版本发布"两条源点开"几乎没有信息"。根因是
  `_rss_items` 的正文正则不认 Atom 的 `<content>`（已在 live.py 修掉），
  但**修复前入库的记录 desc 已经退化成标题**，光改代码不会追溯历史数据。

本工具用 `data/live_cache/*.xml` 原始快照重跑一次解析（走**已修好**的
  `_rss_items`），按 `link` 匹配回填 live_feed.jsonl 与 corpus.json 里
  正文过薄的条目。

诚实边界（重要）：
  只回填「**源里本来就有**正文」的条目。实测 667 条正文过薄中：
    · 51 条能从快照回填（几乎全是 GitHub releases.atom 的发布说明）
    · 616 条**源 feed 本身就只有标题、没有 description/content**
      —— 这部分**任何代码都变不出正文**，只能靠 UI 明示"该源未提供正文摘要"，
      绝不允许拿标题冒充正文（那已经是既有的 desc=标题 回退行为，见 live.py）。

用法：
    python tools/回填实时正文.py --check    # 只报告
    python tools/回填实时正文.py
副作用：desc 参与检索索引，回填后 .idxcache 会因文件大小变化而失效，
        下次启动全量重建（实测约 13 分钟）。
"""
import gc
import glob
import io
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

import live as L  # noqa: E402

CORPUS_FP = os.path.join(ROOT, "data", "corpus.json")
MIN_BODY = 40          # 正文短于这个长度视为"退化"
TRUNC = 2500           # 与 live.py 的 summ[:2500] 保持一致


def build_snapmap():
    """link → 正文（走已修好的 _rss_items，能取到 Atom <content>）。"""
    out = {}
    files = glob.glob(os.path.join(L.CACHE_DIR, "*.xml"))
    for fp in files:
        try:
            xml = io.open(fp, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        try:
            items = L._rss_items(xml, os.path.basename(fp))
        except Exception:  # noqa: BLE001 —— 单个坏快照不能中断整体回填
            continue
        for it in items:
            s = (it.get("summary") or "").strip()
            if it.get("link") and len(s) > MIN_BODY:
                out[it["link"]] = s[:TRUNC]
    return out, len(files)


def _thin(d):
    t = str(d.get("title") or "").strip()
    s = str(d.get("desc") or "").strip()
    if not t:
        return False
    return s == t or len(s) < MIN_BODY


def main():
    dry = "--check" in sys.argv[1:]
    snap, nfiles = build_snapmap()
    print("扫描缓存快照 %d 个，可提供正文的 link %d 条" % (nfiles, len(snap)))

    # ── live_feed.jsonl ──
    rows = []
    with io.open(L.FEED_FP, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    n_fix = n_nofix = 0
    for r in rows:
        if not _thin(r):
            continue
        new = snap.get(r.get("link") or "")
        if new and len(new) > len(str(r.get("desc") or "").strip()):
            r["desc"] = new
            n_fix += 1
        else:
            n_nofix += 1
    print("live_feed：可回填 %d 条 · 源本身无正文 %d 条" % (n_fix, n_nofix))

    # ── corpus.json（按 link 匹配；语料里存的是同一批条目）──
    if not os.path.isfile(CORPUS_FP):
        print("找不到 corpus.json，跳过")
        return 0
    t0 = time.time()
    with open(CORPUS_FP, encoding="utf-8") as f:
        corpus = json.load(f)
    c_fix = 0
    for key in ("records", "knowledge", "papers"):
        for r in corpus.get(key) or []:
            if not isinstance(r, dict) or not _thin(r):
                continue
            new = snap.get(r.get("link") or "")
            if new and len(new) > len(str(r.get("desc") or "").strip()):
                r["desc"] = new
                c_fix += 1
    print("corpus：可回填 %d 条（载入 %.1fs）" % (c_fix, time.time() - t0))

    if dry:
        print("--check：未写盘。")
        return 0
    if not (n_fix or c_fix):
        print("无需回填。")
        return 0

    stamp = time.strftime("%Y%m%d")
    for fp in (L.FEED_FP, CORPUS_FP):
        bak = "%s.bak-desc-%s" % (fp, stamp)
        if os.path.isfile(fp) and not os.path.isfile(bak):
            shutil.copy2(fp, bak)
            print("已备份 →", os.path.basename(bak))

    tmp = L.FEED_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, L.FEED_FP)
    print("已写回", L.FEED_FP)

    if c_fix:
        tmp = CORPUS_FP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
        del corpus
        gc.collect()
        with open(tmp, encoding="utf-8") as f:      # 校验合法再替换
            json.load(f)
        os.replace(tmp, CORPUS_FP)
        print("已写回", CORPUS_FP)
    print("★ desc 参与检索索引：下次启动会重建 .idxcache（约 13 分钟，一次性）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())