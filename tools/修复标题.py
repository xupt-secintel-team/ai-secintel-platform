# -*- coding: utf-8 -*-
"""修复标题.py —— 就地重写历史数据里被点号切碎的 CVE 标题（2026-10-07）

## 为什么要这个工具

`core/fetch_corpus.py:build_record` 以前用 `desc.split(".")[0]` 生成标题。
漏洞描述里全是版本号，第一个点几乎总是版本号里的点：

    "IBM Langflow OSS 1.0.0 through 1.12.2 could allow ..."
    → 标题 = "IBM Langflow OSS 1"

于是 5 个不同 CVE 的标题一字不差，情报列表里显示成 5 行"重复条目"，
日报按标题去重时还会把它们**合并成一条**（静默丢情报）。

根因已修（`short_title()`），但 `data/` 下已经落盘的几十万条记录仍是旧标题，
所以再跑一次这个工具就地改写。**只改标题一个字段，其余字段原样写回。**

## 覆盖的数据文件

| 文件 | 说明 |
|---|---|
| `data/corpus.json` | 主语料（records / knowledge 两大数组） |
| `data/live_feed.jsonl` | 快车道实时流（逐行 JSON） |
| `data/monitor_state.json` | 定时增量同步的 history[*].summary.new_docs |
| `data/cn/*.json` | 中文社区 / 投稿文章（列表形式） |

## 用法

    py -3 tools/修复标题.py --dry   # 只统计会改多少条，不写盘（先跑这个）
    py -3 tools/修复标题.py         # 真正改写 + 预热索引缓存
    py -3 tools/修复标题.py --no-warm   # 改写但不预热索引（下次启动会重建索引）

写盘一律「先写 .tmp 再 os.replace」——中途中断不会留下半个损坏的语料。
改完 corpus.json 后 `.idxcache` 的字节指纹必然失配，服务下次启动会重建索引
（数分钟）。加 `--warm`（默认开）会在这里就把索引建好并落盘，让下次启动秒开。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "core"))

import paths                       # noqa: E402
from fetch_corpus import short_title   # noqa: E402

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def fix_rec(rec):
    """就地修正一条记录。返回 True 表示标题被改过。"""
    if not isinstance(rec, dict):
        return False
    rid = str(rec.get("id") or "")
    if not CVE_RE.match(rid):
        return False
    desc = rec.get("desc")
    if not desc:
        return False
    want = short_title(rid, desc)
    if rec.get("title") == want:
        return False
    rec["title"] = want
    return True


def _iter_lists(obj):
    """从任意嵌套结构里找出「记录列表」并逐条修正。

    corpus.json 是 {"meta":…, "records":[…], "knowledge":[…], …}，
    monitor_state.json 是 {"history":[{"summary":{"new_docs":[…]}}]}，
    data/cn/*.json 是顶层列表。统一按「list 且元素是含 id 的 dict」识别。
    """
    n = 0
    if isinstance(obj, dict):
        for v in obj.values():
            n += _iter_lists(v)
    elif isinstance(obj, list):
        hit = False
        for it in obj:
            if isinstance(it, dict) and it.get("id"):
                hit = True
                if fix_rec(it):
                    n += 1
        if not hit:
            for it in obj:
                n += _iter_lists(it)
    return n


def _atomic_write_json(fp, obj, **kw):
    tmp = fp + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, **kw)
    for i in range(5):                       # Windows 下文件可能被短暂占用
        try:
            os.replace(tmp, fp)
            return
        except PermissionError:
            time.sleep(0.4 * (i + 1))
    os.replace(tmp, fp)


def fix_json_file(fp, dry):
    try:
        with io.open(fp, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:120]
    n = _iter_lists(obj)
    if n and not dry:
        _atomic_write_json(fp, obj, ensure_ascii=False, separators=(",", ":"))
    return n, None


def fix_jsonl_file(fp, dry):
    try:
        with io.open(fp, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:120]
    n, out = 0, []
    for line in lines:
        s = line.strip()
        if not s:
            out.append(line)
            continue
        try:
            r = json.loads(s)
        except Exception:  # noqa: BLE001 —— 坏行原样保留，不丢数据
            out.append(line)
            continue
        if fix_rec(r):
            n += 1
        out.append(json.dumps(r, ensure_ascii=False) + "\n")
    if n and not dry:
        tmp = fp + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(out)
        os.replace(tmp, fp)
    return n, None


def main():
    ap = argparse.ArgumentParser(description="就地修复历史数据里被切碎的 CVE 标题")
    ap.add_argument("--dry", action="store_true", help="只统计，不写盘")
    ap.add_argument("--no-warm", action="store_true", help="不预热索引缓存")
    a = ap.parse_args()

    targets = [(paths.CORPUS_FP, "json")]
    for name in ("live_feed.jsonl", "monitor_state.json"):
        p = os.path.join(paths.DATA_DIR, name)
        if os.path.isfile(p):
            targets.append((p, "jsonl" if name.endswith(".jsonl") else "json"))
    cn = os.path.join(paths.DATA_DIR, "cn")
    if os.path.isdir(cn):
        for fn in sorted(os.listdir(cn)):
            if fn.endswith(".json") and not fn.endswith(".bak"):
                targets.append((os.path.join(cn, fn), "json"))

    total = 0
    for fp, kind in targets:
        if not os.path.isfile(fp):
            continue
        fn = fix_jsonl_file(fp, a.dry) if kind == "jsonl" else fix_json_file(fp, a.dry)
        n, err = fn
        size_mb = round(os.path.getsize(fp) / 1048576.0, 1)
        if err:
            print("  [跳过] %-46s %s" % (os.path.basename(fp), err))
            continue
        total += n
        print("  %s %-44s %6.1f MB  标题被修正 %d 条"
              % ("[dry]" if a.dry else "[ok] ", os.path.relpath(fp, _ROOT),
                 size_mb, n))

    print("\n标题修正合计：%d 条%s" % (total, "（dry-run，未写盘）" if a.dry else ""))
    if a.dry or not total:
        return 0

    if not a.no_warm:
        print("\n预热索引缓存（把 .idxcache 重建好，下次启动秒开；约数分钟）...")
        try:
            from engine import Engine
            t0 = time.time()
            eng = Engine(paths.CORPUS_FP)
            eng._save_index_cache(paths.CORPUS_FP)
            print("  索引缓存已更新：%d 文档（%.1fs）" % (len(eng.docs), time.time() - t0))
        except Exception as e:  # noqa: BLE001 —— 预热失败不影响数据修复
            print("  预热失败（不影响数据，只是下次启动要重建索引）：%s" % str(e)[:160])
    else:
        print("\n未预热索引：服务下次启动会全量重建（数分钟）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
