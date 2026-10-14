# -*- coding: utf-8 -*-
"""_cleanup_test_artifacts.py —— 清除本机假文章服务器注入的测试投稿

## 为什么需要这个工具

`POST /api/m1/submit_article`（用户粘贴链接即时收录）在本机回归时被
`tools/_e2e_article_server.py`（假文章服务器，端口 8891/8892）灌过一批测试稿：
标题是 "Prompt Injection 实战：大模型越狱与防护 · 菊梅梅桥" 这类随机文案，
链接全部指向 `http://127.0.0.1:8892/?r=...`。它们会：

  · 出现在左栏「实时监测 · 最新情报」最上面（同标题只差作者后缀，看着像重复条目）
  · 混进每日按类报告（被算进「③ AI应用与智能体」）
  · 污染"与已有文章过分相同"判定（实测同标题出现 3 次）

判据用**链接里的 127.0.0.1**，不用标题 —— 标题是随机的，按标题判会误伤
真实采集数据。真实外链（freebuf.com / csdn.net …）一条都不碰。

## 覆盖范围（2026-10-07 扩到语料本体）

旧版只清 `data/cn/submitted.json` 与 `data/live_feed.jsonl`，结果**语料里那份
还在**（`corpus.json` 才是主体语料），所以清完在界面里照样看得见。现在一并清：

| 文件 | 说明 |
|---|---|
| `data/live_feed.jsonl` | 快车道实时流（服务启动回放源） |
| `data/cn/submitted.json` | 投稿文章离线并入源 |
| `data/corpus.json` | 主体语料（records / knowledge） |
| `data/live_seen.json` | 已见 id 集合（不清也不会复活，只是留垃圾） |

写盘一律先备份 `.bak`；`corpus.json` 改完 `.idxcache` 必然失配，
服务下次启动会重建索引（数分钟），这是预期行为。

用法：
    py -3 tools/_cleanup_test_artifacts.py            # dry-run，看清单
    py -3 tools/_cleanup_test_artifacts.py --apply    # 真删（先备份 .bak）
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MARK = "127.0.0.1"


def _backup(fp):
    try:
        shutil.copy(fp, fp + ".bak")
    except OSError:
        pass


def _hit(rec):
    return isinstance(rec, dict) and MARK in str(rec.get("link") or "")


def _clean_list(obj, dry):
    """递归找出所有「记录列表」并剔除测试稿，返回命中数。"""
    n = 0
    if isinstance(obj, dict):
        for v in obj.values():
            n += _clean_list(v, dry)
    elif isinstance(obj, list):
        if any(isinstance(x, dict) and "id" in x for x in obj):
            keep = [x for x in obj if not _hit(x)]
            n += len(obj) - len(keep)
            if n and not dry:
                obj[:] = keep
        else:
            for x in obj:
                n += _clean_list(x, dry)
    return n


def clean_json(fp, dry):
    if not os.path.isfile(fp):
        return 0
    try:
        with io.open(fp, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:  # noqa: BLE001
        print("  [跳过] %s：%s" % (os.path.basename(fp), str(e)[:90]))
        return 0
    if not dry:
        _backup(fp)
    n = _clean_list(obj, dry)
    if n and not dry:
        tmp = fp + ".tmp"
        with io.open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, fp)
    return n


def clean_jsonl(fp, dry):
    if not os.path.isfile(fp):
        return 0
    with io.open(fp, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    kept, n = [], 0
    for line in lines:
        s = line.strip()
        if not s:
            kept.append(line)
            continue
        try:
            o = json.loads(s)
        except Exception:  # noqa: BLE001 —— 坏行原样保留，不丢数据
            kept.append(line)
            continue
        if _hit(o):
            n += 1
            continue
        kept.append(line)
    if n and not dry:
        _backup(fp)
        tmp = fp + ".tmp"
        with io.open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(kept)
        os.replace(tmp, fp)
    return n


def collect_ids(fp):
    """先把要删的 id 收集出来（用于清 live_seen.json）。"""
    ids = set()
    if not os.path.isfile(fp):
        return ids
    op = io.open(fp, "r", encoding="utf-8", errors="replace")
    try:
        if fp.endswith(".jsonl"):
            for line in op:
                s = line.strip()
                if not s:
                    continue
                try:
                    o = json.loads(s)
                except Exception:  # noqa: BLE001
                    continue
                if _hit(o):
                    ids.add(str(o.get("id")))
        else:
            walk_obj = json.load(op)

            def walk(o):
                if isinstance(o, dict):
                    if _hit(o):
                        ids.add(str(o.get("id")))
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
            walk(walk_obj)
    except Exception:  # noqa: BLE001 —— 收集失败不阻断清理
        pass
    finally:
        op.close()
    ids.discard("None")
    ids.discard("")
    return ids


def main():
    ap = argparse.ArgumentParser(description="清除本机假文章服务器（127.0.0.1）注入的测试投稿")
    ap.add_argument("--apply", action="store_true", help="真正写盘（默认只统计）")
    a = ap.parse_args()
    dry = not a.apply

    data = os.path.join(ROOT, "data")
    feed = os.path.join(data, "live_feed.jsonl")
    corpus = os.path.join(data, "corpus.json")
    subs = os.path.join(data, "cn", "submitted.json")

    ids = collect_ids(feed) | collect_ids(subs) | collect_ids(corpus)

    total = 0
    for fp, fn in ((feed, clean_jsonl), (subs, clean_json), (corpus, clean_json)):
        n = fn(fp, dry)
        total += n
        mb = (os.path.getsize(fp) / 1048576.0) if os.path.isfile(fp) else 0
        print("  %s %-22s %7.1f MB  命中 %d 条"
              % ("[dry]" if dry else "[ok] ", os.path.basename(fp), mb, n))

    # live_seen.json：结构 {ids:[...], meta:{...}}
    seen = os.path.join(data, "live_seen.json")
    n = 0
    if ids and os.path.isfile(seen):
        try:
            with io.open(seen, "r", encoding="utf-8") as f:
                sd = json.load(f)
            before = len(sd.get("ids") or [])
            sd["ids"] = [x for x in (sd.get("ids") or []) if x not in ids]
            n = before - len(sd["ids"])
            if n and not dry:
                _backup(seen)
                with io.open(seen, "w", encoding="utf-8") as f:
                    json.dump(sd, f, ensure_ascii=False)
        except Exception as e:  # noqa: BLE001
            print("  [跳过] live_seen.json：%s" % str(e)[:90])
    print("  %s %-22s %14d 条"
          % ("[dry]" if dry else "[ok] ", "live_seen.json", n))

    print("\n合计命中测试投稿 %d 条%s"
          % (total, "（dry-run，未写盘）" if dry else "（已清理，原文件留有 .bak）"))
    if not dry and total:
        print("提示：corpus.json 已变，下次启动服务会重建索引（数分钟，属预期）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
