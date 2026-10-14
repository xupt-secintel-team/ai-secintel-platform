# -*- coding: utf-8 -*-
"""
增量合并：data/live_feed.jsonl（快车道实时流）→ data/corpus.json 的 knowledge
=============================================================================
为什么需要它：
  快车道每 15s 抓到的博客/公告/论文条目只写进 data/live_feed.jsonl，
  启动时靠 _live_replay 灌回引擎内存 —— 但**不进 corpus.json**。
  结果是：CrowdStrike 61 条、OpenAI 48 条、ZDI 40 条、ESET 20 条这些新来源，
  在检索里搜得到，可在语料体检里根本不出现（体检只读 corpus），
  重启后也要等回放；更关键的是它们不参与问答的语料基座。
  本脚本把 corpus 里还没有的 id 追加进 knowledge，不动 records（漏洞记录），
  不重拉任何网络源。

用法：
  python tools/合并快车道情报.py              # 先看缺多少（dry-run）
  python tools/合并快车道情报.py --apply      # 真正写入
  python tools/合并快车道情报.py --apply --limit 100
"""

import io
import json
import os
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

import paths  # noqa: E402

DATA = paths.DATA_DIR
CORPUS_FP = os.path.join(DATA, "corpus.json")
FEED_FP = os.path.join(DATA, "live_feed.jsonl")
BACKUP_FP = CORPUS_FP + ".bak_live"


def _load_feed():
    """读实时流，按 id 去重（后写的覆盖先写的），返回有序列表。"""
    if not os.path.isfile(FEED_FP):
        return []
    out, seen = [], set()
    for line in open(FEED_FP, "r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        rid = r.get("id")
        if not rid or rid in seen:
            continue
        seen.add(rid)
        out.append(r)
    return out


def main():
    apply = "--apply" in sys.argv
    limit = 0
    for i, a in enumerate(sys.argv):
        if a == "--limit" and i + 1 < len(sys.argv):
            try:
                limit = int(sys.argv[i + 1])
            except ValueError:
                limit = 0

    feed = _load_feed()
    print(f"实时流条目：{len(feed)}")

    t0 = time.time()
    with open(CORPUS_FP, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    print(f"语料加载完成（{time.time() - t0:.1f}s）"
          f"records={len(corpus.get('records', []))} "
          f"knowledge={len(corpus.get('knowledge', []))}")

    have = set()
    for d in corpus.get("records", []):
        have.add(str(d.get("id") or ""))
    for d in corpus.get("knowledge", []):
        have.add(str(d.get("id") or ""))

    todo = [r for r in feed if str(r.get("id") or "") not in have]
    print(f"corpus 中缺失：{len(todo)} 条")
    if not todo:
        print("无需合并。")
        return

    if limit:
        todo = todo[:limit]
        print(f"（--limit 生效，本轮只处理 {len(todo)} 条）")

    # 来源分布预览
    from collections import Counter
    src = Counter((r.get("sources") or ["?"])[0] for r in todo)
    print("—— 待并入来源 Top 15 ——")
    for k, v in src.most_common(15):
        print(f"  {k:<28} {v}")

    if not apply:
        print("\n这是 dry-run。确认无误后加 --apply 真正写入。")
        return

    # 备份（只保留一份，避免 342MB × N 撑爆磁盘）
    if not os.path.isfile(BACKUP_FP):
        print(f"备份原语料 → {os.path.basename(BACKUP_FP)}")
        with open(BACKUP_FP + ".tmp", "w", encoding="utf-8") as f:
            json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(BACKUP_FP + ".tmp", BACKUP_FP)

    kn = corpus.setdefault("knowledge", [])
    for r in todo:
        r.setdefault("kind", f"{(r.get('sources') or ['?'])[0]} 实时情报")
        r.setdefault("tags", [])
        if "实时情报" not in r["tags"]:
            r["tags"].append("实时情报")
        r.setdefault("fetched_at", time.strftime("%Y-%m-%dT%H:%M:%S"))
        kn.append(r)

    print(f"写入中（knowledge {len(kn)} 条）...")
    t1 = time.time()
    tmp = CORPUS_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CORPUS_FP)
    print(f"完成：新增 {len(todo)} 条，knowledge 合计 {len(kn)}，"
          f"耗时 {time.time() - t1:.1f}s")
    print("注意：服务需重启（或触发一次全量同步）才会加载新的 corpus。")


if __name__ == "__main__":
    main()
