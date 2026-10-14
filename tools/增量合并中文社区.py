# -*- coding: utf-8 -*-
"""
增量合并：data/cn/*.json（中文社区文章）→ data/corpus.json 的 knowledge
=========================================================================
为什么需要这个脚本：
  merge_full.py / merge_ai.py 都是「全量重建」—— 要重拉 KEV / GHSA / NVD 全量池
  并多进程富化，跑一次几十分钟。而快车道每 15s 落盘的中文社区文章，只写了
  data/cn/*.json，没有进 corpus.json —— 引擎只加载 corpus，于是「文章已经在
  本地文件里，却检索不到」。
  这里只做一件事：把 data/cn 里**corpus 还没有的 id** 追加进 knowledge，
  不动 records（漏洞记录），不重拉任何网络源。

用法：
  python tools/增量合并中文社区.py            # 先看缺多少（dry-run）
  python tools/增量合并中文社区.py --apply    # 真正写入
  python tools/增量合入中文社区.py --limit 50 # 最多补 50 条（先小批量验证）
"""

import io
import json
import os
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

import paths  # noqa: E402
import extra_sources as X  # noqa: E402
import live as L  # noqa: E402 —— 只为复用 _guess_cat（与 merge_ai.classify_knowledge 同口径）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

DATA = paths.DATA_DIR
CORPUS_FP = os.path.join(DATA, "corpus.json")
CN_DIR = os.path.join(DATA, "cn")
CN_FILES = ["csdn.json", "anquanke.json", "xz.json", "submitted.json"]
BACKUP_FP = CORPUS_FP + ".bak_cn"


def load_existing_ids(corpus):
    got = set()
    for r in (corpus.get("records") or []):
        if isinstance(r, dict) and r.get("id"):
            got.add(str(r["id"]).upper())
    for r in (corpus.get("knowledge") or []):
        if isinstance(r, dict) and r.get("id"):
            got.add(str(r["id"]).upper())
    for r in (corpus.get("papers") or []):
        if isinstance(r, dict) and r.get("id"):
            got.add(str(r["id"]).upper())
    return got


def main():
    apply = "--apply" in sys.argv
    limit = 0
    for a in sys.argv[1:]:
        if a.startswith("--limit="):
            try:
                limit = int(a.split("=", 1)[1])
            except ValueError as _sw_e:
                _swallow("tools/增量合并中文社区.py:62", _sw_e)

    print("[cn-merge] ---------- 增量合并 data/cn → corpus.json ----------")
    with open(CORPUS_FP, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    knowledge = corpus.get("knowledge") or []
    records = corpus.get("records") or []
    print(f"[cn-merge] 现有：records {len(records)} / knowledge {len(knowledge)}")

    have = load_existing_ids(corpus)
    print(f"[cn-merge] 已有 id 总数 {len(have)}")

    missing = []
    for fn in CN_FILES:
        fp = os.path.join(CN_DIR, fn)
        if not os.path.isfile(fp):
            print(f"[cn-merge] 跳过（缺失）{fn}")
            continue
        try:
            with open(fp, "r", encoding="utf-8") as f:
                arr = json.load(f)
        except Exception as e:  # noqa: BLE001
            print(f"[cn-merge] {fn} 读取失败：{e}")
            continue
        n0 = len(missing)
        seen = set()
        for r in arr:
            if not isinstance(r, dict):
                continue
            rid = str(r.get("id") or "").strip()
            if not rid or rid.upper() in have or rid in seen:
                continue
            seen.add(rid)
            # 兜底字段骨架：data/cn 的条目来自 harvest_cn / live 两条通道，
            # 字段基本一致，这里只补可能缺的，避免引擎建索引或前端渲染时报错
            r.setdefault("published", "")
            r.setdefault("sources", [])
            if not r.get("type"):
                r["type"] = "article"
            if not r.get("category"):
                r["category"] = L._guess_cat(
                    str(r.get("title") or "") + " " + str(r.get("desc") or ""))
            r.pop("live", None)
            missing.append(r)
        print(f"[cn-merge] {fn}: {len(arr)} 条 → 待补 {len(missing) - n0} 条")

    print(f"[cn-merge] 合计待补 {len(missing)} 条")
    if not missing:
        print("[cn-merge] 无新增，退出。")
        return

    if limit and len(missing) > limit:
        print(f"[cn-merge] --limit={limit}，本次只补前 {limit} 条")
        missing = missing[:limit]

    if not apply:
        print("[cn-merge] dry-run（未写入）。加 --apply 真正执行。前 5 条预览：")
        for r in missing[:5]:
            print("   ", r.get("id"), "|", r.get("published"), "|",
                  (r.get("title") or "")[:40])
        return

    # 备份（只保留一份最近备份，324MB 的文件不宜多留）
    import shutil
    shutil.copy2(CORPUS_FP, BACKUP_FP)
    print(f"[cn-merge] 已备份 → {BACKUP_FP}")

    knowledge.extend(missing)
    corpus["knowledge"] = knowledge

    tmp = CORPUS_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CORPUS_FP)

    # 索引缓存基于 corpus 的 mtime/size，必须清掉，否则引擎仍在旧索引里找
    idx = CORPUS_FP + ".idxcache"
    if os.path.isfile(idx):
        os.remove(idx)
        print("[cn-merge] 已清除索引缓存（下次启动自动重建）")

    sz = os.path.getsize(CORPUS_FP) / 1048576
    print(f"[cn-merge] ✅ 写入完成：knowledge {len(knowledge)} 条，总文档 "
          f"{len(records) + len(knowledge)}，文件 {sz:.1f} MB")


if __name__ == "__main__":
    main()
