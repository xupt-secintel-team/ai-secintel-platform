# -*- coding: utf-8 -*-
"""扫描语料里「标题被截断成描述的字面前缀」的坏记录（short_title 修复前的遗留）。"""
import io, json, os, sys, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
from fetch_corpus import short_title

t0 = __import__("time").time()
corpus = json.load(io.open(os.path.join(ROOT, "data", "corpus.json"), encoding="utf-8"))
print("载入 %.1fs" % (__import__("time").time() - t0), flush=True)
bad = []
for key in ("records", "knowledge", "papers"):
    for r in corpus.get(key) or []:
        if not isinstance(r, dict):
            continue
        cid = str(r.get("id") or "")
        t = str(r.get("title") or "").strip()
        d = str(r.get("desc") or "").strip()
        if not (cid.startswith("CVE-") and t and d):
            continue
        core = t.rstrip("…").strip()
        # 坏特征：标题是描述的字面前缀（正确标题会带 "CVE-x " 前缀，不会是描述前缀）
        if d.startswith(core) and t != short_title(cid, d):
            bad.append((cid, t, short_title(cid, d)))
print("命中坏记录：%d 条" % len(bad))
print("\n--- 前 15 条 ---")
for cid, old, new in bad[:15]:
    print("  %s\n     旧: %s\n     新: %s" % (cid, old[:80], new[:110]))
print("\n按来源键分布:", collections.Counter(k for k in ("records","knowledge","papers") for _ in ()))
json.dump([{"id": c, "old": o, "new": n} for c, o, n in bad],
          io.open(os.path.join(ROOT, "data", "_bad_titles.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("\n明细已写入 data/_bad_titles.json")
