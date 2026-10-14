# -*- coding: utf-8 -*-
"""reorder_by（索引整体重排）回归测试。

背景：monitor 落盘前把 records 按 published 倒序排，引擎里却是
「旧记录原序 + 新记录追加末尾」→ 两边顺序分叉 → .idxcache 的 id 指纹对不上
→ 每次启动全量重建（实测 360~410s）。

修法是在写盘那一刻调 Engine.reorder_by()，把内存索引也排成同一顺序。
倒排表 postings 里存的是**下标**，顺序一变下标全失效，所以这个重排
必须把 postings / dl / tf / concept_vecs / recency / cat_docs / id_map
全部同步平移 —— 漏一个就会出现「A 的分数配 B 的正文」。

本测试的核心断言：重排前后**同一条查询必须命中同一批文档**（顺序可变，
集合与各自的分值必须一致）。只比 id 集合不够 —— 索引错位时集合往往还
是对的，错的是分数和正文。
"""
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.engine import SearchEngine  # noqa: E402


def _mk(i, text, cat="vuln"):
    return {
        "id": f"CVE-2026-{100000 + i}",
        "title": f"sample {i}",
        "desc": text,
        "published": f"2026-09-{(i % 28) + 1:02d}",
        "category": cat,
        "cvss": {"score": 5.0 + (i % 5), "severity": "MEDIUM"},
        "products": [f"prod{i % 7}"],
        "cwe": [f"CWE-{i % 20}"],
        "sources": ["test"],
    }


def main():
    tmp = os.path.join(tempfile.gettempdir(), "_reorder_test.json")
    corpus = {
        "meta": {"version": "test"},
        "papers": [],
        "records": [_mk(i, f"alpha{tok} beta common") for i, tok in
                    enumerate(["zzz", "yyy", "xxx", "www", "vvv", "uuu", "ttt", "sss"])],
        "knowledge": [],
    }
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False)

    eng = SearchEngine(tmp)
    print(f"初始文档数 {len(eng.docs)}")

    queries = ["alpha", "beta common", "zzz", "prod3", "CWE-5"]
    before = {}
    for q in queries:
        r = eng.search(q, top_k=50)
        before[q] = {(x.get("id"), round(float(x.get("score") or 0), 4))
                     for x in (r.get("results") or [])}
    print(f"重排前采集 {len(queries)} 个查询的 (id, score) 快照")

    # 新顺序：完全倒序（模拟按 published 倒序落盘的效果）
    new_order = [d["id"] for d in reversed(eng.docs)]
    ok = eng.reorder_by(new_order)
    print(f"reorder_by 返回 {ok}（应为 True）")
    assert ok, "reorder_by 应当成功"

    # 1) 顺序确实变了
    now = [d["id"] for d in eng.docs]
    assert now == new_order, "docs 顺序未按 id_order 排好"
    print("① docs 顺序已倒置  OK")

    # 2) id_map 指向的文档正确
    for idx, i in enumerate(new_order):
        j = eng.id_map[i.upper()]
        assert eng.docs[j]["id"] == i, f"id_map 错位: {i} -> {j}"
    print("② id_map 与 docs 一致  OK")

    # 3) 倒排表下标指向正确文档（这是最容易错的地方）
    import random
    random.seed(0)
    checked = 0
    for _ in range(30):
        t = random.choice(list(eng.postings.keys()))
        for doc_i in eng.postings[t]:
            agg = eng.tf[doc_i]
            assert t in agg, f"倒排错位: 词项 {t} 指向下标 {doc_i}，但该文档没有这个词"
            checked += 1
    print(f"③ 倒排表下标校验通过（{checked} 个 (词项,下标) 对）  OK")

    # 4) 并行数组长度一致
    n = len(eng.docs)
    for name in ("tf", "td_lower", "dl", "concept_vecs", "recency", "_ids_upper"):
        assert len(getattr(eng, name)) == n, f"{name} 长度 {len(getattr(eng,name))} != {n}"
    print(f"④ 并行数组长度一致（{n} 条）  OK")

    # 5) 检索结果与重排前完全一致（id 集合与分值都要一致）
    bad = 0
    for q in queries:
        r = eng.search(q, top_k=50)
        after = {(x.get("id"), round(float(x.get("score") or 0), 4))
                 for x in (r.get("results") or [])}
        if after != before[q]:
            bad += 1
            miss = before[q] - after
            extra = after - before[q]
            print(f"  [FAIL] {q!r}: 少了 {sorted(miss)[:3]} 多了 {sorted(extra)[:3]}")
    assert bad == 0, f"{bad} 个查询重排后结果发生变化"
    print("⑤ 重排前后检索结果完全一致  OK")

    # 6) cat_docs 分面仍能对上
    for c, idxs in eng.cat_docs.items():
        for i in idxs:
            assert eng.docs[i].get("category") == c, f"cat_docs 错位: {c} @ {i}"
    print("⑥ 类别分面下标正确  OK")

    for p in (tmp, tmp + ".idxcache"):
        if os.path.isfile(p):
            os.remove(p)
    print("\nALL PASS")


if __name__ == "__main__":
    main()
