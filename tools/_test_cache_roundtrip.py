# -*- coding: utf-8 -*-
"""冷启动缓存往返测试：模拟「增量写入 → 按 published 重排落盘 → 保存缓存 → 重启」。

这是线上反复出现「每次启动都全量重建 360~410s」的最小复现。
链路：
  1. 建一份小语料，起引擎（建索引 + 落缓存）
  2. 增量 add_documents 追加新文档（进引擎末尾）
  3. 按 published 倒序重排语料文件（monitor 落盘时的行为）
  4. 调 reorder_by(磁盘顺序) 对齐内存（apply_new_docs 新增的行为）
  5. 保存缓存
  6. 重启引擎 —— 断言：命中缓存、文档数正确、检索结果正确

未修之前第 6 步必然判失效（id 指纹对不上）。
"""
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.engine import SearchEngine  # noqa: E402


def _mk(i, text):
    return {
        "id": f"CVE-2026-{200000 + i}",
        "title": f"rec {i}",
        "desc": text,
        "published": f"2026-09-{(i % 28) + 1:02d}",
        "category": "vuln",
        "cvss": {"score": 7.5, "severity": "HIGH"},
        "products": [f"p{i % 5}"],
        "cwe": ["CWE-79"],
        "sources": ["test"],
    }


def main():
    tmp = os.path.join(tempfile.gettempdir(), "_cache_rt.json")
    for p in (tmp, tmp + ".idxcache"):
        if os.path.isfile(p):
            os.remove(p)

    base = [_mk(i, f"word{i} shared common") for i in range(40)]
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"meta": {}, "papers": [], "records": base, "knowledge": []}, f)

    eng = SearchEngine(tmp)
    print(f"① 首建：{len(eng.docs)} 条，来自缓存={eng._loaded_from_cache}")

    # 追加新文档（引擎末尾，模拟快车道增量）
    new = [_mk(100 + i, f"newword{i} shared fresh") for i in range(5)]
    added = eng.add_documents(new)
    print(f"② 增量追加 {added} 条 → {len(eng.docs)} 条")

    # monitor 落盘：全部记录按 published 倒序
    allrec = [dict(d) for d in eng.docs]
    allrec.sort(key=lambda r: r.get("published", ""), reverse=True)
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"meta": {}, "papers": [], "records": allrec, "knowledge": []}, f)

    # apply_new_docs 新增的行为：内存顺序对齐磁盘
    order = eng._disk_order(tmp)
    ok = eng.reorder_by(order)
    print(f"③ 顺序对齐={ok}；内存首条={eng.docs[0]['id']} 磁盘首条={allrec[0]['id']}")

    # 保存缓存
    eng._save_index_cache(tmp)
    print("④ 缓存已保存")

    # 重排后本次会话的检索基线（重启后必须一致）
    probe = ["shared common", "newword3", "word12", "CWE-79"]
    base_hits = {}
    for q in probe:
        r = eng.search(q, top_k=50)
        base_hits[q] = {(x.get("id"), round(float(x.get("score") or 0), 4))
                        for x in (r.get("results") or [])}

    # 重启
    t = time.time()
    eng2 = SearchEngine(tmp)
    dt = time.time() - t
    print(f"⑤ 重启耗时 {dt:.2f}s，来自缓存={eng2._loaded_from_cache}，{len(eng2.docs)} 条")
    assert eng2._loaded_from_cache, "重启未命中缓存 —— 说明顺序又分叉了"
    assert len(eng2.docs) == len(eng.docs), "文档数不一致"

    bad = 0
    for q in probe:
        r = eng2.search(q, top_k=50)
        after = {(x.get("id"), round(float(x.get("score") or 0), 4))
                 for x in (r.get("results") or [])}
        if after != base_hits[q]:
            bad += 1
            print(f"  [FAIL] {q!r} 重排后结果不一致")
    assert bad == 0, f"{bad} 个查询不一致"
    print("⑥ 重启后检索结果与重排前一致  OK")

    for p in (tmp, tmp + ".idxcache"):
        if os.path.isfile(p):
            os.remove(p)
    print("\nALL PASS")


if __name__ == "__main__":
    main()
