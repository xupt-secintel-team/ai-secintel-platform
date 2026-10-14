# -*- coding: utf-8 -*-
"""语料库全面体检：来源构成、时间覆盖、字段完整度、重复与脏数据。

用法： python tools/语料库体检.py            # 控制台摘要
       python tools/语料库体检.py --json     # 输出 machine 版（供扩源脚本对照）
"""
import os
import re
import sys
import json
import collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
CORPUS = os.path.join(ROOT, "data", "corpus.json")

ISO = re.compile(r"^\d{4}-\d{2}-\d{2}")


def load():
    with open(CORPUS, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    c = load()
    recs = c.get("records", [])
    kb = c.get("knowledge", [])
    docs = recs + kb
    print(f"语料文件 {os.path.getsize(CORPUS)/1048576:.0f}MB")
    print(f"漏洞情报 records = {len(recs):,}   知识条目 knowledge = {len(kb):,}   合计 = {len(docs):,}")
    print(f"论文 papers = {len(c.get('papers', [])):,}")

    # ---- 来源构成 ----
    by_src = collections.Counter()
    by_kind = collections.Counter()
    latest = {}
    for d in docs:
        srcs = d.get("sources") or ["(无)"]
        s = srcs[0] if isinstance(srcs, list) and srcs else str(srcs)
        by_src[s] += 1
        by_kind[d.get("kind") or d.get("type") or "(无)"] += 1
        pub = (d.get("published") or "")[:10]
        if ISO.match(pub) and pub > latest.get(s, ""):
            latest[s] = pub
    print("\n—— 来源构成（前 25）——")
    for s, n in by_src.most_common(25):
        print(f"  {s:<26} {n:>7,}   最新 {latest.get(s) or '-'}")
    print(f"  来源种类合计：{len(by_src)}")

    print("\n—— 条目类型（前 15）——")
    for k, n in by_kind.most_common(15):
        print(f"  {k:<26} {n:>7,}")

    # ---- 时间覆盖 ----
    years = collections.Counter()
    dated = 0
    for d in docs:
        pub = (d.get("published") or "")[:10]
        if ISO.match(pub):
            dated += 1
            years[pub[:4]] += 1
    print("\n—— 时间覆盖 ——")
    print(f"  有发布日期 {dated:,} / {len(docs):,}（{dated*100//max(len(docs),1)}%）")
    for y in sorted(years):
        print(f"  {y}: {years[y]:,}")
    recent = [d for d in docs if (d.get("published") or "")[:10] >= "2026-09-01"]
    print(f"  2026-09-01 以来新增：{len(recent):,}")

    # ---- 字段完整度 / 脏数据 ----
    empty_desc = sum(1 for d in docs if not (d.get("desc") or "").strip())
    short_desc = sum(1 for d in docs if 0 < len((d.get("desc") or "").strip()) < 30)
    empty_title = sum(1 for d in docs if not (d.get("title") or "").strip())
    empty_pub = sum(1 for d in docs if not ISO.match((d.get("published") or "")[:10]))
    no_ref = sum(1 for d in docs if not (d.get("refs") or d.get("article_url") or d.get("link")))
    ids = [d.get("id") for d in docs]
    dup = [k for k, v in collections.Counter(ids).items() if v > 1]
    print("\n—— 完整度 / 脏数据 ——")
    print(f"  标题为空       {empty_title:,}")
    print(f"  摘要为空       {empty_desc:,}")
    print(f"  摘要 <30 字    {short_desc:,}")
    print(f"  日期缺失/非法  {empty_pub:,}")
    print(f"  无外链/引用    {no_ref:,}")
    print(f"  重复 id        {len(dup):,}" + (f"（样例 {dup[:3]}）" if dup else ""))

    if "--json" in sys.argv:
        out = {"records": len(recs), "knowledge": len(kb), "papers": len(c.get("papers", [])),
               "sources": dict(by_src), "source_latest": latest, "years": dict(years),
               "kinds": dict(by_kind), "dirty": {"empty_title": empty_title, "empty_desc": empty_desc,
                                                 "short_desc": short_desc, "bad_date": empty_pub,
                                                 "no_ref": no_ref, "dup_id": len(dup)}}
        fp = os.path.join(ROOT, "output", "语料库体检.json")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\n已写出 {fp}")


if __name__ == "__main__":
    main()
