# -*- coding: utf-8 -*-
"""离线富化回填 —— 用 NVD 官方数据补齐语料里缺失的富化维度。

背景
====
采集时 NVD/CNA 对不少 CVE 还没完成分析（vulnStatus 未达 Analyzed、configurations
为空），语料里这些条目的 CWE / CPE / 补丁链接就是空的。等 NVD 补齐后再回填一次，
就能把这些维度补上 —— 这是「情报富化」的正常一环，而不是改评分口径。

数据源：data/nvd_enrich_index.json（由 tools/build_nvd_enrich_index.py 从
data/nvd_cache.json 抽取，内容与 NVD 官方 API 响应同源）。

回填策略：**只补空，不覆盖**。已有值一律保留；补进去的值会在该条目的
`enriched_by` 里记一笔来源，便于审计和「同源一致性」排查。

用法：
    python tools/enrich_backfill.py            # 正式写回 data/corpus.json
    python tools/enrich_backfill.py --dry-run  # 只统计，不落盘
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402

DATA_DIR = paths.DATA_DIR
CORPUS = os.path.join(DATA_DIR, "corpus.json")
INDEX = os.path.join(DATA_DIR, "nvd_enrich_index.json")
REPORT = os.path.join(ROOT, "评测", "结果", "_backfill_report.json")

PROV = "nvd_offline_backfill"


KEYS = ("cvss", "cwe", "cpe", "vendors", "products",
        "patch_links", "advisory_links", "poc_links")


def filled(v, key: str = "") -> bool:
    """字段是否已填充。CVSS 是 dict，必须真的有分/等级才算填了。"""
    if v is None:
        return False
    if isinstance(v, (list, tuple, set)):
        return len(v) > 0
    if isinstance(v, dict):
        if key == "cvss":
            return bool(v.get("score") or v.get("severity"))
        return len(v) > 0
    if isinstance(v, str):
        return bool(v.strip())
    return True


def coverage(records) -> dict:
    n = len(records) or 1
    return {k: round(sum(1 for d in records if filled(d.get(k), k)) / n * 100, 2)
            for k in KEYS}


def merge_links(old, new, cap=10):
    """URL 列表合并去重（保序）。"""
    out = [x for x in (old or []) if isinstance(x, str) and x.strip()]
    seen = set(out)
    for u in (new or []):
        if isinstance(u, str) and u.strip() and u not in seen:
            out.append(u)
            seen.add(u)
    return out[:cap]


def main(dry_run: bool = False) -> dict:
    t0 = time.time()
    print("载入富化索引 ...", flush=True)
    index = json.load(open(INDEX, encoding="utf-8"))
    print("索引 %d 条" % len(index), flush=True)

    print("载入语料 ...", flush=True)
    corpus = json.load(open(CORPUS, encoding="utf-8"))
    records = corpus.get("records") or []
    print("语料 %d 条记录" % len(records), flush=True)

    before = coverage(records)
    touched = collections.Counter()
    backfilled_ids = []

    for d in records:
        cid = str(d.get("id") or "").upper()
        src = index.get(cid)
        if not src:
            continue
        changed = []
        prov = d.get("enriched_by") or []
        if not isinstance(prov, list):
            prov = []

        # ── CVSS ─────────────────────────────────────────────────
        cv = d.get("cvss") or {}
        if not (isinstance(cv, dict) and (cv.get("score") or cv.get("severity"))):
            if src.get("cvss"):
                d["cvss"] = dict(src["cvss"])
                changed.append("cvss")

        # ── CWE ──────────────────────────────────────────────────
        if not filled(d.get("cwe")) and src.get("cwe"):
            d["cwe"] = [{"id": c, "name": "", "source": "nvd"} for c in src["cwe"]]
            changed.append("cwe")

        # ── CPE / 厂商 / 产品 ─────────────────────────────────────
        if not filled(d.get("cpe")) and src.get("cpe"):
            d["cpe"] = list(src["cpe"])
            changed.append("cpe")
        if not filled(d.get("vendors")) and src.get("vendors"):
            d["vendors"] = list(src["vendors"])
            changed.append("vendors")
        if not filled(d.get("products")) and src.get("products"):
            d["products"] = list(src["products"])
            changed.append("products")

        # ── 链接类维度 ────────────────────────────────────────────
        if src.get("patch"):
            new = merge_links(d.get("patch_links"), src["patch"])
            if new != (d.get("patch_links") or []):
                d["patch_links"] = new
                changed.append("patch_links")
        if src.get("advisory"):
            new = merge_links(d.get("advisory_links"), src["advisory"])
            if new != (d.get("advisory_links") or []):
                d["advisory_links"] = new
                changed.append("advisory_links")
        if src.get("exploit"):
            new = merge_links(d.get("poc_links"), src["exploit"])
            if new != (d.get("poc_links") or []):
                d["poc_links"] = new
                changed.append("poc_links")

        if changed:
            if PROV not in prov:
                prov.append(PROV)
            d["enriched_by"] = prov
            backfilled_ids.append(cid)
            for k in changed:
                touched[k] += 1

    after = coverage(records)
    n = len(records)
    report = {
        "生成时间": time.strftime("%Y-%m-%d %H:%M:%S"),
        "数据源": "data/nvd_enrich_index.json ← data/nvd_cache.json + NVD 官方年度 feed（2024/2025/2026/recent）",
        "语料记录数": n,
        "回填条目数": len(backfilled_ids),
        "维度填充率_回填前%": before,
        "维度填充率_回填后%": after,
        "各维度回填条目数": dict(touched),
        "耗时s": round(time.time() - t0, 1),
        "dry_run": dry_run,
    }

    if not dry_run and backfilled_ids:
        os.makedirs(os.path.dirname(REPORT), exist_ok=True)
        # 只留 ID 清单（供准确率评测排除同源样本用），不落全量快照
        with open(REPORT, "w", encoding="utf-8") as f:
            json.dump({**report, "backfilled_ids": backfilled_ids}, f,
                      ensure_ascii=False, indent=1)

        tmp = CORPUS + ".new"
        print("写出 %s ..." % tmp, flush=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
        bak = CORPUS + ".pre_enrich.bak"
        if not os.path.exists(bak):
            os.replace(CORPUS, bak)
        os.replace(tmp, CORPUS)
        report["备份"] = bak
        print("已写回 %s（原文件备份为 %s）" % (CORPUS, bak), flush=True)

    print(json.dumps({k: v for k, v in report.items() if k != "backfilled_ids"},
                     ensure_ascii=False, indent=1))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    main(a.dry_run)
