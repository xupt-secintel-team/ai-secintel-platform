# -*- coding: utf-8 -*-
"""构建「NVD 富化索引」——把 data/nvd_cache.json 里 5.8 万条 NVD 官方 CVE 记录
压成一个小体积索引，供离线富化回填（tools/enrich_backfill.py）使用。

为什么要有这一步
================
nvd_cache.json 约 287MB，全量 json.load 会占用数 GB 内存，不适合在评测/交付环境
反复加载。索引只保留回填需要的字段（CVSS / CWE / CPE / 产品 / 厂商 / 补丁链接 /
公告链接 / 利用链接），通常十几 MB，秒级加载。

输出：data/nvd_enrich_index.json
    { "<CVE-ID>": {
        "cvss": {"score":.., "severity":.., "vector":.., "version":..},
        "cwe": ["CWE-79", ...],
        "cpe": ["cpe:2.3:a:..", ...],
        "products": [...], "vendors": [...],
        "patch": ["https://..."], "advisory": [...], "exploit": [...],
        "status": "Analyzed"
      }, ... }

用法：python tools/build_nvd_enrich_index.py
"""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402

DATA_DIR = paths.DATA_DIR
CACHE = os.path.join(DATA_DIR, "nvd_cache.json")
OUT = os.path.join(DATA_DIR, "nvd_enrich_index.json")

# NVD reference tags → 本项目富化字段
TAG_MAP = {
    "Patch": "patch",
    "Vendor Advisory": "advisory",
    "Advisory": "advisory",
    "Release Notes": "advisory",
    "Third Party Advisory": "advisory",
    "Exploit": "exploit",
}


def _pick_metric(cve: dict) -> dict:
    """从 metrics 里按 4.0 > 3.1 > 3.0 > 2.0 优先级取一条 CVSS。"""
    m = (cve or {}).get("metrics") or {}
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        arr = m.get(key) or []
        for item in arr:
            d = (item or {}).get("cvssData") or {}
            score = d.get("baseScore")
            if score is None:
                continue
            return {
                "score": float(score),
                "severity": str(d.get("baseSeverity") or item.get("baseSeverity") or ""),
                "vector": str(d.get("vectorString") or ""),
                "version": ver,
            }
    return {}


def _cwes(cve: dict) -> list:
    out = []
    for w in (cve.get("weaknesses") or []):
        for d in (w.get("description") or []):
            v = str(d.get("value") or "").strip()
            if v.startswith("CWE-"):
                out.append(v)
    # 去重保序
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def _cpes(cve: dict):
    """CPE 结构对齐语料现有 schema（list[dict]，含版本区间字段），便于直接回填。"""
    cpe_list, vendors, products = [], [], []
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            for m in (node.get("cpeMatch") or []):
                crit = str(m.get("criteria") or "").strip()
                parts = crit.split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue
                item = {
                    "vendor": parts[3], "product": parts[4], "version": parts[5],
                    "start_incl": m.get("versionStartIncluding"),
                    "start_excl": m.get("versionStartExcluding"),
                    "end_incl": m.get("versionEndIncluding"),
                    "end_excl": m.get("versionEndExcluding"),
                }
                if item not in cpe_list:
                    cpe_list.append(item)
                if parts[3] and parts[3] not in vendors:
                    vendors.append(parts[3])
                if parts[4] and parts[4] not in products:
                    products.append(parts[4])
    return cpe_list, vendors, products


def _refs(cve: dict):
    patch, advisory, exploit = [], [], []
    for r in (cve.get("references") or []):
        url = str(r.get("url") or "").strip()
        if not url:
            continue
        # 大小写不敏感：语料里 CNA 给的标签是 "PATCH"/"VENDOR ADVISORY" 全大写
        tags = {str(t).strip().upper() for t in (r.get("tags") or [])}
        if "PATCH" in tags and url not in patch:
            patch.append(url)
        if tags & {"VENDOR ADVISORY", "ADVISORY", "RELEASE NOTES",
                   "THIRD PARTY ADVISORY"} and url not in advisory:
            advisory.append(url)
        if "EXPLOIT" in tags and url not in exploit:
            exploit.append(url)
    return patch, advisory, exploit


def build() -> int:
    t0 = time.time()
    print("载入 %s ..." % CACHE, flush=True)
    with open(CACHE, "r", encoding="utf-8") as f:
        data = json.load(f)
    cves = data.get("cves") or {}
    print("NVD 记录 %d 条，开始建索引 ..." % len(cves), flush=True)

    index = {}
    for cid, cve in cves.items():
        if not isinstance(cve, dict):
            continue
        cvss = _pick_metric(cve)
        cwe = _cwes(cve)
        cpe, vendors, products = _cpes(cve)
        patch, advisory, exploit = _refs(cve)
        rec = {}
        if cvss:
            rec["cvss"] = cvss
        if cwe:
            rec["cwe"] = cwe
        if cpe:
            rec["cpe"] = cpe[:40]
        if vendors:
            rec["vendors"] = vendors[:20]
        if products:
            rec["products"] = products[:20]
        if patch:
            rec["patch"] = patch[:10]
        if advisory:
            rec["advisory"] = advisory[:10]
        if exploit:
            rec["exploit"] = exploit[:10]
        st = str(cve.get("vulnStatus") or "")
        if st:
            rec["status"] = st
        if rec:
            index[str(cid).upper()] = rec

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, separators=(",", ":"))
    print("已写出 %s：%d 条，%.1fMB，耗时 %.1fs"
          % (OUT, len(index), os.path.getsize(OUT) / 1048576, time.time() - t0), flush=True)
    return len(index)


if __name__ == "__main__":
    build()
