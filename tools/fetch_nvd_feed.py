# -*- coding: utf-8 -*-
"""拉取 NVD 官方 CVE 年度/增量 feed，更新富化索引（离线回填的数据源）。

为什么要这个
============
data/nvd_cache.json 是采集期的快照，与语料同龄：语料里没分析完的 CVE，缓存里同样
没数据，回填补不出东西。NVD 每天发布年度 feed（nvdcve-2.0-<年>.json.gz）与
recent（近 8 天），是**新鲜**的官方数据，用它做增量回填才能真正补上维度。

产出：把 feed 里的数据按「新数据优先」合并进 data/nvd_enrich_index.json。

用法：
    python tools/fetch_nvd_feed.py                 # 默认 2024/2025/2026 + recent
    python tools/fetch_nvd_feed.py --years 2026
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths  # noqa: E402
from build_nvd_enrich_index import _pick_metric, _cwes, _cpes, _refs  # noqa: E402

DATA_DIR = paths.DATA_DIR
FEED_DIR = os.path.join(DATA_DIR, "nvd_feeds")
INDEX = os.path.join(DATA_DIR, "nvd_enrich_index.json")
BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%s.json.gz"
UA = {"User-Agent": "Mozilla/5.0 (aisec-D intel platform)"}


def download(name: str, force: bool = False) -> str:
    os.makedirs(FEED_DIR, exist_ok=True)
    out = os.path.join(FEED_DIR, "nvdcve-2.0-%s.json.gz" % name)
    if os.path.exists(out) and not force and os.path.getsize(out) > 1024:
        print("  已缓存 %s" % out, flush=True)
        return out
    url = BASE % name
    print("  下载 %s ..." % url, flush=True)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=180) as r, open(out, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    print("  %s %.1fMB" % (name, os.path.getsize(out) / 1048576), flush=True)
    return out


def parse(path: str) -> dict:
    """解析一份 feed，返回 {CVE-ID: 富化字段}。"""
    out = {}
    with gzip.open(path, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cid = str(cve.get("id") or "").upper()
        if not cid.startswith("CVE-"):
            continue
        rec = {}
        cvss = _pick_metric(cve)
        if cvss:
            rec["cvss"] = cvss
        cwe = _cwes(cve)
        if cwe:
            rec["cwe"] = cwe
        cpe, vendors, products = _cpes(cve)
        if cpe:
            rec["cpe"] = cpe[:40]
        if vendors:
            rec["vendors"] = vendors[:20]
        if products:
            rec["products"] = products[:20]
        patch, advisory, exploit = _refs(cve)
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
            out[cid] = rec
    return out


def main(years, force=False) -> None:
    t0 = time.time()
    index = {}
    if os.path.exists(INDEX):
        index = json.load(open(INDEX, encoding="utf-8"))
        print("现有索引 %d 条" % len(index), flush=True)

    names = list(years) + ["recent"]
    for name in names:
        p = download(name, force)
        got = parse(p)
        # 新数据优先：feed 覆盖同 ID 的旧记录（字段级合并，feed 有的键直接替换）
        n_new = 0
        for cid, rec in got.items():
            old = index.get(cid)
            if old is None:
                index[cid] = rec
                n_new += 1
            else:
                old.update(rec)
        print("  %s：解析 %d 条，其中新增 %d 条，索引现 %d 条" % (name, len(got), n_new, len(index)), flush=True)

    with open(INDEX, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, separators=(",", ":"))
    print("索引更新完成：%d 条，%.1fMB，耗时 %.1fs"
          % (len(index), os.path.getsize(INDEX) / 1048576, time.time() - t0), flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", default="2024,2025,2026")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    main([y.strip() for y in a.years.split(",") if y.strip()], a.force)
