# -*- coding: utf-8 -*-
"""验证位置索引：CI_ID → 机房/机柜/城市 是否真能从 CMDB 关联出来。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

import cmdb_scan as CS  # noqa: E402

SRC = r"E:\cmdb\csv"
FILES = [
    "idc_room.csv", "cabinet.csv",
    "physical_server.csv", "vm_cloud_host.csv", "network_device.csv",
    "security_device.csv", "storage_device.csv", "gpu_node.csv",
    "middleware_instance.csv", "database_instance.csv", "bigdata_component.csv",
    "app_instance.csv", "container_pod.csv",
    "vulnerability.csv",
]
files = []
for f in FILES:
    p = os.path.join(SRC, f)
    with open(p, "rb") as fh:
        files.append({"filename": f, "data": fh.read()})

idx = CS._build_loc_index(files)
print("index stats:", idx.stats)
print("ci2idc=%d ci2cab=%d ci2host=%d idc_info=%d cab_info=%d" % (
    len(idx.ci2idc), len(idx.ci2cab), len(idx.ci2host),
    len(idx.idc_info), len(idx.cab_info)))

print("\n--- 机房样例 ---")
for k in list(idx.idc_info)[:3]:
    print("  ", k, idx.idc_info[k])
print("--- 机柜样例 ---")
for k in list(idx.cab_info)[:3]:
    print("  ", k, idx.cab_info[k])

# 拿台账里真实的 CI 逐个验
import csv
seen = []
with open(os.path.join(SRC, "vulnerability.csv"), encoding="utf-8",
          errors="replace", newline="") as fh:
    for i, row in enumerate(csv.DictReader(fh)):
        cid = row["CI_ID"]
        if cid and cid not in [s[0] for s in seen]:
            seen.append((cid, row["AFFECTED_COMPONENT"]))
        if len(seen) >= 14:
            break

print("\n--- 台账真实 CI 的位置解析 ---")
hit = 0
for cid, comp in seen:
    d = idx.resolve(cid)
    if d:
        hit += 1
    print("  %-14s %-18s -> %s" % (cid, comp[:16], idx.location_text(cid) or "（未登记）"))
print("\n命中率: %d / %d" % (hit, len(seen)))
