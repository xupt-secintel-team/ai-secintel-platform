# -*- coding: utf-8 -*-
"""离线跑真实 CMDB 全量数据（CSV），验证第 4 版报告的全部评审指标。

不走 HTTP——服务进程可能加载着旧模块，离线跑才是「当前磁盘代码」的真实产出。
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

import cmdb_scan as CS  # noqa: E402

SRC = r"E:\cmdb\csv"
FILES = [
    # 位置相关（机房/机柜/资产）
    "idc_room.csv", "cabinet.csv", "physical_server.csv", "vm_cloud_host.csv",
    "network_device.csv", "security_device.csv", "storage_device.csv", "gpu_node.csv",
    "middleware_instance.csv", "database_instance.csv", "bigdata_component.csv",
    "app_instance.csv", "container_pod.csv",
    # 业务 / 软件
    "application.csv", "domain_cert.csv", "software_package.csv", "ip_allocation.csv",
    # 漏洞台账 + 交叉验证
    "vulnerability.csv", "patch_record.csv", "alert_record.csv",
]
cfg = {"mode": "file", "name": "E:\\cmdb\\csv 全量离线验证", "files": []}
for f in FILES:
    p = os.path.join(SRC, f)
    if not os.path.isfile(p):
        print("SKIP", f)
        continue
    with open(p, "rb") as fh:
        cfg["files"].append({"filename": f, "data": fh.read()})

t0 = time.time()
res = CS.analyze(None, cfg)
print("elapsed %.1fs  ok=%s" % (time.time() - t0, res.get("ok")))
if not res.get("ok"):
    print("error:", res.get("error"))
    raise SystemExit(1)

rep = res["report"]
out_dir = os.path.join(ROOT, "测试报告")
os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(out_dir, "cmdb_offline_check.json"), "w", encoding="utf-8") as f:
    json.dump(rep, f, ensure_ascii=False, indent=1)
md = CS.report_to_markdown(rep)
md_path = os.path.join(out_dir, "cmdb_offline_check.md")
with open(md_path, "w", encoding="utf-8") as f:
    f.write(md)
print("json -> 测试报告/cmdb_offline_check.json")
print("md   -> %s  (%d chars, %d lines)" % (md_path, len(md), md.count("\n") + 1))

s = rep["risk"]["summary"]
pr = rep["priority"]
print("\n=== scale ===")
print(json.dumps(rep["scale"], ensure_ascii=False))
print("=== data_source ===", rep.get("data_source"))
print("=== summary ===")
print(json.dumps(s, ensure_ascii=False, indent=1))
print("=== priority n =", len(pr))
if pr:
    print("--- 第 1 条工单全部字段 ---")
    print(json.dumps(pr[0], ensure_ascii=False, indent=1)[:3500])
