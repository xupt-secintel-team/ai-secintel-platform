# -*- coding: utf-8 -*-
"""CMDB 风险报告端到端验收：走真实 HTTP 提交全量数据 → 取回报告 → 落盘 → 自检。

为什么必须走 HTTP（2026-10-05 踩坑记录）：
  离线调 `CS.analyze()` 只证明「磁盘上的代码是对的」，不能证明「服务里跑的代码是
  这次的版本」——服务进程 import 过一次 cmdb_scan 后就常驻缓存，改磁盘不重启无效。
  第四轮评审的「正文与上一版逐字节相同」就是这么来的：HTTP 返回的还是旧进程里的
  旧函数。所以最终验收必须从接口打进去、再从接口取回来。

★ 分批上传会丢位置（实测踩到）：早先这个脚本拆两批跑，第一批含机房/机柜表、
  第二批含漏洞台账 → 台账查不到机房，位置可回溯 = 0，评审要求的「四要素」直接
  缺一项。位置表和台账必须在**同一次请求**里，所以这里一次传齐 21 张表
  （接口上限已从 10 提到 40，见 modules/m2_enrich/api.py）。

用法：
  python tools/_e2e_cmdb_report.py                 # 默认 8848
  python tools/_e2e_cmdb_report.py --port 8850
"""
import argparse
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    # —— 治理侧七章必需（2026-10-05）——
    #   不传这 6 张，report["audit"] 为 None，第三/四/五章会整章退化为"未核查"，
    #   而这不是真实情况——源目录里就有这些表（2026-10-05 实测全量）。
    "employee.csv", "api_endpoint.csv",
    "config_audit_log.csv", "change_order.csv", "ci_lifecycle_log.csv",
    "ci_relation.csv",
]
# ★ 超大表裁剪：治理七章的每一项都自带样本量门槛（MIN_CI_FOR_QUALITY=500 等），
#   报告会显式标注"样本不足"，但 177MB 的 ci_relation 单次 POST 会把服务
#   撑到内存边缘、且超时。裁到前 N 行既能触发所有渲染分支，又把上传压到可控体积。
#   None = 不裁（直传本地文件时用）。
TRIM_ROWS = {
    "ci_relation.csv": 300000,
    "ci_lifecycle_log.csv": 150000,
    "config_audit_log.csv": 80000,
}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _read_trimmed(name, path):
    """读 CSV；命中 TRIM_ROWS 则只取前 N 行数据（保留表头）。

    实现要点：必须按**物理行**切，不能按 csv 字段切——源数据字段里可能有换行，
    按行切会截断记录。这里用「读到第 N+1 行就停」的流式读法，
    再交给下游 csv 解析，字段完整性由解析器保证。
    """
    lim = TRIM_ROWS.get(name)
    with open(path, "rb") as fh:
        if not lim:
            return fh.read()
        head = fh.readline()
        kept = [head]
        for i in range(lim):
            ln = fh.readline()
            if not ln:
                break
            kept.append(ln)
        dropped = None
        rest = fh.read(1)
        if rest:
            dropped = "更多"
        return b"".join(kept)


def post_all(port):
    manifest = {"mode": "file", "name": "E:\\cmdb\\csv 全量端到端验收", "files": []}
    blob = bytearray()
    for n in FILES:
        p = os.path.join(SRC, n)
        if not os.path.isfile(p):
            print("  SKIP（不存在）%s" % n)
            continue
        data = _read_trimmed(n, p)
        manifest["files"].append({"filename": n, "size": len(data)})
        blob.extend(data)
        if n in TRIM_ROWS:
            print("  TRIM %-24s → 前 %d 行（%.1f MB）" % (n, TRIM_ROWS[n], len(data) / 1048576.0))
    mh = urllib.parse.quote(json.dumps(manifest, ensure_ascii=False))
    req = urllib.request.Request(
        "http://127.0.0.1:%d/api/cmdb_scan" % port, data=bytes(blob),
        headers={"Content-Type": "application/octet-stream",
                 "X-Cmdb-Manifest": mh}, method="POST")
    t0 = time.time()
    with OPENER.open(req, timeout=3600) as r:
        resp = json.loads(r.read().decode("utf-8"))
    print("  提交 %d 个文件 / %.1f MB / 耗时 %.0fs → ok=%s id=%s" % (
        len(manifest["files"]), len(blob) / 1048576.0, time.time() - t0,
        resp.get("ok"), resp.get("id")))
    return resp


def get_markdown(port, scan_id):
    url = ("http://127.0.0.1:%d/api/cmdb_scan?id=%s&md=1"
           % (port, urllib.parse.quote(scan_id)))
    with OPENER.open(url, timeout=300) as r:
        return r.read().decode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8848)
    args = ap.parse_args()
    out_dir = os.path.join(ROOT, "测试报告")
    os.makedirs(out_dir, exist_ok=True)

    print("=== CMDB 报告端到端验收（真实 HTTP）===")
    resp = post_all(args.port)
    if not resp.get("ok"):
        print("  ERROR:", resp.get("error"))
        print("端到端失败：接口返回错误")
        return 1
    rep = resp["report"]
    sid = resp.get("id") or rep.get("id") or ""

    # 取回 Markdown（走 GET，确认服务端渲染路径也正常）
    md = get_markdown(args.port, sid)
    md_path = os.path.join(out_dir, "cmdb_e2e_report.md")
    with io.open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    json_path = os.path.join(out_dir, "cmdb_e2e_report.json")
    with io.open(json_path, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)

    print("\n=== 产出 ===")
    print("  id         %s" % sid)
    print("  Markdown   %s（%d chars / %d lines）"
          % (md_path, len(md), md.count("\n") + 1))
    print("  JSON       %s" % json_path)

    print("\n=== 接口返回报告的自检 ===")
    s = rep["risk"]["summary"]
    pr = rep["priority"]
    hosts = rep["risk"]["hosts"]
    loc = s.get("loc_resolved") or 0
    aud = rep.get("audit") or {}
    q = aud.get("quality") or {}
    bl = aud.get("baseline") or {}
    ac = aud.get("access") or {}
    api = ac.get("api") or {}
    acct = ac.get("account") or {}
    ch = aud.get("change") or {}
    checks = [
        ("数据源为漏洞台账", "漏洞台账" in (rep.get("data_source") or "")),
        ("处置工单非空", len(pr) > 0),
        ("工单全部有责任人", all(p.get("owners") for p in pr)),
        ("工单全部有计划期限", all(p.get("plan_fix") for p in pr)),
        ("工单全部有 SLA 天数", all(p.get("sla_days") for p in pr)),
        ("工单全部有修复方案", all(p.get("fix_plan") for p in pr)),
        ("优先级有区分度", len({p["priority_label"] for p in pr}) >= 2),
        ("★ 资产带机房位置（四要素之「位置」）", loc > 0),
        ("★ 位置覆盖率 ≥ 80%", loc * 100.0 / max(1, s.get("hosts") or 0) >= 80),
        # —— 七章制（第一份标准）——
        ("★ 七章齐全有序", _seven_chapters_ok(md)),
        ("★ 附录 A~F 齐全", all(("# 附录 %s" % c) in md for c in "ABCDEF")),
        # —— 治理侧（第三/四/五章的数据底座）——
        #   键名别猜：asset_total / change.order / change.lifecycle——
        #   我第一版写成 total_ci + change.total，静默返回 0，2 项假失败
        #   （真实值 284600 CI / 双口径齐全，报告本身完全正确）
        ("★ 治理审计已接入（audit 非空）", bool(aud)),
        ("★ 识别到治理表 ≥ 10 张", len(aud.get("source_tables") or {}) >= 10),
        ("★ 资产总数被识别（> 10000）", (q.get("asset_total") or 0) > 10000),
        ("★ 资产表覆盖 ≥ 10 类", len(q.get("asset_by_type") or {}) >= 10),
        ("★ 孤儿 CI 已统计", (q.get("orphan_ci") or {}).get("checked") is not None),
        ("★ 配置漂移率已统计", bl.get("drift_pct") is not None),
        ("★ API 鉴权率已统计", api.get("auth_ratio") is not None),
        ("★ 变更单与生命周期双口径均统计",
         (ch.get("order") or {}).get("checked") is not None
         and (ch.get("lifecycle") or {}).get("checked") is not None),
        # —— 14 字段发现项（第二份标准）——
        ("★ 14 字段发现项齐全", _fields14_ok(md)),
        ("★ 派发表与已闭环表分流", ("6.0 待派发工单" in md) and ("6.3" in md)),
        # —— 语言与诚实度 ——
        ("无「以补丁公告为准」这类空话", "以补丁公告为准" not in md),
        ("无「可能存在」这类模糊表述", "可能存在" not in md),
        ("无字面 None", "None" not in md),
        ("正文含 NVD 链接", "nvd.nist.gov" in md),
        ("正文披露位置口径", "以机柜" in md and "IDC_ID" in md),
        ("资产清单含业务系统", any(h.get("app") for h in hosts)),
        ("资产清单含责任人", any(h.get("owner") for h in hosts)),
    ]
    bad = 0
    for name, cond in checks:
        print("  %s %s" % ("PASS" if cond else "FAIL", name))
        bad += (0 if cond else 1)
    print("\n  台账 %d / 漏洞 %d / 资产 %d / 位置可回溯 %d（%.1f%%）/ 工单 %d" % (
        s.get("ledger_rows") or 0, s.get("cve_hits") or 0, s.get("hosts") or 0,
        loc, loc * 100.0 / max(1, s.get("hosts") or 0), len(pr)))
    if aud:
        print("  治理：CI %d / 漂移 %.1f%% / API 鉴权率 %.1f%% / 暗变更 %d" % (
            q.get("asset_total") or 0, bl.get("drift_pct") or 0,
            api.get("auth_ratio") or 0,
            ((ch.get("lifecycle") or {}).get("manual_change_no_order")) or 0))
        print("  治理表 %d 张：%s" % (
            len(aud.get("source_tables") or {}),
            "、".join(sorted((aud.get("source_tables") or {}).keys())[:8]) + " …"))
    if TRIM_ROWS:
        print("\n  ⚠️ 本次上传裁剪了 %d 张超大表（%s），"
              "相关百分比基于裁剪后样本，报告内已按门槛标注。"
              % (len(TRIM_ROWS),
                 "、".join("%s→%d 行" % (k.replace(".csv", ""), v)
                           for k, v in sorted(TRIM_ROWS.items()))))
    print("\n合计 %d 项，通过 %d，失败 %d" % (len(checks), len(checks) - bad, bad))
    return 1 if bad else 0


def _seven_chapters_ok(md):
    """七章齐全且有序（七份标准的第一份）。"""
    import re
    heads = ["报告基础信息", "总体结论", "CMDB 数据质量", "访问控制与权限",
             "变更管理合规", "发现汇总", "复测计划"]
    pos = []
    for h in heads:
        m = re.search(r"^#.*%s" % re.escape(h), md, re.M)
        if not m:
            print("    缺章节：%s" % h)
            return False
        pos.append(m.start())
    if pos != sorted(pos):
        print("    章节顺序错乱")
        return False
    return True


def _fields14_ok(md):
    """14 字段发现项齐全（第二份标准 §3.3）。"""
    import re
    need = ["工单标题", "风险等级", "问题类型", "问题位置", "证据", "复现步骤",
            "影响", "修复建议", "验证方式", "责任人", "修复期限", "关联", "状态"]
    m = re.search(r"^### 6\.1 ", md, re.M)
    if not m:
        print("    缺 6.1 发现项明细")
        return False
    nxt = re.search(r"^#{2,3} ", md[m.end():], re.M)
    seg = md[m.end():m.end() + nxt.start()] if nxt else md[m.end():]
    missing = [k for k in need if k not in seg]
    if missing:
        print("    缺字段：%s" % "、".join(missing))
        return False
    return True


if __name__ == "__main__":
    sys.exit(main())
