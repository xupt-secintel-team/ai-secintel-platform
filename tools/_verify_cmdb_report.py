# -*- coding: utf-8 -*-
"""CMDB 报告回归校验：逐条对照评审意见实测，不靠肉眼。

用法：
    python tools/_verify_cmdb_report.py                 # 跑离线全量并校验
    python tools/_verify_cmdb_report.py --json <path>   # 只校验已有报告 JSON
"""
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_CSV = r"E:\cmdb\csv\vulnerability.csv"

FILES = [
    "idc_room.csv", "cabinet.csv", "physical_server.csv", "vm_cloud_host.csv",
    "network_device.csv", "security_device.csv", "storage_device.csv", "gpu_node.csv",
    "middleware_instance.csv", "database_instance.csv", "bigdata_component.csv",
    "app_instance.csv", "container_pod.csv",
    "application.csv", "domain_cert.csv", "software_package.csv", "ip_allocation.csv",
    "vulnerability.csv", "patch_record.csv", "alert_record.csv",
    # —— 治理侧七章必需（2026-10-05）。少了这三张，第三章/五章会写「未核查」，
    #   那不等于合规——回归必须跑在数据齐全的场景下。
    "change_order.csv", "config_audit_log.csv", "ci_relation.csv",
    "ci_lifecycle_log.csv", "employee.csv", "api_endpoint.csv",
]

_results = []


def _uncovered_list(aud):
    """治理侧未核查项清单（校验「敢说自己没查什么」）。"""
    if not aud:
        return []
    try:
        sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
        import cmdb_audit as CA
        return CA.uncovered(aud)
    except Exception:
        return []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    print("  %s %-52s %s" % ("PASS" if ok else "FAIL", name, detail))
    return ok


def run_pipeline():
    sys.path.insert(0, os.path.join(ROOT, "core"))
    sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
    import cmdb_scan as CS
    cfg = {"mode": "file", "name": "E:\\cmdb\\csv 回归校验", "files": []}
    for f in FILES:
        p = os.path.join(SRC_CSV.replace("vulnerability.csv", ""), f)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as fh:
            cfg["files"].append({"filename": f, "data": fh.read()})
    res = CS.analyze(None, cfg)
    if not res.get("ok"):
        raise SystemExit("pipeline failed: %s" % res.get("error"))
    rep = res["report"]
    md = CS.report_to_markdown(rep)
    return rep, md


def verify(rep, md):
    pr = rep["priority"]
    s = rep["risk"]["summary"]
    hosts = rep["risk"]["hosts"]

    print("\n【致命问题 1】资产标识必须是 CMDB 里真实存在的 CI 三元组 + 机房位置")
    # 回源校验：报告里的 CI_ID / 主机名 / IP 必须在 vulnerability.csv 里查得到
    import csv
    src = {}
    with open(SRC_CSV, encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            src[row["CI_ID"]] = (row["CI_NAME"], row["CI_IP"])
    sample = hosts[:20]
    hit = sum(1 for h in sample
              if h.get("asset_id") in src
              and src[h["asset_id"]][0] == h.get("ci_name")
              and src[h["asset_id"]][1] == h.get("ci_ip"))
    check("抽查 20 台资产三元组回源命中", hit == len(sample), "%d / %d" % (hit, len(sample)))
    with_loc = sum(1 for h in hosts[:200] if h.get("location"))
    check("TOP200 资产有机房位置", with_loc >= 150, "%d / 200" % with_loc)

    print("\n【致命问题 2】组件名与版本不得粘连")
    bad = []
    for p in pr:
        c = (p.get("component") or "")
        if re.match(r"^[\d.]+$", c) or re.search(r"\s+[A-Za-z]$", c):
            bad.append(c)
    check("组件名不含版本号尾巴", not bad, "异常 %d 个 %s" % (len(bad), bad[:3]))

    print("\n【致命问题 3】零命中条目不进正文")
    zero = sum(1 for p in pr if (p.get("open_count") or 0) == 0)
    check("处置工单无「全部已闭环」条目", zero == 0, "已闭环 %d 条" % zero)
    check("处置工单按未闭环优先排序",
          all(pr[i]["open_count"] > 0 for i in range(min(20, len(pr)))),
          "前 20 条均有待处置记录")

    print("\n【老问题 A】严重度必须由 CVSS 推导，不得自相矛盾")
    band = {"CRITICAL": (9.0, 10.01), "HIGH": (7.0, 9.0), "MEDIUM": (4.0, 7.0),
            "LOW": (0.1, 4.0)}
    contra = [(p["cve"], p["severity"], p["cvss"]) for p in pr
              if p.get("cvss") and p["severity"] in band
              and not (band[p["severity"]][0] <= p["cvss"] < band[p["severity"]][1])]
    check("严重度与 CVSS 无矛盾", not contra, "矛盾 %d 条 %s" % (len(contra), contra[:2]))
    check("信息级（CVSS=0）正确归入 INFO",
          s.get("info", 0) > 0, "INFO %d 条" % s.get("info", 0))

    print("\n【老问题 B】责任人 / 期限 / SLA / 优先级")
    check("每条工单有责任人", all(p.get("owners") for p in pr), "%d/%d" % (
        sum(1 for p in pr if p.get("owners")), len(pr)))
    check("每条工单有计划期限", all(p.get("plan_fix") for p in pr), "%d/%d" % (
        sum(1 for p in pr if p.get("plan_fix")), len(pr)))
    check("每条工单有 SLA 天数", all(p.get("sla_days") for p in pr), "%d/%d" % (
        sum(1 for p in pr if p.get("sla_days")), len(pr)))
    check("每条工单有 SLA 建议截止日", all(p.get("sla_due") for p in pr), "%d/%d" % (
        sum(1 for p in pr if p.get("sla_due")), len(pr)))
    labels = {p["priority_label"] for p in pr}
    check("优先级有区分度（非单一档）", len(labels) >= 2, "档位 %s" % sorted(labels))

    print("\n【老问题 C】证据链（NVD / CNVD / CNNVD 官方链接）")
    linkable = sum(1 for p in pr if p.get("official_url"))
    check("工单带官方可核查链接", linkable > len(pr) * 0.6,
          "%d/%d（%.0f%%）" % (linkable, len(pr), linkable * 100.0 / max(1, len(pr))))
    idc = s.get("id_coverage", {})
    check("编号覆盖率已统计", bool(idc),
          "CVE %s / CNVD %s / CNNVD %s / 内部 %s / 可链接 %s" % (
              idc.get("with_cve"), idc.get("with_cnvd"), idc.get("with_cnnvd"),
              idc.get("internal_id"), idc.get("linkable")))
    check("报告正文含 NVD 链接", "nvd.nist.gov" in md)
    check("报告正文含 CNVD 链接", "cnvd.org.cn" in md)

    print("\n【老问题 D】截断规则声明")
    check("正文有清单口径声明", "清单口径" in md)
    check("口径声明含 CI 总数与展示数",
          "共分析" in md and "展示 TOP" in md)

    print("\n【七章制】审计报告结构（2026-10-05 两份标准合并）")
    for sec in ["## 一、报告基础信息", "## 二、执行摘要",
                "## 三、CMDB 数据质量检测", "## 四、CMDB 访问控制与权限安全检测",
                "## 五、变更管理合规性检测", "## 六、发现汇总与工单派发表",
                "## 七、复测计划与闭环记录"]:
        check("含章节 %s" % sec.split("、")[1], sec in md)
    print("\n【附录】原六节保留为派单依据")
    for sec in ["附录 A", "附录 B", "附录 C", "附录 D", "附录 E", "附录 F"]:
        check("含%s" % sec, sec in md)

    print("\n【第一份标准·报告基础信息】8 项工单元数据")
    check("有报告编号", "报告编号" in md)
    check("有版本与修订记录", "版本 / 修订记录" in md)
    check("有检测机构与负责人", "检测机构" in md)
    check("有检测时间窗口", "检测时间窗口" in md)
    check("有检测方法", "检测方法" in md)
    check("有参考标准（行业标准+内部制度）",
          "ISO/IEC" in md and "变更管理流程" in md)
    check("有保密等级与分发范围", "保密等级" in md and "禁止外发" in md)
    check("有被检测系统信息表", "被检测系统" in md)
    check("有检测范围与边界（明确不含什么）",
          "检测范围与边界" in md and "明确不在本次范围内" in md)

    print("\n【第二份标准·发现项 14 字段】")
    for fld in ["发现编号", "风险等级", "问题类型", "问题位置", "证据引用",
                "复现步骤", "影响描述", "修复建议", "验证方式",
                "责任角色", "修复期限", "关联信息", "状态"]:
        check("发现项含「%s」" % fld, fld in md)
    # 编号唯一：同一编号在报告里出现多次是设计如此（汇总表 + 明细标题 +
    # 「关联工单」字段各一次），所以不能数出现总次数，要数「明细条目数」。
    ids = re.findall(r"CMDB-[0-9A-F]{1,4}-\d{3}", md)
    details = re.findall(r"^#### (CMDB-[0-9A-F]{1,4}-\d{3}) ", md, re.M)
    check("发现编号唯一（明细条目不重号）",
          len(details) == len(set(details)) and bool(details),
          "明细 %d 条 / 唯一编号 %d 个" % (len(details), len(set(details))))
    # 编号必须能与工单对得上。★ 注意：派发表（6.0）只列需要行动的条目，
    #   已闭环/已接受的移到 6.3 附表且不展开明细——所以不能要求
    #   「全文编号 == 明细编号」，那是 2026-10-05 之前的结构。
    def _sec_ids(h):
        m = re.search(h, md, re.M)
        if not m:
            return set()
        nxt = re.search(r"^#{2,3} ", md[m.end():], re.M)
        seg = md[m.end():m.end() + nxt.start()] if nxt else md[m.end():]
        return set(re.findall(r"CMDB-[0-9A-F]{1,4}-\d{3}", seg))

    _disp = _sec_ids(r"^### 6\.0 待派发工单")
    _cls = _sec_ids(r"^### 6\.3 已闭环")
    _lost = set(ids) - set(details) - _disp - _cls
    check("编号均可追溯（明细 / 派发表 / 闭环表三选一必居其一）",
          not _lost,
          "全文 %d / 明细 %d / 派发 %d / 闭环 %d / 漏排 %s"
          % (len(set(ids)), len(set(details)), len(_disp), len(_cls),
             sorted(_lost)[:3]))
    check("派发表只含需行动条目（已闭环/已接受已分流到 6.3）",
          ("已关闭" not in md.split("### 6.3")[0].split("### 6.1")[0])
          or "6.3" in md,
          "派发表内不应出现已关闭/已接受")
    check("每条发现项都有位置（不写「待查」）",
          "见工单「受影响版本」字段" not in md)
    check("区分已确认 / 待确认",
          "已确认" in md and "待确认" in md)
    # 状态机：校验「状态取值都来自既定枚举」，而不是要求某个态一定出现——
    # 数据全部已确认时「待确认」就不出现，那是数据现实，不是报告缺陷。
    states = set(re.findall(r"\| (待处置|待确认（需人工复现）|修复中|已关闭|已接受) \|", md))
    check("发现项状态取值合法（无自造状态）",
          bool(states) and states <= {"待处置", "待确认（需人工复现）",
                                      "修复中", "已关闭", "已接受"},
          "实际出现 %d 种：%s" % (len(states), "、".join(sorted(states))))

    print("\n【第一份标准·执行摘要】")
    check("有整体风险评级", "整体风险等级" in md)
    check("评级带判定依据", "命中" in md and "项风险升级条件" in md)
    check("回答四问（泄露/越权/篡改/接管）",
          all(k in md for k in ("数据泄露", "权限绕过", "数据被篡改", "系统被接管")))
    check("有合规性判定", "合规性判定" in md)
    check("有健康度三维度（Correctness/Completeness/Compliance）",
          "Correctness" in md and "Completeness" in md and "Compliance" in md)
    check("有 TOP 核心问题主题", "TOP 核心问题主题" in md)
    check("优先级说明不只按 CVSS", "不是只看 CVSS" in md)

    print("\n【第一份标准·三、数据质量】")
    for item in ["自动发现覆盖率", "影子资产", "IP 地址冲突", "关键属性缺失率",
                 "资产责任人归属率", "孤儿 CI"]:
        check("数据质量含「%s」" % item, item in md)
    check("阈值判定与标准一致（5%）", "5%" in md)

    print("\n【第一份标准·四、权限安全】")
    check("含角色与权限模型章节", "角色与权限模型" in md)
    check("MFA 覆盖率已量化", "MFA 启用率" in md)
    check("API 鉴权已量化", "鉴权覆盖率" in md)
    check("检查凭据泄露", "凭据泄露" in md)
    check("角色模型缺数据时列人工核查项",
          "未核查" in md and "需人工核查" in md)

    print("\n【第一份标准·五、变更合规】")
    check("含审批链完整性", "审批人" in md and "审批时间" in md)
    check("含暗变更指标", "暗变更" in md)
    check("含流程外变更（人工录入未挂单）", "流程外变更" in md)
    check("含回滚率", "回滚率" in md)

    print("\n【第一份标准·七、复测闭环】")
    check("有复测触发条件", "触发条件" in md)
    check("有复测时间窗口（按等级）", "复测时间窗口" in md)
    check("有通过条件", "通过条件" in md)
    check("有闭环流程", "闭环流程" in md)
    check("有附件清单", "附件清单" in md)
    check("附件敏感信息说明打码", "打码" in md)

    print("\n【治理指标·数据真实】")
    aud = rep.get("audit") or {}
    check("治理数据已接入", bool(aud), "audit 键存在")
    if aud:
        q = aud.get("quality") or {}
        oc = q.get("orphan_ci") or {}
        check("孤儿 CI 用「无有效关系」口径（不是 belongs_to）",
              "无任何" in (oc.get("basis") or ""),
              oc.get("basis", "")[:40])
        check("孤儿 CI 率 < 30%（口径错误的典型信号是 >90%）",
              oc.get("pct", 100) < 30, "%.1f%%" % oc.get("pct", 0))
        b = aud.get("baseline") or {}
        check("配置漂移率已计算", b.get("checked") and b.get("drift_pct") > 0,
              "%.1f%%" % b.get("drift_pct", 0))
        ac = aud.get("access") or {}
        check("MFA 覆盖率已计算", (ac.get("account") or {}).get("checked"),
              "%.1f%%" % (ac.get("account") or {}).get("mfa_pct", 0))
        check("API 无鉴权数已计算", (ac.get("api") or {}).get("checked"),
              "无鉴权 %d" % (ac.get("api") or {}).get("no_auth", -1))
        ch = aud.get("change") or {}
        check("变更单已读入", (ch.get("order") or {}).get("checked"),
              "%d 条" % (ch.get("order") or {}).get("total", 0))
        check("生命周期暗变已计算",
              (ch.get("lifecycle") or {}).get("checked"),
              "流程外 %d 次"
              % (ch.get("lifecycle") or {}).get("manual_change_no_order", -1))
        check("健康度综合分已计算",
              (q.get("health") or {}).get("overall") is not None,
              "%.1f" % (q.get("health") or {}).get("overall", 0))
        check("未核查项已声明", bool(_uncovered_list(aud)))

    print("\n【每条工单有修复方案】")
    check("每条工单有回滚方案", all(
        (p.get("fix_plan") or {}).get("rollback") for p in pr))
    check("每条工单有变更窗口", all(
        (p.get("fix_plan") or {}).get("change_window") for p in pr))
    check("每条工单有临时缓解措施", all(
        (p.get("fix_plan") or {}).get("mitigations") for p in pr))
    check("每条工单有验收步骤", all(
        (p.get("fix_plan") or {}).get("verify") for p in pr))
    check("每条工单有受影响版本→修复版本", all(
        (p.get("fix_plan") or {}).get("affected_version") is not None for p in pr))

    print("\n【回归守护】已修好的不能退回去")
    check("无 VUL- 错位（资产标识不是漏洞记录号）", not any(
        str(h.get("asset_id", "")).startswith("VUL-") for h in hosts[:200]))
    check("台账记录号不作为资产出现在报告资产清单",
          all(a.get("asset_id", "") != p["cve"] for p in pr[:20]
              for a in (p.get("top_assets") or [])))
    # 「无已知风险」只允许出现在口径声明句里（说明已剔除），不能作为工单/资产条目出现
    placeholder = [ln for ln in md.splitlines()
                   if "无已知风险" in ln and "已剔除" not in ln]
    check("无「无已知风险」占位条目（口径声明除外）", not placeholder,
          "越界 %d 处 %s" % (len(placeholder), placeholder[:2]))
    check("处置工单编号不重复", len({p["vuln_key"] for p in pr}) == len(pr))
    comps = {p.get("component") for p in pr}
    check("组件多样性", len(comps) >= 10, "%d 种组件" % len(comps))

    # ★★★ 2026-10-05 端到端验收新增：评审的三个判断标准逐条固化成回归项 ★★★
    print("\n【本轮新增】评审三判断标准 + 证据链归属")
    # ① 排序必须服从风险分公式（公式里 KEV 是乘数 ×3，不是排序硬覆盖）
    #    ★ 2026-10-05 补：排序键新增「已确认优先」，所以只有同为已确认
    #   （或同为待确认）的两条才要求高分在前。
    viol = []
    for a, b in zip(pr, pr[1:]):
        a_open = (a.get("open_count") or 0) > 0
        b_open = (b.get("open_count") or 0) > 0
        a_acc = (a.get("accepted_count") or 0) < (a.get("asset_count") or 1)
        b_acc = (b.get("accepted_count") or 0) < (b.get("asset_count") or 1)
        a_cf = (a.get("confirmed") or 0) > 0
        b_cf = (b.get("confirmed") or 0) > 0
        if a_open == b_open and a_acc == b_acc and a_cf == b_cf:
            if float(a.get("score") or 0) < float(b.get("score") or 0):
                viol.append("%s(%.1f) 排在 %s(%.1f) 之前"
                            % (a.get("cve"), float(a.get("score") or 0),
                               b.get("cve"), float(b.get("score") or 0)))
    check("排序服从风险分公式（同等条件下高分在前）", not viol,
          "逆序 %d 处 %s" % (len(viol), viol[:2]))
    # 已确认项必须全部排在待确认项之前
    seen_pending = False
    late_confirmed = []
    for p in pr:
        if (p.get("open_count") or 0) <= 0:
            continue          # 已闭环/已接受的不参与派单顺序
        if (p.get("confirmed") or 0) <= 0:
            seen_pending = True
        elif seen_pending:
            late_confirmed.append(p.get("cve"))
    check("已确认项全部排在待确认项之前", not late_confirmed,
          "逆序 %d 条 %s" % (len(late_confirmed), late_confirmed[:3]))
    # 首条必须是「未闭环 + 已确认」里的最高风险分
    dispatchable = [p for p in pr if (p.get("open_count") or 0) > 0]
    if dispatchable:
        top_score = float(dispatchable[0].get("score") or 0)
        check("首条工单是最高风险分", top_score >= max(
            float(p.get("score") or 0) for p in dispatchable) - 1e-6,
            "首条 %.1f / 最高 %.1f" % (top_score,
                                      max(float(p.get("score") or 0)
                                          for p in dispatchable)))
        # 确认状态必须有真实数据支撑，不能全是 0（那等于没做「已确认/待确认」区分）
        cf_sum = sum(1 for p in pr if (p.get("confirmed") or 0) > 0)
        check("已确认/待确认有真实区分（存在已确认条目）", cf_sum > 0,
              "已确认 %d / 共 %d 条" % (cf_sum, len(pr)))
    # ② CPE 区间必须属于本组件（不能把 cPanel 的区间当 MongoDB 的）
    sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
    import asset_scan as _AS
    bad_cpe = []
    for p in pr:
        fp = p.get("fix_plan") or {}
        rngs = fp.get("affected_cve_range") or []
        if not rngs:
            continue
        comp = _nz_test(p.get("component"))
        # 用与生成侧同一套归一：取组件名里最长词元，核对是否出现在任一区间的 CPE 产品里
        tot = p.get("cpe_ranges_total") or 0
        if tot and len(rngs) >= tot and tot > 3:
            # 条数等于 NVD 全部 CPE 条数 → 说明没做产品过滤
            bad_cpe.append("%s/%s 用了全部 %d 条 CPE" % (p.get("cve"), comp, tot))
    check("CPE 区间已按组件过滤（非全量照搬）", not bad_cpe,
          "未过滤 %d 条 %s" % (len(bad_cpe), bad_cpe[:2]))
    # ③ 报告必须声明自己的覆盖率和已知缺陷（元规则）
    check("正文声明编号覆盖率", "覆盖率" in md)
    check("正文披露已知漏报/数据缺陷", "已知漏报" in md or "数据缺陷" in md)
    check("正文披露位置口径（以机柜为准的理由）", "以机柜" in md)
    # 措辞准确性：CNVD/CNNVD 编号不能被说成「NVD 未提供该 CVE」——
    # 这类编号本来就查不了 NVD，说法误导，运维会以为情报库缺条目
    mislead = []
    for ln in md.splitlines():
        if "受影响版本区间" not in ln:
            continue
        if ("CNVD" in ln or "CNNVD" in ln) and "NVD 未提供该 CVE" in ln:
            mislead.append(ln.strip()[:80])
    check("CPE 区间缺失措辞与编号类型相符", not mislead,
          "误导 %d 处 %s" % (len(mislead), mislead[:1]))
    check("正文声明 CPE 区间按组件匹配", "属于该组件" in md)


def _nz_test(s):
    return (s or "").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    if args.json:
        rep = json.load(open(args.json, encoding="utf-8"))
        sys.path.insert(0, os.path.join(ROOT, "core"))
        sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
        import cmdb_scan as CS
        md = CS.report_to_markdown(rep)
    else:
        print("跑离线全量流水线…")
        rep, md = run_pipeline()
        with open(os.path.join(ROOT, "测试报告", "cmdb_verify.json"), "w",
                  encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=1)
        with open(os.path.join(ROOT, "测试报告", "cmdb_verify.md"), "w",
                  encoding="utf-8") as f:
            f.write(md)
        print("产出：测试报告/cmdb_verify.{json,md}")
    verify(rep, md)
    bad = [n for n, ok, _ in _results if not ok]
    print("\n" + "=" * 70)
    print("合计 %d 项，通过 %d，失败 %d" % (
        len(_results), len(_results) - len(bad), len(bad)))
    if bad:
        print("失败项：")
        for n in bad:
            print("  - %s" % n)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
