# -*- coding: utf-8 -*-
"""CMDB 治理审计指标采集（2026-10-05 · 第七章制审计报告）。

★ 为什么单独一个模块（而不是塞进 cmdb_scan.py）：
  cmdb_scan.py 负责「漏洞风险」——漏洞台账、风险分、处置工单。
  本模块负责「CMDB 治理审计」——数据质量、权限安全、变更合规。
  两者数据源、判定标准、读者对象都不同，混在一起会让 3800 行的文件
  变成谁都不敢改的黑箱。治理指标也不参与漏洞风险计算，纯旁路。

★ 铁律：只报「能从源数据算出来」的指标。
  CMDB 导出里没有的东西（如影子资产的主动探测结果、角色权限配置表）
  一律标为「本次导出不含该数据」并进入未覆盖清单，
  绝不填 0冒充「检测通过」——那是审计报告最致命的失真。

数据来源（E:\\cmdb\\csv 实测表头）：
  资产表    physical_server / vm_cloud_host / network_device / security_device /
            storage_device / gpu_node / middleware_instance / database_instance /
            container_pod / app_instance / bigdata_component
  质量      ip_allocation（IP 冲突 / 僵尸 IP） / ci_relation（孤儿 CI / 自动发现占比）
  基线      config_audit_log（IS_DRIFT / DRIFT_LEVEL / APPROVE_REQUIRED）
  变更      change_order / ci_lifecycle_log
  权限      employee（MFA / SSO） / api_endpoint（AUTH_TYPE / IS_PUBLIC）
  证书      domain_cert（TLS 版本 / 密钥长度 / 临期）
"""
from __future__ import annotations

import os
import re
from collections import Counter, OrderedDict, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

# —— CMDB 资产表识别（首列主键 → 表类型）——
#    ★ 键一律小写：表头会被 _norm_header 转成大写后再比对，
#      这里若写成大写键，classify_table 会永远返回 ''（实测踩过：
#      ASSET_TABLES 写大写 SRV_ID，表头也是 SRV_ID，却一个都识别不出来）。
ASSET_TABLES: Dict[str, str] = {
    "srv_id": "物理机", "vm_id": "虚拟机", "net_id": "网络设备",
    "sec_id": "安全设备", "stg_id": "存储设备", "gpu_node_id": "GPU节点",
    "mw_id": "中间件", "db_id": "数据库", "pod_id": "容器POD",
    "inst_id": "应用实例", "bd_id": "大数据组件", "comp_id": "容器集群",
}

# —— 资产表关键属性（3.1 关键属性缺失率）——
#    值为空 → 缺失。这些字段是「派单时必须知道」的信息。
CRITICAL_ATTRS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("IP 地址", ("INNER_IP", "MGMT_IP", "HOST_IP", "POD_IP", "MANAGEMENT_IP")),
    ("责任人", ("OWNER",)),
    ("员工号", ("EMP_ID",)),
    ("所属部门", ("DEPT_ID",)),
    ("业务系统", ("APP_NAME", "BIZ_DOMAIN", "BUSINESS_BG")),
    ("环境标签", ("ENV_TYPE",)),
    ("重要程度", ("IMPORTANCE",)),
    ("在册状态", ("CMDB_STATUS",)),
)

# —— 3.1 判定阈值（来自审计标准）——
COVERAGE_DIFF_FAIL = 5.0     # 自动发现覆盖率差异率 > 5% 即不合格
ORPHAN_WARN_RATIO = 20.0      # 孤儿 CI 占比 > 20% 判 High
MISSING_ATTR_FAIL = 5.0       # 关键属性缺失率 > 5% 判 High
# —— 样本量门槛（2026-10-05）——
#   实测踩坑：只喂 20 个 CI + 201 条关系时，孤儿率算出 100%，会被当成
#   「CMDB 质量全面崩坏」写进执行摘要。样本不足时结论没有意义，
#   宁可标「样本不足，未判定」也不能给一个假的高风险。
MIN_CI_FOR_QUALITY = 500      # 质量类指标（孤儿率/冲突率/缺失率）最低样本
MIN_REL_FOR_AUTO = 1000       # 自动发现占比最低样本

# —— 3.2 基线偏离分级：安全相关字段从严 ——
#    这些字段偏离会直接导致越权/暴露/审计缺失，标 High 及以上。
SECURITY_CRITICAL_FIELDS = frozenset((
    "PERMISSION", "AUTH", "PASSWORD", "ACL", "FIREWALL", "PORT", "PROTOCOL",
    "SSL", "TLS", "ENCRYPT", "AUDIT", "LOG", "ACCOUNT", "ROOT", "PRIVILEGE",
))
HIGH_RISK_FIELDS = frozenset((
    "OS_VERSION", "VERSION", "STATUS", "ENV_TYPE", "IMPORTANCE", "CMDB_STATUS",
))


def _nz(v: Any) -> str:
    """None / 空串 / 各种 falsy 归一成空串（不 strip 内容，避免破坏地址）。"""
    if v is None:
        return ""
    s = str(v).strip()
    return "" if s in ("", "-", "--", "null", "NULL", "None", "N/A") else s


def _is_yn(v: Any) -> bool:
    return _nz(v).upper() in ("Y", "YES", "TRUE", "1", "是")


def _rate(num: int, den: int) -> float:
    return round(num * 100.0 / den, 2) if den else 0.0


def _norm_header(cells: Iterable[Any]) -> List[str]:
    return [_nz(c).upper() for c in (cells or [])]


# ==========================================================================
# 表识别
# ==========================================================================
def classify_table(header: List[str]) -> str:
    """按首列主键判定表类型。返回表名（小写下划线）或 ''。

    ★ 必须看首列（表主键），不能靠「有哪些列」猜：
      gpu_node 既有 GPU_NODE_ID 又有 CAB_ID/IDC_ID，靠列存在性判
      会把 GPU 节点表当成机柜表（2026-10-05 实测踩过）。
    """
    h = _norm_header(header)
    if not h:
        return ""
    pk = h[0].lower()
    if pk in ASSET_TABLES:
        return pk
    if pk == "change_id":
        return "change_order"
    if pk == "audit_id":
        return "config_audit_log"
    if pk == "rel_id":
        return "ci_relation"
    if pk == "log_id":
        return "ci_lifecycle_log"
    if pk == "ip_id":
        return "ip_allocation"
    if pk == "emp_id":
        return "employee"
    if pk == "api_id":
        return "api_endpoint"
    if pk == "dc_id":
        return "domain_cert"
    return ""


def _rows_of(records: List[List[Any]]) -> Tuple[List[str], List[Dict[str, str]]]:
    """把「首行为表头」的记录流切成 (表头, 行 dict 列表)。"""
    if not records:
        return [], []
    header = _norm_header(records[0])
    if not any(header):
        return [], []
    out: List[Dict[str, str]] = []
    for rec in records[1:]:
        if not rec or not any(_nz(c) for c in rec):
            continue
        out.append({header[i]: _nz(rec[i]) for i in range(min(len(header), len(rec)))})
    return header, out


# ==========================================================================
# 3.1 资产发现完整性与准确性
# ==========================================================================
def audit_data_quality(tables: Dict[str, List[Dict[str, str]]]) -> Dict[str, Any]:
    """CMDB 数据质量：正确性 / 完整性 / 合规性三个 KPI。

    返回结构里每个指标都带 checked 标记：
      checked=False → 本次导出无该数据，报告必须写「未覆盖」而非 0。
    """
    r: Dict[str, Any] = {}

    # —— 3.1.1 资产台账总览 ——
    asset_rows: List[Dict[str, str]] = []
    per_table: Counter = Counter()
    ci_ids: set = set()
    for tname, trows in tables.items():
        if tname not in ASSET_TABLES:
            continue
        label = ASSET_TABLES[tname]
        per_table[label] += len(trows)
        pk = tname.upper()          # 主键列名 = 表名大写
        for row in trows:
            v = _nz(row.get(pk))
            if v:
                ci_ids.add(v)
            asset_rows.append(row)
    r["asset_total"] = len(asset_rows)
    r["asset_ci_total"] = len(ci_ids)
    r["asset_by_type"] = dict(per_table.most_common())

    # —— 3.1.2 自动发现覆盖率 ——
    # 口径：ci_relation 里 IS_AUTO_DISCOVER=Y 的关系占比，反映 CMDB 里
    # 「有多少关系是机器探测发现的」而非人工录入。
    # ★ 注意：这不是标准里的「主动扫描 vs CMDB 差异率」——真实差异率需要
    #   一次主动探测扫描做基准，本次 CMDB 导出不含该数据。
    rel = tables.get("ci_relation") or []
    if rel:
        auto = sum(1 for x in rel if _is_yn(x.get("IS_AUTO_DISCOVER")))
        r["auto_discover"] = {
            "checked": True,
            "relations": len(rel),
            "auto": auto,
            "manual": len(rel) - auto,
            "auto_pct": _rate(auto, len(rel)),
            "pending": sum(1 for x in rel if _nz(x.get("STATUS")) == "待确认"),
            "invalid": sum(1 for x in rel if _nz(x.get("STATUS")) == "已失效"),
        }
    else:
        r["auto_discover"] = {"checked": False,
                              "reason": "本次导出不含 ci_relation（CI 关系拓扑表）"}

    # 覆盖率差异率（标准要求的 5% 判定项）
    r["coverage_diff"] = {
        "checked": False,
        "reason": "需一次主动探测扫描（IP/MAC/端口/OS/组件）作为基准，"
                  "本次 CMDB 导出不含扫描结果，无法计算差异率",
        "threshold": COVERAGE_DIFF_FAIL,
    }

    # —— 3.1.3 影子资产 / 僵尸 CI ——
    # 影子资产需外部扫描基准；这里给出「已下线但 IP 仍在使用」的可算部分。
    ips = tables.get("ip_allocation") or []
    if ips:
        conflict = [x for x in ips if _is_yn(x.get("IS_CONFLICT"))]
        unused = [x for x in ips if _nz(x.get("USAGE_STATUS")) in ("空闲", "已回收")]
        # —— 僵尸 CI：资产表标「在线运行/在册」，但它名下的 IP 已空闲或回收 ——
        #   这是 CMDB 里真实存在的不一致：机器还在册、网络资源已释放。
        #   ★ 取主键不能靠 dict.values()[0]（依赖表头列序，换个导出就错），
        #   必须按已知主键列取值。
        alive: set = set()
        for pk, rows in tables.items():
            if pk not in ASSET_TABLES:
                continue
            key = pk.upper()
            for row in rows:
                if _nz(row.get("CMDB_STATUS")) in ("在线运行", "在册"):
                    v = _nz(row.get(key))
                    if v:
                        alive.add(v)
        zombie = [x for x in unused
                  if _nz(x.get("CI_ID")) and _nz(x.get("CI_ID")) in alive]
        r["shadow"] = {
            "checked": False,
            "reason": "影子资产（实际存在但未录入 CMDB）需外部主动探测发现，"
                      "本次导出无该数据；下方「IP 占用与在册 CI 冲突」为可算的近似项",
        }
        r["ip_quality"] = {
            "checked": True,
            "total": len(ips),
            "conflict": len(conflict),
            "conflict_pct": _rate(len(conflict), len(ips)),
            "unused": len(unused),
            "zombie_assigned": len(zombie),
            "basis": "僵尸 CI = CMDB 标在线运行/在册，但其名下 IP 使用状态为「空闲/已回收」",
            "sufficient": len(ips) >= MIN_CI_FOR_QUALITY,
            "conflict_samples": [
                {"ip": x.get("IP_ADDRESS", ""), "ci_id": x.get("CI_ID", ""),
                 "hostname": x.get("HOSTNAME", ""), "ci_type": x.get("CI_TYPE", ""),
                 "usage": x.get("USAGE_STATUS", "")}
                for x in conflict[:20]
            ],
            "zombie_samples": [
                {"ip": x.get("IP_ADDRESS", ""), "ci_id": x.get("CI_ID", ""),
                 "hostname": x.get("HOSTNAME", ""), "usage": x.get("USAGE_STATUS", ""),
                 "owner": x.get("OWNER", ""), "dept": x.get("DEPT_ID", "")}
                for x in zombie[:20]
            ],
        }
    else:
        r["shadow"] = {"checked": False, "reason": "本次导出不含 ip_allocation"}
        r["ip_quality"] = {"checked": False, "reason": "本次导出不含 ip_allocation"}

    # —— 3.1.4 / 3.1.5 的统计单元：按 CI 去重，不是按行——
    #★ 为什么必须去重（2026-10-06 审查发现）：
    #   ① 同一台机器会出现在多张资产表（物理机 + 它上面跑的中间件/容器/应用
    #      实例各一张表，共用同一个 CI 标识）；
    #   ② 多库合并（cfg["paths"] 传多个 .db）时同一批 CI 会在每个库里各出现一次，
    #      实测「新快照 + 旧快照」两个库重叠上传，责任人归属率从 10.00% 漂到 15.38%，
    #      报告数字随上传了几个库而变，而报告里没有任何地方说明这一点。
    #   而下方 orphan_ci 用的分母已经是去重后的 len(ci_ids)，两处口径必须一致，
    #   否则「孤儿率 13.5%」与「责任人归属率 15.38%」放在同一章里无法互相印证。
    # 合并策略：同一 CI 的多个来源行按字段取「首个非空值」，与 _build_ledger_report
    # 里资产清单的合并方式一致。
    _ci_rows: "OrderedDict[str, dict]" = OrderedDict()
    _pk_of = {t: t.upper() for t in ASSET_TABLES}
    for tname, trows in tables.items():
        if tname not in ASSET_TABLES:
            continue
        pk = _pk_of[tname]
        for row in trows:
            cid = _nz(row.get(pk))
            if not cid:
                # 无主键的行无法定位到具体 CI，退回按行计入，避免静默丢弃数据
                cid = "\x00row\x00%s\x00%d" % (tname, len(_ci_rows))
            cur = _ci_rows.get(cid)
            if cur is None:
                _ci_rows[cid] = dict(row)
                continue
            for k, v in row.items():
                if not _nz(cur.get(k)) and _nz(v):
                    cur[k] = v
    ci_rows: List[Dict[str, str]] = list(_ci_rows.values())
    r["asset_rows_total"] = len(asset_rows)      # 原始行数，保留供对照
    r["asset_ci_total"] = len(ci_ids)

    # —— 3.1.4 关键属性缺失率（分母 = 去重后的 CI 数）——
    attr_stat: Dict[str, Dict[str, int]] = {}
    for label, cands in CRITICAL_ATTRS:
        miss = sum(1 for row in ci_rows
                   if not any(_nz(row.get(c)) for c in cands))
        total = len(ci_rows)
        if total:
            attr_stat[label] = {"missing": miss, "total": total,
                                "pct": _rate(miss, total)}
    r["attr_missing"] = {
        "checked": bool(attr_stat),
        "items": attr_stat,
        "worst": max(attr_stat.items(), key=lambda kv: kv[1]["pct"])[0] if attr_stat else "",
        "worst_pct": max((v["pct"] for v in attr_stat.values()), default=0.0),
        "basis": "按 CI 去重统计（同一 CI 出现在多张表/多个库只计一次）",
    }

    # —— 3.1.5 资产责任人归属率（分母同上）——
    owned = sum(1 for row in ci_rows
                if _nz(row.get("OWNER")) and _nz(row.get("EMP_ID")))
    r["ownership"] = {
        "checked": bool(ci_rows),
        "total": len(ci_rows),
        "owned": owned,
        "pct": _rate(owned, len(ci_rows)),
        "rows_total": len(asset_rows),
        "basis": "按 CI 去重统计（同一 CI 出现在多张表/多个库只计一次）",
        "no_owner_samples": [
            {"ci": _nz(x.get(_pk_of[t])), "type": ASSET_TABLES.get(t, ""),
             "env": _nz(x.get("ENV_TYPE")), "app": _nz(x.get("APP_NAME")),
             "ip": next((_nz(x.get(c)) for c in ("INNER_IP", "MGMT_IP", "HOST_IP")
                         if _nz(x.get(c))), "")}
            for t, rows in tables.items() if t in ASSET_TABLES
            for x in rows if not (_nz(x.get("OWNER")) and _nz(x.get("EMP_ID")))
        ][:20],
    }

    # —— 3.1.6 孤儿 CI ——
    # ★ 口径修正（2026-10-05 实测踩坑，差异 7 倍）：
    #   审计标准里的 Orphan CI 是「未关联到任何业务服务的 CI」。若照字面只查
    #   REL_TYPE=belongs_to，实测 284600 个资产 CI 里 belongs_to 命中 **0 个**
    #   ——因为 belongs_to 只连 app / ipa / dc / api / job 这五类非资产对象，
    #   基础设施 CI（srv/vm/net/mw/db…）根本不参与这条关系。按那个口径算出的
    #   93.4% 是假的，会让 CMDB 团队白整改三轮。
    #   正确口径：CI 在整张关系图里没有任何**有效**关系（STATUS≠已失效）即为孤儿，
    #   实测 13.5%，才是可执行的整改基数。两个数都会写进报告，让读者看到口径差异。
    if rel:
        effective: set = set()
        belong: set = set()
        for x in rel:
            if _nz(x.get("STATUS")) == "已失效":
                continue
            for col in ("SOURCE_CI_ID", "TARGET_CI_ID"):
                v = _nz(x.get(col))
                if v:
                    effective.add(v)
            if _nz(x.get("REL_TYPE")) == "belongs_to":
                v = _nz(x.get("SOURCE_CI_ID"))
                if v:
                    belong.add(v)
        orphan = [c for c in ci_ids if c and c not in effective]
        # 样本量不足时不给结论（见 MIN_CI_FOR_QUALITY 说明）
        enough = len(ci_ids) >= MIN_CI_FOR_QUALITY
        r["orphan_ci"] = {
            "checked": True,
            "total": len(ci_ids),
            "orphan": len(orphan),
            "pct": _rate(len(orphan), len(ci_ids)),
            "threshold": ORPHAN_WARN_RATIO,
            "effective_rel": len(effective),
            # 备选口径一并留档，供读者判断整改范围
            "belong_only": len([c for c in ci_ids if c and c in belong]),
            "basis": "在 ci_relation 关系图中无任何 STATUS≠已失效 的关系",
            "sufficient": enough,
            "note": "" if enough else "样本不足（CI %d < %d），本项百分比仅供参考，"
                                      "不宜作为整改依据" % (len(ci_ids), MIN_CI_FOR_QUALITY),
            "samples": orphan[:20],
        }
    else:
        r["orphan_ci"] = {"checked": False, "reason": "本次导出不含 ci_relation"}

    # —— 健康度综合评分（Correctness / Completeness / Compliance）——
    r["health"] = _health_score(r)
    return r


def _health_score(q: Dict[str, Any]) -> Dict[str, Any]:
    """把可算的指标折成三个 KPI。不可算的项不参与，给出 coverage 说明。

    ★ 样本量不足时 overall 只给参考值并标 sufficient=False——
      20 个 CI 算出「健康度 48.5」会被当成真实质量结论。
    """
    enough = int(q.get("asset_ci_total") or 0) >= MIN_CI_FOR_QUALITY
    dims: Dict[str, Dict[str, Any]] = {}

    # Correctness：IP 冲突率 + 孤儿 CI 率（越低越好）
    parts = []
    ipq = q.get("ip_quality") or {}
    if ipq.get("checked"):
        parts.append((100.0 - float(ipq.get("conflict_pct") or 0), "IP 冲突率"))
    orph = q.get("orphan_ci") or {}
    if orph.get("checked"):
        parts.append((100.0 - float(orph.get("pct") or 0), "孤儿 CI 率"))
    if parts:
        dims["Correctness"] = {
            "score": round(sum(p[0] for p in parts) / len(parts), 1),
            "basis": "、".join("100 − %s" % p[1] for p in parts),
        }

    # Completeness：关键属性完整度 + 责任人归属率
    parts = []
    am = q.get("attr_missing") or {}
    if am.get("checked") and am.get("items"):
        vals = [100.0 - float(v["pct"]) for v in am["items"].values()]
        parts.append((sum(vals) / len(vals), "关键属性完整度"))
    own = q.get("ownership") or {}
    if own.get("checked"):
        parts.append((float(own.get("pct") or 0), "责任人归属率"))
    if parts:
        dims["Completeness"] = {
            "score": round(sum(p[0] for p in parts) / len(parts), 1),
            "basis": "、".join(p[1] for p in parts),
        }

    # Compliance：需以「资产是否纳入正式变更流程」判定。
    # 变更单只覆盖「有变更动作的 CI」，无法反推全量 CI 的流程绑定关系 →
    # 这一维度不参与评分，如实标为未核查。
    dims["Compliance"] = {"score": None,
                          "basis": "需以「资产是否纳入正式变更流程」判定，"
                                   "本次导出不含流程绑定关系"}

    checked = [k for k, v in dims.items() if v.get("score") is not None]
    overall = (round(sum(dims[k]["score"] for k in checked) / len(checked), 1)
               if checked else None)
    return {"dims": dims, "overall": overall, "checked_dims": checked,
            "unchecked_dims": [k for k in dims if k not in checked],
            "sufficient": enough,
            "sample_note": "" if enough else
            "样本量不足（CI %d < %d），综合分仅供参考"
            % (q.get("asset_ci_total") or 0, MIN_CI_FOR_QUALITY)}


# ==========================================================================
# 3.2 配置基线符合性
# ==========================================================================
def audit_baseline(tables: Dict[str, List[Dict[str, str]]]) -> Dict[str, Any]:
    """配置基线核查：漂移率、偏离分级、待审批变更。

    数据源 config_audit_log（配置项变更审计）：
      IS_DRIFT=Y → 检出漂移；DRIFT_LEVEL=严重漂移/轻微漂移
      APPROVE_REQUIRED=Y 但无审批 → 高危（未经批准的配置变更）
    """
    rows = tables.get("config_audit_log") or []
    if not rows:
        return {"checked": False,
                "reason": "本次导出不含 config_audit_log（配置项审计日志），"
                          "基线符合性无法核查"}
    drift = [x for x in rows if _is_yn(x.get("IS_DRIFT"))]
    severe = [x for x in drift if _nz(x.get("DRIFT_LEVEL")) == "严重漂移"]
    minor = [x for x in drift if _nz(x.get("DRIFT_LEVEL")) == "轻微漂移"]
    # 未经批准的配置变更：要求审批但 CHANGE_SOURCE 属自动同步/回调
    no_approve = [x for x in rows
                  if _is_yn(x.get("APPROVE_REQUIRED"))
                  and _nz(x.get("CHANGE_SOURCE")) in ("云平台回调", "API集成", "自动发现同步")
                  and _nz(x.get("RESULT")) != "成功"]
    field_stat: Counter = Counter()
    for x in drift:
        field_stat[_nz(x.get("FIELD_CN")) or _nz(x.get("FIELD_NAME")) or "(未命名)"] += 1

    # —— 源数据缺陷检测：OLD_VALUE / NEW_VALUE 被填成「另一个字段的值」（2026-10-05）
    #   实测 20.1% 的漂移记录如此：字段=内存容量 却写 「CentOS 7.9 → 二级重要」，
    #   新值是 IMPORTANCE 的枚举。原样打印会让运维以为有人把内存容量
    #   改成了「二级重要」——这比不报更糟。检出后在报告里显式说明。
    enum_markers = ("级", "重要", "一般", "边缘", "在线", "运行", "环境",
                    "生产", "测试", "无漂移", "已下线", "在册")
    value_fields = ("重要等级", "运行状态", "环境类型", "CMDB状态",
                    "责任部门", "所属部门", "业务域")
    bad_value = []
    for x in drift:
        f = _nz(x.get("FIELD_CN"))
        nv = _nz(x.get("NEW_VALUE"))
        ov = _nz(x.get("OLD_VALUE"))
        if f in value_fields:
            continue
        if any(k in nv for k in enum_markers) and not any(
                k in nv for k in ("核", "GB", "TB", "MB", "%")):
            bad_value.append(x)
        elif ov and any(k in ov for k in enum_markers) and not any(
                k in ov for k in ("核", "GB", "TB", "MB", "%")):
            bad_value.append(x)
    bad_ids = {id(x) for x in bad_value}
    return {
        "checked": True,
        "total": len(rows),
        "drift": len(drift),
        "drift_pct": _rate(len(drift), len(rows)),
        "severe": len(severe),
        "minor": len(minor),
        "fail": sum(1 for x in rows if _nz(x.get("RESULT")) == "失败"),
        "partial": sum(1 for x in rows if _nz(x.get("RESULT")) == "部分成功"),
        "auto_sync": sum(1 for x in rows if _is_yn(x.get("IS_AUTO_SYNC"))),
        "unapproved": len(no_approve),
        "top_fields": field_stat.most_common(15),
        # 源数据缺陷：字段名与「原值/新值」语义不符的比例
        "value_mismatch": len(bad_value),
        "value_mismatch_pct": _rate(len(bad_value), len(drift)),
        "value_mismatch_note": "这些记录的 OLD_VALUE / NEW_VALUE 填的是其他配置项的值"
                               "（如「内存容量」的新值写成「二级重要」），"
                               "**不能据此判断配置差异**，需回查 CMDB 变更历史",
        "severe_samples": [
            {"ci": x.get("CI_ID", ""), "ci_name": x.get("CI_NAME", ""),
             "field": x.get("FIELD_CN", ""),
             # 值语义不符时不打印「原值 → 新值」，避免误导
             "old": ("（值语义不符，不展示）" if id(x) in bad_ids
                     else x.get("OLD_VALUE", "")),
             "new": ("（值语义不符，不展示）" if id(x) in bad_ids
                     else x.get("NEW_VALUE", "")),
             "mismatch": id(x) in bad_ids,
             "src": x.get("CHANGE_SOURCE", ""),
             "level": x.get("DRIFT_LEVEL", ""), "time": x.get("OPERATE_TIME", ""),
             "dept": x.get("DEPT_ID", "")}
            for x in severe[:20]
        ],
        "unapproved_samples": [
            {"ci": x.get("CI_ID", ""), "field": x.get("FIELD_CN", ""),
             "src": x.get("CHANGE_SOURCE", ""), "result": x.get("RESULT", ""),
             "operator": x.get("OPERATOR", ""), "ip": x.get("OPERATOR_IP", ""),
             "time": x.get("OPERATE_TIME", "")}
            for x in no_approve[:20]
        ],
    }


# ==========================================================================
# 四、访问控制与权限安全
# ==========================================================================
def audit_access_control(tables: Dict[str, List[Dict[str, str]]]) -> Dict[str, Any]:
    """4.1 角色与权限模型 / 4.2 API 与集成安全。

    ★ 重要边界：CMDB 导出里没有「角色定义表」「超级管理员账号表」。
      标准要求的「SuperAdmin 账号数 ≤ 2」无法从导出数据判定，
      这里标 checked=False 并说明需要什么数据——不拿 MFA 覆盖率冒充权限合规。
    """
    r: Dict[str, Any] = {}

    # —— 4.1.1 账号安全基线（employee）——
    emp = tables.get("employee") or []
    if emp:
        admins_like = [x for x in emp
                       if _nz(x.get("JOB_LEVEL")).startswith("M")
                       or any(k in _nz(x.get("POSITION"))
                              for k in ("管理员", "admin", "Admin", "运维", "平台"))]
        mfa_off = [x for x in emp if _nz(x.get("MFA_ENABLED")).upper() == "N"]
        sso_off = [x for x in emp if _nz(x.get("SSO_ENABLED")).upper() == "N"]
        mfa_off_admin = [x for x in mfa_off
                         if _nz(x.get("JOB_LEVEL")).startswith("M")]
        r["account"] = {
            "checked": True,
            "total": len(emp),
            "privileged_like": len(admins_like),
            "mfa_enabled": len(emp) - len(mfa_off),
            "mfa_pct": _rate(len(emp) - len(mfa_off), len(emp)),
            "mfa_disabled": len(mfa_off),
            "mfa_disabled_privileged": len(mfa_off_admin),
            "sso_disabled": len(sso_off),
            "sso_disabled_privileged": sum(
                1 for x in sso_off if _nz(x.get("JOB_LEVEL")).startswith("M")),
            "by_emp_type": dict(Counter(_nz(x.get("EMP_TYPE")) or "(空)" for x in emp)),
            "mfa_off_samples": [
                {"emp": x.get("EMP_ID", ""), "level": x.get("JOB_LEVEL", ""),
                 "position": x.get("POSITION", ""), "dept": x.get("DEPT_NAME", ""),
                 "type": x.get("EMP_TYPE", ""), "ci_owned": x.get("CI_OWNED_COUNT", "")}
                for x in mfa_off_admin[:20]
            ],
        }
    else:
        r["account"] = {"checked": False, "reason": "本次导出不含 employee（人员账号表）"}

    # —— 4.1.2 角色权限模型 ——
    r["rbac"] = {
        "checked": False,
        "reason": "需 CMDB 平台侧导出「角色定义表 + 角色-账号绑定表」"
                  "（SuperAdmin/Admin/Viewer 及授权粒度）；"
                  "本次导出为业务资产数据，不含平台权限配置",
        "manual_checks": [
            "超级管理员账号数量及使用情况（应 ≤ 2 个）",
            "是否存在「全员可写」或默认高权限配置",
            "权限变更是否有审批记录，是否可按单个 CI 粒度授权/撤销",
            "职责分离：资产录入人与审批人是否为同一账号",
        ],
    }

    # —— 4.2.1 API 认证与暴露面（api_endpoint）——
    apis = tables.get("api_endpoint") or []
    if apis:
        noauth = [x for x in apis
                  if "无鉴权" in _nz(x.get("AUTH_TYPE"))]
        noauth_public = [x for x in noauth if _is_yn(x.get("IS_PUBLIC"))]
        sensitive_noauth = [x for x in apis
                            if _is_yn(x.get("IS_SENSITIVE"))
                            and ("无鉴权" in _nz(x.get("AUTH_TYPE"))
                                 or _nz(x.get("AUTH_TYPE")) == "")]
        http_sensitive = [x for x in apis
                          if _nz(x.get("PROTOCOL")).upper() == "HTTP"
                          and _is_yn(x.get("IS_SENSITIVE"))]
        r["api"] = {
            "checked": True,
            "total": len(apis),
            "auth_types": dict(Counter(_nz(x.get("AUTH_TYPE")) or "(空)" for x in apis)),
            "public": sum(1 for x in apis if _is_yn(x.get("IS_PUBLIC"))),
            "no_auth": len(noauth),
            "no_auth_public": len(noauth_public),
            "sensitive": sum(1 for x in apis if _is_yn(x.get("IS_SENSITIVE"))),
            "sensitive_no_auth": len(sensitive_noauth),
            "sensitive_plain_http": len(http_sensitive),
            "deprecated_public": sum(1 for x in apis
                                     if _is_yn(x.get("IS_PUBLIC"))
                                     and _is_yn(x.get("IS_DEPRECATED"))),
            "auth_ratio": _rate(
                sum(1 for x in apis if _nz(x.get("AUTH_TYPE"))
                    and "无鉴权" not in _nz(x.get("AUTH_TYPE"))), len(apis)),
            "critical_samples": ([
                {"api": x.get("API_PATH", ""), "app": x.get("APP_NAME", ""),
                 "auth": x.get("AUTH_TYPE", ""), "public": x.get("IS_PUBLIC", ""),
                 "sensitive": x.get("IS_SENSITIVE", ""), "proto": x.get("PROTOCOL", ""),
                 "owner": x.get("OWNER", "")}
                for x in (noauth_public + sensitive_noauth)[:20]
            ]),
        }
    else:
        r["api"] = {"checked": False, "reason": "本次导出不含 api_endpoint"}

    # —— 4.2.2 凭据泄露静态检查 ——
    # 只能扫「明文存储的凭据字段」，不等于代码级硬编码检查。
    cred_pat = re.compile(
        r"(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)",
        re.I)
    leaks: List[Dict[str, str]] = []
    scanned = 0
    for tname, rows in tables.items():
        if not rows:
            continue
        for col in rows[0].keys():
            if not cred_pat.search(col or ""):
                continue
            scanned += 1
            for row in rows:
                v = _nz(row.get(col))
                # 明文口令特征：有值、非掩码、非引用
                if not v or v in ("******", "***", "*** ***", "MASKED", "REDACTED"):
                    continue
                if re.match(r"^(\$|ENC\(|\{\{|vault:|ref:|@ref)", v, re.I):
                    continue
                if len(v) < 8:
                    continue
                # 取 CI 标识：按各表已知主键列取，不用 dict.values()[0]
                ci = next((_nz(row.get(k))
                           for k in ("CI_ID", "SRV_ID", "VM_ID", "NET_ID",
                                     "MW_ID", "DB_ID") if _nz(row.get(k))), "")
                leaks.append({"table": tname, "column": col, "ci": ci,
                              "preview": v[:6] + "***（已截断）"})
                break        # 每列只报一条，避免刷屏
    r["credential"] = {
        "checked": scanned > 0,
        "scanned_columns": scanned,
        "plaintext_guess": len(leaks),
        "note": "仅检查 CMDB 导出中是否存在疑似明文凭据字段；"
                "代码仓库硬编码密钥需 SAST 扫描，本次不含该数据",
        "samples": leaks[:20],
    }

    # —— 4.2.3 证书安全（domain_cert）——
    certs = tables.get("domain_cert") or []
    if certs:
        weak_tls = [x for x in certs
                    if _nz(x.get("TLS_VERSION")).upper() in ("TLSV1", "TLSV1.0",
                                                              "TLSV1.1", "SSL3.0", "SSLV3")]
        weak_key = [x for x in certs
                    if _nz(x.get("CERT_KEY_LEN")).isdigit()
                    and int(_nz(x.get("CERT_KEY_LEN"))) < 2048]
        soon = [x for x in certs
                if _nz(x.get("REMAIN_DAYS")).isdigit()
                and 0 <= int(_nz(x.get("REMAIN_DAYS"))) <= 30]
        r["cert"] = {
            "checked": True,
            "total": len(certs),
            "weak_tls": len(weak_tls),
            "weak_key": len(weak_key),
            "expiring_30d": len(soon),
            "no_auto_renew": sum(1 for x in certs
                                 if _nz(x.get("AUTO_RENEW")).upper() == "N"),
            "tls_versions": dict(Counter(_nz(x.get("TLS_VERSION")) or "(空)"
                                         for x in certs)),
            "samples": [
                {"domain": x.get("DOMAIN_NAME", ""), "tls": x.get("TLS_VERSION", ""),
                 "key": x.get("CERT_KEY_LEN", ""), "remain": x.get("REMAIN_DAYS", ""),
                 "owner": x.get("OWNER", "")}
                for x in (weak_tls + weak_key)[:20]
            ],
        }
    else:
        r["cert"] = {"checked": False, "reason": "本次导出不含 domain_cert"}
    return r


# ==========================================================================
# 五、变更管理合规性
# ==========================================================================
def audit_change(tables: Dict[str, List[Dict[str, str]]]) -> Dict[str, Any]:
    """变更合规：暗变更、审批链完整性、执行及时率。

    ★ 标准里的两个直接指标：
      「发现未经批准的配置的次数」 → unapproved_configs
      「已记录的配置不能被找到情形的次数」 → 需基线核查工具基准，本次不可算
    """
    r: Dict[str, Any] = {}
    chg = tables.get("change_order") or []
    if chg:
        by_status = Counter(_nz(x.get("CHANGE_STATUS")) or "(空)" for x in chg)
        done = [x for x in chg if _nz(x.get("CHANGE_STATUS")) == "已完成"]
        rolled = [x for x in chg if _nz(x.get("CHANGE_STATUS")) == "已回滚"]
        #—— 审批链完整性 ——
    #★ 口径说明（2026-10-05 实测）：change_order 表里 50000 条变更单
    #   APPROVE_TIME 100% 非空、APPROVER 无空值 → 该表自身合规，
        #   「有执行时间但无审批时间」这条判据在这份数据上恒为 0。
    #   真正的「暗变更」不在变更单表里，而在 ci_lifecycle_log：
    #   人工录入了上线/下线/变更类事件却没挂任何变更单号（下方 lifecycle.dark_manual）。
        # —— 审批链完整性 ——
        # ★ 口径说明（2026-10-05 实测）：change_order 表 50000 条变更单
        #   APPROVE_TIME 100% 非空、APPROVER 无空值 → 该表自身合规，
        #   「有执行时间但无审批时间」这条判据在这份数据上恒为 0。
        #   真正的「暗变更」不在变更单表里，而在 ci_lifecycle_log：
        #   人工录入上线/下线/变更类事件却未挂任何变更单号（lifecycle.dark_manual）。
        #   两个口径都报，读者才知道流程管控究竟漏在哪。
        no_approver = [x for x in chg
                       if _nz(x.get("CHANGE_STATUS")) in ("已完成", "执行中", "已回滚")
                       and not _nz(x.get("APPROVER"))]
        no_approve_time = [x for x in chg
                           if _nz(x.get("CHANGE_STATUS")) in ("已完成", "执行中")
                           and not _nz(x.get("APPROVE_TIME"))]
        dark = [x for x in chg
                if _nz(x.get("REAL_START")) and not _nz(x.get("APPROVE_TIME"))]
        dark = [x for x in chg if _nz(x.get("REAL_START")) and not _nz(x.get("APPROVE_TIME"))]
        # 执行延迟：REAL_START 晚于 PLAN_END（超窗口未审批/未按期）
        delayed = []
        for x in chg:
            ps, pe, rs = (_nz(x.get("PLAN_START")), _nz(x.get("PLAN_END")),
                          _nz(x.get("REAL_START")))
            if pe and rs and rs[:10] > pe[:10]:
                delayed.append(x)
        no_rollback_plan = [x for x in chg
                            if _nz(x.get("RISK_LEVEL")) in ("高", "重大")
                            and not _nz(x.get("IS_ROLLBACK"))
                            and _nz(x.get("CHANGE_TYPE")) == "重大变更"]
        emergency = [x for x in chg if _is_yn(x.get("IS_EMERGENCY"))]
        emergency_no_approve = [x for x in emergency if not _nz(x.get("APPROVE_TIME"))]
        r["order"] = {
            "checked": True,
            "total": len(chg),
            "by_status": dict(by_status.most_common()),
            "by_risk": dict(Counter(_nz(x.get("RISK_LEVEL")) or "(空)" for x in chg)),
            "by_type": dict(Counter(_nz(x.get("CHANGE_TYPE")) or "(空)" for x in chg)),
            "completed": len(done),
            "rolled_back": len(rolled),
            "rollback_pct": _rate(len(rolled), len(chg)),
            "no_approver": len(no_approver),
            "no_approve_time": len(no_approve_time),
            "dark_change": len(dark),
            "dark_change_pct": _rate(len(dark), len(chg)),
            "delayed": len(delayed),
            "emergency": len(emergency),
            "emergency_no_approve": len(emergency_no_approve),
            "major_no_rollback": len(no_rollback_plan),
            "dark_samples": [
                {"no": x.get("CHANGE_NO", ""), "title": x.get("CHANGE_TITLE", ""),
                 "type": x.get("CHANGE_TYPE", ""), "risk": x.get("RISK_LEVEL", ""),
                 "applicant": x.get("APPLICANT", ""), "dept": x.get("DEPT_ID", ""),
                 "real_start": x.get("REAL_START", ""), "status": x.get("CHANGE_STATUS", "")}
                for x in dark[:20]
            ],
        }
    else:
        r["order"] = {"checked": False, "reason": "本次导出不含 change_order"}

    # —— 生命周期事件（发现未经批准的配置 / 记录了但找不到）——
    life = tables.get("ci_lifecycle_log") or []
    if life:
        manual = [x for x in life if _nz(x.get("OPERATOR_SOURCE")) == "人工录入"]
        manual_change = [x for x in manual
                         if "变更" in _nz(x.get("EVENT_TYPE"))
                         or "上线" in _nz(x.get("EVENT_TYPE"))
                         or "下线" in _nz(x.get("EVENT_TYPE"))]
        manual_no_order = [x for x in manual_change
                           if not _nz(x.get("RELATED_ORDER"))]
        r["lifecycle"] = {
            "checked": True,
            "total": len(life),
            "by_event": dict(Counter(_nz(x.get("EVENT_TYPE")) or "(空)"
                                     for x in life).most_common()),
            "by_source": dict(Counter(_nz(x.get("OPERATOR_SOURCE")) or "(空)"
                                      for x in life).most_common()),
            "manual": len(manual),
            "manual_change": len(manual_change),
            "manual_change_no_order": len(manual_no_order),
            "samples": [
                {"ci": x.get("CI_ID", ""), "name": x.get("CI_NAME", ""),
                 "event": x.get("EVENT_TYPE", ""), "operator": x.get("OPERATOR", ""),
                 "time": x.get("EVENT_TIME", ""), "dept": x.get("DEPT_ID", "")}
                for x in manual_no_order[:20]
            ],
        }
    else:
        r["lifecycle"] = {"checked": False, "reason": "本次导出不含 ci_lifecycle_log"}

    # —— 5.x 配置记录与实物一致性 ——
    base = tables.get("config_audit_log") or []
    r["config_not_found"] = {
        "checked": False,
        "reason": "标准要求的「已记录的配置不能被找到」需基线核查工具"
                  "（Ansible/Chef/Puppet）现场复检，本次导出不含核查结果",
        "note": "已记录 %d 条配置审计记录，失败 %d 条（RESULT=失败）可作为部分参考"
                % (len(base), sum(1 for x in base if _nz(x.get("RESULT")) == "失败")),
    }
    return r


# ==========================================================================
# 七、复测计划（把六章发现映射成可复测的判定项）
# ==========================================================================
# —— 复测窗口：按严重度定 SLA（对齐第五章/第三章的严重度语义）——
RETEST_WINDOW: Dict[str, int] = {"CRITICAL": 2, "HIGH": 7, "MEDIUM": 30, "LOW": 90}
RETEST_SLA_DAYS: Dict[str, int] = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}

SEV_CN: Dict[str, str] = {"CRITICAL": "严重", "HIGH": "高危",
                          "MEDIUM": "中危", "LOW": "低危", "INFO": "信息",
                          "UNKNOWN": "未知"}


def retest_plan(severity: str) -> Dict[str, Any]:
    """按严重度给出复测触发条件、时间窗口与通过条件。"""
    sev = (severity or "MEDIUM").upper()
    if sev not in RETEST_WINDOW:
        sev = "MEDIUM"
    return {
        "trigger": "工单状态变更为「已修复」后自动触发复扫（无需人工发起）",
        "window_days": RETEST_WINDOW[sev],
        "sla_days": RETEST_SLA_DAYS[sev],
        "criteria": {
            "CRITICAL": "复扫该 CI 全部端口与组件，确认原漏洞特征消失且无新增高危；"
                        "48 小时内未复测通过则工单自动升级",
            "HIGH": "复扫确认漏洞特征消失，且受影响资产数较基线减少至 0；"
                    "7 天内未复测通过则工单自动升级",
            "MEDIUM": "基线核查工具复检该项配置，RESULT=成功",
            "LOW": "抽样复检，抽检比例不低于 30%，全部通过",
        }[sev],
    }


# ==========================================================================
# 汇总入口
# ==========================================================================
def collect(tables: Dict[str, List[Dict[str, str]]]) -> Dict[str, Any]:
    """从已分类的表字典汇总全部治理指标。"""
    # tables_from_sqlite 会塞一个 __truncated__ 标记（值不是行列表），
    # 万一被直接传进来也不能让它进 collect 的统计口径
    tables = {k: v for k, v in (tables or {}).items()
              if k != "__truncated__" and isinstance(v, list)}
    quality = audit_data_quality(tables)
    return {
        "quality": quality,
        "baseline": audit_baseline(tables),
        "access": audit_access_control(tables),
        "change": audit_change(tables),
        "tables_seen": sorted(t for t in tables if tables[t]),
    }


# ==========================================================================
# 表格 → 表字典（file / sqlite 两种来源）
# ==========================================================================
def tables_from_records(records: List[List[Any]]) -> Dict[str, List[Dict[str, str]]]:
    """从「首行为表头」的二维记录流里切出所有能识别的治理表。"""
    out: Dict[str, List[Dict[str, str]]] = {}
    cur_name = ""
    cur: List[List[Any]] = []
    for rec in records:
        header = _norm_header(rec)
        kind = classify_table(header)
        if kind:
            if cur_name and cur:
                _, rows = _rows_of(cur)
                out.setdefault(cur_name, []).extend(rows)
            cur_name, cur = kind, [rec]
        elif cur_name:
            cur.append(rec)
    if cur_name and cur:
        _, rows = _rows_of(cur)
        out.setdefault(cur_name, []).extend(rows)
    return out


def tables_from_sqlite(path: str, limit_rows: int = 200000) -> Dict[str, List[Dict[str, str]]]:
    """从 SQLite 库读治理表（按主键白名单，不做全表扫）。

    ★ 截断必须留痕（2026-10-06 审查发现）：超过 limit_rows 的表会被静默截断，
      但之前返回值里没有任何标记，报告会把「20 万行样本」当成「全量」呈现——
      实测 25 万行 ip_allocation 只读 20 万，冲突率照样按 20 万算并写进报告，
      管理层看不出这是抽样。截断过的表会在返回结构里带
      `__truncated__ = {kind: (实读行数, 是否触顶)}`，由 collect_governance
      转成 audit["truncated_tables"]，报告第三章显式披露。
    """
    import sqlite3
    out: Dict[str, List[Dict[str, str]]] = {}
    truncated: Dict[str, List[int]] = {}
    if not path or not os.path.isfile(path):
        return out
    try:
        conn = sqlite3.connect(path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            exist = {r[0].lower() for r in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        # ★ 按「首列主键」判定表类型，不按表名硬匹配：实际 SQLite 库里的表名
        #   常带业务前缀（cmdb_physical_server 之类），按名字匹配会一张都读不到。
        #   复用与 CSV 路径同一套 classify_table，保证两种模式口径一致。
            for tname in sorted(exist):
                cols = [r[1] for r in cur.execute(
                    'PRAGMA table_info("%s")' % tname).fetchall()]
                if not cols:
                    continue
                kind = classify_table(cols)
                if not kind:
                    continue
                rows = [{c: _nz(row[c]) for c in cols}
                        for row in cur.execute('SELECT * FROM "%s" LIMIT %d'
                                               % (tname, limit_rows + 1))]
                # 多读 1 行用来判断是否触顶（不额外count，全量 count 在大库上很慢）
                if len(rows) > limit_rows:
                    rows = rows[:limit_rows]
                    truncated[kind] = [limit_rows, 1]
                out.setdefault(kind, []).extend(rows)
        finally:
            # ★ close 放 finally（2026-10-06）：原来它在 try 末尾，中途抛异常
            #   （比如上传的不是 SQLite 文件）就漏句柄 → Windows 上临时 .db
            #   被占用删不掉，用户的库永久残留在 data/tmp_cmdb。Linux 能删，
            #   所以这个 bug 只在 Windows 显形。
            conn.close()
    except Exception:  # noqa: BLE001
        return out
    if truncated:
        out["__truncated__"] = truncated      # type: ignore[assignment]
    return out


# ==========================================================================
# 执行摘要：整体风险评级
# ==========================================================================
def overall_rating(audit: Dict[str, Any], vuln_summary: Dict[str, Any]) -> Dict[str, Any]:
    """按治理 + 漏洞两侧的实测值给一个定性评级，并写清判定依据。

    评级规则（每命中一条升一档，起点「中风险」）：
      - 整体健康度 < 70                → 低
      - 孤儿 CI 率 > 20% 或 IP 冲突率 > 5%  → 低
      - 关键属性缺失率 > 5%             → 低
      - 严重漂移占比 > 5% 或暗变更 > 5% → 低
      - 敏感 API 无鉴权 / 明文凭据 / 弱 TLS 任一 > 0 → 低
      - CRITICAL 漏洞占比 > 10% 或 KEV 命中 → 高
    """
    q = audit.get("quality") or {}
    b = audit.get("baseline") or {}
    ac = audit.get("access") or {}
    ch = audit.get("change") or {}
    reasons: List[str] = []
    hits = 0
    grade = "中风险"

    h = q.get("health") or {}
    if h.get("overall") is not None and h["overall"] < 70 \
            and (q.get("asset_total") or 0) >= MIN_CI_FOR_QUALITY:
        hits += 1
        reasons.append("CMDB 健康度 %.1f 分（< 70）" % h["overall"])
    orph = q.get("orphan_ci") or {}
    if orph.get("checked") and orph.get("sufficient", True) \
            and orph.get("pct", 0) > ORPHAN_WARN_RATIO:
        hits += 1
        reasons.append("孤儿 CI 率 %.1f%%（> 20%%）" % orph["pct"])
    ipq = q.get("ip_quality") or {}
    if ipq.get("checked") and ipq.get("sufficient", True) \
            and ipq.get("conflict_pct", 0) > COVERAGE_DIFF_FAIL:
        hits += 1
        reasons.append("IP 地址冲突率 %.1f%%（> 5%%）" % ipq["conflict_pct"])
    am = q.get("attr_missing") or {}
    if am.get("checked") and am.get("worst_pct", 0) > MISSING_ATTR_FAIL:
        hits += 1
        reasons.append("关键属性「%s」缺失率 %.1f%%（> 5%%）"
                       % (am.get("worst", ""), am["worst_pct"]))
    if b.get("checked") and b.get("drift_pct", 0) > 5:
        hits += 1
        reasons.append("配置漂移率 %.1f%%（> 5%%），其中严重漂移 %d 条"
                       % (b["drift_pct"], b["severe"]))
    co = (ch.get("order") or {})
    lc = (ch.get("lifecycle") or {})
    # 暗变更主口径：人工录入的变更类事件未挂变更单（change_order 表本身合规，
    # 「有执行无审批」恒为 0，用它评级会漏掉真正的流程外操作）
    if lc.get("checked") and lc.get("manual_change_no_order", 0):
        hits += 1
        reasons.append("流程外变更 %d 次（人工录入上线/下线/变更事件但未关联变更单）"
                       % lc["manual_change_no_order"])
    if co.get("checked") and co.get("dark_change_pct", 0) > 5:
        hits += 1
        reasons.append("未经审批即执行的变更单 %d 条（占 %.1f%%）"
                       % (co["dark_change"], co["dark_change_pct"]))
    api = ac.get("api") or {}
    if api.get("checked"):
        if api.get("sensitive_no_auth", 0) or api.get("sensitive_plain_http", 0):
            hits += 1
            reasons.append("敏感 API 无鉴权 %d 条 / 明文 HTTP 传输敏感数据 %d 条"
                           % (api["sensitive_no_auth"], api["sensitive_plain_http"]))
    cred = ac.get("credential") or {}
    if cred.get("checked") and cred.get("plaintext_guess", 0):
        hits += 1
        reasons.append("疑似明文凭据字段 %d 处" % cred["plaintext_guess"])
    cert = ac.get("cert") or {}
    if cert.get("checked") and cert.get("weak_tls", 0):
        hits += 1
        reasons.append("使用 TLS 1.0/1.1 的证书 %d 张" % cert["weak_tls"])
    acct = ac.get("account") or {}
    if acct.get("checked") and acct.get("mfa_disabled_privileged", 0):
        hits += 1
        reasons.append("管理岗未启用 MFA %d 人" % acct["mfa_disabled_privileged"])

    #★ 口径（2026-10-06 审查修正）：原写 crit*100.0/ledger_rows 是把
    #   「漏洞条目（组）数」除以「台账原始行数」——分子分母不同量纲。
    #   实测 20 个 CRITICAL 编号各命中 50 台资产（1000 行）时算出 2.00%，
    #   真实严重占比是 20/20=100%，直接漏掉「CRITICAL 占比 > 10%」的升级条件，
    #   整体评级少升一档。正确分母是cve_hits（去重后的漏洞条目数），
    #   与分子同为「组」；分组聚合见 cmdb_scan._build_ledger_report 的 groups。
    crit = vuln_summary.get("critical") or 0
    tot = vuln_summary.get("cve_hits") or 0
    if tot and crit * 100.0 / tot > 10:
        hits += 1
        reasons.append("严重（CVSS≥9.0）漏洞占比 %.1f%%（%d / %d 条去重漏洞条目）"
                       % (crit * 100.0 / tot, crit, tot))
    #★ 用kev_count（真实总数），不用 len(kev_ids)：kev_ids 在 cmdb_scan侧
    #   为控制报告体积被截断到 20 条，直接取长度会把「命中 53 个」写成
    #   「命中 20 个」——执行摘要里的数字不能是展示配额。
    kev_ids = vuln_summary.get("kev_ids") or []
    kev_count = vuln_summary.get("kev_count")
    if not isinstance(kev_count, int) or kev_count < 0:
        kev_count = len(kev_ids)
    if kev_count:
        hits += 1
        reasons.append("命中 CISA KEV 在野利用漏洞 %d 个%s"
                       % (kev_count,
                          "" if isinstance(vuln_summary.get("kev_count"), int)
                          else "（清单仅列前 %d 个）" % len(kev_ids)))

    if hits >= 5:
        grade = "高风险"
    elif hits >= 2:
        grade = "中高风险"
    elif hits == 1:
        grade = "中风险"
    else:
        grade = "中低风险"
    return {"grade": grade, "hits": hits,
            "reasons": reasons or ["各项实测指标均未触发升级条件"],
            "uncov": uncovered(audit)}


def uncovered(audit: Dict[str, Any]) -> List[str]:
    """列出本次导出无法核查的标准检查项（诚实度：敢说自己没查什么）。"""
    out: List[str] = []
    q = audit.get("quality") or {}
    if not q.get("coverage_diff", {}).get("checked"):
        out.append("自动发现覆盖率差异率（缺主动探测扫描基准）")
    if not q.get("shadow", {}).get("checked"):
        out.append("影子资产清单（缺外部扫描基准）")
    if not q.get("orphan_ci", {}).get("checked"):
        out.append("孤儿 CI 关联度（缺 ci_relation）")
    if not (audit.get("access") or {}).get("rbac", {}).get("checked"):
        out.append("角色与权限模型 / 超级管理员账号数（缺平台角色配置导出）")
    if not (audit.get("access") or {}).get("credential", {}).get("checked"):
        out.append("代码级硬编码密钥（缺 SAST 扫描）")
    if not (audit.get("change") or {}).get("config_not_found", {}).get("checked"):
        out.append("已记录配置在现场找不到的情形（缺基线核查工具复检）")
    if not (audit.get("baseline") or {}).get("checked"):
        out.append("配置基线符合性偏离率（缺 config_audit_log）")
    return out
