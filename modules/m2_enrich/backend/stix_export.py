r"""STIX 2.1 / TAXII 2.1 标准导出 —— 成员B · m2_enrich 情报富化

把模块 1 语料里的漏洞条目序列化成 STIX 2.1 标准 SDO，可直接导入
Splunk / QRadar / OpenCTI / MISP 等企业 SIEM / TIP 平台；同时提供
最小可用 TAXII 2.1 服务端（discovery / api-root / collections / objects），
SIEM 侧可用任意 TAXII 客户端（如 taxii2-client、OpenCTI connector）订阅拉取。

设计约束（与本项目模块自治约定一致）：
- 只读 engine.docs（模块 1 语料），不写回、不改主体；
- 确定性 ID：STIX ID 用 uuid5（固定 namespace）从 CVE 号派生，同一条目
  两次导出 ID 一致 —— SIEM 侧的去重/合并/时间线依赖这个性质；
- 离线安全：不外发任何数据；TAXII 只在本机端口上被动应答；
- 自定义字段全部用 x_ 前缀（STIX 2.1 对自定义属性的规范要求），
  避免被严格的消费方拒收。

对外接口（api.py 薄封装后暴露）：
    GET  /api/stix?sev=&kev=1&days=&ids=&limit=      导出 STIX Bundle 文件
    GET  /taxii2/                                    TAXII discovery
    GET  /taxii2/root/                               api-root
    GET  /taxii2/root/collections/                   集合清单
    GET  /taxii2/root/collections/<cid>/objects/     拉取对象（envelope）

TAXII 鉴权（可选）：设置环境变量 AISEC_TAXII_KEY 后，请求必须带
`Authorization: Bearer <key>` 头或 `?key=` 参数，否则返回 TAXII 标准的
401 error envelope。
"""

import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------- 基础工具

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# 固定 namespace：同一 CVE 在任何部署里都生成同一个 UUID（可复现导出）
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://aisec-d.local/stix2.1/cve")

STIX_CT = "application/stix+json;version=2.1"
TAXII_CT = "application/taxii+json;version=2.1"

API_ROOT_PATH = "/taxii2/root/"

# TAXII 集合定义：id -> (标题, 描述, 过滤函数名)。过滤在 _filter_docs 里落地。
COLLECTIONS: Dict[str, Dict[str, str]] = {
    "all": {
        "title": "aisec-D 全量漏洞情报",
        "description": "语料库全部漏洞条目（按 modified 降序，默认前 2000 条）",
    },
    "kev": {
        "title": "CISA KEV 在野利用",
        "description": "被 CISA KEV 目录收录（已确认在野利用）的漏洞",
    },
    "critical": {
        "title": "CRITICAL 严重漏洞",
        "description": "CVSS 严重级别为 CRITICAL 的漏洞",
    },
}


def _nz(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _sev_of(doc: dict) -> str:
    s = _nz((doc.get("cvss") or {}).get("severity")
            if isinstance(doc.get("cvss"), dict) else doc.get("severity"))
    return s.upper() if s.upper() in _SEV_ORDER else "UNKNOWN"


def _score_of(doc: dict) -> Optional[float]:
    cv = doc.get("cvss")
    if isinstance(cv, dict) and isinstance(cv.get("score"), (int, float)):
        return float(cv["score"])
    if isinstance(cv, (int, float)):
        return float(cv)
    return None


def _parse_ts(v: Any) -> Optional[float]:
    """ISO 字符串 -> epoch 秒。语料时间是 UTC 的 'YYYY-MM-DDTHH:MM:SS(.fff)'。"""
    s = _nz(v)
    if not s:
        return None
    try:
        return time.mktime(time.strptime(s[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")) - time.timezone
    except ValueError:
        return None


def _iso_stix(v: Any, fallback: Optional[float] = None) -> str:
    """STIX 时间戳：UTC，毫秒精度，Z 结尾。"""
    ep = _parse_ts(v)
    if ep is None:
        ep = fallback if fallback is not None else time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ep))


# ---------------------------------------------------------------- SDO 构造

def stix_id_of(cve: str) -> str:
    """vulnerability--<uuid5>，确定性。"""
    return "vulnerability--" + str(uuid.uuid5(_NS, _nz(cve)))


def vulnerability_sdo(doc: dict) -> dict:
    """语料条目 -> STIX 2.1 vulnerability SDO。"""
    cve = _nz(doc.get("id"))
    now = time.time()
    created = _iso_stix(doc.get("published"), fallback=now)
    modified = _iso_stix(doc.get("modified"), fallback=now)
    score = _score_of(doc)
    sev = _sev_of(doc)
    kev = doc.get("kev") if isinstance(doc.get("kev"), dict) else {}
    exploited = bool(kev.get("exploited")) or bool(doc.get("exploited"))

    refs = [{"source_name": "cve",
             "external_id": cve,
             "url": "https://nvd.nist.gov/vuln/detail/%s" % cve}]
    link = _nz(doc.get("link"))
    if link and link != refs[0]["url"]:
        refs.append({"source_name": "aisec-d", "url": link})

    labels = [sev.lower()]
    if exploited:
        labels.append("kev")

    sdo: Dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id_of(cve),
        "created": created,
        "modified": modified,
        "name": cve,
        "description": (_nz(doc.get("title")) + ("\n\n" + _nz(doc.get("desc"))
                                                if _nz(doc.get("desc")) else "")).strip() or cve,
        "external_references": refs,
        "labels": labels,
        "confidence": int(round(min(max(float(doc.get("ai_score") or 0.5), 0.0), 1.0) * 100)),
    }
    # ---- 自定义属性（x_ 前缀，STIX 2.1 规范允许） ----
    if score is not None:
        sdo["x_cvss_score"] = round(score, 1)
    sdo["x_cvss_severity"] = sev
    vec = _nz((doc.get("cvss") or {}).get("vector")) if isinstance(doc.get("cvss"), dict) else ""
    if vec:
        sdo["x_cvss_vector"] = vec
    cpe = doc.get("cpe") or []
    if isinstance(cpe, list) and cpe:
        sdo["x_cpe_ranges"] = [
            {k: e.get(k) for k in ("vendor", "product", "version",
                                   "start_incl", "start_excl", "end_incl", "end_excl")
             if e.get(k) not in (None, "")}
            for e in cpe if isinstance(e, dict)
        ][:20]
    prods = doc.get("products") or []
    if prods:
        sdo["x_products"] = [ _nz(p) for p in prods[:16] ]
        vendors = doc.get("vendors") or []
        if vendors:
            sdo["x_vendors"] = [ _nz(v) for v in vendors[:8] ]
    if exploited:
        sdo["x_kev"] = {k: kev.get(k) for k in ("date_added", "due_date", "known_ransomware")
                        if kev.get(k)}
    patches = doc.get("patch_links") or []
    if patches:
        sdo["x_patch_links"] = [ _nz(p) for p in patches[:8] ]
    cwe = _nz(doc.get("cwe"))
    if cwe:
        sdo["x_cwe"] = cwe
    return sdo


def _filter_docs(docs: List[dict], min_sev: str = "LOW", kev_only: bool = False,
                 days: Optional[float] = None, ids: Optional[List[str]] = None,
                 limit: int = 2000) -> List[dict]:
    floor = _SEV_ORDER.get((min_sev or "LOW").upper(), 1)
    id_set = {x.strip().upper() for x in (ids or []) if _nz(x)}
    now = time.time()
    out = []
    for d in docs:
        if not isinstance(d, dict) or not _nz(d.get("id")).startswith("CVE-"):
            continue
        order = _SEV_ORDER.get(_sev_of(d), 0)
        # UNKNOWN（无 CVSS）不算"低于门槛"：默认全量导出时带上，显式 HIGH+ 时仍排除
        if order < floor and not (order == 0 and floor <= 1):
            continue
        if kev_only:
            kev = d.get("kev") if isinstance(d.get("kev"), dict) else {}
            if not (kev.get("exploited") or d.get("exploited")):
                continue
        if id_set and _nz(d.get("id")).upper() not in id_set:
            continue
        if days is not None:
            ts = _parse_ts(d.get("modified")) or _parse_ts(d.get("published")) or 0
            if ts < now - days * 86400:
                continue
        out.append(d)
    out.sort(key=lambda d: _parse_ts(d.get("modified")) or _parse_ts(d.get("published")) or 0,
             reverse=True)
    return out[: max(1, min(int(limit or 2000), 5000))]


def bundle(docs: List[dict], **kw) -> dict:
    """STIX 2.1 Bundle（含过滤）。"""
    sel = _filter_docs(docs, **kw)
    objs = [vulnerability_sdo(d) for d in sel]
    bid = "bundle--" + str(uuid.uuid5(_NS, "bundle:" + hashlib.sha256(
        json.dumps([o["id"] + o["modified"] for o in objs]).encode()).hexdigest()))
    return {"type": "bundle", "id": bid, "objects": objs}


# ---------------------------------------------------------------- TAXII 2.1

def taxii_error(status: int, title: str, desc: str) -> dict:
    return {"title": title, "http_status": str(status), "description": desc}


def _collections_payload() -> dict:
    return {"collections": [
        {"id": cid, "title": m["title"], "description": m["description"],
         "can_read": True, "can_write": False, "media_types": [STIX_CT]}
        for cid, m in COLLECTIONS.items()
    ]}


def taxii_discovery(scheme: str = "http", host: str = "127.0.0.1:8848") -> dict:
    return {
        "title": "aisec-D TAXII 2.1 Server",
        "description": "aisec-D 情报富化模块 · STIX 2.1 订阅服务（只读）",
        "default": "%s://%s%s" % (scheme, host, API_ROOT_PATH),
        "api_roots": ["%s://%s%s" % (scheme, host, API_ROOT_PATH)],
        "contact": "aisec-d@local",
    }


def taxii_root() -> dict:
    return {
        "id": "aisec-d-root",
        "title": "aisec-D 情报根",
        "description": "模块 1 语料的 STIX 2.1 视图",
        "default": API_ROOT_PATH,
        "api_roots": [API_ROOT_PATH],
        "max_content_length": 64 * 1024 * 1024,
    }


def taxii_collection(cid: str) -> Optional[dict]:
    m = COLLECTIONS.get(cid)
    if not m:
        return None
    return {"id": cid, "title": m["title"], "description": m["description"],
            "can_read": True, "can_write": False, "media_types": [STIX_CT]}


def taxii_objects(cid: str, docs: List[dict], match_id: str = "",
                  added_after: str = "", limit: int = 2000) -> Optional[dict]:
    """envelope：{more, objects:[...]}。cid 不合法返回 None。"""
    if cid not in COLLECTIONS:
        return None
    kw: Dict[str, Any] = {"limit": limit}
    if cid == "kev":
        kw["kev_only"] = True
    if cid == "critical":
        kw["min_sev"] = "CRITICAL"
    mid = _nz(match_id).upper()
    if mid:
        kw["ids"] = [mid]
    after = _parse_ts(added_after)
    if after is not None:
        sel = _filter_docs(docs, **kw)
        sel = [d for d in sel if (_parse_ts(d.get("modified"))
                                  or _parse_ts(d.get("published")) or 0) > after]
    else:
        sel = _filter_docs(docs, **kw)
    return {"more": False, "objects": [vulnerability_sdo(d) for d in sel]}


def check_taxii_auth(header_auth: str, query_key: str = "") -> bool:
    """AISEC_TAXII_KEY 未配置 → 放行；配置了 → 校验 Bearer 头或 ?key=。"""
    key = _nz(os.environ.get("AISEC_TAXII_KEY"))
    if not key:
        return True
    if query_key == key:
        return True
    h = _nz(header_auth)
    return h == "Bearer %s" % key or h == "Key %s" % key


def export_markdown(b: dict) -> str:
    """Bundle 摘要（给人看的附页，不参与 TAXII）。"""
    objs = b.get("objects") or []
    lines = ["# STIX 2.1 导出摘要", "",
             "- Bundle ID：`%s`" % b.get("id"),
             "- 对象数：%d（vulnerability SDO）" % len(objs),
             "- 生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"), "",
             "| CVE | 严重度 | CVSS | KEV | 标题 |", "|---|---|---|---|---|"]
    for o in objs[:80]:
        lines.append("| %s | %s | %s | %s | %s |" % (
            o["name"], o.get("x_cvss_severity", "-"), o.get("x_cvss_score", "-"),
            "✅" if "kev" in o.get("labels", []) else "",
            _nz(o.get("description", ""))[:60].replace("|", "\\|")))
    if len(objs) > 80:
        lines.append("\n（其余 %d 条见 Bundle 文件）" % (len(objs) - 80))
    return "\n".join(lines)
