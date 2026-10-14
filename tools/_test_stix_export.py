# -*- coding: utf-8 -*-
"""stix_export 离线回归（假语料，不依赖引擎）。运行：python tools/_test_stix_export.py"""
import io
import os
import re
import sys
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "m2_enrich", "backend"))

import stix_export as SX  # noqa: E402

N = [0]


def check(cond, msg):
    N[0] += 1
    if not cond:
        raise AssertionError("FAIL #%d: %s" % (N[0], msg))


NOW = time.time()          # 必须用真实时钟：_filter_docs 的 days 是和 time.time() 比的


def _iso(ep):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime(ep))


def doc(i, sev="HIGH", score=7.5, kev=False, ai=0.9, ts=None, prod="nginx",
        cpe=None, patches=None, cwe="CWE-79"):
    ts = ts if ts is not None else NOW - i * 3600
    return {
        "id": "CVE-2026-%05d" % i,
        "title": "组件 %d 远程代码执行" % i,
        "desc": "攻击者可利用该漏洞在目标系统执行任意代码。",
        "cvss": {"score": score, "severity": sev, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
        "kev": {"exploited": True, "date_added": "2026-09-01", "due_date": "2026-09-22"} if kev else {"exploited": False},
        "ai_score": ai,
        "published": _iso(ts - 86400),
        "modified": _iso(ts),
        "products": [prod], "vendors": ["v%d" % i],
        "cpe": cpe if cpe is not None else [],
        "patch_links": patches or [],
        "cwe": cwe, "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-%05d" % i,
    }


CORPUS = [
    doc(1, sev="CRITICAL", score=9.8, kev=True, ts=NOW - 100),
    doc(2, sev="HIGH", score=8.1, ts=NOW - 3 * 86400),
    doc(3, sev="LOW", score=3.1, ts=NOW - 40 * 86400),
    doc(4, sev="MEDIUM", score=5.5, kev=True, ts=NOW - 10 * 86400),
    doc(5, sev="CRITICAL", score=10.0, ts=NOW - 2 * 86400,
        cpe=[{"vendor": "nginx", "product": "nginx", "version": "1.20.0"}],
        patches=["https://nginx.org/security/advisories"], cwe="CWE-22"),
]

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

# ---------- 1. SDO 结构 ----------
b = SX.bundle(CORPUS)
check(b["type"] == "bundle" and b["id"].startswith("bundle--"), "Bundle 类型与 ID 前缀")
check(UUID_RE.match(b["id"].split("--", 1)[1]) is not None, "Bundle UUIDv5 格式")
objs = b["objects"]
check(len(objs) == 5, "默认 min_sev=LOW 为最低门槛（5 条全保留）")
o = objs[0]
check(o["type"] == "vulnerability" and o["spec_version"] == "2.1", "SDO type/spec_version")
check(UUID_RE.match(o["id"].split("--", 1)[1]) is not None, "SDO UUIDv5 格式")
for k in ("created", "modified", "name", "description", "external_references", "labels"):
    check(k in o, "SDO 必备字段 %s" % k)
check(o["name"].startswith("CVE-"), "name 为 CVE 号")
check(o["external_references"][0]["external_id"] == o["name"], "external_references 指向 CVE")
check(o["modified"].endswith("Z") and "T" in o["modified"], "STIX 时间戳 UTC Z 结尾")

# ---------- 2. 确定性 ----------
b2 = SX.bundle(CORPUS)
check(b["id"] == b2["id"], "同语料两次导出 Bundle ID 一致")
ids1 = {x["id"] for x in b["objects"]}
ids2 = {x["id"] for x in b2["objects"]}
check(ids1 == ids2, "SDO ID 确定性（uuid5）")

# ---------- 3. 自定义字段 ----------
c5 = [x for x in objs if x["name"] == "CVE-2026-00005"][0]
check(c5.get("x_cvss_score") == 10.0, "x_cvss_score")
check(c5.get("x_cvss_severity") == "CRITICAL", "x_cvss_severity")
check("x_cvss_vector" in c5, "x_cvss_vector")
check(isinstance(c5.get("x_cpe_ranges"), list) and c5["x_cpe_ranges"][0]["version"] == "1.20.0",
      "x_cpe_ranges 序列化")
check(c5.get("x_cwe") == "CWE-22", "x_cwe")
check("x_patch_links" in c5, "x_patch_links")
check(c5.get("x_products") == ["nginx"], "x_products")
k1 = [x for x in objs if x["name"] == "CVE-2026-00001"][0]
check("kev" in k1["labels"] and k1.get("x_kev", {}).get("date_added") == "2026-09-01", "KEV 标签与 x_kev")
check(k1["confidence"] == 90, "confidence 由 ai_score 换算")

# ---------- 4. 过滤器 ----------
bx = SX.bundle(CORPUS, min_sev="CRITICAL")
check({x["name"] for x in bx["objects"]} == {"CVE-2026-00001", "CVE-2026-00005"}, "min_sev=CRITICAL")
bk = SX.bundle(CORPUS, kev_only=True)
check({x["name"] for x in bk["objects"]} == {"CVE-2026-00001", "CVE-2026-00004"}, "kev_only")
bd = SX.bundle(CORPUS, days=7)
check({x["name"] for x in bd["objects"]} == {"CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00005"},
      "days=7 时间过滤")
bi = SX.bundle(CORPUS, ids=["cve-2026-00003"])
check(len(bi["objects"]) == 1 and bi["objects"][0]["name"] == "CVE-2026-00003", "ids 过滤（大小写不敏感）")

# ---------- 5. TAXII ----------
disc = SX.taxii_discovery()
check("api_roots" in disc and disc["default"].endswith("/taxii2/root/"), "discovery 结构")
root = SX.taxii_root()
check(root["id"] == "aisec-d-root" and root["api_roots"] == ["/taxii2/root/"], "api-root 结构")
cols = SX._collections_payload()
check({c["id"] for c in cols["collections"]} == {"all", "kev", "critical"}, "三个集合")
check(all(c["can_read"] and not c["can_write"] for c in cols["collections"]), "集合只读")
check(SX.taxii_collection("nope") is None, "未知集合返回 None")

env = SX.taxii_objects("all", CORPUS)
check(env["more"] is False and len(env["objects"]) == 5, "envelope all")
envk = SX.taxii_objects("kev", CORPUS)
check({x["name"] for x in envk["objects"]} == {"CVE-2026-00001", "CVE-2026-00004"}, "kev 集合过滤")
envc = SX.taxii_objects("critical", CORPUS)
check({x["name"] for x in envc["objects"]} == {"CVE-2026-00001", "CVE-2026-00005"}, "critical 集合过滤")
envm = SX.taxii_objects("all", CORPUS, match_id="CVE-2026-00002")
check(len(envm["objects"]) == 1 and envm["objects"][0]["name"] == "CVE-2026-00002", "match_id 过滤")
enva = SX.taxii_objects("all", CORPUS, added_after=_iso(NOW - 5 * 86400))
check({x["name"] for x in enva["objects"]} == {"CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00005"},
      "added_after 增量拉取")
check(SX.taxii_objects("bogus", CORPUS) is None, "非法集合 objects 返回 None")

# ---------- 6. 鉴权 ----------
os.environ.pop("AISEC_TAXII_KEY", None)
check(SX.check_taxii_auth("") is True, "未配 Key 放行")
os.environ["AISEC_TAXII_KEY"] = "sekrit"
check(SX.check_taxii_auth("") is False, "配 Key 后无凭证拒绝")
check(SX.check_taxii_auth("Bearer sekrit") is True, "Bearer 头通过")
check(SX.check_taxii_auth("", query_key="sekrit") is True, "?key= 通过")
check(SX.check_taxii_auth("Bearer wrong") is False, "错 Key 拒绝")
del os.environ["AISEC_TAXII_KEY"]

# ---------- 7. 脏数据健壮性 ----------
dirty = [None, {}, {"id": "NOT-CVE"}, {"id": "CVE-2026-99999", "title": "只有 id"}]
bd3 = SX.bundle(dirty)
check(len(bd3["objects"]) == 1, "脏数据：仅合法 CVE 入 Bundle")
o9 = bd3["objects"][0]
check(o9["x_cvss_severity"] == "UNKNOWN", "缺 cvss → UNKNOWN")
check(UUID_RE.match(o9["id"].split("--", 1)[1]) is not None, "缺时间的裸条目也能出 ID")

md = SX.export_markdown(b)
check("STIX 2.1 导出摘要" in md and "CVE-2026-00001" in md, "Markdown 摘要")

print("STIX EXPORT TEST OK (%d checks)" % N[0])
