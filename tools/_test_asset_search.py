# -*- coding: utf-8 -*-
"""
_test_asset_search.py —— 测绘实查测试（离线、可复跑）
=========================================================================
不真连外网：把 asset_search._HTTP_GET_JSON 换成假传输，喂「各平台文档里的
真实响应结构」，验证解析口径；演示模式做确定性与显式标注检查。

覆盖：
  ① platform_status：Key/Email 缺一不可（FOFA）+ 配齐即 True
  ② 无 Key → 演示模式：ok=True、demo=True、确定性（同查询同结果）、显式 demo_note
  ③ FOFA/Shodan/Quake/ZoomEye 假传输解析：total、facet、样本字段映射
  ④ 失败路径：假传输抛错 → ok=False 且不伪装成演示数据；空查询/未知平台报错
  ⑤ search_for_cve：survey 选语法 + 兜底语法

用法： py tools/_test_asset_search.py
"""
from __future__ import annotations

import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import asset_search as SR  # noqa: E402

FAILS = []
OKS = []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


def clear_env():
    for k in ("AISEC_FOFA_KEY", "AISEC_FOFA_EMAIL", "AISEC_SHODAN_KEY",
              "AISEC_QUAKE_KEY", "AISEC_ZOOMEYE_KEY"):
        os.environ.pop(k, None)


def fake_transport(handler):
    """handler(method, url, params, headers, body, timeout) -> (code, obj)"""
    def _h(method, url, **kw):
        return handler(method, url, kw.get("params") or {},
                       kw.get("headers") or {}, kw.get("body"), kw.get("timeout"))
    return _h


# ---------- ① platform_status ----------
print("\n=== ① Key 配置判定 ===")
clear_env()
st = SR.platform_status()
check(all(not st[p]["configured"] for p in st), "未配任何 Key → 全部演示模式")
os.environ["AISEC_FOFA_KEY"] = "fk_test"
st = SR.platform_status()
check(st["fofa"]["configured"] is False, "FOFA 只配 Key 缺 Email → 仍未配置")
os.environ["AISEC_FOFA_EMAIL"] = "a@b.c"
st = SR.platform_status()
check(st["fofa"]["configured"] is True, "FOFA Key+Email 齐全 → 已配置")
os.environ["AISEC_SHODAN_KEY"] = "sk_test"
st = SR.platform_status()
check(st["shodan"]["configured"] is True, "Shodan 只需 Key → 已配置")

# ---------- ② 演示模式 ----------
print("\n=== ② 演示模式 ===")
clear_env()
r1 = SR.search("fofa", 'body="Ollama is running"')
check(r1.get("ok") is True and r1.get("demo") is True and r1.get("mode") == "demo",
      "无 Key → 自动演示模式且 ok=True")
check("AISEC_FOFA_KEY" in (r1.get("demo_note") or ""), "demo_note 指明缺哪个环境变量")
check(bool(r1.get("compliance")), "合规文案随结果返回")
check(isinstance(r1.get("total"), int) and r1["total"] > 0, "演示总量为正整数",
      r1.get("total"))
check(sum(c["count"] for c in r1["countries"]) <= r1["total"], "国家分布之和不超过总量")
check(bool(r1["samples"]) and all("invalid" in s["host"] for s in r1["samples"]),
      "演示样本用 .invalid 域名（不可路由，不会冒充真实资产）")
r2 = SR.search("fofa", 'body="Ollama is running"')
check(r1["total"] == r2["total"] and r1["countries"] == r2["countries"],
      "确定性：同一查询两次结果一致")
r3 = SR.search("fofa", 'body="X-Jenkins"')
check(r3["total"] != r1["total"], "不同查询给出不同演示数据")
bad = SR.search("fofa", "")
check(bad.get("ok") is False, "空查询 → ok=False")
bad2 = SR.search("baidu", "x")
check(bad2.get("ok") is False and "不支持" in (bad2.get("error") or ""), "未知平台 → 明确报错")

# ---------- ③ FOFA 假传输解析 ----------
print("\n=== ③ FOFA 真实响应结构解析 ===")
os.environ["AISEC_FOFA_KEY"] = "fk_test"
os.environ["AISEC_FOFA_EMAIL"] = "a@b.c"


def fofa_handler(method, url, params, headers, body, timeout):
    assert "fofa.info" in url, url
    rows = [
        ["host1.example.com", "198.51.100.10", "443", "United States", "AS1 orgA", "Ollama", "Ollama"],
        ["198.51.100.20", "198.51.100.20", "11434", "China", "AS2 orgB", "Ollama", ""],
        ["host3.example.com", "198.51.100.30", "443", "China", "AS2 orgB", "Ollama", "Ollama WebUI"],
    ]
    return 200, {"error": False, "size": 2341, "results": rows}


SR._HTTP_GET_JSON = fake_transport(fofa_handler)
r = SR.search("fofa", 'body="Ollama is running"', cve="CVE-2024-37032")
SR._HTTP_GET_JSON = None
check(r.get("mode") == "real" and r.get("demo") is False, "配齐 Key → 走真实路径")
check(r.get("total") == 2341, "FOFA total 取自 size 字段", r.get("total"))
cs = {c["value"]: c["count"] for c in r.get("countries") or []}
check(cs.get("China") == 2 and cs.get("United States") == 1, "首页样本本地聚合国家分布", cs)
check((r["samples"][0]["product"] or "") == "Ollama" and r["samples"][0]["port"] == "443",
      "样本字段按 fields 顺序正确映射")
check(r.get("cve") == "CVE-2024-37032" and bool(r.get("compliance")), "CVE/合规随行")

# ---------- ④ Shodan 假传输解析 ----------
print("\n=== ④ Shodan facets + 样本 ===")
os.environ["AISEC_SHODAN_KEY"] = "sk_test"
calls = {"n": 0}


def shodan_handler(method, url, params, headers, body, timeout):
    if "/host/count" in url:
        return 200, {"total": 892, "facets": {
            "country": [{"value": "CN", "count": 487}, {"value": "US", "count": 301}],
            "org": [{"value": "China Telecom", "count": 210}],
            "asn": [{"value": "AS4134", "count": 198}],
            "port": [{"value": "443", "count": 500}]}}
    calls["n"] += 1
    return 200, {"matches": [
        {"ip_str": "198.51.100.10", "port": 443, "hostnames": ["a.example.com"],
         "org": "AS1 orgA", "asn": "AS1", "product": "Ollama",
         "location": {"country_name": "United States"},
         "http": {"title": "Ollama"}},
        {"ip_str": "198.51.100.20", "port": 11434, "hostnames": [],
         "org": "AS2 orgB", "asn": "AS2", "product": "",
         "location": {"country_name": "China"}, "http": {}}]}


SR._HTTP_GET_JSON = fake_transport(shodan_handler)
r = SR.search("shodan", 'vuln:"CVE-2021-44228"', samples=True)
SR._HTTP_GET_JSON = None
check(r.get("mode") == "real" and r.get("total") == 892, "Shodan total 取自 count 接口")
check({c["value"]: c["count"] for c in r["countries"]}.get("CN") == 487,
      "国家分布用官方 facets（CN=487）")
check(r["facets_from"] == "api", "Shodan 标注 facets 来自官方 API")
check(r["samples"][0]["host"] == "a.example.com" and r["samples"][1]["host"] == "198.51.100.20",
      "样本 hostnames 为空时回退 IP")
check(calls["n"] == 1, "样本只追加一次 host/search 请求", calls["n"])

# ---------- ⑤ Quake / ZoomEye 假传输解析 ----------
print("\n=== ⑤ Quake / ZoomEye ===")
os.environ["AISEC_QUAKE_KEY"] = "qk_test"


def quake_handler(method, url, params, headers, body, timeout):
    assert method == "POST" and headers.get("X-QuakeToken") == "qk_test"
    assert body.get("query") == 'app:"Ollama"'
    return 200, {"code": 0, "meta": {"total": 500}, "data": [
        {"ip": "198.51.100.10", "port": 443, "hostname": "a.example.com",
         "location": {"country_en": "United States", "country_code": "US"},
         "service": {"http": {"title": "Ollama"}}},
        {"ip": "198.51.100.20", "port": 11434, "hostname": "",
         "location": {"country_en": "China", "country_code": "CN"},
         "service": {"http": {"title": ""}}}]}


SR._HTTP_GET_JSON = fake_transport(quake_handler)
r = SR.search("quake", 'app:"Ollama"')
SR._HTTP_GET_JSON = None
check(r.get("mode") == "real" and r.get("total") == 500, "Quake total 取自 meta.total")
check({c["value"]: c["count"] for c in r["countries"]}.get("China") == 1, "Quake 国家聚合")

os.environ["AISEC_ZOOMEYE_KEY"] = "zk_test"


def zoomeye_handler(method, url, params, headers, body, timeout):
    assert headers.get("API-KEY") == "zk_test"
    return 200, {"code": 0, "data": {"total": 77, "list": [
        {"ip": "198.51.100.10", "port": 443, "domain": "a.example.com",
         "country": "United States", "org": "orgA", "asn": "AS1", "title": "t1"},
        {"ip": "198.51.100.20", "port": 8080, "domain": "",
         "country": "China", "org": "orgB", "asn": "AS2", "title": "t2"}]}}


SR._HTTP_GET_JSON = fake_transport(zoomeye_handler)
r = SR.search("zoomeye", 'app:"Ollama"')
SR._HTTP_GET_JSON = None
check(r.get("mode") == "real" and r.get("total") == 77, "ZoomEye total 取自 data.total")
check(r["samples"][0]["asn"] == "AS1" and r["samples"][0]["port"] == "443", "ZoomEye 样本映射")

# ---------- ⑥ 失败路径 ----------
print("\n=== ⑥ 失败路径：绝不把错误伪装成数据 ===")
def broken_handler(method, url, params, headers, body, timeout):
    raise ConnectionError("timeout")


SR._HTTP_GET_JSON = fake_transport(broken_handler)
r = SR.search("shodan", 'vuln:"CVE-2021-44228"')
SR._HTTP_GET_JSON = None
check(r.get("ok") is False and "Shodan 查询失败" in (r.get("error") or ""),
      "网络失败 → ok=False + 明确错误")
check(r.get("demo") is None and "demo" not in r, "失败结果不带演示数据")
check("demo=1" in (r.get("hint") or ""), "错误提示里给出演示模式开关")

def notjson_handler(method, url, params, headers, body, timeout):
    class R:
        status_code = 200
        def json(self):
            raise ValueError("not json")
    return R().status_code, (_ for _ in ()).throw(ValueError("not json"))


SR._HTTP_GET_JSON = fake_transport(notjson_handler)
r = SR.search("shodan", 'vuln:"CVE-2021-44228"')
SR._HTTP_GET_JSON = None
# _http_json 内部已包装 ValueError，走 RuntimeError 分支
check(r.get("ok") is False, "非 JSON 响应 → ok=False")

# ---------- ⑦ search_for_cve ----------
print("\n=== ⑦ 按 CVE 自动选语法 ===")


class FakeEngine:
    def detail(self, cid):
        if cid == "CVE-2024-37032":
            return {"id": cid, "title": "Ollama path traversal",
                    "products": ["ollama"], "vendors": []}
        return None


SR._HTTP_GET_JSON = fake_transport(fofa_handler)
r = SR.search_for_cve("CVE-2024-37032", FakeEngine(), "fofa")
SR._HTTP_GET_JSON = None
check(r.get("query") == 'body="Ollama is running"',
      "CVE 实查默认取测绘语法第一条（精确指纹优先）", r.get("query"))
check(bool(r.get("alternatives")), "备选语法随行")
check((r.get("survey") or {}).get("id") == "CVE-2024-37032", "survey 数据随行（前端展示用）")

r = SR.search_for_cve("CVE-2024-99999", FakeEngine(), "fofa", force_demo=True)
check(r.get("query") == 'cve="CVE-2024-99999"',
      "语料无该 CVE 时用平台 CVE 语法兜底", r.get("query"))
check(r.get("demo") is True and r.get("ok") is True, "force_demo → 演示模式")

# ---------- 汇总 ----------
print("\n" + "=" * 56)
print("PASS %d / FAIL %d" % (len(OKS), len(FAILS)))
if FAILS:
    for f in FAILS:
        print("  FAIL:", f)
    sys.exit(1)
print("ASSET SEARCH TEST OK")
