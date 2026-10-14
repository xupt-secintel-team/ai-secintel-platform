# -*- coding: utf-8 -*-
"""
asset_search.py —— 受影响互联网资产「测绘实查」
============================================================
把 asset_locator.py 生成的测绘语法真正发到测绘平台查询，回答：

    「这个 CVE / 这条语法，全网有多少台暴露资产？分布在哪些国家 / ASN / 组织？」

设计要点
--------
1. **合规边界不变**：查询的是测绘平台（FOFA/Shodan/Quake/ZoomEye）已有的公开索引数据，
   不对本系统之外的任何主机发起探测或扫描。合规文案随结果一起返回。
2. **Key 全部走环境变量，代码里不落任何密钥**：
       AISEC_FOFA_KEY    + AISEC_FOFA_EMAIL     —— FOFA REST API
       AISEC_SHODAN_KEY                          —— Shodan REST API
       AISEC_QUAKE_KEY                           —— 360 Quake
       AISEC_ZOOMEYE_KEY                         —— ZoomEye
3. **无 Key 自动进入「演示模式」**：用查询串做种子的确定性演示数据（同一查询每次结果
   一致），``demo=true`` 显式标注，前端打横幅；绝不允许把演示数据伪装成真实结果。
   配好 Key 后自动切换真实查询，链路与展示完全一致。
4. ** Facet 口径**：Shodan 用官方 facets 聚合；FOFA/Quake/ZoomEye 用首页样本本地聚
   合（样本足够大时与全量分布基本一致，误差可接受，不为此多烧一次配额）。

统一入口::

    search(platform, query)                       -> dict   任意语法实查
    search_for_cve(cve_id, engine, platform)      -> dict   按 CVE 自动选语法
    platform_status()                             -> dict   哪些平台配了 Key
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
try:  # 依赖降级：装了 requests 用 requests，没装就用 core/httpcompat 兼容层
    import requests  # noqa: F401
except ImportError:  # pragma: no cover
    import httpcompat as requests  # noqa: F401

try:
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

COMPLIANCE = ("查询的是测绘平台已收录的公开索引数据，不对目标主机发起任何探测/扫描；"
              "命中≠受影响，需核对版本区间与补丁状态后再处置。")

# 各平台 Key 的环境变量名（platform_status 供前端显示「已配置/演示模式」）
ENV_KEYS: Dict[str, Dict[str, str]] = {
    "fofa":    {"key": "AISEC_FOFA_KEY", "extra": "AISEC_FOFA_EMAIL", "label": "FOFA"},
    "shodan":  {"key": "AISEC_SHODAN_KEY", "extra": "", "label": "Shodan"},
    "quake":   {"key": "AISEC_QUAKE_KEY", "extra": "", "label": "Quake(360)"},
    "zoomeye": {"key": "AISEC_ZOOMEYE_KEY", "extra": "", "label": "ZoomEye"},
}

_TIMEOUT = 25
# 测试注入点：单测里替换成假传输，避免真实外呼
_HTTP_GET_JSON = None            # type: Optional[callable]


def _env(*names: str) -> str:
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return ""


def platform_status() -> Dict[str, Dict[str, object]]:
    """前端角标用：每个平台是否已配置 Key。FOFA 需要 Key+Email 同时在。"""
    out = {}
    for pid, meta in ENV_KEYS.items():
        ok = bool(_env(meta["key"]))
        if meta["extra"]:
            ok = ok and bool(_env(meta["extra"]))
        out[pid] = {"label": meta["label"], "configured": ok, "env": meta["key"]}
    return out


# ==========================================================================
# 底层 HTTP（可注入）
# ==========================================================================
def _http_json(method: str, url: str, *, params: Optional[dict] = None,
               headers: Optional[dict] = None, body: Optional[dict] = None,
               timeout: int = _TIMEOUT) -> Tuple[int, Any]:
    """GET/POST 并解析 JSON。返回 (status_code, obj)。非 JSON 抛 ValueError。"""
    if _HTTP_GET_JSON is not None:                       # 单测注入
        return _HTTP_GET_JSON(method, url, params=params,
                              headers=headers, body=body, timeout=timeout)
    if method.upper() == "POST":
        resp = requests.post(url, params=params, headers=headers,
                             json=body, timeout=timeout)
    else:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
    try:
        data = resp.json()
    except Exception as e:  # noqa: BLE001
        raise ValueError("响应不是 JSON（HTTP %s）：%s" % (resp.status_code, str(e)[:120]))
    return resp.status_code, data


# ==========================================================================
# 各平台适配器：入参 query，出参归一化 dict
#   { total, countries, asns, orgs, ports, samples, facets_from }
# ==========================================================================
def _facets_from_rows(rows: List[dict], facets_from: str) -> Dict[str, List[dict]]:
    """本地聚合（FOFA/Quake/ZoomEye 首页样本）。"""
    def _top(key: str, n: int) -> List[dict]:
        c = Counter()
        for r in rows:
            v = str(r.get(key) or "").strip()
            if v:
                c[v] += 1
        return [{"value": k, "count": v} for k, v in c.most_common(n)]
    if facets_from == "local":
        return {"countries": _top("country", 12), "asns": _top("asn", 8),
                "orgs": _top("org", 8), "ports": _top("port", 8)}
    return {"countries": [], "asns": [], "orgs": [], "ports": []}


def _fofa(query: str, samples: bool, limit: int) -> Dict[str, Any]:
    key = _env("AISEC_FOFA_KEY")
    email = _env("AISEC_FOFA_EMAIL")
    if not key or not email:
        raise PermissionError("缺少 AISEC_FOFA_KEY / AISEC_FOFA_EMAIL")
    fields = "host,ip,port,country,as_organization,product,title"
    code, data = _http_json("GET", "https://fofa.info/api/v1/search/all",
                            params={"email": email, "key": key,
                                    "qbase64": base64.b64encode(
                                        query.encode("utf-8")).decode("ascii"),
                                    "fields": fields,
                                    "size": str(limit if samples else 1)})
    if code != 200 or not isinstance(data, dict) or data.get("error"):
        raise RuntimeError("FOFA 返回异常：%s" % str(data)[:160])
    rows: List[dict] = []
    if samples:
        for r in (data.get("results") or [])[:limit]:
            if not isinstance(r, list) or len(r) < 5:
                continue
            rows.append({"host": str(r[0] or ""), "ip": str(r[1] or ""),
                         "port": str(r[2] or ""), "country": str(r[3] or ""),
                         "org": str(r[4] or ""),
                         "product": str(r[5] or "") if len(r) > 5 else "",
                         "title": str(r[6] or "") if len(r) > 6 else ""})
    out = {"total": int(data.get("size") or 0), "samples": rows,
           "facets_from": "local"}
    out.update(_facets_from_rows(rows, "local"))
    return out


def _shodan(query: str, samples: bool, limit: int) -> Dict[str, Any]:
    key = _env("AISEC_SHODAN_KEY")
    if not key:
        raise PermissionError("缺少 AISEC_SHODAN_KEY")
    facets = "country,org,asn,port"
    code, data = _http_json("GET", "https://api.shodan.io/shodan/host/count",
                            params={"key": key, "query": query, "facets": facets})
    if code != 200 or not isinstance(data, dict) or data.get("error"):
        raise RuntimeError("Shodan 返回异常：%s" % str(data)[:160])
    out = {"total": int(data.get("total") or 0), "samples": [],
           "facets_from": "api"}
    fc = data.get("facets") or {}
    out["countries"] = [{"value": str(f.get("value") or ""), "count": int(f.get("count") or 0)}
                        for f in (fc.get("country") or [])[:12]]
    out["orgs"] = [{"value": str(f.get("value") or ""), "count": int(f.get("count") or 0)}
                   for f in (fc.get("org") or [])[:8]]
    out["asns"] = [{"value": str(f.get("value") or ""), "count": int(f.get("count") or 0)}
                   for f in (fc.get("asn") or [])[:8]]
    out["ports"] = [{"value": str(f.get("value") or ""), "count": int(f.get("count") or 0)}
                    for f in (fc.get("port") or [])[:8]]
    if samples:  # 样本需再花 1 个查询积分，按需开启
        code, data = _http_json("GET", "https://api.shodan.io/shodan/host/search",
                                params={"key": key, "query": query,
                                        "minify": "true", "page": "1"})
        if code == 200 and isinstance(data, dict) and not data.get("error"):
            rows = []
            for m in (data.get("matches") or [])[:limit]:
                loc = m.get("location") or {}
                http = m.get("http") or {}
                rows.append({
                    "host": (m.get("hostnames") or [""])[0] if m.get("hostnames") else str(m.get("ip_str") or ""),
                    "ip": str(m.get("ip_str") or ""), "port": str(m.get("port") or ""),
                    "country": str(loc.get("country_name") or ""), "org": str(m.get("org") or ""),
                    "asn": str(m.get("asn") or ""), "product": str(m.get("product") or ""),
                    "title": str((http.get("title") if isinstance(http, dict) else "") or ""),
                })
            out["samples"] = rows
    return out


def _quake(query: str, samples: bool, limit: int) -> Dict[str, Any]:
    token = _env("AISEC_QUAKE_KEY")
    if not token:
        raise PermissionError("缺少 AISEC_QUAKE_KEY")
    code, data = _http_json("POST", "https://quake.360.net/api/v3/search/quake_service",
                            headers={"X-QuakeToken": token,
                                     "Content-Type": "application/json"},
                            body={"query": query, "start": 0, "size": limit,
                                  "ignore_cache": False, "latest": True, "short": False})
    if code != 200 or not isinstance(data, dict) or data.get("code") not in (0, "0"):
        raise RuntimeError("Quake 返回异常：%s" % str(data)[:160])
    meta = data.get("meta") or {}
    rows: List[dict] = []
    if samples:
        for m in (data.get("data") or [])[:limit]:
            if not isinstance(m, dict):
                continue
            loc = m.get("location") or {}
            svc = m.get("service") or {}
            http = svc.get("http") if isinstance(svc, dict) else {}
            rows.append({"host": str(m.get("hostname") or ""), "ip": str(m.get("ip") or ""),
                         "port": str(m.get("port") or ""),
                         "country": str(loc.get("country_en") or loc.get("country_code") or ""),
                         "org": str(m.get("org") or ""), "asn": str(loc.get("asn") or ""),
                         "title": str((http.get("title") if isinstance(http, dict) else "") or "")})
    out = {"total": int(meta.get("total") or 0), "samples": rows, "facets_from": "local"}
    out.update(_facets_from_rows(rows, "local"))
    return out


def _zoomeye(query: str, samples: bool, limit: int) -> Dict[str, Any]:
    key = _env("AISEC_ZOOMEYE_KEY")
    if not key:
        raise PermissionError("缺少 AISEC_ZOOMEYE_KEY")
    code, data = _http_json("GET", "https://api.zoomeye.hk/host/search",
                            params={"query": query, "page": "1"},
                            headers={"API-KEY": key})
    if code != 200 or not isinstance(data, dict) or data.get("code") not in (0, "0"):
        raise RuntimeError("ZoomEye 返回异常：%s" % str(data)[:160])
    d = data.get("data") or {}
    rows: List[dict] = []
    if samples:
        for m in (d.get("list") or [])[:limit]:
            if not isinstance(m, dict):
                continue
            rows.append({"host": str(m.get("domain") or ""), "ip": str(m.get("ip") or ""),
                         "port": str(m.get("port") or ""), "country": str(m.get("country") or ""),
                         "org": str(m.get("org") or ""), "asn": str(m.get("asn") or ""),
                         "title": str(m.get("title") or "")})
    out = {"total": int(d.get("total") or 0), "samples": rows, "facets_from": "local"}
    out.update(_facets_from_rows(rows, "local"))
    return out


_ADAPTERS = {"fofa": _fofa, "shodan": _shodan, "quake": _quake, "zoomeye": _zoomeye}


# ==========================================================================
# 演示模式：查询串做种子的确定性数据（同查询同结果，显式标注）
# ==========================================================================
_DEMO_COUNTRIES = ["CN", "US", "DE", "JP", "SG", "HK", "FR", "GB", "IN", "KR",
                   "NL", "BR", "CA", "RU", "AU"]


def _demo(platform: str, query: str) -> Dict[str, Any]:
    seed = int.from_bytes(hashlib.md5(("%s|%s" % (platform, query)).encode()).digest()[:8],
                          "big")
    rnd = random.Random(seed)
    total = 260 + seed % 9800
    weights = [rnd.uniform(0.6, 1.0), rnd.uniform(0.4, 0.8)] + \
              [rnd.uniform(0.02, 0.3) for _ in range(len(_DEMO_COUNTRIES) - 2)]
    s = sum(weights)
    countries, acc = [], total
    for i, c in enumerate(_DEMO_COUNTRIES):
        n = int(total * weights[i] / s)
        if n <= 0:
            continue
        countries.append({"value": c, "count": min(n, acc)})
        acc -= n
        if acc <= 0:
            break
    countries.sort(key=lambda x: -x["count"])
    slug = re.sub(r"[^a-z0-9]+", "-", query.lower()).strip("-")[:24] or "demo"
    samples = [{"host": "demo-%d.%s.invalid" % (i + 1, slug), "ip": "203.0.113.%d" % ((seed + i) % 250 + 1),
                "port": str(rnd.choice([80, 443, 8080, 8443, 11434, 9200])),
                "country": countries[i % max(len(countries), 1)]["value"],
                "org": "演示网络 AS%d" % (40000 + (seed + i) % 9000),
                "asn": "AS%d" % (40000 + (seed + i) % 9000),
                "product": "", "title": "（演示样本，配置 Key 后显示真实资产）"}
               for i in range(8)]
    return {"total": total, "countries": countries[:12],
            "asns": [{"value": "AS%d" % (40000 + seed % 9000), "count": max(total // 3, 1)},
                     {"value": "AS%d" % (41000 + seed % 9000), "count": max(total // 7, 1)}],
            "orgs": [{"value": "演示运营商 A", "count": max(total // 4, 1)},
                     {"value": "演示运营商 B", "count": max(total // 9, 1)}],
            "ports": [{"value": str(p), "count": c}
                      for p, c in [("443", int(total * 0.42)),
                                   ("80", int(total * 0.28)),
                                   ("8080", int(total * 0.14)),
                                   ("8443", int(total * 0.09))]],
            "samples": samples, "facets_from": "demo"}


# ==========================================================================
# 统一入口
# ==========================================================================
def search(platform: str, query: str, *, cve: str = "", samples: bool = True,
           limit: int = 100, force_demo: bool = False) -> Dict[str, Any]:
    """实查任意测绘语法。无 Key / 用户显式要求 / 平台请求失败时降级演示模式。"""
    platform = (platform or "").strip().lower()
    query = (query or "").strip()
    if platform not in _ADAPTERS:
        return {"ok": False, "error": "不支持的平台：%s（可选 fofa/shodan/quake/zoomeye）"
                                      % platform}
    if not query:
        return {"ok": False, "error": "查询语法为空"}

    demo_forced = force_demo or platform_status().get(platform, {}).get("configured") is not True
    if not demo_forced:
        try:
            t0 = time.time()
            r = _ADAPTERS[platform](query, samples, limit)
            return {"ok": True, "mode": "real", "platform": platform, "query": query,
                    "cve": cve, "demo": False, "took_ms": int((time.time() - t0) * 1000),
                    "queried_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "compliance": COMPLIANCE, **r}
        except PermissionError as e:                       # 没配 Key
            demo_reason = str(e)
        except Exception as e:  # noqa: BLE001 —— 网络/配额/语法错误：明确报错，不静默伪装
            _swallow("modules/m2_enrich/backend/asset_search.py:search", e)
            return {"ok": False, "platform": platform, "query": query, "cve": cve,
                    "error": "%s 查询失败：%s" % (ENV_KEYS[platform]["label"], str(e)[:200]),
                    "hint": "可加 demo=1 查看演示模式效果，或检查 Key / 配额 / 语法"}
    else:
        demo_reason = "未配置 %s" % ENV_KEYS[platform]["key"]

    t0 = time.time()
    d = _demo(platform, query)
    return {"ok": True, "mode": "demo", "platform": platform, "query": query,
            "cve": cve, "demo": True, "demo_note": "演示数据（%s）—— 同一查询每次结果一致，"
            "仅用于展示链路与界面；配置 %s 后自动切换真实查询。"
            % (demo_reason, ENV_KEYS[platform]["key"]),
            "took_ms": int((time.time() - t0) * 1000),
            "queried_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "compliance": COMPLIANCE, **d}


def _best_query_for_platform(platform: str, survey: dict) -> Tuple[str, List[dict]]:
    """从 asset_locator.survey 里为平台挑一条主查询 + 备选列表。"""
    items = [q for q in (survey.get(platform) or []) if q.get("kind") != "note"]
    if not items:
        for alt in ("shodan", "fofa", "quake", "zoomeye"):
            items = [q for q in (survey.get(alt) or []) if q.get("kind") != "note"]
            if items:
                break
    if not items:
        prods = (survey.get("generated_from") or {}).get("products") or []
        if prods:
            items = [{"q": 'body="%s"' % prods[0], "why": "产品名兜底", "product": prods[0]}]
    main = items[0].get("q", "") if items else ""
    return main, items[:8]


def search_for_cve(cve_id: str, engine, platform: str = "fofa", *,
                   samples: bool = True, limit: int = 100,
                   q: str = "", force_demo: bool = False) -> Dict[str, Any]:
    """按 CVE 实查：默认取 asset_locator 生成语法里的第一条（精确指纹优先）。

    :param q: 用户在界面上选中的某条语法；给了就优先用用户的。
    """
    cve_id = (cve_id or "").strip().upper()
    survey = {}
    if cve_id:
        try:
            import asset_locator as AL  # noqa: E402
            d = engine.detail(cve_id) if engine is not None else None
            survey = AL.survey(cve_id, item=d, assets=None)
        except Exception as e:  # noqa: BLE001
            _swallow("modules/m2_enrich/backend/asset_search.py:search_for_cve", e)
            survey = {}
    query = (q or "").strip() or _best_query_for_platform(platform, survey)[0]
    if not query and cve_id:
        query = 'vuln:"%s"' % cve_id if platform == "shodan" else 'cve="%s"' % cve_id
    out = search(platform, query, cve=cve_id, samples=samples,
                 limit=limit, force_demo=force_demo)
    out["survey"] = survey
    out["alternatives"] = _best_query_for_platform(platform, survey)[1]
    return out
