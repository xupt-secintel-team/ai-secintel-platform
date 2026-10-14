# -*- coding: utf-8 -*-
"""
papers.py —— 学术论文多源获取（arXiv 主源 + Crossref 备源）
=============================================================
arXiv 对同一 IP 的连发查询会触发 429 限流，因此这里做双源容错：
  · 主源 arXiv    —— 预印本，AI 安全方向覆盖最全
  · 备源 Crossref —— 正式发表文献（会议/期刊），带 venue 信息
两源统一归一化为同一记录结构，供 engine.link_papers 做关联推理。
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

UA = {"User-Agent": "AI-Sec-Intel-Collector/1.0 (academic competition project)"}
NS = {"a": "http://www.w3.org/2005/Atom"}


def _get(url, timeout=25, tries=2, backoff=5):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            if i < tries - 1:
                time.sleep(backoff * (i + 1))
    raise RuntimeError(f"{url} :: {last}")


# --------------------------------------------------------------------------
# arXiv
# --------------------------------------------------------------------------
def fetch_arxiv(query, max_results=60):
    url = ("https://export.arxiv.org/api/query?search_query=" + urllib.parse.quote(query) +
           f"&start=0&max_results={max_results}&sortBy=submittedDate&sortOrder=descending")
    raw = _get(url, timeout=20, tries=1)
    root = ET.fromstring(raw)
    out = []
    for e in root.findall("a:entry", NS):
        title = " ".join((e.findtext("a:title", "", NS) or "").split())
        if not title:
            continue
        out.append({
            "source": "arXiv",
            "title": title,
            "summary": " ".join((e.findtext("a:summary", "", NS) or "").split()),
            "url": e.findtext("a:id", "", NS),
            "published": (e.findtext("a:published", "", NS) or "")[:10],
            "authors": [" ".join((a.findtext("a:name", "", NS) or "").split())
                        for a in e.findall("a:author", NS)][:6],
            "venue": "arXiv preprint",
            "categories": [c.get("term") for c in e.findall("a:category", NS)],
        })
    return out


# --------------------------------------------------------------------------
# Crossref
# --------------------------------------------------------------------------
def fetch_crossref(query, rows=60):
    url = ("https://api.crossref.org/works?query.bibliographic=" + urllib.parse.quote(query) +
           f"&rows={rows}&select=title,abstract,URL,issued,author,container-title,subject"
           "&mailto=ai-sec-intel@example.edu")
    raw = _get(url)
    d = json.loads(raw.decode("utf-8"))
    out = []
    for it in (d.get("message", {}).get("items") or []):
        titles = it.get("title") or []
        if not titles:
            continue
        title = " ".join(titles[0].split())
        if not title:
            continue
        abs_ = (it.get("abstract") or "")
        abs_ = " ".join(abs_.replace("<jats:p>", " ").replace("</jats:p>", " ")
                        .replace("<jats:title>", " ").replace("</jats:title>", " ").split())
        # 去掉残余标签
        while "<" in abs_ and ">" in abs_:
            a, b = abs_.find("<"), abs_.find(">", abs_.find("<"))
            if b <= a:
                break
            abs_ = abs_[:a] + " " + abs_[b + 1:]
        issued = ((it.get("issued") or {}).get("date-parts") or [[None]])[0]
        pub = "-".join(str(x).zfill(2) for x in issued if x) if issued and issued[0] else ""
        venue = (it.get("container-title") or ["Crossref"])[0]
        out.append({
            "source": "Crossref",
            "title": title,
            "summary": abs_,
            "url": it.get("URL", ""),
            "published": pub,
            "authors": [" ".join((a.get("given", "") + " " + a.get("family", "")).split())
                        for a in (it.get("author") or [])][:6],
            "venue": venue,
            "categories": it.get("subject") or [],
        })
    return out


# --------------------------------------------------------------------------
# 统一采集（双源 + 去重）
# --------------------------------------------------------------------------
def collect(queries, arxiv_max=60, crossref_rows=50, verbose=True):
    papers, seen = [], set()
    for i, q in enumerate(queries, 1):
        got = []
        # 主源 arXiv
        try:
            got = fetch_arxiv(q, arxiv_max)
            if verbose:
                print(f"  [{i}/{len(queries)}] arXiv  '{q[:44]}' -> {len(got)}", flush=True)
        except Exception as e:  # noqa: BLE001
            if verbose:
                print(f"  [{i}/{len(queries)}] arXiv  '{q[:44]}' 失败（降级到 Crossref）: {str(e)[:60]}", flush=True)
        # 备源 Crossref
        try:
            c = fetch_crossref(q, crossref_rows)
            if verbose:
                print(f"  [{i}/{len(queries)}] Crossref '{q[:44]}' -> {len(c)}", flush=True)
            got = got + c
        except Exception as e:  # noqa: BLE001
            if verbose:
                print(f"  [{i}/{len(queries)}] Crossref 失败: {str(e)[:60]}", flush=True)

        new = 0
        for p in got:
            key = p["title"].lower()[:180]
            if key and key not in seen:
                seen.add(key)
                papers.append(p)
                new += 1
        if verbose:
            print(f"      累计去重 {len(papers)}（本次新增 {new}）", flush=True)
        time.sleep(2.0)
    return papers
