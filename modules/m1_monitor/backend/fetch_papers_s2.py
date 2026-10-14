# -*- coding: utf-8 -*-
"""
fetch_papers_s2.py —— Semantic Scholar 论文采集（arXiv替代）
==========================================================
arXiv API 在当前网络下持续 406，改用 Semantic Scholar Graph API。
无 API Key 限流严格，采用慢速请求 + 429 指数退避 + 断点续传。

输出：data/papers_s2.json（结构与 papers 列表对齐）
用法：python fetch_papers_s2.py
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = paths.DATA_DIR
OUT = os.path.join(DATA, "papers_s2.json")

# 安全研究主题（覆盖AI安全各方向）
TOPICS = [
    "prompt injection large language model",
    "LLM jailbreak attack",
    "adversarial machine learning",
    "training data poisoning",
    "model extraction stealing",
    "membership inference attack",
    "RAG retrieval augmented generation security",
    "AI agent security tool use",
    "LLM supply chain vulnerability",
    "machine learning model security defense",
    "AI safety guardrail",
    "data privacy federated learning",
]

FIELDS = "title,abstract,authors,year,externalIds,url,venue,publicationDate"
PER_TOPIC = 40


def load_json(path, default):
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as _sw_e:
            _swallow("modules/m1_monitor/backend/fetch_papers_s2.py:56", _sw_e)
    return default


def save_json(path, obj):
    tmp = path + ".tmp"
    payload = json.dumps(obj, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
    os.replace(tmp, path)


def s2_request(url, max_retries=6):
    """带429指数退避的请求"""
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "AI-SecIntel/1.0 (academic research; student project)",
                "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = min(15 * (attempt + 1), 90)
                print(f"    429 限流，等待{wait}s...", flush=True)
                time.sleep(wait)
                continue
            if e.code in (403, 503):
                time.sleep(20 * (attempt + 1))
                continue
            raise
        except Exception as e:
            print(f"    网络错误: {str(e)[:60]}，重试", flush=True)
            time.sleep(10 * (attempt + 1))
    return None


def to_paper(p):
    """映射到系统paper格式"""
    ext = p.get("externalIds") or {}
    url = p.get("url") or ""
    if ext.get("ArXiv"):
        url = "https://arxiv.org/abs/" + ext["ArXiv"]
    elif ext.get("DOI"):
        url = "https://doi.org/" + ext["DOI"]
    authors = [a.get("name", "") for a in (p.get("authors") or []) if a.get("name")][:6]
    date = p.get("publicationDate") or ""
    year = p.get("year") or (date[:4] if date else "")
    return {
        "title": p.get("title") or "",
        "summary": p.get("abstract") or "",
        "url": url,
        "published": date or (str(year) if year else ""),
        "authors": authors,
        "categories": [p.get("venue")] if p.get("venue") else [],
        "source": "Semantic Scholar",
    }


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/fetch_papers_s2.py:119", _sw_e)
    os.makedirs(DATA, exist_ok=True)
    cache = load_json(OUT, {"done": [], "papers": []})
    done = set(cache["done"])
    papers = cache["papers"]
    seen_titles = {p["title"].lower() for p in papers}

    todo = [t for t in TOPICS if t not in done]
    print(f"Semantic Scholar 论文采集：总{len(TOPICS)}主题，已完成{len(done)}，待采集{len(todo)}")

    for topic in todo:
        url = ("https://api.semanticscholar.org/graph/v1/paper/search?" +
               urllib.parse.urlencode({"query": topic, "limit": PER_TOPIC, "fields": FIELDS}))
        d = s2_request(url)
        added = 0
        if d:
            for p in d.get("data", []):
                if not p.get("title"):
                    continue
                key = p["title"].lower()
                if key in seen_titles:
                    continue
                paper = to_paper(p)
                if paper["summary"]:  # 只要有摘要的
                    papers.append(paper)
                    seen_titles.add(key)
                    added += 1
        done.add(topic)
        save_json(OUT, {"done": list(done), "papers": papers})
        print(f"  '{topic[:40]}' +{added} (总{len(papers)})", flush=True)
        time.sleep(6)   # 主题间隔，降低限流概率

    print(f"完成：共采集 {len(papers)} 篇论文 → {OUT}")


if __name__ == "__main__":
    import io  # noqa
    main()
