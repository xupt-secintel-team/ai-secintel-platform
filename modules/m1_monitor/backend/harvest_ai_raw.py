# -*- coding: utf-8 -*-
"""
harvest_ai_raw.py —— AI 安全多源原始数据归档（只收 AI 安全，目标 ≥10GB）
=========================================================================
对 CVE/NVD、安全社区、厂商公告、安全博客等主流渠道的 AI 安全信息做自动化采集，
原始产物（PDF / HTML / 全文 JSONL）落到独立数据仓库，供检索语料抽取与追溯。

数据仓库：环境变量 AI_RAW_DIR，默认 <项目根>/data/ai_sec_raw
  arxiv/     AI 安全论文（元数据 JSONL + PDF 全文）
  blogs/     厂商公告 / 安全博客（RSS + 文章正文）
  nvd/       NVD 中 AI 相关 CVE 的完整记录
  ghsa/      GHSA/OSV 中 AI 组件的完整公告
  hf/        HuggingFace 镜像上安全相关模型 / 数据集卡片
  cn/        中文 AI 安全文章（CSDN / 安全客 / 先知）

用法：
  python harvest_ai_raw.py arxiv [--pdf-cap N] [--max-per-query N]
  python harvest_ai_raw.py blogs [--article-cap N]
  python harvest_ai_raw.py nvd
  python harvest_ai_raw.py ghsa
  python harvest_ai_raw.py hf
  python harvest_ai_raw.py report
  python harvest_ai_raw.py all
"""

import argparse
import html
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from html.parser import HTMLParser

CURL = "curl"

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetch_corpus as F  # noqa: E402
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


RAW = os.environ.get("AI_RAW_DIR") or os.path.join(paths.DATA_DIR, "ai_sec_raw")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
TIMEOUT = 45


def log(*a):
    print("[airaw]", *a, flush=True)


def _ensure(*parts):
    p = os.path.join(RAW, *parts)
    os.makedirs(p, exist_ok=True)
    return p


def http_get(url, tries=4, timeout=TIMEOUT, headers=None, binary=False):
    """经 curl 子进程取数据。
    arXiv API / 部分站点按 TLS 指纹拦截 python-urllib（406），curl 正常，
    故本模块统一走 curl，行为与命令行实测一致。"""
    last = None
    hdrs = {"User-Agent": UA}
    hdrs.update(headers or {})
    for i in range(tries):
        cmd = [CURL, "-sS", "-L", "--max-time", str(timeout),
               "--retry", "0", "-o", "-", "-w", ""]
        for k, v in hdrs.items():
            cmd += ["-H", f"{k}: {v}"]
        cmd.append(url)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
            if p.returncode != 0:
                raise RuntimeError(f"curl exit {p.returncode}: {p.stderr[:120]!r}")
            data = p.stdout
            if not binary:
                return data.decode("utf-8", "replace")
            return data
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.5 * (i + 1) + 0.5)
    raise RuntimeError(f"GET failed: {url} :: {last}")


def _load_state(fp):
    if os.path.isfile(fp):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                return json.load(f)
        except ValueError as _sw_e:
            _swallow("modules/m1_monitor/backend/harvest_ai_raw.py:100", _sw_e)
    return {}


def _save_state(fp, st):
    """原子写状态。Windows 下 os.replace 可能被索引/杀软短暂占用 → 重试 + 降级直写。"""
    tmp = fp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)
    for i in range(6):
        try:
            os.replace(tmp, fp)
            return
        except PermissionError:
            time.sleep(0.4 * (i + 1))
    try:
        with open(fp, "w", encoding="utf-8") as f:   # 降级：直接覆写
            f.write(open(tmp, "r", encoding="utf-8").read())
        os.remove(tmp)
    except Exception as _sw_e:  # noqa: BLE001 —— 状态写失败不应中断采集
        _swallow("modules/m1_monitor/backend/harvest_ai_raw.py:120", _sw_e)


def _dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(root, fn))
            except OSError as _sw_e:
                _swallow("modules/m1_monitor/backend/harvest_ai_raw.py:130", _sw_e)
    return total


# ==========================================================================
# 1. arXiv —— AI 安全论文（元数据 + PDF 全文，主力体积来源）
# ==========================================================================
ARXIV_QUERIES = [
    'abs:"prompt injection"',
    'abs:"jailbreak" AND abs:"language model"',
    'abs:"large language model" AND abs:"security"',
    'abs:"large language model" AND abs:"vulnerability"',
    'abs:"large language model" AND abs:"attack"',
    'abs:"LLM agent" AND abs:"attack"',
    'abs:"adversarial example"',
    'abs:"adversarial attack" AND abs:"neural"',
    'abs:"data poisoning"',
    'abs:"backdoor attack" AND abs:"model"',
    'abs:"model extraction"',
    'abs:"model stealing"',
    'abs:"membership inference"',
    'abs:"model inversion"',
    'abs:"malicious model"',
    'abs:"unsafe model"',
    'abs:"retrieval augmented generation" AND abs:"attack"',
    'abs:"vector database" AND abs:"security"',
    'abs:"embedding" AND abs:"privacy"',
    'abs:"AI supply chain"',
    'abs:"machine learning supply chain"',
    'abs:"guardrail" AND abs:"bypass"',
    'abs:"safety alignment" AND abs:"attack"',
    'abs:"red teaming" AND abs:"language model"',
    'abs:"toxicity" AND abs:"language model"',
    'abs:"hallucination" AND abs:"attack"',
    'abs:"training data extraction"',
    'abs:"privacy leakage" AND abs:"language model"',
    'abs:"deepfake" AND abs:"detection"',
    'abs:"federated learning" AND abs:"attack"',
    'abs:"differential privacy" AND abs:"machine learning"',
    'abs:"AI agent" AND abs:"security"',
    'abs:"tool use" AND abs:"language model" AND abs:"attack"',
    'abs:"code generation" AND abs:"security"',
    'abs:"vulnerability detection" AND abs:"deep learning"',
    'abs:"malware detection" AND abs:"machine learning"',
    'abs:"intrusion detection" AND abs:"deep learning"',
    'abs:"AI model" AND abs:"watermark" AND abs:"attack"',
    'abs:"quantization" AND abs:"attack"',
    'abs:"fine-tuning" AND abs:"safety"',
]

ARXIV_CATS = "cat:cs.CR OR cat:cs.AI OR cat:cs.LG OR cat:cs.CL OR cat:cs.CV"


def _arxiv_parse(xml):
    """返回 [{id, title, summary, published, updated, authors, cats, pdf, abs_url, comment, journal}]"""
    out = []
    for m in re.finditer(r"<entry>(.*?)</entry>", xml, re.S):
        e = m.group(1)
        g = lambda pat, d="": (re.search(pat, e, re.S).group(1).strip() if re.search(pat, e, re.S) else d)
        aid = g(r"<id>http://arxiv\.org/abs/([^<]+)</id>")
        if not aid:
            continue
        pdf = g(r'<link[^>]*title="pdf"[^>]*href="([^"]+)"')
        if not pdf:
            pdf = "https://arxiv.org/pdf/" + aid
        out.append({
            "id": aid,
            "title": html.unescape(re.sub(r"\s+", " ", g(r"<title>(.*?)</title>"))),
            "summary": html.unescape(re.sub(r"\s+", " ", g(r"<summary>(.*?)</summary>"))),
            "published": g(r"<published>([^<]+)</published>")[:10],
            "updated": g(r"<updated>([^<]+)</updated>")[:10],
            "authors": [a.strip() for a in re.findall(r"<name>([^<]+)</name>", e)][:12],
            "cats": re.findall(r'<category[^>]*term="([^"]+)"', e),
            "comment": html.unescape(g(r'<arxiv:comment[^>]*>(.*?)</arxiv:comment>')),
            "journal": html.unescape(g(r'<arxiv:journal_ref[^>]*>(.*?)</arxiv:journal_ref>')),
            "pdf": pdf,
            "abs_url": "https://arxiv.org/abs/" + aid,
        })
    return out


def harvest_arxiv(pdf_cap=7000, max_per_query=600):
    d = _ensure("arxiv")
    pdf_dir = os.path.join(d, "pdf")
    os.makedirs(pdf_dir, exist_ok=True)
    meta_fp = os.path.join(d, "metadata.jsonl")
    st_fp = os.path.join(d, "_state.json")
    st = _load_state(st_fp)
    done_q = set(st.get("queries", []))
    seen = set(st.get("ids", []))

    # ---- 1a. 元数据采集 ----
    with open(meta_fp, "a", encoding="utf-8") as mf:
        for qi, q in enumerate(ARXIV_QUERIES, 1):
            if q in done_q:
                continue
            got = 0
            start = 0
            while got < max_per_query:
                sq = f"({ARXIV_CATS}) AND {q}"
                url = ("https://export.arxiv.org/api/query?search_query="
                       + urllib.parse.quote(sq)
                       + f"&start={start}&max_results=100&sortBy=submittedDate&sortOrder=descending")
                try:
                    xml = http_get(url, tries=3, timeout=60)
                except Exception as e:  # noqa: BLE001
                    log(f"  Q{qi} start={start} 失败: {str(e)[:70]}")
                    break
                ents = _arxiv_parse(xml)
                if not ents:
                    break
                for r in ents:
                    if r["id"] in seen:
                        continue
                    seen.add(r["id"])
                    mf.write(json.dumps(r, ensure_ascii=False) + "\n")
                    got += 1
                mf.flush()
                start += 100
                if len(ents) < 100:
                    break
                time.sleep(3.2)          # arXiv API 礼貌限速
            done_q.add(q)
            st["queries"] = sorted(done_q)
            st["ids"] = sorted(seen)
            _save_state(st_fp, st)
            log(f"  [Q{qi}/{len(ARXIV_QUERIES)}] 累计唯一论文 {len(seen)}（本查询 +{got}）")
    log(f"论文元数据：{len(seen)} 篇 → {meta_fp}")

    # ---- 1b. PDF 全文下载（按此控制归档体积） ----
    items = []
    with open(meta_fp, "r", encoding="utf-8") as f:
        for line in f:
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
    st["pdf_done"] = st.get("pdf_done", [])
    done_pdf = set(st["pdf_done"])
    # 已是磁盘上存在的 PDF 也计入
    for it in items:
        fp = os.path.join(pdf_dir, it["id"].replace("/", "_") + ".pdf")
        if os.path.isfile(fp) and os.path.getsize(fp) > 20000:
            done_pdf.add(it["id"])
    have0 = len(done_pdf)
    target = min(pdf_cap, len(items))
    log(f"PDF 下载：已有 {have0}，目标 {target}（并发 4）")
    todo = [it for it in items if it["id"] not in done_pdf][: max(0, target - have0)]

    from concurrent.futures import ThreadPoolExecutor, as_completed
    done_cnt = [have0]
    lock = __import__("threading").Lock()
    bytes_got = [_dir_size(pdf_dir)]

    def _dl(it):
        fp = os.path.join(pdf_dir, it["id"].replace("/", "_") + ".pdf")
        time.sleep(0.5)          # arXiv 礼貌限速（3 并发 ≈ 1.2 req/s）
        try:
            blob = http_get(it["pdf"], tries=3, timeout=120, binary=True)
            if blob[:4] != b"%PDF" or len(blob) < 20000:
                raise RuntimeError("not a pdf / too small")
            with open(fp, "wb") as f:
                f.write(blob)
            return (it["id"], len(blob))
        except Exception as e:  # noqa: BLE001
            return (it["id"], -1)

    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(_dl, it): it for it in todo}
        for fu in as_completed(futs):
            aid, sz = fu.result()
            with lock:
                done_pdf.add(aid)
                if sz > 0:
                    done_cnt[0] += 1
            if done_cnt[0] % 25 == 0:
                st["pdf_done"] = sorted(done_pdf)
                _save_state(st_fp, st)
                sz_gb = _dir_size(pdf_dir) / 1024 / 1024 / 1024
                log(f"    PDF {done_cnt[0]}/{target}，体积 {sz_gb:.2f}GB")
    st["pdf_done"] = sorted(done_pdf)
    _save_state(st_fp, st)
    log(f"PDF 完成 {len(done_pdf)} 篇，体积 {_dir_size(pdf_dir)/1024/1024/1024:.2f}GB")


# ==========================================================================
# 2. 厂商公告 / 安全博客（RSS + 文章正文全文）
# ==========================================================================
BLOG_FEEDS = [
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("Wiz", "https://www.wiz.io/blog/rss.xml"),
    ("Snyk", "https://snyk.io/blog/feed/"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("OpenAI", "https://openai.com/blog/rss.xml"),
    ("GitHub Security", "https://github.blog/tag/security/feed/"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("AWS Security", "https://aws.amazon.com/blogs/security/feed/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Securelist", "https://securelist.com/feed/"),
    ("OWASP GenAI", "https://genai.owasp.org/feed/"),
    ("MSRC", "https://msrc.microsoft.com/blog/feed"),
]


class _TextExtract(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer", "form"}
    BLOCK = {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "section", "article", "tr"}

    def __init__(self):
        super().__init__()
        self.buf = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.buf.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag in self.BLOCK:
            self.buf.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.buf.append(data)

    def text(self):
        t = "".join(self.buf)
        t = re.sub(r"[ \t\r\f\v]+", " ", t)
        t = re.sub(r"\n\s*\n+", "\n", t)
        return t.strip()


def _strip_html(h):
    # CDATA 段（RSS/Atom 标题与正文常见）HTMLParser 不输出其文本，先拆掉包装
    h = (h or "").replace("<![CDATA[", "").replace("]]>", "")
    p = _TextExtract()
    try:
        p.feed(html.unescape(h))
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/harvest_ai_raw.py:374", _sw_e)
    return p.text()


def _rss_items(xml, source):
    out = []
    for m in re.finditer(r"<(item|entry)\b.*?</\1>", xml, re.S):
        b = m.group(0)
        g = lambda pat, d="": (re.search(pat, b, re.S).group(1).strip() if re.search(pat, b, re.S) else d)
        link = g(r"<link[^>]*href=\"([^\"]+)\"") or g(r"<link>([^<]+)</link>")
        title = html.unescape(_strip_html(g(r"<(?:title|media:title)[^>]*>(.*?)</(?:title|media:title)>")))
        if not link or not title:
            continue
        guid = g(r"<(?:guid|id)[^>]*>([^<]+)</(?:guid|id)>") or link
        pub = g(r"<(?:pubDate|published|updated|dc:date)[^>]*>([^<]+)</")
        summary = _strip_html(g(r"<(?:description|summary|content:encoded)[^>]*>(.*?)</(?:description|summary|content:encoded)>"))
        out.append({"source": source, "guid": guid, "title": title, "link": link,
                    "published": pub, "summary": summary[:4000]})
    return out


def harvest_blogs(article_cap=4000):
    d = _ensure("blogs")
    art_dir = os.path.join(d, "articles")
    os.makedirs(art_dir, exist_ok=True)
    idx_fp = os.path.join(d, "articles.jsonl")
    st_fp = os.path.join(d, "_state.json")
    st = _load_state(st_fp)
    done_link = set(st.get("links", []))
    feeds_done = st.get("feeds", {})
    n_new = 0

    # 2a. 抓取各 feed 的条目清单
    all_items = []
    for source, url in BLOG_FEEDS:
        try:
            xml = http_get(url, tries=3, timeout=40)
        except Exception as e:  # noqa: BLE001
            log(f"  feed {source} 失败: {str(e)[:60]}")
            continue
        items = _rss_items(xml, source)
        feeds_done[source] = len(items)
        all_items += items
        log(f"  feed {source}: {len(items)} 条")
        time.sleep(0.8)
    _save_state(st_fp, {**st, "feeds": feeds_done, "links": sorted(done_link)})

    # 2b. 抓正文（按需，达到上限即停）
    todo = [it for it in all_items if it["link"] not in done_link]
    log(f"文章待抓 {len(todo)} 条（上限 {article_cap}）")
    with open(idx_fp, "a", encoding="utf-8") as of:
        for it in todo:
            if n_new >= article_cap:
                break
            try:
                h = http_get(it["link"], tries=2, timeout=35)
            except Exception:  # noqa: BLE001
                done_link.add(it["link"])
                continue
            text = _strip_html(h)
            if len(text) < 300:          # JS 渲染或无正文
                done_link.add(it["link"])
                continue
            aid = re.sub(r"[^A-Za-z0-9._-]", "_", it["guid"])[:100] or str(abs(hash(it["link"])))
            safe = it["source"].replace(" ", "_") + "__" + aid + ".txt"
            with open(os.path.join(art_dir, safe), "w", encoding="utf-8") as f:
                f.write(it["title"] + "\n\n" + text[:400000])
            rec = {**it, "text_file": safe, "text_len": len(text)}
            of.write(json.dumps(rec, ensure_ascii=False) + "\n")
            done_link.add(it["link"])
            n_new += 1
            if n_new % 50 == 0:
                of.flush()
                _save_state(st_fp, {**st, "feeds": feeds_done, "links": sorted(done_link)})
                log(f"    正文 {n_new}/{article_cap}，体积 {_dir_size(art_dir)/1024/1024:.0f}MB")
            time.sleep(0.7)
    of_ok = True
    _save_state(st_fp, {**st, "feeds": feeds_done, "links": sorted(done_link)})
    log(f"博客正文新增 {n_new} 篇，累计 {len(done_link)} 链接，体积 {_dir_size(art_dir)/1024/1024:.0f}MB")


# ==========================================================================
# 3. NVD —— 从全量收割中筛出 AI 相关 CVE，落完整记录
# ==========================================================================
def _nvd_worker_init():
    pass


def _nvd_worker(cve):
    """单条 CVE → AI 安全富化记录（非 AI 返回 None）。供多进程调用。"""
    try:
        rec = F.build_record(cve, {}, {}, [])
        ok, score, cat, reason, tags = F.classify(rec)
        if not ok:
            return None
        rec["ai_score"] = score
        rec["category"] = cat
        rec["category_reason"] = reason
        rec["risk_tags"] = tags
        rec["scope"] = "AI安全"
        rec["refs"] = rec.get("refs", [])[:6]
        rec["cpe"] = rec.get("cpe", [])[:8]
        rec["tags_raw"] = rec.get("tags_raw", [])[:10]
        if len(rec.get("desc", "")) > 1500:
            rec["desc"] = rec["desc"][:1500]
        return rec
    except Exception:  # noqa: BLE001
        return None


def harvest_nvd(rebuild=False):
    """从 NVD 全量分片中筛出 AI 相关 CVE（多进程富化 + 断点续跑）。"""
    from concurrent.futures import ProcessPoolExecutor
    d = _ensure("nvd")
    out_fp = os.path.join(d, "ai_cve.jsonl")
    st_fp = os.path.join(d, "_state.json")
    if rebuild and os.path.isfile(out_fp):
        os.remove(out_fp)
    st = _load_state(st_fp)
    done_files = set(st.get("files", []))
    raw_files = sorted(__import__("glob").glob(paths.data_path("nvd_full", "*Q*.jsonl")))
    log(f"NVD 分片 {len(raw_files)} 个，已处理 {len(done_files)}")
    seen = set(st.get("ids", []))
    n_ai = n_tot = 0
    t0 = time.time()
    workers = min(6, os.cpu_count() or 4)
    try:                       # 进程池比线程池更吃内存，低配档必须压到 2
        from envprofile import T
        workers = T.workers(workers)
    except Exception:
        pass
    with open(out_fp, "a", encoding="utf-8") as of, \
            ProcessPoolExecutor(max_workers=workers, initializer=_nvd_worker_init) as ex:
        for fp in raw_files:
            if os.path.basename(fp) in done_files:
                continue
            batch = []
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        c = json.loads(line)
                    except ValueError:
                        continue
                    n_tot += 1
                    cid = (c.get("id") or "").upper()
                    if not cid or cid in seen:
                        continue
                    seen.add(cid)
                    batch.append(c)
            for rec in ex.map(_nvd_worker, batch, chunksize=200):
                if rec is not None:
                    of.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    n_ai += 1
            of.flush()
            done_files.add(os.path.basename(fp))
            st["files"] = sorted(done_files)
            st["ids"] = sorted(seen)
            _save_state(st_fp, st)
            log(f"  {os.path.basename(fp)}：AI 累计 {n_ai} / 扫描 {n_tot}（{round(time.time()-t0)}s）")
    log(f"NVD AI CVE：{n_ai} 条 → {out_fp}（{os.path.getsize(out_fp)/1024/1024:.1f}MB）")


# ==========================================================================
# 4. GHSA —— AI 组件的完整公告
# ==========================================================================
def harvest_ghsa():
    d = _ensure("ghsa")
    src = paths.data_path("ghsa_full.json")
    if not os.path.isfile(src):
        log("缺少 data/ghsa_full.json，跳过")
        return
    with open(src, "r", encoding="utf-8") as f:
        g = json.load(f)
    prod_names = set(F.AI_PRODUCTS.keys())

    def _is_ai(blob):
        b = blob.lower()
        for n in prod_names:
            if len(n) >= 4 and re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", b):
                return n
        for kw in F.AI_DESC_KEYWORDS:
            if F.kw_hit(kw, b):
                return kw
        return None

    out = {"AI组件公告": [], "统计": {}}
    hit = 0
    for a in (g.get("ghsa_standalone") or []):
        blob = " ".join([a.get("title", ""), a.get("desc", ""), " ".join(a.get("products", []))])
        why = _is_ai(blob)
        if why:
            out["AI组件公告"].append({"why": why, "advisory": a})
            hit += 1
    for a in (g.get("ghsa_projects") or []):
        blob = " ".join([a.get("title", ""), a.get("desc", ""), " ".join(a.get("products", []))])
        why = _is_ai(blob)
        if why:
            out["AI组件公告"].append({"why": why, "advisory": a})
            hit += 1
    fp = os.path.join(d, "ai_advisories.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)
    out["统计"] = {"总数": hit}
    log(f"AI 组件公告：{hit} 条 → {fp}（{os.path.getsize(fp)/1024/1024:.1f}MB）")


# ==========================================================================
# 5. HuggingFace（镜像）—— 安全相关模型 / 数据集卡片
# ==========================================================================
HF_TERMS = ["security", "vulnerability", "malware", "exploit", "phishing", "intrusion",
            "pentest", "cyber", "threat", "prompt-injection", "jailbreak", "guardrail",
            "red-team", "adversarial", "safe-guard", "safety", "ctf", "forensics",
            "detection", "classifier", "llm-security", "ai-security"]


def harvest_hf(max_models=4000, max_datasets=1500):
    d = _ensure("hf")
    st_fp = os.path.join(d, "_state.json")
    st = _load_state(st_fp)
    seen = set(st.get("ids", []))
    out_fp = os.path.join(d, "models.jsonl")
    with open(out_fp, "a", encoding="utf-8") as of:
        for kind, cap in (("models", max_models), ("datasets", max_datasets)):
            got = 0
            for term in HF_TERMS:
                if got >= cap:
                    break
                for page in range(0, 6):
                    url = (f"https://hf-mirror.com/api/{kind}?search={urllib.parse.quote(term)}"
                           f"&limit=100&skip={page*100}&full=true")
                    try:
                        arr = json.loads(http_get(url, tries=2, timeout=30))
                    except Exception as e:  # noqa: BLE001
                        log(f"  hf {kind}/{term} 失败: {str(e)[:60]}")
                        break
                    if not isinstance(arr, list) or not arr:
                        break
                    for it in arr:
                        mid = it.get("id") or it.get("modelId")
                        key = f"{kind}:{mid}"
                        if not mid or key in seen:
                            continue
                        seen.add(key)
                        card = it.get("cardData") or {}
                        rec = {
                            "kind": kind, "id": mid, "downloads": it.get("downloads"),
                            "likes": it.get("likes"), "tags": (it.get("tags") or [])[:40],
                            "pipeline_tag": it.get("pipeline_tag"), "created": it.get("createdAt"),
                            "lastModified": it.get("lastModified"),
                            "library": it.get("library_name"),
                            "card_text": json.dumps(card, ensure_ascii=False)[:4000] if card else "",
                            "search_term": term,
                        }
                        of.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        got += 1
                    of.flush()
                    time.sleep(0.4)
                    if len(arr) < 100:
                        break
                st["ids"] = sorted(seen)
                _save_state(st_fp, st)
                log(f"  hf {kind}: {got}（累计 {len(seen)}）")
    log(f"HuggingFace 条目：{len(seen)} → {out_fp}")


# ==========================================================================
# 6. 体积报告
# ==========================================================================
def report():
    log(f"数据仓库：{RAW}")
    tot = 0
    for sub in sorted(os.listdir(RAW)) if os.path.isdir(RAW) else []:
        p = os.path.join(RAW, sub)
        if os.path.isdir(p):
            s = _dir_size(p)
            tot += s
            log(f"  {sub:10s} {s/1024/1024/1024:8.3f} GB")
    log(f"  {'合计':10s} {tot/1024/1024/1024:8.3f} GB / 目标 10 GB")
    return tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["arxiv", "blogs", "nvd", "ghsa", "hf", "report", "all"])
    ap.add_argument("--pdf-cap", type=int, default=7000)
    ap.add_argument("--max-per-query", type=int, default=600)
    ap.add_argument("--article-cap", type=int, default=4000)
    args = ap.parse_args()
    if args.mode in ("arxiv", "all"):
        harvest_arxiv(pdf_cap=args.pdf_cap, max_per_query=args.max_per_query)
    if args.mode in ("blogs", "all"):
        harvest_blogs(article_cap=args.article_cap)
    if args.mode in ("nvd", "all"):
        harvest_nvd()
    if args.mode in ("ghsa", "all"):
        harvest_ghsa()
    if args.mode in ("hf", "all"):
        harvest_hf()
    report()


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
