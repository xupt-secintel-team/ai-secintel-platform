# -*- coding: utf-8 -*-
"""
extra_sources.py —— 扩展数据源采集（GitHub / CSDN）
==========================================================
在 NVD + KEV + OSV + arXiv/Crossref + ATLAS 之外新增四类信息来源：

  1. GitHub Security Advisories —— 按 AI 组件包定向查询官方供应链公告
     （与 NVD 按 CVE 号去重：已有 CVE 则把公告合并进原记录，GHSA 独有条目单独成文）
  2. GitHub 仓库情报 —— AI 安全工具/研究仓库（topic 搜索 + star 门控），
     作为「可检索知识条目」并入知识底座（工具情报是知识情报系统的重要一环）
  3. CSDN 技术文章 —— 中文社区一手实践文章（搜索 API + AI 安全关键词门控），
     补齐中文语境下的技术情报覆盖
  4.（学术源扩充在 papers/augment 流程：arXiv + Crossref 检索方向加密）

全部记录使用与 ATLAS to_records 一致的完整 schema，可直接进检索索引。
输出：data/extra_sources.json（advisory 合并信息 / repo / article 知识条目）
"""

import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from taxonomy import RISK_CATEGORIES  # noqa: E402
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）

try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None, note=""):
            pass


HERE = os.path.dirname(os.path.abspath(__file__))
OUT = paths.data_path("extra_sources.json")
UA = {"User-Agent": "AI-Sec-Intel-Collector/1.0 (academic competition project)",
      "Accept": "application/vnd.github+json"}
TIMEOUT = 30

# --------------------------------------------------------------------------
# 查询配置
# --------------------------------------------------------------------------
# GitHub Advisory 按 AI 组件包定向查询（未认证限额 60 req/h）
GHSA_PACKAGES = [
    "langchain", "langchain-core", "langchain-community", "langflow", "llama-index",
    "llama-cpp-python", "ollama", "vllm", "gradio", "transformers",
    "huggingface-hub", "mlflow", "ray", "torchserve", "diffusers",
    "keras", "open-webui", "flowise", "dify", "chromadb",
    "milvus", "qdrant", "weaviate", "semantic-kernel",
    # —— 扩充（2026-09-23）——
    "litellm", "langgraph", "autogen", "crewai", "localai",
    "text-generation-webui", "fastgpt", "ragflow", "chatglm", "gpt4all",
    "anythingllm", "llamafactory",
    # —— 经典 Web / 基础组件（全领域供应链公告） ——
    "django", "flask", "werkzeug", "jinja2", "requests",
    "express", "lodash", "axios", "jquery", "next",
    "openssl", "log4j-core", "fastjson", "jackson-databind", "struts",
    "tomcat", "spring-core", "rails", "laravel", "wordpress",
]

# GitHub 仓库 topic 检索（未认证 10 req/min）
GH_REPO_QUERIES = [
    "topic:llm-security", "topic:ai-security", "topic:prompt-injection",
    "topic:llm-firewall", "topic:ai-red-teaming", "topic:llm-guardrails",
    "topic:ai-safety", "topic:llm-evaluation",
    # —— 扩充 ——
    "topic:prompt-security", "topic:jailbreak", "topic:ai-attacks",
    "topic:llm-testing",
    # —— 全领域安全（通用网络安全） ——
    "topic:vulnerability-scanner", "topic:sql-injection", "topic:xss",
    "topic:penetration-testing", "topic:pentest", "topic:exploit",
    "topic:red-team", "topic:osint", "topic:ctf", "topic:ctf-tools",
    "topic:reverse-engineering", "topic:malware-analysis", "topic:fuzzing",
    "topic:web-security", "topic:network-security", "topic:incident-response",
    "topic:threat-hunting", "topic:security-tools", "topic:burp-suite",
    "topic:rce", "topic:poc", "topic:cve", "topic:cybersecurity",
    "topic:infosec", "topic:forensics", "topic:ransomware",
    "topic:privilege-escalation", "topic:active-directory", "topic:cloud-security",
    "topic:kubernetes-security", "topic:owasp", "topic:payloads",
    "topic:bug-bounty", "topic:exploitation", "topic:shellcode",
    "topic:android-security", "topic:iot-security", "topic:api-security",
]

# CSDN 检索词（中文技术情报）
CSDN_QUERIES = [
    "提示词注入", "大模型安全", "AI安全", "模型越狱", "大模型漏洞",
    "数据投毒", "RAG安全", "智能体安全", "MCP安全", "AI供应链安全",
    "LangChain漏洞", "OLLAMA漏洞", "提示词注入防御", "LLM安全",
    # —— 扩充 ——
    "大模型越狱", "LLM攻防", "AI红队", "模型窃取", "智能体越狱",
    "MCP注入", "RAG投毒", "vLLM漏洞", "AI应用安全", "大模型攻防",
    # —— 全领域安全（通用网络安全） ——
    "SQL注入", "XSS攻击", "跨站脚本", "SSRF", "反序列化漏洞",
    "渗透测试", "内网渗透", "域渗透", "漏洞挖掘", "代码审计",
    "逆向工程", "CTF", "Web安全", "应急响应", "勒索病毒",
    "免杀", "提权", "后渗透", "红队", "护网", "漏洞复现",
    "模糊测试", "云安全", "容器安全", "webshell", "信息收集",
    "社会工程学", "缓冲区溢出", "RCE漏洞", "逻辑漏洞", "API安全",
    # —— 2026-09-29 扩充：AI 安全新面 + 近期热点 ——
    "深度伪造", "Deepfake", "语音克隆", "AI钓鱼", "模型水印",
    "AI隐私", "GPU漏洞", "CUDA漏洞", "算力安全", "提示词泄露",
    "Agent协议", "A2A安全", "LLM防火墙", "AI合规", "模型投毒",
    "恶意模型", "HuggingFace投毒", "pickle反序列化", "钓鱼网站", "反诈",
]

# CSDN 质量门控：标题/描述必须命中安全相关词（否则与安全无关的杂文会混入）
CSDN_GATE = re.compile(
    r"提示词注入|提示注入|大模型|llm|gpt|智能体|agent|越狱|jailbreak|投毒|poison"
    r"|ai安全|人工智能安全|模型安全|rag|检索增强|mcp|ollama|langchain|vllm"
    r"|gradio|huggingface|transformers|供应链|漏洞|攻防|渗透|安全测试|红队|guardrail"
    r"|对抗样本|adversarial|模型窃取|成员推理|多模态安全|fine-?tuning|微调"
    # —— 全领域安全词 ——
    r"|sql注入|sqli|xss|跨站|csrf|ssrf|xxe|反序列化|命令执行|代码执行|rce"
    r"|缓冲区溢出|溢出|提权|越权|弱口令|暴力破解|webshell|后门|木马|勒索|病毒"
    r"|逆向|免杀|加壳|shellcode|exp利用|poc|cve-|ctf|靶场|护网|蓝队|应急响应"
    r"|取证|蜜罐|waf|防火墙|入侵检测|ids|ips|edr|杀软|流量分析|内网|域控"
    r"|信息收集|指纹识别|端口扫描|目录扫描|子域名|社会工程|钓鱼|僵尸网络"
    r"|云安全|容器安全|k8s|kubernetes|docker|api安全|数据安全|加密|密码学"
    r"|漏洞挖掘|代码审计|模糊测试|fuzz|安全加固|基线|等保|零信任|安全运营"
    r"|vulnerability|exploit|malware|ransomware|backdoor|trojan|phishing"
    r"|penetration|pentest|red ?team|blue ?team|osint|forensics|reverse engineering", re.I)

# CSDN 无效标题模式（推广/下载/课程导流类）
CSDN_BAD_TITLE = re.compile(r"下载|资源包|课程|优惠券|招募|招聘|直播预约| VIP |会员专属")


# --------------------------------------------------------------------------
# 通用 HTTP
# --------------------------------------------------------------------------
def http_get(url, headers=None, ssl_ctx=None, tries=3, backoff=4):
    h = dict(UA)
    if headers:
        h.update(headers)
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h)
            kw = {"timeout": TIMEOUT}
            if ssl_ctx is not None:
                kw["context"] = ssl_ctx
            with urllib.request.urlopen(req, **kw) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503):
                time.sleep(backoff * (i + 1))
                continue
            raise
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(backoff * (i + 1))
    raise RuntimeError(f"GET failed: {url} :: {last}")


def get_json(url, headers=None, ssl_ctx=None, tries=3):
    return json.loads(http_get(url, headers=headers, ssl_ctx=ssl_ctx, tries=tries).decode("utf-8"))


def par_map(func, items, workers=8, desc=""):
    """并行抓取（对 GitHub/CSDN/DBLP 这类可并发的源提速）

    workers 会按性能档位压低（低配机上限 2）：并发换不来速度，
    只会把单核压满导致整体更慢 —— 见 core/envprofile.py。
    """
    try:                                  # 性能档位：拿不到就按原样跑
        from envprofile import T
        workers = T.workers(workers)
    except Exception:
        pass
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for i, res in enumerate(ex.map(func, items), 1):
            if res:
                out.append(res)
            if i % 5 == 0 or i == len(items):
                print(f"  [{desc}] {i}/{len(items)}", flush=True)
    return out


# --------------------------------------------------------------------------
# 空记录骨架（与 ATLAS to_records schema 对齐，engine 无需改动）
# --------------------------------------------------------------------------
def _skeleton(rid, rtype, kind, title, desc, published, sources, category, reason, tags):
    return {
        "id": rid, "type": rtype, "kind": kind,
        "title": title, "desc": desc,
        "published": published or "", "modified": "",
        "status": kind,
        # ⑤~⑪ 为通用安全分类 → scope=通用安全；①~④ 为 AI 安全
        "scope": "通用安全" if category[:1] in "⑤⑥⑦⑧⑨⑩⑪" else "AI安全",
        "cvss": {"score": None, "severity": "", "vector": "", "version": "",
                 "exploitability": None, "impact": None},
        "cwe": [], "cpe": [], "products": [], "vendors": [],
        "refs": [], "poc_links": [], "patch_links": [], "advisory_links": [],
        "osv_packages": [], "osv_summaries": [], "osv_refs": [],
        "sources": sources, "kev": {}, "tags": tags, "risk_tags": [],
        "ai_score": 1.0, "category": category, "category_reason": reason,
        "atlas": [], "atlas_mitigations": [], "papers": [], "remediation": [],
    }


def _guess_category(text, products=None):
    """分类：**统一走引擎分类器**（`core/fetch_corpus.py:classify`）。

    旧实现是手搓的一套正则，按顺序命中即返回，而最先判的偏偏是 AI 类：

        if re.search(r"inference|serving|框架|推理", t): return "① …"
        if re.search(r"agent|智能体|rag|检索增强|mcp|编排|工作流", t): return "③ …"

    「框架」「推理」「编排」是中文技术文章里的通用词，于是**几乎任何中文安全
    文章都会被判成 AI 安全**；"rag" 还是裸子串，会被 st**orage** / aver**ag**e 命中。
    结果就是同一条内容在实时流、离线语料、日报里分类各不相同。

    统一到 classify() 之后与实时流 / 离线语料 / 日报同口径，且没有 AI 证据时
    只会落到通用分类（⑤~⑪），不会"默认成 AI"。
    """
    rec = {
        "title": text or "",
        "desc": text or "",
        "products": [str(p) for p in (products or []) if p],
        "vendors": [],
        "cwe": [],
        "tags_raw": [],
    }
    try:
        import fetch_corpus as F
        _ok, _score, cat, _reason, _tags = F.classify(rec)
        if cat:
            return cat
    except Exception as _sw_e:  # noqa: BLE001 —— 分类失败不能拖垮采集
        _swallow("core/extra_sources.py:_guess_category", _sw_e)
    return "⑤ Web应用与API安全"


# --------------------------------------------------------------------------
# 1. GitHub Security Advisories
# --------------------------------------------------------------------------
def _fetch_ghsa_pkg(pkg):
    url = f"https://api.github.com/advisories?affects={urllib.parse.quote(pkg)}&per_page=20"
    try:
        arr = get_json(url, tries=2)
        return (pkg, arr)
    except Exception as e:  # noqa: BLE001
        print(f"  [GHSA] {pkg} 失败: {str(e)[:60]}", flush=True)
        return (pkg, [])


def collect_ghsa():
    """返回 (advisories 列表, 供 CVE 合并的映射)"""
    print(f"GitHub Security Advisories：{len(GHSA_PACKAGES)} 个 AI 组件包 ...")
    results = par_map(_fetch_ghsa_pkg, GHSA_PACKAGES, workers=4, desc="GHSA")

    advisories, seen = [], set()
    for pkg, arr in results:
        for a in arr or []:
            gid = a.get("ghsa_id")
            if not gid or gid in seen:
                continue
            seen.add(gid)
            # 受影响包与版本
            pkgs, vuln_desc = [], []
            for v in a.get("vulnerabilities") or []:
                pn = (v.get("package") or {}).get("name") or ""
                if pn:
                    pkgs.append(pn)
                rng = v.get("vulnerable_version_range") or ""
                fpv = v.get("first_patched_version")
                fp = fpv.get("identifier", "") if isinstance(fpv, dict) else (fpv or "")
                if rng or fp:
                    vuln_desc.append(f"{pn}: {rng or '*'} → 修复 {fp or '待定'}")
            cvss = a.get("cvss") or {}
            score = cvss.get("score")
            sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
            sev = sev_map.get((a.get("severity") or "").lower(), "")
            desc = " ".join((a.get("description") or "").split())
            if vuln_desc:
                desc = (desc + "\n受影响版本区间：" + "；".join(vuln_desc)).strip()
            cve_id = a.get("cve_id") or ""
            url_ad = f"https://github.com/advisories/{gid}"
            rec = _skeleton(
                rid=gid, rtype="advisory", kind="GitHub 供应链公告",
                title=" ".join((a.get("summary") or "").split()) or gid,
                desc=desc or (a.get("summary") or ""),
                published=(a.get("published_at") or "")[:10],
                sources=["GitHub Advisory"],
                category=_guess_category(desc + " " + (a.get("summary") or ""), pkgs),
                reason=f"GitHub 官方供应链公告（affects={', '.join(pkgs[:4])}）",
                tags=["供应链公告"] + [f"包:{p}" for p in pkgs[:4]],
            )
            rec["modified"] = (a.get("updated_at") or "")[:10]
            rec["products"] = sorted(set(pkgs))[:8]
            if score is not None:
                rec["cvss"] = {"score": score, "severity": sev, "vector": cvss.get("vector_string") or "",
                               "version": cvss.get("severities") and "" or "", "exploitability": None, "impact": None}
            rec["advisory_links"] = [url_ad]
            rec["cwe"] = [{"id": w, "name": "", "source": "GitHub"} for w in (a.get("cwe_ids") or [])][:3]
            rec["ghsa_cve"] = cve_id
            advisories.append(rec)
    # 按 CVE 号供合并
    by_cve = {}
    standalone = []
    for r in advisories:
        cve = r.pop("ghsa_cve", "")
        if cve:
            by_cve.setdefault(cve.upper(), []).append(r)
        else:
            standalone.append(r)
    print(f"  GHSA 公告：{len(advisories)} 条（其中 {len(standalone)} 条独立、{len(by_cve)} 组可并回已有 CVE）")
    return standalone, by_cve


# --------------------------------------------------------------------------
# 2. GitHub AI 安全仓库情报
# --------------------------------------------------------------------------
MIN_STARS = 60

def _fetch_repos(q):
    url = ("https://api.github.com/search/repositories?q=" + urllib.parse.quote(q) +
           "&sort=stars&order=desc&per_page=30")
    try:
        d = get_json(url, tries=2)
        return d.get("items") or []
    except Exception as e:  # noqa: BLE001
        print(f"  [repo] '{q}' 失败: {str(e)[:60]}", flush=True)
        return []


def collect_repos():
    print(f"GitHub 仓库情报：{len(GH_REPO_QUERIES)} 组 topic 检索 ...")
    all_items = []
    for i, q in enumerate(GH_REPO_QUERIES, 1):
        all_items += _fetch_repos(q)      # search API 限 10 req/min，串行 + 间隔
        print(f"  [repo] {i}/{len(GH_REPO_QUERIES)} '{q}'", flush=True)
        time.sleep(7)
    dedup, seen = [], set()
    for r in all_items:
        key = r.get("full_name")
        if key and key not in seen:
            seen.add(key)
            dedup.append(r)
    ok = [r for r in dedup if (r.get("stargazers_count") or 0) >= MIN_STARS]
    ok.sort(key=lambda r: -(r.get("stargazers_count") or 0))
    ok = ok[:400]
    out = []
    for r in ok:
        desc = " ".join((r.get("description") or "AI security repository").split())
        topics = r.get("topics") or []
        rec = _skeleton(
            rid="GH:" + r["full_name"], rtype="repo", kind="GitHub 安全工具仓库",
            title=r["full_name"],
            desc=desc,
            published=(r.get("created_at") or "")[:10],
            sources=["GitHub"],
            category=_guess_category(desc + " " + " ".join(topics)),
            reason="GitHub topic 检索命中（" + "、".join(topics[:4]) + "）",
            tags=["安全工具仓库"] + topics[:5],
        )
        rec["modified"] = (r.get("pushed_at") or "")[:10]
        rec["stars"] = r.get("stargazers_count")
        rec["language"] = r.get("language") or ""
        rec["repo_topics"] = topics[:10]
        rec["repo_url"] = r.get("html_url", "")
        rec["advisory_links"] = [r.get("html_url", "")]
        out.append(rec)
    print(f"  仓库知识条目：{len(out)} 个（去重 {len(dedup)}，star≥{MIN_STARS}）")
    return out


# --------------------------------------------------------------------------
# 2.5 学术论文 → 可检索知识条目（论文不再只能通过漏洞关联间接触达）
# --------------------------------------------------------------------------
def papers_to_knowledge(papers):
    """把 arXiv/Crossref 论文转为可全文检索的知识条目（type=paper）"""
    out, seen = [], set()
    for p in papers or []:
        title = " ".join((p.get("title") or "").split())
        if not title or title.lower() in seen:
            continue
        seen.add(title.lower())
        summary = " ".join((p.get("summary") or "").split())[:1200]
        authors = p.get("authors") or []
        if isinstance(authors, str):
            authors = [authors]
        venue = p.get("venue") or p.get("source") or ""
        cat = _guess_category(title + " " + summary)
        rec = _skeleton(
            rid="PAPER:" + (p.get("url") or title)[:80], rtype="paper", kind="学术论文",
            title=title,
            desc=(title + "。" + summary).strip("。"),
            published=(p.get("published") or "")[:10],
            sources=[p.get("source") or "arXiv"],
            category=cat,
            reason=f"学术论文（{p.get('source', '')} · {venue}）",
            tags=["学术论文"] + ([venue] if venue else []),
        )
        rec["authors"] = authors[:6]
        rec["venue"] = venue
        rec["article_url"] = p.get("url") or ""
        rec["advisory_links"] = [p.get("url")] if p.get("url") else []
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# 3. CSDN 技术文章
# --------------------------------------------------------------------------
def _fetch_csdn(q):
    url = ("https://so.csdn.net/api/v3/search?q=" + urllib.parse.quote(q) +
           "&t=blog&p=1")
    try:
        d = get_json(url, tries=2)
        return (q, d.get("result_vos") or [])
    except Exception as e:  # noqa: BLE001
        print(f"  [CSDN] '{q}' 失败: {str(e)[:60]}", flush=True)
        return (q, [])


def _clean(s):
    return re.sub(r"<[^>]+>", "", s or "").replace("&amp;", "&").replace("&quot;", '"').strip()


def _to_int(v):
    """CSDN 的阅读数可能是 '2335' / '1.2万' / null，统一转 int"""
    if v is None:
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    s = str(v).strip()
    if s.endswith("万"):
        try:
            return int(float(s[:-1]) * 10000)
        except ValueError:
            return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def collect_csdn():
    print(f"CSDN 技术文章：{len(CSDN_QUERIES)} 组检索 ...")
    results = par_map(_fetch_csdn, CSDN_QUERIES, workers=4, desc="CSDN")
    seen, out = set(), []
    for _, items in results:
        for it in items:
            if (it.get("type") or "") != "blog":
                continue
            url = (it.get("url") or "").split("?")[0]
            title = _clean(it.get("title"))
            desc = _clean(it.get("description") or it.get("digest"))
            if not title or not url or url in seen:
                continue
            blob = title + " " + desc
            if not CSDN_GATE.search(blob) or CSDN_BAD_TITLE.search(title):
                continue
            if len(desc) < 60:
                continue
            created = _clean(str(it.get("created_at") or ""))[:10] or "2024-01-01"
            if created < "2023-01-01":
                continue
            seen.add(url)
            aid = it.get("articleid") or str(abs(hash(url)))
            rec = _skeleton(
                rid="CSDN:" + str(aid), rtype="article", kind="CSDN 社区文章",
                title=title,
                desc=title + "。" + desc,
                published=created,
                sources=["CSDN"],
                category=_guess_category(blob),
                reason="中文社区技术文章（CSDN 检索 + AI 安全关键词门控通过）",
                tags=["社区文章"],
            )
            rec["author"] = _clean(it.get("nickname") or it.get("username") or "")
            rec["views"] = _to_int(it.get("view") if it.get("view") is not None else it.get("view_num"))
            rec["article_url"] = url
            rec["advisory_links"] = [url]
            out.append(rec)
    out.sort(key=lambda r: -(r.get("views") or 0))
    out = out[:400]
    print(f"  CSDN 文章知识条目：{len(out)} 篇（质量门控通过）")
    return out


# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def collect_all():
    t0 = time.time()
    ghsa_standalone, ghsa_by_cve = collect_ghsa()
    repos = collect_repos()
    articles = collect_csdn()

    data = {
        "ghsa_standalone": ghsa_standalone,
        "ghsa_by_cve": ghsa_by_cve,
        "repos": repos,
        "articles": articles,
        "meta": {
            "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "elapsed_sec": round(time.time() - t0, 1),
            "ghsa": len(ghsa_standalone) + len(ghsa_by_cve),
            "repos": len(repos),
            "articles": len(articles),
        },
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print(f"已保存 {OUT} ({os.path.getsize(OUT)/1024/1024:.2f} MB，耗时 {data['meta']['elapsed_sec']}s)")
    return data


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    collect_all()
