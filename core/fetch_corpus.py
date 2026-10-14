# -*- coding: utf-8 -*-
"""
fetch_corpus.py —— 多源 AI 安全情报采集与富化
================================================
数据源（4 类，覆盖赛题「情报监测 + 情报富化」要求）：

  1. NVD  (services.nvd.nist.gov)  —— CVE 漏洞主库：描述 / CVSS / CWE / CPE / 参考链接
  2. CISA KEV (known exploited)    —— 在野利用标记、整改要求、勒索软件关联
  3. OSV / GitHub Advisory         —— 开源 AI 组件（PyPI/npm）供应链公告
  4. arXiv                         —— AI 安全学术论文，按关键词与漏洞做关联

富化维度（≥5 种）：CVSS 评分 · CWE 弱点 · 受影响资产(CPE厂商/产品/版本区间) ·
POC 可利用性 · 修复建议/补丁 · 关联论文 · 在野利用状态 · AI 风险分类

输出：data/corpus.json   （含 fetch_meta 采集元信息，供时效性统计）
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from taxonomy import (  # noqa: E402
    AI_DESC_KEYWORDS, AI_PRODUCTS, CWE_AI_HINT, RISK_CATEGORIES,
    DEFAULT_CATEGORY, MODEL_LAYER_TAGS, AI_RELEVANCE_THRESHOLD,
    CWE_GENERAL_HINT, GENERAL_VULN_RULES, DEFAULT_GENERAL_CATEGORY,
)
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）


HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = paths.DATA_DIR
os.makedirs(DATA_DIR, exist_ok=True)

UA = {"User-Agent": "AI-Sec-Intel-Collector/1.0 (academic research; contact: student project)"}
NVD_SLEEP = 6.5          # 无 API Key 时 NVD 限速 5 req / 30s
TIMEOUT = 45

# --------------------------------------------------------------------------
# 采集关键词：围绕 AI 全栈（框架 / 模型 / 应用 / 供应链）
# --------------------------------------------------------------------------
NVD_QUERIES = [
    "large language model",
    "prompt injection",
    "ollama",
    "vllm",
    "langchain",
    "huggingface",
    "gradio",
    "text generation inference",
    "triton inference server",
    "diffusion model",
    "vector database",
    "model context protocol",
    "open webui",
    "dify",
    "mlflow",
    "kubeflow",
    "comfyui",
    "stable diffusion",
    "llama.cpp",
    "safetensors",
    "jupyter notebook",
    "torchserve",
    "ray cluster",
    "chatbot",
    "ai agent",
    # —— 扩充（2026-09-23：LLM 供应链 / 国产模型栈 / 智能体框架 / 网关）——
    "llm",
    "litellm",
    "langflow",
    "llama-index",
    "anythingllm",
    "ragflow",
    "fastgpt",
    "chatglm",
    "openai",
    "chatgpt",
    "mistral",
    "guardrail",
    "crewai",
    "autogen",
    "semantic kernel",
    "localai",
    "privategpt",
    "text generation webui",
    "generative ai",
    "retrieval augmented generation",
    "ai gateway",
    "chatchat",
    "deepseek",
    # —— 全领域网络安全（通用漏洞类型 / 热点组件 / 平台） ——
    "sql injection",
    "cross-site scripting",
    "cross-site request forgery",
    "server-side request forgery",
    "xml external entity",
    "remote code execution",
    "command injection",
    "deserialization",
    "path traversal",
    "file upload vulnerability",
    "open redirect",
    "request smuggling",
    "prototype pollution",
    "buffer overflow",
    "use after free",
    "out-of-bounds",
    "integer overflow",
    "type confusion",
    "privilege escalation",
    "authentication bypass",
    "improper access control",
    "hardcoded password",
    "default credentials",
    "information disclosure",
    "denial of service",
    "memory corruption",
    "kernel vulnerability",
    "hypervisor",
    "container escape",
    "openssl",
    "log4j",
    "apache struts",
    "fastjson",
    "jackson-databind",
    "spring framework",
    "django",
    "laravel",
    "wordpress plugin",
    "apache http server",
    "jenkins",
    "gitlab",
    "tomcat",
    "weblogic",
    "exchange server",
    "active directory",
    "oauth",
    "jwt",
    "saml",
    "vpn",
    "router firmware",
    "iot device",
    "ransomware",
    "backdoor",
    "supply chain attack",
    "dependency confusion",
    "certificate validation",
    "smart contract",
    "kubernetes",
    "docker",
]

# OSV 查询的 AI 开源组件（PyPI / npm）
OSV_PACKAGES = [
    ("PyPI", "transformers"), ("PyPI", "langchain"), ("PyPI", "langchain-core"),
    ("PyPI", "llama-index"), ("PyPI", "ollama"), ("PyPI", "vllm"),
    ("PyPI", "gradio"), ("PyPI", "torch"), ("PyPI", "tensorflow"),
    ("PyPI", "sentence-transformers"), ("PyPI", "huggingface-hub"),
    ("PyPI", "llama-cpp-python"), ("PyPI", "chromadb"), ("PyPI", "pymilvus"),
    ("PyPI", "qdrant-client"), ("PyPI", "mlflow"), ("PyPI", "ray"),
    ("PyPI", "onnx"), ("PyPI", "onnxruntime"), ("PyPI", "peft"),
    ("PyPI", "datasets"), ("PyPI", "tokenizers"), ("PyPI", "bentoml"),
    ("PyPI", "dspy"), ("PyPI", "crewai"), ("PyPI", "autogen-agentchat"),
    ("PyPI", "sglang"), ("PyPI", "deepspeed"), ("PyPI", "comfyui"),
    ("npm", "langchain"), ("npm", "@langchain/core"), ("npm", "ollama"),
    ("npm", "flowise"), ("npm", "n8n"), ("npm", "openai"),
    # —— 扩充 ——
    ("PyPI", "litellm"), ("PyPI", "langflow"), ("PyPI", "langgraph"),
    ("PyPI", "fastembed"), ("PyPI", "txtai"), ("PyPI", "gpt4all"),
    ("npm", "@langchain/langgraph"), ("npm", "langflow"),
]

# arXiv 查询（AI 安全方向）
ARXIV_QUERIES = [
    'all:"prompt injection"',
    'all:"large language model" AND all:"vulnerability"',
    'all:"LLM agent" AND all:"security"',
    'all:"model extraction attack"',
    'all:"adversarial machine learning" AND all:"security"',
    'all:"AI supply chain" AND all:"security"',
    'all:"jailbreak" AND all:"language model"',
]

# --------------------------------------------------------------------------
# CWE 名称表（常用子集）
# --------------------------------------------------------------------------
CWE_NAMES = {
    "CWE-20": "Improper Input Validation", "CWE-22": "Path Traversal",
    "CWE-23": "Relative Path Traversal", "CWE-59": "Link Following",
    "CWE-77": "Command Injection", "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting", "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection", "CWE-95": "Eval Injection",
    "CWE-119": "Buffer Overflow", "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow", "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read", "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure", "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation", "CWE-306": "Missing Authentication",
    "CWE-311": "Missing Encryption", "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition", "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free", "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference", "CWE-494": "Download of Code Without Integrity Check",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-506": "Embedded Malicious Code",
    "CWE-521": "Weak Password Requirements", "CWE-601": "Open Redirect",
    "CWE-611": "XXE", "CWE-613": "Insufficient Session Expiration",
    "CWE-668": "Exposure of Resource", "CWE-732": "Incorrect Permission Assignment",
    "CWE-770": "Allocation without Limits", "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hard-coded Credentials", "CWE-829": "Inclusion of Untrusted Functionality",
    "CWE-862": "Missing Authorization", "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery", "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-1336": "Server-Side Template Injection", "CWE-1426": "Improper Validation of Generative AI Output",
    "CWE-1427": "Improper Neutralization of Input Used in LLM Prompt",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
    "CWE-1188": "Insecure Default Initialization",
    "CWE-915": "Mass Assignment", "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}


# ==========================================================================
# 通用 HTTP
# ==========================================================================
def _net():
    """延迟导入 core/net.py（避免与顶层 import 顺序耦合）。"""
    try:
        import net
        return net
    except ImportError:  # pragma: no cover
        import sys as _sys
        _p = os.path.dirname(os.path.abspath(__file__))
        if _p not in _sys.path:
            _sys.path.insert(0, _p)
        import net
        return net


def http_get(url, headers=None, data=None, tries=3, timeout=None):
    """urllib 版 GET。2026-09-30：接入自适应代理 + 证书降级。

    urllib 本来会读环境变量代理，但（a）代理端口漂移后环境变量可能是旧的，
    （b）代理做 TLS 中间人时 urllib 直接抛 CERTIFICATE_VERIFY_FAILED（KEV 那行日志）。
    这里显式走 core/net.py 探测到的代理，并在证书失败时用不校验上下文重试。
    """
    h = dict(UA)
    if headers:
        h.update(headers)
    last = None
    to = timeout or TIMEOUT
    proxy, verify = "", True
    try:
        net = _net()
        proxy = net.detect_proxy()
    except Exception:  # noqa: BLE001
        net = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers=h)
            if net is not None and (proxy or not verify):
                with net.opener(proxy, verify).open(req, timeout=to) as r:
                    return r.read()
            with urllib.request.urlopen(req, timeout=to) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503):
                time.sleep(8 * (i + 1))
                continue
            raise
        except Exception as e:  # noqa: BLE001
            last = e
            if net is not None and net.ssl_fallback(e) and verify:
                verify = False          # MITM 代理：下一次重试跳过证书校验
                continue
            time.sleep(3 * (i + 1))
    raise RuntimeError(f"GET failed: {url} :: {last}")


def log(*a):
    print("[collect]", *a, flush=True)


# ==========================================================================
# 1. NVD 采集
# ==========================================================================
def fetch_nvd(keyword, limit=2000):
    q = urllib.parse.quote(keyword)
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={q}&resultsPerPage={limit}&noRejected=")
    raw = http_get(url)
    return json.loads(raw.decode("utf-8"))


def parse_cvss(cve):
    """从 NVD 原始记录抽 CVSS。

    ★ 必须优先取 type=="Primary"（2026-10-08 评测实测发现）：
      NVD 同一 CVE 常同时给多条度量（CNVD/厂商自评 = Secondary，NVD 官方 = Primary），
      且**数组顺序不保证 Primary 在前**。原实现直接 `arr[0]`，实测 300 个标注样本里
      11 条取到了 Secondary，**严重低估风险等级**：
        CVE-2022-0902 语料取到 Secondary 8.1/HIGH，而 NVD Primary 是 9.8/CRITICAL；
        CVE-2022-2750 语料 6.3/MEDIUM，Primary 9.8/CRITICAL。
      差 3.5 分、跨两个等级 —— 对安全产品来说这是实质性错误（会让高危漏洞看着不紧急）。
    ★★ 还要注意 **type 标在哪个版本上是独立的**（实测 CVE-2013-2423 / CVE-2021-34473）：
      NVD 可能只在老版本 V2 上标 Primary，而新版本 V3.1 全是 CNA 的 Secondary。
      所以**不能按 V40→V2 逐版本找 Primary**（会在只有 Secondary 的版本上停下），
      必须**全版本扫 Primary**，找不到才按版本优先级取第一条。

    ★★ 更常见：**多个版本同时标了 Primary**（实测语料 58210 条里有 22230 条如此）。
      例如 CVE-2022-31210 的 V3.1=9.8 与 V2=7.5 都是 Primary。
      此时必须取**最高版本**的那个（V3.1 9.8），因为 V2 是老版本、评分口径已过时。
      早先的"全版本扫 Primary"实现取的是**最后一个**命中 → 拿到 V2 的 7.5，
      会把正确值判成错误（这与"数组顺序不保证 Primary 在前"是**两个独立的坑**）。
    """
    metrics = cve.get("metrics", {})
    order = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    def _pack(m, key, severity_out):
        d = m.get("cvssData", {})
        severity = m.get("baseSeverity") or d.get("baseSeverity", "")
        severity_out.update({
            "score": d.get("baseScore"),
            "severity": (severity or "").upper(),
            "vector": d.get("vectorString", ""),
            # version 取原值（"3.1"/"4.0"/"2.0"），别用 key.replace 派生
            "version": d.get("version") or key.replace("cvssMetricV", ""),
            "exploitability": m.get("exploitabilityScore"),
            "impact": m.get("impactScore"),
        })

    out = {}
    # 按版本从新到旧扫，**首个带 Primary 的版本即取它**（order 本身就是优先级）
    for key in order:
        m = next((x for x in (metrics.get(key) or [])
                  if x.get("type") == "Primary"), None)
        if m is not None and (m.get("cvssData") or {}).get("baseScore") is not None:
            _pack(m, key, out)
            return out
    # 没有任何版本标 Primary → 按版本优先级取第一条
    for key in order:
        arr = metrics.get(key) or []
        if arr and (arr[0].get("cvssData") or {}).get("baseScore") is not None:
            _pack(arr[0], key, out)
            return out
    return {"score": None, "severity": "", "vector": "", "version": "", "exploitability": None, "impact": None}


def parse_cpe(cve):
    """提取受影响厂商 / 产品 / 版本区间"""
    items, vendors, products = [], set(), set()
    for cfg in cve.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 5:
                    continue
                vendor, product = parts[3], parts[4]
                vendors.add(vendor)
                products.add(product)
                items.append({
                    "vendor": vendor, "product": product,
                    "version": parts[5] if len(parts) > 5 else "*",
                    "start_incl": m.get("versionStartIncluding"),
                    "start_excl": m.get("versionStartExcluding"),
                    "end_incl": m.get("versionEndIncluding"),
                    "end_excl": m.get("versionEndExcluding"),
                })
    return items, sorted(vendors), sorted(products)


def parse_refs(cve):
    refs, poc, patch, advisory = [], [], [], []
    for r in cve.get("references", []) or []:
        url = r.get("url", "")
        tags = [t.upper() for t in (r.get("tags") or [])]
        src = r.get("source", "")
        refs.append({"url": url, "tags": tags, "source": src})
        low = url.lower()
        if ("EXPLOIT" in tags or "PROOF" in "".join(tags)) or \
           any(k in low for k in ("exploit-db", "packetstormsecurity", "github.com/", "gist.github")) and \
           any(k in low for k in ("poc", "exploit", "cve-")):
            poc.append(url)
        if "PATCH" in tags or any(k in low for k in ("/commit/", "/pull/", "security/patch", "release")):
            patch.append(url)
        if any(t in tags for t in ("VENDOR", "ADVISORY")) or any(
                k in low for k in ("/security/", "advisory", "advisories", "security-bulletin",
                                   "ghsa-", "cert.", "cisa.gov", "nvd.nist.gov")):
            advisory.append(url)
    return refs, poc, patch, advisory


def parse_cwe(cve):
    out = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in [x["id"] for x in out]:
                out.append({"id": v, "name": CWE_NAMES.get(v, ""), "source": w.get("source", "")})
    return out


# ==========================================================================
# 2. CISA KEV
# ==========================================================================
def fetch_kev(timeout=25, tries=2):
    """CISA KEV 全量快照（1729 条，约 2MB）。

    timeout / tries 可收紧：默认 http_get 是 45s × 3 次 = 最坏 135s，
    快车道一轮只要 15s，被它一顶单轮就变成两百多秒（实测 205s）。
    快车道传 timeout=15/tries=1 快速失败即可——_kev() 有 120s 缓存兜底，
    抓不到就继续用上一份，不会有数据缺口。
    """
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    try:
        d = json.loads(http_get(url, timeout=timeout, tries=tries).decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        log("KEV failed:", e)
        return {}
    out = {}
    for v in d.get("vulnerabilities", []):
        out[v["cveID"]] = {
            "exploited": True,
            "date_added": v.get("dateAdded"),
            "short_desc": v.get("shortDescription"),
            "required_action": v.get("requiredAction"),
            "due_date": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
        }
    log(f"KEV: {len(out)} records")
    return out


# ==========================================================================
# 3. OSV / GHSA
# ==========================================================================
def fetch_osv(pkg, ecosystem):
    url = "https://api.osv.dev/v1/query"
    body = json.dumps({"package": {"name": pkg, "ecosystem": ecosystem}}).encode()
    try:
        raw = http_get(url, headers={"Content-Type": "application/json"}, data=body, tries=2)
        return json.loads(raw.decode("utf-8")).get("vulns", []) or []
    except Exception as e:  # noqa: BLE001
        log(f"OSV {ecosystem}/{pkg} failed: {e}")
        return []


def osv_to_records(vulns, osv_index):
    """OSV 记录 → 统一的 CVE-ish 记录，并按 CVE/别名合并到主库"""
    for v in vulns:
        aliases = [a for a in (v.get("aliases") or []) if a.startswith("CVE-")]
        vid = v.get("id", "")
        rec = {
            "osv_id": vid,
            "summary": (v.get("summary") or "").strip(),
            "details": (v.get("details") or "").strip(),
            "ecosystem": (v.get("affected") or [{}])[0].get("package", {}).get("ecosystem", ""),
            "pkg": (v.get("affected") or [{}])[0].get("package", {}).get("name", ""),
            "aliases": v.get("aliases") or [],
            "references": [r.get("url") for r in (v.get("references") or [])],
            "published": v.get("published"),
            "modified": v.get("modified"),
            "severity": v.get("database_specific", {}).get("severity"),
            "cwe_ids": v.get("database_specific", {}).get("cwe_ids") or [],
            "affected_ranges": [],
        }
        for a in v.get("affected") or []:
            for r in a.get("ranges") or []:
                rec["affected_ranges"].append({
                    "type": r.get("type"),
                    "events": r.get("events"),
                })
        target_ids = aliases or []
        for tid in target_ids:
            osv_index.setdefault(tid, []).append(rec)
        if not aliases:
            osv_index.setdefault(vid, []).append(rec)
    return osv_index


# ==========================================================================
# 4. arXiv 论文
# ==========================================================================
ARXIV_NS = {"a": "http://www.w3.org/2005/Atom"}


def fetch_arxiv(query, max_results=60):
    url = ("http://export.arxiv.org/api/query?search_query=" + urllib.parse.quote(query) +
           f"&start=0&max_results={max_results}&sortBy=submittedDate&sortOrder=descending")
    try:
        raw = http_get(url, tries=2)
    except Exception as e:  # noqa: BLE001
        log("arXiv failed:", query, e)
        return []
    root = ET.fromstring(raw)
    out = []
    for e in root.findall("a:entry", ARXIV_NS):
        out.append({
            "title": " ".join((e.findtext("a:title", "", ARXIV_NS) or "").split()),
            "summary": " ".join((e.findtext("a:summary", "", ARXIV_NS) or "").split()),
            "url": e.findtext("a:id", "", ARXIV_NS),
            "published": (e.findtext("a:published", "", ARXIV_NS) or "")[:10],
            "authors": [" ".join((a.findtext("a:name", "", ARXIV_NS) or "").split())
                        for a in e.findall("a:author", ARXIV_NS)][:6],
            "categories": [c.get("term") for c in e.findall("a:category", ARXIV_NS)],
        })
    return out


# ==========================================================================
# AI 相关性门控 + 风险分类
# ==========================================================================
STOP = set("""a an the of in on for and or to with by from is are was were be been being this that these
those it its as at into via which who whom when where how not no such any all may can could would should
before after during under over between without within use used using allow allows attacker attackers
remote local arbitrary unauthorized improper insufficient validation version versions prior through
user users system systems via""".split())


def _tokens(text):
    return set(re.findall(r"[a-z0-9][a-z0-9\-\.\+]{1,40}", (text or "").lower()))


def classify(rec):
    """返回 (是否AI相关, 相关性分数, 风险分类, 分类依据, 标签)"""
    text = " ".join([rec.get("desc", ""), rec.get("title", ""),
                     " ".join(rec.get("products", [])), " ".join(rec.get("vendors", [])),
                     " ".join(rec.get("tags_raw", []))]).lower()

    score = 0.0
    reasons = []

    # (a) 组件命中：权重最高
    cat_votes, prod_hits = {}, []
    for p in rec.get("products", []) + rec.get("vendors", []):
        pl = p.lower()
        for name, (cat, w) in AI_PRODUCTS.items():
            if pl == name or pl.replace("_", "-") == name.replace("_", "-"):
                cat_votes[cat] = cat_votes.get(cat, 0) + w
                prod_hits.append(name)
                break

    # OSV 包名同样参与
    for pkg in rec.get("osv_packages", []):
        pl = pkg.lower()
        for name, (cat, w) in AI_PRODUCTS.items():
            if pl == name:
                cat_votes[cat] = cat_votes.get(cat, 0) + w
                prod_hits.append(name)

    if prod_hits:
        score += 0.75
        reasons.append("命中 AI 组件：" + ", ".join(sorted(set(prod_hits))[:4]))

    # (b) 描述关键词命中
    kw_hits = sorted({k for k in AI_DESC_KEYWORDS if kw_hit(k, text)})
    if kw_hits:
        score += min(0.55, 0.16 * len(kw_hits))
        reasons.append("描述含 AI 语义：" + ", ".join(kw_hits[:4]))

    # (c) CWE 指示
    for w in rec.get("cwe", []):
        if w["id"] in CWE_AI_HINT:
            cat, hint = CWE_AI_HINT[w["id"]]
            cat_votes[cat] = cat_votes.get(cat, 0) + 0.6
            score += 0.12
            reasons.append(f"{w['id']} → {hint}")

    # (d) 提示词注入等模型层行为词
    tags = []
    for k, zh in MODEL_LAYER_TAGS:
        if kw_hit(k, text):
            tags.append(zh)
            cat_votes["② 模型与数据层"] = cat_votes.get("② 模型与数据层", 0) + 0.7
            score += 0.14
    if tags:
        reasons.append("模型层风险行为：" + "、".join(sorted(set(tags))))

    score = min(score, 1.0)
    if score >= AI_RELEVANCE_THRESHOLD:
        if cat_votes:
            category = max(cat_votes.items(), key=lambda x: x[1])[0]
        else:
            category = DEFAULT_CATEGORY
        return True, round(score, 3), category, "; ".join(reasons), sorted(set(tags))

    # —— 非 AI 范畴：走通用网络安全分类（全领域扩展） ——
    g_votes, g_tags, g_reasons = {}, [], []
    for w in rec.get("cwe", []):
        wid = w["id"]
        if wid in CWE_GENERAL_HINT:
            cat, hint = CWE_GENERAL_HINT[wid]
            g_votes[cat] = g_votes.get(cat, 0) + 1.0
            g_tags.append(hint)
            g_reasons.append(f"{wid} → {hint}")
    for kw, cat, zh in GENERAL_VULN_RULES:
        if kw_hit(kw, text):
            g_votes[cat] = g_votes.get(cat, 0) + 0.6
            g_tags.append(zh)
            if len(g_reasons) < 4:
                g_reasons.append(f"描述命中「{kw}」→ {zh}")
    category = max(g_votes.items(), key=lambda x: x[1])[0] if g_votes else DEFAULT_GENERAL_CATEGORY
    if not g_reasons:
        g_reasons.append("通用网络安全情报（未命中特定弱点规则，归入默认分类）")
    return False, round(score, 3), category, "; ".join(g_reasons), sorted(set(g_tags))


def kw_hit(term, text):
    """词边界匹配，避免 dify 命中 modify / cuda 命中 barracuda 这类子串误判"""
    pat = r"(?<![a-z0-9])" + re.escape(term).replace(r"\ ", r"[\s\-_]+") + r"(?![a-z0-9])"
    return re.search(pat, text) is not None


def link_papers(rec, papers):
    """漏洞 ↔ 论文关联：基于特征词共现（可解释的关联推理）

    分级策略（用于抑制泛词造成的弱关联）：
      强特征（权重2）：漏洞自身的 AI 组件名、命中的模型层风险术语（如 prompt injection）
      弱特征（权重1）：所属风险分类的方向性词（如 inference / adversarial）
    成立条件：加权得分 ≥ 2 且至少命中 1 个强特征 ——
    即论文必须与漏洞共享一个**具体**特征，而非仅主题相近。
    """
    strong, weak = set(), set()
    for p in rec.get("products", [])[:6]:
        n = (p or "").lower().replace("_", "-")
        if n in AI_PRODUCTS:
            strong.add(n)
    text = (rec.get("desc", "") + " " + rec.get("title", "")).lower()
    for k, zh in MODEL_LAYER_TAGS:
        if kw_hit(k, text):
            strong.add(k)
    cat = rec.get("category", "")
    cat_keys = {
        "① AI基础设施与推理框架": ["inference", "serving", "inference server", "model serving",
                             "model deployment", "gpu"],
        "② 模型与数据层": ["prompt injection", "jailbreak", "poisoning", "model extraction",
                        "adversarial", "embedding", "vector database", "training data",
                        "llm security", "model weights"],
        "③ AI应用与智能体": ["llm agent", "ai agent", "tool use", "retrieval augmented",
                        "agentic", "agent security", "multi-agent"],
        "④ AI供应链与平台": ["supply chain", "third-party", "dependency", "huggingface",
                        "model hub", "package manager"],
    }.get(cat, [])
    weak.update(cat_keys)
    if not strong and not weak:
        return []
    # 必须命中强特征才可达标 —— 无强特征时直接返回，避免全量扫描论文（全领域语料下的关键提速）
    if not strong:
        return []

    denom = 2 * len(strong) + len(weak)
    scored = []
    for p in papers:
        blob = (p["title"] + " " + p.get("summary", "")[:2500]).lower()
        sh = sorted({k for k in strong if kw_hit(k, blob)})
        wh = sorted({k for k in weak if kw_hit(k, blob)})
        score = 2.0 * len(sh) + 1.0 * len(wh)
        # 必须共享具体特征，且总分达标
        if sh and score >= 2.0:
            scored.append((score, sh + wh, sh, p))
    scored.sort(key=lambda x: -x[0])
    out = []
    for sc, hits, sh, p in scored[:3]:
        out.append({
            "title": p["title"], "url": p["url"], "published": p.get("published", ""),
            "authors": p.get("authors", []), "venue": p.get("venue", ""),
            "source": p.get("source", ""),
            "summary": (p.get("summary") or "")[:420],
            "match_terms": hits, "match_score": round(min(sc / denom, 1.0), 2),
            "strong_terms": sh,
        })
    return out


def remediation(rec):
    """基于富化信息生成修复建议（可解释规则，非黑箱）"""
    steps = []
    prods = [p for p in rec.get("products", []) if p != "*"][:3]
    if rec.get("kev", {}).get("exploited"):
        steps.append(f"【紧急】该漏洞已被 CISA 列入在野利用清单"
                     f"（{rec['kev'].get('date_added','')}），须在 "
                     f"{rec['kev'].get('due_date','尽快')} 前完成处置。")
        if rec["kev"].get("required_action"):
            steps.append("官方整改要求：" + rec["kev"]["required_action"])
    if prods:
        vers = []
        for m in rec.get("cpe", []):
            if m.get("end_excl"):
                vers.append(f"< {m['end_excl']}")
            elif m.get("end_incl"):
                vers.append(f"<= {m['end_incl']}")
        vtxt = ("；受影响版本区间：" + "，".join(sorted(set(vers))[:3])) if vers else ""
        steps.append(f"升级受影响组件 {'、'.join(prods)} 至官方修复版本{vtxt}。")
    if rec.get("patch_links"):
        steps.append("官方补丁/提交：" + rec["patch_links"][0])
    if not rec.get("patch_links") and rec.get("advisory_links"):
        steps.append("厂商公告（含修复说明）：" + rec["advisory_links"][0])
    if not steps:
        steps.append("暂无官方补丁信息，建议最小化暴露面并对相关接口做输入校验与访问控制。")
    return steps


def fetch_nvd_cve(cid):
    """按 CVE 号精确抓取单条（用于 KEV 定向补充采集）"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cid)}"
    d = json.loads(http_get(url).decode("utf-8"))
    vs = d.get("vulnerabilities") or []
    return vs[0]["cve"] if vs else None


def extract_desc(c):
    for d in c.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ((c.get("descriptions") or [{}])[0]).get("value", "")


# --------------------------------------------------------------------------
# 标题派生（2026-10-07 重写）
# --------------------------------------------------------------------------
# 句末标点的判据是「[.!?] + 至少一个空白 + 下一个句子以大写字母/括号/数字开头」。
# **不能用 `desc.split(".")[0]`** —— 漏洞描述里全是版本号，第一个点几乎总是
# 版本号里的点。实测 NVD 原文
#   "IBM Langflow OSS 1.0.0 through 1.12.2 could allow a remote authenticated
#    attacker to execute arbitrary code due to ..."
# 按点切的结果是 **"IBM Langflow OSS 1"**，于是 CVE-2026-97679 / 97674 / 97671 /
# 93447 / 104335 五条不同漏洞的标题一字不差，情报列表里显示成"5 行重复条目"
# （用户截图反馈的就是这个）。
# `.+?[.!?]` 用非贪婪，取第一个**真正的**句子结尾。
_SENT_END = re.compile(r"^(.+?[.!?])\s+(?=[A-Z(\[\d])")

# 标题上限：列表行放不下，还会把正文挤没
_TITLE_MAX = 180


def short_title(cid, desc):
    """由漏洞描述派生一条**可读且唯一**的短标题。

    三条规则，每条都是踩过坑的：
      1. 句边界按「. ! ? + 空白 + 大写/数字开头」判定（见 `_SENT_END`），
         不按第 1 个点切 —— 否则版本号会把标题切成 "IBM Langflow OSS 1"。
      2. 前缀漏洞编号。即使两条 CVE 描述一字不差（NVD 里确实存在这种重复登记），
         标题也不会撞车；同时日报按标题去重时不会把两条 CVE 合并成一条
         —— 那是**静默丢情报**，比标题难看严重得多。
      3. 超长截断到 `_TITLE_MAX` 并加省略号。
    """
    s = " ".join(str(desc or "").split())
    if s:
        m = _SENT_END.match(s)
        if m:
            s = m.group(1)
    s = s.strip()
    if len(s) > _TITLE_MAX:
        s = s[:_TITLE_MAX].rstrip() + "…"
    cid = str(cid or "").strip()
    if not s:
        return cid or "(无标题)"
    if cid and not s.upper().startswith(cid.upper()):
        return "%s %s" % (cid, s)
    return s


def build_record(c, kev, osv_index, papers, extra_products=None):
    """把一条 NVD CVE 组装为完整的富化情报记录。

    AI 相关 → scope="AI安全"（四分类）；否则 → scope="通用安全"（通用七分类）。
    供全量采集、KEV 定向补充与实时增量采集共用。

    供全量采集与 KEV 定向补充采集共用。
    extra_products: 由权威外部源（如 CISA KEV 的 vendor/product 字段）确定的组件名，
                    在 AI 相关性判定前注入，避免因 NVD 缺 CPE 而漏掉真实 AI 漏洞。
    """
    cid = c.get("id")
    desc = extract_desc(c)
    cpe_items, vendors, products = parse_cpe(c)
    if extra_products:
        products = sorted(set(products) | {p for p in extra_products if p})
        vendors = sorted(set(vendors) | {v for v in extra_products if v})
    refs, poc, patch, advisory = parse_refs(c)
    cwes = parse_cwe(c)

    osv_hits = osv_index.get(cid, [])
    osv_pkgs, osv_refs, osv_summaries = [], [], []
    for o in osv_hits:
        if o.get("pkg"):
            osv_pkgs.append(o["pkg"])
        if o.get("summary"):
            osv_summaries.append(o["summary"])
        for u in o.get("references", [])[:6]:
            if u:
                osv_refs.append(u)

    rec = {
        "id": cid,
        "title": short_title(cid, desc),
        "desc": " ".join(desc.split()),
        "published": c.get("published", ""),
        "modified": c.get("lastModified", ""),
        "status": c.get("vulnStatus", ""),
        "cvss": parse_cvss(c),
        "cwe": cwes,
        "cpe": cpe_items[:40],
        "vendors": vendors[:12],
        "products": products[:12],
        "refs": refs[:40],
        "poc_links": sorted(set(poc))[:8],
        "patch_links": sorted(set(patch))[:8],
        "advisory_links": sorted(set(advisory))[:8],
        "osv_packages": sorted(set(osv_pkgs)),
        "osv_summaries": osv_summaries[:3],
        "osv_refs": sorted(set(osv_refs))[:8],
        "sources": ["NVD"] + (["OSV/GHSA"] if osv_hits else []),
        "kev": kev.get(cid, {}),
        "tags_raw": [t for r in refs for t in r["tags"]],
    }

    ok, score, cat, reason, tags = classify(rec)
    rec["scope"] = "AI安全" if ok else "通用安全"
    rec["ai_score"] = score
    rec["category"] = cat
    rec["category_reason"] = reason
    rec["risk_tags"] = tags
    rec["tags"] = tags + [cat]
    if rec["kev"]:
        rec["sources"].append("CISA KEV")
        rec["tags"].append("在野利用")
    if rec["poc_links"]:
        rec["tags"].append("存在POC")
    rec["papers"] = link_papers(rec, papers)
    if rec["papers"]:
        rec["sources"].append("arXiv")
    rec["remediation"] = remediation(rec)
    return rec


# ==========================================================================
# 主流程
# ==========================================================================
def main():
    t0 = time.time()
    log("=== 1/4 采集 NVD ===")
    cves = {}
    for i, q in enumerate(NVD_QUERIES, 1):
        try:
            d = fetch_nvd(q)
            n = 0
            for v in d.get("vulnerabilities", []):
                c = v.get("cve", {})
                cid = c.get("id")
                if cid and cid not in cves:
                    cves[cid] = c
                    n += 1
            log(f"  [{i}/{len(NVD_QUERIES)}] '{q}' total={d.get('totalResults')} new={n} pool={len(cves)}")
        except Exception as e:  # noqa: BLE001
            log(f"  [{i}/{len(NVD_QUERIES)}] '{q}' FAILED {e}")
        if i < len(NVD_QUERIES):
            time.sleep(NVD_SLEEP)
    log(f"NVD 去重后原始漏洞池：{len(cves)}")

    log("=== 2/4 采集 CISA KEV ===")
    kev = fetch_kev()

    log("=== 3/4 采集 OSV/GHSA ===")
    osv_index = {}
    for i, (eco, pkg) in enumerate(OSV_PACKAGES, 1):
        vulns = fetch_osv(pkg, eco)
        osv_to_records(vulns, osv_index)
        if i % 8 == 0:
            log(f"  [{i}/{len(OSV_PACKAGES)}] OSV 记录 {len(osv_index)}")
        time.sleep(0.4)
    log(f"OSV 索引：{len(osv_index)} 条")

    log("=== 4/4 采集 arXiv ===")
    papers, seen = [], set()
    for q in ARXIV_QUERIES:
        for p in fetch_arxiv(q):
            if p["title"] not in seen:
                seen.add(p["title"])
                papers.append(p)
        time.sleep(3.1)   # arXiv 建议 3s 间隔
    log(f"arXiv 论文：{len(papers)}")

    # ---------------- 组装 + 富化 ----------------
    log("=== 组装与富化 ===")
    records, skipped = [], 0
    for cid, c in cves.items():
        rec = build_record(c, kev, osv_index, papers)
        if rec is None:
            skipped += 1
            continue
        records.append(rec)

    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    log(f"AI 相关漏洞：{len(records)}（过滤掉 {skipped} 条非 AI 相关）")

    corpus = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "elapsed_sec": round(time.time() - t0, 1),
            "nvd_pool": len(cves),
            "records": len(records),
            "kev_total": len(kev),
            "osv_index": len(osv_index),
            "papers": len(papers),
            "sources": ["NVD", "CISA KEV", "OSV/GHSA", "arXiv"],
            "nvd_queries": NVD_QUERIES,
            "osv_packages": [f"{e}/{p}" for e, p in OSV_PACKAGES],
            "arxiv_queries": ARXIV_QUERIES,
        },
        "papers": papers,
        "records": records,
    }
    out = os.path.join(DATA_DIR, "corpus.json")
    with open(out, "w", encoding="utf-8") as f:
        # 紧凑格式（2026-09-30）：indent=1 只是好看，代价是文件从 254MB 涨到
        # 400MB+ —— json.load 解析时间、索引缓存体积、冷启动耗时全部跟着涨。
        # 要看内容用 tools 里的导出脚本，落盘一律 separators=(",", ":")。
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    log(f"写入 {out}  ({os.path.getsize(out)/1024/1024:.2f} MB)")

    # 概览
    from collections import Counter
    print("分类分布:", dict(Counter(r["category"] for r in records)))
    print("严重度分布:", dict(Counter(r["cvss"]["severity"] or "UNKNOWN" for r in records)))
    print("含POC:", sum(1 for r in records if r["poc_links"]),
          " 在野利用:", sum(1 for r in records if r["kev"]),
          " 关联论文:", sum(1 for r in records if r["papers"]))


if __name__ == "__main__":
    main()
