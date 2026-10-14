# -*- coding: utf-8 -*-
"""
poc_scraper.py —— 独立 POC/EXP 代码抓取模块
============================================
在「搜索1.1」现有代码之外，以纯 import 方式接入（不 import 本模块时，对原项目零影响）。

职责：给定一个 CVE 编号，从多个平台检索并抓取对应的 POC / EXP 代码，
统一为 ``POCResult`` 结构返回。

数据源（按优先级）：
  1. GitHub Search API —— 智能关键词扩展搜索 + 质量筛选 + POC 类型分类 + 代码抓取；
  2. Exploit-DB —— 以离线 files_exploits.csv（GitLab 官方镜像）为主；
  3. Packet Storm Security —— 作为补充来源（JS 渲染站点，尽力而为）。

深度优化（相对初版）：
  - 优化1 智能关键词扩展搜索：从 NVD 提取 产品名/漏洞类型/攻击向量/昵称，
    生成 5~8 个关键词，覆盖 CVE 编号与「log4j rce / log4shell poc」这类别名搜索；
  - 优化2 POC 类型细分类：poc_type 枚举（exploit_code/scanner/detection_script/
    environment/payload/analysis/other），规则快速分类 + DeepSeek LLM 二级精判；
  - 优化3 多维度排序：综合 可靠性×类型×代码完整性×star 归一化 评分；
  - 优化4 代码抓取增强：跳过依赖目录/二进制、50KB 截断标注、失败重试、统计；
  - 优化5 相似度去重：difflib 基于 描述+README 前 500 字符，阈值 0.8，保留高 star。

用法::
    from poc_scraper import search_poc, save_poc_results

    results = search_poc("CVE-2021-44228")   # -> List[POCResult]
    for r in results:
        print(r.source, r.poc_type, r.reliability, r.score, r.url)
    save_poc_results(results)

配置：
    同目录下的 ``poc_scraper_config.json``（可选）。结构::

        {
          "github_token": "",        # GitHub 访问令牌；留空走未认证限流(10次/分钟)
          "timeout": 15,             # 单次 HTTP 超时（秒）
          "max_results": 25,         # 每个数据源最多返回条数
          "verify_ssl": false,       # 是否校验 HTTPS 证书；内网/代理证书异常时设 false
          "deepseek_api_key": "",    # DeepSeek LLM（POC 真实性/类型精判，可选）
          "deepseek_base_url": "https://api.deepseek.com",
          "deepseek_model": "deepseek-chat",
          "github_per_query": 15,    # 每个搜索 query 取前 N 条
          "similarity_threshold": 0.8,  # 相似度去重阈值
          "max_code_files": 5,       # 每个仓库最多抓取的代码文件数
          "max_code_file_kb": 50,    # 单个代码文件最大 KB（超出截断）
          "deep_process_cap": 50     # 深处理（拉 README+代码）的最大候选仓库数
        }

依赖：
    pip install requests beautifulsoup4

设计要点：
    - 每个数据源封装为独立类，统一继承 :class:`BasePOCSearcher`；
    - 单源失败（网络/被拦截/限流）不影响其它源，逐源 try/except 隔离；
    - GitHub 对 429 响应做限流等待（Retry-After / X-RateLimit-Reset）处理；
    - 单个优化点失败不影响整体流程（异常隔离）；
    - 全模块使用 :mod:`logging` 输出日志，每个阶段打印数量变化；
    - 全部函数带类型注解与 docstring。
"""

from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import difflib
import hashlib
import io
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
# sys.path 引导必须排在三方依赖之前：否则没装 requests/bs4 时无法走降级实现。
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

try:  # 依赖降级：没装 requests 时用标准库实现（core/httpcompat.py，API 子集兼容）
    import requests
except ImportError:  # pragma: no cover - 取决于运行环境
    import httpcompat as requests  # noqa: F401

try:  # bs4 只在两处 HTML 解析里用到，缺失时给出可控降级而不是整个模块导入失败
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - 取决于运行环境
    BeautifulSoup = None


logger = logging.getLogger("poc_scraper")
# 模块被 import 时不主动配置日志（避免污染宿主进程），仅挂一个空处理器防告警。
logger.addHandler(logging.NullHandler())

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = paths.DATA_DIR
CONFIG_PATH = os.path.join(HERE, "poc_scraper_config.json")

# 主要代码文件的扩展名（用于识别「主要代码文件」与语言推断）
_CODE_EXTS = {
    ".py": "Python", ".js": "JavaScript", ".go": "Go", ".java": "Java",
    ".c": "C", ".cpp": "C++", ".h": "C/C++", ".cs": "C#", ".rb": "Ruby",
    ".php": "PHP", ".pl": "Perl", ".sh": "Shell", ".bash": "Shell",
    ".ps1": "PowerShell", ".rs": "Rust", ".lua": "Lua", ".swift": "Swift",
    ".kt": "Kotlin", ".scala": "Scala", ".ts": "TypeScript", ".sql": "SQL",
    ".yml": "YAML", ".yaml": "YAML", ".json": "JSON", ".html": "HTML",
}

# 各类 README 文件名的候选（按出现概率排序）
_README_NAMES = ("README.md", "README.rst", "README.txt", "README", "readme.md")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 AI-Sec-Intel-POC/1.0"
)


# ==========================================================================
# POC 类型枚举 与 排序权重（优化2 / 优化3）
# ==========================================================================
# 细分类：真正的利用代码、扫描器、检测脚本、环境搭建、payload、分析报告、其他
POC_TYPE_EXPLOIT = "exploit_code"        # 真正的利用代码（能直接触发漏洞）
POC_TYPE_SCANNER = "scanner"             # 漏洞扫描器/检测工具
POC_TYPE_DETECT = "detection_script"     # 检测脚本（只判断是否存在，不利用）
POC_TYPE_ENV = "environment"             # 漏洞环境搭建（docker、靶场）
POC_TYPE_PAYLOAD = "payload"             # payload/绕过词表
POC_TYPE_ANALYSIS = "analysis"           # 分析报告/技术文章（非代码）
POC_TYPE_OTHER = "other"                 # 其他

POC_TYPES = (
    POC_TYPE_EXPLOIT, POC_TYPE_SCANNER, POC_TYPE_DETECT,
    POC_TYPE_ENV, POC_TYPE_PAYLOAD, POC_TYPE_ANALYSIS, POC_TYPE_OTHER,
)

# 中文标签（用于展示/分组）
POC_TYPE_LABELS = {
    POC_TYPE_EXPLOIT: "利用代码",
    POC_TYPE_SCANNER: "扫描器",
    POC_TYPE_DETECT: "检测脚本",
    POC_TYPE_ENV: "环境搭建",
    POC_TYPE_PAYLOAD: "Payload/词表",
    POC_TYPE_ANALYSIS: "分析报告",
    POC_TYPE_OTHER: "其他",
}

# 排序权重：可靠性（优化3）
_RELIABILITY_W = {"高": 1.0, "中": 0.6, "低": 0.3}
# 排序权重：poc_type（优化3）
_POC_TYPE_W = {
    POC_TYPE_EXPLOIT: 1.0,
    POC_TYPE_PAYLOAD: 0.7,
    POC_TYPE_SCANNER: 0.5,
    POC_TYPE_DETECT: 0.4,
    POC_TYPE_ENV: 0.3,
    POC_TYPE_ANALYSIS: 0.2,
    POC_TYPE_OTHER: 0.1,
}

# 知名漏洞昵称映射（NVD 不含，人工补充，可扩展；优化1）
_KNOWN_NICKNAMES: Dict[str, List[str]] = {
    "CVE-2021-44228": ["log4shell"],
    "CVE-2014-0160": ["heartbleed"],
    "CVE-2014-6271": ["shellshock"],
    "CVE-2017-0144": ["eternalblue", "ms17-010"],
    "CVE-2017-5638": ["struts2", "struts"],
    "CVE-2021-26855": ["proxylogon"],
    "CVE-2020-1472": ["zerologon"],
    "CVE-2020-0796": ["smbghost", "coronablue"],
    "CVE-2019-0708": ["bluekeep"],
    "CVE-2021-41773": ["apache path traversal"],
}

# POC 类型规则（两级分类的第一级；顺序即优先级）
# 关键词刻意收紧：去掉 docker/lab/check/article/report 等泛化词，避免把通用仓库
# 误判为漏洞环境/分析报告。优先级按「身份信号强弱」排序：scanner/scan 是强身份
# 信号，排在 exploit 之前——否则「scanner for finding RCE」这类描述里的 rce 会把
# 扫描器误判成利用代码；POC 集合（名字含 poc）不含 scan，仍会正确落到 exploit。
_POC_TYPE_RULES: Sequence[Tuple[Tuple[str, ...], str]] = (
    (("vulhub", "靶场", "环境搭建", "复现环境", "漏洞环境", "vulnhub",
      "vulnerable environment"), POC_TYPE_ENV),
    (("scanner", "scan", "扫描器", "漏洞扫描"), POC_TYPE_SCANNER),
    (("exploit", "exploitation", "rce", "poc", "proof of concept",
      "getshell", "利用代码", "远程代码执行", "命令执行"), POC_TYPE_EXPLOIT),
    (("detector", "detection", "checker", "finder", "检测", "探测"), POC_TYPE_DETECT),
    (("wordlist", "字典", "bypass", "绕过", "payload"), POC_TYPE_PAYLOAD),
    (("writeup", "analysis", "分析", "报告", "paper"), POC_TYPE_ANALYSIS),
)


def _kw_hit(text: str, word: str) -> bool:
    """判断关键词是否命中：ASCII 用词边界，中文用子串。"""
    if word.isascii():
        return re.search(rf"\b{re.escape(word)}\b", text) is not None
    return word in text


def classify_poc_type(text: str) -> Tuple[str, float]:
    """规则快速分类（两级分类的第一级）。

    返回 ``(poc_type, confidence)``；confidence 为负数表示规则无法确定，
    需交给 LLM 精判（第二级）。
    """
    t = (text or "").lower()
    for words, typ in _POC_TYPE_RULES:
        if any(_kw_hit(t, w) for w in words):
            return typ, 0.9
    return POC_TYPE_OTHER, -1.0


# ==========================================================================
# 相关性评分（保守优化：只加字段 / 调排序，不删除、不调 LLM）
# ==========================================================================
# 官方源码组织：这些 owner 的仓库是「漏洞所在的官方源码」，不是 POC，相关性记为 0
_OFFICIAL_ORGS = {
    "apache", "microsoft", "google", "mozilla", "apple", "oracle", "adobe",
    "redhat", "ibm", "cisco", "vmware", "nginx", "openssl", "php", "python",
    "nodejs", "rust-lang", "eclipse", "jenkins", "mariadb", "postgres",
    "kubernetes", "docker", "elastic", "spring-projects", "facebook", "meta",
    "hashicorp", "grafana", "gitlab", "github",
}
# 漏洞关键词（产品名 + 这些词 → 6-8 分）
_VULN_KW = ("rce", "exploit", "vulnerability", "cve", "poc", "漏洞", "利用", "注入",
            "exp", "execution", "injection", "overflow", "disclosure", "bypass",
            "traversal")
# 通用漏洞/攻击向量词（仅这些、无产品名/CVE → 1-3 分）
_GEN_KW = ("ldap", "jndi", "rmi", "rce", "exploit", "vulnerability", "scan",
           "poc", "cve", "deserialization", "injection", "漏洞", "利用")


def _prod_hit(text: str, product: str) -> bool:
    """产品名命中：词边界或版本号后缀（log4j / log4j2）算命中，同名异项目（log4js）不算。"""
    p = re.escape(product)
    return (re.search(rf"\b{p}\b", text) is not None
            or re.search(rf"\b{p}\d", text) is not None)


def _match_tier(name: str, description: str, readme: str, code: str, cve_id: str,
                products: Sequence[str], source: str = "",
                poc_type: str = "", verified: bool = False) -> str:
    """② 精度优化：给结果打「匹配等级」，把"真 POC"和"只是提到这个组件"分开。

    A = 可确证与该 CVE 相关的利用材料
        · 官方武器化/模板库（metasploit / nuclei-templates / exploit-db / packetstorm）
        · 仓库名 或 抓到的代码里出现 CVE 编号
        · 描述/README 出现 CVE 编号，且带漏洞关键词或已被判为 POC
    B = 较可能相关（描述/README 提 CVE；或仓库名带产品名+漏洞词；或代码里出现脆弱端点/产品名）
    C = 只是"提及了该组件"的项目（README 里列了它作为依赖/接口，并非利用代码）——默认折叠
    D = 官方组件仓库 / 无关噪声 —— 默认折叠

    判据只看仓库自身内容与来源，**不依赖排序算法**，因此可用于前后精度对比。
    """
    n = (name or "").lower()
    d = (description or "").lower()
    rd = (readme or "")[:4000].lower()
    cd = (code or "")[:8000].lower()
    cve = (cve_id or "").lower()
    prods = [p.lower() for p in (products or []) if p]
    repo = n.split("/")[-1]
    src = (source or "").lower()

    # A：官方武器化 / 模板库，本身就是可利用材料
    if src in ("metasploit", "nuclei-templates", "exploit-db", "packetstorm"):
        return "A"

    # D：官方组件仓库（受影响组件本身，不是 POC）—— 用既有的官方组织名单 + 仓库名=产品名
    owner = n.split("/")[0] if "/" in n else ""
    if products and repo in prods:
        return "D"
    if owner and owner in _OFFICIAL_ORGS:
        return "D"

    cve_in_name = bool(cve and cve in n)
    cve_in_code = bool(cve and cve in cd)
    cve_in_text = bool(cve and (cve in d or cve in rd))
    prod_in_name = any(_prod_hit(n, p) for p in prods)
    prod_in_code = any(_prod_hit(cd, p) for p in prods) if prods else False
    prod_in_readme = any(_prod_hit(rd, p) for p in prods) if prods else False
    # 仓库名先做分隔符归一（_ - . → 空格），否则 \b 匹配不到 penetration_testing_poc 里的 poc
    repo_words = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", " ", repo)
    vuln_kw = any(_kw_hit(n, k) or _kw_hit(d, k) or _kw_hit(repo_words, k) for k in _VULN_KW)
    # PoC 合集型仓库（名字里就写着 poc / exploit / 复现，不带具体 CVE 号）——当作较可能相关
    poc_repo = any(_kw_hit(repo_words, k) or _kw_hit(d, k) for k in ("poc", "exploit", "vuln", "exp", "复现"))

    if cve_in_name or cve_in_code:
        return "A"
    if cve_in_text and (vuln_kw or verified or poc_repo):
        return "A"
    if cve_in_text:
        return "B"
    if (prod_in_name or prod_in_code) and vuln_kw:
        return "B"
    if poc_repo:
        return "B"
    if (prod_in_name or prod_in_code) and verified:
        return "B"
    if prod_in_name or prod_in_code or prod_in_readme:
        return "C"
    return "D"


def _relevance_score(name: str, description: str, readme: str, cve_id: str,
                     products: Sequence[str], owner: str = "") -> float:
    """规则版相关性评分（0-10，快速判断，不调 LLM，避免变慢/不稳定）。

    优先级（由高到低，命中即返回）：
    1. 官方源码仓库（owner 属官方组织，或仓库名 == 产品名）→ 0（不是 POC，沉底）
    2. 名称/描述/README 含 CVE 编号 → 10 / 9 / 8
    3. 含产品名 + 漏洞关键词 → 7；仅产品名 → 5
    4. 仅含通用漏洞词（ldap/jndi/rce 等）→ 2
    5. 其余 → 0
    """
    name_l = (name or "").lower()
    desc_l = (description or "").lower()
    readme_l = (readme or "")[:2000].lower()
    cve_l = (cve_id or "").lower()
    products_l = [p.lower() for p in (products or []) if p]
    owner_l = (owner or "").lower()
    repo_l = name_l.split("/")[-1]

    # 1) 官方源码仓库
    if owner_l in _OFFICIAL_ORGS or (products_l and repo_l in products_l):
        return 0.0

    # 2) CVE 编号命中（名称 > 描述 > README）
    if cve_l:
        if cve_l in name_l:
            return 10.0
        if cve_l in desc_l:
            return 9.0
        if cve_l in readme_l:
            return 8.0

    # 3) 产品名命中
    if any(_prod_hit(name_l, p) or _prod_hit(desc_l, p) or _prod_hit(readme_l, p)
           for p in products_l):
        has_vuln = any(_kw_hit(name_l, k) or _kw_hit(desc_l, k) for k in _VULN_KW)
        return 7.0 if has_vuln else 5.0

    # 4) 仅通用漏洞词
    if any(_kw_hit(name_l, k) or _kw_hit(desc_l, k) or _kw_hit(readme_l, k)
           for k in _GEN_KW):
        return 2.0

    return 0.0


def _nvd_products(cve_id: str, session: requests.Session, timeout: float) -> List[str]:
    """从 NVD 拉取该 CVE 的产品名列表（供非 GitHub 源做相关性评分）。

    逻辑与 GitHubPOCSearcher._fetch_cve_info 中的产品提取一致，独立实现以不改动
    既有关键词扩展流程。失败返回空列表。
    """
    products: List[str] = []
    try:
        resp = session.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id}, timeout=timeout,
        )
        if resp.status_code != 200:
            return products
        cve = (resp.json().get("vulnerabilities") or [{}])[0].get("cve", {})
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        desc_l = desc.lower()
        seen: set = set()
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    parts = (m.get("criteria") or "").split(":")
                    if len(parts) < 5 or parts[2] != "a" or parts[4] in ("-", "*", ""):
                        continue
                    prod = parts[4]
                    if prod in seen:
                        continue
                    seen.add(prod)
                    if desc_l and prod in desc_l:
                        products.append(prod)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m2_enrich/backend/poc_scraper.py:389", _sw_e)
    return products


# ==========================================================================
# 数据模型
# ==========================================================================
@dataclass
class POCResult:
    """单条 POC/EXP 抓取结果。"""

    poc_id: str                 # 唯一标识（基于 URL 的确定性哈希）
    source: str                 # 来源平台：github / exploit-db / packetstorm
    url: str                    # POC 详情/主页 URL
    title: str                  # 标题
    author: str = ""            # 作者（抓不到留空）
    code_content: str = ""      # 抓取到的代码/README 正文（抓不到留空）
    language: str = ""          # 主要语言
    verified: bool = False      # 是否可判断为已验证（如含 CVE 串 / 官方审核库）
    reliability: str = "低"     # 可靠性：高 / 中 / 低
    poc_type: str = POC_TYPE_OTHER  # POC 类型（见 POC_TYPE_* 枚举）
    stars: int = 0              # GitHub 星标数（非 GitHub 源为 0）
    score: float = 0.0          # 综合排序得分（优化3）
    relevance_score: float = 0.0  # 相关性评分 0-10（保守优化：规则判断，不调 LLM）
    match_tier: str = ""        # 匹配等级 A/B/C/D（②精度优化：A=确证 POC，C=仅提及组件，D=官方/无关）
    raw_rank: int = 0           # 抓取原始名次（用于「优化前 vs 优化后」精度对比）
    fetched_at: str = ""        # 抓取时间（ISO 本地时间）

    def to_dict(self) -> Dict[str, object]:
        """转为普通 dict（便于 JSON / 数据库落盘）。"""
        return asdict(self)


# ==========================================================================
# 工具函数
# ==========================================================================
def _now() -> str:
    """返回当前本地时间的 ISO 字符串（秒级）。"""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _make_id(source: str, url: str) -> str:
    """基于 (source, url) 生成确定性唯一 poc_id。"""
    digest = hashlib.sha1(f"{source}|{url}".encode("utf-8")).hexdigest()[:16]
    return f"{source}-{digest}"


def _lang_from_path(path: str) -> str:
    """从文件路径推断语言，无法判断返回空串。"""
    ext = os.path.splitext(path)[1].lower()
    return _CODE_EXTS.get(ext, "")


def _norm_url(url: str) -> str:
    """规范化 URL 用作去重键（去空白、去尾斜杠）。"""
    return (url or "").strip().rstrip("/")


def _yaml_field(text: str, key: str) -> str:
    """从简单 YAML 文本中提取顶层缩进字段值（用于 Nuclei 模板 info 块）。"""
    m = re.search(rf"(?m)^\s*{re.escape(key)}:\s*(.+?)\s*$", text)
    return (m.group(1).strip() if m else "")


def _first_author(author: object) -> str:
    """规范化作者字段（可能是字符串或列表），取第一作者。"""
    if isinstance(author, list) and author:
        return str(author[0])
    if isinstance(author, str):
        return author
    return ""


def _dedup(results: Sequence[POCResult]) -> List[POCResult]:
    """按 URL 去重（URL 为空时退化为 (source,title) 作为键）。"""
    seen: set = set()
    out: List[POCResult] = []
    for r in results:
        key = _norm_url(r.url) or f"{r.source}|{r.title}"
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def load_config(path: str = CONFIG_PATH) -> Dict[str, object]:
    """加载配置文件；文件不存在或解析失败时返回默认配置。"""
    default: Dict[str, object] = {
        "github_token": "",
        "timeout": 15,
        "max_results": 25,
        "verify_ssl": True,
        # 可选：DeepSeek LLM 用于 POC 真实性/类型精判（留空则仅用规则）
        "deepseek_api_key": "",
        "deepseek_base_url": "https://api.deepseek.com",
        "deepseek_model": "deepseek-chat",
        # 优化调优项
        "github_per_query": 15,      # 每个 query 取前 N 条
        "similarity_threshold": 0.8,  # 相似度去重阈值
        "max_code_files": 5,          # 每个仓库最多抓取代码文件数
        "max_code_file_kb": 50,       # 单个代码文件最大 KB
        "deep_process_cap": 50,       # 深处理候选仓库数上限
    }
    if not os.path.isfile(path):
        return dict(default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(default)
        merged.update(data or {})
        return merged
    except (OSError, ValueError) as e:  # noqa: BLE001
        logger.warning("配置文件读取失败，使用默认配置: %s", e)
        return default


# ==========================================================================
# 基类
# ==========================================================================
class BasePOCSearcher:
    """POC 数据源统一基类。

    子类只需实现 :meth:`search`；公共的 HTTP 重试 / 超时 / 429 限流处理
    统一由 :meth:`_http_get` 提供。
    """

    name: str = "base"          # 数据源名（子类覆盖）
    _UA: str = DEFAULT_UA

    def __init__(self, timeout: float = 15, max_results: int = 25,
                 verify_ssl: bool = True) -> None:
        self.timeout = timeout
        self.max_results = max_results
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self._UA})
        self.session.verify = verify_ssl
        if not verify_ssl:
            # 仅在内网/代理环境证书异常且用户主动关闭验证时，抑制不安全请求告警
            try:  # 缺失 urllib3 只影响告警抑制，不影响抓取本身
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError as _sw_e:
                _swallow("modules/m2_enrich/backend/poc_scraper.py:532", _sw_e)
            logger.warning("已关闭 SSL 证书验证（不安全，仅建议在受信任网络使用）")

    # ------------------------------------------------------------------
    def _http_get(
        self,
        url: str,
        params: Optional[Dict[str, object]] = None,
        headers: Optional[Dict[str, str]] = None,
        retries: int = 3,
        timeout: Optional[float] = None,
    ) -> Optional[requests.Response]:
        """带重试 / 超时 / 429 限流处理的 GET 请求。

        失败（网络异常、非 2xx、429 限流）会按指数退避重试；
        429 时额外读取 Retry-After / X-RateLimit-Reset 等待。最终失败返回 None。
        """
        timeout = timeout or self.timeout
        last_err: Optional[Exception] = None
        for attempt in range(retries):
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=timeout)
                if resp.status_code == 429:
                    self._handle_rate_limit(resp)
                    continue
                resp.raise_for_status()
                return resp
            except requests.exceptions.RequestException as e:  # noqa: BLE001
                last_err = e
                wait = self._backoff(attempt)
                logger.warning(
                    "%s 请求失败(%d/%d): %s，%.1fs 后重试",
                    self.name, attempt + 1, retries, e, wait,
                )
                time.sleep(wait)
        logger.error("%s 请求最终失败: %s", self.name, last_err)
        return None

    @staticmethod
    def _backoff(attempt: int) -> float:
        """指数退避：1s、2s、4s……"""
        return min(2 ** attempt, 8.0)

    def _handle_rate_limit(self, resp: requests.Response) -> None:
        """处理 429：读取等待时长并休眠（有界，避免无限等待）。"""
        wait = 0
        try:
            wait = int(resp.headers.get("Retry-After", 0))
        except ValueError:
            wait = 0
        if wait <= 0:
            try:
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                if reset:
                    wait = max(reset - int(time.time()), 1)
            except ValueError:
                wait = 0
        wait = min(max(wait, 1), 120)  # 至少 1s，最多 120s
        logger.warning("%s 触发限流(429)，等待 %ds 后重试", self.name, wait)
        time.sleep(wait)

    def _mk(self, url: str, **fields: object) -> POCResult:
        """构造 POCResult，自动填充 poc_id / fetched_at 与缺省字段。"""
        defaults: Dict[str, object] = {
            "poc_id": _make_id(self.name, url),
            "source": self.name,
            "url": url,
            "title": "",
            "fetched_at": _now(),
        }
        defaults.update(fields)
        return POCResult(**defaults)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    def search(self, cve_id: str) -> List[POCResult]:
        """检索并返回该 CVE 的 POC 结果列表（子类实现）。"""
        raise NotImplementedError


# ==========================================================================
# 数据源 1：GitHub Search API（深度优化版）
# ==========================================================================
class GitHubPOCSearcher(BasePOCSearcher):
    """GitHub POC 搜索（深度优化版）。

    流程：智能关键词扩展 → 多维度搜索 → 质量筛选 → 相似度去重 → 类型分类
    → 代码抓取 → 综合排序。完整处理 GitHub 速率限制。

    Token 读取顺序：构造参数 > 环境变量 GITHUB_TOKEN > 配置文件。
    """

    name = "github"
    _SEARCH_REPO = "https://api.github.com/search/repositories"
    _SEARCH_CODE = "https://api.github.com/search/code"
    _REPO_API = "https://api.github.com/repos"
    _NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # POC 强信号关键词（仓库名/描述/README 命中越多越可能是真 POC）
    _POC_HINT = (
        "exploit", "poc", "proof of concept", "rce", "remote code execution",
        "vulnerability", "cve", "bypass", "payload", "exploitation", "0day",
        "利用", "漏洞", "复现", "检测", "exp",
    )
    # 噪音仓库信号（文档/笔记/合集，降权）
    _NOISE_HINT = (
        "notes", "learning", "awesome", "cheatsheet", "interview", "study",
        "blog", "tutorial", "collect", "list", "面试", "笔记", "合集", "资源",
    )
    # 代码文件扩展名（用于从文件树中筛选代码文件）
    _CODE_FILE_EXTS = (
        ".py", ".sh", ".java", ".c", ".cpp", ".go", ".js", ".rb", ".php",
        ".pl", ".rs", ".cs", ".ps1", ".lua", ".ts", ".kt", ".scala", ".swift",
    )
    # 优先抓取的文件名片段
    _PRIORITY_NAME = ("exploit", "poc", "cve", "main", "exp")
    # 跳过抓取的依赖目录（优化4）
    _SKIP_DIRS = (
        "node_modules", "vendor", ".git", "dist", "build", "target",
        "__pycache__", ".idea", ".vscode",
    )

    def __init__(self, token: str = "", timeout: float = 15, max_results: int = 25,
                 verify_ssl: bool = True, llm_api_key: str = "",
                 llm_base_url: str = "", llm_model: str = "deepseek-chat",
                 per_query: int = 15, similarity_threshold: float = 0.8,
                 max_code_files: int = 5, max_code_file_kb: int = 50,
                 deep_process_cap: int = 50) -> None:
        super().__init__(timeout, max_results, verify_ssl)
        self.token = (token or os.environ.get("GITHUB_TOKEN") or "").strip()
        self.llm_api_key = (llm_api_key or os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        self.llm_base_url = llm_base_url or os.environ.get(
            "DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.llm_model = llm_model
        self.per_query = per_query
        self.similarity_threshold = similarity_threshold
        self.max_code_files = max_code_files
        self.max_code_file_kb = max_code_file_kb
        self.deep_process_cap = deep_process_cap
        self._core_exhausted = False   # 核心 API 限流标记（限流后跳过代码抓取）
        self._raw_timeout = min(timeout, 10)  # raw 抓取用更短超时，避免拖慢
        if not self.token:
            logger.warning(
                "未配置 GitHub Token，搜索/代码接口速率受限（search 10/min、core 60/h），"
                "建议通过环境变量 GITHUB_TOKEN 或配置文件配置"
            )

    # ------------------------------------------------------------------
    def _api_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "User-Agent": self._UA,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _api_get(self, url: str, params: Optional[Dict[str, object]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 retries: int = 3) -> Optional[requests.Response]:
        """GitHub API 专用 GET：在通用重试基础上，主动检查速率剩余。"""
        resp = self._http_get(url, params, headers, retries)
        if resp is not None:
            self._check_rate_limit(resp)
        return resp

    def _check_rate_limit(self, resp: requests.Response) -> None:
        """检查 X-RateLimit-Remaining，剩余过少时主动等待至重置。

        区分两类限流：搜索限流（1 分钟窗口，等待短）与核心限流（1 小时窗口，
        等待长）。核心限流时不长等待，标记 ``_core_exhausted`` 让代码抓取降级。
        """
        try:
            remaining = int(resp.headers.get("X-RateLimit-Remaining", -1))
            if 0 <= remaining <= 2:
                reset = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = max(reset - int(time.time()), 1) if reset else 60
                if wait <= 60:
                    logger.warning("GitHub 搜索限流（剩余 %d），等待 %ds 至重置", remaining, wait)
                    time.sleep(min(wait, 60))
                else:
                    self._core_exhausted = True
                    logger.warning(
                        "GitHub 核心 API 限流（剩余 %d，%ds 后重置），跳过后续代码抓取",
                        remaining, wait,
                    )
        except (ValueError, TypeError) as _sw_e:
            _swallow("modules/m2_enrich/backend/poc_scraper.py:718", _sw_e)

    # ==================================================================
    # 优化1：智能关键词扩展搜索
    # ==================================================================
    def _fetch_cve_info(self, cve_id: str) -> Dict[str, object]:
        """从 NVD 拉取漏洞元信息（标题描述 / 产品 / 漏洞类型）。失败返回空 dict。"""
        info: Dict[str, object] = {"description": "", "products": [], "types": []}
        try:
            resp = self.session.get(self._NVD_URL, params={"cveId": cve_id},
                                    timeout=self.timeout)
            if resp.status_code != 200:
                return info
            cve = (resp.json().get("vulnerabilities") or [{}])[0].get("cve", {})
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            info["description"] = desc
            desc_l = desc.lower()
            # 产品名：part=a 且出现在描述中（过滤捆绑了该组件的第三方产品）
            seen: set = set()
            for cfg in cve.get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = (m.get("criteria") or "").split(":")
                        if len(parts) < 5 or parts[2] != "a" or parts[4] in ("-", "*", ""):
                            continue
                        prod = parts[4]
                        if prod in seen:
                            continue
                        seen.add(prod)
                        if desc_l and prod in desc_l:
                            info["products"].append(prod)
            info["types"] = self._detect_vuln_types(desc_l)
        except Exception as e:  # noqa: BLE001
            logger.debug("NVD 元信息提取失败: %s", e)
        return info

    @staticmethod
    def _detect_vuln_types(text: str) -> List[str]:
        """从描述文本检测漏洞类型（rce/sqli/xss 等）。"""
        types: List[str] = []
        if "remote code execution" in text or "arbitrary code" in text or "code execution" in text:
            types.append("rce")
        if "sql injection" in text or "sqli" in text:
            types.append("sqli")
        if "cross-site scripting" in text or "xss" in text:
            types.append("xss")
        if "denial of service" in text or "denial-of-service" in text:
            types.append("dos")
        if "privilege escalation" in text:
            types.append("privesc")
        if "directory traversal" in text or "path traversal" in text:
            types.append("traversal")
        if "server-side request forgery" in text or "ssrf" in text:
            types.append("ssrf")
        if "deserialization" in text:
            types.append("deserialization")
        if "authentication bypass" in text or "auth bypass" in text:
            types.append("authbypass")
        if "buffer overflow" in text:
            types.append("overflow")
        return types

    @staticmethod
    def _extract_attack_vectors(desc: str) -> List[str]:
        """从描述提取攻击向量关键词（JNDI/LDAP 等，用于补全搜索角度）。"""
        vectors: List[str] = []
        for kw in ("jndi", "ldap", "rmi", "deserialization", "ssrf", "smb",
                   "smtp", "imap", "tcp", "udp", "dns", "xml", "yaml", "template"):
            if re.search(rf"\b{kw}\b", desc.lower()):
                vectors.append(kw)
        return vectors

    def _extract_keywords(self, cve_id: str) -> List[str]:
        """智能关键词扩展（优化1）：输入 CVE，输出 5~8 个搜索关键词。

        覆盖：CVE 编号、产品名+漏洞类型、攻击向量、别名/昵称。
        """
        info = self._fetch_cve_info(cve_id)
        self._cve_info = info  # 缓存，供 _process_repo 做相关性评分（优化：只加字段）
        desc = str(info.get("description", "") or "")
        products = list(info.get("products", []) or [])
        types = list(info.get("types", []) or [])
        nicknames = _KNOWN_NICKNAMES.get(cve_id, [])

        keywords: List[str] = []
        seen: set = set()

        def add(kw: str) -> None:
            kw = kw.strip().lower()
            if kw and kw not in seen:
                seen.add(kw)
                keywords.append(kw)

        # 1) CVE 编号（必含）
        add(cve_id.lower())
        # 2) 产品名 + 漏洞类型（如 log4j rce、log4j exploit）
        for p in products:
            add(p)
            for t in types:
                add(f"{p} {t}")
            add(f"{p} exploit")
        # 3) 攻击向量关键词（如 jndi injection、ldap rce）
        for vec in self._extract_attack_vectors(desc):
            add(vec)
            for t in types:
                add(f"{vec} {t}")
        # 4) 别名/昵称（Log4Shell 等）
        for n in nicknames:
            add(n)
            add(f"{n} exploit")
            add(f"{n} poc")
        # 5) 兜底：确保有足够的通用组合
        if len(keywords) < 5:
            add(f"{cve_id.lower()} exploit")
            add(f"{cve_id.lower()} poc")
            add(f"{cve_id.lower()} rce")
        return keywords[:8]

    def _build_queries(self, cve_id: str, keywords: List[str]) -> List[Tuple[str, str]]:
        """构建搜索 query 列表，返回 [(query, 说明)]。

        CVE 编号做字段限定（name/description/readme），其余关键词用默认搜索
        （GitHub 默认覆盖 name+desc+readme+topic）。
        """
        qual = "fork:false stars:>0 size:>0"
        cve = cve_id.lower()
        qs: List[Tuple[str, str]] = [
            (f'"{cve}" in:name {qual}', "cve-name"),
            (f'"{cve}" in:description {qual}', "cve-desc"),
            (f'"{cve}" in:readme {qual}', "cve-readme"),
        ]
        for kw in keywords:
            if kw == cve:
                continue
            qs.append((f'"{kw}" {qual}', f"kw-{kw}"))
        return qs

    def _run_queries(self, queries: List[Tuple[str, str]]) -> List[Dict[str, object]]:
        """执行多个搜索 query，按 full_name 去重；有 Token 并行，无 Token 串行+间隔。"""

        def run(ql: Tuple[str, str]) -> List[Dict[str, object]]:
            q, label = ql
            try:
                found = self._run_repo_search(q, label)
                logger.info("github query[%s] 命中 %d 条", label, len(found))
                return found
            except Exception as e:  # noqa: BLE001
                logger.error("github query[%s] 失败: %s", label, e)
                return []

        repos: Dict[str, Dict[str, object]] = {}
        if self.token:
            _w = 4
            try:               # 性能档位：低配机器上并发压到 2（GitHub API 也更易触发限流）
                from envprofile import T
                _w = T.workers(4)
            except Exception:
                pass
            with ThreadPoolExecutor(max_workers=_w) as ex:
                futs = [ex.submit(run, ql) for ql in queries]
                for fut in as_completed(futs):
                    for r in fut.result() or []:
                        repos[str(r.get("full_name", ""))] = r
        else:
            for ql in queries:
                for r in run(ql):
                    repos[str(r.get("full_name", ""))] = r
                time.sleep(0.6)  # 未认证限流严格：串行 + 间隔
        return list(repos.values())

    def _run_repo_search(self, query: str, label: str) -> List[Dict[str, object]]:
        resp = self._api_get(
            self._SEARCH_REPO,
            params={"q": query, "per_page": self.per_query,
                    "sort": "stars", "order": "desc"},
            headers=self._api_headers(),
        )
        if resp is None:
            return []
        data = resp.json()
        if not isinstance(data, dict) or "items" not in data:
            logger.warning("github query[%s] 异常响应: %s",
                           label, str(data.get("message", ""))[:120])
            return []
        return [it for it in data.get("items", []) if isinstance(it, dict)]

    def _search_code(self, cve_id: str) -> List[Dict[str, object]]:
        """search/code 端点（需认证），从代码片段结果中提取所属仓库。"""
        resp = self._api_get(self._SEARCH_CODE, params={"q": f'"{cve_id}"', "per_page": 20},
                             headers=self._api_headers())
        if resp is None:
            return []
        data = resp.json()
        if not isinstance(data, dict) or "items" not in data:
            logger.warning("github code 搜索异常响应: %s", str(data.get("message", ""))[:120])
            return []
        out: Dict[str, Dict[str, object]] = {}
        for it in data.get("items", []):
            repo = it.get("repository") if isinstance(it, dict) else None
            if isinstance(repo, dict) and repo.get("full_name"):
                out[str(repo["full_name"])] = repo
        return list(out.values())

    @staticmethod
    def _merge_repos(a: List[Dict[str, object]], b: List[Dict[str, object]]) -> List[Dict[str, object]]:
        merged: Dict[str, Dict[str, object]] = {}
        for r in a + b:
            merged[str(r.get("full_name", ""))] = r
        return list(merged.values())

    def _filter_quality(self, repos: List[Dict[str, object]]) -> List[Dict[str, object]]:
        """质量筛选：排除 fork、零 star、空仓库、纯文档/笔记仓库。"""
        kept: List[Dict[str, object]] = []
        for r in repos:
            if r.get("fork"):
                continue
            if int(r.get("stargazers_count", 0) or 0) <= 0:
                continue
            if int(r.get("size", 0) or 0) <= 0:
                continue
            blob = f"{(r.get('name') or '').lower()} {(r.get('description') or '').lower()}"
            if any(w in blob for w in self._NOISE_HINT) and not any(
                w in blob for w in ("exploit", "poc", "cve")
            ):
                continue
            kept.append(r)
        kept.sort(key=lambda r: int(r.get("stargazers_count", 0) or 0), reverse=True)
        return kept

    # ==================================================================
    # 优化5：相似度去重
    # ==================================================================
    @staticmethod
    def _sig(repo: Dict[str, object]) -> str:
        """构造去重签名：描述 + README 前 500 字符。"""
        desc = str(repo.get("description") or "")
        readme = str(repo.get("_readme") or "")[:500]
        return (desc + " " + readme).lower().strip()

    @staticmethod
    def _similar(a: str, b: str) -> float:
        """字符级相似度（difflib）。空签名兜底处理。"""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _dedup_similar(self, repos: List[Dict[str, object]]) -> Tuple[List[Dict[str, object]], int]:
        """相似度去重：保留 star 多的，过滤内容近似重复（fork/转发）。"""
        kept: List[Dict[str, object]] = []
        removed = 0
        ordered = sorted(repos, key=lambda r: int(r.get("stargazers_count", 0) or 0), reverse=True)
        for r in ordered:
            sig = self._sig(r)
            if any(self._similar(sig, self._sig(k)) > self.similarity_threshold for k in kept):
                removed += 1
            else:
                kept.append(r)
        return kept, removed

    # ==================================================================
    # 主流程
    # ==================================================================
    def search(self, cve_id: str) -> List[POCResult]:
        self._core_exhausted = False
        keywords = self._extract_keywords(cve_id)
        logger.info("关键词(%d个): %s", len(keywords), ", ".join(keywords))

        queries = self._build_queries(cve_id, keywords)
        repos = self._run_queries(queries)
        logger.info("多 query 合并去重后：%d 个仓库", len(repos))

        repos = self._filter_quality(repos)
        logger.info("质量筛选后：%d 个候选仓库", len(repos))

        # 深处理候选：按 star 取前 deep_process_cap 个，拉 README 供分类+去重
        repos.sort(key=lambda r: int(r.get("stargazers_count", 0) or 0), reverse=True)
        deep = repos[: self.deep_process_cap]
        logger.info("进入深处理 %d 个（上限 %d），拉取 README ...", len(deep), self.deep_process_cap)
        for r in deep:
            r["_readme"] = self._fetch_readme(str(r.get("full_name", "") or ""))

        kept, removed = self._dedup_similar(deep)
        logger.info("相似度去重：候选 %d → 保留 %d，去除 %d 条重复",
                    len(deep), len(kept), removed)

        stats: Dict[str, object] = {"total": 0, "code_ok": 0, "fail": {}}
        results: List[POCResult] = []
        for repo in kept[: self.max_results]:
            try:
                r = self._process_repo(repo, cve_id, stats)
                if r is not None:
                    results.append(r)
            except Exception as e:  # noqa: BLE001 —— 单仓库失败不影响其它
                logger.warning("处理仓库失败 %s: %s", repo.get("full_name", "?"), e)

        total = int(stats["total"])
        code_ok = int(stats["code_ok"])
        rate = (100.0 * code_ok / total) if total else 0.0
        logger.info("代码抓取：共 %d 个仓库，成功 %d（%.0f%%），失败 %d，原因分布 %s",
                    total, code_ok, rate, total - code_ok, stats["fail"])
        logger.info("github 最终 %d 个 POC", len(results))
        return results

    def _process_repo(self, repo: Dict[str, object], cve_id: str,
                      stats: Dict[str, object]) -> Optional[POCResult]:
        full_name = str(repo.get("full_name", "") or "")
        html_url = str(repo.get("html_url", "") or "")
        description = str(repo.get("description") or "")
        owner = repo.get("owner")
        author = str(owner.get("login", "") if isinstance(owner, dict) else "")
        language = str(repo.get("language") or "")
        stars = int(repo.get("stargazers_count", 0) or 0)
        readme = str(repo.get("_readme", "") or "")

        # 优化2：类型分类（规则一级 + LLM 二级）
        poc_type, conf = classify_poc_type(f"{full_name} {description} {readme[:2000]}")
        is_poc, reliability = self._judge_poc(full_name, description, readme, cve_id)
        if self.llm_api_key and conf < 0:
            llm = self._llm_analyze(full_name, description, readme, cve_id)
            if llm:
                is_poc = bool(llm.get("is_poc", is_poc))
                poc_type = str(llm.get("poc_type", poc_type))
                reliability = str(llm.get("reliability", reliability))

        # 优化4：代码抓取（所有候选都抓，最大化代码覆盖率）
        code_content, reason = self._fetch_code(full_name)
        stats["total"] = int(stats.get("total", 0)) + 1
        if code_content:
            stats["code_ok"] = int(stats.get("code_ok", 0)) + 1
        else:
            fails = stats.setdefault("fail", {})
            if isinstance(fails, dict):
                fails[reason or "未知"] = int(fails.get(reason or "未知", 0)) + 1

        # 相关性评分（保守优化）：规则判断 0-10，不调 LLM，不改既有分类/抓取逻辑
        products = list(getattr(self, "_cve_info", {}).get("products", []) or [])
        rel = _relevance_score(full_name, description, readme, cve_id, products, author)
        # ② 精度优化：匹配等级（用 README + 抓到的代码做判据，比只按分数排更准）
        tier = _match_tier(full_name, description, readme, code_content, cve_id, products,
                           source="github", poc_type=poc_type, verified=is_poc)

        return self._mk(
            html_url,
            title=full_name or description or html_url,
            author=author,
            code_content=code_content,
            language=language,
            verified=is_poc,
            reliability=reliability,
            poc_type=poc_type,
            stars=stars,
            relevance_score=rel,
            match_tier=tier,
        )

    def _judge_poc(self, full_name: str, description: str, readme: str,
                   cve_id: str) -> Tuple[bool, str]:
        """判断是否真 POC，返回 (is_poc, reliability)。"""
        blob = f"{full_name.lower()} {(description or '').lower()} {(readme or '')[:3000].lower()}"
        hint_hits = [w for w in self._POC_HINT if w in blob]
        cve_hit = cve_id.lower() in blob

        is_poc = bool(cve_hit and hint_hits)
        reliability = "中" if (is_poc and len(hint_hits) >= 2) else "低"
        return is_poc, reliability

    def _llm_analyze(self, full_name: str, description: str, readme: str,
                     cve_id: str) -> Optional[Dict[str, object]]:
        """DeepSeek 二级分类：统一判断 is_poc/poc_type/reliability/confidence。"""
        prompt = (
            f"分析以下 GitHub 仓库与漏洞 {cve_id} 的关系并分类。\n"
            f"仓库名: {full_name}\n描述: {description}\nREADME 摘要: {readme[:1500]}\n\n"
            '只输出 JSON，字段：'
            '{"is_poc": true/false, '
            '"poc_type": "exploit_code/scanner/detection_script/environment/payload/analysis/other", '
            '"reliability": "高/中/低", "confidence": 0.0~1.0, "reason": "判断理由"}'
        )
        try:
            resp = self.session.post(
                f"{self.llm_base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.llm_api_key}",
                         "Content-Type": "application/json"},
                json={"model": self.llm_model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0,
                      "response_format": {"type": "json_object"}},
                timeout=30,
            )
            if resp.status_code != 200:
                logger.debug("LLM 返回 %d", resp.status_code)
                return None
            return json.loads(resp.json()["choices"][0]["message"]["content"])
        except Exception as e:  # noqa: BLE001
            logger.debug("LLM 分析失败: %s", e)
            return None

    # ==================================================================
    # 优化4：代码抓取增强
    # ==================================================================
    def _is_code_file(self, path: str) -> bool:
        """判断是否为应抓取的代码文件（跳过依赖目录/二进制/图片）。"""
        pl = path.lower()
        if any(seg in pl for seg in self._SKIP_DIRS):
            return False
        return os.path.splitext(pl)[1] in self._CODE_FILE_EXTS

    def _code_priority(self, path: str) -> Tuple[int, int]:
        """代码文件优先级：exploit/poc/cve/main 靠前，文件名短者优先。"""
        base = os.path.basename(path).lower()
        return (0 if any(p in base for p in self._PRIORITY_NAME) else 1, -len(base))

    def _fetch_code(self, full_name: str) -> Tuple[str, str]:
        """抓取仓库代码文件内容。返回 (code_content, reason)，reason 空表示成功。"""
        files = self._fetch_tree_files(full_name)
        if not files:
            return "", "无文件树(空仓库或 trees API 受限)"
        code_files = [f for f in files if self._is_code_file(f)]
        if not code_files:
            return "", "无代码文件(仓库可能为文档/配置类)"
        code_files.sort(key=self._code_priority)
        maxb = self.max_code_file_kb * 1024
        chunks: List[str] = []
        for f in code_files[: self.max_code_files]:
            content = self._fetch_raw_file(full_name, f)
            if not content:
                continue
            if len(content) > maxb:
                content = content[:maxb] + (
                    f"\n// [文件截断：原始 {len(content)} 字节 > {self.max_code_file_kb}KB]"
                )
            chunks.append(f"// ---- {f} ----\n{content}")
        if not chunks:
            return "", "代码文件下载失败"
        return "\n\n".join(chunks)[:120000], ""

    def _fetch_tree_files(self, full_name: str) -> List[str]:
        """通过 git trees API 获取仓库文件列表（recursive，直接用 HEAD 引用）。"""
        if self._core_exhausted:
            return []
        url = f"{self._REPO_API}/{full_name}/git/trees/HEAD"
        resp = self._api_get(url, params={"recursive": "1"},
                             headers=self._api_headers(), retries=2)
        if resp is None:
            return []
        try:
            tree = resp.json().get("tree", [])
        except ValueError:
            return []
        return [str(t.get("path", "")) for t in tree
                if t.get("type") == "blob" and t.get("size", 0)]

    def _fetch_readme(self, full_name: str) -> str:
        """从 raw.githubusercontent.com 抓取 README（不受 API 限流）。"""
        if not full_name:
            return ""
        for name in _README_NAMES:
            raw = f"https://raw.githubusercontent.com/{full_name}/HEAD/{name}"
            try:
                resp = self.session.get(raw, timeout=self._raw_timeout)
                if resp.status_code == 200 and resp.text.strip():
                    return resp.text[:60000]
            except requests.exceptions.RequestException as e:  # noqa: BLE001
                logger.debug("抓取 README 失败 %s/%s: %s", full_name, name, e)
        return ""

    def _fetch_raw_file(self, full_name: str, path: str) -> str:
        """从 raw.githubusercontent.com 抓取单文件（多分支尝试 + 失败重试）。

        404=路径变了直接跳过；403=限流等 1s 重试。
        """
        for ref in ("HEAD", "main", "master"):
            raw = f"https://raw.githubusercontent.com/{full_name}/{ref}/{path}"
            for _ in range(2):
                try:
                    resp = self.session.get(raw, timeout=self._raw_timeout)
                    if resp.status_code == 200:
                        return resp.text
                    if resp.status_code == 404:
                        break
                    if resp.status_code == 403:
                        time.sleep(1)
                        continue
                    break
                except requests.exceptions.RequestException:  # noqa: BLE001
                    time.sleep(1)
        return ""


# 向后兼容别名
GitHubSearcher = GitHubPOCSearcher


# ==========================================================================
# 数据源 2：Exploit-DB
# ==========================================================================
class ExploitDBSearcher(BasePOCSearcher):
    """Exploit-DB 漏洞利用代码库。

    主路径：解析官方 GitLab 镜像的 ``files_exploits.csv``（本地缓存），按 CVE
    过滤。Exploit-DB 为人工审核库，结果标记 verified=True、reliability=高、
    poc_type=exploit_code。
    """

    name = "exploit-db"
    # 官方 GitLab 镜像（GitHub 仓库 master 分支已无此 CSV，需用 GitLab main 分支）
    _CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    _RAW_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
    _CACHE = os.path.join(DATA_DIR, "exploitdb_files.csv")

    def __init__(self, timeout: float = 15, max_results: int = 25,
                 cache_path: str = _CACHE, verify_ssl: bool = True) -> None:
        super().__init__(timeout, max_results, verify_ssl)
        self.cache_path = cache_path

    # ------------------------------------------------------------------
    def search(self, cve_id: str) -> List[POCResult]:
        results = self._search_offline(cve_id)
        logger.info("exploit-db 命中 %d 条", len(results))
        return results

    def _load_csv_rows(self) -> List[Dict[str, str]]:
        """加载（或下载并缓存）files_exploits.csv，返回行列表。"""
        if not os.path.isfile(self.cache_path):
            logger.info("下载 Exploit-DB files_exploits.csv ...")
            resp = self._http_get(self._CSV_URL, retries=2)
            if resp is None:
                return []
            try:
                os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    f.write(resp.text)
            except OSError as e:  # noqa: BLE001
                logger.warning("缓存 CSV 失败: %s", e)
        try:
            with open(self.cache_path, "r", encoding="utf-8", errors="replace") as f:
                return list(csv.DictReader(f))
        except OSError as e:  # noqa: BLE001
            logger.warning("读取 CSV 失败: %s", e)
            return []

    def _search_offline(self, cve_id: str) -> List[POCResult]:
        results: List[POCResult] = []
        needle = cve_id.lower()
        # 相关性评分需产品名（区分「Log4j 2 - RCE」与「AD Manager Plus - RCE」误标）
        products = _nvd_products(cve_id, self.session, self.timeout)
        for row in self._load_csv_rows():
            eid = (row.get("id") or "").strip()
            file_path = (row.get("file") or "").strip()
            description = (row.get("description") or "").strip()
            # CVE 编号主要位于 codes 列，辅以 description/file/tags 兜底
            haystack = " ".join(
                row.get(k) or "" for k in ("codes", "description", "file", "tags", "aliases")
            ).lower()
            if needle not in haystack:
                continue
            if not eid or not file_path:
                continue
            code = self._fetch_raw(file_path)
            results.append(self._mk(
                f"https://www.exploit-db.com/exploits/{eid}",
                title=description or f"Exploit-DB {eid}",
                author=(row.get("author") or "").strip(),
                code_content=code,
                language=_lang_from_path(file_path),
                verified=True,
                reliability="高",
                poc_type=POC_TYPE_EXPLOIT,
                relevance_score=_relevance_score("", description, "", cve_id, products),
            ))
            if len(results) >= self.max_results:
                break
        return results

    def _fetch_raw(self, file_path: str) -> str:
        """从 GitLab 镜像抓取漏洞利用代码原文。"""
        if not file_path:
            return ""
        resp = self._http_get(self._RAW_BASE + file_path.lstrip("/"), retries=1)
        return (resp.text[:60000]) if resp is not None else ""


# ==========================================================================
# 数据源 3：Packet Storm Security
# ==========================================================================
class PacketStormSearcher(BasePOCSearcher):
    """Packet Storm Security 补充来源。

    尝试 CVE 标签页 ``/files/cve/{CVE}`` 与搜索页，解析文件列表并抓取下载原文。
    注意：该站点近年改为 JavaScript 渲染搜索结果，静态抓取可能拿不到数据；
    本类尽力而为，站点结构变动 / 被拦截时静默降级（仅返回 URL/标题或空列表）。
    """

    name = "packetstorm"
    _BASE = "https://packetstormsecurity.com"

    def __init__(self, timeout: float = 15, max_results: int = 25,
                 verify_ssl: bool = True) -> None:
        super().__init__(timeout, max_results, verify_ssl)

    # ------------------------------------------------------------------
    def search(self, cve_id: str) -> List[POCResult]:
        results: List[POCResult] = []
        for url in (
            f"{self._BASE}/files/cve/{cve_id}",
            f"{self._BASE}/search/?q={cve_id}",
        ):
            if len(results) >= self.max_results:
                break
            results.extend(self._parse_page(url))
        logger.info("packetstorm 命中 %d 条", len(results))
        return results[: self.max_results]

    def _parse_page(self, url: str) -> List[POCResult]:
        resp = self._http_get(url, retries=1)
        if resp is None:
            return []
        if BeautifulSoup is None:  # 未装 bs4：HTML 解析跳过，其余数据源照常工作
            logger.warning("未安装 beautifulsoup4，跳过 PacketStorm 页面解析"
                           "（pip install beautifulsoup4 可恢复该源）")
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        results: List[POCResult] = []
        seen: set = set()
        for a in soup.select("a[href]"):
            href = a.get("href", "") or ""
            if "/files/download/" in href or "/files/tags/" in href:
                continue
            m = re.search(r"/files/(\d+)", href)
            if not m:
                continue
            detail_url = href if href.startswith("http") else self._BASE + href
            if detail_url in seen:
                continue
            seen.add(detail_url)
            title = a.get_text(" ", strip=True)
            if not title or len(title) < 3:
                continue
            code, author = self._fetch_detail(detail_url)
            poc_type, _ = classify_poc_type(title)
            results.append(self._mk(
                detail_url,
                title=title,
                author=author,
                code_content=code,
                language=_lang_from_path(title),
                verified=bool(code),
                reliability="中" if code else "低",
                poc_type=poc_type,
                # Packet Storm 按 CVE 页面/检索命中，属 CVE 直接相关来源
                relevance_score=9.0,
            ))
            if len(results) >= self.max_results:
                break
        return results

    def _fetch_detail(self, detail_url: str) -> Tuple[str, str]:
        """抓取详情页，返回 (代码原文, 作者)。抓不到时返回空。"""
        resp = self._http_get(detail_url, retries=1)
        if resp is None:
            return "", ""
        if BeautifulSoup is None:  # 未装 bs4：退化为纯文本抽取（正文仍可用）
            return (resp.text or "")[:60000], ""
        soup = BeautifulSoup(resp.text, "html.parser")
        author = ""
        for meta in soup.select('meta[name="author"]'):
            author = meta.get("content", "") or ""
            break
        for a in soup.select("a[href]"):
            href = a.get("href", "") or ""
            if "/files/download/" not in href:
                continue
            dl_url = href if href.startswith("http") else self._BASE + href
            r = self._http_get(dl_url, retries=1)
            if r is not None and r.text.strip():
                return r.text[:60000], author
        return "", author


# ==========================================================================
# 数据源 4：Nuclei Templates（检测模板）
# ==========================================================================
class NucleiTemplatesSearcher(BasePOCSearcher):
    """Nuclei 检测模板（ProjectDiscovery nuclei-templates 仓库）。

    模板按 CVE 编号路径化存储（``http/cves/{year}/CVE-{id}.yaml``），因此无需
    GitHub 搜索 API，直接经 raw.githubusercontent.com 预测路径抓取，不消耗 API
    配额。Nuclei 模板为「检测」性质，标记 poc_type=detection_script、reliability=高。
    """

    name = "nuclei-templates"
    _RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates"

    def __init__(self, timeout: float = 15, max_results: int = 25,
                 verify_ssl: bool = True) -> None:
        super().__init__(timeout, max_results, verify_ssl)

    # ------------------------------------------------------------------
    def search(self, cve_id: str) -> List[POCResult]:
        m = re.match(r"CVE-(\d{4})-\d+", cve_id)
        if not m:
            return []
        year = m.group(1)
        # 新旧目录结构都尝试：main/http/cves/ 与 master/cves/
        candidates = (
            f"{self._RAW_BASE}/main/http/cves/{year}/{cve_id}.yaml",
            f"{self._RAW_BASE}/master/cves/{year}/{cve_id}.yaml",
        )
        for url in candidates:
            text = self._fetch_raw(url)
            if text:
                logger.info("nuclei-templates 命中 1 条")
                return [self._to_result(cve_id, url, text)]
        logger.info("nuclei-templates 命中 0 条")
        return []

    def _fetch_raw(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and resp.text.strip():
                return resp.text
        except requests.exceptions.RequestException as e:  # noqa: BLE001
            logger.debug("抓取 nuclei 模板失败 %s: %s", url, e)
        return ""

    def _to_result(self, cve_id: str, url: str, text: str) -> POCResult:
        name = _yaml_field(text, "name") or f"{cve_id} Nuclei 检测模板"
        severity = _yaml_field(text, "severity") or ""
        author = _yaml_field(text, "author") or ""
        title = f"{name} ({severity})" if severity else name
        return self._mk(
            url,
            title=title,
            author=author,
            code_content=text,
            language="yaml",
            verified=True,
            reliability="高",
            poc_type=POC_TYPE_DETECT,
            # 模板路径即 CVE-{id}.yaml，与该 CVE 严格对应
            relevance_score=10.0,
        )


# ==========================================================================
# 数据源 5：Metasploit Framework（利用模块）
# ==========================================================================
class MetasploitSearcher(BasePOCSearcher):
    """Metasploit Framework 利用模块（rapid7/metasploit-framework 仓库）。

    通过仓库内 ``db/modules_metadata_base.json``（模块元数据索引，含 CVE 引用）
    建立 CVE → 模块映射，再经 raw.githubusercontent.com 抓取模块 Ruby 源码。
    索引一次性下载并本地缓存（与 Exploit-DB CSV 同一模式），不消耗 GitHub API 配额。
    """

    name = "metasploit"
    _META_URL = ("https://raw.githubusercontent.com/rapid7/metasploit-framework/"
                 "master/db/modules_metadata_base.json")
    _RAW_BASE = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master"
    _CACHE = os.path.join(DATA_DIR, "metasploit_modules_metadata.json")

    def __init__(self, timeout: float = 15, max_results: int = 25,
                 verify_ssl: bool = True, cache_path: str = _CACHE) -> None:
        super().__init__(timeout, max_results, verify_ssl)
        self.cache_path = cache_path

    # ------------------------------------------------------------------
    def search(self, cve_id: str) -> List[POCResult]:
        meta = self._load_meta()
        if not meta:
            return []
        results: List[POCResult] = []
        for fullname, mod in meta.items():
            if not isinstance(mod, dict):
                continue
            refs = mod.get("references")
            if not isinstance(refs, list) or cve_id not in refs:
                continue
            path = str(mod.get("path") or "").strip()
            code = self._fetch_module(path) if path else ""
            title = str(mod.get("name") or fullname)
            mtype = str(mod.get("type") or "")
            if mtype == "exploit":
                poc_type = POC_TYPE_EXPLOIT
            elif mtype in ("auxiliary", "post", "scanner"):
                poc_type = POC_TYPE_DETECT
            else:
                poc_type = POC_TYPE_OTHER
            results.append(self._mk(
                f"https://github.com/rapid7/metasploit-framework/blob/master{path}",
                title=title,
                author=_first_author(mod.get("author")),
                code_content=code,
                language="ruby",
                verified=bool(code),
                reliability="高" if code else "中",
                poc_type=poc_type,
                # 命中依据为模块 references 中的 CVE 引用，严格对应
                relevance_score=10.0,
            ))
            if len(results) >= self.max_results:
                break
        logger.info("metasploit 命中 %d 条", len(results))
        return results

    def _load_meta(self) -> Dict[str, object]:
        if not os.path.isfile(self.cache_path):
            logger.info("下载 Metasploit 模块元数据索引 ...")
            try:
                resp = self.session.get(self._META_URL, timeout=max(self.timeout, 30))
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, dict):
                    return {}
                os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False)
            except (requests.exceptions.RequestException, ValueError, OSError) as e:  # noqa: BLE001
                logger.warning("下载 Metasploit 元数据失败: %s", e)
                return {}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError) as e:  # noqa: BLE001
            logger.warning("读取 Metasploit 元数据失败: %s", e)
            return {}

    def _fetch_module(self, path: str) -> str:
        if not path:
            return ""
        try:
            resp = self.session.get(f"{self._RAW_BASE}{path}", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text[:60000]
        except requests.exceptions.RequestException as e:  # noqa: BLE001
            logger.debug("抓取 Metasploit 模块失败 %s: %s", path, e)
        return ""


# ==========================================================================
# 统一入口
# ==========================================================================
def _default_searchers(cfg: Dict[str, object]) -> List[BasePOCSearcher]:
    """根据配置构建默认数据源列表。

    优先级：github > exploit-db > packetstorm > nuclei-templates > metasploit。
    """
    timeout = float(cfg.get("timeout", 15) or 15)
    max_results = int(cfg.get("max_results", 25) or 25)
    token = str(cfg.get("github_token", "") or "")
    verify_ssl = bool(cfg.get("verify_ssl", True))
    return [
        GitHubPOCSearcher(
            token=token, timeout=timeout, max_results=max_results, verify_ssl=verify_ssl,
            llm_api_key=str(cfg.get("deepseek_api_key", "") or ""),
            llm_base_url=str(cfg.get("deepseek_base_url", "") or ""),
            llm_model=str(cfg.get("deepseek_model", "deepseek-chat") or "deepseek-chat"),
            per_query=int(cfg.get("github_per_query", 15) or 15),
            similarity_threshold=float(cfg.get("similarity_threshold", 0.8) or 0.8),
            max_code_files=int(cfg.get("max_code_files", 5) or 5),
            max_code_file_kb=int(cfg.get("max_code_file_kb", 50) or 50),
            deep_process_cap=int(cfg.get("deep_process_cap", 50) or 50),
        ),
        ExploitDBSearcher(timeout=timeout, max_results=max_results, verify_ssl=verify_ssl),
        PacketStormSearcher(timeout=timeout, max_results=max_results, verify_ssl=verify_ssl),
        NucleiTemplatesSearcher(timeout=timeout, max_results=max_results, verify_ssl=verify_ssl),
        MetasploitSearcher(timeout=timeout, max_results=max_results, verify_ssl=verify_ssl),
    ]


def _score_results(results: List[POCResult], cve_id: str = "") -> List[POCResult]:
    """优化3：多维度综合评分并降序排序。

    得分 = 0.4×可靠性 + 0.3×类型权重 + 0.15×代码完整性 + 0.15×star 归一化。
    star 归一化：log(star+1) / log(max_star+1)。

    ② 精度优化：排序以「匹配等级」为第一关键字（A 确证 POC > B 较可能 > C 仅提及组件 > D 官方/噪声），
    再按 relevance_score、综合得分、star 排序；同时记录 raw_rank（优化前的原始名次）
    以便用同一批数据做「优化前 vs 优化后」精度对比。
    """
    if not results:
        return results
    for i, r in enumerate(results, 1):
        r.raw_rank = i
        if not r.match_tier:
            r.match_tier = _match_tier(r.title, "", "", r.code_content, cve_id,
                                       [], source=r.source, poc_type=r.poc_type,
                                       verified=r.verified)
    max_star = max((r.stars for r in results), default=0)
    for r in results:
        rel = _RELIABILITY_W.get(r.reliability, 0.3)
        typ = _POC_TYPE_W.get(r.poc_type, 0.1)
        code = 1.0 if r.code_content else 0.3
        star_norm = (math.log(r.stars + 1) / math.log(max_star + 1)) if max_star > 0 else 0.0
        r.score = round(0.4 * rel + 0.3 * typ + 0.15 * code + 0.15 * star_norm, 4)
    tier_rank = {"A": 0, "B": 1, "C": 2, "D": 3, "": 4}
    return sorted(results, key=lambda r: (tier_rank.get(r.match_tier, 4),
                                          -r.relevance_score, -r.score, -r.stars))


def search_poc(
    cve_id: str,
    searchers: Optional[Sequence[BasePOCSearcher]] = None,
    config: Optional[Dict[str, object]] = None,
) -> List[POCResult]:
    """统一入口：检索某 CVE 对应的 POC/EXP 信息列表。

    :param cve_id: CVE 编号，如 ``"CVE-2021-44228"``（自动转大写）。
    :param searchers: 自定义数据源列表；缺省按优先级构造
        github/exploit-db/packetstorm/nuclei-templates/metasploit。
    :param config: 配置字典；缺省从 ``poc_scraper_config.json`` 读取。
    :return: 去重、综合评分、降序排序后的 POC 结果列表。单源失败不影响其它源。
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id:
        logger.warning("search_poc 收到空 CVE 编号")
        return []

    if searchers is None:
        searchers = _default_searchers(config or load_config())

    collected: List[POCResult] = []
    for searcher in searchers:
        try:
            collected.extend(searcher.search(cve_id) or [])
        except Exception as e:  # noqa: BLE001 —— 单源失败不影响其它源
            logger.error("数据源 %s 异常，已跳过: %s", getattr(searcher, "name", searcher), e)

    before_dedup = len(collected)
    result = _dedup(collected)  # URL 精确去重
    if before_dedup != len(result):
        logger.info("URL 精确去重：%d → %d（去除 %d）",
                    before_dedup, len(result), before_dedup - len(result))
    result = _score_results(result, cve_id)
    logger.info("search_poc(%s) 共 %d 条结果（去重+评分排序后）", cve_id, len(result))
    return result


# ==========================================================================
# 持久化
# ==========================================================================
def save_poc_results(
    results: Sequence[POCResult],
    path: Optional[str] = None,
    merge: bool = True,
) -> str:
    """将 POC 结果持久化为 JSON 文件。

    本项目当前没有关系型数据库，语料/缓存均采用 JSON 文件；本函数遵循同一
    规范，写入 ``data/poc_results.json``。:param merge: 为 True 时与已有文件
    按 URL 合并去重后落盘。

    :return: 实际写入的文件路径。
    """
    path = path or os.path.join(DATA_DIR, "poc_results.json")
    existing: List[Dict[str, object]] = []
    if merge and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (OSError, ValueError) as e:  # noqa: BLE001
            logger.warning("读取已有结果失败，忽略: %s", e)

    merged = _dedup([
        POCResult(**r) for r in existing if isinstance(r, dict)
    ] + list(results))  # type: ignore[arg-type]

    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = [r.to_dict() for r in merged]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logger.info("已保存 %d 条 POC 结果到 %s", len(payload), path)
    return path


def save_poc_results_db(
    results: Sequence[POCResult],
    db_path: Optional[str] = None,
) -> str:
    """将 POC 结果写入 SQLite 数据库（标准库 sqlite3，零额外依赖）。

    供需要结构化查询/去重场景使用；本项目默认仍用 JSON（见
    :func:`save_poc_results`）。表结构按 POCResult 字段一一对应，URL 唯一。

    :return: 数据库文件路径。
    """
    import sqlite3

    db_path = db_path or os.path.join(DATA_DIR, "poc_results.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS poc_results (
                poc_id TEXT PRIMARY KEY,
                source TEXT, url TEXT UNIQUE, title TEXT, author TEXT,
                code_content TEXT, language TEXT, verified INTEGER,
                reliability TEXT, poc_type TEXT, stars INTEGER, score REAL,
                relevance_score REAL, fetched_at TEXT
            )
            """
        )
        # 兼容旧库：缺失新列时补上（忽略已存在错误）
        for col, ddl in (
            ("poc_type", "TEXT"), ("stars", "INTEGER"), ("score", "REAL"),
            ("relevance_score", "REAL"),
        ):
            try:
                conn.execute(f"ALTER TABLE poc_results ADD COLUMN {col} {ddl}")
            except sqlite3.OperationalError as _sw_e:
                _swallow("modules/m2_enrich/backend/poc_scraper.py:1729", _sw_e)
        for r in results:
            conn.execute(
                """
                INSERT OR REPLACE INTO poc_results
                (poc_id, source, url, title, author, code_content,
                 language, verified, reliability, poc_type, stars, score,
                 relevance_score, fetched_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    r.poc_id, r.source, r.url, r.title, r.author,
                    r.code_content, r.language, int(r.verified),
                    r.reliability, r.poc_type, r.stars, r.score,
                    r.relevance_score, r.fetched_at,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    logger.info("已写入 %d 条 POC 结果到 SQLite %s", len(results), db_path)
    return db_path


# ==========================================================================
# 演示 / 自测入口
# ==========================================================================
if __name__ == "__main__":
    import sys
    _sys_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stdout = _sys_stdout  # noqa: F401
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    demo_cve = "CVE-2021-44228"
    print(f"=== 演示：search_poc({demo_cve}) ===")
    _t0 = time.time()
    rs = search_poc(demo_cve)
    print(f"耗时 {time.time() - _t0:.1f}s，共 {len(rs)} 条结果\n")
    for _i, _r in enumerate(rs, 1):
        print(f"[{_i}] {_r.source:12s} type={_r.poc_type:16s} "
              f"可靠性={_r.reliability} 得分={_r.score:.3f} verified={_r.verified}")
        print(f"    {_r.title[:90]}")
        print(f"    {_r.url}")
        if _r.code_content:
            print(f"    code_content {len(_r.code_content)} 字符")
        print()
    if rs:
        print("保存 JSON:", save_poc_results(rs))
