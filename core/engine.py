# -*- coding: utf-8 -*-
"""
engine.py —— 可解释的混合检索引擎
====================================
面向 AI 安全情报的自然语言检索，四层打分：

  L1 词法层  字段加权 BM25（CVE号/产品/CWE/描述/参考链接 权重差异化）
  L2 短语层  领域术语短语命中加成（"prompt injection" 视为一个原子证据）
  L3 概念层  领域本体概念空间匹配 —— 用 taxonomy.SYNONYMS 的别名组作为概念维度，
             查询与文档在同一概念上激活即得分（解决中英/同义/上下位的语义鸿沟）
  L4 排序层  业务信号微调（CVSS / 在野利用 / POC / 时效），权重受限以保证相关性主导

查询理解增强（2026-09）：
  · 结构化算子  product:/vendor:/cwe:/severity:/cvss>=9/year:2024-2025/kev:yes 等，
                支持 -算子 取反，纯算子查询进入「结构化筛选」浏览模式
  · 否定项      -term / -"短语"（结果必须不含）
  · 通配符      prompt* / *jail*（对索引词典展开，限量注入词法层）
  · 拼写容错    OOV 词对索引词典做编辑距离模糊匹配，低权重召回 + did-you-mean
  · 时效微调    近 1.5 年条目按半衰期小幅加成（上限 +10%，相关性仍主导）

并输出：意图识别、查询扩展轨迹、命中证据、高亮片段、维度聚合 —— 全部可回溯。
"""

import math
import os
import re
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime, timezone

# 引擎写入锁：add_documents / update_documents 会一边改 self.df 一边在 _recompute_stats
# 里迭代 self.df；快车道实时轮询（每 15s）与「提交链接即时收录」等会并发调用它们，
# 不加锁就会 RuntimeError: dictionary changed size during iteration。所有写操作串行化。
_WRITE_LOCK = threading.RLock()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from taxonomy import (  # noqa: E402
    SYNONYMS, EN_EXTRA, INTENT_RULES, DEFAULT_INTENT, INTENT_FIELD_BIAS,
    FIELD_WEIGHTS, RISK_CATEGORIES, AI_PRODUCTS,
    RISK_SUBCATEGORIES, subclassify,   # P0-4：MCP Server / Agentic AI 风险子类
)
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

K1, B = 1.4, 0.72

STOP = set("""a an the of in on for and or to with by from is are was were be been being this that these
those it its as at into via which who whom when where how not no such any all may can could would should
before after during under over between without within use used using allow allows attacker attackers
remote local arbitrary unauthorized improper insufficient validation version versions prior through
user users system systems what how many which""".split())

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# ==========================================================================
# 高级查询语法：结构化算子 / 否定 / 通配符
# ==========================================================================
OP_KEYS = {
    "product": "product", "prod": "product", "产品": "product",
    "vendor": "vendor", "厂商": "vendor",
    "cwe": "cwe",
    "severity": "severity", "sev": "severity",
    "cvss": "cvss",
    "epss": "epss",
    "year": "year",
    "kev": "kev", "exploited": "kev",
    "poc": "poc",
    "ioc": "ioc", "indicator": "ioc",
    "paper": "paper", "papers": "paper",
    "category": "category", "cat": "category", "分类": "category",
    "source": "source", "src": "source", "来源": "source",
    "scope": "scope",
    "type": "type", "类型": "type",
}
OP_RE = re.compile(
    r"(?<![\w\-/.])(?P<neg>-?)(?P<key>" +
    "|".join(sorted(OP_KEYS, key=len, reverse=True)) +
    r")\s*[:：]\s*(?P<val>\"[^\"]{1,60}\"|[^\s，,；;]+)", re.I)
CVSS_CMP_RE = re.compile(
    r"(?<![\w])(?P<neg>-?)cvss\s*(?P<op>>=|<=|>|<)\s*(?P<val>\d+(?:\.\d+)?)", re.I)
# EPSS 比较算子（P0-2）：复刻 CVSS_CMP_RE 范式，支持 epss>=0.5 / epss<0.1。
# EPSS 单位是 0~1 浮点（与官方一致，不乘 100）。
EPSS_CMP_RE = re.compile(
    r"(?<![\w])(?P<neg>-?)epss\s*(?P<op>>=|<=|>|<)\s*(?P<val>\d+(?:\.\d+)?)", re.I)
SEV_CN = {"严重": "CRITICAL", "高危": "HIGH", "中危": "MEDIUM", "低危": "LOW", "未知": "UNKNOWN"}
NEG_PHRASE_RE = re.compile(r'(?<!\S)-"([^"]{2,60})"')
NEG_TERM_RE = re.compile(r"(?<![\w/])-([a-z0-9][a-z0-9\.\-_]{1,40})(?![\w-])")
WILDCARD_RE = re.compile(r"(?<![\w/])[a-z0-9][a-z0-9\.\-_]*\*[a-z0-9\.\-_]*(?![\w])")


def _lev(a, b, cap):
    """带截断的 Damerau-Levenshtein 距离（>cap 即提前返回 cap+1）"""
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    prev2, prev = [], list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i]
        rowmin = i
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)
            cur.append(v)
            rowmin = min(rowmin, v)
        if rowmin > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[lb]

# 领域原子术语（查询中出现则应作为短语处理）
PHRASE_TERMS = sorted(
    {k for k in SYNONYMS if " " in k and k.isascii()} |
    {v for vs in SYNONYMS.values() for v in vs if " " in v and v.isascii()} |
    {"prompt injection", "model context protocol", "retrieval augmented generation",
     "remote code execution", "server-side request forgery", "path traversal",
     "insecure deserialization", "supply chain", "arbitrary file read",
     "large language model", "text generation inference", "inference server",
     "known exploited", "proof of concept", "privilege escalation",
     "authentication bypass", "authorization bypass", "model extraction"},
    key=len, reverse=True,
)

CJK_RE = re.compile(r"[\u4e00-\u9fff]+")
WORD_RE = re.compile(r"[a-z0-9][a-z0-9\-\.\+_]{1,40}")


# ==========================================================================
# 文本处理
# ==========================================================================
def stem(w):
    # 注意：以 ss 结尾的词（bypass / access）不能去 s，否则产生 bypas / acces 这类噪声词项
    if w.endswith("ss"):
        return w
    for suf in ("ies", "ing", "ers", "er", "ed", "es", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            base = w[: -len(suf)]
            if suf == "ies":
                return base + "y"
            return base
    return w


def tokenize(text):
    """英文词 + 复合符号词（llama.cpp / cve-2024-37032）"""
    out = []
    for m in WORD_RE.finditer((text or "").lower()):
        w = m.group(0).strip(".-+_")
        if len(w) < 2 or w in STOP or w.isdigit():
            continue
        out.append(w)
        s = stem(w)
        if s != w:
            out.append(s)
    return out


def cjk_ngrams(text, lo=2, hi=8):
    out = []
    for m in CJK_RE.finditer(text or ""):
        s = m.group(0)
        for n in range(lo, min(hi, len(s)) + 1):
            for i in range(0, len(s) - n + 1):
                out.append(s[i:i + n])
    return out


# ==========================================================================
# 概念空间（用别名组定义本体概念）
# ==========================================================================
CATEGORY_CN = {
    "① AI基础设施与推理框架": ["推理框架", "推理引擎", "模型服务", "基础设施", "推理", "部署框架"],
    "② 模型与数据层": ["模型层", "数据层", "模型文件", "向量库", "向量数据库", "模型权重"],
    "③ AI应用与智能体": ["智能体", "应用层", "应用", "编排", "工具调用", "插件"],
    "④ AI供应链与平台": ["供应链", "依赖", "组件仓库", "模型仓库", "第三方组件", "平台"],
    "⑤ Web应用与API安全": ["web安全", "web应用", "api安全", "注入", "跨站", "网站安全", "接口安全"],
    "⑥ 系统与二进制安全": ["系统安全", "二进制", "内存", "溢出", "内核", "驱动", "提权", "逆向"],
    "⑦ 网络与协议安全": ["网络安全", "协议", "dns", "流量", "拒绝服务", "无线", "路由"],
    "⑧ 云原生与容器安全": ["云原生", "容器", "云安全", "k8s", "镜像", "云计算"],
    "⑨ 身份与访问管理": ["身份", "认证", "鉴权", "越权", "口令", "凭据", "单点登录"],
    "⑩ 恶意代码与威胁活动": ["恶意代码", "病毒", "木马", "勒索", "钓鱼", "apt", "威胁", "僵尸网络"],
    "⑪ 数据安全与密码学": ["数据安全", "密码学", "加密", "证书", "信息泄漏", "密钥"],
}


def build_concepts():
    """两族概念：
       ① 术语概念 —— 由 taxonomy.SYNONYMS 的别名组构成（细粒度语义）
       ② 分类概念 —— 与赛题四分类对齐（粗粒度主题召回）
    """
    concepts = {}
    for key, aliases in SYNONYMS.items():
        group = {key} | {a.lower() for a in aliases}
        cid = "C::T::" + (sorted(group, key=len)[0])
        concepts[cid] = {"aliases": group, "label": key, "kind": "term"}

    for cat, cn in CATEGORY_CN.items():
        aliases = {cat, RISK_CATEGORIES[cat]["short"]} | set(cn)
        aliases |= {p for p, (c, _) in AI_PRODUCTS.items() if c == cat}
        cid = "C::CAT::" + cat
        concepts[cid] = {"aliases": aliases, "label": RISK_CATEGORIES[cat]["short"],
                         "kind": "category", "cat": cat}
    return concepts


CONCEPTS = build_concepts()
# alias -> concept id 倒排
ALIAS2CONCEPT = {}
for cid, c in CONCEPTS.items():
    for a in c["aliases"]:
        ALIAS2CONCEPT.setdefault(a, []).append(cid)

# 别名值 -> SYNONYMS 键 倒排（同义词反向扩展：查询词命中别名时扩展整组）
ALIAS2KEYS = {}
for _k, _vs in SYNONYMS.items():
    for _v in _vs:
        ALIAS2KEYS.setdefault(_v.lower(), []).append(_k)


# 字段名 → 位掩码（tf 条目内联字段信息，替代独立的 term_fields 集合结构，
# 30 万级文档下内存从 ~4x 降为 1x；见 _build_index）
FIELD_ORDER = ["id", "product", "vendor", "cwe", "title", "desc", "refs",
               "papers", "atlas", "tags", "advisory", "category", "kev", "ioc"]
FIELD_BIT = {fn: 1 << i for i, fn in enumerate(FIELD_ORDER)}

# 概念别名 / 领域短语的多模式匹配：Aho-Corasick 自动机一次扫描取得「全部命中
# 别名集合」（C 实现，较 1500 选一的组合正则快约 20-50 倍，30 万级文档构建的关键）；
# 无 ahocorasick 库时回退为组合前瞻正则。两者语义均与原 `a in blob`（大小写
# 敏感、允许重叠命中）完全一致。
try:
    import ahocorasick as _ahocorasick
except ImportError:  # 库缺失时降级，功能不受影响（仅构建变慢）
    _ahocorasick = None


def _combined_lookahead(terms):
    terms = sorted({t for t in terms if t}, key=len, reverse=True)
    return re.compile("(?=(" + "|".join(re.escape(t) for t in terms) + "))")


def _build_matcher(terms):
    terms = sorted({t for t in terms if t})
    if _ahocorasick is not None:
        auto = _ahocorasick.Automaton()
        for t in terms:
            auto.add_word(t, t)
        auto.make_automaton()
        return ("ac", auto)
    return ("re", _combined_lookahead(terms))


def _match_set(matcher, text):
    kind, obj = matcher
    if not text:
        return set()
    if kind == "ac":
        return {v for _, v in obj.iter(text)}
    return {m.group(1) for m in obj.finditer(text)}


CONCEPT_MATCHER = _build_matcher(
    a for c in CONCEPTS.values() for a in c["aliases"])
PHRASE_MATCHER = _build_matcher(PHRASE_TERMS)
# 概念别名 frozenset 预计算（构建期集合求交，避免重复构造）
_CONCEPT_ALIAS_SETS = {cid: frozenset(c["aliases"]) for cid, c in CONCEPTS.items()}


# ==========================================================================
# 检索引擎
# ==========================================================================
# 归一整型用到的字段清单（两版合并后的超集）
_NORM_LIST_FIELDS = (
    "products", "vendors", "sources", "poc_links", "patch_links", "refs",
    "advisory_links", "osv_packages", "osv_summaries", "osv_refs", "tags",
    "risk_tags", "atlas", "atlas_evidence", "atlas_mitigations", "papers",
    "cpe", "repo_topics", "ioc",
)
# 元素必须是 dict 的结构化列表字段（渲染/索引路径会取键，脏元素会导致整条查询 500）
_NORM_DICT_LIST_FIELDS = ("cwe", "refs", "papers", "atlas", "atlas_mitigations", "cpe")
_NORM_STR_FIELDS = ("id", "title", "desc", "published", "modified",
                    "category", "scope", "type", "status", "kind")

# ISO 日期前缀（YYYY-MM-DD，含 1 位月/日的宽容匹配）
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{1,2}-\d{1,2}")
# 英文月份名 → 数字（RFC 2820 / 常见博客日期兜底解析用）
_MONTHS = {m: i + 1 for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}


def _fix_bad_date(v):
    """尽力把坏日期修复成 YYYY-MM-DD；修不出来就返回空串（排序沉底、界面显示 —）。

    背景：快车道历史数据里 'Fri, 18 Sep 2026 ...' 被 [:10] 硬截成 'Fri, 18 Se'，
    字符串排序时 'F'>'2' 被当成最新，latest() 的未来日期过滤又把整条隐藏。
    """
    import datetime as _dt
    s = str(v).strip()
    m = _ISO_DATE_RE.match(s)
    if m:
        return s[:10]
    # 被截断的 RFC 2822 残骸："Fri, 18 Se"（快车道 [:10] 硬截的产物）。
    # 为什么放在 parsedate 前面：这类串连年份都没有，parsedate_to_datetime 必抛
    # ValueError —— 建一次索引白抛 300+ 次（实测 303 次），等于拿异常当流程控制，
    # 热路径上不该这么写。判据"串里没有 4 位年份"能把残骸与完整 RFC 串干净分开，
    # 两类串的修复结果与调整顺序前完全一致。
    if not re.search(r"\d{4}", s):
        m = re.match(r"^[A-Za-z]{3},\s*(\d{1,2})\s+([A-Za-z]{1,3})", s)
        if m:
            day, mon = int(m.group(1)), m.group(2).lower()
            for name, num in _MONTHS.items():
                if name.startswith(mon) and sum(1 for n in _MONTHS if n.startswith(mon)) == 1:
                    # 月份前缀唯一（Se→Sep）才敢修；Ju（Jun/Jul）这类二义的交给 URL/缓存修复
                    year = _dt.date.today().year
                    try:
                        cand = _dt.date(year, num, day)
                        if cand > _dt.date.today():
                            cand = _dt.date(year - 1, num, day)
                        return cand.isoformat()
                    except ValueError:
                        break
    # RFC 2820 完整串（未被截断的）
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(s)
        if dt is not None:
            return dt.strftime("%Y-%m-%d")
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/engine.py:300", _sw_e)
    # 任意位置藏着 2026/09/18 或 2026年9月18日
    m = re.search(r"(20\d{2})\s*[-/年.]\s*(\d{1,2})\s*[-/月.]\s*(\d{1,2})", s)
    if m:
        return "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3)))
    return ""


def _sev_from_score(score):
    """CVSS 3.1 评分区间 → 等级（仅在数据源未给 severity 时兜底使用）。"""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s <= 0.0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


def _normalize_doc(d):
    """补齐检索管线依赖的字段默认值（宿主 + 网盘两版归一逻辑的超集）。

    合并后的语料来自多条采集管线（NVD / GHSA / arXiv / HuggingFace / 仓库 /
    中文社区 / 实时快车道），字段结构并不一致：cvss 可能缺失、为 null 或被抓成
    字符串；products / cwe 可能写成裸标量。一旦这些脏记录被算子匹配、分面统计、
    索引构建或渲染路径读到，就会把整条查询打成 500。

    此处统一收口成标准结构，保证「任何一条脏记录都不影响整库可用性」。
    """
    if not isinstance(d, dict):
        return d

    # —— cvss：必须是 dict，且 score 为数值或 None、severity 为字符串或 None ——
    cv = d.get("cvss")
    if not isinstance(cv, dict):
        cv = d["cvss"] = {}
    if isinstance(cv.get("score"), bool) or not isinstance(cv.get("score"), (int, float)):
        cv["score"] = None
    if cv.get("severity") is not None and not isinstance(cv.get("severity"), str):
        cv["severity"] = str(cv["severity"])
    cv.setdefault("severity", None)
    cv.setdefault("vector", "")
    # 等级兜底（2026-09-30）：NVD 增量更新只给 baseScore 时，severity 会停留在
    # 上一版的旧值 —— 表现是「评分 9.9 却标着 MEDIUM」，列表按等级筛高危会漏。
    # 这里按 CVSS 3.1 区间补算；数据源给了官方评级则以数据源为准（不覆盖）。
    if not cv.get("severity") and isinstance(cv.get("score"), (int, float)):
        cv["severity"] = _sev_from_score(cv["score"])
    cv.setdefault("version", "")
    cv.setdefault("exploitability", None)
    cv.setdefault("impact", None)

    # —— 列表型字段：标量包装成单元素列表（不丢数据），None/"" 归空 ——
    for k in _NORM_LIST_FIELDS:
        v = d.get(k)
        if not isinstance(v, list):
            d[k] = [] if v in (None, "") else [v]

    # —— 结构化列表字段：剔除非 dict 元素，避免下游取键崩溃 ——
    for k in _NORM_DICT_LIST_FIELDS:
        v = d.get(k)
        if not isinstance(v, list):
            d[k] = []
        elif any(not isinstance(x, dict) for x in v):
            d[k] = [x for x in v if isinstance(x, dict)]

    # —— 字符串型字段：非空非字符串一律转字符串 ——
    for k in _NORM_STR_FIELDS:
        if d.get(k) is not None and not isinstance(d[k], str):
            d[k] = str(d[k])

    d.setdefault("title", "")
    d.setdefault("desc", "")
    d.setdefault("kev", None)
    d.setdefault("type", "vulnerability")
    d.setdefault("scope", "AI安全")
    d.setdefault("category", "")

    # —— 日期清洗：published/modified 必须是 YYYY-MM-DD 前缀 ——
    # 快车道旧数据里存在 'Wed, 29 Ju'（RFC 2820 被 [:10] 硬截）这类坏值，
    # 排序时被当成"最大日期"，latest() 的未来日期过滤又会把整条隐藏。
    for k in ("published", "modified"):
        v = d.get(k)
        if v and not _ISO_DATE_RE.match(v):
            fixed = _fix_bad_date(v)
            d[k] = fixed
    return d


# ==========================================================================
# 原文外链推导（2026-10-12）
# ==========================================================================
# 背景：同一条情报的外链在语料里散落在多个字段 —— article_url（博客/社区
# 文章）、repo_url（GitHub 仓库）、link（arXiv 论文）、pdf（论文 PDF）、
# advisory_links / refs / poc_links / patch_links / osv_refs（公告与引用）。
#
# 而检索卡片与详情此前只渲染 refs 一系，于是「社区文章、工具仓库、学术论文、
# HuggingFace 模型」这几类条目经常一个可点的原文入口都没有 —— 用户看到的就是
# 「点了文章却没有跳转链接」。这里统一收口成 canonical_url()，列表与详情共用。
#
# 原则：只用**采集时就已经落地的真实链接**；确实没有时才按 id 规则回退到该来源
# 的官方详情页（NVD / GitHub Advisory / HuggingFace / GitHub）。绝不猜解 URL
# —— 猜出来的地址点开是 404，比没有链接更糟。
_EXT_URL_FIELDS = ("article_url", "repo_url", "link", "pdf", "url")
_EXT_URL_LISTS = ("advisory_links", "refs", "poc_links", "patch_links", "osv_refs")


def _first_http(v):
    """从「字符串 / {url: ...} / 上述两者的列表」里取出第一个 http(s) 链接"""
    if isinstance(v, str):
        return v if v.startswith("http") else ""
    if isinstance(v, dict):
        u = v.get("url") or ""
        return u if isinstance(u, str) and u.startswith("http") else ""
    if isinstance(v, (list, tuple)):
        for x in v:
            u = _first_http(x)
            if u:
                return u
    return ""


def canonical_url(d):
    """推导一条情报的「原文页面」地址；拿不到可靠地址时返回空串"""
    if not isinstance(d, dict):
        return ""
    cid = str(d.get("id") or "")

    # CVE 的原文页就是 NVD 详情页：比采集自 CNA 的任意一条 refs 更稳定更权威，
    # 且 refs 全集在详情面板的「参考链接」里已分组全量展示，不必重复。
    if cid.startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + cid
    if cid.startswith("GHSA-"):
        return "https://github.com/advisories/" + cid

    for k in _EXT_URL_FIELDS:
        u = _first_http(d.get(k))
        if u:
            return u
    for k in _EXT_URL_LISTS:
        u = _first_http(d.get(k))
        if u:
            return u

    # 按 id 回退（确定性映射，不做任何 URL 猜解）
    if cid.startswith("HF:") and "/" in cid[3:]:
        return "https://huggingface.co/" + cid[3:]
    if cid.startswith("GH:") and "/" in cid[3:]:
        return "https://github.com/" + cid[3:]
    # 中文社区：快车道 live.py 的 news API 通道偶发不返回 url 字段（实测 32 条
    # AQ:/XZ: 记录 link 为空），详情页与日报就没有"原文"入口。这里按 id 前缀补
    # 确定性映射 —— 两个平台的详情页 URL 规则都是**官方源自己给出的**，不是猜的：
    #   安全客：https://www.anquanke.com/post/id/{id}
    #     实测 post/id/316151 标题与 AQ:316151 精确一致（2026-10-13）。
    #   先知社区：https://xz.aliyun.com/news/{id}
    #     取自先知社区官方 RSS(xz.aliyun.com/feed) 的 <link> 全集 —— 逐条核对
    #     XZ:92857/92855/92868/92886/92898/92915 的摘要与本地记录 desc 精确匹配。
    #   AQK: 是离线收割脚本的前缀（与 AQ: 同一篇文章的两种 id），一并覆盖。
    if cid.startswith("AQK:"):
        return "https://www.anquanke.com/post/id/" + cid[4:]
    if cid.startswith("AQ:"):
        return "https://www.anquanke.com/post/id/" + cid[3:]
    if cid.startswith("XZ:"):
        return "https://xz.aliyun.com/news/" + cid[3:]
    return ""


# ── F2 返修：标准/法规结构化条目「标题精确命中」附加分 ────────────────────
# 判据：查询串与标题都按同一规则归一化（去空白 + 去中英文标点，保留 0-9/a-z/CJK），
# 归一化查询串是归一化标题的**子串**时，给 STD:/REG: 条目一个固定加分使其置顶。
# 为什么抽成模块函数：归一化对「查询」与「标题」必须完全一致，两处各写一份迟早漂移。
_PUNCT_RE = re.compile(r"[^0-9a-z\u4e00-\u9fff]+")
_STDLIKE_TITLE_BOOST = 60.0   # 量级足以在同分档置顶，但低于 CVE 号精确命中(120)


def _norm_probe(s) -> str:
    """归一化探针串：小写 + 去空白/中英文标点，仅留 0-9 a-z 与 CJK。"""
    return _PUNCT_RE.sub("", (s or "").lower())


class SearchEngine:
    # 索引磁盘缓存版本：构建逻辑（打分相关结构）变更时必须递增，
    # 否则 30 万级文档下每次服务启动都要全量重建索引（分钟级）。
    INDEX_CACHE_VERSION = "v4"   # v4 = 宿主增量索引 + 网盘归一化逻辑合并后的构建口径
    # 缓存"尾部增量"上限：语料只是在末尾追加了不超过这个数量的新文档时，
    # 直接复用旧缓存 + 对尾部增量建索引，避免整库重建（10 万条实测 355s）。
    # 超过就老实全量重建 —— 增量条数太多时，增量路的常数开销会逼近重建。
    # 按实测 3.4ms/条估算：5000 条 ≈ 17s，远小于 355s。
    INDEX_CACHE_TAIL_LIMIT = 5000
    # 缓存"容忍删除"上限（占缓存文档数的比例）。
    # 语料被删也是常态：AI 闸门筛选 / 重采集替换都会让一批 id 消失，旧口径下只要
    # 有一条对不上就整份缓存作废 → 每次启动 300s+ 全量重建。删除是"下标平移"，
    # 代价远低于重新分词，所以给一个宽松的比例阈值；超过就老实重建。
    INDEX_CACHE_DROP_RATIO = 0.10

    def __init__(self, corpus_path):
        import json
        with open(corpus_path, "r", encoding="utf-8") as f:
            self.corpus = json.load(f)
        self.vuln_docs = self.corpus["records"]
        self.kb_docs = self.corpus.get("knowledge", [])
        # 统一索引进同一倒排表：漏洞情报 + 威胁知识条目
        self.docs = self.vuln_docs + self.kb_docs
        for d in self.docs:
            _normalize_doc(d)
        self.papers = self.corpus.get("papers", [])
        # 聚合缓存（必须在加载索引缓存之前初始化：命中 .idxcache 时不会再走 _build_index）
        # 命中集合 == 全库时复用，省掉每次检索对 8.8 万条逐条统计（2026-09-28）
        self._global_facets = None
        self._global_agg = None
        # BM25 长度归一因子（只与文档长度有关，与查询无关）—— 惰性构建，见 _ensure_norm
        self._norm = None
        self._norm_avgdl = None
        self._loaded_from_cache = False
        self._incremental_from_cache = 0   # 命中缓存后尾部增量补建的条数（0=纯缓存命中）
        self._dropped_from_cache = 0       # 命中缓存后按「下标平移」剔除的已删文档条数
        if not self._load_index_cache(corpus_path):
            # 缓存失效要留下痕迹：语料改了格式/顺序、或缓存被别的写入路径搞脏时，
            # 这里会静默地花几百秒重建（实测一次 378.8s），不说一声根本不知道
            # 是「本来就慢」还是「缓存没命中」。重建后会立刻落盘，下次恢复秒开。
            print("  [index] 索引缓存未命中 / 已失效 → 全量重建（约需数分钟，完成后自动落盘）")
            self._build_index()
            self._save_index_cache(corpus_path)
        elif self._dropped_from_cache or self._incremental_from_cache:
            # 复用之后索引内容其实已经变了（剔除已删 / 补了增量）。顺手落盘，
            # 下次启动就能直接精确命中；否则每轮重启都要再做一次平移+增量。
            try:
                self._save_index_cache(corpus_path)
            except Exception as _sw_e:  # noqa: BLE001 —— 写盘失败不该拖住启动
                _swallow("core/engine.py:__init__.resave", _sw_e)

    # ---------------- 索引缓存 ----------------
    def _cache_path(self, corpus_path):
        return corpus_path + ".idxcache"

    def _idseq_sig(self):
        """文档 id 序列指纹。

        必须校验顺序的原因（2026-09-30 修的是一个会静默出错的坑）：
        倒排表 postings 里存的都是**文档下标**，而下标只有在文档顺序完全一致时
        才有意义。轻量同步会把新 CVE append 到引擎 docs 末尾，可 monitor 落盘时
        又把 records 按 published 倒序排过 —— 于是「文件里的顺序」和「引擎里的顺序」
        不再相同。此时若照旧只按 (版本, mtime, 大小, 条数) 判定缓存命中，
        下次启动就会套用一份下标错位好几万条的索引：检索不报错，但返回的
        是"A 的分数 + B 的正文"，属于最难发现的那类错误。
        """
        import hashlib
        h = hashlib.md5()
        for d in self.docs:
            h.update((d.get("id") or "").encode("utf-8", "ignore"))
            h.update(b"\x00")
        return h.hexdigest()

    def _cache_key(self, corpus_path):
        st = os.stat(corpus_path)
        return (self.INDEX_CACHE_VERSION, st.st_mtime_ns, st.st_size,
                len(self.docs), self._idseq_sig())

    def _cache_key_ok(self, key, corpus_path):
        """缓存键校验（容忍两种键，便于语料拷贝 / 网盘分发后直接复用）：
           ① 精确键  version + mtime_ns + size + docs
           ② 便携键  version + size + docs
        ② 的必要性：文件一经复制/下载，mtime_ns 必然变化；若只认精确键，
        分发出去的 .idxcache 永远失效，每个新环境首次启动都要全量重建索引。"""
        try:
            st = os.stat(corpus_path)
        except OSError:
            return False
        if not (isinstance(key, tuple) and key and key[0] == self.INDEX_CACHE_VERSION):
            return False
        k = list(key)
        # 顺序指纹缺失（旧版缓存）一律判失效：宁可花 6 分钟重建，
        # 也不能套用一份下标可能错位的索引。
        if len(k) < 5 or k[3] != len(self.docs) or k[2] != st.st_size:
            return False
        try:
            if k[4] != self._idseq_sig():
                return False
        except Exception:  # noqa: BLE001
            return False
        # mtime 一致 = 精确命中；mtime 变了但内容签名（大小 + 条数 + id 序列）全对
        # = 便携命中（语料被复制 / 网盘分发后 mtime 必然变，不该因此作废缓存）。
        # 上面已经把 size / 条数 / id 指纹三者都比过了，所以这两种都算命中。
        return True

    def _reorder_docs(self, order, max_drop_ratio=INDEX_CACHE_DROP_RATIO):
        """按给定的 id 顺序重排 self.docs，使文档下标与缓存索引对齐。

        轻量同步把新 CVE append 到引擎末尾，而 monitor 落盘时又把 records 按
        published 倒序排过 —— 两边顺序一旦分叉，缓存里的倒排下标就全错位了。
        与其作废缓存（下次启动 6 分钟重建），不如把当时的顺序记下来，
        加载时按它把 docs 摆回去：10 万条重排只要几十毫秒。

        少量 id 消失（AI 闸门筛选、重采集替换）不再判死：返回保留下来的文档
        在**旧索引里的下标**，交给 _compact_index 做下标平移即可继续复用；
        只有消失比例超过 max_drop_ratio 才放弃（那时重映射的收益抵不上重建）。

        返回 (ok, keep_old)：ok=False 时 keep_old 为空，调用方应回退全量重建。
        """
        if not order:
            return False, []
        by_id, dup = {}, 0
        for d in self.docs:
            k = d.get("id") or ""
            if k in by_id:
                dup += 1
            by_id[k] = d
        new_docs, keep_old, miss = [], [], 0
        limit = len(order) * max_drop_ratio
        for j, _id in enumerate(order):
            d = by_id.pop(_id, None)
            if d is None:
                miss += 1
                if miss > limit:      # 消失得太多，重映射的收益抵不上重建
                    return False, []
                continue
            new_docs.append(d)
            keep_old.append(j)        # 该文档在旧索引中的下标
        if by_id:                                  # 缓存里没有的新文档：追加在末尾
            new_docs.extend(by_id.values())
        self.docs = new_docs
        self.N = len(self.docs)
        # 记下明细：缓存失效时，人只看到「又要等五分钟」，却不知道是 miss（有文档
        # 消失）还是 dup（id 重复）造成的。留着数字，启动日志才说得清。
        self._reorder_stat = {"miss": miss, "dup": dup, "new": len(by_id)}
        return dup == 0, keep_old

    def _compact_index(self, keep_old, n_old):
        """按下标平移压缩索引：剔除已消失的文档，保留其余全部索引结构。

        为什么值得做：语料被删是常态（AI 闸门筛选 / 重采集替换一轮就能去掉近
        两千条），旧口径下 miss>0 即整份缓存作废，每次启动都要重新分词 10 万篇
        （实测 321s）。而删除只是「下标重编号」：postings 是紧凑数组，过滤+平移
        是批量内存操作；tf/dl/概念向量都是并行数组，按下标取即可。剩下唯一做不
        到精确的是 phrase_df（没存短语级 postings），保留近似值，6h 全量轮会抹平。

        调用前提：self.docs 已经是「保留文档」列表（长度 == len(keep_old)），
        新增文档由调用方随后走 add_documents 追加。
        """
        from array import array
        from collections import Counter

        # 旧下标 → 新下标（-1 = 该文档已从语料中消失）
        remap = [-1] * n_old
        for new_i, old_i in enumerate(keep_old):
            remap[old_i] = new_i

        _np = None
        try:                       # numpy 只是加速器，没有就走纯 Python 循环
            import numpy as _np
            rmp = _np.asarray(remap, dtype=_np.int32)
        except Exception:  # noqa: BLE001
            _np = None

        new_postings = {}
        for t, p in self.postings.items():
            if not p:
                continue
            if _np is not None and p.itemsize == 4:
                old = _np.frombuffer(memoryview(p), dtype=_np.uint32)
                kept = rmp[old]
                kept = kept[kept >= 0]
                q = array("I")
                if kept.size:
                    q.frombytes(kept.astype(_np.uint32).tobytes())
            else:
                q = array("I", [i for i in (remap[x] for x in p) if i >= 0])
            if q:
                new_postings[t] = q
        self.postings = new_postings
        # df 必须跟着 postings 重算：它是「出现该词项的文档数」，
        # 直接沿用旧值会让被删文档继续贡献 IDF，长尾词的权重会虚高。
        self.df = Counter({t: len(p) for t, p in new_postings.items()})

        # 并行数组：按下标整体取样（顺序即 keep_old 的顺序）
        self.tf = [self.tf[j] for j in keep_old]
        self.td_lower = [self.td_lower[j] for j in keep_old]
        self.dl = [self.dl[j] for j in keep_old]
        self.concept_vecs = [self.concept_vecs[j] for j in keep_old]
        self.recency = [self.recency[j] for j in keep_old]

        # 短语频次：留了逐条短语明细就能精确重算，不再沿用含已删文档的旧值
        _phr = getattr(self, "phrase_of", None)
        if isinstance(_phr, list) and len(_phr) == n_old:
            self.phrase_of = [_phr[j] for j in keep_old]
            _pd = {}
            for phr in self.phrase_of:
                for p in phr:
                    _pd[p] = _pd.get(p, 0) + 1
            self.phrase_df = _pd
        else:
            # 旧版缓存没有短语明细：退回近似值，同时置空明细，
            # 免得后面 add_documents 往错位的位置上追加。
            self.phrase_of = None

        self.cat_docs = {c: {remap[i] for i in v
                             if 0 <= i < n_old and remap[i] >= 0}
                         for c, v in self.cat_docs.items()}
        # 产品计数可以精确重算（被删文档的 products 应当一并扣掉）
        pc = Counter()
        for d in self.docs:
            for pr in (d.get("products") or []):
                pc[pr] += 1
        self.product_counter = pc

        self.N = len(keep_old)
        self._ids_upper = [(d.get("id") or "").upper() for d in self.docs]
        self.id_map = {u: i for i, u in enumerate(self._ids_upper)}
        self.avgdl = (sum(self.dl) / self.N) if self.N else 0.0
        self._recompute_stats()      # idf / concept_idf / 词典桶：全部按新 N 与 df 重算
        self._by_pub_desc = sorted(range(self.N), key=self._pub_key, reverse=True)
        self._norm = None            # 长度归一因子依赖 dl，作废让它惰性重建
        self._global_facets = None
        self._global_agg = None

    def reorder_by(self, id_order):
        """按给定的 id 顺序就地重排索引（不重建），返回是否成功。

        用途：monitor 落盘前会把 records/knowledge 按 published 倒序排，
        而引擎里是「旧记录原序 + 新记录追加末尾」——两者顺序必然分叉，
        于是每次写语料都会让 .idxcache 的 id 指纹对不上，下次启动全量重建
        （实测 360~410s）。

        与其每次启动都让 _reorder_docs 兜底重排，不如在写盘那一刻就把引擎
        也排成同一个顺序：内存顺序 == 磁盘顺序，缓存永远自洽。
        10 万条重排实测 200ms 级，比启动时省下的几百秒划算得多。

        id 集合必须完全一致（含重复计数），否则不动，交给启动时的
        _reorder_docs + 指纹校验兜底。
        """
        from array import array
        from collections import Counter
        cur = [d.get("id") or "" for d in self.docs]
        if len(cur) != len(id_order) or Counter(cur) != Counter(id_order):
            return False
        # 老下标 → 每条记录的全套索引数据（tf/dl/概念向量/类别…）打包带走，
        # 重排后按新顺序重新收集。逐个平移下标太容易漏掉某个并行数组。
        old_tf, old_tdl = list(self.tf), list(self.td_lower)
        old_dl, old_cvec = list(self.dl), list(self.concept_vecs)
        old_rec = list(self.recency)
        old_phr = list(self.phrase_of) if isinstance(
            getattr(self, "phrase_of", None), list) else None
        old_cat = {c: set(v) for c, v in self.cat_docs.items()}

        by_id = {}
        for i, d in enumerate(self.docs):
            k = d.get("id") or ""
            by_id[k] = (i, d)
        new_docs, new_order = [], []
        for k in id_order:
            oi, d = by_id[k]
            new_docs.append(d)
            new_order.append(oi)

        self.docs = new_docs
        self.tf = [old_tf[i] for i in new_order]
        self.td_lower = [old_tdl[i] for i in new_order]
        self.dl = [old_dl[i] for i in new_order]
        self.concept_vecs = [old_cvec[i] for i in new_order]
        self.recency = [old_rec[i] for i in new_order]
        if old_phr is not None:
            self.phrase_of = [old_phr[i] for i in new_order]
        # vuln_docs / kb_docs 必须跟着一起排：首页统计走 vuln_docs，
        # 只排 docs 会让「统计的数字」和「检索到的那条」指向不同文档。
        kb_ids = {(d.get("id") or "") for d in self.kb_docs}
        if kb_ids:
            self.vuln_docs = [d for d in new_docs if (d.get("id") or "") not in kb_ids]
            self.kb_docs = [d for d in new_docs if (d.get("id") or "") in kb_ids]
        else:
            self.vuln_docs = new_docs

        self.N = len(self.docs)
        self._ids_upper = [(d.get("id") or "").upper() for d in self.docs]
        self.id_map = {u: i for i, u in enumerate(self._ids_upper)}
        # 倒排表里存的是旧下标，顺序一变全失效 —— 按新下标整体重建。
        self.postings = {}
        for i, agg in enumerate(self.tf):
            for t in agg:
                p = self.postings.get(t)
                if p is None:
                    p = self.postings[t] = array("I")
                p.append(i)
        pos_map = {old_i: new_i for new_i, old_i in enumerate(new_order)}
        self.cat_docs = {c: {pos_map[i] for i in idxs if i in pos_map}
                         for c, idxs in old_cat.items()}
        self._norm = None
        self._by_pub_desc = sorted(range(self.N), key=self._pub_key, reverse=True)
        return True

    def _disk_order(self, corpus_path):
        """读语料文件，返回其 records + knowledge 的 id 顺序（用于顺序对齐）。

        只解析 id 序列会省很多内存，但语料是单个 JSON 文档，没有更轻的读法；
        实测 267MB / 10 万条 json.load 约 3.4s，而它换来的是重启少花几百秒，
        这笔账是划算的。读取失败返回 None，调用方会跳过对齐。
        """
        import json
        try:
            with open(corpus_path, "r", encoding="utf-8") as f:
                c = json.load(f)
        except Exception:  # noqa: BLE001
            return None
        order = [d.get("id") or "" for d in (c.get("records") or [])]
        order += [d.get("id") or "" for d in (c.get("knowledge") or [])]
        return order

    def _load_index_cache(self, corpus_path):
        import pickle
        fp = self._cache_path(corpus_path)
        try:
            if not os.path.isfile(fp):
                return False
            with open(fp, "rb") as f:
                key, payload = pickle.load(f)
            if not isinstance(payload, dict):
                return False
            # 先按缓存记录的顺序把 docs 摆回去，再做键校验（此时的 _idseq_sig
            # 才是"和索引对齐的那个顺序"），最后才把索引结构装进引擎。
            # 校验不通过必须回滚：_reorder_docs 是就地改 self.docs 的，
            # 若放弃这份缓存却留着重排后的 docs，紧接着的 _build_index() 就会
            # 基于一个「和磁盘文件不一致的顺序」建索引 —— 下一次保存缓存时
            # 又把这个错序写进去，越滚越偏。
            before = self.docs
            _order = payload.get("doc_order") or []
            _n_order = len(_order)
            try:
                _ok, _keep = self._reorder_docs(_order)
                if not _ok:
                    _st = getattr(self, "_reorder_stat", {}) or {}
                    self._cache_reject = (
                        "文档对不上：缓存记录的 %d 条里有 %d 条在当前语料中已不存在"
                        "（超过 %.0f%% 的容忍上限），另有 %d 条重复 id"
                        % (_n_order, _st.get("miss", -1),
                           self.INDEX_CACHE_DROP_RATIO * 100, _st.get("dup", -1)))
                    self.docs = before
                    return False
            except Exception as _sw_e:  # noqa: BLE001
                _swallow("core/engine.py:_load_index_cache.reorder", _sw_e)
                self.docs = before
                return False
            # 命中判定分两种：
            #   ① 精确命中：文档集合完全没变 → 走原来的 key 校验（含 id 顺序指纹）
            #   ② 前缀命中 + 尾部增量：语料只是在末尾追加了少量新情报
            #      （本平台的常态：快车道/定时同步每轮都会 append 新 CVE）
            #      旧口径下只要条数变了就整个缓存作废，下次启动必吃 355s 全量重建；
            #      改成"复用旧索引 + 只给尾部增量建索引"，把启动压到秒级~十几秒。
            #      前缀一致性由 _reorder_docs 保证：它成功返回就意味着
            #      docs[:len(doc_order)] 与缓存里的索引下标一一对应。
            # 命中判定：一分为四。
            #   dropped = 缓存里有、当前语料中已经消失的条数
            #   added   = 当前语料里新增、缓存中没有的条数
            n_now = len(self.docs)
            n_keep = len(_keep)                 # 可复用的基数（缓存里"还在"的那些）
            dropped = _n_order - n_keep
            added = n_now - n_keep
            if added > self.INDEX_CACHE_TAIL_LIMIT:
                self._cache_reject = (
                    "新增 %d 条，超过尾部增量上限 %d 条（整体重建更划算）"
                    % (added, self.INDEX_CACHE_TAIL_LIMIT))
                self.docs = before
                return False
            if dropped == 0 and added == 0:
                # ① 精确命中：文档集合完全没变 → 走原来的 key 校验（含 id 顺序指纹）
                if not self._cache_key_ok(key, corpus_path):
                    self._cache_reject = (
                        "条数没变但内容签名变了（有文档被就地更新），保守起见不复用")
                    self.docs = before
                    return False
                compact = False
            elif dropped == 0:
                compact = False     # ② 纯尾部增量：旧下标一字不动
            elif dropped <= _n_order * self.INDEX_CACHE_DROP_RATIO:
                compact = True      # ③ 带删除复用：下标平移后继续用（AI 闸门筛选常态）
            else:
                self._cache_reject = (
                    "语料被删 %d 条（占缓存 %.1f%%），超过 %.0f%% 容忍上限"
                    % (dropped, dropped * 100.0 / max(_n_order, 1),
                       self.INDEX_CACHE_DROP_RATIO * 100))
                self.docs = before
                return False

            payload.pop("doc_order", None)   # 顺序已用于重排，不进引擎属性
            all_docs = self.docs
            # 先把 docs 截到"可复用基数"，套用旧索引，再把新增按 add_documents 追加，
            # 这样新旧两条路径写的是同一套下标体系。
            self.docs = all_docs[:n_keep]
            self.__dict__.update(payload)
            # payload 里没有 docs（顺序敏感，已在上面就地重排），
            # 但 _ids_upper 是按下标排列的，必须跟着重排后的 docs 重算。
            self._ids_upper = [d["id"].upper() for d in self.docs]
            self._loaded_from_cache = True     # 供启动日志区分「读缓存 / 全量重建」
            if compact:
                try:
                    self._compact_index(_keep, _n_order)
                    self._dropped_from_cache = dropped   # 启动日志/体检可见
                except Exception as _sw_e:      # 压缩失败不能留半截索引
                    _swallow("core/engine.py:_load_index_cache.compact", _sw_e)
                    self._cache_reject = (
                        "剔除 %d 条已删文档时失败（%s: %s），不能留半截索引"
                        % (dropped, type(_sw_e).__name__, _sw_e))
                    self.docs = before
                    return False
            if added:
                try:
                    self.add_documents(all_docs[n_keep:])
                    self._incremental_from_cache = added   # 启动日志/体检可见
                except Exception as _sw_e:      # 增量失败不能留半截索引
                    _swallow("core/engine.py:_load_index_cache", _sw_e)
                    self._cache_reject = (
                        "尾部 %d 条增量建索引失败（%s: %s），不能留半截索引"
                        % (added, type(_sw_e).__name__, _sw_e))
                    self.docs = before
                    return False
            return True
        except Exception:  # noqa: BLE001 —— 缓存损坏一律回退全量重建
            return False

    def _save_index_cache(self, corpus_path):
        import pickle
        # 用 get 而不是下标：phrase_of 是后加的字段，旧缓存里没有，
        # 缺了就只存已有的（加载侧会容忍它缺失，退回 phrase_df 近似值）。
        payload = {k: self.__dict__[k] for k in (
            "tf", "td_lower", "dl", "df", "concept_vecs", "postings",
            "phrase_df", "phrase_idf", "phrase_of", "N", "avgdl", "idf", "max_idf",
            "bigram_idf_cap", "id_map", "cat_docs", "concept_idf",
            "dict_terms", "dict_by_len", "product_counter", "recency",
            "_by_pub_desc", "_ids_upper",
        ) if k in self.__dict__}
        # 文档顺序必须一起存：倒排表里全是下标，顺序一变索引就错位。
        payload["doc_order"] = [d.get("id") or "" for d in self.docs]
        try:
            tmp = self._cache_path(corpus_path) + ".tmp"
            with open(tmp, "wb") as f:
                pickle.dump((self._cache_key(corpus_path), payload), f, protocol=4)
            os.replace(tmp, self._cache_path(corpus_path))
        except Exception as _sw_e:  # noqa: BLE001 —— 缓存写失败不阻塞服务
            _swallow("core/engine.py:668", _sw_e)

    # ---------------- 索引 ----------------
    def _field_text(self, d):
        papers_txt = " ".join(p["title"] + " " + p.get("summary", "")[:400] for p in d.get("papers", []))
        atlas_txt = " ".join(
            t["id"] + " " + t["name"] + " " + " ".join(t.get("tactics", [])) + " " +
            t.get("description", "")[:200]
            for t in d.get("atlas", [])
        )
        mit_txt = " ".join(m["name"] + " " + m.get("use", "")[:160]
                           for m in d.get("atlas_mitigations", []))
        return {
            "id": d["id"],
            "product": " ".join(d.get("products", [])),
            "vendor": " ".join(d.get("vendors", [])),
            "cwe": " ".join(w["id"] + " " + w.get("name", "") for w in d.get("cwe", [])),
            "title": d.get("title", ""),
            "desc": d.get("desc", "") + " " + " ".join(d.get("osv_summaries", [])),
            "refs": " ".join(r["url"] for r in d.get("refs", [])) + " " +
                    " ".join(d.get("poc_links", [])) + " " + " ".join(d.get("patch_links", [])),
            "papers": papers_txt,
            "atlas": atlas_txt + " " + mit_txt,
            "tags": " ".join(d.get("tags", []) + d.get("osv_packages", [])),
            "advisory": " ".join(d.get("advisory_links", [])),
            "category": d.get("category", ""),
            "kev": (" ".join(str(v) for v in d.get("kev", {}).values()) if d.get("kev") else ""),
        }

    def _index_one(self, i, d):
        """为单个文档构建索引条目。返回 (tf_entry, (title_lo, desc_lo), cvec, phrase_hits)。
        抽成独立方法既供全量构建，也供实时增量追加（add_documents）复用。"""
        import sys as _sys
        intern = _sys.intern
        f = self._field_text(d)
        agg = {}
        for fname, ftext in f.items():
            w = FIELD_WEIGHTS.get(fname, 1.0)
            counts = Counter(tokenize(ftext))
            # CJK bigram：中文文章/中文查询的正向词法匹配（BM25 层原本只索引英文词）
            if fname in ("title", "desc"):
                for t, c in Counter(cjk_ngrams(ftext, 2, 2)).items():
                    counts[t] += c
            bit = FIELD_BIT[fname]
            for t, c in counts.items():
                t = intern(t)
                e = agg.get(t)
                if e is None:
                    agg[t] = [c * w, bit]
                else:
                    e[0] += c * w
                    e[1] |= bit
        title_lo, desc_lo = f["title"].lower(), f["desc"].lower()
        # 概念向量：组合正则一次扫描 blob → 命中别名集合 → 各概念命中计数
        blob = " ".join([f["title"], f["desc"][:6000], f["product"], f["vendor"],
                         f["cwe"], f["tags"], f["category"], f["kev"], f["atlas"][:2500]]).lower()
        matched = _match_set(CONCEPT_MATCHER, blob)
        cvec = defaultdict(float)
        for cid, c in CONCEPTS.items():
            if c["kind"] == "category":
                continue
            hit = len(_CONCEPT_ALIAS_SETS[cid] & matched)
            if hit:
                cvec[cid] = min(1.0, 0.5 + 0.25 * hit)
        for cid, c in CONCEPTS.items():
            if c["kind"] == "category" and c["cat"] == d.get("category"):
                cvec[cid] = 1.0
        # 短语文档频次：df 语义是「包含该短语的文档数」，按文档去重
        phrase_hits = _match_set(PHRASE_MATCHER, title_lo + "\n" + desc_lo)
        return agg, (title_lo, desc_lo), dict(cvec), phrase_hits

    @staticmethod
    def _recency_of(d):
        p = (d.get("published") or "")[:10]
        try:
            dt = datetime.fromisoformat(p).replace(tzinfo=timezone.utc)
            age = max(0.0, (datetime.now(timezone.utc) - dt).days / 365.25)
            return 0.5 ** (age / 1.5)
        except ValueError:
            return 0.0

    def _pub_key(self, i):
        d = self.docs[i]
        return ((d.get("published") or "")[:10],
                (d.get("modified") or "")[:10],
                d.get("id", ""))

    def _recompute_stats(self):
        """全量重算 IDF 类派生结构（N 变化后必须刷新）。O(词表) ~ 0.1-0.5s。"""
        N = max(self.N, 1)
        self.idf = {t: math.log(1 + (N - df + 0.5) / (df + 0.5)) for t, df in self.df.items()}
        self.max_idf = max(self.idf.values()) if self.idf else 1.0
        # CJK bigram 的 IDF 上限：按 df=50 折算（约等价于一个中频普通词项）
        self.bigram_idf_cap = math.log(1 + (N - 50 + 0.5) / 50.5)
        self.phrase_idf = {
            p: math.log(1 + (N - df + 0.5) / (df + 0.5)) if df else 3.0
            for p, df in self.phrase_df.items()
        }
        cdf = Counter()
        for cv in self.concept_vecs:
            for cid in cv:
                cdf[cid] += 1
        self.concept_idf = {
            cid: math.log(1 + (N - df + 0.5) / (df + 0.5)) if df else 3.0
            for cid, df in cdf.items()
        }
        # 词典辅助结构：通配符展开 + 拼写容错（按长度分桶 + 首字母过滤）
        self.dict_terms = [t for t in self.df if t.isascii()]
        self.dict_by_len = {}
        for t in self.dict_terms:
            if t.isalpha():
                self.dict_by_len.setdefault(len(t), []).append(t)

    def _build_index(self):
        from array import array
        self.tf = []                 # per doc: term -> [加权词频, 字段位掩码]
        self.td_lower = []           # per doc: (title_lower, desc_lower) —— 短语层专用
        self.dl = []
        self.df = Counter()
        self.concept_vecs = []
        self.postings = {}           # term -> array('I')（有序 doc id，紧凑 4B/条）
        self.phrase_df = {}          # 短语文档频次
        # 每条文档命中的短语明细：只为让「语料被删」时能精确重算 phrase_df。
        # 没有它，剔除文档后短语频次只能沿用旧值（实测偏差可达三成），
        # 而 phrase_idf 直接参与短语命中加权。体积代价几 MB，换一个精确值。
        self.phrase_of = []

        for i, d in enumerate(self.docs):
            agg, tdl, cvec, phr = self._index_one(i, d)
            self.tf.append(agg)
            self.td_lower.append(tdl)
            self.dl.append(sum(v[0] for v in agg.values()) or 1.0)
            for t in agg:
                self.df[t] += 1
                p = self.postings.get(t)
                if p is None:
                    p = self.postings[t] = array("I")
                p.append(i)
            self.concept_vecs.append(cvec)
            self.phrase_of.append(phr)
            for p in phr:
                self.phrase_df[p] = self.phrase_df.get(p, 0) + 1

        self.N = len(self.docs)
        self.avgdl = sum(self.dl) / max(self.N, 1)

        # 精确命中辅助结构
        self.id_map = {d["id"].upper(): i for i, d in enumerate(self.docs)}
        self.cat_docs = {}
        for i, d in enumerate(self.docs):
            c = d.get("category")
            if c:
                self.cat_docs.setdefault(c, set()).add(i)

        self.recency = [self._recency_of(d) for d in self.docs]
        self.product_counter = Counter(p for d in self.docs for p in d.get("products", []))
        self._recompute_stats()

        # 大语料辅助结构（30 万级文档下避免每次请求全库排序/扫描）：
        #   _by_pub_desc  按发布时间倒序的文档下标（latest feed 直接截取）
        #   _ids_upper    全量文档 id 大写表（suggest 前缀扫描免逐次 lower）
        self._by_pub_desc = sorted(range(self.N), key=self._pub_key, reverse=True)
        self._ids_upper = [d["id"].upper() for d in self.docs]

        # 聚合缓存：命中集合 == 全库时（首屏 / 空查询）直接复用，避免每次检索统计 8.8 万条
        self._global_facets = None
        self._global_agg = None

    # ---------------- 实时增量 ----------------
    def has_document(self, doc_id):
        return doc_id.upper() in self.id_map

    def find_id_by_link(self, url):
        """按链接查已收录文档 id（提交去重用）。加 _WRITE_LOCK 与并发 add/update 串行，
        避免「去重扫描」与快车道/其他提交的 add_documents 同时改 docs 列表
        → RuntimeError: list changed size during iteration（list 迭代期间被 resize）。"""
        u = (url or "").rstrip("/")
        if not u:
            return None
        with _WRITE_LOCK:
            for d in self.docs:
                if (d.get("link") or "").rstrip("/") == u:
                    return d.get("id")
        return None

    def add_documents(self, recs):
        """增量追加文档到索引（实时更新快车道用）。返回实际新增数量。
        不落盘、不重建全量索引；派生统计一次性重算。
        整体加 _WRITE_LOCK：快车道实时轮询与「提交链接即时收录」会并发调用本方法，
        不串行化会在 _recompute_stats 迭代 self.df 时撞上另一线程改 df → RuntimeError。"""
        with _WRITE_LOCK:
            from array import array
            if not recs:
                return 0
            added = 0
            for d in recs:
                did = (d.get("id") or "").strip()
                if not did or did.upper() in self.id_map:
                    continue
                _normalize_doc(d)
                i = len(self.docs)
                self.docs.append(d)
                agg, tdl, cvec, phr = self._index_one(i, d)
                self.tf.append(agg)
                self.td_lower.append(tdl)
                self.dl.append(sum(v[0] for v in agg.values()) or 1.0)
                for t in agg:
                    self.df[t] += 1
                    p = self.postings.get(t)
                    if p is None:
                        p = self.postings[t] = array("I")
                    p.append(i)
                self.concept_vecs.append(cvec)
                if isinstance(getattr(self, "phrase_of", None), list):
                    self.phrase_of.append(phr)
                for p in phr:
                    self.phrase_df[p] = self.phrase_df.get(p, 0) + 1
                self.id_map[did.upper()] = i
                self._ids_upper.append(did.upper())
                c = d.get("category")
                if c:
                    self.cat_docs.setdefault(c, set()).add(i)
                self.recency.append(self._recency_of(d))
                for p in d.get("products", []):
                    self.product_counter[p] += 1
                added += 1
                # 每条都同步：检索线程此刻可能正在打分，让它看到一致的文档数，
                # 而不是"dl 已经变长、N 还停在旧值"的半截状态。
                self.N = len(self.docs)
                self._norm = None
            if not added:
                return 0
            self.N = len(self.docs)
            self.avgdl = sum(self.dl) / max(self.N, 1)
            self._recompute_stats()
            self._by_pub_desc = sorted(range(self.N), key=self._pub_key, reverse=True)
            self._global_facets = None        # 文档集变了，全库聚合缓存失效
            self._global_agg = None
            return added

    def update_documents(self, recs):
        """就地更新已存在文档（NVD 会把已收录 CVE 的 CVSS/CWE/描述改掉）。

        为什么不做"删除旧词项再重建"：倒排 postings 里散落着该文档下标，
        精确摘除要扫全部词表（10 万文档下几十万词项），代价远高于收益。
        这里采用增量策略：
          · 结构化字段（desc/cvss/cwe/status/modified/链接）整体覆盖 —— 筛选、展示立即准确
          · 词项只增不减 —— 新描述里的新词能被检索到；旧词残留最多让个别查询多命中一条，
            且 6h 全量轮会彻底重建索引把偏差抹平
        返回实际更新数量。
        """
        with _WRITE_LOCK:
            from array import array
            if not recs:
                return 0
            upd = 0
            for d in recs:
                did = (d.get("id") or "").strip().upper()
                i = self.id_map.get(did)
                if i is None:
                    continue
                old = self.docs[i]
                _normalize_doc(d)
                # 富化结果（poc/文章映射等）以引擎内现有值为准，除非新记录带了值
                merged = dict(old)
                merged.update(d)
                self.docs[i] = merged
                # vuln_docs / kb_docs 与 docs 共享同一批 dict 对象（docs 是两者拼接的结果）。
                # 这里换成 merged 后必须同步写回，否则首页统计（severity / 年份 / 产品，
                # 走 vuln_docs）拿到的还是更新前的旧字段，和详情/检索对不上。
                if i < len(self.vuln_docs):
                    self.vuln_docs[i] = merged
                elif i - len(self.vuln_docs) < len(self.kb_docs):
                    self.kb_docs[i - len(self.vuln_docs)] = merged

                old_agg = self.tf[i] if i < len(self.tf) else {}
                agg, tdl, cvec, phr = self._index_one(i, merged)
                self.tf[i] = agg
                self.td_lower[i] = tdl
                self.dl[i] = sum(v[0] for v in agg.values()) or 1.0
                self.concept_vecs[i] = cvec
                # 只补新词项：old_agg 是 dict，O(1) 判断；别用 `i in postings[t]`，
                # array 的 in 是线性扫描，热门词项 posting 十几万长会直接卡死
                for t in agg:
                    if t in old_agg:
                        continue
                    self.df[t] = self.df.get(t, 0) + 1
                    p = self.postings.get(t)
                    if p is None:
                        p = self.postings[t] = array("I")
                    p.append(i)
                if isinstance(getattr(self, "phrase_of", None), list) \
                        and i < len(self.phrase_of):
                    self.phrase_of[i] = phr
                for p in phr:
                    self.phrase_df[p] = self.phrase_df.get(p, 0) + 1
                self.recency[i] = self._recency_of(merged)
                c = merged.get("category")
                if c:
                    # 分类可能已变：先从旧分类集合里摘掉，再进新分类。
                    # 只加不减的话，改了分类的文档会被旧分类的概念查询继续拉进候选。
                    for _s in self.cat_docs.values():
                        _s.discard(i)
                    self.cat_docs.setdefault(c, set()).add(i)
                for p in merged.get("products", []):
                    self.product_counter[p] += 1
                upd += 1
            if not upd:
                return 0
            self.N = len(self.docs)
            self.avgdl = sum(self.dl) / max(self.N, 1)
            self._recompute_stats()
            self._by_pub_desc = sorted(range(self.N), key=self._pub_key, reverse=True)
            self._global_facets = None
            self._global_agg = None
            return upd

    # ---------------- 查询理解 ----------------
    @staticmethod
    def _extract_ops(raw):
        """抽取 key:value 与 cvss>=N / epss>=N 形式的结构化算子，返回 (ops, 剩余文本)"""
        ops, spans = [], []
        for m in CVSS_CMP_RE.finditer(raw):
            ops.append({"kind": "cvss", "cmp": m.group("op"), "val": m.group("val"),
                        "neg": bool(m.group("neg")), "raw": m.group(0).strip()})
            spans.append(m.span())
        for m in EPSS_CMP_RE.finditer(raw):
            ops.append({"kind": "epss", "cmp": m.group("op"), "val": m.group("val"),
                        "neg": bool(m.group("neg")), "raw": m.group(0).strip()})
            spans.append(m.span())
        for m in OP_RE.finditer(raw):
            if any(s <= m.start() < e for s, e in spans):
                continue
            key = OP_KEYS[m.group("key").lower()]
            val = m.group("val").strip('"').strip()
            entry = {"kind": key, "val": val,
                     "neg": bool(m.group("neg")), "raw": m.group(0).strip()}
            if key == "cvss":
                # cvss:>=9 / cvss:7-9 / cvss:9（裸值按 >= 处理）
                if val[:2] in (">=", "<="):
                    entry["cmp"], entry["val"] = val[:2], val[2:]
                elif val[:1] in (">", "<"):
                    entry["cmp"], entry["val"] = val[:1], val[1:]
                elif "-" in val[1:]:
                    entry["range"] = val
                else:
                    entry["cmp"] = ">="
            if key == "epss":
                # epss:>=0.5 / epss:0.1（裸值按 >= 处理）
                if val[:2] in (">=", "<="):
                    entry["cmp"], entry["val"] = val[:2], val[2:]
                elif val[:1] in (">", "<"):
                    entry["cmp"], entry["val"] = val[:1], val[1:]
                else:
                    entry["cmp"] = ">="
            if key == "severity":
                entry["val"] = SEV_CN.get(val, val).upper()
            ops.append(entry)
            spans.append(m.span())
        text = raw
        for s, e in sorted(spans, reverse=True):
            text = text[:s] + " " + text[e:]
        return ops, text

    def _fuzzy(self, w, maxn=4):
        """OOV 词对索引词典做编辑距离模糊匹配（长度分桶 + 首字母约束）"""
        cap = 1 if len(w) < 8 else 2
        L, first = len(w), w[0]
        cands = []
        for l in range(L - cap, L + cap + 1):
            for t in self.dict_by_len.get(l, ()):
                if t[0] != first or t == w:
                    continue
                dd = _lev(w, t, cap)
                if dd <= cap:
                    cands.append((t, dd, self.df[t]))
        cands.sort(key=lambda x: (x[1], -x[2]))
        out, seen = [], set()
        for t, _, _ in cands:
            if t in seen:
                continue
            seen.add(t)
            out.append(t)
            if len(out) >= maxn:
                break
        return out

    def parse_query(self, q, expand=True):
        raw = (q or "").strip()
        # ① 结构化算子（先从原文剥离，避免 key/value 进入词法层）
        ops, text = self._extract_ops(raw)

        # ② 否定项：-"短语" / -term（数字不算，避免误伤版本/年份）
        must_not = []
        def _neg(m):
            w = m.group(1)
            if not w.isdigit():
                must_not.append(w.lower())
            return " "
        text = NEG_PHRASE_RE.sub(_neg, text)
        text = NEG_TERM_RE.sub(_neg, text)

        ids = [m.group(0).upper() for m in CVE_RE.finditer(text)]
        low = text.lower()

        # ③ 通配符：prompt* / *jail*（剥离后单独对词典展开）
        wildcards = []
        def _wild(m):
            wildcards.append(m.group(0))
            return " "
        low = WILDCARD_RE.sub(_wild, low)

        # 引号短语
        quoted = re.findall(r'"([^"]{2,60})"', low)

        # 中文 n-gram -> 概念 / 扩展
        grams = cjk_ngrams(low)
        cn_hits = sorted({g for g in grams if g in SYNONYMS}, key=len, reverse=True)[:12]

        # 词法项
        terms = Counter()
        for t in tokenize(low):
            terms[t] += 1.0
        primary = set(terms)          # 用户原始输入词（拼写容错只针对这部分）
        if expand:
            for t in list(terms):
                for e in EN_EXTRA.get(t, []):
                    terms[e] = max(terms.get(e, 0), 0.5)

        cn_ph = set()   # 扩展得到的中文/混排列别名 → 走 L2 精确短语层（而非 bigram）

        def _add_alias(a, w=0.6):
            """别名注入：英文按词元 + 整短语；中文记为精确短语（bigram 会把同一短语
               的相关切片独立累加造成重复计分）"""
            if a.isascii():
                for t in tokenize(a):
                    terms[t] = max(terms.get(t, 0), w)
                terms[a] = max(terms.get(a, 0), w)
            else:
                for t in tokenize(a):           # 混排里的英文部分（如 sql注入 -> sql）
                    terms[t] = max(terms.get(t, 0), w)
                if len(a) >= 2:
                    cn_ph.add(a)

        def _add_rev(a, w_en=0.45):
            """反向扩展注入：权重低于正向扩展；缩写在反向扩展中不注入
               （IDF 过高的稀有缩写会主导排序）"""
            if a.isascii():
                if len(a) <= 4 and " " not in a:
                    return
                for t in tokenize(a):
                    terms[t] = max(terms.get(t, 0), w_en)
                terms[a] = max(terms.get(a, 0), w_en)
            else:
                for t in tokenize(a):
                    terms[t] = max(terms.get(t, 0), w_en)
                if len(a) >= 2:
                    cn_ph.add(a)

        expansion = []          # 记录扩展轨迹，供前端展示
        if expand:
            for g in cn_hits:
                expansion.append({"from": g, "to": SYNONYMS[g]})
                for a in SYNONYMS[g]:
                    _add_alias(a)

            # ④ 英文单词命中同义词键（xss / sqli / sqlmap / webshell ...）→ 扩展整组
            en_hits = [t for t in list(terms) if t in SYNONYMS][:8]
            for g in en_hits:
                expansion.append({"from": g, "to": SYNONYMS[g]})
                for a in SYNONYMS[g]:
                    _add_alias(a)

            # ⑤ 查询词命中别名值 → 反向扩展整组（如输入 jailbreak 也能带上「越狱」组）。
            #    单词级英文别名仅放行「有辨识度」的（语料中较少见 jailbreak/kerberoasting），
            #    泛化词（injection/bypass/tool）反向扩展会严重稀释排序。
            rev = set()
            for t in list(terms):
                if not t.isascii() or (len(t) >= 5 and self.df.get(t, 0) < 400):
                    for k in ALIAS2KEYS.get(t, []):
                        rev.add(k)
            for phrase in PHRASE_TERMS:
                if phrase in low:
                    for k in ALIAS2KEYS.get(phrase, []):
                        rev.add(k)
            seen_grp = set(cn_hits) | set(en_hits)
            added = set(x.lower() for x in seen_grp)
            for g in seen_grp:
                added.update(a.lower() for a in SYNONYMS[g])
            for g in sorted(rev, key=len)[:8]:
                if g in seen_grp:
                    continue
                grp = {g.lower()} | {a.lower() for a in SYNONYMS[g]}
                if added and len(grp & added) / len(grp) > 0.5:
                    continue            # 与已扩展组高度重叠（如 rce/远程代码执行 同族），跳过
                seen_grp.add(g)
                added |= grp
                expansion.append({"from": "≈" + g, "to": SYNONYMS[g]})
                _add_rev(g)
                for a in SYNONYMS[g]:
                    _add_rev(a)

        # 概念激活（查询侧）
        q_concepts = defaultdict(float)
        for g in cn_hits:
            for cid in ALIAS2CONCEPT.get(g, []):
                q_concepts[cid] = 1.0
        for phrase in PHRASE_TERMS:
            if phrase in low:
                for t in tokenize(phrase):
                    terms[t] = max(terms.get(t, 0), 0.85)
                for cid in ALIAS2CONCEPT.get(phrase, []):
                    q_concepts[cid] = 1.0
        for t in list(terms):
            for cid in ALIAS2CONCEPT.get(t, []):
                q_concepts[cid] = max(q_concepts[cid], 0.9)

        # 短语集合（用于 L2）：剔除互相嵌套的短短语，避免「language model」与
        # 「large language model」被重复加成
        raw_phrases = set(quoted)
        for p in PHRASE_TERMS:
            if p in low:
                raw_phrases.add(p)
        if expand:
            for g in cn_hits:
                for a in SYNONYMS[g]:
                    if " " in a:
                        raw_phrases.add(a)
            raw_phrases |= cn_ph          # 扩展得到的中文别名 → 精确短语层
        phrases = []
        for p in sorted(raw_phrases, key=len, reverse=True):
            if not any(p != q and p in q for q in phrases):
                phrases.append(p)

        # 中文 bigram 词法项：索引已含 CJK bigram，中文查询可与中文文章直接匹配。
        # 权重取低值（0.5）：bigram 是字级切分，天然比英文整词噪声大，防止淹没词法主信号。
        for g in cjk_ngrams(low, 2, 2):
            if self.df.get(g, 0) > 0:
                terms[g] = max(terms.get(g, 0), 0.5)

        # 通配符展开：对索引词典做正则匹配，按 DF 降序限量注入词法层
        for w in wildcards:
            pat = re.compile("^" + re.escape(w).replace(r"\*", ".*") + "$")
            hits = [t for t in self.dict_terms if pat.match(t)]
            hits.sort(key=lambda t: -self.df[t])
            for t in hits[:24]:
                terms[t] = max(terms.get(t, 0), 0.45)
            expansion.append({"from": "通配 " + w, "to": hits[:6]})

        # 拼写容错：OOV 原始词 → 词典近邻（低权重召回 + did-you-mean）
        corrections = []
        for t in sorted(primary):
            if self.df.get(t, 0) > 0 or len(t) < 4 or not t.isalpha() or not t.isascii():
                continue
            cands = self._fuzzy(t)
            if cands:
                for c in cands[:2]:
                    terms[c] = max(terms.get(c, 0), 0.35)
                corrections.append({"from": t, "to": cands[0], "alts": cands[1:3]})
                expansion.append({"from": "纠错 " + t, "to": cands[:3]})
        did_you_mean = [{"from": c["from"], "to": c["to"]}
                        for c in corrections if self.df[c["to"]] >= 5]

        intent, intent_evidence = self._detect_intent(low)
        # 新增：显式检索工具/文章的意图信号（避免知识类条目被默认压低后检索不到）
        want_repo = bool(re.search(r"工具|仓库|开源|项目|github|repo|框架选型|软件", low))
        want_article = bool(re.search(r"文章|博客|教程|csdn|学习|入门|实践|攻略|经验|分享|原理|解析", low))
        # 漏洞导向查询：CVE/版本/利用/POC 语境下，社区文章/工具仓库应明显让位给漏洞情报
        vuln_intent = bool(re.search(r"漏洞|脆弱性|cve|版本|利用|复现|poc|exp\b|vuln|vulnerab|exploit|patch|补丁|修复|受影响", low))
        return {
            "raw": raw, "ids": ids, "terms": dict(terms), "phrases": phrases,
            "concepts": dict(q_concepts), "expansion": expansion,
            "cn_terms": cn_hits, "intent": intent, "intent_evidence": intent_evidence,
            "want_repo": want_repo, "want_article": want_article, "vuln_intent": vuln_intent,
            "ops": ops, "must_not": must_not, "did_you_mean": did_you_mean,
        }

    # ---------------- 结构化算子匹配 ----------------
    @staticmethod
    def _truthy(v):
        return v.lower() in ("yes", "true", "1", "y", "是", "有", "在野")

    # IOC 提取：从漏洞描述/标题/参考里派生 IP / 域名 / hash（语料无独立 IOC 源时
    # 的兜底，2026-10-07 补 IOC 本体）。显式 ioc 字段优先。
    _IOC_RE = {
        "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "hash": re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I),
        "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
        "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.I),
    }

    @classmethod
    def _extract_ioc(cls, d):
        """返回该条目的 IOC 集合（显式字段 ∪ 从文本派生）。"""
        iocs = set()
        for x in (d.get("ioc") or []):
            if isinstance(x, dict):
                x = x.get("value") or x.get("ioc")
            if x:
                iocs.add(str(x).strip().lower())
        blob = " ".join([str(d.get("title", "")), str(d.get("desc", "")),
                         " ".join(str(r) for r in (d.get("refs") or []))])
        for kind, pat in cls._IOC_RE.items():
            for m in pat.finditer(blob):
                v = m.group(0).strip().rstrip(".").lower()
                if v and not v.startswith(("http://", "https://")):
                    iocs.add(v)
        return iocs

    @classmethod
    def _match_ioc(cls, d, v, lv):
        """ioc: 算子匹配。值为具体 IOC 时精确/子串匹配；值为类型词时按类型判。"""
        typemap = {"ip": "ip", "域名": "domain", "domain": "domain",
                   "hash": "hash", "哈希": "hash", "url": "url", "链接": "url"}
        if lv in typemap:
            return bool(cls._extract_ioc(d))
        iocs = cls._extract_ioc(d)
        return any(lv in x for x in iocs)

    def _match_op(self, d, op):
        k, v = op["kind"], op["val"]
        lv = v.lower()
        if k == "product":
            return any(lv in p.lower() for p in d.get("products", []))
        if k == "vendor":
            return any(lv in x.lower() for x in d.get("vendors", []))
        if k == "cwe":
            vv = v.upper()
            if not vv.startswith("CWE"):
                vv = "CWE-" + vv.lstrip("-")
            return any(w.get("id", "").upper() == vv for w in d.get("cwe", []))
        if k == "severity":
            return (d["cvss"]["severity"] or "UNKNOWN").upper() == v
        if k == "cvss":
            s = d["cvss"]["score"] or 0.0
            if op.get("range"):
                try:
                    a, b = op["range"].split("-", 1)
                    return float(a) <= s <= float(b)
                except ValueError:
                    return False
            try:
                t = float(op["val"])
            except (TypeError, ValueError):
                return False
            cmp_ = op.get("cmp", ">=")
            return {">=": s >= t, "<=": s <= t, ">": s > t, "<": s < t}.get(cmp_, s >= t)
        if k == "epss":
            # EPSS 利用概率算子（P0-2）：文档 epss 字段由 core/priority.attach_epss 挂载。
            ev = d.get("epss")
            if ev is None:
                return False
            try:
                t = float(op["val"])
                e = float(ev)
            except (TypeError, ValueError):
                return False
            cmp_ = op.get("cmp", ">=")
            return {">=": e >= t, "<=": e <= t, ">": e > t, "<": e < t}.get(cmp_, e >= t)
        if k == "year":
            y = (d.get("published") or "")[:4]
            if not y.isdigit():
                return False
            yi = int(y)
            try:
                if v[:2] in (">=", "<="):
                    return yi >= int(v[2:]) if v[:2] == ">=" else yi <= int(v[2:])
                if "-" in v[1:]:
                    a, b = v.split("-", 1)
                    return int(a) <= yi <= int(b)
                return yi == int(v)
            except ValueError:
                return False
        if k == "kev":
            return bool(d.get("kev")) == self._truthy(v)
        if k == "poc":
            return bool(d.get("poc_links")) == self._truthy(v)
        if k == "ioc":
            # IOC 匹配：优先显式 ioc 字段，否则从 desc/title/refs 派生提取。
            # 值可以是具体 IOC（IP/域名/hash）或类型（ip/domain/hash/url）。
            return self._match_ioc(d, v, lv)
        if k == "paper":
            return bool(d.get("papers")) == self._truthy(v)
        if k == "category":
            cat = d.get("category", "")
            short = RISK_CATEGORIES.get(cat, {}).get("short", "")
            # P0-4：子类标签（MCP Server / Agentic AI）也参与分类筛选，
            # 使 /api/search?category=MCP Server 能下钻到子类条目（不改 doc["category"]）。
            subtags = d.get("risk_subtags") or []
            return lv in cat.lower() or v in short or any(
                lv == str(s).lower() or v == s for s in subtags)
        if k == "source":
            return any(lv in s.lower() for s in d.get("sources", []))
        if k == "scope":
            return lv in (d.get("scope", "") or "").lower()
        if k == "type":
            m = {"漏洞": "vulnerability", "工具": "repo", "仓库": "repo",
                 "文章": "article", "论文": "paper"}
            return d.get("type", "vulnerability") == m.get(v, lv)
        return True

    def _match_ops(self, d, ops):
        for op in ops:
            ok = self._match_op(d, op)
            if op["neg"]:
                ok = not ok
            if not ok:
                return False
        return True

    @staticmethod
    def _detect_intent(low):
        best, best_w, ev = DEFAULT_INTENT, 0.0, []
        for name, keys, w in INTENT_RULES:
            hits = [k for k in keys if k in low]
            if hits and len(hits) * w > best_w:
                best, best_w, ev = name, len(hits) * w, hits
        return best, ev

    # ---------------- 检索 ----------------
    def _priority_score(self, i):
        """P0-2：单条文档的漏洞优先级归一化分（0~100），用于 sort=priority。

        口径复用 `core/priority.build()`（CVSS + EPSS + KEV + 可达性）；
        任何缺失/异常一律返回 0（排序时排到最后），**绝不把整次检索打成 500**。
        计算放 core（core↔core），EPSS 值由 `core/priority.attach_epss` 在启动时挂到 doc["epss"]。
        """
        try:
            import priority as _P
        except Exception:  # noqa: BLE001
            try:
                from core import priority as _P  # type: ignore
            except Exception:
                return 0
        try:
            s = _P.build(self.docs[i]).get("score", 0)
            return int(s) if isinstance(s, (int, float)) else 0
        except Exception:  # noqa: BLE001
            return 0

    def search(self, q, filters=None, top_k=30, sort="relevance", page=1, expand=True):
        import time as _t
        t0 = _t.time()
        filters = filters or {}
        qp = self.parse_query(q, expand=expand)
        bias = INTENT_FIELD_BIAS.get(qp["intent"], {})
        terms = qp["terms"]

        # 候选预选：只对「可能得分 >0」的文档打分（倒排索引并集）。
        # 覆盖所有正分来源：词项 BM25 / 短语（其组成词）/ 概念（别名 token + 分类全集）/
        # CVE 号精确 / 产品名精确（产品词本身已索引）。
        browse = not (terms or qp["ids"] or qp["phrases"] or qp["concepts"])
        ops = qp.get("ops") or []
        must_not = qp.get("must_not") or []
        structured = bool(ops or must_not)
        if browse:
            cand = range(self.N)
        else:
            cand_terms = set(terms)
            for c in qp["concepts"]:
                for a in CONCEPTS[c]["aliases"]:
                    cand_terms.update(tokenize(a))
                    cand_terms.update(cjk_ngrams(a, 2, 2))   # 中文别名经 bigram 倒排纳入候选
            for p in qp["phrases"]:
                cand_terms.update(tokenize(p))
                cand_terms.update(cjk_ngrams(p, 2, 2))       # 中文别名短语同理
            cand = set()
            for t in cand_terms:
                hit = self.postings.get(t)
                if hit:
                    cand.update(hit)     # array('I')：set.update 接受任意可迭代对象
            for c in qp["concepts"]:
                cc = CONCEPTS[c]
                if cc["kind"] == "category":
                    cand |= self.cat_docs.get(cc["cat"], set())
            for cid in qp["ids"]:
                j = self.id_map.get(cid.upper())
                if j is not None:
                    cand.add(j)

        # 预过滤（UI 筛选器）
        allowed = self._apply_filters(cand, filters)
        # 查询内结构化算子 + 否定项（硬约束；英文否定项按词边界匹配，
        # 避免 -dos 误伤 windows 这类包含子串的词）
        if structured:
            mn_pats = [re.compile(r"(?<![a-z0-9])" + re.escape(mt) + r"(?![a-z0-9])")
                       if mt.isascii() else None for mt in must_not]
            def _excluded(i):
                for pat, mt in zip(mn_pats, must_not):
                    blob = self._blob_of(i)
                    if (pat.search(blob) if pat else mt in blob):
                        return True
                return False
            allowed = [i for i in allowed
                       if self._match_ops(self.docs[i], ops) and not _excluded(i)]

        # 空查询 → 浏览模式：按时间倒序给出全量概览（含纯算子的结构化筛选）
        if browse:
            label = "结构化筛选" if structured else "浏览模式"
            browse_ev = {label: 1.0}
            scored = [(i, 1.0) for i in allowed]
            scored.sort(key=lambda x: self.docs[x[0]].get("published", ""), reverse=True)
        else:
            qmax_idf = max((self.idf.get(t, 0.0) for t in terms), default=1.0) or 1.0
            bmc = {} if bias else None      # mask→字段偏好倍率 查询级缓存
            # 查询级预计算：词项打分因子 + 文档长度归一因子（旧实现都在每条候选里重算）
            qterms = self._qterms(terms, qmax_idf)
            qmap = dict(qterms)
            self._ensure_norm()
            scored = []
            for i in allowed:
                # want_ev=False：先只算分。证据字典（"匹配依据"）只给最终展示的那一页重建，
                # 旧实现给全部命中文档（动辄 5~6 万条）各建一份字典，纯属浪费（2026-09-28）
                s, _ev = self._score(i, qp, bias, terms, qmax_idf, bmc, qterms, qmap, want_ev=False)
                if s <= 0:
                    continue
                scored.append((i, s))
            scored.sort(key=lambda x: -x[1])
        total = len(scored)

        # 分面统计（基于当前命中集合，用过滤前的集合更利于导航；此处用命中集合）
        # 性能优化：命中集合 == 全库时（空查询/未筛选浏览，也就是首屏默认路径），
        # 分面就是全局分布 —— 复用每代索引只算一次的缓存，省掉 8.8 万条逐条统计（2026-09-28）
        idxs = [i for i, _ in scored]
        facets, agg = self._facets_and_agg(idxs)

        # 排序策略
        #   relevance 相关性（默认）· risk 风险（CVSS）· recent 最新 · trust 可信度
        # trust 为合并新增：跨源合并后同一情报可能被多条管线收录，可信度（多源交叉
        # 验证 + 可利用性 + 时效）成为「该信哪一条」的关键判据，故单独提供排序入口。
        if sort == "risk":
            scored.sort(key=lambda x: (-(self.docs[x[0]]["cvss"]["score"] or 0), -x[1]))
        elif sort == "recent":
            scored.sort(key=lambda x: (self.docs[x[0]]["published"], -x[1]), reverse=True)
        elif sort == "trust":
            scored.sort(key=lambda x: (
                -(self.docs[x[0]].get("confidence")
                  if isinstance(self.docs[x[0]].get("confidence"), (int, float)) else -1),
                -(self.docs[x[0]].get("trust_score")
                  if isinstance(self.docs[x[0]].get("trust_score"), (int, float)) else -1),
                -x[1]))
        elif sort == "priority":
            # P0-2：按漏洞优先级四元组归一化分排序（CVSS/EPSS/KEV/可达性，core/priority.build）。
            # 分值缺失（无 CVSS/EPSS/可达性）一律视为 -1 排到最后，**绝不抛异常**——
            # 早前结构化查询里混入无评分文档会让整次检索 500。
            scored.sort(key=lambda x: (-self._priority_score(x[0]), -x[1]))

        start = max(0, (page - 1) * top_k)
        page_items = scored[start:start + top_k]

        # 只给这一页的条目补算证据（每页 12 条，代价可忽略）
        results = [self._render(i, s,
                                (browse_ev if browse
                                 else self._score(i, qp, bias, terms, qmax_idf, bmc, qterms, qmap)[1]),
                                qp)
                   for i, s in page_items]
        return {
            "query": qp,
            "browse": browse,
            "total": total,
            "page": page, "page_size": top_k,
            "pages": max(1, math.ceil(total / top_k)),
            "results": results,
            "facets": facets,
            "answer": self._answer_card(qp, idxs, filters, browse, structured, agg=agg),
            "elapsed_ms": round((_t.time() - t0) * 1000, 1),
        }

    # ---------------- 打分 ----------------
    def _blob_of(self, i):
        """按需重建文档检索文本（否定项硬约束等稀有路径使用；
        大语料下不再常驻 lower_text 全量副本，节省数百 MB 内存）"""
        d = self.docs[i]
        return " ".join([
            d.get("title", ""), (d.get("desc") or "")[:6000],
            " ".join(d.get("products", [])), " ".join(d.get("vendors", [])),
            " ".join(w.get("id", "") + " " + w.get("name", "") for w in d.get("cwe", [])),
            " ".join(d.get("tags", []) + d.get("osv_packages", [])),
            d.get("category", ""),
        ]).lower()

    def _apply_filters(self, cand, f):
        sev = set(f.get("severity") or [])
        cats = set(f.get("category") or [])
        kinds = set(f.get("kind") or [])
        srcs = set(f.get("source") or [])
        scopes = set(f.get("scope") or [])
        year_from = f.get("year_from")
        year_to = f.get("year_to")
        cvss_min = f.get("cvss_min")
        out = []
        for i in cand:
            d = self.docs[i]
            if sev and (d["cvss"]["severity"] or "UNKNOWN") not in sev:
                continue
            # P0-4：category 过滤器同时接受子类标签（facets.category 里露出的 MCP Server /
            # Agentic AI 可点选下钻），不改 doc["category"]，纯加法。
            if cats and d.get("category") not in cats \
                    and not (cats & set(d.get("risk_subtags") or [])):
                continue
            # P0-1：kind 过滤器（技术标准 / 政策法规 / 行业规范 / 供应链合规）
            if kinds and (d.get("kind") or "") not in kinds:
                continue
            if scopes and d.get("scope", "AI安全") not in scopes:
                continue
            if srcs and not (srcs & set(d.get("sources", []))):
                continue
            if f.get("exploited_only") and not d.get("kev"):
                continue
            if f.get("poc_only") and not d.get("poc_links"):
                continue
            if f.get("has_paper_only") and not d.get("papers"):
                continue
            y = (d.get("published") or "")[:4]
            if y.isdigit():
                if year_from and int(y) < int(year_from):
                    continue
                if year_to and int(y) > int(year_to):
                    continue
            if cvss_min is not None and (d["cvss"]["score"] or 0) < float(cvss_min):
                continue
            out.append(i)
        return out

    def _ensure_norm(self):
        """文档长度归一因子 norm_i = K1*(1-B+B*dl/avgdl)（与查询无关，整库只算一次）。

        旧实现在 _score 里对每条候选重算一次除法+乘法：5~6 万条候选 × 每次检索，
        纯属重复劳动。文档集/avgdl 变化时自动重建（2026-09-28）。
        """
        # 判定基准必须是 len(self.dl) 而不是 self.N：增量写入时 dl 已经 append 了新元素，
        # 而 self.N 要等循环结束才更新，拿 N 判会误以为"没变"，接着 _score 对新下标
        # 取 self._norm[i] 直接 IndexError（并发检索时必现的 500）。
        if self._norm is None or len(self._norm) != len(self.dl) or self._norm_avgdl != self.avgdl:
            k1 = K1 * (1 - B)
            k2 = K1 * B / (self.avgdl or 1.0)
            self._norm = [k1 + k2 * dl for dl in self.dl]
            self._norm_avgdl = self.avgdl
        return self._norm

    def _qterms(self, terms, qmax_idf):
        """把每个查询词项的"与文档无关"部分预先算好：qw_eff * idf * (K1+1)。

        idf / qw_eff / (K1+1) 三项都只依赖查询，旧实现却放在每条文档的循环里重算
        （6 万条 × 十几个词项 = 百万次浮点运算/次检索）。提到循环外后数值完全等价。
        """
        idf_map = self.idf
        cap = self.bigram_idf_cap
        out = []
        for t, qw in terms.items():
            idf = idf_map.get(t, 0.0)
            if idf <= 0:
                continue
            # CJK bigram 是字级切分，其"稀有度"是切分伪影而非语义特异度
            # （如 码执/程代 在英文为主的语料里天然高 IDF），压制其 IDF 上限，
            # 否则扩展注入的 bigram 会让中文短文以数倍分数压过字面命中的英文 CVE
            if len(t) == 2 and not t.isascii():
                idf = min(idf, cap)
            # 查询词 IDF 归一：判别性词（jailbreak）应压过通用词（model）
            qw_eff = qw * (0.35 + 0.65 * min(idf / qmax_idf, 1.0))
            out.append((t, qw_eff * idf * (K1 + 1)))
        return out

    def _score(self, i, qp, bias, terms, qmax_idf=1.0, bmc=None, qterms=None, qmap=None,
               want_ev=True):
        # 热路径（每次检索要对数万条候选打分）：把属性查找绑成局部变量，
        # 8.8 万条 × 每条约 10 个词项时，省下的属性查找是可观的毫秒数（2026-09-28）
        tf = self.tf[i]
        s = 0.0
        ev = {}
        # 兜底：并发增量写入期间 _norm 可能还没补到最新下标（长度归一因子的
        # 重建由 _ensure_norm 触发），与其 IndexError 让整个请求 500，
        # 不如对这条现算一次（一次除法，代价可忽略）。
        if self._norm is not None and i < len(self._norm):
            norm = self._norm[i]
        else:
            norm = K1 * (1 - B + B * self.dl[i] / (self.avgdl or 1.0))
        if qterms is None:
            qterms = self._qterms(terms, qmax_idf)
        if qmap is None:
            qmap = dict(qterms)
        if bias:
            bias_get = bias.get
            field_order = FIELD_ORDER

        def _add(t, tv, factor):
            """单个词项的 BM25 贡献（含字段偏好倍率）"""
            nonlocal s
            contrib = factor * tv[0] / (tv[0] + norm)
            if bias:
                mask = tv[1]
                mult = bmc.get(mask) if bmc is not None else None
                if mult is None:
                    mult = 1.0
                    for bi, fn in enumerate(field_order):
                        if mask >> bi & 1:
                            bv = bias_get(fn, 1.0)
                            if bv > mult:
                                mult = bv
                    if bmc is not None:
                        bmc[mask] = mult
                contrib *= mult
            s += contrib
            if want_ev:
                ev[t] = ev.get(t, 0.0) + contrib

        # 短侧迭代：查询词项经同义词/中文 bigram 扩展后常有几十个，而多数文档只包含其中几个 ——
        # 谁短就遍历谁，省掉大量"查了但没有"的 dict.get（命中集合大时这是主要开销，2026-09-28）
        if len(tf) < len(qterms):
            for t, tv in tf.items():
                factor = qmap.get(t)
                if factor is not None:
                    _add(t, tv, factor)
        else:
            for t, factor in qterms:
                tv = tf.get(t)
                if tv:
                    _add(t, tv, factor)

        # L2 短语加成（按短语 IDF 加权，抑制高频短语的通胀效应）
        blob_title, blob_desc = self.td_lower[i]
        phrase_idf = self.phrase_idf
        for p in qp["phrases"]:
            pidf = phrase_idf.get(p)
            if pidf is None:
                pidf = 2.0
            if p in blob_title:
                add = 0.62 * pidf
                s += add
                if want_ev:
                    ev["«" + p + "»"] = ev.get("«" + p + "»", 0) + add
            elif p in blob_desc:
                add = 0.30 * pidf
                s += add
                if want_ev:
                    ev["«" + p + "»"] = ev.get("«" + p + "»", 0) + add

        # L3 概念空间匹配（按概念 IDF 加权）
        cvec = self.concept_vecs[i]
        if cvec and qp["concepts"]:
            concept_idf = self.concept_idf
            shared = set(cvec) & set(qp["concepts"])
            if shared:
                cscore = sum(qp["concepts"][c] * cvec[c] * concept_idf.get(c, 1.0)
                             for c in shared) / max(len(qp["concepts"]), 1)
                add = min(2.8 * cscore, 12.0)
                s += add
                for c in sorted(shared, key=lambda x: -concept_idf.get(x, 0))[:4]:
                    lab = CONCEPTS[c]["label"]
                    if want_ev:
                        ev["◆" + lab] = ev.get("◆" + lab, 0) + add / min(len(shared), 4)

        # CVE 号精确命中
        if qp["ids"] and self.docs[i]["id"].upper() in qp["ids"]:
            s += 120.0
            if want_ev:
                ev[self.docs[i]["id"]] = 120.0

        # 产品名精确命中（"ollama 漏洞" 应优先返回 Ollama 本体漏洞）
        for p in self.docs[i].get("products", []):
            if p.lower() in terms:
                s += 9.0
                if want_ev:
                    ev["@" + p] = 9.0

        # 知识类条目类型微调：
        #   显式想找工具/文章 → 加成；漏洞导向查询 → 强降权；默认 → 轻降权。
        # 全部记录进 ev，保持可解释。
        dtype = self.docs[i].get("type", "vulnerability")
        if dtype == "repo":
            mod = 1.30 if qp.get("want_repo") else (0.50 if qp.get("vuln_intent") else 0.88)
        elif dtype == "article":
            mod = 1.30 if qp.get("want_article") else (0.40 if qp.get("vuln_intent") else 0.93)
        elif dtype == "paper":
            # 论文条目：论文研究意图加成，漏洞导向强降权，默认轻降权
            mod = 1.35 if qp.get("intent") == "论文研究" else (0.45 if qp.get("vuln_intent") else 0.92)
        else:
            mod = 1.0
        if mod != 1.0 and s > 0:
            ev["⇕" + ("工具/仓库加成" if mod > 1 else ("漏洞导向·知识条目降权" if qp.get("vuln_intent") else "知识条目降权"))] = \
                ev.get("⇕", 0) + (mod - 1.0) * s
            s *= mod

        # L4 时效微调：半衰期 1.5 年，上限 +10%（相关性仍绝对主导）
        rf = self.recency[i]
        if rf > 0.02 and s > 0:
            add = s * min(0.10 * rf, 0.10)
            s += add
            if want_ev:
                ev["⏱时效微调"] = ev.get("⏱时效微调", 0) + add

        # F2 返修：标准/法规结构化条目「标题精确命中」窄加权（**不动 BM25 主公式**）。
        # 仅当 ①id 以 STD:/REG: 开头 且 ②归一化查询串是归一化标题的子串 —— 此时加固定分，
        # 使「生成式人工智能服务管理暂行办法」这类查询的首条回到结构化条目，
        # 而非被 CSDN 转述文章顶掉。条件极窄（要求整串标题子串），对通用查询几乎不触发。
        # 性能：探针归一化只对 STD:/REG: 候选（数十条）执行，且不写入 qp（避免污染出参）。
        did2 = self.docs[i]["id"]
        if did2.startswith(("STD:", "REG:")):
            probe = _norm_probe(qp.get("raw", ""))
            if probe and probe in _norm_probe(self.docs[i].get("title", "")):
                s += _STDLIKE_TITLE_BOOST
                if want_ev:
                    ev["⊞标准条款标题命中"] = ev.get("⊞标准条款标题命中", 0) + _STDLIKE_TITLE_BOOST

        return s, ev

    # ---------------- 渲染 ----------------
    def _render(self, i, score, ev, qp):
        d = self.docs[i]
        top_ev = sorted(ev.items(), key=lambda x: -x[1])[:6]
        return {
            "id": d["id"],
            "type": d.get("type", "vulnerability"),
            "kind": d.get("kind", ""),
            "title": d.get("title", ""),
            # 原文外链（2026-10-12）：检索卡片上的「↗ 原文」按钮直接用它，
            # 不必再点开详情才能拿到链接
            "url": canonical_url(d),
            "published": (d.get("published") or "")[:10],
            "modified": (d.get("modified") or "")[:10],
            "status": d.get("status", ""),
            "cvss": d.get("cvss") or {"score": None, "severity": "", "vector": ""},
            "cwe": [w for w in d.get("cwe", []) if isinstance(w, dict)][:4],
            "products": d.get("products", [])[:6],
            "vendors": d.get("vendors", [])[:4],
            "category": d.get("category", ""),
            "scope": d.get("scope", "AI安全"),
            "category_short": RISK_CATEGORIES.get(d.get("category", ""), {}).get("short", ""),
            "category_color": RISK_CATEGORIES.get(d.get("category", ""), {}).get("color", "#888"),
            "category_reason": d.get("category_reason", ""),
            "tags": d.get("tags", []),
            "risk_tags": d.get("risk_tags", []),
            "sources": d.get("sources", []),
            "osv_packages": d.get("osv_packages", []),
            "exploited": bool(d.get("kev")),
            # —— 证据可信度 / 多源交叉验证 / 可利用性（credibility.py 富化后挂载）——
            # 有则透出、无则为空值；保证「可信度检索卡片」字段通路完整（合并自网盘版）
            "trust_score": d.get("trust_score"),
            "trust_level": d.get("trust_level", ""),
            "trust_label": d.get("trust_label", ""),
            "cross_count": d.get("cross_count", 0),
            "cross_label": d.get("cross_label", ""),
            "cross_verified": bool(d.get("cross_verified")),
            "exploit_score": d.get("exploit_score"),
            "exploit_label": d.get("exploit_label", ""),
            "freshness": d.get("freshness"),
            "confidence": d.get("confidence"),
            "poc_count": len(d.get("poc_links", [])),
            "patch_count": len(d.get("patch_links", [])),
            "paper_count": len(d.get("papers", [])),
            "atlas": [{"id": t.get("id", ""), "name": t.get("name", "")}
                      for t in d.get("atlas", [])][:4],
            "mitigation_count": len(d.get("atlas_mitigations", [])),
            "ai_score": d.get("ai_score"),
            "score": round(score, 3),
            "stars": d.get("stars"),
            "views": d.get("views"),
            "author": d.get("author", ""),
            "language": d.get("language", ""),
            "evidence": [{"term": t, "weight": round(w, 2)} for t, w in top_ev],
            "why": self._why(top_ev, qp),
            "snippet": self._snippet(d, qp),
        }

    @staticmethod
    def _why(top_ev, qp):
        parts = []
        lits = [t for t, _ in top_ev if not t[0] in "«◆@⇕⏱"]
        ph = [t.strip("«»") for t, _ in top_ev if t.startswith("«")]
        cp = [t[1:] for t, _ in top_ev if t.startswith("◆")]
        pr = [t[1:] for t, _ in top_ev if t.startswith("@")]
        if pr:
            parts.append("受影响组件精确命中 " + "、".join(pr))
        if ph:
            parts.append("术语短语命中「" + "」「".join(ph) + "」")
        if lits:
            parts.append("关键词 " + "、".join(lits[:5]))
        if cp:
            parts.append("概念关联：" + "、".join(cp[:3]))
        if not parts:
            parts.append("弱相关命中")
        return "；".join(parts)

    def _snippet(self, d, qp):
        """返回高亮片段（HTML）"""
        text = d.get("desc", "")
        terms = set(t for t in qp["terms"] if len(t) > 2 or (len(t) == 2 and not t.isascii()))
        for p in qp["phrases"]:
            terms.add(p)
        sents = re.split(r"(?<=[.;])\s+", text)
        best, best_n = "", -1
        for s in sents:
            low = s.lower()
            n = sum(3 if " " in t else 1 for t in terms if t in low)
            if n > best_n:
                best, best_n = s, n
        frag = best if best_n > 0 else text[:300]
        if not best_n > 0:
            frag = text[:300] + ("…" if len(text) > 300 else "")
        return self._highlight(frag[:460], terms)

    @staticmethod
    def _escape(t):
        return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    @classmethod
    def _highlight(cls, text, terms):
        out = cls._escape(text)
        for t in sorted(terms, key=len, reverse=True):
            if len(t) < 3 and t.isascii():   # 中文 bigram（2 字）保留高亮
                continue
            out = re.sub("(" + re.escape(cls._escape(t)) + ")", r"<mark>\1</mark>", out, flags=re.I)
        return out

    # ---------------- 聚合 ----------------
    def _facets(self, idxs):
        docs = self.docs
        cat, sev, src, yr, prod, cwe, scope = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
        # P0-1/P0-4：新增 kind（标准/法规计数维度）与 risk_subtags（MCP Server / Agentic AI 子类）。
        # **纯加法**：不改既有 facet 键与排序主逻辑，只在末尾把子类计数并入 category。
        kind, sub = Counter(), Counter()
        for i in idxs:
            d = docs[i]
            cat[d.get("category", "未分类")] += 1
            sev[(d.get("cvss") or {}).get("severity") or "UNKNOWN"] += 1
            scope[d.get("scope", "AI安全")] += 1
            _k = d.get("kind")
            if _k:
                kind[_k] += 1
            for _t in (d.get("risk_subtags") or []):
                sub[_t] += 1
            for s in d.get("sources", []):
                src[s] += 1
            y = (d.get("published") or "")[:4]
            if y.isdigit():
                yr[y] += 1
            for p in d.get("products", [])[:3]:
                prod[p] += 1
            for w in d.get("cwe", [])[:2]:
                if isinstance(w, dict):
                    cwe[w.get("id", "")] += 1
        cat_items = cat.most_common()
        seen_cat = {k for k, _ in cat_items}
        for _t, _c in sub.most_common():
            if _t not in seen_cat:                     # 子类名不与 ①~⑪ 冲突，追加而非打散
                cat_items.append((_t, _c))
        return {
            "category": cat_items,
            "severity": sev.most_common(),
            "scope": scope.most_common(),
            "source": src.most_common(),
            "year": sorted(yr.items(), reverse=True),
            "product": prod.most_common(10),
            "cwe": cwe.most_common(10),
            "kind": kind.most_common(),
        }

    def _facets_fast(self, idxs):
        """命中集合覆盖全库时（空查询 / 未筛选浏览 —— 首屏默认路径）复用全局分面缓存。

        旧实现无论命中多少都逐条统计一遍：8.8 万条文档 ≈ 0.45s，而首屏恰好是这条路径。
        索引一代只算一次，命中集合变小（有查询词或筛选）时仍走逐条统计（2026-09-28）。
        """
        if len(idxs) == self.N:
            if self._global_facets is None:
                self._global_facets = self._facets(range(self.N))
            return self._global_facets
        return self._facets(idxs)

    def _scan(self, idxs):
        """一次遍历同时产出「分面」与「答复卡统计」。

        旧实现是 _facets + _aggregate 两次全量扫描；命中 5 万条时这两步合计约 0.45s，
        合并后省掉一整遍。category / severity 两个计数器两边口径一致，直接共用（2026-09-28）。
        """
        docs = self.docs
        cat = Counter()
        sev = Counter()
        src = Counter()
        yr = Counter()
        prod3 = Counter()
        prod2 = Counter()
        cwe = Counter()
        scope = Counter()
        # P0-1/P0-4：与 _facets 同口径 —— kind（标准/法规）+ 子类计数（并入 category）。
        kind = Counter()
        sub = Counter()
        exploited = poc = papers = 0
        for i in idxs:
            d = docs[i]
            c = d.get("category", "未分类")
            cat[c] += 1
            s = (d.get("cvss") or {}).get("severity") or "UNKNOWN"
            sev[s] += 1
            scope[d.get("scope", "AI安全")] += 1
            _k = d.get("kind")
            if _k:
                kind[_k] += 1
            for _t in (d.get("risk_subtags") or []):
                sub[_t] += 1
            for x in d.get("sources", []):
                src[x] += 1
            y = (d.get("published") or "")[:4]
            if y.isdigit():
                yr[y] += 1
            ps = d.get("products", [])
            for p in ps[:3]:
                prod3[p] += 1
            for p in ps[:2]:
                prod2[p] += 1
            for w in d.get("cwe", [])[:2]:
                if isinstance(w, dict):
                    cwe[w.get("id", "")] += 1
            if d.get("kev"):
                exploited += 1
            if d.get("poc_links"):
                poc += 1
            if d.get("papers"):
                papers += 1
        cat_items = cat.most_common()
        seen_cat = {k for k, _ in cat_items}
        for _t, _c in sub.most_common():
            if _t not in seen_cat:
                cat_items.append((_t, _c))
        facets = {
            "category": cat_items,
            "severity": sev.most_common(),
            "scope": scope.most_common(),
            "source": src.most_common(),
            "year": sorted(yr.items(), reverse=True),
            "product": prod3.most_common(10),
            "cwe": cwe.most_common(10),
            "kind": kind.most_common(),
        }
        return facets, (sev, cat, prod2, exploited, poc, papers)

    def _facets_and_agg(self, idxs):
        """分面 + 答复卡统计（全库命中走缓存，否则一次扫描同时给出）"""
        if len(idxs) == self.N:
            if self._global_facets is None or self._global_agg is None:
                f, a = self._scan(range(self.N))
                self._global_facets, self._global_agg = f, a
            return self._global_facets, self._global_agg
        return self._scan(idxs)

    def _aggregate(self, idxs):
        """一次遍历同时算 6 项统计（旧实现是 6 个独立生成器 = 6 遍全量扫描）"""
        docs = self.docs
        sev, cats, prods = Counter(), Counter(), Counter()
        exploited = poc = papers = 0
        for i in idxs:
            d = docs[i]
            sev[d["cvss"]["severity"] or "UNKNOWN"] += 1
            cats[d.get("category", "未分类")] += 1
            for p in d.get("products", [])[:2]:
                prods[p] += 1
            if d.get("kev"):
                exploited += 1
            if d.get("poc_links"):
                poc += 1
            if d.get("papers"):
                papers += 1
        return sev, cats, prods, exploited, poc, papers

    def _answer_card(self, qp, idxs, filters, browse=False, struct_only=False, agg=None):
        n = len(idxs)
        if agg is None:
            if n == self.N:                   # 全库命中：复用索引级缓存（首屏路径）
                if self._global_agg is None:
                    self._global_agg = self._aggregate(range(self.N))
                agg = self._global_agg
            else:
                agg = self._aggregate(idxs)
        sev, cats, prods, exploited, poc, papers = agg
        crit = sev.get("CRITICAL", 0) + sev.get("HIGH", 0)

        bullets = [f"命中 {n} 条 AI 安全情报（其中高危/严重 {crit} 条）"]
        if qp.get("ops"):
            bullets.append("已应用结构化算子：" + " ".join(op["raw"] for op in qp["ops"][:6]))
        if qp.get("must_not"):
            bullets.append("已排除包含：" + "、".join(qp["must_not"][:5]))
        if exploited:
            bullets.append(f"{exploited} 条已被 CISA 列入在野利用清单，建议优先处置")
        if poc:
            bullets.append(f"{poc} 条存在公开 POC/利用代码，可被快速复现")
        if prods:
            bullets.append("涉及组件 Top： " + "、".join(f"{p}({c})" for p, c in prods.most_common(5)))
        if cats:
            bullets.append("风险分布：" + "、".join(f"{c}({v})" for c, v in cats.most_common(4)))
        if papers:
            bullets.append(f"{papers} 条已自动关联 AI 安全学术论文")

        plan = {
            "修复建议": ["定位受影响版本区间，升级至官方修复版本", "核对补丁提交与厂商公告链接",
                     "检查是否存在联网暴露实例并收敛访问控制"],
            "影响范围": ["按 CPE 厂商/产品聚合受影响资产", "核对版本区间与部署形态",
                     "排查同厂商其他组件的连带影响"],
            "POC与利用": ["优先处置存在公开 POC 与在野利用的条目", "在隔离环境复现验证",
                      "核查日志中是否存在对应攻击特征"],
            "资产暴露": ["统计公网暴露面与实例数", "梳理资产清单与责任人", "制定收敛与加固方案"],
            "论文研究": ["按关联强度阅读论文摘要", "提取攻击面与防御建议", "沉淀为检测规则"],
            "攻击链": ["自入口点梳理：未授权接口 → 注入/解析 → 权限提升", "串联 CWE 与 ATT&CK 阶段",
                    "输出可利用性判定与阻断点"],
            "统计趋势": ["按年份观察披露趋势", "按组件与弱点类型定位高发区域", "跟踪新高危条目"],
            "最新动态": ["按发布时间倒序跟踪新披露", "关注在野利用标记变化", "订阅关键组件公告"],
        }.get(qp["intent"], ["按相关性排序查看证据", "结合筛选器缩小范围", "打开详情查看富化信息"])

        return {
            "intent": ("结构化筛选" if struct_only else "全量浏览") if browse else qp["intent"],
            "intent_evidence": qp["intent_evidence"],
            "did_you_mean": qp.get("did_you_mean", []),
            "ops": [op["raw"] for op in qp.get("ops", [])][:8],
            "must_not": qp.get("must_not", [])[:8],
            "summary": bullets,
            "plan": (["使用顶部搜索框用自然语言提问", "用左侧筛选与排序快速缩小范围", "点击任一情报查看全量富化详情"]
                     if (browse and not struct_only) else plan),
            "expansion": [
                {"from": e["from"], "to": e["to"][:6]} for e in qp["expansion"][:8]
            ],
            "concepts": [CONCEPTS[c]["label"] for c in list(qp["concepts"])[:8]],
            "stats": {
                "total": n, "critical_high": crit, "exploited": exploited, "poc": poc,
                "papers": papers,
                "severity": dict(sev),
                "category": dict(cats),
            },
        }

    # ---------------- 详情 ----------------
    def detail(self, cid):
        i = self.id_map.get((cid or "").upper())
        return self.docs[i] if i is not None else None

    def stats(self):
        m = self.corpus.get("meta", {})
        sev = Counter(d["cvss"]["severity"] or "UNKNOWN" for d in self.vuln_docs)
        cat = Counter(d.get("category", "") for d in self.docs)
        src = Counter(s for d in self.docs for s in d.get("sources", []))
        yrs = Counter((d.get("published") or "")[:4] for d in self.vuln_docs)
        kb_type = Counter(d.get("type", "knowledge") for d in self.kb_docs)
        scope = Counter(d.get("scope", "AI安全") for d in self.docs)
        # P0-1：标准/法规条目按 kind 计数（技术标准/政策法规/行业规范/供应链合规）。
        # 计在 self.docs 上 —— 标准条目是运行期 inject 进来的，不在 kb_docs 里。
        kind_counts = Counter(d.get("kind") for d in self.docs if d.get("kind"))
        return {
            "meta": m,
            "total": len(self.docs),
            "vulnerabilities": len(self.vuln_docs),
            "knowledge": len(self.kb_docs),
            "scope": scope.most_common(),
            "kb_type": kb_type.most_common(),
            "kind_counts": dict(kind_counts),
            "atlas": self.corpus.get("atlas", {}),
            "severity": sev.most_common(),
            "category": [{"name": k, "count": v, "color": RISK_CATEGORIES.get(k, {}).get("color", "#888")}
                         for k, v in cat.most_common()],
            "source": src.most_common(),
            "years": sorted([(k, v) for k, v in yrs.items() if k.isdigit()]),
            "exploited": sum(1 for d in self.docs if d.get("kev")),
            "poc": sum(1 for d in self.docs if d.get("poc_links")),
            "papers": len(self.papers),
            "paper_linked": sum(1 for d in self.docs if d.get("papers")),
            "terms": len(self.df),
            "products": Counter(p for d in self.vuln_docs for p in d.get("products", [])).most_common(12),
        }

    def suggest(self, q):
        """检索建议：CVE 号 / 组件（按词频）/ 英文术语 / 中文术语 / 拼写建议"""
        q = (q or "").strip().lower()
        out = {"cves": [], "products": [], "terms": [], "cn_terms": []}
        if not q:
            return out
        qu = q.upper()
        out["cves"] = []
        for i, iu in enumerate(self._ids_upper):
            if qu in iu:
                out["cves"].append(self.docs[i]["id"])
                if len(out["cves"]) >= 8:
                    break
        pcnt = Counter()
        for p, c in self.product_counter.items():
            if q in p.lower():
                pcnt[p] = c
        out["products"] = [p for p, _ in pcnt.most_common(8)]
        out["terms"] = [t for t in PHRASE_TERMS if q in t][:8]
        # 中文术语：命中 SYNONYMS 键时提示对应英文扩展（降低中英鸿沟的输入门槛）
        if CJK_RE.search(q):
            out["cn_terms"] = [k for k in SYNONYMS if q in k][:8]
        # 拼写建议：产品无命中且像英文单词时，对产品名做编辑距离 1 纠错
        if not out["products"] and q.isascii() and q.isalpha() and len(q) >= 4:
            alt = sorted(((p, _lev(q, p.lower(), 1), c)
                          for p, c in self.product_counter.items()
                          if abs(len(p) - len(q)) <= 1 and p[0].lower() == q[0]),
                         key=lambda x: (x[1], -x[2]))
            out["products"] = [p for p, dd, _ in alt if dd <= 1][:5]
        return out

    def latest(self, n=14):
        """最新情报 feed：按发布时间（次要按更新时间）倒序，供「实时监测」面板。
        过滤未来日期（Crossref 论文的印刷出版日常是 2026-12-31 之类的占位日期）。
        只对"能解析成合法 ISO 日期"的记录做未来过滤——坏日期（历史脏数据）
        不再被字符串比较误判成未来日期而整条隐藏（2026-09-28 修复）。"""
        import datetime as _dt
        today = (_dt.date.today() + _dt.timedelta(days=1)).isoformat()

        pool = (self.docs[i] for i in self._by_pub_desc)
        ds = []
        for d in pool:
            pub = (d.get("published") or "")[:10]
            if pub and _ISO_DATE_RE.match(pub) and pub > today:
                continue
            ds.append(d)
            if len(ds) >= n:
                break
        # 用户投稿置顶：保证「提交链接即时收录」的文章一定出现在 feed 顶部，
        # 不被同日大量条目淹没（即便其发布日期不是最新的）。
        # 扫描全库挑 submitted 是 O(n)（~10万条，亚毫秒级），feed 调用频次低，可接受。
        sub = [(i, d) for i, d in enumerate(self.docs) if d.get("submitted")]
        if sub:
            sub.sort(key=lambda x: x[0], reverse=True)      # 新提交的在末尾 → 反转置顶
            sub_ids = {id(d) for _, d in sub}
            rest = [d for d in ds if id(d) not in sub_ids]
            ordered = [d for _, d in sub] + rest
        else:
            ordered = ds
        ordered = ordered[:n]
        return {
            "total": len(self.docs),
            "items": [{
                "id": d["id"],
                "type": d.get("type", "vulnerability"),
                "kind": d.get("kind", ""),
                "title": d.get("title", ""),
                "published": (d.get("published") or "")[:10],
                "modified": (d.get("modified") or "")[:10],
                "cvss": d["cvss"]["score"],
                "severity": d["cvss"]["severity"] or "",
                "products": (d.get("products") or [])[:3],
                "category": d.get("category", ""),
                "is_new": "实时新增" in (d.get("tags") or []),
                "exploited": bool(d.get("kev")),
                "submitted": bool(d.get("submitted")),
                "quality_tier": d.get("quality_tier", ""),
                "link": d.get("link", ""),
                "views": d.get("views"),
                "stars": d.get("stars"),
            } for d in ordered],
        }

    def similarity_to_existing(self, rec, top_k=8):
        """近重检测：把 rec 当成查询，用现有索引找最相似的已收录文档。

        返回 {"content_containment", "title_sim", "similar_id", "similar_title"}：
          · content_containment：新文章词项质量（权重）被某篇已收录文档覆盖的比例（0~1）
          · title_sim：标题词袋 Jaccard（0~1），转载/雷同标题几乎一致 → 接近 1
        用于「提交链接即时收录」过滤掉过分相同的文章（同文转载 / 高度雷同）。
        复用 _index_one（不改引擎状态）与 search（倒排并集打分），无需为新检测建独立索引。
        """
        # 1) 新文章的词项权重（复用索引构建逻辑，i=0 仅占位，不写入引擎）
        try:
            agg, (title_lo, _), _, _ = self._index_one(0, rec)
        except Exception:  # noqa: BLE001
            return {"content_containment": 0.0, "title_sim": 0.0,
                    "similar_id": None, "similar_title": None}
        if not agg:
            return {"content_containment": 0.0, "title_sim": 0.0,
                    "similar_id": None, "similar_title": None}
        total = sum(v[0] for v in agg.values()) or 1.0
        qtext = (rec.get("title") or "") + " " + (rec.get("desc") or "")[:2000]
        new_title_tokens = set(tokenize(title_lo)) | set(cjk_ngrams(title_lo, 2, 2))
        # 候选来源（并集）：
        #   · search 召回（top_k 放大到 30，覆盖「与语料库已有文档雷同」）
        #   · 新文权重最高的若干词项的倒排并集 —— 关键：刚提交的近似稿尚未在 BM25
        #     相关排序里冒头（被长文档的 IDF 压强压在 top8 之外），但共享高权重词项必在
        #     其倒排里，直接拉倒排即可比到，确保「同一篇稿件被不同链接重复提交」能被拦下。
        cand_set = set()
        try:
            res = self.search(qtext, top_k=max(top_k, 30), expand=True)
            for r in (res or {}).get("results", []):
                j = self.id_map.get((r.get("id") or "").upper())
                if j is not None:
                    cand_set.add(j)
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("core/engine.py:2092", _sw_e)
        # 权重最高 12 个词项的倒排并集。
        # 实测正常文章并集约 1000 条（全库 1%），不是瓶颈。这里只加一道防御：
        # df 超过全库六成的词项（「漏洞」这类）几乎没有区分度，拉进来等于让下面
        # 的逐篇比对白扫一遍。正常文章不会触发，留着是防极端长文把并集撑成全库扫描。
        # 试过按 df 升序只取稀有词项（阈值 20000），实测会把并集打到 0 条、
        # 近重检测只剩 search 召回，判别力反而下降，故放弃。
        _MAX_CAND_DF = int(self.N * 0.6) if self.N else 0
        for t, _ in sorted(agg.items(), key=lambda kv: -kv[1][0])[:12]:
            if _MAX_CAND_DF and self.df.get(t, 0) > _MAX_CAND_DF:
                continue
            hit = self.postings.get(t)
            if hit:
                cand_set.update(hit)
        best = None  # (score, cont, tsim, rid, rtitle)
        for i in cand_set:
            tfi = self.tf[i]
            inter = 0.0
            for t, e in agg.items():           # 词项质量包含率：新文章词项被该文档覆盖多少
                c = tfi.get(t)
                if c:
                    inter += min(e[0], c[0])
            cont = inter / total
            ti = self.docs[i]
            ti_title = (ti.get("title") or "").lower()
            ti_tokens = set(tokenize(ti_title)) | set(cjk_ngrams(ti_title, 2, 2))
            tsim = _jaccard(new_title_tokens, ti_tokens)
            score = max(cont, tsim)
            if best is None or score > best[0]:
                best = (score, cont, tsim, ti.get("id"), ti.get("title"))
        if best is None:
            return {"content_containment": 0.0, "title_sim": 0.0,
                    "similar_id": None, "similar_title": None}
        return {"content_containment": best[1], "title_sim": best[2],
                "similar_id": best[3], "similar_title": best[4]}


def attach_subtags(engine):
    """P0-4：把 taxonomy.subclassify() 派生的风险子类标签挂到 engine.docs 的 doc["risk_subtags"]。

    与 `ensure_credibility` 挂 trust_score 同范式：在引擎加载后运行期挂载，
    **不改 doc["category"]**（保证 ①~⑪ 历史统计 414/741/1139/538 不减少），
    只让 facets.category 与 category 过滤器能露出/下钻 MCP Server / Agentic AI 子类。

    返回挂上至少 1 个子类的文档数（幂等：已挂过的文档不重复计算）。
    """
    if engine is None:
        return 0
    if getattr(engine, "_subtags_attached", False):
        return getattr(engine, "_subtags_count", 0)
    docs = getattr(engine, "docs", None) or []
    n = 0
    for d in docs:
        if not isinstance(d, dict):
            continue
        try:
            tags = subclassify(d)
        except Exception:  # noqa: BLE001
            tags = []
        d["risk_subtags"] = tags
        if tags:
            n += 1
    try:
        engine._subtags_attached = True
        engine._subtags_count = n
    except Exception:  # noqa: BLE001
        pass
    return n


def _jaccard(a, b):
    """两个词袋集合的 Jaccard 相似度（0~1）。"""
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# 分类概念由 taxonomy 风险分类驱动（在 build_concepts 内生成）


if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    e = SearchEngine(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "corpus.json"))
    print("docs:", len(e.docs))
    for q in ["ollama 远程代码执行", "提示词注入", "langchain 反序列化"]:
        r = e.search(q, top_k=3)
        print("=" * 60)
        print("Q:", q, "| intent:", r["answer"]["intent"], "| total:", r["total"])
        print("summary:", r["answer"]["summary"][:2])
        for x in r["results"]:
            print(f"  {x['id']:18s} {x['cvss']['score']} {x['products'][:2]} | {x['why'][:90]}")
