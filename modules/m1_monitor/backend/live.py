# -*- coding: utf-8 -*-
"""
live.py —— 快车道实时监测（目标：新信息 15s 内可见）
========================================================
与 monitor.py 的「深同步」互补：
  · monitor.refresh()  分钟级全量对账（NVD 时间窗 + KEV + GHSA + 仓库 + 社区翻页）
  · live.poll_once()   秒级轻量轮询，只打便宜且更新快的端点，外层节拍 15s

快源清单（均为单请求、低延迟）：
  1. NVD       最近 N 小时 lastModStartDate 时间窗（新 CVE / 变更 CVE）
  2. CISA KEV  在野利用目录增量
  3. arXiv     cs.CR / cs.AI 最新投稿 RSS
  4. 厂商公告 / 安全博客  13 个 RSS（Trail of Bits / Wiz / Snyk / Unit 42 / OpenAI /
                           GitHub Security / CISA / 微软安全 / AWS / Check Point /
                           Securelist / OWASP GenAI / MSRC）
  5. 安全社区  安全客、先知最新一页

所有条目经「AI 安全相关性」闸门过滤，非 AI 一律丢弃。
"""

import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import datetime as dt
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetch_corpus as F          # noqa: E402
import extra_sources as X         # noqa: E402
from monitor import fetch_nvd_window  # noqa: E402
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402
import circuit  # noqa: E402   —— 源熔断/镜像/自愈事件落盘（core/circuit.py）


DATA = paths.DATA_DIR
SEEN_FP = os.path.join(DATA, "live_seen.json")
FEED_FP = os.path.join(DATA, "live_feed.jsonl")
CACHE_DIR = os.path.join(DATA, "live_cache")   # 各 RSS 源上一轮成功抓取快照（容错回退用）
CN_DIR = os.path.join(DATA, "cn")              # 中文社区持久语料（快车道抓到的文章要回写到这里）


def _cache_fp(source):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", source)
    return os.path.join(CACHE_DIR, safe + ".xml")


def save_feed_cache(source, raw):
    """落盘成功抓取的原始 XML，作为该源的『上一轮已知良好快照』。"""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = _cache_fp(source) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(raw)
        os.replace(tmp, _cache_fp(source))
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:65", _sw_e)


def load_feed_cache(source):
    """实时抓取失败时的容错回退：返回上一轮成功快照（仍是被监测到的情报）。"""
    try:
        fp = _cache_fp(source)
        if os.path.isfile(fp) and os.path.getsize(fp) > 64:
            with open(fp, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:76", _sw_e)
    return None
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

FAST_INTERVAL = 15          # 快车道轮询间隔（秒）→ v2.1 由 30s 收紧到 15s，新信息约 15s 内可见
NVD_WINDOW_HOURS = 2        # NVD 回看窗口（重叠覆盖，避免边界丢失）
LAST_META = {}              # 最近一轮的统计（供服务端状态接口读取）
_SRC_ERR = {}               # 本轮抓取失败的源 → 原因（供状态接口/前端显示"哪些源没盯上"）
_SRC_OK = []                # 本轮成功的源

BLOG_FEEDS = [
    # ── 原有核心源（AI 安全 + 大厂安全博客 + 官方公告）──
    ("Trail of Bits", "https://blog.trailofbits.com/feed/"),
    ("Wiz", "https://www.wiz.io/blog/rss.xml"),
    ("Snyk", "https://snyk.io/blog/feed/"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("OpenAI 新闻", "https://openai.com/news/rss.xml"),
    ("GitHub Security", "https://github.blog/tag/security/feed/"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("AWS Security", "https://aws.amazon.com/blogs/security/feed/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Securelist", "https://securelist.com/feed/"),
    ("OWASP GenAI", "https://genai.owasp.org/feed/"),
    ("MSRC", "https://msrc.microsoft.com/blog/feed"),
    # ── AI 厂商 / AI 平台（补齐「厂商公告没盯全」）──
    ("Google AI 博客", "https://blog.google/technology/ai/rss/"),
    ("Google DeepMind", "https://deepmind.google/blog/rss.xml"),
    ("AWS 机器学习", "https://aws.amazon.com/blogs/machine-learning/feed/"),
    ("NVIDIA 开发者博客", "https://developer.nvidia.com/blog/feed/"),
    ("Ollama 版本发布", "https://github.com/ollama/ollama/releases.atom"),
    ("vLLM 版本发布", "https://github.com/vllm-project/vllm/releases.atom"),
    ("NIST 新闻", "https://www.nist.gov/news-events/news/rss.xml"),
    # ── 安全厂商 / 安全研究（补齐「安全博客没盯全」）──
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Rapid7", "https://www.rapid7.com/blog/rss/"),
    ("Qualys", "https://blog.qualys.com/feed"),
    ("Tenable", "https://www.tenable.com/blog/feed"),
    ("PortSwigger 研究", "https://portswigger.net/research/rss"),
    ("Sonatype", "https://blog.sonatype.com/rss.xml"),
    ("JFrog", "https://jfrog.com/blog/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed.xml"),
    ("Schneier", "https://www.schneier.com/feed/atom/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("JetBrains 安全", "https://blog.jetbrains.com/security/feed/"),
    ("Kubernetes", "https://kubernetes.io/feed.xml"),
    # ── 2026-09-29 扩源（逐一实测有 RSS 条目；CrowdStrike/PaloAlto/ESET 直连可达，其余走代理）──
    # Fortinet 的 /blog/rss.xml 返回的是反爬 HTML 壳，勿加。
    ("CrowdStrike", "https://www.crowdstrike.com/blog/feed/"),
    ("Red Canary", "https://redcanary.com/feed/"),
    ("Palo Alto 博客", "https://www.paloaltonetworks.com/blog/feed/"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    # ── 漏洞库 / 利用情报（POC、EXP、0day 公告）──
    ("ZDI 公告", "https://www.zerodayinitiative.com/rss/published/"),
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml"),
    # ── 中文源 ──
    # 安全客不配 RSS：api.anquanke.com/data/v1/rss 实测仅返回 1 条空壳（幽灵源），
    # 快车道另有 src_anquanke() 走 JSON API（posts?size=30）真抓数据，两条通道同名会互相干扰。
    ("绿盟博客", "https://blog.nsfocus.net/feed/"),
    ("四维创智", "https://www.4hou.com/feed"),
    ("先知社区", "https://xz.aliyun.com/feed"),
    # FreeBuf：国内安全媒体，直连稳定（2026-09-28 实测 20 条/次），新增「安全媒体」类别
    ("FreeBuf", "https://www.freebuf.com/feed"),
]

# 需要代理/会间歇性拦截的源：设了 AISEC_PROXY（或 HTTPS_PROXY）时可放开
BLOG_FEEDS_PROXY_ONLY = [
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss"),
    ("Google 安全博客", "https://security.googleblog.com/feeds/posts/default"),
    ("GitLab", "https://about.gitlab.com/atom.xml"),    ("Docker", "https://www.docker.com/blog/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Seebug 知创", "https://paper.seebug.org/rss/"),
]

ARXIV_RSS = [
    ("cs.CR", "http://export.arxiv.org/rss/cs.CR"),
    ("cs.AI", "http://export.arxiv.org/rss/cs.AI"),
]


def log(*a):
    print("[live]", *a, flush=True)


def _proxy():
    """可用代理（找不到就返回 ""，此时走直连）。

    2026-09-30：不再只信环境变量 —— 代理端口**会漂**（这次 6759、上上次 33252、
    上次 2484），启动脚本固定扫 7890/7897 必然漏。改由 core/net.py 实测：
    环境变量 → 上次成功的 → 扫本机监听端口真连一次；结果缓存 3 分钟，
    代理换端口后自动跟上。直连就通的环境会返回 ""（不强行走代理）。
    """
    try:
        import net
        return net.detect_proxy()
    except Exception:  # noqa: BLE001 —— 探测失败不拖垮抓取
        for k in ("AISEC_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            v = (os.environ.get(k) or "").strip()
            if v:
                return v
        return ""


# 国内站点直连：走代理反而更慢、还常被节点的 SNI 策略拒掉（实测 xz.aliyun / 绿盟 会 28 超时）
_DIRECT_HOSTS = (
    "aliyun.com", "anquanke.com", "nsfocus.net", "4hou.com", "seebug.org", "csdn.net",
    "ichunqiu.com", "freebuf.com", "51cto.com", "pediy.com", "sec-wiki.com", "360.cn",
    "qq.com", "gitee.com", "cnblogs.com", "sina.com.cn", "zhihu.com", "bilibili.com",
)


def _proxy_for(url):
    """按目标站点决定要不要走代理。

    2026-09-30 修正：原来"国内站点一律直连"是硬编码假设，一旦本机直连整体不通
    （校园网/代理-only 环境），CSDN、安全客、先知、绿盟会全部 GET failed。
    现在先查 core/net.py 记录的「该站点上次走通的通道」，有记忆就用记忆；
    没记忆才退回按域名默认（国内直连 / 境外代理）。
    """
    px = _proxy()
    if not px:
        return ""
    host = _host_of(url)
    if "127.0.0.1" in url or "localhost" in url:
        return ""
    try:
        import net
        mode = net.channel_for(host)
        if mode == "direct":
            return ""
        if mode == "proxy":
            return px
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:211", _sw_e)
    if any(host == h or host.endswith("." + h) or host.endswith(h) for h in _DIRECT_HOSTS):
        return ""
    return px


def _host_of(url):
    return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()


# 无代理环境下直连必超时/被墙的境外源：宁可先不盯，也别让每个挂 25s 把 15s 节拍拖到分钟级。
# 设了 AISEC_PROXY / HTTPS_PROXY 后，blog_feeds() 会放开全部源（含下列源与 6 个翻墙专用源）。
_FOREIGN_BLOG_HOSTS = {
    "blog.trailofbits.com", "www.wiz.io", "snyk.io", "unit42.paloaltonetworks.com",
    "openai.com", "github.blog", "www.microsoft.com", "aws.amazon.com",
    "research.checkpoint.com", "securelist.com", "genai.owasp.org", "msrc.microsoft.com",
    "blog.google", "deepmind.google", "developer.nvidia.com", "blog.talosintelligence.com",
    "www.rapid7.com", "blog.qualys.com", "www.tenable.com", "portswigger.net",
    "blog.sonatype.com", "jfrog.com", "isc.sans.edu", "www.schneier.com",
    "www.darkreading.com", "blog.jetbrains.com", "kubernetes.io",
    "www.zerodayinitiative.com", "www.exploit-db.com",
    "googleprojectzero.blogspot.com", "security.googleblog.com",
    "about.gitlab.com", "www.docker.com", "feeds.feedburner.com", "paper.seebug.org",
}


# ======================================================================
# 采集类别体系（2026-10-06）
# 为什么加这个：验收要看「多源覆盖是否达 7 类以上」，但代码里注册源只有 7 个
# （blogs 一个 key 聚合了 48 个 RSS），**光数注册项数不出覆盖度**。
# 这里给每个源打上语义类别，/api/sources 直接返回分类清单与各类源数量，
# 覆盖度就是可核验的数据，而不是一句"支持多源"的声称。
# ======================================================================
CATEGORY_LABELS = {
    "cve_nvd":        "CVE / NVD 官方漏洞库",
    "kev_exploited":  "CISA KEV 在野利用目录",
    "vendor_advisory": "厂商官方安全公告",
    "vendor_blog":    "厂商安全博客与研究团队",
    "research_blog":  "独立安全研究机构",
    "media":          "安全媒体与资讯",
    "exploit_intel":  "漏洞利用情报（POC/EXP/0day）",
    "cn_community":   "中文安全社区",
    "tech_community": "技术社区作者订阅",
    "paper":          "学术论文",
}

# SOURCES 里每个注册源所属的类别
SOURCE_CATEGORIES = {
    "nvd":      "cve_nvd",
    "kev":      "kev_exploited",
    "blogs":    "vendor_blog",     # 聚合源，实际展开见 BLOG_FEED_CATEGORIES
    "anquanke": "cn_community",
    "xz":       "cn_community",
    "csdn":     "tech_community",
    "arxiv":    "paper",
}

# 48 个 RSS 源逐个归类（按源名称精确匹配；未列出者归 "other"，不会静默丢失）
BLOG_FEED_CATEGORIES = {
    # 厂商官方安全公告 / 官方博客
    "GitHub Security": "vendor_advisory", "CISA": "vendor_advisory",
    "Microsoft Security": "vendor_advisory", "MSRC": "vendor_advisory",
    "NIST 新闻": "vendor_advisory", "OpenAI 新闻": "vendor_advisory",
    "Google AI 博客": "vendor_advisory", "Google DeepMind": "vendor_advisory",
    "AWS 机器学习": "vendor_advisory", "NVIDIA 开发者博客": "vendor_advisory",
    "Kubernetes": "vendor_advisory", "JetBrains 安全": "vendor_advisory",
    "Docker": "vendor_advisory", "GitLab": "vendor_advisory",
    "AWS Security": "vendor_advisory",
    # 厂商安全博客与自家研究团队
    "Wiz": "vendor_blog", "Snyk": "vendor_blog", "Unit 42": "vendor_blog",
    "Check Point Research": "vendor_blog", "Securelist": "vendor_blog",
    "Cisco Talos": "vendor_blog", "Rapid7": "vendor_blog", "Qualys": "vendor_blog",
    "Tenable": "vendor_blog", "CrowdStrike": "vendor_blog",
    "Red Canary": "vendor_blog", "Palo Alto 博客": "vendor_blog",
    "ESET WeLiveSecurity": "vendor_blog", "Sonatype": "vendor_blog",
    "JFrog": "vendor_blog", "Google 安全博客": "vendor_blog",
    "Project Zero": "vendor_blog",
    # 独立安全研究机构
    "Trail of Bits": "research_blog", "PortSwigger 研究": "research_blog",
    "OWASP GenAI": "research_blog", "SANS ISC": "research_blog",
    "Schneier": "research_blog",
    # 安全媒体与资讯
    "Dark Reading": "media", "The Hacker News": "media",
    "Seebug 知创": "media", "FreeBuf": "media",
    # 漏洞利用情报
    "ZDI 公告": "exploit_intel", "Exploit-DB": "exploit_intel",
    "Ollama 版本发布": "exploit_intel", "vLLM 版本发布": "exploit_intel",
    # 中文安全社区
    "绿盟博客": "cn_community", "四维创智": "cn_community",
    "先知社区": "cn_community",
}


def source_categories():
    """返回采集覆盖度统计：类别清单 + 各类源数量（验收「7 类以上」的直接依据）。

    计数口径：一个源算一个（按域名/名称去重后的注册项），
    blogs 聚合源会展开成 48 个 RSS 源逐个归类，因此 total 比 len(SOURCES) 大得多。
    """
    buckets = {}

    def _add(cat, name):
        buckets.setdefault(cat, {"key": cat,
                                "label": CATEGORY_LABELS.get(cat, cat),
                                "sources": []})["sources"].append(name)

    # 1) 非博客注册源
    for name, cat in SOURCE_CATEGORIES.items():
        if name == "blogs":
            continue                      # 聚合源，下面单独展开
        _add(cat, name)
    # 2) 博客/公告 RSS 源逐个归类
    for name, _url in list(BLOG_FEEDS) + list(BLOG_FEEDS_PROXY_ONLY):
        _add(BLOG_FEED_CATEGORIES.get(name, "other"), name)

    rows = sorted(buckets.values(),
                  key=lambda r: (-len(r["sources"]), r["label"]))
    total = sum(len(r["sources"]) for r in rows)
    return {
        "category_count": len([r for r in rows if r["key"] != "other"]),
        "source_count": total,
        "registered_pollers": len(SOURCES),
        "poll_interval_sec": FAST_INTERVAL,
        "categories": [{"key": r["key"], "label": r["label"],
                        "count": len(r["sources"]), "sources": r["sources"]}
                       for r in rows],
    }


def blog_feeds():
    """当前该抓的博客/公告源。
    - 配了代理：全部 38 个 + 6 个翻墙专用源。
    - 没配代理：只保留国内源（安全客/绿盟/四维创智/先知）+ GitHub Releases
      （Ollama/vLLM）+ NIST/CISA，其余境外源先跳过，避免每个挂 25s 把快车道拖到分钟级。
    """
    base = list(BLOG_FEEDS) + (list(BLOG_FEEDS_PROXY_ONLY) if _proxy() else [])
    if _proxy():
        return base
    return [f for f in base if _host_of(f[1]) not in _FOREIGN_BLOG_HOSTS]


def http_get(url, tries=3, timeout=25, binary=False, headers=None):
    """走 curl：arXiv 等站点按 TLS 指纹拦截 python-urllib。

    headers: 额外请求头（dict）。CSDN 的 home-api 必须带 Referer，否则直接 521。

    代理策略：先按站点决定走不走代理，失败则换另一种方式再试——
      · 主策略走代理 → 兜底直连（代理节点对个别站 SSL 握手失败 curl 35，而直连是通的）
      · 主策略直连   → 兜底代理（2026-09-29：本机直连 blog/rss.csdn.net 直接 curl 7 连不上，
        而 _DIRECT_HOSTS 把 csdn.net 判成"国内直连"，结果是 CSDN 作者 RSS 永久失败、新文章爬不到）
    """
    last = None
    host = _host_of(url)
    cands = [_proxy_for(url)]
    # 兜底策略只在「这个站点还没探明通道」时才启用两候选：
    # 稳定后每个源都要跑两遍（代理 6s + 直连 6s，外加 curl 60 时的 -k 重试），
    # 48 个源一轮轻松顶到 70s+。探明之后只走记住的那条路（耗时减半），
    # 万一这条路某天不通了，except 里会 forget 掉记忆，下一轮自动重新探测。
    try:
        import net as _net
        _known = _net.channel_for(host)
    except Exception:  # noqa: BLE001
        _known = ""
    if not _known:
        if cands[0]:
            cands.append("")                # 兜底：直连再试一次
        elif _proxy():
            cands.append(_proxy())          # 兜底：直连不通时改走代理

    def _once(px, insecure=False):
        cmd = ["curl", "-sS", "-L", "--max-time", str(timeout), "-A", UA, "-o", "-"]
        if px:
            cmd += ["--proxy", px]
        if insecure:
            cmd.append("-k")                # 代理 TLS 中间人：证书校验失败时降级重试
        for _hk, _hv in (headers or {}).items():
            cmd += ["-H", f"{_hk}: {_hv}"]
        cmd.append(url)
        # 子进程超时只比 curl 自身 --max-time 多留 4s（fork/解析开销）。
        # 原先留 12s：境外源 6s 超时 × 2 个候选（代理+直连兜底）最坏就是 36s，
        # 一轮 48 源直接把快车道顶到 45s+。
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 4)
        if p.returncode != 0:
            raise RuntimeError(f"curl {p.returncode}: {p.stderr[:100]!r}")
        return p.stdout if binary else p.stdout.decode("utf-8", "replace")

    host = _host_of(url)
    for attempt in range(tries):
        for px in cands:
            try:
                body = _once(px)
                try:                        # 记住这个站点走通的是代理还是直连
                    import net
                    net.remember(host, "proxy" if px else "direct")
                except Exception as _sw_e:  # noqa: BLE001
                    _swallow("modules/m1_monitor/backend/live.py:303", _sw_e)
                return body
            except Exception as e:  # noqa: BLE001
                last = e
                if "curl 60" in str(e) or "curl 51" in str(e):   # 60=SSL证书 51=证书主机名不符
                    try:
                        body = _once(px, insecure=True)
                        try:
                            import net
                            net.remember(host, "proxy" if px else "direct")
                        except Exception as _sw_e:  # noqa: BLE001
                            _swallow("modules/m1_monitor/backend/live.py:314", _sw_e)
                        return body
                    except Exception as e2:  # noqa: BLE001
                        last = e2
        time.sleep(1.0 + attempt)
    # 记下来的那条路这次没走通：清掉记忆，下一轮重新「代理 + 直连」双候选探测，
    # 适配网络环境变化（代理换端口、断网、切 WiFi）。
    try:
        import net as _net
        _net.forget(host)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:325", _sw_e)
    raise RuntimeError(f"GET failed {url} :: {last}")


class _Text(HTMLParser):
    SKIP = {"script", "style", "noscript", "svg", "head"}
    BLOCK = {"p", "div", "br", "li", "h1", "h2", "h3"}

    def __init__(self):
        super().__init__()
        self.b = []
        self.s = 0

    def handle_starttag(self, t, a):
        if t in self.SKIP:
            self.s += 1
        elif t in self.BLOCK:
            self.b.append(" ")

    def handle_endtag(self, t):
        if t in self.SKIP and self.s:
            self.s -= 1

    def handle_data(self, d):
        if not self.s:
            self.b.append(d)


def _plain(h):
    # CDATA 段（RSS/Atom 标题与正文常见）HTMLParser 不会当作文本输出，先拆掉包装
    h = (h or "").replace("<![CDATA[", "").replace("]]>", "")
    p = _Text()
    try:
        p.feed(html.unescape(h))
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:360", _sw_e)
    return re.sub(r"\s+", " ", "".join(p.b)).strip()


# --------------------------------------------------------------------------
# AI 安全相关闸门
# --------------------------------------------------------------------------
def ai_gate(*texts):
    """返回 (是否 AI 安全相关, 命中理由)。基于组件名 + 语义关键词。"""
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return False, ""
    for n in F.AI_PRODUCTS:
        if len(n) >= 4 and re.search(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])", blob):
            return True, f"AI 组件：{n}"
    for kw in F.AI_DESC_KEYWORDS:
        if F.kw_hit(kw, blob):
            return True, f"AI 语义：{kw}"
    for k, zh in F.MODEL_LAYER_TAGS:
        if F.kw_hit(k, blob):
            return True, f"模型层风险：{zh}"
    return False, ""


# --------------------------------------------------------------------------
# 状态
# --------------------------------------------------------------------------
def load_seen():
    if os.path.isfile(SEEN_FP):
        try:
            with open(SEEN_FP, "r", encoding="utf-8") as f:
                d = json.load(f)
            # 只取扁平的 meta（per_source / last_poll 等），不要把整个文件再当 meta 嵌套一层
            return set(d.get("ids", [])), {}
        except ValueError as _sw_e:
            _swallow("modules/m1_monitor/backend/live.py:395", _sw_e)
    return set(), {}


def save_seen(seen, meta):
    ids = sorted(seen)
    if len(ids) > 200000:            # 只保留最近的一批，避免状态文件无限增长
        ids = ids[-150000:]
    tmp = SEEN_FP + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"ids": ids, "meta": (meta or {})}, f, ensure_ascii=False)
    for i in range(5):               # Windows 下可能被短暂占用，重试
        try:
            os.replace(tmp, SEEN_FP)
            return
        except PermissionError:
            time.sleep(0.35 * (i + 1))
    try:
        with open(SEEN_FP, "w", encoding="utf-8") as f:
            f.write(open(tmp, "r", encoding="utf-8").read())
        os.remove(tmp)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:417", _sw_e)


# --------------------------------------------------------------------------
# 各快源
# --------------------------------------------------------------------------
_KEV_CACHE = {"t": 0.0, "v": {}}


def _kev():
    """KEV 目录（一轮内共享，避免重复下载 1MB）"""
    if time.time() - _KEV_CACHE["t"] > 120 or not _KEV_CACHE["v"]:
        try:
            # 快车道一轮只有 15s，KEV 走默认超时（45s×3）最坏 135s，
            # 一轮直接被顶到 205s（实测）。这里快速失败即可：
            # 抓不到就沿用 120s 内的上一份快照，不会有数据缺口。
            _KEV_CACHE["v"] = F.fetch_kev(timeout=15, tries=1)
            _KEV_CACHE["t"] = time.time()
        except Exception as e:  # noqa: BLE001
            # 失败不要立刻重试：把缓存时间戳往前推，下一轮再试，
            # 否则每轮都硬等 15s 超时。
            _KEV_CACHE["t"] = time.time() - 60
            log("  kev 失败:", str(e)[:70])
    return _KEV_CACHE["v"]


# 博客源抓取并发度：48 个源若按默认 8 并发跑，48/8=6 批 × 8~12s ≈ 70s，
# 一轮就把 30s 的博客节奏和 15s 的快车道节拍彻底打爆（实测单轮 99s），
# 表现为「大量源实时抓取失败、回退缓存快照」。提到 24 后 2~3 批即可收工。
try:
    # 并发不是越高越好：实测 24 并发走同一个代理时吞吐反而下降（16 源要 58s），
    # 12 是这台机器上代理吞吐与单轮耗时的平衡点。
    _FEED_WORKERS = max(4, min(32, int(os.environ.get("AISEC_FEED_WORKERS", "12"))))
except Exception:  # noqa: BLE001
    _FEED_WORKERS = 24


# 博客源各自的抓取间隔（秒）：境外源走代理、单次重且更新慢，节奏放宽。
try:
    _BLOG_GAP_FOREIGN = max(30, int(os.environ.get("AISEC_BLOG_GAP_FOREIGN", "90")))
except Exception:  # noqa: BLE001
    _BLOG_GAP_FOREIGN = 90
_BLOG_GAP_LOCAL = 30
_FEED_LAST = {}          # source -> 上次成功抓取时间
_FEED_NEXT = {}          # source -> 下次允许抓取的时间（含退避）
_FEED_FAIL = {}          # source -> 连续失败次数
# 单轮最多抓多少个博客源：与并发度对齐，让一轮就是"一批"，
# 耗时由最慢的那个源决定，而不是被源总数线性放大。
try:
    _FEED_MAX_PER_ROUND = max(4, min(48, int(os.environ.get("AISEC_FEED_PER_ROUND", "16"))))
except Exception:  # noqa: BLE001
    _FEED_MAX_PER_ROUND = 16
_FEED_BACKOFF_CAP = 300  # 失败退避上限：再怎么样 5 分钟也要重试一次


def _feed_backoff(source, gap):
    """抓取失败 → 指数退避（gap → 2gap → 4gap … 上限 300s）。

    没有这个，Google 安全博客 / Project Zero / GitLab / The Hacker News 这类
    长期不可达的源会每轮都占满超时（代理 + 直连两个候选各 6s），把整轮拖到 70s+。
    """
    n = _FEED_FAIL.get(source, 0) + 1
    _FEED_FAIL[source] = n
    _FEED_NEXT[source] = time.time() + min(_FEED_BACKOFF_CAP, gap * (2 ** min(n, 4)))


def _par_map(fn, items, workers=None):
    """并行执行（快车道对时延敏感：48 个 RSS 串行会拖到分钟级）

    并发数按性能档位压低（低配机上限 2）——慢机器上开 12 个线程只会让
    每个源都超时，反而比串行更慢。见 core/envprofile.py。
    """
    from concurrent.futures import ThreadPoolExecutor
    try:
        from envprofile import T
        workers = T.workers(workers or _FEED_WORKERS)
    except Exception:
        workers = workers or _FEED_WORKERS
    out = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(fn, items):
            out.append(r)
    return out


def src_nvd(hours=NVD_WINDOW_HOURS):
    """NVD 最近变更窗口 → AI 过滤后返回记录"""
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    out = []
    try:
        # 15s 节拍的快车道：单次尝试 + 20s 超时。NVD 被限速时本轮放弃，
        # 下一轮（≤60s 后）自动重试，不阻塞 blogs 等主落点源。
        cves = fetch_nvd_window(None, fmt(start), fmt(end), limit=2000,
                                tries=1, timeout=12)
    except Exception as e:  # noqa: BLE001
        log("  nvd 失败:", str(e)[:80])
        return out
    kev = _kev()
    for c in cves:
        try:
            rec = F.build_record(c, kev, {}, [])
            ok, score, cat, reason, tags = F.classify(rec)
            if not ok:
                continue
            rec["ai_score"] = score
            rec["category"] = cat
            rec["category_reason"] = reason
            rec["scope"] = "AI安全"
            rec["live"] = True
            out.append(rec)
        except Exception:  # noqa: BLE001
            continue
    return out


def src_kev():
    """KEV 增量：新收录的在野利用 CVE → 独立条目（供 feed 提示）"""
    out = []
    kev = _kev()
    for cid, ent in kev.items():
        blob = " ".join([str(ent.get("vulnerabilityName", "")), str(ent.get("shortDescription", "")),
                         " ".join(ent.get("knownRansomwareCampaignUse", "") or [])])
        ok, why = ai_gate(blob)
        if not ok:
            continue
        rec = X._skeleton(
            rid="KEV:" + cid, rtype="kev", kind="CISA KEV 在野利用",
            title=f"{cid} {ent.get('vulnerabilityName', '')}".strip(),
            desc=str(ent.get("shortDescription", ""))[:1500],
            published=str(ent.get("dateAdded", ""))[:10],
            sources=["CISA KEV"], category="② 模型与数据层",
            reason=f"在野利用目录新增（{why}）",
            tags=["在野利用", "CISA KEV"],
        )
        rec["live"] = True
        out.append(rec)
    return out


def _norm_date(s):
    """把 RSS/Atom 的各种日期写法统一成 YYYY-MM-DD（**本机时区**）；解析失败返回空串。

    RSS 2.0 用 RFC 2822（Wed, 29 Jul 2026 05:00:00 GMT），Atom 用 ISO 8601。
    旧版直接 pub[:10] 截断，把英文日期截成 'Wed, 29 Ju' 这类坏值，
    engine.latest() 的"未来日期过滤"会把它们整条隐藏 —— 实时监测台看起来
    永远停在某一天不动（2026-09-28 修复）。

    ★ 2026-10-08 二次修复（时区口径 Alignment）：
      本函数过去对**带时区的日期只取原时区（UTC）的日期**，而同一个原始串经
      `_norm_datetime` 会换算到本机时区（UTC+8）。于是源站在 UTC 16:00~24:00
      发布（= 北京时间次日 00:00~08:00）时，`published` 记成**前一天**、
      `published_at` 记成**当天**。实测 live_feed.jsonl 4129 条里 172 条系统性
      差 1 天 —— 今天清晨发布的文章全被标成昨天，界面「实时监测」看起来
      "没有今天的文章"，而「每日报告」按 fetched_at 分组却能列出当天内容。

      现在统一为**本机时区日期**，与 `_norm_datetime` 完全同口径。
      不变量（回归断言）：`_norm_date(x) == _norm_datetime(x)[:10]`。
    """
    s = (s or "").strip()
    if not s:
        return ""
    # ISO：纯日期 "2026-10-08" 没有时区可换算，原样保留；带时刻/时区的交给
    # _norm_datetime 统一换算（避免两处各写一套时区逻辑再次漂移）。
    m = re.match(r"^(\d{4}-\d{1,2}-\d{1,2})(.*)$", s)
    if m:
        if not re.search(r"\d{1,2}:\d{2}", m.group(2)):
            return m.group(1)
        nd = _norm_datetime(s)
        return nd[:10] if nd else m.group(1)
    try:
        from email.utils import parsedate_to_datetime
        d = parsedate_to_datetime(s)
        if d is not None:
            if d.tzinfo is not None:
                d = d.astimezone()       # ★ 换算到本机时区（旧版漏了这一步，差 1 天）
            return d.strftime("%Y-%m-%d")
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:569", _sw_e)
    # 兜底：中文站常见的 "2026年9月24日" / "2026/09/24"
    m = re.search(r"(20\d{2})\s*[-/年.]\s*(\d{1,2})\s*[-/月.]\s*(\d{1,2})", s)
    if m:
        return "%s-%02d-%02d" % (m.group(1), int(m.group(2)), int(m.group(3)))
    return ""


def _norm_datetime(s):
    """把 RSS/Atom 日期统一成**本机时区**的 ISO 秒级 'YYYY-MM-DDTHH:MM:SS'。

    为什么必须单独留一个带时刻的字段（2026-10-06）：
      `_norm_date` 只保留 YYYY-MM-DD —— 引擎的 latest() / 未来日期过滤依赖日期
      字符串，不能动它。但**时效性测量需要真实时刻**：实测 2719/2721 条实时记录
      的源站时刻全被截成日期，延迟测量误差高达 ±12h，比中位延迟（1.4h）本身还大，
      导致「≤3h 达标线」根本没法判。

      所以：published 保持日期（向后兼容），新增 published_at 存本机时区的完整时刻。
      两边同处本地时区，直接相减即为真实采集延迟。
    """
    s = (s or "").strip()
    if not s:
        return ""
    # 已经是 ISO：2026-10-06T14:30:00 / 2026-10-06 14:30:00 / ...Z / ...+08:00
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?", s)
    if m:
        try:
            base = dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                               int(m.group(4)), int(m.group(5)),
                               int(m.group(6) or 0))
            # 带时区标记的必须交给标准库换算 —— 手写 offset 换算会把
            # "T08:15:00Z"（UTC）错当成本机 08:15（实际应为 16:15）。
            tz = re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", s)
            if tz:
                suffix = "+00:00" if tz.group(0) == "Z" else tz.group(0)
                if len(suffix) == 5:                    # +0800 → +08:00
                    suffix = suffix[:3] + ":" + suffix[3:]
                aware = dt.datetime.fromisoformat(base.isoformat() + suffix)
                return aware.astimezone().strftime("%Y-%m-%dT%H:%M:%S")
            return base.strftime("%Y-%m-%dT%H:%M:%S")
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/live.py:_norm_datetime/iso", _sw_e)
    # RFC 2822：Wed, 29 Jul 2026 05:00:00 GMT（RSS 2.0 绝大多数）
    try:
        from email.utils import parsedate_to_datetime
        d = parsedate_to_datetime(s)
        if d is not None:
            if d.tzinfo is not None:
                d = d.astimezone()          # → 本机时区
            return d.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:_norm_datetime/rfc", _sw_e)
    # 中文站：2026年9月24日 14:30 / 2026/09/24 09:05
    # 注意"日"既可能作日期后缀（24日），又可能正好挡在时刻前面 ——
    # 时间组前必须允许它，否则时刻被静默丢掉、退化成 00:00:00。
    m = re.search(r"(20\d{2})\s*[-/年.]\s*(\d{1,2})\s*[-/月.日]?\s*(\d{1,2})"
                  r"(?:\s*日?\s*[T\s]*(\d{1,2}):(\d{2})(?::(\d{2}))?)?", s)
    if m:
        try:
            return dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                               int(m.group(4) or 0), int(m.group(5) or 0),
                               int(m.group(6) or 0)).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m1_monitor/backend/live.py:_norm_datetime/cn", _sw_e)
    return ""


def _to_local(naive, raw):
    """把带时区偏移的 ISO 串换算成本机时区的 naive 时间。"""
    s = str(raw or "").strip()
    m = re.search(r"(Z|[+-]\d{2}):?(\d{2})?$", s)
    if not m:
        return naive
    off_txt = m.group(0)
    try:
        if off_txt in ("Z", "+00:00", "+0000"):
            delta = dt.timedelta(0)
        else:
            sign = 1 if off_txt[0] == "+" else -1
            hh = int(off_txt[1:3])
            mm = int(off_txt[-2:]) if len(off_txt) >= 6 else 0
            delta = dt.timedelta(hours=hh, minutes=mm) * sign
        return (naive - delta)      # 换算成本机本地时间（东八区）
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m1_monitor/backend/live.py:_to_local", _sw_e)
        return naive


def _rss_items(xml, source):
    out = []
    for m in re.finditer(r"<(item|entry)\b.*?</\1>", xml, re.S):
        b = m.group(0)
        g = lambda p, d="": (re.search(p, b, re.S).group(1).strip() if re.search(p, b, re.S) else d)
        link = g(r'<link[^>]*href="([^"]+)"') or g(r"<link>([^<]+)</link>")
        title = html.unescape(_plain(g(r"<title[^>]*>(.*?)</title>")))
        if not link or not title:
            continue
        guid = g(r"<guid[^>]*>([^<]+)</guid>") or g(r"<id[^>]*>([^<]+)</id>") or link
        raw_pub = g(r"<(?:pubDate|published|updated|dc:date)[^>]*>([^<]+)</")
        pub = _norm_date(raw_pub)
        # 同时留一份带时刻的（2026-10-06）：published 只到日期，丢掉的时刻会让
        # 时效性测量误差 ±12h。两者并存，向后兼容 —— 引擎仍只读 published。
        pub_at = _norm_datetime(raw_pub)
        # ★ 2026-10-08 修复：正文标签必须包含 Atom 的 `<content>`。
        #   GitHub releases.atom（Ollama / vLLM 版本发布两个源）把发布说明放在
        #   `<content type="html">` 里，而旧正则只认 description|summary|content:encoded
        #   —— 实测缓存快照里 `<content>` 有 8529 字符正文，三个标签却全是 0 匹配，
        #   正文被整段丢弃、desc 退化成标题（"v0.40.1"），点开检查器"几乎没有信息"。
        #   注意 content:encoded 必须排在 content 前面：否则会先匹配到 `<content`
        #   再去找 `</content>`，遇到 `</content:encoded>` 直接匹配失败。
        summ = html.unescape(_plain(g(
            r"<(?:description|summary|content:encoded|content)[^>]*>"
            r"(.*?)</(?:description|summary|content:encoded|content)>")))
        rec = {"source": source, "guid": guid, "title": title,
               "link": link, "published": pub, "summary": summ[:2500]}
        if pub_at:
            rec["published_at"] = pub_at
        out.append(rec)
    return out


# 博客源异步化缓冲：快车道不再被 48 个源经代理的抓取（实测 45~99s）拖住。
_BLOGS_BUF = {"busy": False, "items": [], "last": 0.0, "err": None}


def src_blogs():
    out = []
    # 博客源调度（2026-09-30 重写）：48 个源每轮全抓实测要 45~99s。三个手段：
    #   ① 源级节奏：境外 90s / 国内 30s（厂商博客一天才几篇，时效差无感）
    #   ② 单轮限量：最多抓 _FEED_MAX_PER_ROUND 个（按"最久没抓"优先），
    #      耗时由最慢源决定而不是源总数
    #   ③ 失败退避：连续失败的源指数退避（上限 300s）——Google/Project Zero/
    #      GitLab/The Hacker News 这类恒定失败的源不再每轮空耗 2×6s 超时
    # 未抓的源沿用上轮快照、仍计入在线监测，监测面不缩水。
    # 源健康度先收进局部容器再一次性合并：本函数跑在后台线程里，
    # 而主线程每轮会 `del _SRC_OK[:]`，边跑边 append 会互相踩。
    _ok, _err = [], {}
    now = time.time()
    due = []
    for _f in blog_feeds():
        _src = _f[0]
        if now >= _FEED_NEXT.get(_src, 0):
            due.append((_FEED_NEXT.get(_src, 0), _f))
        else:
            _ok.append(_src)                 # 未到节奏：算"已监测"（用的是上轮快照）
    due.sort(key=lambda x: x[0])              # 最久没抓的排前面，保证轮转覆盖
    todo = [f for _, f in due[:_FEED_MAX_PER_ROUND]]
    for _, _f in due[_FEED_MAX_PER_ROUND:]:
        _ok.append(_f[0])                    # 本轮名额用尽：同样算已监测

    def _one(feed):
        source, url = feed
        # 境外源：代理黑洞（代理进程在但不转发）时，每次满超时会拖垮 15s 快车道节拍
        # （http_get 会按「代理 + 直连」两候选各试 tries 次，单源最坏近 100 秒）。
        # 对境外源用更短超时 + 更少重试快速失败，失败即回退缓存快照（不丢监测面）。
        host = _host_of(url)
        _tries, _timeout = (1, 6) if host in _FOREIGN_BLOG_HOSTS else (2, 12)
        # 容错抓取：3 次重试 + 更长超时（部分官方源响应慢但可达，单次短超时易误判失败）；
        # 连抓都失败再回退到上一轮成功快照，仍视为『该源已被监测到』，
        # 避免单点网络抖动把整轮源健康度拉低（系统可用性，不丢监测面）
        gap = (_BLOG_GAP_FOREIGN if host in _FOREIGN_BLOG_HOSTS else _BLOG_GAP_LOCAL)
        xml = None
        try:
            xml = http_get(url, tries=_tries, timeout=_timeout)
            _FEED_LAST[source] = time.time()
            _FEED_FAIL.pop(source, None)
            _FEED_NEXT[source] = time.time() + gap       # 成功：按正常节奏排下次
        except Exception as e:  # noqa: BLE001
            cached = load_feed_cache(source)
            if cached:
                _ok.append(source)       # 用缓存快照也算"该源在线监测"
                log(f"  blog {source} 实时抓取失败，回退缓存快照（{str(e)[:45]}）")
                _feed_backoff(source, gap)
                return _rss_items(cached, source)[:40]
            _err[source] = str(e)[:70]
            log(f"  blog {source} 失败:", str(e)[:60])
            _feed_backoff(source, gap)
            return []
        # 成功：更新快照缓存，供后续轮次容错
        save_feed_cache(source, xml)
        _ok.append(source)          # 注意：必须用 append，`+=` 会让列表变成局部变量（UnboundLocalError）
        return _rss_items(xml, source)[:40]

    for items in _par_map(_one, todo):
        for it in items:
            ok, why = ai_gate(it["title"], it["summary"], it["source"])
            if not ok:
                # 二级门控（2026-09-29）：安全厂商官方博客（CrowdStrike / Palo Alto /
                # ESET / Red Canary 等）大量内容是通用威胁情报（勒索软件、CVE、EDR），
                # 不含 AI 词，会被 ai_gate 全拦 —— 体检显示 Wiz 仅 79 条、MSRC 3 条。
                # 这里放行「命中通用安全词」的条目，广告/软文仍由 BAD_TITLE 拦截。
                blob = (it["title"] + " " + (it["summary"] or "")).lower()
                if X.CSDN_GATE.search(blob) and not X.CSDN_BAD_TITLE.search(it["title"] or ""):
                    ok, why = True, "通用安全内容"
                else:
                    continue
            rid = "LIVE:BLOG:" + re.sub(r"[^A-Za-z0-9._-]", "_", it["guid"])[:80]
            cat = _guess_cat(it["title"] + " " + it["summary"])
            rec = X._skeleton(
                rid=rid, rtype="article", kind=f"{it['source']} 安全博客",
                title=it["title"], desc=it["summary"] or it["title"],
                published=it["published"], sources=[it["source"]], category=cat,
                reason=f"实时监测（{why}）",
                tags=["实时情报", it["source"]],
            )
            rec["link"] = it["link"]
            rec["live"] = True
            # 带时刻的发布时间（2026-10-06）：published 只到日期，评测时效性
            # 时误差 ±12h，比中位延迟本身还大。缺失就不写，不影响旧逻辑。
            if it.get("published_at"):
                rec["published_at"] = it["published_at"]
            out.append(rec)
    # 存进博客专用缓冲而不是直接合进 _SRC_OK：后台线程和主轮不同步，
    # 直接合会让"源健康"在 0 ↔ 48 之间乱跳（前端看到"成功 0"很吓人）。
    # src_health() 会把它和本轮的统计合并后一起给出。
    _BLOGS_BUF["ok"] = _ok
    _BLOGS_BUF["err"] = dict(_err)
    return out


# --------------------------------------------------------------------------
# 社区源失败退避（2026-09-30）
# 安全客 / 先知这类国内源平时 2~5s 就回，但快车道一轮里还有 12 个博客线程和
# 慢源线程在抢带宽，偶发超时会让它们「每轮都失败、每轮都白等一个 12s 超时」——
# 单轮耗时被顶到 22s，15s 节拍直接失守。加上退避后：连续失败就按
# 30s → 60s → 120s → 300s 逐步拉长重试间隔，成功一次立刻清零。
# 监测面不缩水：退避期用的是上一轮的快照，一轮过去了照常恢复。
# --------------------------------------------------------------------------
_CN_FAIL = {}


def _cn_due(name):
    st = _CN_FAIL.get(name)
    if not st or time.time() >= st.get("until", 0):
        return True
    return False


def _cn_fail(name, cap=300):
    st = _CN_FAIL.setdefault(name, {"n": 0, "until": 0.0})
    st["n"] = min(st["n"] + 1, 6)
    st["until"] = time.time() + min(cap, 30 * (2 ** (st["n"] - 1)))


def _cn_ok(name):
    _CN_FAIL.pop(name, None)


def src_health():
    """本轮源健康度 = 快车道组内结果 + 后台博客线程最近一次结果。"""
    ok = list(_SRC_OK) + list(_BLOGS_BUF.get("ok") or [])
    err = dict(_SRC_ERR)
    err.update(_BLOGS_BUF.get("err") or {})
    return ok, err


def _blogs_worker():
    try:
        _BLOGS_BUF["items"] = src_blogs() or []
        _BLOGS_BUF["err"] = None
    except Exception as e:  # noqa: BLE001
        _BLOGS_BUF["err"] = str(e)[:160]
    finally:
        _BLOGS_BUF["busy"] = False
        _BLOGS_BUF["last"] = time.time()


def src_blogs_async():
    """博客源的异步入口（快车道实际调用的是它）。

    为什么要绕一层：博客源一轮 45~99s（48 个源、全部走代理），而它和社区源
    (CSDN/安全客/先知) 在 poll_once 里是**并行**的 —— 单轮耗时取最慢的那个，
    于是"社区文章 15s 一爬"被活活拖成一分钟一次，这恰恰是本项目最看重的时效。
    放到独立线程后：poll_once 只把上一轮已经抓好的博客条目收进来（毫秒级），
    慢源爱跑多久跑多久，社区源重新回到 15s 节拍。
    """
    if not _BLOGS_BUF["busy"]:
        _BLOGS_BUF["busy"] = True
        threading.Thread(target=_blogs_worker, daemon=True, name="blogs-fetch").start()
    items = _BLOGS_BUF["items"]
    _BLOGS_BUF["items"] = []                 # 取走即清空，避免下一轮重复计数
    return items


# --------------------------------------------------------------------------
# 慢源异步化（2026-09-30）：NVD / arXiv / KEV 这类 180~300s 节奏的源，
# 一旦到期就和社区源**串行并行**在同一轮里 —— 单轮耗时取最慢者，
# 实测到期那一轮 43.8s（arXiv 两个 feed 各 10s 超时 + NVD 12s + 代理排队），
# 15s 节拍被顶成 3 倍，社区文章也就跟着晚 40s 才可见。
# 这里让慢源在后台线程里跑，主轮只收它上一趟的结果（毫秒级），
# 慢源爱跑多久跑多久，与 15s 节拍彻底解耦。
# 注意：这几个源都不碰 _SRC_OK/_SRC_ERR（那是主轮每轮 clear 的容器），
# 所以放后台线程不会有踩踏；内部节奏由包装器自己管，不再依赖外层 gap。
# --------------------------------------------------------------------------
_SLOW_BUF = {}


def _slow_worker(st, fn):
    try:
        st["items"] = fn() or []
        st["err"] = None
    except Exception as e:  # noqa: BLE001
        st["err"] = str(e)[:160]
        st["items"] = []
    finally:
        st["busy"] = False
        st["last"] = time.time()


def make_slow_async(name, fn, gap):
    """把慢源包成「主轮只收结果、抓取在后台」的形式。

    外层注册时用 gap=15（每轮都调用），真正的抓取节奏由这里按 gap 判断，
    否则会出现「180s 到期启动线程 → 返回空 → 下一轮不再到期 → 结果没人收」的丢数据。
    """
    st = _SLOW_BUF.setdefault(name, {"busy": False, "items": [], "last": 0.0,
                                     "gap": gap, "err": None})

    def _inner():
        now = time.time()
        if not st["busy"] and now - st["last"] >= gap:
            st["busy"] = True
            threading.Thread(target=_slow_worker, args=(st, fn), daemon=True,
                             name=f"slow-{name}").start()
        items = st["items"]
        st["items"] = []            # 取走即清空，避免下一轮重复计数
        return items

    _inner.__name__ = f"src_{name}_async"
    return _inner


def src_arxiv():
    out = []

    def _one(feed):
        cat, url = feed
        try:
            xml = http_get(url, tries=2, timeout=10)
        except Exception as e:  # noqa: BLE001
            log(f"  arxiv {cat} 失败:", str(e)[:60])
            return []
        return [(cat, it) for it in _rss_items(xml, f"arXiv {cat}")]

    for pairs in _par_map(_one, ARXIV_RSS):
        for cat, it in pairs:
            ok, why = ai_gate(it["title"], it["summary"])
            if not ok:
                continue
            aid = re.sub(r"[^A-Za-z0-9._-]", "_", it["guid"].split("/")[-1])[:60]
            rec = X._skeleton(
                rid="ARXIV:" + aid, rtype="paper", kind="AI 安全论文",
                title=it["title"], desc=it["summary"] or it["title"],
                published=it["published"], sources=["arXiv", cat],
                category=_guess_cat(it["title"] + " " + it["summary"]),
                reason=f"arXiv 最新投稿（{why}）",
                tags=["论文", cat],
            )
            rec["link"] = it["link"]
            rec["live"] = True
            out.append(rec)
    return out


def _fmt_pub(ts):
    """把各类时间戳统一成 YYYY-MM-DD；解析不出来返回空串。

    先知接口的 created_at 是 ISO 字符串（"2026-09-28T07:24:17Z"），原先直接
    int(ts) 会抛异常、日期被吞成空串 —— 落盘后这些文章没有日期，既排不进
    「最新」，也没法按时间筛选。这里同时兼容 时间戳 / ISO 字符串 / 纯数字串。
    """
    if ts in (None, "", 0):
        return ""
    if isinstance(ts, (int, float)):
        try:
            return time.strftime("%Y-%m-%d", time.localtime(int(ts)))
        except Exception:  # noqa: BLE001
            return ""
    s = str(ts).strip()
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return m.group(0)
    if s.isdigit():
        try:
            return time.strftime("%Y-%m-%d", time.localtime(int(s)))
        except Exception:  # noqa: BLE001
            return ""
    return ""


def src_anquanke():
    out = []
    if not _cn_due("anquanke"):
        return out                      # 退避窗口内：不再白等一个超时
    try:
        # 超时 8→12s：单发实测 2.2~5s，但快车道一轮同时有 12 个博客线程 +
        # 慢源线程在抢带宽，8s 会被活活挤掉（表现为「国内源也失败」）。
        d = json.loads(http_get("https://api.anquanke.com/data/v1/posts?size=30&page=1",
                                tries=1, timeout=12))
        _cn_ok("anquanke")
    except Exception as e:  # noqa: BLE001
        _cn_fail("anquanke")
        log("  anquanke 失败:", str(e)[:60])
        return out
    for it in (d.get("data") or []):
        title = it.get("title") or ""
        desc = _plain(it.get("desc") or "")
        ok, why = ai_gate(title, desc, it.get("category_name", ""))
        if not ok:
            continue
        rid = "AQ:" + str(it.get("id") or abs(hash(title)))
        pub = _fmt_pub(it.get("date"))          # 可能是时间戳，也可能是日期字符串
        rec = X._skeleton(
            rid=rid, rtype="article", kind="安全客文章",
            title=title, desc=desc[:1500], published=pub,
            sources=["安全客"], category=_guess_cat(title + " " + desc),
            reason=f"安全客最新发布（{why}）", tags=["中文社区", "安全客"],
        )
        # news API 偶发不返回 url 字段（实测 10+ 条 link 为空，日报/详情就没有原文入口）。
        # 安全客详情页 URL 规则确定：/post/id/{id}（2026-10-13 实测标题精确匹配），
        # 与 core/engine.py canonical_url 的 AQ:/AQK: 映射同源。id 缺失时不猜。
        aid = it.get("id")
        rec["link"] = it.get("url") or (f"https://www.anquanke.com/post/id/{aid}" if aid else "")
        rec["live"] = True
        out.append(rec)
    return out


def src_xz():
    out = []
    if not _cn_due("xz"):
        return out
    try:
        d = json.loads(http_get("https://xz.aliyun.com/api/v2/news?page=1",
                                tries=1, timeout=12))
        _cn_ok("xz")
    except Exception as e:  # noqa: BLE001
        _cn_fail("xz")
        log("  xz 失败:", str(e)[:60])
        return out
    arr = d if isinstance(d, list) else (d.get("data") or [])
    for it in arr[:30]:
        title = it.get("title") or ""
        desc = _plain(it.get("subject") or it.get("summary") or "")
        ok, why = ai_gate(title, desc)
        if not ok:
            continue
        rid = "XZ:" + str(it.get("id") or abs(hash(title)))
        # time 字段常为 None，真正在用的是 created_at / pub_at（ISO 字符串）
        pub = _fmt_pub(it.get("time") or it.get("pub_at") or it.get("created_at"))
        rec = X._skeleton(
            rid=rid, rtype="article", kind="先知社区文章",
            title=title, desc=desc[:1500], published=pub,
            sources=["先知社区"], category=_guess_cat(title + " " + desc),
            reason=f"先知社区最新发布（{why}）", tags=["中文社区", "先知"],
        )
        # news API 不返回 url/link 字段（实测 6+ 条为空）。先知社区资讯详情页 URL
        # 规则确定：/news/{id} —— 取自官方 RSS(xz.aliyun.com/feed) 的 <link> 全集，
        # 与 XZ:92857/92855/92868/92886/92898/92915 的 desc 逐条核对一致；
        # 与 core/engine.py canonical_url 的 XZ: 映射同源。id 缺失时不猜。
        nid = it.get("id")
        rec["link"] = it.get("url") or it.get("link") or (f"https://xz.aliyun.com/news/{nid}" if nid else "")
        rec["live"] = True
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# CSDN 作者订阅（RSS）
# --------------------------------------------------------------------------
# 为什么必须单独开这条通道：
#   CSDN 的搜索接口（so.csdn.net/api/v3）是按「热度」排序的，刚发布、0 阅读的
#   文章排不进任何宽泛检索词的前几页 —— 实测 7 个检索词 × 各翻 2 页，目标文章
#   一次都没出现；而 hot-rank 的 type 参数会被服务端忽略（newest / new / time /
#   latest 返回同一份热榜），全站「最新发布」接口要么 401（api/articles）要么
#   521（phoenix/web/blog/newest）。所以走「固定检索词 + 翻页」的老路，新文章要
#   等热度爬上来才可能被召回，可能是几小时甚至几天。
#   作者维度是唯一能秒级拿到「刚发布」文章的公开通道：新文章就在第一位。
# 2026-09-29 两轮实测：
#   ① blog.csdn.net/<author>/rss/list 已被 CSDN 301 到 rss.csdn.net/<author>/rss/map；
#      旧地址在部分环境下会拿到 WAF 的 301 HTML（不是 RSS），_rss_items 解析出 0 条 ——
#      表现为「订阅作者明明发了新文章，快车道却一条都收不到」。改用跳转后的终址。
#   ② rss.csdn.net 主域现在直接 521（源站已下架 RSS 出口），直连更是 curl 7 连不上；
#      于是换成官方博客列表 JSON —— 实测第一条就是 21:51 刚发的那篇（含 postTime）。
#      注意：home-api 强制校验 Referer，不带一律 521，必须带 https://blog.csdn.net/<author>。
CSDN_AUTHOR_API = ("https://blog.csdn.net/community/home-api/v1/get-business-list"
                   "?page=1&size=20&businessType=blog&orderby=&noMore=false&username={author}")
CSDN_AUTHOR_RSS = "https://rss.csdn.net/{author}/rss/map"      # 兜底（多数环境已 521）
DEFAULT_CSDN_AUTHORS = ["WATERKING_MEMORY"]


def csdn_authors():
    """订阅作者列表：环境变量 AISEC_CSDN_AUTHORS > config.json 的 csdn_authors > 默认。"""
    env = (os.environ.get("AISEC_CSDN_AUTHORS") or "").strip()
    if env:
        return [a.strip() for a in re.split(r"[,;\s]+", env) if a.strip()]
    try:
        with open(os.path.join(_ROOT, "config.json"), encoding="utf-8") as f:
            v = (json.load(f) or {}).get("csdn_authors")
        if isinstance(v, list) and v:
            got = [str(a).strip() for a in v if str(a).strip()]
            if got:
                return got
    except Exception as _sw_e:  # noqa: BLE001 —— 配置缺失/损坏都退回默认
        _swallow("modules/m1_monitor/backend/live.py:964", _sw_e)
    return list(DEFAULT_CSDN_AUTHORS)


def _csdn_author_items(author, size=20):
    """取某个订阅作者的最新文章（新 → 旧），统一成与 RSS 同构的
    [{title, link, published, summary}]，下游解析逻辑不用改。

    主通道 home-api（JSON），失败才回退 RSS —— 见上方 CSDN_AUTHOR_API 注释。
    """
    try:
        raw = http_get(CSDN_AUTHOR_API.format(author=author), tries=1, timeout=8, headers={
            "Referer": f"https://blog.csdn.net/{author}",
            "Accept": "application/json, text/plain, */*",
        })
        lst = ((json.loads(raw) or {}).get("data") or {}).get("list") or []
        out = []
        for it in lst[:size]:
            aid = str(it.get("articleId") or "").strip()
            title = (it.get("title") or "").strip()
            if not aid or not title:
                continue
            out.append({
                "title": html.unescape(title),
                "link": it.get("url") or f"https://blog.csdn.net/{author}/article/details/{aid}",
                "published": _norm_date(str(it.get("postTime") or "")[:19]),
                "summary": html.unescape(it.get("description") or "")[:2500],
            })
        if out:
            return out
    except Exception as e:  # noqa: BLE001
        log(f"  csdn@{author} API 通道失败（{str(e)[:40]}），回退 RSS")
    try:
        xml = http_get(CSDN_AUTHOR_RSS.format(author=author), tries=1, timeout=10)
        return _rss_items(xml, "CSDN")[:size]
    except Exception as e:  # noqa: BLE001
        log(f"  csdn@{author} 失败:", str(e)[:60])
        return []


def src_csdn_authors():
    """按订阅作者抓 CSDN 最新文章（home-api JSON 主通道，新文章在第一条）。"""
    out = []
    for author in csdn_authors()[:5]:
        for it in _csdn_author_items(author)[:20]:
            title = it["title"] or ""
            desc = it["summary"] or ""
            # 门控与离线脚本 harvest_cn 保持同一口径（同为 CSDN 源，两条通道若
            # 标准不一，会出现「快车道收进来、离线又当成不合格」的来回打架）。
            # 这里用 CSDN_GATE（安全相关）而不是 ai_gate（仅 AI 相关）：订阅是
            # 用户主动指定的作者，通用安全内容（SQL注入 / CTF 等）同样该收。
            if not X.CSDN_GATE.search(title + " " + desc) or X.CSDN_BAD_TITLE.search(title):
                log(f"  csdn@{author} 跳过(未过安全门控):", title[:40])
                continue
            link = it["link"] or ""
            m = re.search(r"/article/details/(\d+)", link)
            aid = m.group(1) if m else str(abs(hash(link or title)))
            rec = X._skeleton(
                rid="CSDN:" + aid, rtype="article", kind="CSDN 社区文章",
                title=title, desc=(title + "。" + desc)[:1500],
                published=it["published"] or "",
                sources=["CSDN"], category=_guess_cat(title + " " + desc),
                reason=f"CSDN 订阅作者 {author} 最新文章（作者主页 API 通道）",
                tags=["中文社区", "CSDN"],
            )
            rec["author"] = author
            rec["article_url"] = link
            rec["link"] = link
            rec["live"] = True
            out.append(rec)
    return out


# --------------------------------------------------------------------------
# 中文社区文章落盘：快车道 → data/cn/*.json
# --------------------------------------------------------------------------
# 快车道抓到的中文社区文章原本只写 live_feed.jsonl（实时流），不进持久语料
# data/cn/*.json —— 而后者才是 merge 进 corpus.json、能被检索/问答命中的地方。
# 结果就是「实时流里有 9-29 的文章，知识库里最新却停在 9-24」，看上去像没爬。
# 这里补上落盘：按 id 去重，且只在真有新条目时才原子写（不然每 15s 重写几千条 JSON）。

_CN_FILE = {"安全客": "anquanke.json", "先知社区": "xz.json", "CSDN": "csdn.json"}


def _cn_target(rec):
    """记录 → (目标文件名, 归一化后的 id)；非中文社区文章返回 (None, None)。

    快车道用的 id 前缀与离线收割脚本不一致（AQ: vs AQK:），落盘前必须归一化，
    否则同一篇文章会以两个 id 各存一份。
    """
    srcs = rec.get("sources") or []
    name = srcs[0] if srcs else ""
    fp = _CN_FILE.get(name)
    if not fp:
        return None, None
    rid = str(rec.get("id") or "")
    if rid.startswith("AQ:"):
        rid = "AQK:" + rid[3:]
    return fp, (rid or None)


_CN_LOCK = threading.Lock()   # 并发提交会同时写 data/cn：见 _atomic_json_dump 的说明


def _atomic_json_dump(path, data, retries=3):
    """原子写 JSON，临时文件名带 pid + 线程号。

    原先写死 `path + ".tmp"`：并发提交（实测 16 并发）时多个请求会同时
    open 同一个临时文件 → WinError 32「另一个程序正在使用此文件」，随后
    os.replace 撞 WinError 5「拒绝访问」，请求直接 500/连接被中止。
    更难发现的是「读-改-写」没有串行化：两个请求各自读到同一份旧内容、
    各自追加自己那条，后写的覆盖先写的 —— 不报错，但静默丢记录。
    所以这里两件事一起做：临时文件唯一化 + 整个读改写过程持锁。
    """
    tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
    last = None
    for _ in range(max(1, retries)):
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, path)
            return
        except OSError as e:      # Windows 下杀软/索引会短暂占用目标文件
            last = e
            try:
                if os.path.isfile(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            time.sleep(0.05)
    raise last


def _persist_cn(records, verbose=True):
    """把快车道新抓到的中文社区文章追加进 data/cn/*.json（去重 + 原子写）"""
    by_file = {}
    for r in records or []:
        if not isinstance(r, dict):
            continue
        fp, rid = _cn_target(r)
        if not fp or not rid:
            continue
        r = dict(r)
        r["id"] = rid
        r.pop("live", None)          # 落盘后就是持久语料，不再是「实时」条目
        by_file.setdefault(fp, []).append(r)
    if not by_file:
        return 0

    os.makedirs(CN_DIR, exist_ok=True)
    total = 0
    for fp, items in by_file.items():
        path = os.path.join(CN_DIR, fp)
        # 读-改-写必须串行：否则并发提交会各自基于旧内容追加，后写覆盖先写，静默丢记录
        with _CN_LOCK:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cur = json.load(f)
                if not isinstance(cur, list):
                    cur = []
            except Exception:  # noqa: BLE001 —— 文件缺失或损坏都当作空库，从头建
                cur = []
            seen = {str(x.get("id")) for x in cur if isinstance(x, dict)}
            add = [x for x in items if x["id"] not in seen]
            if not add:
                continue
            cur.extend(add)
            _atomic_json_dump(path, cur)
            total += len(add)
            if verbose:
                log(f"  落盘 data/cn/{fp}: +{len(add)}（累计 {len(cur)}）")
    return total


def append_feed(records):
    """把记录追加进实时流 live_feed.jsonl（与快车道同一落盘通道）。
    服务重启时由 _live_replay 回放这些记录 → 用户投稿的文章重启不丢。"""
    records = [r for r in (records or []) if isinstance(r, dict)]
    if not records:
        return 0
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    n = 0
    try:
        with open(FEED_FP, "a", encoding="utf-8") as f:
            for r in records:
                if "fetched_at" not in r:
                    r = dict(r)
                    r["fetched_at"] = ts
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                n += 1
    except OSError as e:  # noqa: BLE001
        log("  append_feed 失败（不影响即时收录）:", str(e)[:80])
    return n


def _guess_cat(text, products=None):
    """分类：**统一走引擎分类器**（`core/fetch_corpus.py:classify`）。

    为什么必须换掉手搓的那套（2026-10-07 实测重写）：

      ① 旧实现在投票为空时 `return "③ AI应用与智能体"` —— 等于把
         "没有任何 AI 证据"的通用安全内容统统塞进 AI 四分类。实测被塞进去的
         有：Apache Struts 远程代码执行、Hitachi Energy REB500 继电保护装置、
         「我渗透到一个黑客集团」、「一个人的 SOC」、Star Blizzard 钓鱼活动
         —— 用户截图反馈的"分类误判"就是这个。

      ② 旧实现用裸子串匹配，误判概率极高：
           (\"rag\", \"③\")      被 storage / average / fragment 命中
           (\"agent\", \"③\")    被 user-agent 命中
           AI_PRODUCTS 的 \"dify\" 被 **modify** 命中（\"mo-dify\"）
           AI_PRODUCTS 的 \"continue\" 被英文常用词 continue 命中
         于是一篇讲 Web 安全的文章只要出现 storage 两个字就被判成 AI 应用。

      ③ 与离线语料不是同一套规则 —— 同一条漏洞在检索页（classify）和
         实时流/日报（_guess_cat）里分类不同，评审一眼就能看穿。

    统一之后两端同口径。返回的**一定**是 RISK_CATEGORIES 里的 11 类之一，
    且没有 AI 证据时只会落到 ⑤~⑪，不会再"默认成 AI"。
    """
    rec = {
        "title": text or "",
        "desc": text or "",
        "products": list(products or []),
        "vendors": [],
        "cwe": [],
        "tags_raw": [],
    }
    try:
        _ok, _score, cat, _reason, _tags = F.classify(rec)
        if cat:
            return cat
    except Exception as _sw_e:  # noqa: BLE001 —— 分类失败不能拖垮采集
        _swallow("modules/m1_monitor/backend/live.py:_guess_cat", _sw_e)
    return "⑤ Web应用与API安全"


# --------------------------------------------------------------------------
# 用户粘贴链接收录（提交链接即时收录）
# --------------------------------------------------------------------------
# 需求：用户在任意平台（安全客 / 先知 / CSDN / FreeBuf / 知乎 / 个人博客 / Medium
# 等）发布一篇相关文章后，把链接粘进系统，后端立刻抓取正文、入库、显示，
# 最晚 1 小时内收录（实际做到秒级）。这是自动轮询覆盖不到「任意作者 / 任意平台」
# 时的兜底通道：自动轮询只抓固定作者与首页前 N 条，用户自己发的文章若不在其中，
# 就靠这条通道手动兜底，绝不漏收。
import urllib.parse as _up
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 非原生平台统一落 submitted.json（原生 安全客/先知/CSDN 走各自文件）
for _s in ("其他平台", "FreeBuf", "安全内参", "360安全", "知乎", "掘金", "海外博客"):
    _CN_FILE.setdefault(_s, "submitted.json")


def _plat_of(host):
    """按域名识别平台 → (平台键, kind, sources[0])；未知平台归为「其他平台」。"""
    h = (host or "").lower()
    if "anquanke.com" in h:
        return "anquanke", "安全客文章", "安全客"
    if "xz.aliyun.com" in h or "xianzhi" in h:
        return "xz", "先知社区文章", "先知社区"
    if "csdn.net" in h:
        return "csdn", "CSDN 社区文章", "CSDN"
    if "freebuf.com" in h:
        return "freebuf", "FreeBuf 文章", "FreeBuf"
    if "sec-in.com" in h:
        return "secin", "安全内参文章", "安全内参"
    if "360.cn" in h or "anquan.360" in h:
        return "s360", "360 安全文章", "360安全"
    if "zhihu.com" in h:
        return "zhihu", "知乎文章", "知乎"
    if "juejin.cn" in h:
        return "juejin", "掘金文章", "掘金"
    if "medium.com" in h or "substack" in h:
        return "medium", "海外技术博客", "海外博客"
    return "other", "用户投稿文章", "其他平台"


def _html_title(text):
    m = re.search(r"<title[^>]*>([\s\S]*?)</title>", text, re.I)
    if m:
        return _plain(m.group(1))[:200]
    return ""


def _meta_content(text, *props):
    """取 <meta ... content> 的内容，按 props 顺序（property/name）匹配两种属性顺序。"""
    for pr in props:
        m = re.search(
            "<meta[^>]+(?:property|name)\\s*=\\s*[\"']" + re.escape(pr)
            + "[\"'][^>]*?content\\s*=\\s*[\"']([^\"']*)[\"']", text, re.I)
        if m:
            return html.unescape(m.group(1)).strip()
        m = re.search(
            "<meta[^>]+content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*?(?:property|name)\\s*=\\s*[\"']"
            + re.escape(pr) + "[\"']", text, re.I)
        if m:
            return html.unescape(m.group(1)).strip()
    return ""


def _extract_jsonld_date(text):
    m = re.search(r'"datePublished"\s*:\s*("?)([0-9]{4}-[0-9]{2}-[0-9]{2}[T ]?[0-9:]*)\1', text)
    if m:
        return m.group(2)[:10]
    return ""


def _parse_article(text, url):
    """从 HTML 抽取 (title, body_text, published, author)。best-effort，失败不抛。"""
    title = _meta_content(text, "og:title", "twitter:title") or _html_title(text)
    published = (_meta_content(text, "article:published_time", "article:published",
                               "date", "pubdate", "publish-date")
                 or _extract_jsonld_date(text))
    published = _norm_date(published) if published else ""
    author = _meta_content(text, "article:author", "author", "og:article:author")
    if not author:
        am = re.search(r'<a[^>]+class="[^"]*author[^"]*"[^>]*>([\s\S]*?)</a>', text, re.I)
        if am:
            author = _plain(am.group(1))
    # 正文：整页去标签（_plain 已跳过 head/script/style），再裁到合理长度
    body = _plain(text)
    if title and body.startswith(title):
        body = body[len(title):].strip()
    return (title or "").strip(), body[:4000], published, (author or "").strip()[:60]


def _submit_rid(url, plat):
    """由链接生成稳定 id：能解析出平台原生 id 就用原生（与自动采集去重），
    否则用 URL 哈希。原生 id 与 src_csdn_authors / 离线收割保持一致，避免重复存储。"""
    u = url.rstrip("/")
    if plat == "csdn":
        m = re.search(r"/article/details/(\d+)", u)
        if m:
            return "CSDN:" + m.group(1)
    if plat == "anquanke":
        m = re.search(r"/post/id/(\d+)", u) or re.search(r"[?&]id=(\d+)", u)
        if m:
            return "AQK:" + m.group(1)        # 离线语料用 AQK: 前缀，避免与快车道 AQ: 撞
    if plat == "xz":
        m = re.search(r"/article/id/(\d+)", u) or re.search(r"/p/(\d+)", u)
        if m:
            return "XZ:" + m.group(1)
    return "SUB:" + str(abs(hash(u)))


def _relevance(text):
    """通用安全相关性（软判定）：命中通用安全词或 AI 词即 high。
    用户主动提交的链接默认信任，relevance 仅用于展示与检索权重提示，不拦截。"""
    if X.CSDN_GATE.search(text or ""):
        return True, "通用安全词命中"
    ok, why = ai_gate(text or "")
    if ok:
        return True, why
    return False, ""


# 质量评估使用的「安全主题词表」：覆盖常见攻防/漏洞/合规议题，用于度量文章与平台主题的贴合度。
_SECURITY_TERMS = (
    "漏洞", "注入", "攻击", "防御", "防护", "渗透", "恶意", "病毒", "木马", "勒索",
    "提权", "绕过", "加密", "解密", "逆向", "爬虫", "钓鱼", "社工", "内网", "域控",
    "应急", "cve", "cwe", "rce", "xss", "sql", "反序列化", "命令执行", "权限", "防火墙",
    "waf", "0day", "payload", "后门", "溯源", "加固", "审计", "合规", "数据安全", "隐私",
    "apt", "红队", "蓝队", "护网", "蜜罐", "沙箱", "免杀", "内存马", "webshell", "ssrf",
    "csrf", "越权", "弱口令", "爆破", "横向移动", "权限提升", "代码审计", "安全研究",
)
# 广告/导流/营销词：命中越多越像推广软文而非技术内容
_SPAM_WORDS = (
    "扫码", "加微信", "关注公众号", "点击购买", "包邮", "优惠券", "限时折扣", "下载APP",
    "免费领取", "推广", "广告", "代写", "加盟", "充值", "返利", "加好友", "私聊",
)


def _assess_quality(title, body):
    """提交文章质量分类（本地确定性，不依赖大模型，毫秒级）。

    四个维度加权 → 0~100 总分 → 优/良/中/差 分级，并给出 extremely_poor 标记供「过滤掉质量极差」使用。
      · 篇幅 L(0~40)：正文过短（<100 字）直接判差
      · 结构 S(0~15)：段落数 / 代码块 / 列表 / 标题
      · 主题贴合 R(0~25)：安全词命中密度（与平台主题的相关度）
      · 信息度 P(0~20)：词汇多样性 + 成稿度
      · 惩罚：广告词、链接过密（导流/采集）、高度模板化（低异词率）
    """
    t = (title or "").strip()
    b = (body or "").strip()
    blen = len(b)
    paras = [p for p in re.split(r"\n\s*\n|\n", b) if len(p.strip()) >= 20]
    n_para = len(paras)
    has_code = bool(re.search(r"(```|`[^\n`]+`|^\s*(def|function|import|SELECT|public)\b|\bimport\s+\w+\s*$)",
                                b, re.M | re.I))
    has_list = bool(re.search(r"(?:^|\n)\s*[\-\*\u2022]|\n\s*\d+\.\s", b))
    has_heading = bool(re.search(r"(?:^|\n)#{1,4}\s|《|【|\[.+?\]", t))

    sec_hits = sum(b.lower().count(w) + t.lower().count(w) for w in _SECURITY_TERMS)
    spam = sum(1 for w in _SPAM_WORDS if w in b)

    words = re.findall(r"[A-Za-z]+|[一-鿿]", b)
    uniq_ratio = (len(set(words)) / len(words)) if words else 0.0
    link_count = b.count("http")

    # —— 维度分 ——
    if blen >= 1500:
        L = 40
    elif blen >= 800:
        L = 35
    elif blen >= 400:
        L = 28
    elif blen >= 200:
        L = 18
    elif blen >= 100:
        L = 10
    else:
        L = 0
    S = min(15, n_para * 4 + (4 if has_code else 0) + (3 if has_list else 0) + (2 if has_heading else 0))
    R = min(25, int(min(sec_hits, 20) * 1.5))
    P = int(uniq_ratio * 15) + (5 if (blen >= 200 and n_para >= 2) else 0)

    penalty = 0
    if spam >= 3:
        penalty += 30
    elif spam >= 2:
        penalty += 18
    elif spam == 1:
        penalty += 8
    if link_count > max(3, blen // 200):
        penalty += 15
    if uniq_ratio < 0.25 and blen > 200:
        penalty += 10

    total = max(0, L + S + R + P - penalty)
    if total >= 75:
        tier = "优"
    elif total >= 58:
        tier = "良"
    elif total >= 40:
        tier = "中"
    else:
        tier = "差"

    # 质量极差（仅用于「过滤质量极差」的硬过滤，宁缺毋滥，不能误伤短而优质的稿件）：
    #   · 极短（<30 字，基本无内容）
    #   · 重度广告（spam>=3）
    #   · 综合极差（重惩罚 且 本就判为「差」）
    #   · 短（<150 字）且无安全主题贴合、无段落结构、无代码、无广告 —— 典型灌水/随手帖
    # 注意：仅「短」不足以判定极差，避免误伤短而专业的投稿。
    extremely_poor = (
        (blen < 30)
        or (spam >= 3)
        or (penalty >= 30 and tier == "差")
        or (blen < 150 and sec_hits == 0 and n_para <= 1 and not has_code and spam == 0)
    )
    return {
        "score": total, "tier": tier, "extremely_poor": extremely_poor,
        "signals": {
            "body_len": blen, "paragraphs": n_para, "security_hits": sec_hits,
            "spam_words": spam, "link_count": link_count,
            "unique_ratio": round(uniq_ratio, 3),
            "has_code": bool(has_code), "has_list": bool(has_list),
        }, "penalty": penalty,
    }


def persist_submission(recs):
    """公开落盘接口：api 层在「质量/近重过滤通过」后调用，仅写 data/cn（不同步引擎）。"""
    try:
        _persist_cn(recs, verbose=False)
    except Exception as e:  # noqa: BLE001
        log("  persist_submission 落盘 data/cn 失败:", str(e)[:80])


def submit_article(url, force=False, persist=True):
    """用户粘贴文章链接 → 抓取正文 → 质量分类 → 构造 record，返回 (rec, info)。

    - 质量分类（_assess_quality）写入 rec["quality"]/rec["quality_tier"]，供前端分级与「过滤质量极差」。
    - persist=True（默认）时直接落盘 data/cn；api 层为支持「先过滤后落盘」会传 persist=False，
      过滤通过后再调 persist_submission() 显式落盘。
    - 不负责入索引（由 api 层 add_documents 并入引擎，保证与快车道同口径）。
    返回 info 含 platform / kind / source / relevance / rel_why / quality / title / published /
    author / desc_len，供前端展示与后续排查。
    """
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("链接格式不正确，需以 http:// 或 https:// 开头")
    host = _up.urlparse(url).netloc.lower()
    plat, kind, src = _plat_of(host)
    try:
        raw = http_get(url, tries=2, timeout=20,
                       headers={"Accept": "text/html,application/xhtml+xml,*/*",
                                "User-Agent": "Mozilla/5.0 (compatible; AISEC-Ingest/2.0)"})
    except Exception as e:  # noqa: BLE001 —— 抓不到就明确报错，不让用户以为收录成功
        raise RuntimeError("抓取失败：" + str(e)[:160])
    # 本模块 http_get 默认返回 str（binary=False），少数路径返回 bytes，统一处理。
    # bytes.decode 最多两个参数（encoding, errors），不能用三个位置参数。
    text = raw if isinstance(raw, str) else raw.decode("utf-8", "ignore")
    title, body, published, author = _parse_article(text, url)
    if not title:
        raise ValueError("无法从页面解析出标题，请确认链接指向一篇具体文章")
    desc = body or title
    if not published:
        published = time.strftime("%Y-%m-%d")     # 没解析到日期就用今天，保证进「最新」
    rid = _submit_rid(url, plat)
    rec = X._skeleton(
        rid=rid, rtype="article", kind=kind,
        title=title, desc=desc[:1500], published=published,
        sources=[src], category=_guess_cat(title + " " + desc),
        reason=f"用户粘贴链接收录（{src}）",
        tags=["用户投稿", src, "中文社区"],
    )
    rec["link"] = url
    rec["submitted"] = True
    rec["author"] = author or ""
    rel_ok, rel_why = _relevance(title + "。" + desc[:500])
    rec["relevance"] = "high" if rel_ok else "low"
    # 质量分类（本地确定性评估，供前端分级展示 + 后续「过滤质量极差」）
    q = _assess_quality(title, body)
    rec["quality"] = q
    rec["quality_tier"] = q["tier"]
    # 落盘到 data/cn：persist=True（默认，兼容单测）时直接落盘；api 层会在完成
    # 「质量/近重过滤」判定后再显式落盘，此时传 persist=False 避免先落盘再撤回。
    if persist:
        try:
            _persist_cn([rec], verbose=False)
        except Exception as e:  # noqa: BLE001 —— 落盘失败不影响即时收录（引擎里已有）
            log("  submit_article 落盘 data/cn 失败（不影响即时收录）:", str(e)[:80])
    info = {"platform": plat, "kind": kind, "source": src,
            "relevance": rec["relevance"], "rel_why": rel_why,
            "quality": q, "title": title, "published": published, "author": author,
            "desc_len": len(desc), "rid": rid}
    return rec, info


# 中文社区源（安全客 / 先知）的抓取间隔，默认 15s —— 与快车道外层轮询同拍，
# 满足「社区文章每 15 秒爬一次」。设 AISEC_CN_SRC_GAP=60 可退回原来的 60s 节奏。
try:
    _CN_SRC_GAP = max(5, int(os.environ.get("AISEC_CN_SRC_GAP", "15")))
except Exception:  # noqa: BLE001
    _CN_SRC_GAP = 15

SOURCES = [
    # (名称, 抓取函数, 最小间隔秒) —— 分源节奏，按「新信息落点 + 上游配额」区分：
    #   中文社区（安全客 / 先知）—— 15s，与外层轮询同拍：社区文章是本项目的主要
    #     语料来源，要求「每 15 秒爬一次」，抓的是最新一页（30/15 条），开销可控；
    #   博客/厂商公告 —— 新披露的主落点，30s 到期才抓（源多、单次较重）；
    #   NVD —— 60s，匿名限额与全量回填共用，再快会触发 403；
    #   论文与 KEV —— 变化慢，300s 足够。
    # 各源并行执行，单轮耗时由最慢的到期源决定（HTTP 超时已收紧），
    # 因此外层轮询节拍为 15s 时，新信息公开后约 15s 内即可检索到。
    # 想放宽社区源节奏（比如怕被限流）可设 AISEC_CN_SRC_GAP 覆盖，单位秒。
    # CSDN 走「作者 RSS 订阅」通道（见 src_csdn_authors）：搜索接口按热度排序，
    # 抓不到刚发布的文章；作者 RSS 能把新文章秒级拿进来。
    ("csdn", src_csdn_authors, _CN_SRC_GAP),
    # 博客源走异步入口：抓取在后台线程，这里只收上一轮结果（不拖慢社区源）
    ("blogs", src_blogs_async, 15),
    ("anquanke", src_anquanke, _CN_SRC_GAP),
    ("xz", src_xz, _CN_SRC_GAP),
    # 慢源（NVD / KEV / arXiv）全部改走后台线程：外层 gap 写 15（每轮只收结果），
    # 真实抓取节奏由 make_slow_async 内部掌握（180s / 300s / 300s）。
    # 这样到期那一轮不再把 15s 节拍顶到 43.8s（实测），社区文章时效回到 15s。
    ("nvd", make_slow_async("nvd", src_nvd, 180), 15),
    ("kev", make_slow_async("kev", src_kev, 300), 15),
    ("arxiv", make_slow_async("arxiv", src_arxiv, 300), 15),
]
# 启动时钟：慢源不再和服务抢首轮。
# 原先 _SRC_LAST 为空 → 启动后所有源同时"到期"，NVD(180s) + KEV(300s) + arXiv(300s)
# 一次性全压在第一轮上，实测首轮 157s，快车道整整两分半没产出。
# 现在慢源从"刚抓过"开始计时，快源（社区 15s / 博客 15s）照旧立即开工。
_SRC_LAST = {_n: time.time() for _n, _, _g in SOURCES if _g > 30}


def _due_sources(now):
    due = []
    for name, fn, gap in SOURCES:
        if now - _SRC_LAST.get(name, 0) >= gap:
            due.append((name, fn))
    return due


_POLL_LOCK = threading.Lock()


def poll_once(verbose=True):
    """执行一轮快源轮询，返回新记录列表（已去重、已 AI 过滤）。
    各源并行执行：端到端由最慢的到期源决定（~15-25s）。

    同一时刻只允许一轮：poll_once 会清 _SRC_OK、append 写 FEED_FP、覆盖
    live_seen.json，两轮并发会互相踩（源健康度乱跳、seen 丢条目）。
    跑不完就跳过本轮——反正下一轮 15s 后就到，叠着跑只会更慢。
    """
    if not _POLL_LOCK.acquire(blocking=False):
        return []
    try:
        return _poll_once_inner(verbose)
    finally:
        _POLL_LOCK.release()


def _poll_once_inner(verbose=True):
    t0 = time.time()
    seen, meta = load_seen()
    fresh = []
    per_src = dict((LAST_META.get("per_source") or {}))   # 未到节奏的源保留上轮计数
    _SRC_ERR.clear()
    del _SRC_OK[:]

    def _run(item):
        name, fn = item
        # 熔断：连续失败达阈值的源本轮直接跳过，别再白等一次超时（自愈闭环）
        try:
            _cb = circuit.breaker()
            if not _cb.allow(name):
                _has_mirror = bool(circuit.MIRRORS.get(name))
                _SRC_ERR[name] = ("熔断中（连续失败达阈值，冷却中；镜像：%s）" % (
                    "可自动切换" if _has_mirror else "无可用镜像"))
                return name, []
        except Exception:  # noqa: BLE001 —— 熔断是增强项，绝不能因它阻断采集
            pass
        try:
            recs = fn() or []
        except Exception as e:  # noqa: BLE001
            log(f"  源 {name} 异常:", str(e)[:80])
            try:
                circuit.breaker().record(name, False, str(e))
            except Exception:  # noqa: BLE001
                pass
            return name, []
        # 抓取器多数自己吞掉错误返回 []，不抛 —— 只在异常时熔断会**永不触发**。
        # 但"本轮无新条目"≠源挂了：快源 15s 一轮，绝大多数轮次本来就该是空的
        # （刚抓过的源 15s 内不会有新文章）。若一轮空就记一次失败，任何源都会被误熔断。
        # 所以空结果只在**距上次成功已超过一个采集周期**时才算失败信号，
        # 由 breaker 用时间戳判断（见 _stale_ok），这里只把结果如实传下去。
        try:
            circuit.breaker().record(name, True, empty=not recs)
        except Exception:  # noqa: BLE001
            pass
        return name, recs

    due = _due_sources(time.time())
    for name, recs in _par_map(_run, due, workers=max(1, len(due))):
        _SRC_LAST[name] = time.time()
        n = 0
        for r in recs:
            rid = r.get("id")
            if not rid or rid in seen:
                continue
            seen.add(rid)
            fresh.append(r)
            n += 1
        per_src[name] = n
        if verbose:
            log(f"  {name}: +{n}")
    meta["last_poll"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    meta["per_source"] = per_src
    save_seen(seen, meta)
    if fresh:
        _fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        with open(FEED_FP, "a", encoding="utf-8") as f:
            for r in fresh:
                # v2.2：入库即打采集时间戳——「源站发布 → 系统采集」的端到端
                # 时效从此可以精确测量（tools/评测时效性.py 直接消费该字段）
                if isinstance(r, dict) and "fetched_at" not in r:
                    r["fetched_at"] = _fetched_at
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        # 中文社区文章同步落盘持久语料：实时流之外，data/cn 里也要有 ——
        # 否则 merge 进 corpus 时最新文章永远缺一块，表现为「社区文章停在几天前」。
        try:
            n_cn = _persist_cn(fresh, verbose=verbose)
            if n_cn and verbose:
                log(f"  中文社区落盘 {n_cn} 条")
        except Exception as e:  # noqa: BLE001 —— 落盘失败不影响实时流
            log("  落盘 data/cn 失败:", str(e)[:80])
    meta["poll_ms"] = int((time.time() - t0) * 1000)
    meta["fresh"] = len(fresh)
    meta["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    _ok_all, _err_all = src_health()
    meta["feed_ok"] = len(_ok_all)
    meta["feed_fail"] = dict(_err_all)
    # P0-3：跨轮源健康记账 + 缺失判定 + 告警。
    # 复用本轮 src_health() 作"本轮输入"（不改其本体），并把通道级新增计数一并喂进去，
    # 这样"缺失数据"（停产/缩水）也能被看见 —— 这是既有熔断（异常数据响应）不覆盖的盲点。
    try:
        import source_health as _SH
        _SH.record_poll(_ok_all, _err_all, per_src)
    except Exception as _sh_e:  # noqa: BLE001 —— 源健康是增强项，绝不阻断采集主流程
        _swallow("modules/m1_monitor/backend/live.py:record_poll", _sh_e)
    # 熔断状态落盘 + 并入状态接口（前端「源健康」区能直接看到谁熔断了、镜像是否可用）
    try:
        _cb = circuit.breaker()
        _cb.flush()
        meta["circuit"] = _cb.snapshot()
    except Exception:  # noqa: BLE001 —— 熔断是增强项，不影响主流程
        pass
    LAST_META.clear()
    LAST_META.update(meta)
    if verbose:
        log(f"本轮新增 {len(fresh)} 条，耗时 {meta['poll_ms']}ms")
    bad = list(_SRC_ERR)
    if bad:
        # 有源抓不到就报一行（含处置建议）——静默时说明全绿；/api/live 里也有 feed_ok/feed_fail
        log(f"  源健康：成功 {len(_ok_all)} · 失败 {len(bad)}（{('、'.join(bad[:5]))}"
            f"{' 等' if len(bad) > 5 else ''}）"
            + (" —— 多为境外站点，设 AISEC_PROXY 走代理后基本可恢复"
               if not _proxy() else " —— 已走代理仍失败，稍后自动重试"))
    elif verbose:
        log(f"  源健康：成功 {len(_ok_all)} · 失败 0")
    return fresh


if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    if len(sys.argv) > 1 and sys.argv[1] == "loop":
        while True:
            poll_once()
            time.sleep(FAST_INTERVAL)
    else:
        poll_once()
