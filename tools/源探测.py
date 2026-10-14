# -*- coding: utf-8 -*-
"""候选情报源批量探测：直连/代理两种通道各测一次，报告可达性与 RSS 条目数。

用法： python tools/源探测.py
"""
import re
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
PROXY = "http://127.0.0.1:33252"

CANDS = [
    # ── 中文源（优先直连）──
    ("看雪学院", "https://www.kanxue.com/rss.php"),
    ("安全内参", "https://www.secshi.com/feed"),
    ("360 CERT", "https://cert.360.cn/feed"),
    ("奇安信攻防社区", "https://forum.butian.net/rss"),
    ("腾讯玄武实验室", "https://xuanwulab.com/zh/atom.xml"),
    ("TSRC 博客", "https://security.tencent.com/index.php/blog/feed"),
    ("嘶吼(备用)", "https://www.4hou.com/category/热点资讯/feed"),
    ("安全客 RSS(复测)", "https://api.anquanke.com/data/v1/rss"),
    ("腾讯云安全社区", "https://cloud.tencent.com/developer/column/3006/feed"),
    ("博客园安全区", "https://www.cnblogs.com/cate/security/rss"),
    ("CNCERT 通告", "https://www.cert.org.cn/rss/index.xml"),
    ("漏洞盒子公告", "https://www.vulbox.com/rss"),
    # ── 英文源（多数走代理）──
    ("Project Discovery", "https://blog.projectdiscovery.io/rss/"),
    ("CrowdStrike", "https://www.crowdstrike.com/blog/feed/"),
    ("Google Cloud 威胁情报", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("SentinelOne", "https://www.sentinelone.com/labs/feed/"),
    ("Red Canary", "https://redcanary.com/feed/"),
    ("Volexity", "https://www.volexity.com/blog/feed/"),
    ("Palo Alto 博客", "https://www.paloaltonetworks.com/blog/feed/"),
    ("Sophos News", "https://news.sophos.com/en-us/atom.xml"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Trend Micro Research", "https://www.trendmicro.com/en_us/research.html/feed"),
    ("Fortinet 博客", "https://www.fortinet.com/blog/rss.xml"),
    ("Splunk 博客", "https://www.splunk.com/en_us/blog/rss.xml"),
    ("PacketStorm 最新", "https://packetstormsecurity.com/feeds/files/latest/"),
    ("Mandiant(已在GCP)", "https://cloud.google.com/blog/rss/"),
    ("HackerNews 备用直连", "https://thehackernews.com/feeds/posts/default"),
    ("CISA KEV JSON", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
]


def probe(item):
    name, url = item
    res = {}
    for mode, px in (("直连", None), ("代理", PROXY)):
        cmd = ["curl", "-sS", "-L", "--max-time", "10", "-A", UA, "-o", "-"]
        if px:
            cmd += ["--proxy", px]
        cmd.append(url)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=22)
            body = p.stdout[:400000].decode("utf-8", "replace")
            items = len(re.findall(r"<item[\s>]", body)) + len(re.findall(r"<entry[\s>]", body))
            ok_json = body.lstrip()[:1] in ("{", "[")
            res[mode] = (p.returncode == 0, len(p.stdout), items, ok_json)
        except Exception as e:  # noqa: BLE001
            res[mode] = (False, 0, 0, str(e)[:30])
    return name, url, res


def main():
    print(f"{'来源':<20} {'直连':<24} {'代理':<24}")
    good = []
    for name, url, res in ThreadPoolExecutor(8).map(probe, CANDS):
        def fmt(v):
            ok, size, items, extra = v
            if not ok:
                return "✗ 失败"
            tag = f"✓ {size//1024}KB 条目{items}" if items else (f"✓ {size//1024}KB JSON" if extra is True else f"✓ {size//1024}KB")
            return tag
        d, p = fmt(res["直连"]), fmt(res["代理"])
        print(f"{name:<20} {d:<24} {p:<24}")
        if (res["直连"][0] or res["代理"][0]) and (res["直连"][2] or res["代理"][2] or res["代理"][3] or res["直连"][3]):
            good.append((name, url, res))
    print("\n—— 可用（有数据）——")
    for name, url, res in good:
        mode = "直连" if res["直连"][0] and res["直连"][2] else "代理"
        print(f"  [{mode}] {name}  {url}")


if __name__ == "__main__":
    main()
