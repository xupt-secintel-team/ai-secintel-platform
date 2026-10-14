# -*- coding: utf-8 -*-
"""
_test_asset_scan.py —— 资产风险体检测试（离线、可复跑）
=========================================================================
覆盖四件事，任何一件挂掉都直接报 FAIL：
  ① 文件解析：docx / xlsx / txt 三种样例都要能读出行列结构
  ② 资产抽取：域名 / IP / 端口 / 软件+版本 是否抽全（含"空格分隔"的写法）
  ③ 版本区间判定：真阳性（该中的必须中）+ 真阴性（不该中的绝不能中）
  ④ 三种文件得到一致的体检结论（同源同结论，证明解析器之间无口径差）

用法： py tools/_test_asset_scan.py
"""
from __future__ import annotations

import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import asset_scan as AS  # noqa: E402
from engine import SearchEngine  # noqa: E402
import paths  # noqa: E402

FAILS = []
OKS = []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


def find_prod(rep, name):
    for p in rep["risk"]["products"]:
        if (p.get("display") or p["name"]) == name or p["name"] == name:
            return p
    return None


def has_cve(prod, cve):
    return any(f["id"] == cve for f in (prod or {}).get("findings", []))


def main():
    print("载入引擎 ...")
    eng = SearchEngine(paths.CORPUS_FP)
    print("  文档 %d 条（%s）" % (len(eng.docs), "缓存" if getattr(eng, "_loaded_from_cache", False) else "全量"))

    # ---------- ① 文件解析 ----------
    print("\n=== ① 文件解析 ===")
    samples = {}
    for name in ("示例-某公司互联网资产清单.docx", "示例-某公司互联网资产清单.xlsx",
                 "示例-某公司互联网资产清单.txt"):
        fp = os.path.join(ROOT, "data", "asset_samples", name)
        with open(fp, "rb") as f:
            data = f.read()
        doc = AS.read_upload(name, data)
        samples[name] = (data, doc)
        check(doc.chars > 300, "%s 解析出正文" % name, "chars=%d warn=%s" % (doc.chars, doc.warn))
        check(not doc.warn, "%s 无解析告警" % name, doc.warn)
        check("Tomcat" in doc.text and "9.0.30" in doc.text, "%s 正文含组件与版本" % name)
        check(len(doc.rows) >= 10, "%s 保留行列结构" % name, "rows=%d" % len(doc.rows))

    # ---------- ② 资产抽取 ----------
    print("\n=== ② 资产抽取（取 xlsx）===")
    _, doc = samples["示例-某公司互联网资产清单.xlsx"]
    assets = AS.extract_assets(doc.text, doc.rows)
    host_names = {h["name"] for h in assets["hosts"]}
    prods = {(p["name"], p["version"]) for p in assets["products"]}
    for d in ("www.example-corp.cn", "crm.example-corp.cn", "git.example-corp.cn"):
        check(d in host_names, "抽到域名 %s" % d)
    for ip in ("10.10.20.31", "203.0.113.10"):
        check(ip in host_names, "抽到 IP %s" % ip)
    check(any(h["name"] == "10.10.20.31" and h["scope"] == "内网" for h in assets["hosts"]),
          "内网 IP 识别为内网")
    for p, v in (("tomcat", "9.0.30"), ("log4j", "2.14.0"), ("http_server", "2.4.49"),
                 ("nginx", "1.16.1"), ("jenkins", "2.289.1"), ("gitlab", "13.10.0"),
                 ("redis", "5.0.7"), ("fortios", "6.4.2"), ("openssl", "1.1.1g")):
        check((p, v) in prods, "抽到软件 %s %s" % (p, v), sorted(prods))
    check("8080/tcp" in assets["ports"] and "443" in assets["ports"],
          "抽到端口（含 a/b 与 /tcp 两种写法）", assets["ports"])
    check("CentOS 7" in assets["os"], "抽到操作系统", assets["os"])
    check(not any(p["name"] in ("java", "apache") for p in assets["products"]),
          "泛词未造出假资产（Java / Apache 单独出现不算资产）",
          [p["name"] for p in assets["products"]])

    # ---------- ③ 版本区间判定 ----------
    print("\n=== ③ 版本区间判定 ===")
    # 精确命中：真阳性
    tp = [("log4j", "2.14.0", "CVE-2021-44228"),      # Log4Shell
          ("http_server", "2.4.49", "CVE-2021-42013"),  # 路径穿越 RCE（在野利用）
          ("tomcat", "9.0.30", "CVE-2020-1938"),        # Ghostcat
          ("spring_framework", "5.2.0", "CVE-2022-22965"),  # Spring4Shell
          ("jenkins", "2.289.1", "CVE-2024-23897"),
          ("nginx", "1.16.1", "CVE-2019-20372")]
    for name, ver, cve in tp:
        fs = AS.AssetRiskScanner(eng).match({"name": name, "version": ver})
        check(any(f["id"] == cve for f in fs), "真阳性：%s %s 应命中 %s" % (name, ver, cve),
              [f["id"] for f in fs][:5])
    # 真阴性：已修复版本不得再报
    tn = [("log4j", "2.16.0", "CVE-2021-44228"),
          ("log4j", "2.16.0", "CVE-2021-45046"),
          ("http_server", "2.4.60", "CVE-2021-42013"),
          ("tomcat", "9.0.100", "CVE-2020-1938"),
          ("spring_framework", "5.3.18", "CVE-2022-22965")]
    for name, ver, cve in tn:
        fs = AS.AssetRiskScanner(eng).match({"name": name, "version": ver})
        check(not any(f["id"] == cve for f in fs),
              "真阴性：%s %s 不应命中 %s" % (name, ver, cve),
              [f["id"] for f in fs if f["id"] == cve])
    # 版本比较器
    check(AS._vcmp("2.14.0", "2.15.0") < 0 and AS._vcmp("2.16.0", "2.15.0") > 0,
          "版本比较器：数值段")
    check(AS._vcmp("1.1.1", "1.1.1g") < 0 and AS._vcmp("1.0.0rc1", "1.0.0") < 0,
          "版本比较器：字母后缀（1.1.1 < 1.1.1g，rc1 < 正式）")
    check(AS.in_range("2.4.49", {"version": "*", "start_incl": "2.4.49",
                                 "end_incl": None, "end_excl": "2.4.50"}) is True,
          "区间判定：闭开区间 [2.4.49, 2.4.50)")
    check(AS.in_range("2.4.50", {"version": "*", "start_incl": "2.4.49",
                                 "end_incl": None, "end_excl": "2.4.50"}) is False,
          "区间判定：上界（不含）不命中")

    # ---------- ④ 三种文件结论一致 ----------
    print("\n=== ④ 三种文件结论一致 ===")
    reps = {}
    for name, (data, d) in samples.items():
        reps[name] = AS.build_report(name, data, eng, doc=d, persist=False)
    base = reps["示例-某公司互联网资产清单.xlsx"]["risk"]["summary"]
    for name, rep in reps.items():
        s = rep["risk"]["summary"]
        check(s["cve_hits"] == base["cve_hits"] and s["products"] == base["products"],
              "%s 结论与 xlsx 一致" % name, "hits=%s/%s products=%s/%s"
              % (s["cve_hits"], base["cve_hits"], s["products"], base["products"]))

    rep = reps["示例-某公司互联网资产清单.xlsx"]
    log4j = find_prod(rep, "Apache Log4j")
    check(log4j and log4j["risk_level"] == "严重" and has_cve(log4j, "CVE-2021-44228"),
          "Log4j 2.14.0 判为严重且含 Log4Shell")
    check(log4j and log4j["findings"][0]["exploited"] and log4j["findings"][0]["evidence"],
          "命中条目带「在野利用」与版本区间依据",
          log4j["findings"][0] if log4j else None)
    httpd = find_prod(rep, "Apache HTTP Server")
    check(httpd and httpd["kev_count"] >= 1, "httpd 2.4.49 报告出在野利用漏洞",
          httpd and httpd["kev_count"])
    md = AS.report_to_markdown(rep)
    check("# 公司互联网资产风险体检报告" in md and "CVE-2021-44228" in md and "处置建议" in md,
          "Markdown 报告可导出且含结论/明细/处置建议", len(md))

    print("\n===== 结果：%d 项通过 / %d 项失败 =====" % (len(OKS), len(FAILS)))
    if FAILS:
        for f in FAILS:
            print("  FAIL: %s" % f)
        raise SystemExit(1)
    print("ASSET SCAN TEST OK")


if __name__ == "__main__":
    main()
