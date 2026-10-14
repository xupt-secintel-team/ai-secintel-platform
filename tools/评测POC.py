# -*- coding: utf-8 -*-
"""
评测POC.py —— 模块2「POC/EXP 抓取」精度评测（优化前 vs 优化后，同一批数据）
================================================================================
做法（保证不循环自证）：
  1. 对每个 CVE 跑一次真实 POC 搜索（完整搜索，含 GitHub），拿到完整结果集；
  2. 用**本脚本独立实现的判据**给每条结果打真值标签（relevant / not-relevant），
     判据只看仓库名、描述、抓到的代码文本，**不看模块给的 match_tier**；
  3. 「优化前」= 按上一版排序规则（相关性评分 → 综合得分 → star）重排后算 precision@k，
     「优化后」= 按模块当前返回顺序算；两者基于同一批抓取结果，所以差异只来自排序规则本身；
  4. 两个数放一起就是优化幅度；结果还带 raw_rank（抓取原始顺序）作参考。

用法：
    py -3 tools/评测POC.py                 # 默认 6 个 CVE，约 3~6 分钟
    py -3 tools/评测POC.py --cves CVE-2021-44228,CVE-2024-37032
    py -3 tools/评测POC.py --quick         # 只跑离线源（秒级，用于冒烟）
输出：
    测试报告/POC精度评测.md / POC精度评测.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.parse
import urllib.request

BASE = (os.environ.get("AISEC_EVAL_BASE") or os.environ.get("AISEC_MAIN_SERVER")
        or "http://127.0.0.1:8848")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 本机回环强制不走系统代理（设过 HTTP_PROXY 的机器上会 502，症状像"服务坏了"）
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
OUT_MD = os.path.join(ROOT, "测试报告", "POC精度评测.md")
OUT_JSON = os.path.join(ROOT, "测试报告", "POC精度评测.json")

DEFAULT_CVES = [
    "CVE-2024-37032",   # Ollama 路径遍历 RCE
    "CVE-2021-44228",   # Log4Shell
    "CVE-2025-15063",   # Ollama MCP 命令注入
    "CVE-2026-26190",   # Milvus
    "CVE-2026-81265",   # Langflow
    "CVE-2026-41486",   # Ray
]

CURATED = {"metasploit", "nuclei-templates", "exploit-db", "packetstorm"}
POC_WORDS = re.compile(
    r"cve-\d{4}-\d+|poc|proof.of.concept|exploit|exp\b|vuln|漏洞复现|复现|利用|靶场|vulnerable|rce|"
    r"path.traversal|命令注入|writeup|advisory", re.I)
OFFICIAL_OWNER = {
    "ollama", "vllm-project", "gradio-app", "logspace-ai", "comfyanonymous", "milvus-io",
    "langchain-ai", "open-webui", "dify-ai", "ray-project", "langgenius", "huggingface",
    "pytorch", "tensorflow", "apache", "nvidia",
}


def judge(r: dict, cve: str, products: list[str]) -> bool:
    """独立判据：这条是不是与目标 CVE 相关的利用材料（true）还是噪声（false）。

    相关 =
      (a) 来自武器化/模板库；或
      (b) 仓库名/描述/代码里出现该 CVE 编号；或
      (c) 仓库名/描述带 PoC 类关键词 **且** 提到受影响组件名
    噪声 =
      · 官方组件仓库本身（受影响组件，不是 POC）
      · 只是 README 里列了该组件、却没有任何 PoC 线索的项目
    """
    src = str(r.get("source") or "").lower()
    if src in CURATED:
        return True
    title = str(r.get("title") or "")
    url = str(r.get("url") or "")
    code = str(r.get("code_content") or "")
    blob = f"{title} {url} {code[:8000]}".lower()
    name = title.lower()
    owner = name.split("/")[0] if "/" in name else ""

    cve_l = cve.lower()
    prods = [p.lower() for p in (products or [])]

    # 官方组件仓库 → 不是 POC
    if owner in OFFICIAL_OWNER:
        return False

    if cve_l in blob:
        return True
    prod_hit = any(re.search(rf"\b{re.escape(p)}\b", blob) for p in prods) if prods else False
    poc_hit = bool(POC_WORDS.search(f"{title} {url}"))
    if prod_hit and poc_hit:
        return True
    # 仓库名本身就是 PoC 风格（CVE 编号在名字里 / 含 poc/exploit）
    if POC_WORDS.search(name):
        return True
    return False


def http_json(url, payload=None, timeout=120):
    req = urllib.request.Request(url, method="POST" if payload is not None else "GET")
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode()
        req.add_header("Content-Type", "application/json; charset=utf-8")
    with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def products_of(cve: str) -> list[str]:
    try:
        d = http_json(BASE + "/api/detail?id=" + urllib.parse.quote(cve))
        item = d.get("item") or d
        return [str(x) for x in (item.get("products") or [])] or [str(x) for x in (item.get("vendors") or [])]
    except Exception:  # noqa: BLE001
        return []


def run_one(cve: str, quick: bool, wait_s: int = 420):
    quick_q = "1" if quick else "0"
    http_json(f"{BASE}/api/poc?id={urllib.parse.quote(cve)}&quick={quick_q}", payload={"id": cve})
    t0 = time.time()
    while time.time() - t0 < wait_s:
        st = http_json(f"{BASE}/api/poc?id={urllib.parse.quote(cve)}")
        if st.get("done") and not st.get("running"):
            return st
        time.sleep(5)
    return {"error": "超时未完成", "results": []}


def prec_at(rows, k, judge_fn):
    top = rows[:k]
    if not top:
        return None
    good = sum(1 for r in top if judge_fn(r))
    return round(good / len(top) * 100, 1)


def main():
    global BASE
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE)
    ap.add_argument("--cves", default=",".join(DEFAULT_CVES))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=OUT_MD)
    ap.add_argument("--json", default=OUT_JSON)
    args = ap.parse_args()
    BASE = args.base

    cves = [c.strip().upper() for c in args.cves.split(",") if c.strip()]
    print(f"[POC评测] 服务 {BASE}　模式={'快速(离线源)' if args.quick else '完整(含GitHub)'}　CVE {len(cves)} 个")
    rows_out = []
    for cve in cves:
        prods = products_of(cve)
        st = run_one(cve, args.quick)
        rs = st.get("results") or []
        jf = lambda r, p=prods, c=cve: judge(r, c, p)  # noqa: E731
        if not rs:
            print(f"  {cve:18s} 无结果（{st.get('error') or '空'}）")
            rows_out.append({"cve": cve, "n": 0, "error": st.get("error"), "products": prods})
            continue
        before_rows = sorted(rs, key=lambda r: (-(r.get("relevance_score") or 0),
                                                -(r.get("score") or 0),
                                                -(r.get("stars") or 0)))
        raw_rows = sorted(rs, key=lambda r: r.get("raw_rank") or 999)
        after_rows = rs
        rec = {
            "cve": cve, "products": prods, "n": len(rs),
            "tiers": st.get("tiers") or {},
            "before": {f"@{k}": prec_at(before_rows, k, jf) for k in (3, 5, 10)},
            "raw": {f"@{k}": prec_at(raw_rows, k, jf) for k in (3, 5, 10)},
            "after": {f"@{k}": prec_at(after_rows, k, jf) for k in (3, 5, 10)},
            "before_order": [r.get("title") or r.get("url") for r in before_rows[:10]],
            "after_order": [r.get("title") or r.get("url") for r in after_rows[:10]],
            "relevant_total": sum(1 for r in rs if jf(r)),
            # 存全量记录，方便事后换判据/换排序重算，不必再抓一次
            "records": [{"id": r.get("poc_id") or r.get("url"), "title": r.get("title"),
                         "source": r.get("source"), "tier": r.get("match_tier"),
                         "raw_rank": r.get("raw_rank"), "rel": r.get("relevance_score"),
                         "score": r.get("score"), "stars": r.get("stars"),
                         "relevant": bool(jf(r))} for r in rs],
        }
        rows_out.append(rec)
        print(f"  {cve:18s} 共 {len(rs):3d} 条（相关 {rec['relevant_total']}）　"
              f"精度@5 旧规则 {rec['before']['@5']}% → 新规则 {rec['after']['@5']}%　"
              f"@3 {rec['before']['@3']}% → {rec['after']['@3']}%　分级 {rec['tiers']}")

    ok = [r for r in rows_out if r.get("n")]
    def avg(scope, k):
        vals = [r[scope][f"@{k}"] for r in ok if r[scope][f"@{k}"] is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    summary = {
        "cves": len(cves), "with_results": len(ok),
        "before": {f"@{k}": avg("before", k) for k in (3, 5, 10)},
        "raw": {f"@{k}": avg("raw", k) for k in (3, 5, 10)},
        "after": {f"@{k}": avg("after", k) for k in (3, 5, 10)},
        "total_results": sum(r["n"] for r in ok),
        "total_relevant": sum(r["relevant_total"] for r in ok),
    }
    print(f"\n[POC评测] 平均精度 @3 {summary['before']['@3']}% → {summary['after']['@3']}%　"
          f"@5 {summary['before']['@5']}% → {summary['after']['@5']}%　"
          f"@10 {summary['before']['@10']}% → {summary['after']['@10']}%")
    print(f"[POC评测] 结果集 {summary['total_results']} 条，其中判为相关 {summary['total_relevant']} 条")

    L = []
    A = L.append
    A("# POC / EXP 抓取精度评测（优化前 vs 优化后）")
    A("")
    A(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　·　服务：{BASE}")
    A(f"- 模式：{'快速（仅离线武器化源）' if args.quick else '完整（含 GitHub 仓库搜索与代码抓取）'}")
    A(f"- 样本：{summary['with_results']} 个 CVE 有结果 / 共 {summary['cves']} 个；结果集 {summary['total_results']} 条")
    A("")
    A("## 一、结论")
    A("")
    A("| 指标 | 优化前（旧排序规则） | 原始抓取顺序（参考） | 优化后（分级重排） | 变化 |")
    A("|---|---|---|---|---|")
    for k in (3, 5, 10):
        b, rw, a = summary["before"][f"@{k}"], summary["raw"][f"@{k}"], summary["after"][f"@{k}"]
        dlt = "—" if (b is None or a is None) else f"{round(a - b, 1):+}"
        A(f"| 精度 @{k} | {b}% | {rw}% | **{a}%** | {dlt} |")
    A("")
    A("「优化前」= 上一版排序规则（相关性评分降序 → 综合得分 → star），**同一批抓取结果、同一套外部判据**，")
    A("只改排序，所以差异全部来自本次优化；「原始抓取顺序」是各数据源返回的先后顺序，仅作参考。")
    A("")
    A("## 二、逐 CVE 明细")
    A("")
    A("| CVE | 结果数 | 判为相关 | 分级分布 | @3 前→后 | @5 前→后 | @10 前→后 |")
    A("|---|---|---|---|---|---|---|")
    for r in rows_out:
        if not r.get("n"):
            A(f"| {r['cve']} | 0 | — | — | — | — | — |")
            continue
        tiers = " · ".join(f"{k}:{v}" for k, v in sorted((r.get("tiers") or {}).items()))
        A(f"| {r['cve']} | {r['n']} | {r['relevant_total']} | {tiers} | "
          f"{r['before']['@3']}% → {r['after']['@3']}% | "
          f"{r['before']['@5']}% → {r['after']['@5']}% | "
          f"{r['before']['@10']}% → {r['after']['@10']}% |")
    A("")
    A("## 三、Top-5 顺序对照（看噪声是否被压下去）")
    A("")
    for r in rows_out:
        if not r.get("n"):
            continue
        A(f"### {r['cve']}（受影响组件：{', '.join(r['products']) or '—'}）")
        A("")
        A("| # | 优化前 | 优化后 |")
        A("|---|---|---|")
        for i in range(5):
            b = r["before_order"][i] if i < len(r["before_order"]) else "—"
            a = r["after_order"][i] if i < len(r["after_order"]) else "—"
            flag = "" if b == a else " 🔄"
            A(f"| {i+1} | {b} | {a}{flag} |")
        A("")
    A("## 四、判据与口径")
    A("")
    A("- 真值标签由**评测脚本独立实现**（来源属于武器化/模板库、仓库名或抓到的代码含目标 CVE 编号、")
    A("  仓库名/描述带 PoC 类关键词且提到受影响组件），**不读取模块给出的 `match_tier`**，因此不是自证。")
    A("- 官方组件仓库（如 `ollama/ollama`、`open-webui/open-webui`）无论多热门都判为**不相关**：")
    A("  它们是「受影响组件本身」，不是利用代码；模块里被单独分级（D），前端默认折叠。")
    A("- 「快速搜索」不含 GitHub，故该模式下相关条数天然偏少（离线源本身都是武器化材料，精度接近 100%）。")
    A("- 抓取结果受 GitHub 速率限制影响，重复运行的条数会有波动；**同一轮内的前/后对比**才是本报告的结论依据。")
    A("")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"at": time.strftime("%Y-%m-%d %H:%M:%S"), "quick": args.quick,
                   "summary": summary, "rows": rows_out}, f, ensure_ascii=False, indent=2)
    print(f"[POC评测] 报告 {args.out}")
    print(f"[POC评测] 结果 {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
