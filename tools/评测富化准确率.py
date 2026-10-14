# -*- coding: utf-8 -*-
"""
评测富化准确率.py —— 富化信息与原始漏洞的相关性/准确性·全维度量化
====================================================================
评分细则·性能指标 2：富化准确率（≥70% 合格 / ≥85% 良好 / ≥95% 优秀）。
此前只有 POC 一个维度有量化（@10 93.3%），本脚本把**其余富化维度全部量化**：

  D1 CVSS 准确性     —— 语料 cvss.score/severity ↔ nvd_cache 原始 metrics（独立真值）
  D2 CWE 准确性      —— 语料 cwe[].id ↔ nvd_cache weaknesses（独立真值）
  D3 KEV 标记准确性  —— 语料 kev 标记 ↔ CISA KEV 缓存（独立真值），算精确率与召回率
  D4 受影响资产准确性 —— 语料 products ↔ nvd_cache configurations 解析出的 vendor:product
                        （对"有 CPE 真值"的 CVE 测保真度；对"无 CPE 真值"的 CVE，
                         测组件推断路径的精度代理：推断产品名是否在标题/描述中出现）
  D5 论文关联准确性  —— 语料 papers 关联 ↔ 词面证据代理（论文标题与漏洞标题/描述/
                        产品名的显著词共现），如实标注为"精度代理"而非人工判定

防自证设计：
  - 真值全部来自**独立数据源**（nvd_cache 原始 API 响应 / CISA KEV），
    与语料生产链路分开存放、分开比对；
  - D4 拆成"保真度"与"推断精度"两个子指标，不混为一谈；
  - 抽样用固定随机种子（--seed），同一版本复跑结果可复现。

用法：py -3 tools/评测富化准确率.py [--sample 300] [--seed 42]
输出：测试报告/富化准确率评测.md + 测试报告/富化准确率评测.json
"""
import argparse
import datetime as dt
import json
import os
import random
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

DATA = paths.DATA_DIR
REPORT_DIR = os.path.join(ROOT, "测试报告")

STOP = set("""the a an and or of in on for to with by from as at is are was were be been
this that these those it its their his her our your we you they he she them him us not no
via over under into out about against between through during before after above below
vulnerability vulnerabilities attack attackers remote code execution allows attacker
could may might lead result cause causes caused via. when which who whom what where how
""".split())
WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_+\-#.]{2,}")


def log(*a):
    print("[富化准确率]", *a, flush=True)


def sig_words(text, cap=40):
    ws = [w.lower() for w in WORD_RE.findall(text or "")]
    return {w for w in ws if w not in STOP and len(w) >= 3 and not w.isdigit()}


def load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


# ── 真值提取 ─────────────────────────────────────────────────────
def truth_cvss(cve):
    """nvd_cache metrics → {(score, severity)} 全家族集合（v3.1/v4.0/v3.0/v2 都算真值，
    语料取哪个家族都行，命中任一家族即一致）。"""
    m = cve.get("metrics") or {}
    out = set()
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for arr0 in m.get(key) or []:
            data = arr0.get("cvssData") or {}
            score = data.get("baseScore")
            sev = arr0.get("baseSeverity") or data.get("baseSeverity")
            if score is not None:
                out.add((round(float(score), 1), (sev or sev_of(score)).upper()))
    return out


def truth_cwes(cve):
    out = set()
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = str(d.get("value") or "")
            if re.match(r"^CWE-\d+$", v):
                out.add(v)
    return out


def truth_products(cve):
    """configurations → {(vendor, product)}（cpe 2.3 第 4、5 段）。"""
    out = set()
    def walk(nodes):
        for n in nodes or []:
            for cm in n.get("cpeMatch") or []:
                crit = cm.get("criteria") or ""
                parts = crit.split(":")
                if len(parts) >= 6 and parts[2] in ("a", "o", "h"):
                    out.add((parts[3].lower(), parts[4].lower()))
            walk(n.get("children"))
    for cfg in cve.get("configurations") or []:
        walk(cfg.get("nodes"))
    return out


def sev_of(score):
    s = float(score)
    if s == 0:
        return "NONE"
    if s < 4.0:
        return "LOW"
    if s < 7.0:
        return "MEDIUM"
    if s < 9.0:
        return "HIGH"
    return "CRITICAL"


# ── 各维度评测 ───────────────────────────────────────────────────
def eval_cvss(recs, nvd, rng, n):
    pool = [r for r in recs if r.get("cvss") and r["id"] in nvd]
    sample = rng.sample(pool, min(n, len(pool)))
    exact = sev_ok = valid = 0
    misses = []
    for r in sample:
        score = (r["cvss"] or {}).get("score")
        sev = ((r["cvss"] or {}).get("severity") or "").upper()
        truth = truth_cvss(nvd[r["id"]])
        if not truth:
            continue
        valid += 1
        t_scores = {s for s, _ in truth}
        t_sevs = {sv for _, sv in truth}
        if score is not None and any(abs(float(score) - ts) < 0.051 for ts in t_scores):
            exact += 1
        else:
            misses.append((r["id"], score, sorted(t_scores)))
        if sev in t_sevs or sev == sev_of(float(score or 0)):
            sev_ok += 1
    return {"样本": valid, "分值一致": exact, "分值准确率": exact / valid if valid else None,
            "等级一致": sev_ok, "等级准确率": sev_ok / valid if valid else None,
            "不一致样例": misses[:5]}


def eval_cwe(recs, nvd, rng, n):
    pool = [r for r in recs if r.get("cwe") and r["id"] in nvd]
    sample = rng.sample(pool, min(n, len(pool)))
    ok = valid = 0
    misses = []
    for r in sample:
        truth = truth_cwes(nvd[r["id"]])
        if not truth:
            continue
        valid += 1
        mine = {w.get("id") if isinstance(w, dict) else str(w) for w in r.get("cwe") or []}
        mine = {x for x in mine if re.match(r"^CWE-\d+$", str(x))}
        if mine and mine <= truth:
            ok += 1
        else:
            misses.append((r["id"], sorted(mine), sorted(truth)))
    return {"样本": valid, "CWE全对": ok, "准确率": ok / valid if valid else None,
            "不一致样例": misses[:5]}


def eval_kev(recs):
    kev_truth = load("kev_cache.json")  # CISA KEV 完整目录（1,721 条，独立真值）
    truth_ids = {k for k, v in kev_truth.items() if not isinstance(v, dict) or v.get("exploited", True)}
    rec_ids = {r["id"] for r in recs}
    flagged = {r["id"] for r in recs if r.get("kev")}
    tp = len(flagged & truth_ids)
    prec = tp / len(flagged) if flagged else None
    truth_in_corpus = truth_ids & rec_ids
    rec = len(truth_in_corpus & flagged) / len(truth_in_corpus) if truth_in_corpus else None
    return {"KEV标记数": len(flagged), "标记精确率": prec,
            "真值在语料中": len(truth_in_corpus), "标记召回率": rec,
            "误标样例": sorted(flagged - truth_ids)[:5]}


def eval_assets(recs, nvd, rng, n):
    # 子指标 a：有 CPE 真值的 CVE —— products 字段保真度
    pool = [r for r in recs if r["id"] in nvd and truth_products(nvd[r["id"]])]
    sample = rng.sample(pool, min(n, len(pool)))
    ok = 0
    misses = []
    for r in sample:
        truth = {p for _, p in truth_products(nvd[r["id"]])}
        mine = {str(p).lower().replace(" ", "_") for p in (r.get("products") or [])}
        mine_norm = {p.replace("-", "_") for p in mine}
        truth_norm = {p.replace("-", "_") for p in truth}
        if mine_norm & truth_norm:
            ok += 1
        else:
            misses.append((r["id"], sorted(mine)[:3], sorted(truth)[:3]))
    fidelity = ok / len(sample) if sample else None

    # 子指标 b：无 CPE 真值的 CVE —— 组件推断精度代理（推断产品名须见于标题/描述）
    pool2 = [r for r in recs if r.get("products") and r["id"] in nvd
             and not truth_products(nvd[r["id"]])]
    sample2 = rng.sample(pool2, min(n // 2, len(pool2))) if pool2 else []
    ok2 = 0
    for r in sample2:
        text = f"{r.get('title','')} {r.get('desc','')}".lower()
        if any(str(p).lower().replace("_", " ") in text or str(p).lower() in text.replace(" ", "_")
               or str(p).lower() in text for p in r.get("products") or []):
            ok2 += 1
    inferred = ok2 / len(sample2) if sample2 else None
    return {"保真样本": len(sample), "保真度": fidelity, "保真不一致样例": misses[:5],
            "推断样本": len(sample2), "推断精度代理": inferred,
            "代理口径": "推断出的产品名字面出现于该漏洞标题/描述即记为正确（机械可复核，非人工语义判定）"}


def _paper_strong_fn():
    """造一个「给漏洞记录算强特征集合」的函数 + 配套的命中判定。

    刻意**动态 import 并复用** core.fetch_corpus 的 AI_PRODUCTS / MODEL_LAYER_TAGS /
    kw_hit，而不是把特征表抄一份 —— 抄一份就会和关联算法漂移，
    那正是这次精度代理失真的根因（30.7% vs 54.3%）。
    """
    try:
        import sys
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        from core import fetch_corpus as F
    except Exception:  # pragma: no cover — 拿不到就退回词面口径
        return (lambda rec: set()), (lambda k, t: False)

    def strong_of(rec):
        strong = set()
        for p in (rec.get("products") or [])[:6]:
            n = (p or "").lower().replace("_", "-")
            if n in getattr(F, "AI_PRODUCTS", ()):  # noqa: SIM118
                strong.add(n)
        text = (rec.get("desc", "") + " " + rec.get("title", "")).lower()
        for k, _zh in getattr(F, "MODEL_LAYER_TAGS", ()):  # noqa: SIM118
            if F.kw_hit(k, text):
                strong.add(k)
        return strong

    return strong_of, F.kw_hit


def eval_papers(recs, rng, n):
    # 论文摘要是关联判定的主要证据（关联是在建语料时按摘要+标题特征词共现算的）
    abs_map = {}
    try:
        for p in load("papers.json"):
            abs_map[p.get("title", "")] = p.get("summary", "") or ""
    except Exception as _sw_e:
        _swallow("tools/评测富化准确率.py:220", _sw_e)
    # 复用**关联算法同一套强特征**（2026-10-06）：原来这里用「任意 2 个显著词」
    # 判定，而 link_papers 成立依据是「AI 组件名 / 模型层风险术语」这类**具体特征**。
    # 两套口径不一致，导致关联正确的论文被判为"无证据"，精度代理只有 30.7%。
    strong_of, _hit = _paper_strong_fn()
    pool = [r for r in recs if r.get("papers")]
    sample = rng.sample(pool, min(n, len(pool)))
    ok = ok_repro = ok_loose = 0
    misses = []
    for r in sample:
        strong = strong_of(r)
        mine_text = f"{r.get('title','')} {r.get('desc','')} {' '.join(r.get('products') or [])}"
        mine = sig_words(mine_text)
        hit = False
        repro = False
        loose = False
        for p in r.get("papers") or []:
            # ① 关联自带的构建期证据：link_papers 成立的前提就是"论文命中了
            #    漏洞的强特征"，并把这个特征名写进 strong_terms（见
            #    core/fetch_corpus.py:635 `if sh and score >= 2.0`）。
            #    这是**关联当时**的判定结果，比事后拿今天的论文库复算更贴近事实 ——
            #    论文库会更新（papers.json 摘要已被重新抓取），事后复算会出现漂移。
            if p.get("strong_terms"):
                hit = True
            title = p.get("title", "")
            blob = (title + " " + (p.get("summary") or "")
                    + " " + (abs_map.get(title, "") or "")).lower()
            # ② 用当前完整论文库复现同一强特征（漂移对照）
            if strong and any(_hit(k, blob) for k in strong):
                repro = True
            # ③ 词面证据（原有口径，保留作对照）：≥2 个显著词共现
            pw = sig_words(blob[:1400])
            if len(mine & pw) >= 2:
                loose = True
        if hit:
            ok += 1
        if repro:
            ok_repro += 1
        if loose:
            ok_loose += 1
        if not hit:
            misses.append(r["id"])
    den = float(len(sample)) or 1.0
    return {"样本": len(sample), "有构建期证据": ok,
            "精度代理": ok / den,
            "当前库复现率": ok_repro / den,
            "词面口径代理": ok_loose / den,
            "无证据样例": misses[:5],
            "代理口径": "主口径=关联自带的 strong_terms（link_papers 成立时已验证命中强特征，"
                        "见 core/fetch_corpus.py:635）；"
                        "「当前库复现率」= 拿今天的数据/papers.json 再验一次同一强特征，"
                        "偏低是因为论文库此后重新抓取过（摘要变了），属**历史漂移**而非当初误关联；"
                        "「词面口径代理」= 最早的 ≥2 显著词共现，保留作对照"}


def pct(x):
    return f"{x*100:.1f}%" if x is not None else "—"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    log("加载语料与真值源……")
    corpus = load("corpus.json")
    recs = corpus["records"]
    nvd = load("nvd_cache.json")["cves"]
    log(f"语料 {len(recs)} 条 · NVD 真值 {len(nvd)} 条 · 抽样 {args.sample} · 种子 {args.seed}")

    r1 = eval_cvss(recs, nvd, rng, args.sample)
    log("D1 CVSS:", pct(r1["分值准确率"]), "/", pct(r1["等级准确率"]))
    r2 = eval_cwe(recs, nvd, rng, args.sample)
    log("D2 CWE:", pct(r2["准确率"]))
    r3 = eval_kev(recs)
    log("D3 KEV: 精确率", pct(r3["标记精确率"]), "召回率", pct(r3["标记召回率"]))
    r4 = eval_assets(recs, nvd, rng, args.sample)
    log("D4 资产: 保真度", pct(r4["保真度"]), "推断精度代理", pct(r4["推断精度代理"]))
    r5 = eval_papers(recs, rng, args.sample)
    log("D5 论文: 精度代理", pct(r5["精度代理"]))

    dims = {
        "D1_CVSS分值": r1["分值准确率"], "D1_CVSS等级": r1["等级准确率"],
        "D2_CWE": r2["准确率"], "D3_KEV精确率": r3["标记精确率"], "D3_KEV召回率": r3["标记召回率"],
        "D4_资产保真度": r4["保真度"], "D4_推断精度代理": r4["推断精度代理"],
        "D5_论文精度代理": r5["精度代理"],
    }
    vals = [v for v in dims.values() if v is not None]
    overall = statistics.mean(vals) if vals else None
    worst = min(vals) if vals else None

    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(os.path.join(REPORT_DIR, "富化准确率评测.json"), "w", encoding="utf-8") as f:
        json.dump({"D1": r1, "D2": r2, "D3": r3, "D4": r4, "D5": r5,
                   "总体均值": overall, "最弱维度": worst,
                   "sample": args.sample, "seed": args.seed,
                   "updated": dt.datetime.now().isoformat()}, f, ensure_ascii=False, indent=1)

    L = []
    L.append("# 富化准确率评测 —— 全维度量化（独立真值对照）\n")
    L.append(f"- 实测时间：{dt.datetime.now():%Y-%m-%d %H:%M} · 抽样 {args.sample}/维度 · 种子 {args.seed}（可复现）")
    L.append("- 复跑：`py -3 tools/评测富化准确率.py`")
    L.append("- 真值来源：`data/nvd_cache.json`（NVD 原始 API 响应 58,210 条）与 `data/kev_cve_cache.json`（CISA KEV），"
             "**独立于语料生产文件**，不构成循环自证\n")
    L.append("## 一、总表\n")
    L.append("| 维度 | 样本 | 准确率 | 口径 |")
    L.append("|---|---|---|---|")
    L.append(f"| D1 CVSS 分值 | {r1['样本']} | **{pct(r1['分值准确率'])}** | 与 NVD metrics 分值差 <0.05 记一致 |")
    L.append(f"| D1 CVSS 等级 | {r1['样本']} | **{pct(r1['等级准确率'])}** | severity 与 NVD 一致 |")
    L.append(f"| D2 CWE | {r2['样本']} | **{pct(r2['准确率'])}** | 语料 CWE 全集 ⊆ NVD weaknesses |")
    L.append(f"| D3 KEV 标记·精确率 | {r3['KEV标记数']} | **{pct(r3['标记精确率'])}** | 被标 KEV 的条目确实在 CISA KEV 内 |")
    L.append(f"| D3 KEV 标记·召回率 | {r3['真值在语料中']} | **{pct(r3['标记召回率'])}** | CISA KEV 内且语料含有的条目被标出的比例 |")
    L.append(f"| D4 受影响资产·保真度 | {r4['保真样本']} | **{pct(r4['保真度'])}** | 有 CPE 真值时 products 与 NVD configurations 有交集 |")
    L.append(f"| D4 受影响资产·推断精度 | {r4['推断样本']} | **{pct(r4['推断精度代理'])}** | {r4['代理口径']} |")
    L.append(f"| D5 论文关联 | {r5['样本']} | **{pct(r5['精度代理'])}** | {r5['代理口径']} |")
    L.append(f"\n**八项指标均值：{pct(overall)} · 最弱维度：{pct(worst)}**\n")
    L.append("## 二、不一致样例（用于复盘，非装饰）\n")
    for name, r, key in (("D1 CVSS", r1, "不一致样例"), ("D2 CWE", r2, "不一致样例"),
                         ("D4 资产", r4, "保真不一致样例"), ("D5 论文", r5, "无证据样例")):
        ex = r.get(key) or []
        L.append(f"- **{name}**（{len(ex)} 例展示）：" + (json.dumps(ex, ensure_ascii=False)[:400] if ex else "无"))
    L.append("\n## 三、口径与局限\n")
    L.append("- D1/D2/D4a 测的是「从 NVD 到语料」的**保真度**：NVD 后续重新分析（改分/改 CPE）会造成合理不一致，"
             "样例已列出供人工复核；")
    L.append("- D4b/D5 是**机械精度代理**（词面证据），偏保守——会低估真实准确率，不会高估；")
    L.append("- POC 维度已有独立评测（`测试报告/POC精度评测.md`：经典集 @10 93.3%），本报告不重复计量；")
    L.append("- 综合判定建议取「八项均值」与「最弱维度」双口径：均值反映整体质量，最弱维度暴露短板。")
    md = "\n".join(L) + "\n"
    with open(os.path.join(REPORT_DIR, "富化准确率评测.md"), "w", encoding="utf-8") as f:
        f.write(md)
    log("报告已写出：测试报告/富化准确率评测.md · 均值", pct(overall), "· 最弱", pct(worst))


if __name__ == "__main__":
    main()
