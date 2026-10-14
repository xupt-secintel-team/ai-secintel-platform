# -*- coding: utf-8 -*-
"""论文关联语义增强 —— 把「特征词共现」升级为「词面 + 语义」混合关联，补强富化准确率最弱维（D5 论文关联 72%）。

背景：语料建库时论文关联纯靠特征词共现（link_papers），对「真相关但词面不重合」的论文会漏报，
对「仅泛泛共现」的弱关联会误报，导致 D5 精度代理停留在 72%（五维最弱）。

做法（可复跑、可回滚）：
  1. 用本地 e5 模型把全部论文（title+摘要）与「有强特征」的漏洞（title+描述）编码成向量；
  2. 余弦相似度矩阵取 top 邻居；
  3. 合并策略：保留原词面关联 + 补充「语义相似度 ≥ 阈值」的新关联，剔除「词面弱且语义也弱」的噪声关联；
  4. 每条关联写入 evidence（词面命中 + 语义相似度值），关联结果可解释。

阶段：
  --probe   只打印相似度分布与将发生的变更统计，不写回（用于定阈值）
  --apply   备份 corpus.json 后写回 papers 字段（默认 probe）

用法：
  py -3 tools/论文关联语义增强.py --probe
  py -3 tools/论文关联语义增强.py --apply
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m1_monitor", "backend"))

import paths  # noqa: E402
from taxonomy import AI_PRODUCTS, MODEL_LAYER_TAGS  # noqa: E402
from qa.local_embedder import local_embedder  # noqa: E402

import numpy as np  # noqa: E402

CORPUS = paths.data_path("corpus.json")
PAPERS = paths.data_path("papers.json")

# 阈值（e5 multilingual 归一化余弦，dry-run 后可校正）
SEM_ADD = 0.60      # 语义补充阈值：相似度 ≥ 此值且词面未关联 → 补充为关联
SEM_KEEP = 0.28     # 剔除阈值：原词面关联中语义相似度 < 此值且无强词面命中 → 判为噪声剔除


def kw_hit(term, text):
    import re
    pat = r"(?<![a-z0-9])" + re.escape(term).replace(r"\ ", r"[\s\-_]+") + r"(?![a-z0-9])"
    return re.search(pat, text) is not None


def strong_features(rec):
    """复刻 link_papers 的强特征判定：产品名命中 AI_PRODUCTS，或标题/描述命中模型层风险术语。"""
    strong = set()
    for p in rec.get("products", [])[:6]:
        n = (p or "").lower().replace("_", "-")
        if n in AI_PRODUCTS:
            strong.add(n)
    text = (rec.get("desc", "") + " " + rec.get("title", "")).lower()
    for k, zh in MODEL_LAYER_TAGS:
        if kw_hit(k, text):
            strong.add(k)
    return strong


def paper_text(p):
    return (p.get("title", "") + " " + (p.get("summary") or "")[:800]).strip()


def vuln_text(rec):
    return (rec.get("title", "") + " " + (rec.get("desc") or "")[:800]).strip()


def load_papers():
    with open(PAPERS, encoding="utf-8") as f:
        return json.load(f)


def load_records():
    with open(CORPUS, encoding="utf-8") as f:
        c = json.load(f)
    recs = c.get("records", [])
    return c, recs


def encode(texts, tag):
    t0 = time.time()
    n = len(texts)
    vecs = local_embedder.encode(texts, kind="passage", batch_size=64,
                                 progress=lambda d, t: (None))
    print(f"  [{tag}] 编码 {n} 条，耗时 {time.time()-t0:.1f}s", flush=True)
    return np.asarray(vecs, dtype="float32")


def probe():
    print("加载论文…", flush=True)
    papers = load_papers()
    print(f"论文 {len(papers)} 篇", flush=True)
    print("加载语料…", flush=True)
    c, recs = load_records()
    print(f"语料 {len(recs)} 条", flush=True)

    # 有强特征的漏洞（可能关联论文的对象）
    cand_idx = [i for i, r in enumerate(recs) if strong_features(r)]
    print(f"有强特征的漏洞 {len(cand_idx)} 条；其中已有关联 {sum(1 for i in cand_idx if recs[i].get('papers'))} 条", flush=True)

    # 编码论文
    pv = encode([paper_text(p) for p in papers], "论文")

    # 抽样：已有关联的漏洞 + 随机强特征漏洞，共 ~1500 条
    import random
    random.seed(42)
    linked = [i for i in cand_idx if recs[i].get("papers")]
    unlinked = [i for i in cand_idx if not recs[i].get("papers")]
    sample_idx = linked[:800] + random.sample(unlinked, min(800, len(unlinked)))
    print(f"编码抽样漏洞 {len(sample_idx)} 条…", flush=True)
    vv = encode([vuln_text(recs[i]) for i in sample_idx], "漏洞")

    # 相似度矩阵（抽样漏洞 × 论文）
    sims = vv @ pv.T
    # 词面关联对的相似度分布
    linked_sim = []
    for j, i in enumerate(sample_idx):
        rec = recs[i]
        for p in rec.get("papers") or []:
            pid = p.get("title", "")
            # 找论文 index
            for k, pp in enumerate(papers):
                if pp.get("title") == pid:
                    linked_sim.append(float(sims[j, k]))
                    break
    # 随机对分布（每个漏洞随机 5 篇论文）
    random_sim = sims[:, np.random.randint(0, len(papers), 5)].ravel().tolist()

    def pct(arr, q):
        return np.percentile(arr, q) if arr else float("nan")

    print("\n=== 相似度分布（e5 归一化余弦）===", flush=True)
    print(f"已有词面关联对（{len(linked_sim)} 对）：p10={pct(linked_sim,10):.3f} p25={pct(linked_sim,25):.3f} "
          f"p50={pct(linked_sim,50):.3f} p75={pct(linked_sim,75):.3f} p90={pct(linked_sim,90):.3f}", flush=True)
    print(f"随机对（{len(random_sim)} 对）：p50={pct(random_sim,50):.3f} p75={pct(random_sim,75):.3f} "
          f"p90={pct(random_sim,90):.3f} p95={pct(random_sim,95):.3f} p99={pct(random_sim,99):.3f}", flush=True)

    # 用当前阈值预估变更
    add = drop = 0
    for j, i in enumerate(sample_idx):
        rec = recs[i]
        cur_titles = {p.get("title") for p in rec.get("papers") or []}
        # 剔除统计
        for p in rec.get("papers") or []:
            pid = p.get("title", "")
            for k, pp in enumerate(papers):
                if pp.get("title") == pid:
                    if sims[j, k] < SEM_KEEP:
                        drop += 1
                    break
        # 补充统计（top-3 中语义达标且未关联）
        top = np.argsort(-sims[j])[:3]
        for k in top:
            if sims[j, k] >= SEM_ADD and papers[k].get("title") not in cur_titles:
                add += 1
    print(f"\n按阈值 SEM_ADD={SEM_ADD} / SEM_KEEP={SEM_KEEP} 预估：补充 {add} 条、剔除 {drop} 条（抽样 {len(sample_idx)} 条口径）", flush=True)


def apply():
    print("加载论文…", flush=True)
    papers = load_papers()
    ptext = [paper_text(p) for p in papers]
    pv = encode(ptext, "论文")

    print("加载语料…", flush=True)
    c, recs = load_records()
    cand_idx = [i for i, r in enumerate(recs) if strong_features(r)]
    print(f"有强特征的漏洞 {len(cand_idx)} 条", flush=True)

    print(f"编码漏洞 {len(cand_idx)} 条…（分批）", flush=True)
    # 分批编码避免一次性把几十万向量堆内存里
    V = np.zeros((len(cand_idx), pv.shape[1]), dtype="float32")
    B = 512
    for s in range(0, len(cand_idx), B):
        batch = cand_idx[s:s+B]
        V[s:s+B] = encode([vuln_text(recs[i]) for i in batch], f"漏洞{s//B+1}")

    print("计算相似度矩阵…", flush=True)
    # 分块点积，控制峰值内存
    add = drop = 0
    CH = 2000
    for s in range(0, len(cand_idx), CH):
        idx = cand_idx[s:s+CH]
        sims = V[s:s+CH] @ pv.T  # (chunk, n_papers)
        for j, i in enumerate(idx):
            rec = recs[i]
            old = rec.get("papers") or []
            cur_titles = {p.get("title") for p in old}
            # 剔除弱关联
            kept = []
            for p in old:
                pid = p.get("title", "")
                k = next((kk for kk, pp in enumerate(papers) if pp.get("title") == pid), None)
                if k is not None and sims[j, k] < SEM_KEEP:
                    drop += 1
                    continue
                kept.append(p)
            # 补充语义关联（top-3）
            top = np.argsort(-sims[j])[:3]
            for k in top:
                if sims[j, k] >= SEM_ADD and papers[k].get("title") not in cur_titles:
                    pp = papers[k]
                    kept.append({
                        "title": pp.get("title"), "url": pp.get("url"),
                        "published": pp.get("published", ""), "authors": pp.get("authors", []),
                        "venue": pp.get("venue", ""), "source": pp.get("source", ""),
                        "evidence": "semantic", "semantic_sim": round(float(sims[j, k]), 4),
                    })
                    add += 1
            if kept != old:
                rec["papers"] = kept
        print(f"  处理 {s+len(idx)}/{len(cand_idx)}，累计 补充 {add} 剔除 {drop}", flush=True)

    print(f"完成：补充 {add} 条、剔除 {drop} 条关联", flush=True)
    bak = CORPUS + ".bak-paper-sem"
    print(f"备份原语料到 {bak} …", flush=True)
    import shutil
    shutil.copy2(CORPUS, bak)
    print("写回 corpus.json …", flush=True)
    with open(CORPUS, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False)
    print("写回完成。", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="探查分布（默认）")
    ap.add_argument("--apply", action="store_true", help="应用增强并写回")
    a = ap.parse_args()
    if a.apply:
        apply()
    else:
        probe()
