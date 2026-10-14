# -*- coding: utf-8 -*-
"""
merge_ai.py —— AI 安全专用语料合并（非 AI 相关一律舍弃）
=========================================================================
研究对象：AI 安全四大类风险
  ① AI基础设施与推理框架  ② 模型与数据层  ③ AI应用与智能体  ④ AI供应链与平台
渠道：CVE/NVD · 安全社区 · 厂商公告 · 安全博客 · 学术论文 · 模型仓库

输入：
  data/corpus.json               现有语料（记录 + 知识，按 AI 闸门筛选）
  data/nvd_full/*.jsonl          NVD 全量原始 CVE（本地 AI 过滤）
  data/ghsa_full.json            GHSA 全量公告
  data/gh_repos.json             GitHub 仓库收割
  data/cn/*.json                 中文社区文章
  data/extra_sources.json        旧扩展源
  $AI_RAW_DIR/arxiv/metadata.jsonl    AI 安全论文
  $AI_RAW_DIR/blogs/articles.jsonl    厂商公告 / 安全博客正文
  $AI_RAW_DIR/hf/models.jsonl         模型 / 数据集卡片

输出：覆写 data/corpus.json（records / knowledge / papers 均为 AI 安全范畴）
"""

import glob
import io
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetch_corpus as F      # noqa: E402
import extra_sources as X     # noqa: E402
import augment as AUG         # noqa: E402
from live import ai_gate      # noqa: E402 —— 统一的 AI 安全相关性闸门
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402


DATA = paths.DATA_DIR
CORPUS = os.path.join(DATA, "corpus.json")
BACKUP = os.path.join(DATA, "corpus_backup_pre_ai.json")
RAW = os.environ.get("AI_RAW_DIR") or os.path.join(DATA, "ai_sec_raw")

LOG = lambda *a: print("[merge-ai]", *a, flush=True)

_KEV = {}


def _init(kev):
    global _KEV
    _KEV = kev


def _build(cve):
    """NVD 原始 CVE → 富化记录；非 AI 返回 None"""
    try:
        rec = F.build_record(cve, _KEV, {}, [])
        ok, score, cat, reason, tags = F.classify(rec)
        if not ok:
            return None
        rec["ai_score"] = score
        rec["category"] = cat
        rec["category_reason"] = reason
        rec["risk_tags"] = tags
        rec["scope"] = "AI安全"
        return _slim(rec)
    except Exception:  # noqa: BLE001
        return None


def _slim(rec):
    rec["refs"] = rec.get("refs", [])[:6]
    rec["cpe"] = rec.get("cpe", [])[:8]
    rec["tags_raw"] = rec.get("tags_raw", [])[:10]
    if len(rec.get("desc", "")) > 1500:
        rec["desc"] = rec["desc"][:1500]
    for k in ("atlas", "atlas_evidence", "atlas_mitigations", "papers"):
        rec.setdefault(k, [])
    return rec


def _read_jsonl(fp):
    out = []
    if not os.path.isfile(fp):
        return out
    with open(fp, "r", encoding="utf-8") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def classify_knowledge(rec):
    """给知识条目补 AI 范畴的分类（按文本投票到四大类）"""
    text = " ".join([rec.get("title", ""), rec.get("desc", ""),
                     " ".join(rec.get("tags", []))])
    votes = Counter()
    for n, (cat, w) in F.AI_PRODUCTS.items():
        if len(n) >= 4 and n in text.lower():
            votes[cat] += w
    for kw, cat in (("prompt injection", "② 模型与数据层"), ("jailbreak", "② 模型与数据层"),
                    ("data poisoning", "② 模型与数据层"), ("model extraction", "② 模型与数据层"),
                    ("adversarial", "② 模型与数据层"), ("llm", "③ AI应用与智能体"),
                    ("agent", "③ AI应用与智能体"), ("rag", "③ AI应用与智能体"),
                    ("supply chain", "④ AI供应链与平台"), ("hugging face", "④ AI供应链与平台"),
                    ("inference", "① AI基础设施与推理框架"), ("serving", "① AI基础设施与推理框架")):
        if kw in text.lower():
            votes[cat] += 0.6
    if votes:
        return max(votes.items(), key=lambda x: x[1])[0]
    # 语料只保留 AI 安全，知识条目不得落到通用类；无 AI 组件/术语票时归入应用与智能体
    cat = rec.get("category")
    if isinstance(cat, str) and cat[:1] in ("①", "②", "③", "④"):
        return cat
    return "③ AI应用与智能体"


def main():
    t0 = time.time()
    if not os.path.isfile(BACKUP) and os.path.isfile(CORPUS):
        import shutil
        shutil.copy2(CORPUS, BACKUP)
        LOG(f"备份现有语料 → {BACKUP}")

    with open(CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    old_records = corpus.get("records", [])
    LOG(f"现有记录 {len(old_records)} 条（将按 AI 闸门筛选）")

    # ---------- 1. KEV ----------
    try:
        kev = F.fetch_kev()
    except Exception as e:  # noqa: BLE001
        LOG("KEV 失败，置空：", str(e)[:80])
        kev = {}

    # ---------- 2. 现有记录：AI 过滤 + 重分类 ----------
    records, seen = [], set()
    n_drop = 0
    for r in old_records:
        ok, score, cat, reason, tags = F.classify(r)
        if not ok:
            n_drop += 1
            continue
        r["ai_score"], r["category"], r["category_reason"] = score, cat, reason
        r["risk_tags"] = tags
        r["scope"] = "AI安全"
        records.append(_slim(r))
        seen.add(r["id"].upper())
    LOG(f"现有记录保留 {len(records)} 条（丢弃非 AI {n_drop} 条）")

    # ---------- 3. NVD：优先读增量抽取的 AI CVE（harvest_ai_raw.py nvd） ----------
    ai_cve_fp = os.path.join(RAW, "nvd", "ai_cve.jsonl")
    added, consumed = 0, 0
    if os.path.isfile(ai_cve_fp):
        for rec in _read_jsonl(ai_cve_fp):
            cid = (rec.get("id") or "").upper()
            if not cid or cid in seen:
                continue
            seen.add(cid)
            records.append(_slim(rec))
            added += 1
        LOG(f"NVD AI CVE（增量抽取文件）：新增 {added} 条")
    else:
        raw_files = sorted(glob.glob(os.path.join(DATA, "nvd_full", "*Q*.jsonl")))
        LOG(f"未找到 AI CVE 抽取文件，回退扫描 {len(raw_files)} 个 NVD 分片")

        def _iter_new():
            s = set()
            for fp in raw_files:
                with open(fp, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            c = json.loads(line)
                        except ValueError:
                            continue
                        cid = (c.get("id") or "").upper()
                        if not cid or cid in seen or cid in s:
                            continue
                        s.add(cid)
                        yield c

        BATCH = 20000
        batch, workers = [], min(6, os.cpu_count() or 4)
        try:                   # 性能档位：低配机器上进程池压到 2，避免内存抖动
            from envprofile import T
            workers = T.workers(workers)
        except Exception:
            pass
        ex = ProcessPoolExecutor(max_workers=workers, initializer=_init, initargs=(kev,))
        try:
            for c in _iter_new():
                batch.append(c)
                if len(batch) >= BATCH:
                    for rec in ex.map(_build, batch, chunksize=200):
                        if rec is not None:
                            records.append(rec)
                            added += 1
                    consumed += len(batch)
                    batch.clear()
                    LOG(f"  NVD 富化 {consumed} → AI 新增 {added}（{round(time.time()-t0)}s）")
            if batch:
                for rec in ex.map(_build, batch, chunksize=200):
                    if rec is not None:
                        records.append(rec)
                        added += 1
                consumed += len(batch)
        finally:
            ex.shutdown(wait=True)
        LOG(f"NVD 新增 AI 记录 {added} 条（扫描原始 {consumed} 条）")

    # ---------- 4. GHSA：AI 组件公告并回 + 独立公告入知识 ----------
    knowledge = []
    ghsa_fp = os.path.join(DATA, "ghsa_full.json")
    n_merge = 0
    if os.path.isfile(ghsa_fp):
        with open(ghsa_fp, "r", encoding="utf-8") as f:
            ghsa = json.load(f)
        norm = AUG.norm_product
        by_id = {r["id"].upper(): r for r in records}
        for cve, advisories in (ghsa.get("ghsa_by_cve") or {}).items():
            r = by_id.get(cve.upper())
            if not r:
                continue
            blob = " ".join([r.get("title", ""), r.get("desc", ""),
                             " ".join(r.get("products", [])), " ".join(r.get("osv_packages", []))])
            for a in advisories:
                blob += " " + " ".join(a.get("products", []))
            if not ai_gate(blob)[0] and r.get("scope") != "AI安全":
                continue
            for a in advisories:
                if "GitHub Advisory" not in r["sources"]:
                    r["sources"].append("GitHub Advisory")
                for u in a.get("advisory_links", []):
                    if u not in r["advisory_links"]:
                        r["advisory_links"].append(u)
                for pkg in a.get("products", []):
                    pn = norm(pkg)
                    if pn and pn not in r["osv_packages"]:
                        r["osv_packages"].append(pn)
                if a.get("desc"):
                    s = f"GitHub Advisory {a['id']}：{a['desc'][:300]}"
                    if s not in r.get("osv_summaries", []):
                        r.setdefault("osv_summaries", []).append(s)
                n_merge += 1
        for key in ("ghsa_standalone", "ghsa_projects"):
            for a in (ghsa.get(key) or []):
                blob = " ".join([a.get("title", ""), a.get("desc", ""),
                                 " ".join(a.get("products", []))])
                ok, why = ai_gate(blob)
                if not ok:
                    continue
                a = dict(a)
                a["category"] = classify_knowledge(a)
                a["scope"] = "AI安全"
                a["ai_reason"] = why
                knowledge.append(a)
        LOG(f"GHSA：并回 CVE {n_merge} 处，AI 独立公告 {len(knowledge)} 条")

    # ---------- 5. 论文（arXiv 元数据） ----------
    paper_fp = os.path.join(RAW, "arxiv", "metadata.jsonl")
    n_paper = 0
    for p in _read_jsonl(paper_fp):
        blob = p.get("title", "") + " " + p.get("summary", "")
        ok, why = ai_gate(blob)
        if not ok:
            continue
        rid = "ARXIV:" + p["id"].replace("/", "_")
        knowledge.append({
            "id": rid, "type": "paper", "kind": "AI 安全论文",
            "title": p["title"], "desc": p.get("summary", ""),
            "published": p.get("published", ""), "modified": p.get("updated", ""),
            "sources": ["arXiv"] + (p.get("cats") or [])[:2],
            "category": classify_knowledge({"title": p["title"], "desc": p.get("summary", ""),
                                            "tags": p.get("cats") or []}),
            "scope": "AI安全", "reason": f"AI 安全论文（{why}）",
            "tags": ["论文"] + (p.get("cats") or [])[:4],
            "authors": p.get("authors", [])[:8],
            "link": p.get("abs_url", ""), "pdf": p.get("pdf", ""),
            "refs": [], "cwe": [], "products": [], "vendors": [],
            "poc_links": [], "patch_links": [], "advisory_links": [],
            "osv_packages": [], "osv_summaries": [],
        })
        n_paper += 1
    LOG(f"AI 安全论文：{n_paper} 篇")

    # ---------- 6. 厂商公告 / 安全博客正文 ----------
    blog_fp = os.path.join(RAW, "blogs", "articles.jsonl")
    n_blog = 0
    for a in _read_jsonl(blog_fp):
        blob = a.get("title", "") + " " + (a.get("summary") or "")
        ok, why = ai_gate(blob)
        if not ok:
            continue
        rid = "LIVE:BLOG:" + str(a.get("guid", ""))[:80].replace("/", "_")
        rec = X._skeleton(
            rid=rid, rtype="article", kind=f"{a.get('source', '安全博客')} 文章",
            title=a.get("title", ""), desc=(a.get("summary") or a.get("title", ""))[:1500],
            published=(a.get("published") or "")[:10], sources=[a.get("source", "")],
            category=classify_knowledge({"title": a.get("title", ""), "desc": a.get("summary", "")}),
            reason=f"厂商公告/安全博客（{why}）", tags=["厂商公告" if "CISA" in a.get("source", "")
                                                     or "Micro" in a.get("source", "")
                                                     or "AWS" in a.get("source", "")
                                                     or "MSRC" in a.get("source", "") else "安全博客",
                                                     a.get("source", "")],
        )
        rec["scope"] = "AI安全"
        # ★ 原文链接必须带过来（2026-10-13 缺口修复）：此前这里不复制 a 的 link，
        #   knowledge 里 297 条 LIVE:BLOG 记录没有任何 URL 字段，检索卡片与详情
        #   都拿不到"原文"入口。harvest 落的 guid 通常就是文章 URL，但 id 化时
        #   `replace('/', '_')` 是有损变换，事后无法从 id 还原 —— 只能在落库时带上。
        rec["link"] = a.get("link") or a.get("url") or ""
        knowledge.append(rec)
        n_blog += 1
    LOG(f"厂商公告 / 安全博客：{n_blog} 篇")

    # ---------- 7. 模型 / 数据集卡片（hf-mirror） ----------
    hf_fp = os.path.join(RAW, "hf", "models.jsonl")
    n_hf = 0
    for m in _read_jsonl(hf_fp):
        blob = " ".join([m.get("id", ""), " ".join(m.get("tags") or []), m.get("card_text", "")[:1500]])
        ok, why = ai_gate(blob)
        if not ok:
            continue
        kind = "模型" if m.get("kind") == "models" else "数据集"
        rec = X._skeleton(
            rid="HF:" + m.get("id", ""), rtype="model",
            kind=f"HuggingFace {kind}",
            title=m.get("id", ""),
            desc=(m.get("card_text") or " ".join(m.get("tags") or []))[:1500],
            published=(m.get("created") or "")[:10],
            sources=["HuggingFace"], category="④ AI供应链与平台",
            reason=f"AI {kind}仓库条目（{why}）", tags=[kind, "模型仓库"] + (m.get("tags") or [])[:6],
        )
        rec["downloads"] = m.get("downloads")
        rec["likes"] = m.get("likes")
        rec["scope"] = "AI安全"
        knowledge.append(rec)
        n_hf += 1
    LOG(f"HuggingFace 模型/数据集：{n_hf} 条")

    # ---------- 8. GitHub 仓库（AI 过滤） ----------
    n_repo = 0
    repos = []
    rp = os.path.join(DATA, "gh_repos.json")
    if os.path.isfile(rp):
        with open(rp, "r", encoding="utf-8") as f:
            repos = json.load(f)
    else:
        # harvest_github.py 只在全部 owner 跑完才聚合出 gh_repos.json；
        # 中途终止时回退直接读 gh_repos_ai/owner_*.json 分片，避免 GitHub 数据整批丢失
        shard_dir = os.path.join(DATA, "gh_repos_ai")
        for fn in sorted(os.listdir(shard_dir)) if os.path.isdir(shard_dir) else []:
            if not (fn.startswith("owner_") and fn.endswith(".json")):
                continue
            try:
                with open(os.path.join(shard_dir, fn), "r", encoding="utf-8") as f:
                    repos.extend(json.load(f))
            except (ValueError, OSError):
                continue          # 正在写入 / 损坏的分片，跳过
        _seen_r, _uniq = set(), []
        for r in repos:
            rid = r.get("id") or r.get("title")
            if not rid or rid in _seen_r:
                continue
            _seen_r.add(rid)
            _uniq.append(r)
        repos = _uniq
        LOG(f"gh_repos.json 缺失，改读 gh_repos_ai 分片：{len(repos)} 条")
    for r in repos:
        blob = " ".join([r.get("title", ""), r.get("desc", ""), " ".join(r.get("tags", []))])
        ok, why = ai_gate(blob)
        if not ok:
            continue
        r = dict(r)
        r["category"] = classify_knowledge(r)
        r["scope"] = "AI安全"
        r["reason"] = f"AI 安全开源项目（{why}）"
        knowledge.append(r)
        n_repo += 1
    LOG(f"GitHub 仓库（AI 相关）：{n_repo} / {len(repos)}")

    # ---------- 9. 中文社区文章（AI 过滤） ----------
    n_cn = {}
    for name in ("csdn", "anquanke", "xz"):
        fp = os.path.join(DATA, "cn", name + ".json")
        if not os.path.isfile(fp):
            continue
        with open(fp, "r", encoding="utf-8") as f:
            arr = json.load(f)
        keep = 0
        for a in arr:
            blob = " ".join([a.get("title", ""), a.get("desc", ""), " ".join(a.get("tags", []))])
            ok, why = ai_gate(blob)
            if not ok:
                continue
            a = dict(a)
            a["category"] = classify_knowledge(a)
            a["scope"] = "AI安全"
            a["reason"] = f"中文安全社区（{why}）"
            knowledge.append(a)
            keep += 1
        n_cn[name] = f"{keep}/{len(arr)}"
    LOG(f"中文社区（AI 相关）：{n_cn}")

    # ---------- 10. 旧扩展源（repo/article，AI 过滤） ----------
    xs = os.path.join(DATA, "extra_sources.json")
    n_old = 0
    if os.path.isfile(xs):
        with open(xs, "r", encoding="utf-8") as f:
            old = json.load(f)
        for k in ("repos", "articles"):
            for a in (old.get(k) or []):
                blob = " ".join([a.get("title", ""), a.get("desc", ""), " ".join(a.get("tags", []))])
                ok, why = ai_gate(blob)
                if not ok:
                    continue
                a = dict(a)
                a["category"] = classify_knowledge(a)
                a["scope"] = "AI安全"
                knowledge.append(a)
                n_old += 1
    LOG(f"旧扩展源（AI 相关）：{n_old}")

    # ---------- 11. ATLAS 知识（AI 域战术/缓解） ----------
    n_atlas = 0
    try:
        from atlas import AtlasKB
        kb = AtlasKB()
        atlas_k = kb.to_records()
        for a in atlas_k:
            a["scope"] = "AI安全"
            a.setdefault("category", "② 模型与数据层")
        knowledge += atlas_k
        corpus["atlas"] = {
            "version": kb.version,
            "tactics": [{"id": k, "name": v} for k, v in kb.tactics.items()],
            "technique_count": len(kb.tech),
            "mitigation_count": len(kb.mitigations),
            "case_study_count": len(kb.case_studies),
        }
        n_atlas = len(atlas_k)
    except Exception as e:  # noqa: BLE001
        LOG("ATLAS 不可用：", str(e)[:100])
    LOG(f"ATLAS 知识条目：{n_atlas}")

    # ---------- 12. 去重 + 落盘 ----------
    dedup, seen_k = [], set()
    for k in knowledge:
        rid = k.get("id")
        if not rid or rid in seen_k:
            continue
        seen_k.add(rid)
        dedup.append(k)
    knowledge = dedup

    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    knowledge.sort(key=lambda r: r.get("published", ""), reverse=True)
    corpus["records"] = records
    corpus["knowledge"] = knowledge
    corpus["papers"] = []          # 论文已作为知识条目（type=paper）统一检索
    corpus["meta"].update({
        "merged_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "focus": "AI 安全（四大类风险）· 非 AI 已舍弃",
        "records": len(records), "knowledge": len(knowledge),
        "dropped_non_ai": n_drop,
        "nvd_ai_added": added,
        "ghsa_merged": n_merge,
        "sources": {"arxiv_papers": n_paper, "blogs": n_blog, "hf": n_hf,
                    "repos": n_repo, "cn": n_cn, "atlas": n_atlas},
    })
    tmp = CORPUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CORPUS)
    ic = CORPUS + ".idxcache"
    if os.path.isfile(ic):
        os.remove(ic)
    LOG(f"已写入 {CORPUS}（{os.path.getsize(CORPUS)/1024/1024:.1f} MB）"
        f" 记录 {len(records)} + 知识 {len(knowledge)} = {len(records)+len(knowledge)}")
    print("分类分布:", dict(Counter(r.get("category") for r in records).most_common()))
    print("知识分类:", dict(Counter(k.get("category") for k in knowledge).most_common()))
    print(f"总耗时 {round(time.time()-t0)}s")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
