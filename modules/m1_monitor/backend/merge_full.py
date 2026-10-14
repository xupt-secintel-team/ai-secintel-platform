# -*- coding: utf-8 -*-
"""
merge_full.py —— 全量语料合并（20 万级）
================================================
输入：
  data/corpus.json            现有语料（1.6 万条富化记录，含 ATLAS/论文关联，优先保留）
  data/nvd_full/*.jsonl       NVD 全量收割的原始 CVE（harvest_nvd.py）
  data/ghsa_full.json         GHSA 全量（by_cve / standalone / projects）
  data/gh_repos.json          ecosyste.ms 收割的 GitHub 仓库条目
  data/cn/*.json              中文社区文章（CSDN/安全客/先知）
  data/extra_sources.json     旧扩展源（小量，去重后并入）

策略：
  · 已有 CVE 记录（富化程度高）一律保留；NVD 全量仅补充缺失 CVE
  · 新记录走 build_record 完整富化（分类/CVSS/CWE/CPE/修复建议），并做瘦身
    （refs≤6 / cpe≤8 / desc≤1500 / tags_raw≤10）以控制语料体积与引擎内存
  · GHSA 按 CVE 并回记录；独立 GHSA / 受影响项目 / 仓库 / 中文文章 / 论文 → 知识条目
  · KEV 全量重放（含新增在野利用）；组件推断经 AC 自动机加速；ATLAS 仅映射 AI 域

输出：覆写 data/corpus.json（先备份为 corpus_backup_full.json）
"""

import glob
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_corpus as F  # noqa: E402
import extra_sources as X  # noqa: E402
import augment as AUG  # noqa: E402  （复用 EXTRA_CWE / norm_product / infer 组件名表）
# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
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


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = paths.DATA_DIR
CORPUS = os.path.join(DATA, "corpus.json")
BACKUP = os.path.join(DATA, "corpus_backup_full.json")

# --------------------------------------------------------------------------
# 组件推断用的 AC 自动机（对 29 万条记录逐条跑 200 个正则不可行；
# AC 一次扫描 ~0.1ms，候选再做人造词边界复核，语义与 infer_products 一致）
# --------------------------------------------------------------------------
_AC = None
try:
    import ahocorasick
    _AC = ahocorasick.Automaton()
    for _n in AUG.INFER_NAMES:
        _AC.add_word(_n, _n)
    _AC.make_automaton()
except ImportError as _sw_e:
    _swallow("modules/m1_monitor/backend/merge_full.py:61", _sw_e)


def infer_products_fast(rec):
    blob = (rec.get("desc", "") + " " + rec.get("title", "")).lower()
    if _AC is None:
        return AUG.infer_products(rec)
    cands = {v for _, v in _AC.iter(blob)}
    found = []
    for n in cands:
        pat = r"(?<![a-z0-9])" + re.escape(n).replace(r"\ ", r"[\s\-_]") + r"(?![a-z0-9])"
        if re.search(pat, blob):
            found.append(n)
    out = []
    for n in sorted(found, key=len):
        if not any(n != o and (n.startswith(o + "-") or n.endswith("-" + o)) for o in out):
            out.append(n)
    return out[:6]


def slim_record(rec):
    """瘦身：控制 corpus.json 体积与引擎内存（refs/cpe/token 是最大头）"""
    rec["refs"] = rec.get("refs", [])[:6]
    rec["cpe"] = rec.get("cpe", [])[:8]
    rec["tags_raw"] = rec.get("tags_raw", [])[:10]
    if len(rec.get("desc", "")) > 1500:
        rec["desc"] = rec["desc"][:1500]
    rec.setdefault("atlas", [])
    rec.setdefault("atlas_evidence", [])
    rec.setdefault("atlas_mitigations", [])
    return rec


# --------------------------------------------------------------------------
# NVD 原始 CVE → 富化记录（多进程 worker）
# --------------------------------------------------------------------------
_KEV = {}


def _worker_init(kev):
    global _KEV
    _KEV = kev


def _worker(cve):
    try:
        rec = F.build_record(cve, _KEV, {}, [])
        return slim_record(rec)
    except Exception:  # noqa: BLE001 —— 单条坏数据不阻塞全量
        return None


def main():
    t0 = time.time()
    log = lambda *a: print("[merge]", *a, flush=True)

    # ---------- 0. 备份与加载 ----------
    if not os.path.isfile(BACKUP):
        import shutil
        shutil.copy2(CORPUS, BACKUP)
        log(f"已备份现有语料 → {BACKUP}")
    with open(CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    records = corpus["records"]
    have = {r["id"].upper() for r in records}
    log(f"现有记录 {len(records)} 条（保留全部富化信息）")

    # ---------- 1. KEV 全量 ----------
    try:
        kev = F.fetch_kev()
    except Exception as e:  # noqa: BLE001
        log("KEV 下载失败，使用空表：", str(e)[:80])
        kev = {}

    # ---------- 2. GHSA 全量 ----------
    with open(os.path.join(DATA, "ghsa_full.json"), "r", encoding="utf-8") as f:
        ghsa = json.load(f)
    by_cve = ghsa.get("ghsa_by_cve") or {}
    log(f"GHSA：by_cve {len(by_cve)} 组 / 独立 {len(ghsa.get('ghsa_standalone') or [])} 条 / "
        f"受影响项目 {len(ghsa.get('ghsa_projects') or [])} 个")

    # ---------- 3. NVD 全量补充（多进程富化，分批控制内存峰值） ----------
    raw_files = sorted(glob.glob(os.path.join(DATA, "nvd_full", "*Q*.jsonl")))
    log(f"NVD 全量池：{len(raw_files)} 个分片")

    def _iter_new_cves():
        seen_new = set()
        for fp in raw_files:
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        c = json.loads(line)
                    except ValueError:
                        continue
                    cid = (c.get("id") or "").upper()
                    if not cid or cid in have or cid in seen_new:
                        continue
                    seen_new.add(cid)
                    yield c

    added, consumed = 0, 0
    BATCH = 20000
    batch = []
    workers = min(6, (os.cpu_count() or 4))
    try:                       # 性能档位：低配机器上进程池压到 2
        from envprofile import T
        workers = T.workers(workers)
    except Exception:
        pass
    ex = ProcessPoolExecutor(max_workers=workers,
                             initializer=_worker_init, initargs=(kev,))
    try:
        for c in _iter_new_cves():
            batch.append(c)
            if len(batch) >= BATCH:
                for rec in ex.map(_worker, batch, chunksize=300):
                    if rec is not None:
                        records.append(rec)
                        added += 1
                consumed += len(batch)
                batch.clear()
                log(f"  富化进度 {consumed} 条原始 CVE → 新增 {added}（{round(time.time()-t0)}s）")
        if batch:
            for rec in ex.map(_worker, batch, chunksize=300):
                if rec is not None:
                    records.append(rec)
                    added += 1
            consumed += len(batch)
            batch.clear()
    finally:
        ex.shutdown(wait=True)
    log(f"NVD 新增记录：{added} 条（处理原始 {consumed} 条），合计 {len(records)}")

    # ---------- 4. GHSA 并回 CVE 记录（与 augment 同策略） ----------
    rec_by_id = {r["id"].upper(): r for r in records}
    norm = AUG.norm_product
    n_merge = 0
    for cve, advisories in by_cve.items():
        r = rec_by_id.get(cve.upper())
        if not r:
            continue
        for a in advisories:
            if "GitHub Advisory" not in r["sources"]:
                r["sources"].append("GitHub Advisory")
            for u in a.get("advisory_links", []):
                if u not in r["advisory_links"]:
                    r["advisory_links"].append(u)
            for pkg in a.get("products", []):
                pkg_n = norm(pkg)
                if pkg_n and pkg_n not in r["osv_packages"] and pkg_n not in r["products"]:
                    r["osv_packages"].append(pkg_n)
            if a.get("desc"):
                s = "GitHub Advisory " + a["id"] + "：" + a["desc"][:300]
                if s not in r.get("osv_summaries", []):
                    r.setdefault("osv_summaries", []).append(s)
            if "供应链公告" not in r["tags"]:
                r["tags"].append("供应链公告")
            n_merge += 1
    log(f"GHSA 并回已有 CVE：{n_merge} 处")

    # ---------- 5. KEV 重放（补新增在野利用标记） ----------
    n_kev = 0
    for cid, ent in kev.items():
        r = rec_by_id.get(cid.upper())
        if r and not r.get("kev"):
            r["kev"] = ent
            if "CISA KEV" not in r["sources"]:
                r["sources"].append("CISA KEV")
            if "在野利用" not in r["tags"]:
                r["tags"].append("在野利用")
            r["remediation"] = F.remediation(r)
            n_kev += 1
    log(f"KEV 补标：{n_kev} 条")

    # ---------- 6. 组件名归一化 + 推断 + CWE 名称 + GHSA 后重分类 ----------
    ghsa_touched = {c.upper() for c in by_cve}
    n_infer, n_recls = 0, 0
    for r in records:
        r["products"] = sorted({norm(p) for p in r.get("products", []) if p and p != "*"})
        r["vendors"] = sorted({norm(v) for v in r.get("vendors", []) if v and v != "*"})
        if not r["products"]:
            got = infer_products_fast(r)
            if got:
                r["products"] = got
                r["product_source"] = "描述文本推断"
                n_infer += 1
        for w in r.get("cwe", []):
            if not w.get("name"):
                w["name"] = F.CWE_NAMES.get(w["id"], "")
        # GHSA 合并引入了新的受影响包 → 分类可能变化（如归为 AI 供应链）
        if r["id"].upper() in ghsa_touched:
            ok, score, cat, reason, tags = F.classify(r)
            r["scope"] = "AI安全" if ok else "通用安全"
            r["ai_score"], r["category"], r["category_reason"], r["risk_tags"] = \
                score, cat, reason, tags
            t = list(tags) + [cat]
            if r.get("kev"):
                t.append("在野利用")
            if r.get("poc_links"):
                t.append("存在POC")
            if "GitHub Advisory" in r.get("sources", []):
                t.append("供应链公告")
            r["tags"] = sorted(set(t))
            n_recls += 1
    log(f"组件推断 {n_infer} 条 / GHSA 后重分类 {n_recls} 条（{round(time.time()-t0)}s）")

    # ---------- 7. ATLAS 映射（仅 AI 域新记录） + 论文关联 ----------
    papers = corpus.get("papers", [])
    try:
        from atlas import AtlasKB
        kb = AtlasKB()
    except Exception as e:  # noqa: BLE001
        log("ATLAS 不可用，跳过：", str(e)[:100])
        kb = None
    n_atlas = n_link = 0
    for r in records:
        if "atlas" not in r:
            r["atlas"], r["atlas_evidence"], r["atlas_mitigations"] = [], [], []
        if r.get("scope") != "AI安全":
            continue
        if kb is not None and not r["atlas"]:
            techs, why = kb.map_record(r)
            r["atlas"] = techs
            r["atlas_evidence"] = why
            r["atlas_mitigations"] = kb.mitigations_for([t["id"] for t in techs]) if techs else []
            if techs:
                n_atlas += 1
        if papers and not r.get("papers"):
            lp = F.link_papers(r, papers)
            if lp:
                r["papers"] = lp
                n_link += 1
    log(f"ATLAS 新映射 {n_atlas} 条 / 新关联论文 {n_link} 条（{round(time.time()-t0)}s）")

    # ---------- 8. 知识底座装配 ----------
    knowledge = []
    if kb is not None:
        knowledge += kb.to_records()
        corpus["atlas"] = {
            "version": kb.version,
            "tactics": [{"id": k, "name": v} for k, v in kb.tactics.items()],
            "technique_count": len(kb.tech),
            "mitigation_count": len(kb.mitigations),
            "case_study_count": len(kb.case_studies),
        }
    knowledge += list(ghsa.get("ghsa_standalone") or [])
    knowledge += list(ghsa.get("ghsa_projects") or [])
    # GitHub 仓库（ecosyste.ms 新收割 + 旧 400 条，按 rid 去重）
    repos_new = []
    rp = os.path.join(DATA, "gh_repos.json")
    if os.path.isfile(rp):
        with open(rp, "r", encoding="utf-8") as f:
            repos_new = json.load(f)
    knowledge += repos_new
    # 中文社区文章
    cn_counts = {}
    for name in ("csdn", "anquanke", "xz"):
        fp = os.path.join(DATA, "cn", name + ".json")
        if os.path.isfile(fp):
            with open(fp, "r", encoding="utf-8") as f:
                arr = json.load(f)
            cn_counts[name] = len(arr)
            knowledge += arr
    # 旧扩展源（GHSA 部分已被 ghsa_full 取代，仅并入 repo/article）
    xs = os.path.join(DATA, "extra_sources.json")
    if os.path.isfile(xs):
        with open(xs, "r", encoding="utf-8") as f:
            old = json.load(f)
        knowledge += list(old.get("repos") or []) + list(old.get("articles") or [])
    # 论文知识条目
    knowledge += X.papers_to_knowledge(papers)
    # 全局去重（先出现的优先：ATLAS/GHSA 优先于旧源）
    dedup, seen_k = [], set()
    for k in knowledge:
        rid = k.get("id")
        if not rid or rid in seen_k:
            continue
        seen_k.add(rid)
        dedup.append(k)
    knowledge = dedup
    log(f"知识条目：{len(knowledge)} 条（仓库 {len(repos_new)} / 中文 {cn_counts} / "
        f"GHSA 独立 {len(ghsa.get('ghsa_standalone') or [])} / 项目 {len(ghsa.get('ghsa_projects') or [])}）")

    # ---------- 9. 落盘 ----------
    records.sort(key=lambda r: r.get("published", ""), reverse=True)
    corpus["records"] = records
    corpus["knowledge"] = knowledge
    corpus["meta"].update({
        "merged_full_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "records": len(records),
        "knowledge": len(knowledge),
        "nvd_full_added": added,
        "ghsa": {"by_cve": len(by_cve), "merged": n_merge,
                 "standalone": len(ghsa.get("ghsa_standalone") or []),
                 "projects": len(ghsa.get("ghsa_projects") or [])},
        "gh_repos": len(repos_new),
        "cn_articles": cn_counts,
    })
    tmp = CORPUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, CORPUS)
    sz = os.path.getsize(CORPUS) / 1024 / 1024
    log(f"已写入 {CORPUS}（{sz:.1f} MB）总文档 {len(records) + len(knowledge)}")
    # 索引缓存随语料失效
    ic = CORPUS + ".idxcache"
    if os.path.isfile(ic):
        os.remove(ic)

    from collections import Counter
    print("分类分布:", dict(Counter(r["category"] for r in records).most_common()))
    print("scope 分布:", dict(Counter(r.get("scope", "?") for r in records)))
    print(f"总耗时 {round(time.time()-t0)}s")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
