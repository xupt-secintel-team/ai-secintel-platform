# -*- coding: utf-8 -*-
"""
build_data.py —— 断点续传的数据采集脚本
========================================
分批采集NVD，每批保存中间结果，中断后重跑自动续传。
用法：
  python build_data.py              # 采集/续传NVD
  python build_data.py --assemble   # 采集完后组装corpus.json
  python build_data.py --batch 5    # 每批关键词数(默认8)
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_corpus as F
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
NVD_CACHE = os.path.join(DATA, "nvd_cache.json")
KEV_CACHE = os.path.join(DATA, "kev_cache.json")
OSV_CACHE = os.path.join(DATA, "osv_cache.json")
PAPER_CACHE = os.path.join(DATA, "papers_raw.json")
ENRICHED_CACHE = os.path.join(DATA, "enriched_cache.json")
CORPUS = os.path.join(DATA, "corpus.json")


def load_json(path, default):
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as _sw_e:
            _swallow("modules/m1_monitor/backend/build_data.py:43", _sw_e)
    return default


def save_json(path, obj, retries=3):
    # 先完整序列化到内存字符串（避免编码与文件IO交替，在超大dict上更稳），
    # 再一次性写入；失败重试，间歇编码器错误可自愈
    last_err = None
    for attempt in range(retries):
        try:
            payload = json.dumps(obj, ensure_ascii=False)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(payload)
            os.replace(tmp, path)
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(1.5)
    print(f"  [SAVE FAIL] {path}: {last_err}", flush=True)
    raise last_err


def collect_nvd(batch_size=8):
    """分批采集NVD，支持断点续传"""
    cache = load_json(NVD_CACHE, {"done": [], "cves": {}})
    done = set(cache["done"])
    cves = cache["cves"]
    queries = F.NVD_QUERIES

    todo = [q for q in queries if q not in done]
    print(f"NVD采集：总{len(queries)}组，已完成{len(done)}组，待采集{len(todo)}组")

    for batch_start in range(0, len(todo), batch_size):
        batch = todo[batch_start:batch_start + batch_size]
        for q in batch:
            try:
                d = F.fetch_nvd(q)
                n = 0
                for v in d.get("vulnerabilities", []):
                    c = v.get("cve", {})
                    cid = c.get("id")
                    if cid and cid not in cves:
                        # 缓存原始CVE JSON（精简存储）
                        cves[cid] = c
                        n += 1
                done.add(q)
                print(f"  [{len(done)}/{len(queries)}] '{q}' +{n} pool={len(cves)}", flush=True)
            except Exception as e:
                print(f"  [FAIL] '{q}': {str(e)[:80]}", flush=True)
            time.sleep(F.NVD_SLEEP)

        # 每批保存一次
        try:
            save_json(NVD_CACHE, {"done": list(done), "cves": cves})
            print(f"  --- 批次已保存 ({len(done)}/{len(queries)}) ---", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"  --- 保存失败但继续采集: {str(e)[:60]} ---", flush=True)

    remaining = len(queries) - len(done)
    print(f"NVD采集完成：{len(cves)}条CVE，剩余{remaining}组失败(可重跑)")
    return cves


def collect_kev():
    print("采集 CISA KEV ...")
    try:
        kev = F.fetch_kev()
        save_json(KEV_CACHE, kev)
        print(f"  KEV: {len(kev)}条")
        return kev
    except Exception as e:
        print(f"  KEV失败: {e}")
        return load_json(KEV_CACHE, {})


def collect_osv():
    print("采集 OSV/GHSA ...")
    cache = load_json(OSV_CACHE, {"done": [], "index": {}})
    done = set(cache["done"])
    osv_index = cache["index"]

    todo = [p for p in F.OSV_PACKAGES if f"{p[0]}/{p[1]}" not in done]
    print(f"  总{len(F.OSV_PACKAGES)}包，已完成{len(done)}，待采集{len(todo)}")

    for eco, pkg in todo:
        try:
            vulns = F.fetch_osv(pkg, eco)
            F.osv_to_records(vulns, osv_index)
            done.add(f"{eco}/{pkg}")
            print(f"  [{len(done)}/{len(F.OSV_PACKAGES)}] {eco}/{pkg}", flush=True)
        except Exception as e:
            print(f"  [FAIL] {eco}/{pkg}: {str(e)[:60]}", flush=True)
        time.sleep(0.5)
        if len(done) % 10 == 0:
            save_json(OSV_CACHE, {"done": list(done), "index": osv_index})

    save_json(OSV_CACHE, {"done": list(done), "index": osv_index})
    print(f"  OSV索引: {len(osv_index)}条")
    return osv_index


def collect_papers():
    print("采集 arXiv 论文 ...")
    cache = load_json(PAPER_CACHE, {"done": [], "papers": []})
    done = set(cache["done"])
    papers = cache["papers"]

    todo = [q for q in F.ARXIV_QUERIES if q not in done]
    for q in todo:
        try:
            got = F.fetch_arxiv(q)
            seen_titles = {p["title"] for p in papers}
            for p in got:
                if p["title"] not in seen_titles:
                    papers.append(p)
            done.add(q)
            print(f"  '{q[:40]}' -> {len(got)} (总{len(papers)})", flush=True)
        except Exception as e:
            print(f"  [FAIL] '{q[:40]}': {e}", flush=True)
        time.sleep(3.2)
        save_json(PAPER_CACHE, {"done": list(done), "papers": papers})

    print(f"  论文: {len(papers)}篇")
    return papers


def enrich_records(cves, kev, osv_index, papers, chunk=1500):
    """富化全部CVE，支持断点续传（分批保存到enriched_cache）"""
    ec = load_json(ENRICHED_CACHE, {"done": [], "records": []})
    done = set(ec["done"])
    records = ec["records"]
    todo = [(cid, c) for cid, c in cves.items() if cid not in done]
    print(f"  富化续传：已完成{len(done)}，待处理{len(todo)}")

    processed = 0
    for cid, c in todo:
        try:
            rec = F.build_record(c, kev, osv_index, papers)
            if rec:
                records.append(rec)
        except Exception as e:  # noqa: BLE001
            print(f"  [SKIP] {cid}: {str(e)[:60]}")
        done.add(cid)
        processed += 1
        if processed % chunk == 0:
            save_json(ENRICHED_CACHE, {"done": list(done), "records": records})
            print(f"  富化进度 {len(done)}/{len(cves)} (已保存)", flush=True)

    # 全部富化完成，最终保存一次
    save_json(ENRICHED_CACHE, {"done": list(done), "records": records})
    return records


def assemble():
    """把缓存的原始数据组装成corpus.json（富化过程断点续传）"""
    print("=== 组装 corpus.json ===")
    nvd = load_json(NVD_CACHE, {"cves": {}})
    kev = load_json(KEV_CACHE, {})
    osv = load_json(OSV_CACHE, {"index": {}})
    papers_cache = load_json(PAPER_CACHE, {"papers": []})
    pk = load_json(os.path.join(DATA, "papers_kb.json"), {"papers": []})

    cves = nvd["cves"]
    osv_index = osv["index"]
    papers = papers_cache["papers"]
    # 合并离线经典论文知识库
    existing_titles = {p.get("title", "").lower() for p in papers}
    for p in pk.get("papers", []):
        if p.get("title", "").lower() not in existing_titles:
            papers.append(p)
    print(f"  CVE原始: {len(cves)} / KEV: {len(kev)} / OSV: {len(osv_index)} / 论文: {len(papers)}")

    records = enrich_records(cves, kev, osv_index, papers)
    records.sort(key=lambda r: r.get("published", ""), reverse=True)

    # 数据安全特色知识库
    knowledge = []
    dskb_path = os.path.join(DATA, "data_security_kb.json")
    if os.path.isfile(dskb_path):
        dskb = load_json(dskb_path, {"items": []})
        knowledge = dskb.get("items", [])
        print(f"  数据安全知识库: {len(knowledge)}条")

    from datetime import datetime, timezone
    corpus = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "nvd_pool": len(cves),
            "records": len(records),
            "kev_total": len(kev),
            "osv_index": len(osv_index),
            "papers": len(papers),
            "knowledge": len(knowledge),
            "sources": ["NVD", "CISA KEV", "OSV/GHSA", "arXiv", "数据安全知识库"],
        },
        "papers": papers,
        "records": records,
        "knowledge": knowledge,
    }
    save_json(CORPUS, corpus)
    size_mb = os.path.getsize(CORPUS) / 1024 / 1024
    print(f"完成：{len(records)}条记录，写入 corpus.json ({size_mb:.2f} MB)")

    from collections import Counter
    print("分类分布:", dict(Counter(r["category"] for r in records)))
    print("严重度:", dict(Counter(r["cvss"]["severity"] or "UNKNOWN" for r in records)))


def main():
    args = sys.argv[1:]
    batch = 8
    if "--batch" in args:
        batch = int(args[args.index("--batch") + 1])

    if "--assemble" in args:
        assemble()
        return

    # 完整流程：NVD → KEV → OSV → Papers → 组装
    collect_nvd(batch)
    collect_kev()
    collect_osv()
    collect_papers()
    assemble()


if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
