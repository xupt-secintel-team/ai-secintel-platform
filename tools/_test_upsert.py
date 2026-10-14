"""离线验证：引擎增量新增 / 就地更新是否会破坏索引一致性。

用小语料（默认 3000 条，从真实 corpus 截断）跑，避免每次加载 267MB。
    python tools/_test_upsert.py
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import SearchEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
tmp = os.path.join(ROOT, "data", "_upsert_probe.json")
corpus_path = os.path.join(ROOT, "data", "corpus.json")

t0 = time.time()
with open(corpus_path, "r", encoding="utf-8") as f:
    c = json.load(f)
small = {"records": c["records"][:N], "knowledge": c.get("knowledge", [])[:200],
         "papers": []}
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(small, f, ensure_ascii=False)
print(f"小语料 {len(small['records'])} 条，准备 {time.time()-t0:.1f}s")

eng = SearchEngine(tmp)
print(f"引擎就绪：{len(eng.docs)} 条 · {time.time()-t0:.1f}s")

# ---- 1. 挑一条已存在的 CVE 做"更新" ----
cid = small["records"][7]["id"]
old = [d for d in eng.docs if d["id"].upper() == cid.upper()][0]
old_cvss = old.get("cvss")
old_desc = (old.get("desc") or "")[:40]

import copy
upd = copy.deepcopy(old)
upd["desc"] = (old.get("desc") or "") + " ZZZMARKER 全新描述片段 qqqunique"
if isinstance(upd.get("cvss"), dict):
    upd["cvss"]["score"] = 9.9
else:
    upd["cvss"] = 9.9
upd["status"] = "Modified-Probe"

n_add = eng.add_documents([upd])          # 已存在 → 应返回 0
n_upd = eng.update_documents([upd])       # 已存在 → 应返回 1
print(f"add_documents(已存在) = {n_add}（应为 0）; update_documents = {n_upd}（应为 1）")

cur = eng.docs[eng.id_map[cid.upper()]]
print(f"  cvss {old_cvss} -> {cur.get('cvss')}  status={cur.get('status')}")
print(f"  描述已更新: {'ZZZMARKER' in (cur.get('desc') or '')}")
print(f"  文档总数未变: {len(eng.docs) == len(small['records']) + len(small['knowledge'])}")

# ---- 2. 新增文档 ----
newrec = copy.deepcopy(small["records"][0])
newrec["id"] = "CVE-2099-00001"
newrec["desc"] = "探针新增文档 qqqunique ZZZMARKER"
before = len(eng.docs)
n2 = eng.add_documents([newrec])
print(f"新增文档: {before} -> {len(eng.docs)}（add_documents 返回 {n2}，应为 1）")

# ---- 3. 检索仍可用，且能命中新词 ----
r = eng.search("qqqunique", top_k=5)
items = (r.get("results") or r.get("hits") or r.get("docs") or []) if isinstance(r, dict) else r
hits = [h["id"] if isinstance(h, dict) else getattr(h, "id", h) for h in items]
print(f"检索 'qqqunique' 命中 total={r.get('total')} 条: {hits[:5]}")
assert r.get("total") == 2, "新增 + 更新两条都应命中"
print(f"  更新条目可被检索: {cid.upper() in [h.upper() for h in hits]}")
print(f"  新增条目可被检索: {'CVE-2099-00001' in hits}")

# ---- 4. 压力：批量更新 200 条，看耗时 ----
batch = []
for d in small["records"][:200]:
    x = copy.deepcopy(d)
    x["desc"] = (x.get("desc") or "") + " batchprobe"
    batch.append(x)
t1 = time.time()
nb = eng.update_documents(batch)
print(f"批量更新 200 条: 返回 {nb} · 耗时 {time.time()-t1:.2f}s")

t2 = time.time()
nb2 = eng.update_documents(batch)      # 第二次：内容已变过，但函数不做去重，应仍返回 200
print(f"重复更新 200 条: 返回 {nb2} · 耗时 {time.time()-t2:.2f}s（词项已存在，应更快）")
print(f"索引一致性: N={eng.N} docs={len(eng.docs)} tf={len(eng.tf)} dl={len(eng.dl)}")
for _p in (tmp, tmp + '.idxcache'):
    if os.path.isfile(_p):
        os.remove(_p)
print('DONE')
