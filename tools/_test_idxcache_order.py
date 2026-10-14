"""端到端验证：轻量增量 → 落盘（顺序变化）→ 重启复用缓存，索引不错位。

这是 2026-09-30 修的那个"静默错误"的回归测试：
倒排表存的是文档下标，而 monitor 落盘会把 records 按 published 重排，
引擎这边却是 append 到末尾 —— 两边顺序一分叉，缓存里的下标就全错位，
表现为「检索不报错，但返回的是 A 的分数 + B 的正文」。

    python tools/_test_idxcache_order.py
"""
import json, os, sys, copy, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import SearchEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tmp = os.path.join(ROOT, "data", "_idxorder_probe.json")
cache = tmp + ".idxcache"
for p in (tmp, cache):
    if os.path.isfile(p):
        os.remove(p)

# ---------- 1. 造一份小语料 ----------
docs = []
for i in range(200):
    docs.append({
        "id": "CVE-2026-%05d" % i,
        "title": f"样本漏洞 {i} alpha",
        "desc": f"第 {i} 条样本描述，含独有标记 WORD{i:05d}。",
        "published": "2026-09-%02d" % (i % 28 + 1),
        "category": "样本", "cvss": {"score": 5.0}, "products": [], "tags": [],
    })
json.dump({"records": docs, "knowledge": [], "papers": []},
          open(tmp, "w", encoding="utf-8"), ensure_ascii=False)

eng = SearchEngine(tmp)
print(f"1) 初次建索引：{len(eng.docs)} 条，缓存文件 {'已生成' if os.path.isfile(cache) else '缺失'}")

# ---------- 2. 模拟轻量轮：新增一条（引擎 append 到末尾） ----------
new_rec = {
    "id": "CVE-2026-99999", "title": "新增样本 NEWREC",
    "desc": "新增样本描述，含独有标记 WORD99999。",
    "published": "2026-09-30", "category": "样本", "cvss": {"score": 9.8},
    "products": [], "tags": [],
}
n = eng.add_documents([new_rec])
idx_in_engine = eng.id_map["CVE-2026-99999"]
print(f"2) 增量新增 {n} 条 → 引擎内下标 {idx_in_engine}（应为 {len(eng.docs)-1}，即末尾）")

# ---------- 3. 模拟 monitor 落盘：records 按 published 倒序重排 ----------
with open(tmp, "r", encoding="utf-8") as f:
    corpus = json.load(f)
records = corpus["records"] + [copy.deepcopy(new_rec)]
records.sort(key=lambda r: r.get("published", ""), reverse=True)   # 新记录排到最前
corpus["records"] = records
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(corpus, f, ensure_ascii=False)
eng._save_index_cache(tmp)
pos_in_file = [i for i, d in enumerate(records) if d["id"] == "CVE-2026-99999"][0]
print(f"3) 落盘后新记录在文件中的位置 {pos_in_file}（引擎里是 {idx_in_engine}）→ 顺序已分叉")

# ---------- 4. 模拟重启：加载缓存 ----------
eng2 = SearchEngine(tmp)
idx2 = eng2.id_map["CVE-2026-99999"]
got = eng2.docs[idx2]
print(f"4) 重启后：id_map 指向下标 {idx2}，该位置文档的 id = {got['id']}")
assert got["id"] == "CVE-2026-99999", "P0：索引错位！id_map 指向了别的文档"
assert idx2 == idx_in_engine, "P0：重启后下标与保存时不一致，说明没按缓存顺序对齐"

# ---------- 5. 检索验证：查独有标记，必须命中正确的文档 ----------
for mark, want in (("WORD99999", "CVE-2026-99999"), ("WORD00042", "CVE-2026-00042")):
    r = eng2.search(mark, top_k=3)
    items = r.get("results") or []
    ids = [h["id"] for h in items]
    ok = want in ids
    print(f"5) 检索 {mark} → {ids}  {'OK' if ok else '错误！应命中 ' + want}")
    assert ok, f"P0：检索 {mark} 未命中 {want}"
    hit = [h for h in items if h["id"] == want][0]
    print(f"     命中条目标题 = {hit.get('title')!r}")

# ---------- 6. 抽样校验：随机 20 条文档，索引内容必须对得上 ----------
import random
random.seed(7)
bad = 0
for _ in range(20):
    i = random.randrange(len(eng2.docs))
    d = eng2.docs[i]
    mark = f"WORD{int(d['id'].split('-')[-1]):05d}"
    r = eng2.search(mark, top_k=1)
    items = r.get("results") or []
    if not items or items[0]["id"] != d["id"]:
        bad += 1
        print(f"   错位: 下标 {i} 文档 {d['id']} 查 {mark} 却命中 {items[0]['id'] if items else 'None'}")
print(f"6) 随机抽样 20 条：错位 {bad} 条")
assert bad == 0

for _p in (tmp, cache):
    if os.path.isfile(_p):
        os.remove(_p)
print("ALL PASS")
