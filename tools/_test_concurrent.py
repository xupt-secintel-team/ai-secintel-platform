"""并发回归：一边增量入库、一边检索，不该 500。

修的是这个坑：add_documents 循环里 docs/dl/tf 已经变长，self.N 却要等循环结束
才更新；_ensure_norm 又用 len(self._norm) != self.N 判定要不要重建长度归一因子，
于是判定为"没变"，_score 对新下标取 self._norm[i] → IndexError。
轻量同步 5 分钟一轮之后，这个窗口从"理论存在"变成"迟早要踩"。

    python tools/_test_concurrent.py
"""
import json, os, sys, threading, time, copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.engine import SearchEngine  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tmp = os.path.join(ROOT, "data", "_conc_probe.json")

with open(os.path.join(ROOT, "data", "corpus.json"), "r", encoding="utf-8") as f:
    c = json.load(f)
json.dump({"records": c["records"][:2500], "knowledge": c.get("knowledge", [])[:200],
           "papers": []}, open(tmp, "w", encoding="utf-8"), ensure_ascii=False)

eng = SearchEngine(tmp)
print(f"引擎就绪 {len(eng.docs)} 条")

STOP = {"on": False}
ERRS = {"search": [], "add": []}
N_SEARCH = {"n": 0}
N_ADD = {"n": 0}


def _searcher():
    while not STOP["on"]:
        try:
            r = eng.search("漏洞", top_k=5)
            N_SEARCH["n"] += 1
            _ = (r or {}).get("total")
        except Exception as e:  # noqa: BLE001
            ERRS["search"].append(f"{type(e).__name__}: {str(e)[:120]}")
            if len(ERRS["search"]) > 3:
                return


def _adder():
    i = 0
    while not STOP["on"] and i < 300:
        try:
            d = copy.deepcopy(eng.docs[i % 500])
            d["id"] = "CVE-2099-%05d" % i
            d["title"] = f"并发探针 {i}"
            d["desc"] = (d.get("desc") or "") + " 并发探针标记 concprobe"
            eng.add_documents([d])
            if i % 3 == 0:                      # 顺带压 update 路径
                u = copy.deepcopy(d)
                u["desc"] = (u.get("desc") or "") + " 二次改动"
                eng.update_documents([u])
            N_ADD["n"] += 1
        except Exception as e:  # noqa: BLE001
            ERRS["add"].append(f"{type(e).__name__}: {str(e)[:120]}")
            if len(ERRS["add"]) > 3:
                return
        i += 1
        time.sleep(0.002)


ts = [threading.Thread(target=_searcher, daemon=True) for _ in range(4)]
ts.append(threading.Thread(target=_adder, daemon=True))
for t in ts:
    t.start()
t0 = time.time()
while time.time() - t0 < 12:
    time.sleep(0.5)
STOP["on"] = True
for t in ts:
    t.join(timeout=5)

print(f"检索 {N_SEARCH['n']} 次 · 增量写入 {N_ADD['n']} 条 · 文档数 {len(eng.docs)}")
print(f"检索异常 {len(ERRS['search'])} 个: {ERRS['search'][:3]}")
print(f"写入异常 {len(ERRS['add'])} 个: {ERRS['add'][:3]}")

# 一致性收尾校验：随机抽样，索引内容必须对得上
import random
random.seed(11)
bad = 0
for _ in range(15):
    i = random.randrange(len(eng.docs))
    d = eng.docs[i]
    r = eng.search((d.get("title") or "")[:24] or "漏洞", top_k=1)
    if not (r or {}).get("results"):
        continue
    top = r["results"][0]
    if top["id"] != d["id"] and (d.get("title") or "")[:24] not in (top.get("title") or ""):
        bad += 1
print(f"收尾抽样错位 {bad} 条（标题相同/命中即算通过）")
for _p in (tmp, tmp + ".idxcache"):
    if os.path.isfile(_p):
        os.remove(_p)
assert not ERRS["search"] and not ERRS["add"], "P1：并发下出现异常"
print("ALL PASS")
