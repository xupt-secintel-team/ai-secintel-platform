# -*- coding: utf-8 -*-
"""_find_record 索引缓存的失效判据测试（2026-10-06）

这个 bug 极隐蔽：功能完全正确（结果对），只是慢 15 万倍。
语料里只要有两条记录 id 相同，`len(idx) != len(docs)` 就永远成立，
缓存形同虚设 —— 实测 122MB 的 CMDB 库分析要跑 1800 秒还不能出结果，
profiler 显示 _find_record 一个函数吃掉一半时间。

所以这类"性能回归"必须写测试钉住，不能靠"跑一次感觉挺快"。
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

import cmdb_scan as CS  # noqa: E402

_PASS = [0]
_FAIL = [0]


def ok(cond, label, extra=""):
    if cond:
        _PASS[0] += 1
        print("  [PASS] %s" % label)
    else:
        _FAIL[0] += 1
        print("  [FAIL] %s%s" % (label, ("  -> " + str(extra)) if extra else ""))


class FakeEngine:
    def __init__(self, docs):
        self.docs = docs


def mk_docs(n, dup=0):
    """n 条正常记录 + dup 组重复 id"""
    docs = [{"id": "CVE-2026-%06d" % i, "title": "t%d" % i} for i in range(n)]
    for k in range(dup):
        docs.append({"id": "CVE-2026-00000", "title": "dup%d" % k})
    return docs


print("=== ① 语料含重复 id 时缓存必须仍然生效（本 bug 的核心）===")
# dup=2 → idx 长度比 docs 少 2，正是原来失效的那个条件
docs = mk_docs(5000, dup=2)
eng = FakeEngine(docs)
CS._ID_INDEX_CACHE.clear()

t = time.time()
for i in range(300):
    CS._find_record(eng, "CVE-2026-%06d" % (i % 5000))
dt = time.time() - t
ok(dt < 0.5, "300 次查找在 0.5s 内完成（缓存生效）", "%.2fs" % dt)

print("\n=== ② 重复 id 不影响查找正确性 ===")
CS._ID_INDEX_CACHE.clear()
hit = CS._find_record(eng, "CVE-2026-00000")
ok(hit is not None, "重复 id 的记录能被查到（后写的覆盖先写的）",
   "None" if hit is None else "")
ok(hit and hit["title"].startswith("dup"), "取到的是最后一条 dup",
   hit.get("title") if hit else None)

print("\n=== ③ 引擎换代必须自动失效（不能返回旧引擎的数据）===")
CS._ID_INDEX_CACHE.clear()
e1 = FakeEngine([{"id": "CVE-1", "t": "old"}])
e2 = FakeEngine([{"id": "CVE-2", "t": "new"}])
ok(CS._find_record(e1, "CVE-1") is not None, "引擎1 能查到自己的记录")
ok(CS._find_record(e2, "CVE-1") is None,
   "切到引擎2 后查引擎1 的 id → 查不到（缓存没串）")
ok(CS._find_record(e2, "CVE-2") is not None, "引擎2 能查到自己的记录")

print("\n=== ④ 同一引擎 docs 原地变化 → 必须失效重建 ===")
CS._ID_INDEX_CACHE.clear()
eng3 = FakeEngine([{"id": "CVE-A", "t": "1"}])
ok(CS._find_record(eng3, "CVE-A") is not None, "变更前能查到")
eng3.docs.append({"id": "CVE-B", "t": "2"})   # 原地 append，id(docs) 不变
ok(CS._find_record(eng3, "CVE-B") is not None,
   "docs 原地增长后新增记录能被查到（长度变了→失效）")
eng3.docs[0]["title"] = "changed"
ok(CS._find_record(eng3, "CVE-A")["title"] == "changed",
   "docs 内容被修改后返回的是新内容")

print("\n=== ⑤ 边界：空 docs / 缺 id / 非 dict 元素 ===")
CS._ID_INDEX_CACHE.clear()
e = FakeEngine([])
ok(CS._find_record(e, "CVE-X") is None, "空 docs 返回 None 不崩")
e = FakeEngine([{"no_id": 1}, "字符串", 123, None, {"id": "CVE-Y"}])
ok(CS._find_record(e, "CVE-Y") is not None, "混合脏数据里仍能查到有效记录")
ok(CS._find_record(e, "CVE-NOPE") is None, "查不存在的返回 None")

print("\n=== ⑥ 性能断言（防止将来又写回失效判据）===")
CS._ID_INDEX_CACHE.clear()
big = mk_docs(20000, dup=3)
eng4 = FakeEngine(big)
CS._find_record(eng4, "CVE-2026-00001")          # 预热
t = time.time()
for i in range(2000):
    CS._find_record(eng4, "CVE-2026-%06d" % (i % 20000))
dt = time.time() - t
per = dt / 2000 * 1e6
ok(per < 50, "单次平均 < 50us（当前 %.2fus）" % per,
   "%.1fus —— 又退化成每次重建索引了" % per)

print("\n" + "=" * 60)
print("合计 %d 项，通过 %d，失败 %d"
      % (_PASS[0] + _FAIL[0], _PASS[0], _FAIL[0]))
sys.exit(1 if _FAIL[0] else 0)