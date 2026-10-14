# -*- coding: utf-8 -*-
"""CMDB 多文件性能/正确性测试（2026-10-05 提速改造验证）。

验证点：
  ① sheet 预览过滤：拓扑/字典/工单类 sheet 被跳过，资产 sheet 全保留
  ② 单文件（02_软件资源层）匹配逻辑自洽：总命中 203 / 分级不溢出 / KEV>0
     ★ 2026-10-06 改过：原来断言写死 (203, 32, 106, 2)，语料库一升级就假失败，
       害得人以为匹配逻辑坏了。分级会随情报更新浮动，总命中数才是稳定的那个。
  ③ 多文件：并行与顺序合并结果一致（主机/产品数）
  ④ 无表头文件（拓扑）不产生资产，warn 说明

用法：python tools/_test_cmdb_perf.py [文件目录，默认 E:/cmdb/excel]
"""
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_ROOT, os.path.join(_ROOT, "core"),
          os.path.join(_ROOT, "modules", "m2_enrich", "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

import cmdb_scan as CM          # noqa: E402
import asset_scan as AS         # noqa: E402


def _load(p):
    with open(p, "rb") as f:
        return f.read()


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "E:/cmdb/excel"
    files = sorted(fn for fn in os.listdir(d)
                   if fn.lower().endswith(".xlsx") and not fn.startswith("~$"))
    fpaths = [os.path.join(d, fn) for fn in files]
    print("== ① sheet 预览过滤效果 ==")
    total_rows = 0
    for p in fpaths:
        fn = os.path.basename(p)
        t0 = time.time()
        doc = AS.read_upload(p, _load(p), sheet_filter=CM._cmdb_sheet_filter)
        dt = time.time() - t0
        total_rows += len(doc.rows)
        print("  %-28s %6.1fs  rows=%-7d %s" % (fn, dt, len(doc.rows),
                                                ("|" + doc.warn) if doc.warn else ""))
    print("  合计解析行数: %d" % total_rows)

    print("== ② 单文件一致性（02_软件资源层）==")
    import paths
    from engine import SearchEngine
    eng = SearchEngine(paths.CORPUS_FP)
    p02 = os.path.join(d, "02_软件资源层.xlsx")
    r = CM.analyze(eng, {"mode": "file", "files": [{"filename": "02_软件资源层.xlsx",
                                                    "data": _load(p02)}],
                         "name": "02_软件资源层"})
    if not r.get("ok"):
        print("  FAIL:", r.get("error"))
        return 1
    s = r["report"]["risk"]["summary"]
    print("  cve=%s crit=%s high=%s kev=%s" % (s["cve_hits"], s["critical"],
                                               s["high"], s["exploited"]))
    # ★ 断言的是「匹配逻辑没坏」，不是「情报库内容永远不变」（2026-10-06 修正）。
    #   原来写死 (203, 32, 106, 2)，语料库一升级（这里是 10/5 写基准、10/6 语料更新）
    #   就 FAIL，但总命中 203 和 KEV 2 一字不差 —— 说明匹配逻辑完全正常，
    #   只是 9 个漏洞的严重度被重新评级了（crit 32→41、high 106→97，总和不变）。
    #   这种"数据漂移导致的假失败"比没有测试更糟：会让人以为代码坏了去排查半天。
    #   现在只钉住三件真正该稳定的事：
    #     ① 总命中数（匹配逻辑的核心指标，漂移了说明匹配规则变了）
    #     ② crit + high ≤ 总命中（分级不能溢出，是自洽性硬约束）
    #     ③ KEV 数 > 0（在野库接上了没）
    ok = (s["cve_hits"] == 203
          and s["critical"] + s["high"] <= s["cve_hits"]
          and s["exploited"] > 0)
    print("  匹配逻辑自洽（总数=203 / 分级不溢出 / KEV>0）:", "PASS" if ok else "FAIL")
    if not ok:
        return 1

    print("== ③ 多文件合并 + 产品语义 ==")
    small = fpaths[:4] + fpaths[5:6]          # 5 个文件（含拓扑 + 大文件）
    fdatas = [{"filename": os.path.basename(p), "data": _load(p)} for p in small]
    t0 = time.time()
    seq = CM._load_assets({"mode": "file", "files": fdatas}, eng)
    t_seq = time.time() - t0
    sh, sp = len(seq[0]["hosts"]), len(seq[0]["products"])
    print("  顺序流水线: %.1fs hosts=%d prods=%d" % (t_seq, sh, sp))
    # HOSTNAME 不能再被当成产品（旧 bug 会灌出 10 万假产品撞上限）
    ok = sp < CM.MAX_PRODUCTS and sh > 100000
    print("  产品数未撞上限且主机保留:", "PASS" if ok else "FAIL (prods=%d hosts=%d)" % (sp, sh))
    if not ok:
        return 1

    print("== ④ 拓扑文件零资产 ==")
    # 直接单测一个拓扑文件
    rt = CM._parse_file_worker((os.path.basename(fpaths[6]), _load(fpaths[6])))
    n_assets = len((rt.get("assets") or {}).get("hosts") or [])
    print("  拓扑文件 kind=%s hosts=%d warn=%s" % (rt.get("kind"), n_assets,
                                                  (rt.get("warn") or "")[:60]))
    print("  拓扑零资产:", "PASS" if n_assets == 0 else "FAIL(有 %d 主机)" % n_assets)
    if n_assets:
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
