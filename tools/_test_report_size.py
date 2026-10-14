# -*- coding: utf-8 -*-
"""报告体积上限测试（2026-10-06）

这个 bug 极其隐蔽：**功能完全正确**，报告内容一项不缺，只是 JSON 有 604MB。
后果是服务端 json.dumps 时内存/CPU 爆炸 → 浏览器 "Failed to fetch"；
报告落盘 604MB，历史列表里每条都是定时炸弹。

必须写测试钉住，因为"跑一次看着挺快"发现不了 —— 小数据集下体积完全正常。
"""
import json
import os
import sqlite3
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))

import cmdb_scan as CS  # noqa: E402
import paths as _paths   # noqa: E402

_PASS = [0]
_FAIL = [0]


def ok(cond, label, extra=""):
    if cond:
        _PASS[0] += 1
        print("  [PASS] %s" % label)
    else:
        _FAIL[0] += 1
        print("  [FAIL] %s%s" % (label, ("  -> " + str(extra)) if extra else ""))


def build_db(path, rows, components=4):
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE vulnerability (VULN_ID TEXT, VULN_NO TEXT, '
                 'AFFECTED_COMPONENT TEXT, COMPONENT_VERSION TEXT, FIX_VERSION TEXT, '
                 'SEVERITY TEXT, CVSS_SCORE REAL, CI_ID TEXT, CI_NAME TEXT, CI_IP TEXT, '
                 'OWNER TEXT, PLAN_FIX_DATE TEXT, FIX_STATUS TEXT, CWE_ID TEXT, '
                 'VULN_NAME TEXT, IS_INTERNET_FACING TEXT, IS_REGULATORY TEXT)')
    q = ('INSERT INTO vulnerability VALUES (' + ",".join(["?"] * 17) + ")")
    comps = ["Apache Tomcat", "MySQL", "Redis", "Nginx",
             "OpenSSH", "Docker", "Kubernetes", "PostgreSQL"][:components]
    for i in range(rows):
        conn.execute(q, [
            "V%08d" % i, "CVE-2026-%05d" % (i % 99999), comps[i % components],
            "9.0.80", "9.0.83", "高危 High", 8.8, "SRV-%06d" % i,
            "host%06d" % i, "10.1.%d.%d" % (i // 250 % 250, i % 250),
            "张三", "2026-12-01", "未修复", "CWE-20", "远程代码执行漏洞",
            "Y" if i % 3 == 0 else "N", "Y" if i % 5 == 0 else "N"])
    conn.commit()
    conn.close()
    return path


print("=== ① 60 万行台账的报告体积必须可控 ===")
tmp = tempfile.mkdtemp(prefix="cmdb_size_")
db = build_db(os.path.join(tmp, "big.db"), 600000)
print("  造库 %.1f MB / 60 万行" % (os.path.getsize(db) / 1048576.0))

r = CS.analyze(None, {"mode": "sqlite", "paths": [db]})
ok(bool(r.get("ok")), "analyze 成功", r.get("error"))
rep = r.get("report") or {}
raw = json.dumps(rep, ensure_ascii=False).encode("utf-8")
mb = len(raw) / 1048576.0
print("  报告 JSON = %.2f MB" % mb)
# 修复前是 460~604MB。这里给 20MB 上限：既能容纳合理明细，又有足够区分度抓回归。
ok(mb < 20, "报告 JSON < 20MB（否则浏览器必然 Failed to fetch）", "%.1f MB" % mb)

print("\n=== ② 体积不能随台账行数线性膨胀 ===")
small = build_db(os.path.join(tmp, "small.db"), 50000)
r2 = CS.analyze(None, {"mode": "sqlite", "paths": [small]})
mb2 = len(json.dumps(r2.get("report") or {}, ensure_ascii=False).encode("utf-8")) / 1048576.0
print("  5 万行 → %.2f MB ；60 万行 → %.2f MB （行数 12 倍）" % (mb2, mb))
# 允许 6 倍余量（明细本身有增长），但绝不该 12 倍线性跟涨
ok(mb < max(mb2 * 6, 1.0), "体积没有随行数线性膨胀",
   "5万=%.2fMB 60万=%.2fMB 倍数=%.1f" % (mb2, mb, mb / max(mb2, 0.001)))

print("\n=== ③ 截断不能污染统计口径（这是本测试的重点）===")
prods = rep.get("risk", {}).get("products") or []
ok(len(prods) > 0, "有组件条目")
for p in prods[:3]:
    stored = len(p.get("assets") or {})
    total = p.get("asset_count", 0)
    ok(stored <= CS.MAX_COMP_ASSETS,
       "%s: assets 存储数 %d <= 上限 %d" % (p["name"][:12], stored, CS.MAX_COMP_ASSETS))
    ok(total >= stored,
       "%s: asset_count(%d) >= assets 存储数(%d)，截断没把真实总数弄小"
       % (p["name"][:12], total, stored))
    if total > stored:
        ok(bool(p.get("assets_note")),
           "%s: 被截断时明确标注 assets_note" % p["name"][:12])
    # assets 里不能塞完整台账行（那是 604MB 的元凶）
    for sample in list((p.get("assets") or {}).values())[:1]:
        ok(len(sample) <= 6,
           "%s: assets 单条只存精简字段（%d 个字段）" % (p["name"][:12], len(sample)))

print("\n=== ④ 小数据集行为不变（不能为了修大数据的 bug 改坏正常路径）===")
tiny = build_db(os.path.join(tmp, "tiny.db"), 200)
r3 = CS.analyze(None, {"mode": "sqlite", "paths": [tiny]})
ok(bool(r3.get("ok")), "小库 analyze 成功", r3.get("error"))
p3 = (r3.get("report") or {}).get("risk", {}).get("products") or []
ok(len(p3) > 0, "小库有组件条目")
if p3:
    total_small = p3[0].get("asset_count", 0)
    ok(total_small == len(p3[0].get("assets") or {}),
       "小库不触发截断（%d == %d）" % (total_small, len(p3[0].get("assets") or {})))

import shutil
shutil.rmtree(tmp, ignore_errors=True)

print("\n" + "=" * 62)
print("合计 %d 项，通过 %d，失败 %d"
      % (_PASS[0] + _FAIL[0], _PASS[0], _FAIL[0]))
sys.exit(1 if _FAIL[0] else 0)