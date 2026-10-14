# -*- coding: utf-8 -*-
"""_test_ticket_xlsx.py —— 简略台账（.xlsx）导出的离线测试

为什么必须补这一个：2026-10-06 之前，**全仓库没有任何一处测过 build_xlsx**。
邮件测试（_test_mailer.py）用的是自己造的假报告，字段类型干净，踩不到真实数据的坑。
结果真实 CMDB 报告里 200/200 条工单的 sla_days 都是 "8 天" 这种带单位字符串，
而 build_xlsx 里是裸 `int(...)` —— **导出 100% 失败**，前端只显示
「简略台账生成失败：invalid literal for int() with base 10: '8 天'」。

这里钉住四件事：
  ① 脏数据（带单位的字符串 / None / 负数 / 布尔 / 乱码）不能让整份导出失败
  ② 结构契约：四个 sheet、行数与工单数一致
  ③ 脱敏真的作用到数据上（与七章制正文同一套规则），且 off 时不动原文
  ④ 去重键含资产数、责任人兜底、空报告都不崩

用法： python tools/_test_ticket_xlsx.py
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "core"),
           os.path.join(ROOT, "modules", "m2_enrich", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
os.chdir(ROOT)

import cmdb_ticket_xlsx as TX  # noqa: E402

PASS = [0]
FAIL = []


def ck(cond, label, extra=""):
    if cond:
        PASS[0] += 1
        print("  [ ok ] %s" % label)
    else:
        FAIL.append(label)
        print("  [FAIL] %s  %s" % (label, extra))


def mk_rep(pri=None, meta=None):
    if pri is None:
        pri = [
            {"cve": "CVE-2024-1111", "component": "openssl", "severity": "Critical",
             "cvss": 9.8, "score": 9.5, "asset_count": 2, "internet_count": 1,
             "owners": ["zhangsan"], "sla_days": "8 天", "status": "未修复",
             "plan_fix": [], "remediation": ["升级到 3.0.13；先检查 10.20.30.40 配置"],
             "url": "https://example.invalid/CVE-2024-1111"},
            {"cve": "CVE-2024-2222", "component": "nginx", "severity": "High",
             "cvss": 8.1, "score": 8.0, "asset_count": 5, "internet_count": 5,
             "owners": [], "hosts": ["web01"], "sla_days": "15 天", "status": "修复中",
             "remediation": ["升级 nginx"]},
        ]
    return {
        "id": "CMDB-TEST-0001",
        "created_at": "2026-10-06 12:00:00",
        "priority": pri,
        "meta": meta if meta is not None else [{"host": "web01", "owner": "lisi"}],
    }


def sheet_rows(b, name):
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(b))
    ws = wb[name]
    return [[c for c in row] for row in ws.iter_rows(values_only=True)], wb


print("== ① 真实数据形态：sla_days 是「8 天」这种字符串 ==")
rep = mk_rep()
try:
    b = TX.build_xlsx(rep, "basic")
    ck(True, "带单位的 sla_days 不再让导出崩掉")
except Exception as e:  # noqa: BLE001
    b = b""
    ck(False, "带单位的 sla_days 不再让导出崩掉", "%s: %s" % (type(e).__name__, e))
ck(len(b) > 2000, "产出的 xlsx 有实际内容（%d 字节）" % len(b))

print("\n== ② 结构契约 ==")
rows, wb = sheet_rows(b, "工单明细")
ck(set(["风险等级统计", "按责任人分派", "工单明细", "说明"]).issubset(set(wb.sheetnames)),
   "四个 sheet 齐全", wb.sheetnames)
ck(len(rows) == 3, "工单明细 = 表头 + 2 条工单", "%d 行" % len(rows))
hdr = list(rows[0])
ck("SLA(天)" in hdr and "责任人" in hdr, "表头含 SLA(天) / 责任人", hdr[:6])
sla_col = hdr.index("SLA(天)")
ck(rows[1][sla_col] == 8, "「8 天」被解析成数字 8", repr(rows[1][sla_col]))
ck(rows[2][sla_col] == 15, "「15 天」被解析成数字 15", repr(rows[2][sla_col]))

print("\n== ③ 脏数据矩阵（整份导出不许失败）==")
dirty = [
    {"cve": "CVE-D-1", "component": "a", "severity": "High", "asset_count": None,
     "internet_count": "", "sla_days": None},
    {"cve": "CVE-D-2", "component": "b", "severity": "Medium", "asset_count": "3 台",
     "internet_count": "1 个", "sla_days": "30天"},
    {"cve": "CVE-D-3", "component": "c", "severity": "Low", "asset_count": -1,
     "internet_count": 3.7, "sla_days": 0},
    {"cve": "CVE-D-4", "component": "d", "severity": "未知等级", "asset_count": True,
     "internet_count": "abc", "sla_days": "未定义"},
    {"cve": "CVE-D-5", "component": "e", "severity": "", "asset_count": "10.5",
     "internet_count": None, "sla_days": "60 天（监管）"},
]
try:
    b2 = TX.build_xlsx(mk_rep(pri=dirty), "basic")
    ck(True, "五种脏数据组合全部导出成功（%d 字节）" % len(b2))
    r2, _ = sheet_rows(b2, "工单明细")
    ck(len(r2) == len(dirty) + 1, "脏数据也一条不丢地进了台账", "%d 行" % len(r2))
    col = list(r2[0]).index("SLA(天)")
    ck(all(isinstance(row[col], int) for row in r2[1:]),
       "SLA 列全是整数（不会把「未定义」原样塞进去）",
       [row[col] for row in r2[1:]])
except Exception as e:  # noqa: BLE001
    ck(False, "五种脏数据组合全部导出成功", "%s: %s" % (type(e).__name__, e))

print("\n== ④ 空报告 / 畸形输入不崩 ==")
for label, repx in (
    ("priority 为空列表", mk_rep(pri=[])),
    ("priority 为 None", {"id": "X", "created_at": "2026-10-06", "priority": None}),
    ("priority 元素不是 dict", mk_rep(pri=[None, "文本", 123, {"cve": "CVE-OK"}])),
    ("整个报告为空 dict", {}),
    ("meta 是脏的", mk_rep(meta=[None, {"host": None}, {"owner": "x"}, "str"])),
):
    try:
        bx = TX.build_xlsx(repx, "basic")
        ck(len(bx) > 500, "%s → 正常产出" % label)
    except Exception as e:  # noqa: BLE001
        ck(False, "%s → 正常产出" % label, "%s: %s" % (type(e).__name__, e))

print("\n== ⑤ 脱敏真的作用到数据（与正文同一套规则）==")
b3 = TX.build_xlsx(mk_rep(), "off")
r_off, _ = sheet_rows(b3, "工单明细")
flat_off = " ".join(str(c) for row in r_off for c in row if c)
ck("10.20.30.40" in flat_off, "off 级别保留原始 IP（不该偷偷改数据）")

b4 = TX.build_xlsx(mk_rep(), "basic")
r_b, _ = sheet_rows(b4, "工单明细")
flat_b = " ".join(str(c) for row in r_b for c in row if c)
ck("10.20.30.40" not in flat_b, "basic 级别下 IP 已被处理", flat_b[:80])
ck("10.20.30.x" in flat_b, "basic 级别按「前三段.x」规则脱敏")
ck(flat_b != flat_off, "脱敏级别不同 → 产出的内容确实不同")

import openpyxl  # noqa: E402

wb4 = openpyxl.load_workbook(io.BytesIO(b4))
note_txt = " ".join(str(c) for row in wb4["说明"].iter_rows(values_only=True)
                    for c in row if c)
ck("脱敏" in note_txt, "说明页仍写明脱敏级别")
ck("已按" in note_txt or "全表" in note_txt, "说明页文案与「真的脱敏了」一致",
   note_txt[-120:])

print("\n== ⑥ 去重与责任人兜底 ==")
dup = [
    {"cve": "CVE-SAME", "component": "x", "severity": "High", "asset_count": 3},
    {"cve": "CVE-SAME", "component": "x", "severity": "High", "asset_count": 3},
    {"cve": "CVE-SAME", "component": "x", "severity": "High", "asset_count": 9},
]
rd, _ = sheet_rows(TX.build_xlsx(mk_rep(pri=dup), "basic"), "工单明细")
ck(len(rd) - 1 == 2, "同 (CVE,组件,资产数) 去重，资产数不同者保留（2 条）", "%d 条" % (len(rd) - 1))

fallback = [{"cve": "CVE-F", "component": "y", "severity": "High",
             "hosts": ["web01"], "asset_count": 1}]
rf, _ = sheet_rows(TX.build_xlsx(mk_rep(pri=fallback), "basic"), "工单明细")
owner_col = list(rf[0]).index("责任人")
ck(rf[1][owner_col] == "lisi", "工单无 owners 时按 host 从 meta 反查责任人",
   repr(rf[1][owner_col]))

print("\n== ⑦ _to_int 单元行为 ==")
cases = [("8 天", 8), ("30天", 30), ("", 0), (None, 0), (7, 7), (3.9, 3),
         (True, 0), ("abc", 0), ("-5 天", -5), ("第 12 名", 12)]
bad = []
for v, want in cases:
    got = TX._to_int(v)
    if got != want:
        bad.append("%r→%r(期望%r)" % (v, got, want))
ck(not bad, "_to_int 对 10 种输入都符合预期", "; ".join(bad))

print()
print("通过 %d 项，失败 %d 项" % (PASS[0], len(FAIL)))
for f in FAIL:
    print("  -", f)
sys.exit(1 if FAIL else 0)
