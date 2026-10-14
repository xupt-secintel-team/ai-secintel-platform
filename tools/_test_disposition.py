# -*- coding: utf-8 -*-
"""处置闭环回填（DispositionStore）离线测试。

验证「越用越聪明」的机制：
  1. 回填记录：record 规范化、非法 status 拒绝
  2. 同 CVE 秒判：for_cve / boost.same_cve
  3. 同组件自动关联：for_component / boost.related
  4. 落盘持久化 + 统计
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules", "m0_ops", "backend"))

from disposition import DispositionStore, STATUS_LABELS

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}  {detail}")


tmp = tempfile.mkdtemp(prefix="asi_disp_")
store = DispositionStore(tmp)

print("=== ① 回填记录 ===")
r = store.record("CVE-2026-9198", "resolved", component="ollama", note="已升级到 0.1.34", actor="张洺豪")
check("合法回填返回 ok", r.get("ok") is True)
check("回填状态标签映射", r["record"]["status_label"] == "已修复", r.get("record"))

r2 = store.record("", "resolved")
check("缺 CVE 拒绝", r2.get("ok") is False)

r3 = store.record("CVE-2026-9198", "hacked")
check("非法 status 拒绝", r3.get("ok") is False)

print("\n=== ② 同 CVE 秒判 ===")
store.record("CVE-2026-9198", "verified", component="ollama", note="复测通过")
sc = store.for_cve("CVE-2026-9198")
check("同 CVE 两条处置记录", len(sc) == 2, len(sc))
check("最新在前", sc[0]["status"] == "verified", sc[0].get("status"))

boost = store.boost("CVE-2026-9198", ["ollama"])
check("boost.same_cve 命中", boost["same_cve"] is True)
check("秒判提示含『已处置』语义", "已" in boost["hint"], boost["hint"])

print("\n=== ③ 同组件自动关联 ===")
store.record("CVE-2026-0770", "resolved", component="ollama", note="同组件另一漏洞")
store.record("CVE-2025-68613", "resolved", component="nginx")
rel = store.for_component("ollama")
check("同组件关联到 2 条（9198 的 ollama + 0770 的 ollama）",
      len([x for x in rel if x["cve"] in ("CVE-2026-9198", "CVE-2026-0770")]) >= 2, len(rel))

# 决策时：一个新 CVE，但组件是 ollama → 应带出参照
boost_new = store.boost("CVE-2099-0001", ["ollama"])
check("新 CVE 但同组件 → 带出 related 参照", len(boost_new["related"]) >= 1, len(boost_new["related"]))
check("related 不含自身", all(x["cve"] != "CVE-2099-0001" for x in boost_new["related"]))
check("同组件提示含『同组件』语义", "同组件" in boost_new["hint"], boost_new["hint"])

print("\n=== ④ 无关联时 ===")
boost_empty = store.boost("CVE-2099-9999", ["nothing_matches"])
check("无关联 → same_cve=False 且 related 空",
      not boost_empty["same_cve"] and not boost_empty["related"])

print("\n=== ④b 组件名归一化匹配（关键） ===")
# 回填侧存纯组件名「langflow/langflow」，决策侧提取带版本区间「langflow/langflow（≥1.0.0，<1.10.1）」
store.record("CVE-2026-0770", "resolved", component="langflow/langflow", note="同组件")
boost_norm = store.boost("CVE-2026-9999", ["langflow/langflow（≥ 1.0.0，< 1.10.1）"])
check("带版本区间的组件名能匹配到纯组件名记录",
      len(boost_norm["related"]) >= 1, len(boost_norm["related"]))
check("归一化后 related 含同组件 CVE-2026-0770",
      any(r["cve"] == "CVE-2026-0770" for r in boost_norm["related"]),
      [r["cve"] for r in boost_norm["related"]])

print("\n=== ⑤ 统计与持久化 ===")
all_recs = store.all(100)
check("落盘记录总数正确", len(all_recs) == 5, len(all_recs))

# 重新实例化（模拟重启）验证持久化
store2 = DispositionStore(tmp)
check("重启后记录仍在（持久化）", len(store2.all(100)) == 5)

shutil.rmtree(tmp, ignore_errors=True)

print(f"\n结果：通过 {PASS} / 失败 {FAIL}")
sys.exit(1 if FAIL else 0)
