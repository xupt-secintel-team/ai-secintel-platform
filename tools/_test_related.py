# -*- coding: utf-8 -*-
"""build_related（个性化推荐）离线桩测试：不联网，用桩替换 _engine_search。"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "modules", "m3_qa", "backend"))

passed = failed = 0
def check(cond, name, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}  {extra}")

# ── 桩：伪造 qa.retriever._engine_search，按查询返回确定性结果 ──
CALLS = []
def fake_engine_search(query, size):
    CALLS.append((query, size))
    # 返回一批可裁剪成卡片的最小字段
    base = {
        "product:ollama severity:CRITICAL,HIGH": [
            {"id": "CVE-2025-63389", "title": "Ollama RCE", "cvss": {"score": 9.8, "severity": "CRITICAL"},
             "exploited": True, "poc_links": ["x"], "cwe": ["CWE-77"], "products": ["ollama"], "published": "2025-05-01"},
            {"id": "CVE-2024-37032", "title": "Ollama path traversal", "cvss": {"score": 8.8, "severity": "HIGH"},
             "exploited": True, "poc_links": [], "cwe": ["CWE-22"], "products": ["ollama"], "published": "2024-06-01"},
        ],
        "cwe:CWE-22": [
            {"id": "CVE-2024-99999", "title": "Generic traversal", "cvss": {"score": 7.5, "severity": "HIGH"},
             "exploited": False, "poc_links": [], "cwe": ["CWE-22"], "products": ["app"], "published": "2024-01-01"},
        ],
        "kev:yes severity:CRITICAL": [
            {"id": "CVE-2026-00001", "title": "Hot KEV", "cvss": {"score": 10.0, "severity": "CRITICAL"},
             "exploited": True, "poc_links": ["x"], "cwe": ["CWE-94"], "products": ["foo"], "published": "2026-01-01"},
        ],
    }
    return base.get(query, [])

# 注入桩
import qa.report as R
import qa.retriever as RT
RT._engine_search = fake_engine_search

print("=== ① 空证据池 → 仅实时热点兜底 ===")
out = R.build_related("最近有什么高危漏洞？", [], {})
check(isinstance(out, list), "返回列表")
check(len(out) > 0 and out[0]["reason"] == "当前在野利用高危热点", "空证据池回退到热点", str(out))
check(all("reason" in c and "id" in c and "severity" in c for c in out), "每张卡片字段完整")

print("=== ② 含 ollama 组件 → 同组件推荐优先 ===")
docs = [{"id": "CVE-2025-63389", "products": ["ollama"], "cwe": ["CWE-77"],
         "cvss": {"score": 9.8, "severity": "CRITICAL"}, "exploited": True, "poc_links": ["x"]}]
CALLS.clear()
out = R.build_related("ollama 有什么漏洞？", docs, {})
check(len(out) > 0, "有推荐", str(out))
# 证据池里已有 CVE-2025-63389，不应再推荐它自己
ids = [c["id"] for c in out]
check("CVE-2025-63389" not in ids, "不推荐证据池已含的条目", str(ids))
# 应推荐到同组件 CVE-2024-37032
check("CVE-2024-37032" in ids, "推荐同组件其它漏洞", str(ids))
# 首次调用应是组件查询
check(any("product:ollama" in q for q, _ in CALLS), "触发同组件检索", str(CALLS))

print("=== ③ 上限 6 条 + 去重 ===")
big = []
# 构造大量同组件结果，验证上限与去重
many = [{"id": f"CVE-202X-{i:05d}", "products": ["ollama"], "cvss": {"score": 9.0, "severity": "CRITICAL"},
         "cwe": ["CWE-77"], "exploited": False, "poc_links": [], "published": "2026-01-01"} for i in range(20)]
def fake_many(query, size):
    return many[:size]
RT._engine_search = fake_many
out = R.build_related("ollama 漏洞", [], {})
check(len(out) <= 6, "推荐不超过 6 条", str(len(out)))
check(len({c["id"] for c in out}) == len(out), "无重复 id", str(out))

print(f"\n结果：{passed} 通过 / {failed} 失败")
sys.exit(1 if failed else 0)
