# -*- coding: utf-8 -*-
"""
_test_remediation.py —— 修复方案生成测试（离线、可复跑）
=========================================================================
覆盖：
  ① 信号收集：CWE/CPE 区间/KEV/CVSS/补丁链接 → 结构化信号
  ② 模板模式（无 Key）：升级路径、CWE 加固映射、AV:N 收敛、KEV 时限、验证、NVD 链接
  ③ 缓存：命中 cached=True；force=1 重新生成
  ④ LLM 输出归一化：宽松 JSON 提取 + 脏字段丢弃；无 Key 时 _llm_plan 返回 None
  ⑤ Markdown 导出

用法： py tools/_test_remediation.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import remediation as RM  # noqa: E402

FAILS = []
OKS = []


def check(cond, label, extra=""):
    (OKS if cond else FAILS).append(label)
    print("  %s %s%s" % ("[PASS]" if cond else "[FAIL]", label,
                         ("  → " + str(extra)) if (extra and not cond) else ""))


RECORD = {
    "id": "CVE-2026-12345",
    "title": "Demo ERP SQL 注入漏洞（未认证）",
    "desc": "A SQL injection vulnerability in /api/users of Demo ERP 3.0.0 through 3.2.1 "
            "allows unauthenticated attackers to execute arbitrary SQL commands.",
    "cwe": [{"id": "CWE-89", "name": "Improper Neutralization of Special Elements used in an SQL Command"}],
    "cpe": [{"vendor": "demoerp", "product": "erp", "version": "*",
             "start_incl": "3.0.0", "start_excl": None,
             "end_incl": None, "end_excl": "3.2.2"}],
    "cvss": {"score": 9.8, "severity": "CRITICAL",
             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    "kev": {"exploited": True, "date_added": "2026-09-30", "due_date": "2026-10-21",
            "required_action": "Apply updates per vendor instructions.",
            "short_desc": "x"},
    "patch_links": ["https://example.com/advisory/123"],
    "advisory_links": [],
    "refs": [{"url": "https://example.com/poc", "tags": []}],
    "remediation": ["官方建议升级至 3.2.2 及以上。"],
}

# 缓存指向临时目录，不污染真实 data/
RM.CACHE_PATH = os.path.join(tempfile.mkdtemp(prefix="remtest_"), "remediation_cache.json")

print("\n=== ① 信号收集 ===")
sig = RM.build_signals(RECORD)
check(sig["cve"] == "CVE-2026-12345" and sig["severity"] == "CRITICAL", "基础字段")
check(sig["cwes"] == ["CWE-89 Improper Neutralization of Special Elements used in an SQL Command"],
      "CWE 编号+名称", sig["cwes"])
check(any("≥ 3.0.0" in a and "< 3.2.2" in a for a in sig["affected"]), "版本区间翻译成人话",
      sig["affected"])
check(sig["kev"] is True and sig["kev_due"] == "2026-10-21", "KEV 状态与时限")
check("https://example.com/advisory/123" in sig["references"], "补丁链接进入参考")

print("\n=== ② 模板模式（无 Key）===")
for k in ("AISEC_LLM_API_KEY", "DEEPSEEK_API_KEY"):
    os.environ.pop(k, None)
import poc_scraper as PS  # noqa: E402
try:
    _cfg = PS.load_config()
    if isinstance(_cfg, dict):
        _cfg["deepseek_api_key"] = ""
        PS.save_config(_cfg) if hasattr(PS, "save_config") else None
except Exception:
    pass

out = RM.generate("CVE-2026-12345", FakeEngine := type("E", (), {"detail": staticmethod(lambda cid: RECORD)})())
check(out.get("ok") is True, "generate ok")
plan = out.get("plan") or {}
check(plan.get("generated_by") == "template", "无 Key → 模板模式")
check(bool(plan.get("summary")), "有概要")
check(any("3.0.0" in u.get("component", "") for u in plan.get("upgrade") or []),
      "升级路径带受影响区间", plan.get("upgrade"))
cfgs = {c.get("item") for c in plan.get("config") or []}
check(any("SQL 注入" in (i or "") for i in cfgs), "CWE-89 → SQL 参数化加固项", cfgs)
check(any("暴露面收敛" in (i or "") for i in cfgs), "AV:N → 暴露面收敛项")
check(any("在野利用" in m and "2026-10-21" in m for m in plan.get("mitigations") or []),
      "KEV 缓解含处置截止日期")
check(len(plan.get("verify") or []) == 3, "验证方法三条", len(plan.get("verify") or []))
check(any("nvd.nist.gov" in r for r in plan.get("references") or []), "参考含 NVD 链接")
check(plan.get("risk", {}).get("kev") is True, "risk 摘要随行")

print("\n=== ③ 缓存 ===")
out2 = RM.generate("CVE-2026-12345", FakeEngine)
check((out2.get("plan") or {}).get("cached") is True, "二次调用命中缓存")
out3 = RM.generate("CVE-2026-12345", FakeEngine, force=True)
check((out3.get("plan") or {}).get("cached") is None, "force=1 重新生成")
with open(RM.CACHE_PATH, "r", encoding="utf-8") as f:
    check("CVE-2026-12345" in f.read(), "缓存文件落盘")

print("\n=== ④ LLM 路径归一化 ===")
llm_raw = """模型废话开头
```json
{"summary": "升级并收紧鉴权。", 
 "upgrade": [{"component": "demoerp/erp < 3.2.2", "target": "≥ 3.2.2", "note": "备份后再升"},
              {"component": "", "target": "垃圾项应被丢弃"}],
 "config": [{"item": "关闭公网注册接口", "detail": "网关拦截 /api/register", "code": "location /api/register { deny all; }"},
             {"detail": "缺 item 的垃圾项"},
             "完全不是对象的垃圾"],
 "mitigations": [{"text": "先下线"}],
 "verify": ["复测利用路径"], "references": ["https://nvd.nist.gov"],
 "confidence": "high"}
```
结尾废话"""
parsed = RM._parse_json_tolerant(llm_raw)
check(isinstance(parsed, dict) and parsed.get("summary"), "宽松 JSON 提取（带围栏与杂质）")
norm = RM._normalize(parsed)
check(len(norm["upgrade"]) == 1 and norm["upgrade"][0]["target"] == "≥ 3.2.2",
      "脏 upgrade 项被丢弃")
check(len(norm["config"]) == 1 and "deny all" in norm["config"][0]["code"],
      "非对象/缺字段 config 被丢弃")
check(norm["mitigations"] == ["先下线"], "mitigations 拍平成字符串数组")

check(RM._llm_plan(sig, {"api_key": "", "base_url": "https://x", "model": "m"}) is None,
      "无 Key 时 _llm_plan 直接返回 None（不外呼）")
_llm_sig = RM.build_signals(RECORD)
_none = RM._parse_json_tolerant("完全没有 JSON")
check(_none is None, "纯文本 → 解析失败返回 None")

print("\n=== ⑤ Markdown 导出 ===")
md = RM.plan_to_markdown(plan)
check("## 升级路径" in md and "## 配置 / 代码级加固" in md, "导出含主要章节")
check("```" in md and "location / {" in md, "代码块保留")
check("模板模式" in md, "生成方式显式标注")
check("上线前请结合官方公告核对" in md, "免责声明随行")

print("\n" + "=" * 56)
print("PASS %d / FAIL %d" % (len(OKS), len(FAILS)))
if FAILS:
    for f in FAILS:
        print("  FAIL:", f)
    sys.exit(1)
print("REMEDIATION TEST OK")
