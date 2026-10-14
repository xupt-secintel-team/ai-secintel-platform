# -*- coding: utf-8 -*-
"""_test_hardening_round8.py —— 第 8 轮：4 项「有产物/能答对」修复的固化回归

本轮针对用户列出的 8 项问题中**可修且已修**的部分做回归：
  A. 【高】多智能体 0 产物 —— 感知闸门从「仅 KEV/CVSS≥9」扩为多路判据；
  B. 【高】LLM 路径 —— GET 与 POST 的 LLM 配置必须一致（GET 原先永远模板）；
  C. 【中】追问路由 —— 泛指修复意图（"这些漏洞怎么修"）不再答「知识库无匹配」；
  D. 【低】/api/live recent —— 启动回放要一并回填实时区。

覆盖两个维度：
  · **行为级**（真跑函数/真打接口）—— 能变的行为；
  · **源码级**（读源码断言关键调用存在）—— 需要 HTTP 请求对象、或行为依赖
    运行时环境的部分（如 handle_chat_get 的 req 对象），静态断言是这里唯一
    可行的固化手段。写源码断言时**只截取目标函数体**，避免误判别的函数。

用法： py tools/_test_hardening_round8.py
"""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
try:
    import loopback
    loopback.enable()
except Exception:  # noqa: BLE001
    pass
sys.path.insert(0, os.path.join(ROOT, "modules", "m0_ops", "backend"))
sys.path.insert(0, os.path.join(ROOT, "modules", "m3_qa", "backend"))

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f" —— {detail}" if detail else ""))


def _seg(path, start, end):
    """截取源码中 start 函数到 end 函数之间的片段（避免跨函数误判）。"""
    src = open(path, encoding="utf-8").read()
    i = src.find(start)
    if i < 0:
        return ""
    j = src.find(end, i) if end else len(src)
    return src[i:j if j > 0 else len(src)]


# ── A. 感知闸门：多路判据 ────────────────────────────────────────────
print("\n=== A. 感知闸门多路判据（多智能体 0 产物） ===")
try:
    from orchestrator import PerceptionAgent, TraceRecorder, _URGENT_RE, _CVE_MENTION_RE

    # A1. 正则边界：RCE 不得命中 Resource/Source/Force（实测踩过：17 条 arXiv 误报）
    check("A1 RCE 不误报 Resource", not _URGENT_RE.search(
        "Agentic Semantic Sensing for Resource-Adaptive AI-RAN"))
    check("A2 RCE 不误报 Source", not _URGENT_RE.search("Source code review"))
    check("A3 RCE 命中独立写法", bool(_URGENT_RE.search("某组件 RCE 漏洞")))
    check("A4 0Day 命中", bool(_URGENT_RE.search("32个0Day攻破三星S26")))
    check("A5 CVE 编号可抽", _CVE_MENTION_RE.findall("见 CVE-2026-21589 详情") == ["CVE-2026-21589"])

    feed = os.path.join(ROOT, "data", "live_feed.jsonl")
    if os.path.isfile(feed):
        st = os.path.join(tempfile.gettempdir(), "_r8_seen.json")
        if os.path.exists(st):
            os.remove(st)
        agent = PerceptionAgent(feed, st, TraceRecorder())
        evs = agent.scan()
        check("A6 真实 feed 能筛出事件（旧判据恒 0）", len(evs) > 0,
              f"筛出 {len(evs)} 条")
        check("A7 每条事件都带入选原因", all(e.get("reasons") for e in evs))
        check("A8 每条事件都带优先级", all(isinstance(e.get("priority"), int) for e in evs))
        check("A9 论文不进「紧急关键词」类",
              all(not (str(e.get("id", "")).startswith("ARXIV:")
                       and e.get("reasons") == ["紧急关键词"]) for e in evs))
        check("A10 有 CVE 的事件填了 cve 字段",
              all(e.get("cve") for e in evs if "cve提及" in (e.get("reasons") or [])))
        os.path.exists(st) and os.remove(st)
    else:
        check("A6 真实 feed 存在", False, "data/live_feed.jsonl 缺失")
except Exception as e:  # noqa: BLE001
    check("A 感知闸门导入/执行", False, str(e)[:200])

# ── B. 富化必须用 CVE 编号而非 live 条目 id ──────────────────────────
print("\n=== B. 富化实体（live id → CVE 编号） ===")
try:
    seg = _seg(os.path.join(ROOT, "modules", "m0_ops", "backend", "orchestrator.py"),
               "class EnrichExecutor", "class BriefAnalyst")
    check("B1 富化取 event.cve 优先", 'event.get("cve") or event["id"]' in seg)
    check("B2 404 区分「不在库」", 'in_kb' in seg and "404" in seg)
    seg2 = _seg(os.path.join(ROOT, "modules", "m0_ops", "backend", "orchestrator.py"),
                "class DecisionAgent", "class ChallengerAgent")
    check("B3 决策卡用 CVE 编号", '"cve": event.get("cve") or event["id"]' in seg2)
    check("B4 决策卡保留 event_id 可追溯", '"event_id": event["id"]' in seg2)
except Exception as e:  # noqa: BLE001
    check("B 源码断言", False, str(e)[:200])

# ── C. LLM 配置：GET 与 POST 一致 ────────────────────────────────────
print("\n=== C. LLM 路径（GET 读环境配置） ===")
try:
    seg = _seg(os.path.join(ROOT, "modules", "m3_qa", "api.py"),
               "def handle_chat_get", "def handle_chat_post")
    check("C1 GET 读 env_llm_config()", "env_llm_config()" in seg)
    check("C2 GET 仍支持 no_llm 强制模板", "disable_llm" in seg)
    seg_p = _seg(os.path.join(ROOT, "modules", "m3_qa", "api.py"),
                 "def handle_chat_post", "def handle_qa_status")
    check("C3 POST 也读 env_llm_config()", "env_llm_config()" in seg_p)
    seg_s = _seg(os.path.join(ROOT, "modules", "m3_qa", "api.py"),
                 "def handle_qa_status", "def handle_chat_get")
    check("C4 qa/status 给出空 Key 明确提示", "env_key_hint" in seg_s)
    check("C5 提示区分「已填未读到」与「为空」",
          "已填" in seg_s and "为空" in seg_s)
except Exception as e:  # noqa: BLE001
    check("C 源码断言", False, str(e)[:200])

# ── D. 追问路由：泛指修复意图兜底 ────────────────────────────────────
print("\n=== D. 追问路由（泛指修复意图） ===")
try:
    from qa.deep_answer import _FIX_Q_RE, CVE_RE, latest_high_risk_docs  # noqa: F401

    check("D1 修复意图正则命中「修复建议」", bool(_FIX_Q_RE.search("给出修复建议")))
    check("D2 无实体判定：句内无 CVE", not CVE_RE.search("这些漏洞应该怎么修复？"))
    seg = _seg(os.path.join(ROOT, "modules", "m3_qa", "backend", "qa", "__init__.py"),
               "2a. 泛指修复意图兜底", "# 2b. 端到端预算")
    check("D3 chat() 含兜底分支", "latest_high_risk_docs" in seg)
    check("D4 兜底仅在零命中时触发", "if not docs:" in seg)
    check("D5 兜底留痕 query_fallback", "query_fallback" in seg)
except Exception as e:  # noqa: BLE001
    check("D 源码断言", False, str(e)[:200])

# ── E. 实时区 recent 启动回填 ────────────────────────────────────────
print("\n=== E. /api/live recent 启动回填 ===")
try:
    seg = _seg(os.path.join(ROOT, "modules", "m1_monitor", "api.py"),
               "def _live_replay", "def _live_poll_once")
    check("E1 回放函数回填 LIVE['recent']", 'LIVE["recent"]' in seg)
    check("E2 回填标注 replay 以便区分", "replay" in seg)
    check("E3 只在 recent 为空时回填（不覆盖实时新增）", 'if not LIVE.get("recent")' in seg)
except Exception as e:  # noqa: BLE001
    check("E 源码断言", False, str(e)[:200])

# ── F. 时效性报告：双口径成因分解 ────────────────────────────────────
print("\n=== F. 时效性报告按源分层 ===")
try:
    src = open(os.path.join(ROOT, "tools", "评测时效性.py"), encoding="utf-8").read()
    check("F1 含成因分解段", "成因分解" in src)
    check("F2 按来源类型分层", "_srckind" in src)
    md = os.path.join(ROOT, "测试报告", "时效性实测.md")
    if os.path.isfile(md):
        txt = open(md, encoding="utf-8").read()
        check("F3 报告已含分层表", "成因分解" in txt and "学术论文（arXiv）" in txt)
    else:
        check("F3 报告存在", False, "测试报告/时效性实测.md 缺失")
except Exception as e:  # noqa: BLE001
    check("F 时效性报告", False, str(e)[:200])

print("\n" + "=" * 62)
print(f"  通过 {PASS} · 失败 {FAIL} · 跳过 0")
print("=" * 62)
sys.exit(1 if FAIL else 0)
