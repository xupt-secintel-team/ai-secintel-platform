# -*- coding: utf-8 -*-
"""
api.py —— 模块0「智能编排」后端入口（v2.2 新增）
============================================================
负责人：组长
职责：事件驱动的多智能体编排 —— 感知（盯实时情报流）→ 编排（定优先级/限流分派）
      → 富化执行（资产定位 + POC 缓存）→ 研判（简报生成），全程 trace 留痕。

本模块对外接口（启动时自动注册进主体，无需改 core/server.py）：
    GET  /api/ops/status     编排器状态（四个智能体、节拍、阈值、最近一轮）
    GET  /api/ops/events     事件流水（最近 50 条：发现/处置/失败）
    GET  /api/ops/briefs     研判简报（最近 N 条，?n=20）
    POST /api/ops/scan_now   人工触发一轮编排（演示/自测用）
    GET  /api/ops/trace      智能体协作留痕（谁、何时、做了什么、成败、耗时）

实现全部在本模块 backend/orchestrator.py；只通过本机 HTTP 回访复用其他模块能力，
不 import 任何其他模块的代码（遵守「模块间互不 import」硬性约定）。
"""
from __future__ import annotations

import json
import os
import time
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

_ORT = None


def _orchestrator(ctx):
    global _ORT
    if _ORT is None:
        from orchestrator import Orchestrator
        cfg = {}
        try:
            cfg = dict(ctx.core.config or {})
        except Exception as _sw_e:  # noqa: BLE001
            _swallow("modules/m0_ops/api.py:34", _sw_e)
        _ORT = Orchestrator(ctx.data_dir, cfg)
    return _ORT


def handle_tools(req):
    """GET /api/ops/tools —— 智能体工具注册表清单。

    可扩展性的可核验证据：新增能力只是往注册表里加一项，
    这里就会多一条（名称 / 说明 / 超时 / 本地或 HTTP）。
    """
    import orchestrator as O
    tools = O.tool_manifest()
    return req.json({"ok": True, "count": len(tools), "tools": tools,
                     "registry_size": len(O.TOOLS)})


def handle_status(req):
    return req.json(_orchestrator(_CTX[0]).status())


def handle_events(req):
    ort = _orchestrator(_CTX[0])
    data = []
    try:
        with open(ort.events_fp, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m0_ops/api.py:50", _sw_e)
    return req.json({"count": len(data), "events": list(reversed(data[-50:]))})


def handle_briefs(req):
    ort = _orchestrator(_CTX[0])
    n = req.q_int("n") or 20
    data = []
    try:
        with open(ort.briefs_fp, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m0_ops/api.py:62", _sw_e)
    return req.json({"count": len(data), "briefs": list(reversed(data[-n:]))})


def handle_scan_now(req):
    ort = _orchestrator(_CTX[0])
    try:
        result = ort.cycle(manual=True)
        return req.json({"ok": True, **result})
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)}, 500)


def handle_trace(req):
    ort = _orchestrator(_CTX[0])
    n = req.q_int("n") or 50
    return req.json({"trace": ort.trace.list(n)})


def handle_decisions(req):
    """GET /api/ops/decisions —— 处置决策卡（决策智能体产出，最近 N 条）。"""
    ort = _orchestrator(_CTX[0])
    n = req.q_int("n") or 20
    data = []
    try:
        with open(ort.decisions_fp, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m0_ops/api.py:handle_decisions", _sw_e)
    return req.json({"count": len(data), "decisions": list(reversed(data[-n:]))})


def _disposition_body(req):
    """从 body / query 里取回填参数。"""
    body = {}
    try:
        body = json.loads(req.body.decode("utf-8")) if req.body else {}
    except Exception:  # noqa: BLE001
        body = {}
    def pick(*keys):
        for k in keys:
            v = body.get(k)
            if v not in (None, ""):
                return v
        return req.q(k) or ""
    return pick


def handle_disposition_record(req):
    """POST /api/ops/disposition —— 处置结果回填（闭环·自我进化的入口）。

    body: {"cve": "...", "status": "resolved|verified|false_positive|ignored",
           "component": "可选", "note": "可选", "actor": "可选"}
    处置完（打补丁/验证/误报）后调用，回填进记忆库；下次同类漏洞决策时自动复用。
    """
    ort = _orchestrator(_CTX[0])
    if not ort.disposition:
        return req.json({"ok": False, "error": "回填记忆库不可用"}, 503)
    pick = _disposition_body(req)
    r = ort.disposition.record(
        cve=pick("cve", "id"),
        status=pick("status"),
        component=pick("component"),
        note=pick("note"),
        actor=pick("actor"),
    )
    return req.json(r, 200 if r.get("ok") else 400)


def handle_disposition_list(req):
    """GET /api/ops/disposition —— 处置记录列表（?n=50、?cve=...、?component=...）。"""
    ort = _orchestrator(_CTX[0])
    if not ort.disposition:
        return req.json({"ok": False, "error": "回填记忆库不可用"}, 503)
    cve = req.q("cve") or ""
    comp = req.q("component") or ""
    if cve:
        recs = ort.disposition.for_cve(cve)
    elif comp:
        recs = ort.disposition.for_component(comp)
    else:
        recs = ort.disposition.all(int(req.q_int("n") or 50))
    return req.json({"count": len(recs), "dispositions": recs})


def handle_disposition_stats(req):
    """GET /api/ops/disposition/stats —— 回填记忆库统计（「越用越聪明」的量化证据）。"""
    ort = _orchestrator(_CTX[0])
    if not ort.disposition:
        return req.json({"ok": False, "error": "回填记忆库不可用"}, 503)
    recs = ort.disposition.all(100000)
    from collections import Counter
    by_status = Counter(r.get("status") for r in recs)
    by_component = Counter(r.get("component") for r in recs if r.get("component"))
    return req.json({
        "ok": True,
        "total": len(recs),
        "by_status": dict(by_status),
        "by_component": dict(by_component.most_common(10)),
        "memory": "系统累计沉淀的处置经验（同 CVE 秒判 + 同组件自动关联）",
    })



def handle_decide_now(req):
    """POST /api/ops/decide_now —— 对单个 CVE 立即走一遍「富化→简报→决策」链路。

    演示/答辩用：现场输入一个 CVE，秒级看到决策智能体自主产出处置决策卡，
    证明「自主决策 + 任务编排 + 工具调用」不是纸面架构。body: {"id": "CVE-..."}
    """
    cid = (req.q("id") or "").strip().upper()
    if not cid:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
            cid = str(body.get("id") or "").strip().upper()
        except Exception:  # noqa: BLE001
            cid = ""
    if not cid:
        return req.json({"ok": False, "error": "缺少 CVE 编号（?id=CVE-... 或 body {\"id\":...}）"}, 400)
    ort = _orchestrator(_CTX[0])
    try:
        # 先查详情补真实 CVSS/KEV（否则 decide_now 构造的 event 缺信号，优先级判不准）
        ev = {"id": cid, "kind": "", "title": cid, "cvss": 0, "kev": False,
              "published": "", "detected_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        try:
            from orchestrator import _http as _ohttp
            detail = _ohttp("/api/detail", {"id": cid}, timeout=20)
            if detail and detail.get("id"):
                ev["title"] = detail.get("title") or cid
                ev["cvss"] = (detail.get("cvss") or {}).get("score") or 0
                kev = detail.get("kev")
                ev["kev"] = bool(kev.get("exploited")) if isinstance(kev, dict) else bool(kev)
                ev["published"] = str(detail.get("published") or "")[:32]
        except Exception:  # noqa: BLE001
            pass
        # 端到端计时：富化 → 简报 → 决策 三段各自耗时 + 总耗时（答辩「效果显著」量化证据）
        t_total = time.time()
        t0 = time.time()
        enrich = ort.enricher.run(ev)
        t_enrich = (time.time() - t0) * 1000
        t0 = time.time()
        brief = ort.analyst.make(ev, enrich)
        t_brief = (time.time() - t0) * 1000
        t0 = time.time()
        dec = ort.decision.make(ev, enrich)
        t_decision = (time.time() - t0) * 1000
        # 红蓝自博弈：质疑智能体挑战决策 → 收敛出更稳决策
        t0 = time.time()
        final_dec = ort.challenger.challenge(ev, enrich, dec["decision"])
        t_challenge = (time.time() - t0) * 1000
        t_all = (time.time() - t_total) * 1000
        return req.json({"ok": True, "id": cid, "brief": brief["text"],
                         "decision": final_dec, "mode": dec["mode"],
                         "perf": {
                             "enrich_ms": round(t_enrich, 1),
                             "brief_ms": round(t_brief, 1),
                             "decision_ms": round(t_decision, 1),
                             "challenge_ms": round(t_challenge, 1),
                             "total_ms": round(t_all, 1),
                         }})
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)}, 500)


def handle_attribution(req):
    """GET /api/ops/attribution?id=CVE-... —— 溯源归因（漏洞→利用者→ATT&CK 战术映射）。

    答辩演示用：输入一个 CVE，秒级看到「谁在利用 + 攻击链怎么走」，
    证明归因不是黑盒，每条推断都带可解释依据。
    """
    cid = (req.q("id") or "").strip().upper()
    if not cid:
        try:
            body = json.loads(req.body.decode("utf-8")) if req.body else {}
            cid = str(body.get("id") or "").strip().upper()
        except Exception:  # noqa: BLE001
            cid = ""
    if not cid:
        return req.json({"ok": False, "error": "缺少 CVE 编号（?id=CVE-...）"}, 400)
    try:
        from attribution import attribute as _attr
    except Exception:  # noqa: BLE001
        try:
            from modules.m0_ops.backend.attribution import attribute as _attr
        except Exception as e:
            return req.json({"ok": False, "error": f"归因模块不可用: {e}"}, 503)
    try:
        from orchestrator import _http as _ohttp
        detail = _ohttp("/api/detail", {"id": cid}, timeout=20)
        if not detail or not detail.get("id"):
            return req.json({"ok": False, "error": f"未找到 {cid}"}, 404)
        result = _attr(detail)
        return req.json({"ok": True, "id": cid, **result})
    except Exception as e:  # noqa: BLE001
        return req.json({"ok": False, "error": str(e)}, 500)


def start(core):
    """启动钩子：主体就绪后起编排守护线程（可用 config.json 的 ops_enabled=false 关闭）。"""
    try:
        ort = _orchestrator(_CTX[0])
        if ort.start():
            print(f"[m0_ops] 多智能体编排已启动：每 {ort.interval}s 一轮 · "
                  f"触发阈值 KEV 或 CVSS≥9 · 单轮≤{ort.max_per_cycle}事件")
        else:
            print("[m0_ops] 编排器被 config.json 关闭（ops_enabled=false）")
    except Exception as e:  # noqa: BLE001
        print(f"[m0_ops] 编排器启动失败（不影响主服务）：{e}")


_CTX = [None]


def register(ctx):
    _CTX[0] = ctx
    ctx.route("GET", "/api/ops/status", handle_status)
    ctx.route("GET", "/api/ops/tools", handle_tools)
    ctx.route("GET", "/api/ops/events", handle_events)
    ctx.route("GET", "/api/ops/briefs", handle_briefs)
    ctx.route("POST", "/api/ops/scan_now", handle_scan_now)
    ctx.route("GET", "/api/ops/trace", handle_trace)
    ctx.route("GET", "/api/ops/decisions", handle_decisions)
    ctx.route("POST", "/api/ops/decide_now", handle_decide_now)
    ctx.route("GET", "/api/ops/decide_now", handle_decide_now)
    # 溯源归因（漏洞 → 利用者 → ATT&CK 战术映射）
    ctx.route("GET", "/api/ops/attribution", handle_attribution)
    # 处置闭环回填（自我进化）
    ctx.route("POST", "/api/ops/disposition", handle_disposition_record)
    ctx.route("GET", "/api/ops/disposition", handle_disposition_list)
    ctx.route("GET", "/api/ops/disposition/stats", handle_disposition_stats)
    ctx.on_start(start)
