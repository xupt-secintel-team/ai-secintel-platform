# -*- coding: utf-8 -*-
"""
test_orchestrator.py —— 编排器离线自测（不联网、不起服务、零 token）
====================================================================
跑法：py -3 modules/m0_ops/backend/test_orchestrator.py
覆盖：
  1. 感知智能体：从合成 feed 里只挑出 KEV / CVSS≥9 的新事件，且去重
  2. 编排限流：单轮最多处理 max_per_cycle 个，优先级 KEV 在前
  3. 研判模板：无 LLM Key 时简报含 CVSS / KEV / 受影响资产字段
  4. 失败隔离：富化 HTTP 全挂时 cycle 不抛异常、trace 记录失败
  5. 状态持久化：ops_state.json 落盘后重载不重复上报
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import orchestrator as O  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(f"  [{'OK' if cond else 'FAIL'}] {name} {detail}")


def make_feed(tmp, items):
    fp = os.path.join(tmp, "live_feed.jsonl")
    with open(fp, "w", encoding="utf-8") as f:
        for d in items:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    return fp


FEED_ITEMS = [
    {"id": "CVE-2999-0001", "kind": "NVD", "title": "low sev", "cvss": {"score": 5.0}},
    {"id": "CVE-2999-0002", "kind": "NVD", "title": "critical rce", "cvss": {"score": 9.8}},
    {"id": "CVE-2999-0003", "kind": "KEV", "title": "kev exploited", "cvss": {"score": 7.5},
     "kev": {"exploited": True}},
    {"id": "LIVE:BLOG:test", "kind": "博客", "title": "just a blog"},
    {"id": "CVE-2999-0004", "kind": "NVD", "title": "critical 2", "cvss": {"score": 10.0}},
]


def main():
    tmp = tempfile.mkdtemp(prefix="ops_test_")
    feed = make_feed(tmp, FEED_ITEMS)
    state = os.path.join(tmp, "ops_state.json")
    trace = O.TraceRecorder()

    # 1. 感知：只挑 KEV / CVSS≥9
    p = O.PerceptionAgent(feed, state, trace)
    events = p.scan()
    ids = {e["id"] for e in events}
    check("感知只报高危/KEV", ids == {"CVE-2999-0002", "CVE-2999-0003", "CVE-2999-0004"},
          f"实际 {sorted(ids)}")
    check("低危与博客被过滤", "CVE-2999-0001" not in ids and "LIVE:BLOG:test" not in ids)
    # 去重：二扫无事件
    check("二扫去重", p.scan() == [])

    # 2. 编排限流与优先级（关掉网络：enrich 全失败也要跑完）
    ort = O.Orchestrator(tmp, {"ops_interval_sec": 60, "ops_max_per_cycle": 2})
    ort.perception.seen = set()  # 重置，让所有事件重新可见
    O.MAIN_SERVER = "http://127.0.0.1:9"  # 指向不可达地址，验证失败隔离
    result = ort.cycle(manual=True)
    check("单轮限流≤max_per_cycle", len(result["processed"]) <= 2,
          f"processed={result['processed']}")
    check("限流跳过上报", result["skipped"] >= 1, f"skipped={result['skipped']}")
    briefs = []
    try:
        briefs = json.load(open(ort.briefs_fp, encoding="utf-8"))
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("modules/m0_ops/backend/test_orchestrator.py:76", _sw_e)
    first_evt = briefs[0]["event"] if briefs else {}
    check("KEV 优先级最高", first_evt.get("kev") is True, f"首个={first_evt.get('id')}")

    # 3. 简报模板字段齐全（无 Key → template 模式）
    btxt = briefs[0]["brief"] if briefs else ""
    check("简报含CVSS", "CVSS" in btxt)
    check("简报含KEV标记", "KEV" in btxt)
    check("简报含建议", "建议" in btxt)
    check("简报模式为template", briefs and briefs[0]["brief_mode"] == "template")

    # 4. 失败隔离：trace 里有 enrich 失败记录，cycle 正常返回
    fails = [t for t in trace_items(ort) if not t["ok"]]
    check("enrich失败被隔离记录", any(t["agent"] == "enrich" for t in fails),
          f"失败{len(fails)}条")

    # 5. 状态持久化：新实例不重复上报
    ort.perception.save()
    p2 = O.PerceptionAgent(feed, state, O.TraceRecorder())
    check("状态落盘后重载去重", p2.scan() == [])

    # 6. 跨实例简报幂等：第二个编排器（模拟共享 data/ 的另一端口实例）
    #    内存 seen 为空、会把同一事件当"新"，但落简报前查文件应跳过；
    #    唯一可处理的是 ort 因限流从未出简报的事件（CVE-2999-0002）
    before = len(json.load(open(ort.briefs_fp, encoding="utf-8")))
    ort2 = O.Orchestrator(tmp, {"ops_interval_sec": 60, "ops_max_per_cycle": 3})
    ort2.perception.seen = set()   # 模拟全新进程的内存态
    r2 = ort2.cycle(manual=True)
    after_recs = json.load(open(ort.briefs_fp, encoding="utf-8"))
    dup = len(after_recs) - before
    reprocessed = [i for i in r2["processed"] if i != "CVE-2999-0002"]
    check("跨实例不重复出简报", dup <= 1 and not reprocessed,
          f"新增简报{dup}条={r2['processed']}（仅允许补处理未出简报的0002）")

    n_ok = sum(1 for _, ok in RESULTS if ok)
    print(f"\n结果：通过 {n_ok} / 失败 {len(RESULTS) - n_ok}")
    return 0 if n_ok == len(RESULTS) else 1


def trace_items(ort):
    return ort.trace.list(200)


if __name__ == "__main__":
    sys.exit(main())
