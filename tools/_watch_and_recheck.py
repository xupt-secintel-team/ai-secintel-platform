# -*- coding: utf-8 -*-
"""_watch_and_recheck.py —— 等"另一个会话"改完，再自动重跑一遍严苛核查

背景
----
同一工作区可能有另一个会话在并行改代码（修本轮核查发现的问题）。
本轮核查的结论会随它的改动失效，所以不能只看一次就下结论：
  1. 先**盯盘**：扫描 modules/ core/ frontend/ tools/ 测试报告/ 的 mtime；
     连续 120s 无变化 → 判定对方任务结束（最长盯 20 分钟，超时也照样复检）。
  2. 再**自动复检**：跑 enrich_dims 计数、ops 简报/事件条数、qa_log 的 LLM 占比、
     冒烟启动、评分表口径探针（_probe_rubric / _probe_rubric2）。
  3. 输出与"改前基线"的对比，看清修了什么、没修什么。

用法： py tools/_watch_and_recheck.py [最长盯盘分钟]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYEXE = sys.executable
WATCH_DIRS = ["modules", "core", "frontend", "tools", "测试报告"]
SKIP = ("__pycache__",)

# ── 改前基线：本轮三轮核查时实测到的值（2026-10-08 08:2x）
BASELINE = {
    "enrich_dims": 13,
    "enrich_assoc": 3,
    "ops_briefs": 0,
    "ops_events": 0,
    "qa_llm_ratio": 6 / 995,
    "live_cold_items": 0,
}

IDLE_SEC = 120          # 静默多久判定对方收工
POLL_SEC = 20


def snapshot() -> dict:
    """返回 {相对路径: mtime} —— 只盯源码与报告，不盯 data/（服务一直在写 data）。"""
    out = {}
    for d in WATCH_DIRS:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [x for x in dirnames if x not in SKIP]
            for fn in filenames:
                if fn.endswith((".pyc", ".log")):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    out[os.path.relpath(fp, ROOT)] = os.path.getmtime(fp)
                except OSError:
                    pass
    return out


def diff(a, b) -> list:
    changed = [k for k in set(a) | set(b)
               if abs((a.get(k) or 0) - (b.get(k) or 0)) > 0.5 or (k in a) != (k in b)]
    return sorted(changed)


def watch(max_min: int) -> list:
    print("[盯盘] 最长 %d 分钟，静默 %ds 判定结束" % (max_min, IDLE_SEC))
    snap = snapshot()
    last_change = time.time()
    changed_all = []
    deadline = time.time() + max_min * 60
    while time.time() < deadline:
        time.sleep(POLL_SEC)
        now = snapshot()
        d = diff(snap, now)
        if d:
            changed_all += [x for x in d if x not in changed_all]
            last_change = time.time()
            snap = now
            print("  [%s] 有改动 %d 处：%s"
                  % (time.strftime("%H:%M:%S"), len(d), d[:6]))
        elif time.time() - last_change >= IDLE_SEC:
            print("  [%s] 已静默 %ds，判定对方任务结束"
                  % (time.strftime("%H:%M:%S"), IDLE_SEC))
            break
    return changed_all


def _count(fp: str) -> int:
    try:
        d = json.load(open(fp, encoding="utf-8"))
        return len(d) if isinstance(d, (list, dict)) else -1
    except Exception:  # noqa: BLE001
        return -1


def recheck() -> dict:
    res = {}
    # 1 富化维度（离线，不用起服务）
    r = subprocess.run([PYEXE, os.path.join("modules", "m2_enrich", "backend", "enrich_dims.py")],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    line = (r.stdout or "").splitlines()
    res["enrich_line"] = line[0].strip() if line else "(无输出)"
    print("[复检] 富化维度：%s" % res["enrich_line"])

    # 2 编排产物（改前为 0）
    res["ops_briefs"] = _count(os.path.join(ROOT, "data", "ops_briefs.json"))
    res["ops_events"] = _count(os.path.join(ROOT, "data", "ops_events.json"))
    print("[复检] ops_briefs=%d（基线 %d）· ops_events=%d（基线 %d）"
          % (res["ops_briefs"], BASELINE["ops_briefs"],
             res["ops_events"], BASELINE["ops_events"]))

    # 3 问答 LLM 占比（改前 6/995）
    try:
        rows = [json.loads(l) for l in
                open(os.path.join(ROOT, "data", "qa_log.jsonl"), encoding="utf-8")]
        n = len(rows)
        llm = sum(1 for x in rows if x.get("used_llm"))
        res["qa_total"], res["qa_llm"] = n, llm
        print("[复检] qa_log：共 %d 条，LLM 模式 %d 条（占比 %.2f%%，基线 0.60%%）"
              % (n, llm, 100.0 * llm / n if n else 0))
    except Exception as e:  # noqa: BLE001
        print("[复检] qa_log 读取失败", e)

    # 4 引用链：POC 精度评测报告是否存在
    p = os.path.join(ROOT, "测试报告", "POC精度评测.md")
    res["poc_report"] = os.path.isfile(p)
    print("[复检] 《POC精度评测.md》存在：%s（基线 False）" % res["poc_report"])

    # 5 真起服务打接口（两个探针）
    for script, port in (("_probe_rubric.py", 8931), ("_probe_rubric2.py", 8932)):
        print("\n" + "=" * 60)
        print("[复检] 运行 %s（端口 %d）" % (script, port))
        r = subprocess.run([PYEXE, os.path.join("tools", script), str(port)],
                           cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=1200)
        out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        print(out.strip()[-6000:])
        res[script] = out
    return res


def main() -> int:
    max_min = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    changed = watch(max_min)
    print("\n[盯盘] 期间改动文件 %d 个：" % len(changed))
    for c in changed[:40]:
        print("   ·", c)
    print("\n" + "=" * 60)
    recheck()
    return 0


if __name__ == "__main__":
    sys.exit(main())
