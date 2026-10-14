# -*- coding: utf-8 -*-
"""_run_eval_now.py —— 起一个临时实例，把问答相关评测**按模式分开**全跑一遍

为什么要有这个
--------------
评分表要看"问答深度/准确率/链路解释"，而这些指标在**模板模式**与**LLM 模式**下
完全是两回事：模板模式零 token、毫秒级、结论是字段拼装；LLM 模式走工具调用
智能体、十余秒、结论由模型生成。既有台账里**只有模板模式成绩**，
等于拿兜底路径的分数去申报"深度分析"，这在严苛评审下站不住。

本脚本串行跑（并行会争 CPU，把耗时测歪）：
  1. 评测多跳推理.py  —— 脚本自带：配了 Key 会自动加测 LLM/Agent 组
  2. 评测问答深度.py  —— 模板模式（回归基线，验证改动没跑偏）
  3. 评测问答深度.py --llm —— LLM 模式（补上一直缺的那份成绩）

用法： py tools/_run_eval_now.py [端口]
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8940
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def alive() -> bool:
    try:
        return urllib.request.urlopen(BASE + "/api/health", timeout=5).status == 200
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")
    threading.Thread(target=lambda: p.stdout.read(), daemon=True).start()

    print("[boot] 起实例 %s（加载语料 20~60s）…" % BASE)
    t0 = time.time()
    while time.time() - t0 < 180:
        if alive():
            break
        time.sleep(2)
    if not alive():
        print("[boot] 失败")
        p.kill()
        return 1
    print("[boot] 就绪（%.0fs）\n" % (time.time() - t0))

    steps = [
        ("多跳推理（模板+LLM 自动分组）",
         [PYEXE, "-u", os.path.join("tools", "评测多跳推理.py"), "--base", BASE]),
        ("问答深度 · 模板模式（回归）",
         [PYEXE, "-u", os.path.join("tools", "评测问答深度.py"), "--base", BASE]),
        ("问答深度 · LLM 模式（补缺）",
         [PYEXE, "-u", os.path.join("tools", "评测问答深度.py"), "--base", BASE, "--llm"]),
    ]
    for label, cmd in steps:
        print("\n" + "=" * 64)
        print("[RUN] %s" % label)
        print("=" * 64)
        t1 = time.time()
        try:
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=1800)
            print((r.stdout or "").strip()[-4000:])
            if r.stderr:
                print("[stderr] " + r.stderr.strip()[-1500:])
        except subprocess.TimeoutExpired:
            print("  [超时] 该步超过 30 分钟，跳过")
        print("  —— 用时 %.0fs" % (time.time() - t1))

    p.terminate()
    try:
        p.wait(timeout=20)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n[done] 实例已撤（端口 %d）" % PORT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
