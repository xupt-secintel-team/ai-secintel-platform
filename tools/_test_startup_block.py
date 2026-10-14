# -*- coding: utf-8 -*-
"""_test_startup_block.py —— 启动路径上**不允许**有网络调用（2026-10-07）

## 症状

用户报"启动时间过长"，实测 `双击 启动服务.bat` 后 **100 秒端口都没绑上**，
表现是"双击后长时间打不开"。

## 真正的根因（不是"慢"，是"卡死"）

用 faulthandler dump 所有线程栈，抓到主线程停在：

    modules/m1_monitor/api.py:836   start()      ← 启动钩子，主线程
    modules/m1_monitor/backend/live.py:348  blog_feeds()
    core/net.py:145  detect_proxy()

m1 的启动钩子**主线程同步**调 `blog_feeds()`，它要先 `detect_proxy()`。
而 `detect_proxy()` 的开销是**累积**的：

    环境变量段   2 个 URL × 4s = 8s
    上次代理段   2 个 URL × 4s = 8s     （本机无代理，这段必然白等）
    直连段       2 个 URL × 4s = 8s     （同上）
    扫端口段     46 个监听端口 × 2 URL ÷ 8 线程 ≈ 46s
    ────────────────────────────────────
    实测 19s（部分并行）~ 46s（串行最坏）

`PROBE_URLS` 的第一个是 `google.com/generate_204` —— 国内必然超时，
所以**每一段都是满额超时**，一点都不"聪明地快速失败"。

主线程被堵 → `core/server.py` 走不到 `ThreadingHTTPServer(...)`
→ **端口永远不绑定**。后台线程倒是都起来了，但用户访问的是端口。

## 两道修法

1. `modules/m1_monitor/api.py`：源探测挪到 daemon 线程，主线程立刻返回。
   —— 这条最关键：即使 `detect_proxy` 慢，也只慢在后台，不影响端口绑定。
2. `core/net.py`：给 `detect_proxy` 加**总预算** `DETECT_BUDGET`（默认 8s，
   可用 `AISEC_PROXY_BUDGET` 覆盖），四段探测**共用一个 deadline**，
   每次 curl 的 `--max-time` 按剩余预算压低。
   —— 治本：不让"和网络打交道"成为任何调用方的隐式阻塞源。

★ 写这个测试时踩过的坑：预算最初只加在"扫端口"那一段，
  实测仍要 19s —— 因为**前面三段各 8s 早就把预算花光了**。
  只盯"最显眼的那段"会漏掉真正的大头。
"""
from __future__ import annotations

import io
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))

PASS = 0
FAIL = 0


def ck(cond, label, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   " + label)
    else:
        FAIL += 1
        print("  FAIL " + label + (("  " + str(extra)) if extra else ""))


def section(t):
    print("\n=== " + t + " ===")


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


print("_test_startup_block.py —— 启动路径不许有网络调用")

NET = read(os.path.join("core", "net.py"))
M1 = read(os.path.join("modules", "m1_monitor", "api.py"))

# ── 1. m1 启动钩子不得在主线程做网络探测 ────────────────────────
section("[1] m1 启动钩子：源探测必须在后台线程")
# 取 start() 函数体（从 def start( 到下一个顶层 def）
m = re.search(r"\ndef start\(([^)]*)\):(.*?)(?=\ndef |\nclass |\Z)", M1, re.S)
ck(m is not None, "找得到 m1 的 start()")
body = m.group(2) if m else ""
# 启动钩子本体里不能直接出现 blog_feeds( / _proxy( 的同步调用
# （它们在 _fastlane_probe 内部，那是后台线程的函数体）
# ★ 先剥注释：修复说明里必然要写"原来这里主线程同步调 blog_feeds()"，
#   不剥就会把说明文字当成代码 —— 这个误报踩过一次。
_outer = body.split("def _fastlane_probe")[0]
_outer_code = "\n".join(
    l for l in _outer.splitlines()
    if not l.strip().startswith("#")
    and not l.strip().startswith("*")
    and not l.strip().startswith("/*")
)
ck("blog_feeds()" not in _outer_code,
   "start() 主干里没有同步调 blog_feeds()（那是抓取，要走网络）")
ck('name="fastlane"' in body, "源探测跑在名为 fastlane 的 daemon 线程里")
ck("Thread(target=_fastlane_probe" in body, "_fastlane_probe 用线程启动")
ck("daemon=True" in body, "fastlane 线程是 daemon（不挡进程退出）")
# 提示语要说清"后台进行"，否则用户以为没生效
ck("后台" in body, "启动提示说明了源探测在后台进行")

# ── 2. detect_proxy 必须有总预算 ────────────────────────────────
section("[2] detect_proxy 有总预算（治本）")
ck("DETECT_BUDGET" in NET, "定义了 DETECT_BUDGET")
ck("AISEC_PROXY_BUDGET" in NET, "预算可用环境变量覆盖（慢机器可调）")
# 关键：deadline 只能在函数入口算一次 —— 段内重算等于没加预算
ck(NET.count("_deadline = time.time() + DETECT_BUDGET") == 1,
   "deadline 全程只算一次（段内重算 = 预算失效）",
   NET.count("_deadline = time.time() + DETECT_BUDGET"))
# 四段探测都要受预算约束
ck(NET.count("timeout=_tmo()") >= 2,
   "环境变量段 / 上次代理段都用了预算内的超时", NET.count("timeout=_tmo()"))
ck(re.search(r"if _can_direct\(_tmo\(\)\)", NET) is not None,
   "直连段也受预算约束（原先是最容易被漏掉的一段）")
ck(re.search(r"def _try_proxy\(port,\s*deadline=None\)", NET) is not None,
   "_try_proxy 接受 deadline")
ck("def _can_direct(timeout=None)" in NET,
   "_can_direct 接受 timeout（老调用方仍可传 None）")

# ── 3. 实测：预算真的生效 ───────────────────────────────────────
section("[3] 实测 detect_proxy 耗时在预算内")
import net  # noqa: E402

ck(net.DETECT_BUDGET <= 15, "默认预算 %.0fs ≤ 15s" % net.DETECT_BUDGET)
t = time.time()
px = net.detect_proxy(force=True, verbose=False)
dt = time.time() - t
budget = net.DETECT_BUDGET
# 留 1.5s 余量：最后一批 curl 的进程回收不算在预算里
ck(dt <= budget + 1.5,
   "实测 %.1fs ≤ 预算 %.0fs + 1.5s（结果：%s）"
   % (dt, budget, px or "无代理/直连"),
   "%.1fs" % dt)
ck(dt < 20, "实测 %.1fs < 20s（修复前是 19~46s）" % dt)

# ── 4. 探测目标里 google.com 排第一是超时根源 ──────────────────
section("[4] 探测目标的顺序")
ck("google.com" in NET, "PROBE_URLS 里有 google（探测目标未变）")
# 不要求改顺序（有人可能确实需要判断能否直连 google），
# 但必须留个说明：这是超时来源，已被预算兜住
ck(re.search(r"google[^\n]*必然超时|必然超时[^\n]*google", NET) is not None,
   "代码里注明了 google 目标在境内必然超时（靠预算兜住）")

# ── 5. 启动路径上的其它网络调用（防后来者再犯）──────────────────
section("[5] core/server.py 启动路径不阻塞")
SRV = read(os.path.join("core", "server.py"))
# 绑定端口前的那段里，不该有裸的网络调用
bind = SRV.index("ThreadingHTTPServer((\"127.0.0.1\"")
pre = SRV[max(0, bind - 4000):bind]
ck("detect_proxy(" not in pre, "绑定端口前不调 detect_proxy()")
ck("start_scheduler" in pre,
   "（对照）日报调度器在绑定前启动 —— 它是 daemon 线程且不打网络，不算阻塞")

print("\n" + "=" * 60)
print("通过 %d / 失败 %d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
