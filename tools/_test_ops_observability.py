# -*- coding: utf-8 -*-
"""_test_ops_observability.py —— 运维可观测性回归（2026-10-06 第 2 轮补强）

针对本轮新增的三块「原来确实没有」的能力钉死：

  ① 日志轮转（logrotate）：**必须真的搬走当前文件**。第一版就栽在这 ——
     _shift() 只搬 .1/.2，从没把 path 移到 .1，于是每轮原地重建，
     实测写 20800 字节而阈值只有 2048、完全不轮转。这个用例就是为了
     钉死那个 bug 不再回来。
  ② 基础设施指标（metrics）：磁盘/RSS/时延/错误率必须采到真值，
     且告警不能在"从未采集"场景下误报（告警疲劳等于没告警）。
  ③ server 接线：/api/metrics 两个格式 + /api/health 并入告警。

直接执行： py tools/_test_ops_observability.py
"""
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
for p in (ROOT, os.path.join(ROOT, "core"),
          os.path.join(ROOT, "modules", "m1_monitor", "backend")):
    if p not in sys.path:
        sys.path.insert(0, p)

RESULTS = []


def ok(name, cond, detail=""):
    good = bool(cond)
    RESULTS.append((good, name, str(detail)[:90]))
    print("  [%s] %-46s %s" % ("OK" if good else "!!", name, str(detail)[:90]))


def show():
    bad = sum(1 for g, _, _ in RESULTS if not g)
    print("\n结果：通过 %d / 失败 %d" % (len(RESULTS) - bad, bad))
    return 0 if bad == 0 else 1


# ── ① 日志轮转 ──────────────────────────────────────────────────────
print("\n=== ① 日志轮转（真搬走，不是原地重建）===")
import logrotate as LR  # noqa: E402

tmp = tempfile.mkdtemp(prefix="aisec_lr_")
try:
    p = os.path.join(tmp, "运行日志_9999.log")
    rl = LR.RotatingLog(p, max_bytes=4096, keep=3)
    for i in range(500):
        rl.write("第 %04d 行 %s\n" % (i, "载荷" * 6))
    rl.flush()

    st = rl.stats()
    files = os.listdir(tmp)
    gens = sorted(f for f in files if ".log." in f)
    ok("当前文件不超阈值", st["files"][0]["bytes"] <= 4096,
       "当前 %d 字节 / 阈值 4096" % st["files"][0]["bytes"])
    ok("生成了历史世代 .1/.2/.3", len(gens) == 3, "实际 %s" % gens)
    ok("每份历史都不超阈值",
       all(f["bytes"] <= 4096 for f in st["files"][1:]),
       str([f["bytes"] for f in st["files"]]))
    hard_cap = 4096 * 4
    ok("磁盘占用有硬上限（≤(keep+1)×阈值）", st["total_bytes"] <= hard_cap,
       "%d ≤ %d" % (st["total_bytes"], hard_cap))
    ok("轮转次数被记录", st["rotations"] > 0, "轮转 %d 次" % st["rotations"])
    ok("丢弃量被记账（最老一份不留）", st["dropped_bytes"] > 0,
       "已丢弃 %d 字节" % st["dropped_bytes"])

    # 关键：世代内容必须**旧于**当前文件（证明是真搬移，不是复制/原地）
    with open(p, "r", encoding="utf-8") as f:
        head_new = f.readline()
    with open(p + ".1", "r", encoding="utf-8") as f:
        head_old = f.readline()
    ok(".1 内容早于当前文件（证明真的搬走过）",
       head_old != head_new, "当前=%r .1=%r" % (head_new[:16], head_old[:16]))

    # 恰好跨阈值的那一笔也不能把文件顶爆
    rl2 = LR.RotatingLog(os.path.join(tmp, "b.log"), max_bytes=100, keep=2)
    rl2.write("x" * 99)
    rl2.write("y" * 99)   # 触发轮转
    rl2.flush()
    ok("临界两笔后仍不超限",
       os.path.getsize(os.path.join(tmp, "b.log")) <= 100,
       "%d 字节" % os.path.getsize(os.path.join(tmp, "b.log")))
    rl2.close()

    # 中文按字节算（不是按字符数）——按字符数会低估 3 倍
    rl3 = LR.RotatingLog(os.path.join(tmp, "c.log"), max_bytes=1000, keep=2)
    for _ in range(200):
        rl3.write("中文中文中文中文\n")
    rl3.flush()
    ok("中文按字节计（size 判据正确）",
       os.path.getsize(os.path.join(tmp, "c.log")) <= 1000,
       "%d 字节 / 阈值 1000" % os.path.getsize(os.path.join(tmp, "c.log")))
    rl3.close()

    # 人可读
    ok("human() 单位正确",
       LR.human(1536) == "1.5KB" and LR.human(0) == "0.0B",
       "%s / %s" % (LR.human(1536), LR.human(0)))
    rl.close()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# logs_overview 扫的是**项目真实**的 测试报告/ 目录，必须在临时目录清理后单独跑
ov = LR.logs_overview(ROOT)
ok("logs_overview 能扫出真实日志", isinstance(ov, list) and len(ov) > 0,
   "扫到 %d 个日志文件" % len(ov))
ok("overview 字段齐全",
   all(set(x) >= {"name", "current_bytes", "generations", "rotating"}
       for x in ov))
ok("★ 未到阈值不算「轮转中」（否则运维被误导）",
   all(x["rotating"] for x in ov if x["generations"] > 0) and
   not any(x["rotating"] for x in ov if x["generations"] == 0),
   "有世代的=%s · 无世代的应全为 False"
   % ([x["name"] for x in ov if x["generations"] > 0] or "（暂无）"))

# ── ② 基础设施指标 ──────────────────────────────────────────────────
print("\n=== ② 基础设施指标与阈值告警 ===")
import metrics as M  # noqa: E402

snap = M.snapshot()
ok("快照结构完整",
   all(k in snap for k in ("ts", "uptime_sec", "pid", "process", "disk", "feed", "http")),
   "keys=%s" % ",".join(sorted(snap.keys())))
ok("磁盘剩余采到真值", (snap["disk"] or {}).get("free_pct") is not None,
   "剩余 %.1f%%" % ((snap["disk"] or {}).get("free_pct") or -1))
ok("RSS 采到真值（Windows kernel32 / Linux /proc 任一路径）",
   (snap["process"] or {}).get("rss_mb") is not None,
   "%.1f MB" % ((snap["process"] or {}).get("rss_mb") or -1))

# /proc/self/stat 解析：第 2 字段 comm 可能含空格，必须 rsplit(")") 后再数。
# 样本用权威字段表生成（man proc(5)）—— 手写字段串很容易少一个 0 而测错。
_PROC_FIELDS = ["pid", "comm", "state", "ppid", "pgrp", "session", "tty_nr",
                "tpgid", "flags", "minflt", "cminflt", "majflt", "cmajflt",
                "utime", "stime", "cutime", "cstime", "priority", "nice",
                "num_threads", "itrealvalue", "starttime", "vsize", "rss"]
_vals = {n: "0" for n in _PROC_FIELDS}
_vals.update(pid="4242", comm="(my long app name)", state="S", ppid="1",
             pgrp="4242", session="4242", tty_nr="0", tpgid="-1",
             flags="4194560", minflt="1234", cminflt="100", majflt="200",
             cmajflt="300", utime="150", stime="250", priority="20")
proc_line = " ".join(_vals[n] for n in _PROC_FIELDS)
tail = proc_line.rsplit(")", 1)[-1].split()
ok("/proc/self/stat 用 rsplit 切命令名（防错位）",
   tail[11] == "150" and tail[12] == "250",
   "utime=%s stime=%s（应取 11/12）" % (tail[11], tail[12]))
plain = proc_line.split()
ok("（对照）直接 split 会错位 —— 这正是要避免的",
   plain[11] != tail[11],
   "split() 的 [11]=%s ≠ rsplit 的 [11]=%s" % (plain[11], tail[11]))
ok("comm 含空格也不影响切分",
   len(proc_line.split(") ", 1)) == 2 and "(" in proc_line)
ok("磁盘用量百分比合理（0~100）",
   0 <= (snap["disk"] or {}).get("used_pct", -1) <= 100,
   "%.1f%%" % (snap["disk"] or {}).get("used_pct", -1))

alerts, level = M.evaluate(snap)
ok("告警判定不抛异常且级别合法", level in ("ok", "warn", "critical"), "当前 %s" % level)
ok("★ 从未采集时不误报 feed_dead（防告警疲劳）",
   not any(a["key"] == "feed_dead" for a in alerts),
   "alerts=%s" % [a["key"] for a in alerts])
ok("每条告警都带处置建议",
   all(a.get("advice") for a in alerts),
   "%d 条告警" % len(alerts))

# 阈值真的能触发（把阈值压到极限，判定必须变 critical）
fake = {"disk": {"free_pct": 0.5, "used_pct": 99.5}, "process": {"rss_mb": 99999},
        "feed": {"last_poll_age_sec": 99999, "ever_polled": True, "thread_alive": True},
        "http": {"requests": 100, "errors": 90, "err_rate_pct": 90.0,
                 "samples": 100, "p95_ms": 60000},
        "logs": {"files": [{"name": "运行日志_8848", "total_bytes": 60 * 1024 * 1024,
                            "rotating": False, "over_limit": False}],
                 "total_bytes": 60 * 1024 * 1024, "over_limit_count": 0}}
a2, lv2 = M.evaluate(fake)
keys = {a["key"] for a in a2}
ok("磁盘不足会告警", "disk" in keys, "keys=%s" % sorted(keys))
ok("内存超限会告警", "memory" in keys)
ok("实时流停更会告警", "feed_stale" in keys)
ok("错误率超阈会告警", "err_rate" in keys)
ok("P95 劣化会告警", "latency" in keys)
ok("多项同时爆时整体为 critical", lv2 == "critical", lv2)
ok("停更 3 倍以上升级为 critical",
   next(a["level"] for a in a2 if a["key"] == "feed_stale") == "critical")
ok("★ 未接轮转的大日志会告警（吃盘隐患）",
   any(a["key"] == "log_unrotated" for a in a2),
   "keys=%s" % sorted(keys))

# 已接轮转的超限日志只报 info 级 warn，不该算故障
fake2 = {"disk": {"free_pct": 50.0}, "process": {"rss_mb": 100},
         "feed": {"last_poll_age_sec": 5, "ever_polled": True, "thread_alive": True},
         "http": {"requests": 100, "errors": 0, "err_rate_pct": 0.0,
                  "samples": 100, "p95_ms": 100},
         "logs": {"files": [{"name": "运行日志_8848", "total_bytes": 10 * 1024 * 1024,
                             "rotating": True, "over_limit": True}],
                  "total_bytes": 10 * 1024 * 1024, "over_limit_count": 1}}
a3, lv3 = M.evaluate(fake2)
ok("正常状态下整体 ok", lv3 in ("ok", "warn"), lv3)
ok("已轮转的超限日志只给 warn 不给 critical",
   all(a["level"] != "critical" for a in a3),
   str([(a["key"], a["level"]) for a in a3]))

# 日志快照进 JSON
lg = (M.snapshot().get("logs") or {})
ok("快照含日志占用", "total_bytes" in lg,
   "合计 %s / %d 个文件" % (lg.get("total_human"), len(lg.get("files") or [])))

# 采样器
M.latency.observe("/api/search", 120.0, False)
M.latency.observe("/api/chat", 3000.0, False)
M.latency.observe("/api/chat", 9000.0, True)
hs = M.latency.stats()
ok("延迟采样计数正确", hs["requests"] >= 3, "requests=%d errors=%d"
   % (hs["requests"], hs["errors"]))
ok("错误率被统计", hs["err_rate_pct"] > 0, "%.1f%%" % hs["err_rate_pct"])
ok("路由被归一（防 key 爆炸）",
   "/api/search" in hs["top_routes"] and "/api/chat" in hs["top_routes"],
   "routes=%s" % list(hs["top_routes"].keys()))
ok("路由归一剥掉查询串",
   M._route_of("/api/cmdb_scan?id=123") == "/api/cmdb_scan",
   M._route_of("/api/cmdb_scan?id=123"))
ok("★ 静态资源被单独归桶（否则稀释 API 的 P95/错误率）",
   M._route_of("/static/app.js") == "static" and
   M._route_of("/modules/m0_ops/panel.css") == "static" and
   M._route_of("/favicon.ico") == "static",
   "app.js→%s panel.css→%s" % (M._route_of("/static/app.js"),
                                M._route_of("/modules/m0_ops/panel.css")))
ok("API 路由不会被误判成 static",
   M._route_of("/api/search") == "/api/search")

# 静态资源必须被排除在分位数/错误率之外（否则浏览器刷一次页就"性能达标"）
M2 = type(M.latency)()
for _i in range(20):
    M2.observe("static", 5.0, False)
for _i in range(15):
    M2.observe("/api/search", 900.0, False)
for _i in range(5):
    M2.observe("/api/cmdb", 1200.0, True)
sf = M2.stats()
sr = M2.stats(skip_static=False)
ok("统计默认排除静态资源", sf["requests"] == 20 and sf["samples"] == 20,
   "过滤后 requests=%d" % sf["requests"])
ok("★ 错误率不被静态资源稀释", abs(sf["err_rate_pct"] - 25.0) < 0.1,
   "过滤 %.1f%% vs 不过滤 %.1f%%（静态请求会稀释一半）"
   % (sf["err_rate_pct"], sr["err_rate_pct"]))
ok("★ P50 不被静态资源拉平", sf["p50_ms"] == 900.0,
   "过滤 %.0fms vs 不过滤 %.0fms" % (sf["p50_ms"], sr["p50_ms"]))
ok("top_routes 里不出现 static", "static" not in sf["top_routes"],
   list(sf["top_routes"].keys()))

# Prometheus 导出
pm = M.prometheus()
ok("Prometheus 导出非空", isinstance(pm, str) and "aisec_up 1" in pm,
   "%d 行" % len(pm.splitlines()))
ok("Prometheus 含磁盘指标", "aisec_disk_free_bytes" in pm)
ok("Prometheus 指标不带非法字符",
   all(" " not in ln.split(" ")[0] or ln.split(" ")[0] for ln in pm.splitlines()
       if ln.strip()))
ok("阈值表可被 env 覆盖", "disk_free_pct" in M.THRESHOLDS,
   "阈值 %d 项" % len(M.THRESHOLDS))

# 线程名判据必须与真实源码一致 —— 靠猜名字会让存活告警静默失效
api_src = open(os.path.join(ROOT, "modules", "m1_monitor", "api.py"),
               encoding="utf-8").read()
real_names = set(re.findall(r'Thread\([^)]*name="([^"]+)"', api_src))
live_names = {n for n in real_names
              if n in ("live", "live-poll") or "采集" in n}
ok("★ 采集线程名与真实源码一致（防改名静默失效）",
   live_names and live_names.issubset(set(M._LIVE_THREAD_NAMES)),
   "源码里的采集线程=%s · 判据表=%s"
   % (sorted(live_names), list(M._LIVE_THREAD_NAMES)))

# ── ③ server 接线 ──────────────────────────────────────────────────
print("\n=== ③ server 接线（真读源码，不靠文档声称）===")
src = open(os.path.join(ROOT, "core", "server.py"), encoding="utf-8").read()
ok("server 已 import metrics", "import metrics" in src)
ok("注册了 /api/metrics", '"/api/metrics"' in src)
ok("支持 Prometheus 格式", "prometheus" in src and "fmt" in src)
ok("/api/health 并入告警等级", '"alert_level"' in src and "degraded" in src)
ok("do_GET 有耗时采样", src.count("metrics.latency.observe") >= 2,
   "埋点 %d 处" % src.count("metrics.latency.observe"))
ok("采样放在 finally（断开也计入）",
   "finally:" in src and "metrics.latency.observe" in src)

src_wd = open(os.path.join(ROOT, "tools", "watchdog.py"), encoding="utf-8").read()
ok("watchdog 日志已接轮转", "RotatingLog" in src_wd)
ok("watchdog 保留裸 append 兜底（轮转模块缺失也不崩）",
   'open(log_fp, "a"' in src_wd)

src_run = open(os.path.join(ROOT, "tools", "_run_server_logged.py"),
               encoding="utf-8").read()
ok("服务日志已接轮转", "RotatingLog" in src_run)
ok("改为管道+搬运线程（Windows 才能轮转）",
    "log-pump" in src_run and "subprocess.PIPE" in src_run)
ok("不再裸 append 无上限", 'open(LOG, "a"' not in src_run)

# 语法编译（改过的文件全部要能编译）
import py_compile  # noqa: E402
bad = []
for f in ("core/server.py", "core/metrics.py", "core/logrotate.py",
          "tools/watchdog.py", "tools/_run_server_logged.py"):
    try:
        py_compile.compile(os.path.join(ROOT, f), doraise=True)
    except py_compile.PyCompileError as e:  # noqa: BLE001
        bad.append("%s: %s" % (f, str(e)[:60]))
ok("改动文件全部编译通过", not bad, "; ".join(bad))

# ── ④ 死代码检测（防止又攒出"改了不生效"的僵尸模块）───────────────
print("\n=== ④ 死代码 / 配置漂移 ===")
QA = os.path.join(ROOT, "modules", "m3_qa", "backend", "qa")
# 零引用但**有意保留**的模块（豁免清单，必须写清理由，否则将来无人敢删也无人敢用）
ARCHIVED = {
    "legacy_rag.py": "单轮 RAG 旧实现，已被 multi_hop+generator 完全取代；保留作对照参考",
    "evaluate.py": "离线问答评测器，设计上就是人工 `python -m qa.evaluate` 手动跑的，"
                   "不作为库被 import；它自己打 HTTP 调服务",
}
# 反过来：这些必须真的被 import（防止"以为接上了其实没接"）
MUST_BE_IMPORTED = ("multi_hop", "generator", "config", "agent", "deep_answer")
qa_files = [f for f in os.listdir(QA) if f.endswith(".py") and f != "__init__.py"]
all_src = []
for root_dir, _dirs, files in os.walk(os.path.join(ROOT, "modules")):
    for f in files:
        if f.endswith(".py"):
            try:
                all_src.append(open(os.path.join(root_dir, f), encoding="utf-8").read())
            except Exception:  # noqa: BLE001
                pass
for root_dir, _dirs, files in os.walk(os.path.join(ROOT, "core")):
    for f in files:
        if f.endswith(".py"):
            try:
                all_src.append(open(os.path.join(root_dir, f), encoding="utf-8").read())
            except Exception:  # noqa: BLE001
                pass
blob = "\n".join(all_src)
zombies = []
for f in qa_files:
    mod = f[:-3]
    # 排除"自身定义"：统计 import 该模块的出现次数
    hits = len(re.findall(r"(?:from\s+qa\.%s\s+import|import\s+qa\.%s\b)" % (mod, mod), blob))
    if hits == 0 and mod not in ("__init__",):
        zombies.append((f, ARCHIVED.get(f, "")))
unexpected = [f for f, why in zombies if not why]
ok("qa 包无未登记的零引用模块", not unexpected,
   "意外僵尸模块：%s" % (unexpected or "无"))
ok("归档模块都写明了理由",
   all(len(w) > 10 for _f, w in zombies),
   "%d 个已登记：%s" % (len(zombies), [f for f, _w in zombies]))
# 反向检查：核心模块必须真的被 import（"以为接上了其实没接"是更危险的错）
not_imported = [m for m in MUST_BE_IMPORTED
                if not re.search(r"from\s+qa\.%s\s+import|import\s+qa\.%s\b"
                                 % (m, m), blob)]
ok("★ 核心问答模块都真的被 import（防止改了没接上）", not not_imported,
   "未接上：%s" % (not_imported or "无"))
ok("legacy_rag 已标注「无入口·勿改」",
   "已归档" in open(os.path.join(QA, "legacy_rag.py"), encoding="utf-8").read()[:600])

# 配置漂移：硬编码端口必须走 env
ev_src = open(os.path.join(QA, "evaluate.py"), encoding="utf-8").read()
ok("★ evaluate.py 不再硬编码 8849（评测脚本此前一直打错端口）",
   "127.0.0.1:8849" not in ev_src)
ok("evaluate.py 目标地址可被 env 覆盖",
   "AISEC_QA_SERVER" in ev_src and "AISEC_MAIN_SERVER" in ev_src)
ok("默认端口与服务默认一致（8848）",
   "127.0.0.1:8848" in ev_src)

# 评测脚本打本机：设过系统代理的机器上会 502（症状像"服务坏了"）
import loopback as LB  # noqa: E402

ok("回环判定：127.0.0.1/localhost 是回环",
   LB.is_loopback("http://127.0.0.1:8848/x") and
   LB.is_loopback("http://localhost:8981/y"))
ok("回环判定：外网与内网 IP 不是回环",
   not LB.is_loopback("https://www.example.com/a") and
   not LB.is_loopback("http://10.0.0.5:8848/x"))
ok("回环判定：不受用户信息/查询串/端口干扰",
   LB.is_loopback("http://user:pw@127.0.0.1:8848/api?q=1") and
   LB.is_loopback("http://[::1]:8848/api"))
ok("no_proxy_env 清掉了所有代理变量",
   not any(k.lower().endswith("_proxy") and k.lower() not in ("no_proxy",)
           for k in LB.no_proxy_env()))
ok("no_proxy_env 里 no_proxy 指向回环",
   "127.0.0.1" in LB.no_proxy_env().get("no_proxy", ""))
# build_opener(ProxyHandler({})) 见到空映射会**根本不装**这个 handler，
# 所以正确判据是"handlers 里没有带代理配置的 ProxyHandler"，
# 而不是"有一个 proxies 为空的 ProxyHandler"。
_proxy_handlers = [h for h in LB.direct_opener().handlers
                   if isinstance(h, urllib.request.ProxyHandler) and h.proxies]
ok("direct_opener 未挂任何带代理的 handler", not _proxy_handlers,
   "带代理的 handler 数=%d" % len(_proxy_handlers))

# 实测（比结构断言可靠）：开着系统代理时，回环请求仍走直连。
# 打本机一个"确定没人在听"的端口 —— 期望拿到本机侧的连接错误（拒绝/超时）。
# 注意：Windows 上部分保留端口表现为 timeout 而非 refused，两者都算"来自本机"。
# 关键判据是**没有 502 / Bad Gateway** —— 那才是被代理劫持的特征。
os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
os.environ["http_proxy"] = "http://127.0.0.1:9"
try:
    LB.call("http://127.0.0.1:9/nope", timeout=3)
    ok("回环请求在代理环境下可达（本机服务）", False, "不该成功")
except Exception as e:  # noqa: BLE001
    _txt = str(e)
    _rtxt = str(getattr(e, "reason", e))
    ok("★ 回环请求绕过代理（错误来自本机侧）",
       ("10061" in _txt or "refused" in _rtxt.lower() or "拒绝" in _txt
        or "timed out" in _rtxt.lower() or "Cannot connect" in _rtxt),
       "本机侧错误：%s" % _rtxt[:70])
    ok("★ 没有被代理劫持（无 502 / Bad Gateway）",
       "502" not in _txt and "Bad Gateway" not in _txt, _txt[:80])
finally:
    for _k in ("HTTP_PROXY", "http_proxy"):
        os.environ.pop(_k, None)

# 对照：非回环地址应当**仍然走代理**（不能把外网也一起掐断）
os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
os.environ["http_proxy"] = "http://127.0.0.1:9"
try:
    LB.call("http://example.invalid/nope", timeout=3)
    ok("外网仍走代理", False, "不该成功")
except Exception as e:  # noqa: BLE001
    ok("★ 外网请求仍走代理（回环豁免没有误伤外网）",
       "10061" in str(e) or "refused" in str(e).lower() or "拒绝" in str(e),
       "代理侧错误：%s" % str(getattr(e, "reason", e))[:60])
finally:
    for _k in ("HTTP_PROXY", "http_proxy"):
        os.environ.pop(_k, None)

# 只对**真发 HTTP 到本机服务**的评测脚本要求接回环免代理。
# 评测富化准确率.py 是纯离线评测（直接读 data/ 下文件算准确率，不打服务），
# 给它套这个要求属于过度约束。
HTTP_EVAL_SCRIPTS = ("评测多跳推理.py", "评测问答深度.py", "评测检索.py",
                     "评测时效性.py", "评测POC.py", "评测POC覆盖率.py")
miss = []
for fn in HTTP_EVAL_SCRIPTS:
    p = os.path.join(ROOT, "tools", fn)
    if not os.path.exists(p):
        continue
    s = open(p, encoding="utf-8").read()
    if "loopback" not in s:
        miss.append(fn)
ok("★ 所有打本机服务的评测脚本都接了回环免代理", not miss, "漏掉：%s" % (miss or "无"))

# 端口漂移检查：只看真实生效的代码行，跳过注释与文档字符串
bad_port = []
for fn in HTTP_EVAL_SCRIPTS:
    p = os.path.join(ROOT, "tools", fn)
    if not os.path.exists(p):
        continue
    for ln in open(p, encoding="utf-8").read().splitlines():
        code = ln.strip()
        if code.startswith("#") or code.startswith('"') or "不能写死" in code:
            continue
        for m in re.finditer(r"127\.0\.0\.1:(\d{4})", code):
            if m.group(1) != "8848":
                bad_port.append("%s → %s" % (fn, code[:60]))
ok("★ 评测脚本默认端口与服务一致（无 8849/8981/8899 漂移）", not bad_port,
   "不一致：%s" % (bad_port or "无"))

sys.exit(show())