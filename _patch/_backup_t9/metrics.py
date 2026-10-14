# -*- coding: utf-8 -*-
"""metrics.py —— 基础设施指标采集 + 阈值告警（2026-10-06 新增）

为什么补这个（代码核查结论，不是文档声称）：
  改之前，全项目**没有任何一处**采集 CPU / 内存 / 磁盘 / 队列积压，
  也没有任何阈值告警。运维视角的三个真实盲区：
    1. 磁盘写满 → 服务起不来（而日志本来就在无上限往磁盘上追加，见 logrotate.py）
    2. 采集线程卡住 → 实时流停更，但 `/api/health` 依然返回 ok（假健康）
    3. 问答 P95 劣化 → 没有分位数，只能靠人肉感觉

本模块提供：
  · `snapshot()`  —— 进程与主机指标（纯标准库，不装 psutil）
  · `THRESHOLDS`  —— 可调阈值表
  · `evaluate()`  —— 阈值判定，产出 alert 列表（含 level / 处置建议）
  · `latency`     —— 请求耗时采样器（给 server.py 的 do_GET/do_POST 埋点）
  · `prometheus()`—— Prometheus 文本格式导出（可被现成的采集器直接抓）

刻意不引入 psutil：容器镜像已经是最小化的，再加一个 C 扩展会让
`requirements.txt` / `bootstrap.py` / `Dockerfile` / `tools/检查依赖.py`
四处同步全部变复杂（项目约定），而这里需要的四个指标
标准库都能拿到足够精度的值。
"""
from __future__ import annotations

import os
import sys
import threading
import time

try:
    import paths
except Exception:  # pragma: no cover
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))))
    import paths

_START_TS = time.time()

# ── 阈值表 ──────────────────────────────────────────────────────────
# 全部可用环境变量覆盖，改阈值不用改代码（容器里改 env 即可）。
def _f(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


THRESHOLDS = {
    # 磁盘：数据目录所在卷剩余占比（%），低于即告警
    "disk_free_pct": _f("AISEC_ALERT_DISK_FREE_PCT", 10.0),
    # 进程 RSS（MB），超过即告警
    # ★ 默认 6144 而不是拍脑袋的 2048 —— 实测踩过：10 万条语料常驻内存，
    #   实例**刚启动 300 秒** RSS 就有 3022MB（8848 实例跑 10 小时后 4142MB），
    #   阈值 2048 会让每个实例一上来就常年 warn。常亮的告警等于没有告警：
    #   真正内存泄漏时会被淹没在一片黄里，没人看得见。
    #   6144 ≈ 实测启动基线（3GB）的 2 倍，留出缓存增长余量，
    #   只在"确实异常"时才亮。
    "rss_mb": _f("AISEC_ALERT_RSS_MB", 6144.0),
    # 实时流停更（秒）：最近一次成功采集距今，超过即告警（= "假健康"）
    "feed_stale_sec": _f("AISEC_ALERT_FEED_STALE_SEC", 180.0),
    # 采集线程存活：线程死了就是真故障
    "feed_thread_alive": True,
    # HTTP 错误率（%），超过即告警
    "err_rate_pct": _f("AISEC_ALERT_ERR_RATE_PCT", 5.0),
    # 问答 P95 时延（秒），超过即告警
    "latency_p95_sec": _f("AISEC_ALERT_P95_SEC", 8.0),
    # 样本量下限：不足不给 latency 结论（避免 3 个样本就报警）
    "latency_min_samples": int(_f("AISEC_ALERT_MIN_SAMPLES", 20) or 20),
}

SEV_ORDER = {"ok": 0, "warn": 1, "critical": 2}

# 采集守护线程的名字。与 modules/m1_monitor/api.py 里的 Thread(... name=) 一致。
# 改名时这里必须同步 —— tools/_test_ops_observability.py 会真读 api.py 源码
# 比对，改名漏改会让采集存活告警静默失效（这是"靠字符串判断线程"的固有风险，
# 用测试钉住是唯一的低成本办法）。
_LIVE_THREAD_NAMES = ("live", "live-poll", "采集")


# ── 请求耗时采样（滚动窗口）────────────────────────────────────────
class _Latency:
    """定长环形缓冲 + 互斥锁。线程安全、无第三方依赖。"""

    def __init__(self, cap=512):
        self.cap = cap
        self._buf = []
        self._idx = 0
        self._lock = threading.Lock()
        self.total = 0
        self.errors = 0
        self.by_route = {}      # route -> [n, err, sum_ms]

    def observe(self, route, ms, is_error):
        with self._lock:
            self.total += 1
            if is_error:
                self.errors += 1
            # 缓冲里存 (route, ms)，这样 stats() 才能把静态资源摘掉再算分位数。
            # 存裸 ms 的话 P95 会被一次刷新的十几个 .js 拉平。
            item = (route, float(ms))
            if len(self._buf) < self.cap:
                self._buf.append(item)
            else:
                self._buf[self._idx] = item
                self._idx = (self._idx + 1) % self.cap
            r = self.by_route.setdefault(route, [0, 0, 0.0])
            r[0] += 1
            if is_error:
                r[1] += 1
            r[2] += ms
            # 只保留最近的 40 条路由，防止路径参数化导致 key 爆炸
            if len(self.by_route) > 40:
                for k in sorted(self.by_route, key=lambda k: -self.by_route[k][0])[20:]:
                    self.by_route.pop(k, None)

    def stats(self, skip_static=True):
        with self._lock:
            src = [(i, v) for i, v in self._buf if not (skip_static and self._is_static(i))]
            xs = sorted(v for _i, v in src)
            n = len(xs)
            # 错误率/总数同样只算 API：静态资源 404（favicon 之类）不算服务错误
            if skip_static:
                apis = {k: v for k, v in self.by_route.items() if not self._is_static(k)}
            else:
                apis = dict(self.by_route)
            total = sum(v[0] for v in apis.values())
            errors = sum(v[1] for v in apis.values())
            routes = {k: {"n": v[0], "err": v[1], "avg_ms": round(v[2] / v[0], 1) if v[0] else 0}
                      for k, v in sorted(apis.items(), key=lambda kv: -kv[1][0])[:12]}
        def _p(p_):
            if not xs:
                return 0.0
            i = min(len(xs) - 1, max(0, int(round((p_ / 100.0) * len(xs) + 0.5)) - 1))
            return xs[i]
        return {
            "samples": n,
            "requests": total,
            "errors": errors,
            "err_rate_pct": round(errors * 100.0 / total, 2) if total else 0.0,
            "p50_ms": round(_p(50), 1),
            "p95_ms": round(_p(95), 1),
            "p99_ms": round(_p(99), 1),
            "top_routes": routes,
        }

    @staticmethod
    def _is_static(x):
        return x == "static"


latency = _Latency()


def _route_of(path):
    """把 /api/cmdb_scan?id=123 归一成 /api/cmdb_scan，避免路径参数炸开维度。

    静态资源（.js/.css/.png…）单独归到 "static" 桶，而不是混进 API 统计：
    浏览器一次刷新会拉十几个资源文件，全都是 200 且耗时极短，
    混进分母会把 API 的 P95 和错误率都稀释掉（实测能拉到偏差 3~5 倍）。
    """
    p = (path or "").split("?")[0]
    if p.startswith("/api/") or p.startswith("/taxii2/"):
        parts = p.split("/")
        # 保留前 3 段：/api/<模块>/<动作>
        return "/".join(parts[:3]) if len(parts) > 3 else p
    if p.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() in (
            "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff",
            "woff2", "ttf", "map", "webp", "json", "html", "htm"):
        return "static"
    return p or "?"


# ── 主机/进程指标 ──────────────────────────────────────────────────
def _disk_free(path):
    """磁盘剩余。Windows 没有 os.statvfs，走 shutil.disk_usage。"""
    try:
        import shutil
        du = shutil.disk_usage(path)
        return {
            "total_bytes": du.total,
            "free_bytes": du.free,
            "free_pct": round(du.free * 100.0 / du.total, 2) if du.total else 0.0,
            "used_pct": round(du.used * 100.0 / du.total, 2) if du.total else 0.0,
        }
    except Exception:  # noqa: BLE001
        return None


def _rss_mb():
    """进程 RSS（MB）。Linux 读 /proc/self/status，Windows 用 ctypes psapi。
    两者都拿不到就返回 None —— 诚实标未知，不编数字。"""
    try:
        if os.path.exists("/proc/self/status"):
            with open("/proc/self/status", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return round(int(line.split()[1]) / 1024.0, 1)
            return None
    except Exception:  # noqa: BLE001
        pass
    try:
        import ctypes
        import ctypes.wintypes as wt
        from ctypes import wintypes  # noqa: F401

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wt.DWORD),
                ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        c = PMC()
        c.cb = ctypes.sizeof(PMC)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = wt.HANDLE
        handle = k32.GetCurrentProcess()
        # 新系统走 kernel32.K32GetProcessMemoryInfo，老系统走 psapi.GetProcessMemoryInfo
        for dll, fn_name in (("kernel32", "K32GetProcessMemoryInfo"),
                             ("psapi", "GetProcessMemoryInfo")):
            try:
                dll_h = getattr(ctypes.windll, dll)
                fn = getattr(dll_h, fn_name, None)
                if not fn:
                    continue
                # 必须显式声明签名：ctypes 默认按 c_int 处理返回值、并按 4 字节
                # 猜结构体传参，WorkingSetSize 是 64 位 size_t —— 不声明就静默
                # 返回 0（实测：声明后 37.7MB，不声明恒为 None）。
                fn.restype = ctypes.c_int
                fn.argtypes = [wt.HANDLE, ctypes.POINTER(PMC), wt.DWORD]
                if fn(handle, ctypes.byref(c), c.cb):
                    return round(c.WorkingSetSize / 1048576.0, 1)
            except Exception:  # noqa: BLE001
                continue
        return None
    except Exception:  # noqa: BLE001
        return None


def _cpu_times():
    """(用户态秒, 内核秒)。读 /proc/self/stat 的第 14/15 个字段（0-based 13/14）。
    Windows 无 /proc → 返回 None（正确降级，指标里不出现该值）。"""
    try:
        with open("/proc/self/stat", "r", encoding="utf-8", errors="replace") as f:
            parts = f.read().rsplit(")", 1)[-1].split()
        # 用 rsplit(")") 切掉 pid+comm（第 2 字段 comm 可能含空格，如 "(my app)"），
        # 直接 split() 会让后续字段整体错位一格。
        # rsplit 后从 state(1-based #3) 开始数，索引 = 1-based 号 - 2，
        # 故 utime(#14)=索引 11、stime(#15)=索引 12。
        return float(parts[11]), float(parts[12])
    except Exception:  # noqa: BLE001
        return None


_CPU_PREV = {}


def _cpu_pct():
    """进程 CPU 占用（%），需要两次采样才有意义；首次返回 None。"""
    t = _cpu_times()
    if not t:
        return None
    now = time.time()
    prev = _CPU_PREV.get("t")
    _CPU_PREV["t"] = (now, t)
    if not prev or now - prev[0] < 0.5:
        return None
    dt = now - prev[0]
    du = (t[0] - prev[1][0]) + (t[1] - prev[1][1])
    return round(du / dt * 100.0, 1) if dt > 0 else None


def _feed_state():
    """实时采集状态：最近一次成功采集时刻 + 采集线程是否活着。
    数据源是 m1_monitor 的 LAST_META（真实在写），读不到就标 unknown。"""
    try:
        sys_path = os.path.join(paths.MODULES_DIR, "m1_monitor", "backend")
        if sys_path not in os.sys.path:
            os.sys.path.insert(0, sys_path)
        import live as L
        meta = getattr(L, "LAST_META", None) or {}
        at = meta.get("at") or ""
        age = None
        if at:
            try:
                t = time.mktime(time.strptime(at[:19], "%Y-%m-%dT%H:%M:%S"))
                age = round(time.time() - t, 1)
            except Exception:  # noqa: BLE001
                age = None
        alive = None
        # 采集守护线程的判定，**不能靠猜线程名**：真实名字是 "live"
        # （modules/m1_monitor/api.py 里 Thread(target=_live_loop, name="live")），
        # 我第一版猜的是 "live-poll"，结果对着真服务也报"采集线程已消失"——
        # 假告警比没告警更坏。所以这里动态扫一遍已知名字，且以
        # LAST_META 有过采集记录为前提。
        for th in threading.enumerate():
            if th.name in _LIVE_THREAD_NAMES:
                alive = True
                break
        else:
            alive = False
        # 关键：从未采集过（冷启动 / --no-live / 脚本单跑）与"采集中途线程死了"
        # 是两回事。只有存在过采集记录、线程却不在，才算故障。
        # 否则任何独立跑 metrics.py 的场景都会常年报 critical —— 告警疲劳
        # 等于没有告警。
        return {
            "last_poll_at": at or None,
            "last_poll_age_sec": age,
            "fresh_last_round": meta.get("fresh"),
            "poll_ms": meta.get("poll_ms"),
            "feed_ok": meta.get("feed_ok"),
            "feed_fail_count": len(meta.get("feed_fail") or {}),
            "thread_alive": alive,
            "ever_polled": bool(at),
        }
    except Exception:  # noqa: BLE001
        return {"last_poll_at": None, "last_poll_age_sec": None, "thread_alive": None}


def snapshot():
    """一次性采集全部指标。永远不抛异常 —— 监控代码崩了比没监控更糟。"""
    out = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "uptime_sec": round(time.time() - _START_TS, 1),
        "pid": os.getpid(),
        "python": ".".join(str(x) for x in sys.version_info[:3]),
        "threads": threading.active_count(),
    }
    try:
        out["process"] = {
            "rss_mb": _rss_mb(),
            "cpu_pct": _cpu_pct(),
            "threads": threading.active_count(),
        }
    except Exception:  # noqa: BLE001
        out["process"] = {"rss_mb": None, "cpu_pct": None}
    try:
        out["disk"] = _disk_free(paths.DATA_DIR if os.path.isdir(paths.DATA_DIR)
                                 else paths.ROOT)
    except Exception:  # noqa: BLE001
        out["disk"] = None
    try:
        out["feed"] = _feed_state()
    except Exception:  # noqa: BLE001
        out["feed"] = None
    try:
        out["http"] = latency.stats()
    except Exception:  # noqa: BLE001
        out["http"] = {}
    # 日志占用：此前只在 prometheus() 里悄悄算，JSON 侧看不到运维最关心的
    # "日志会不会把磁盘吃满"。这里提到快照里，告警才能直接引用。
    try:
        import logrotate
        logs = logrotate.logs_overview(paths.ROOT)
        out["logs"] = {
            "files": logs,
            "total_bytes": sum(x["total_bytes"] for x in logs),
            "total_human": logrotate.human(sum(x["total_bytes"] for x in logs)),
            "over_limit_count": sum(1 for x in logs if x["over_limit"]),
            "rotating_count": sum(1 for x in logs if x["rotating"]),
        }
    except Exception:  # noqa: BLE001
        out["logs"] = None
    return out


# ── 阈值判定 ───────────────────────────────────────────────────────
def _alert(level, key, msg, advice):
    return {"level": level, "key": key, "msg": msg, "advice": advice}


def evaluate(snap=None):
    """按阈值表判定，返回 (alerts, overall_level)。"""
    s = snap or snapshot()
    th = THRESHOLDS
    alerts = []

    d = s.get("disk") or {}
    f = d.get("free_pct")
    if f is not None and f < th["disk_free_pct"]:
        alerts.append(_alert(
            "critical" if f < 5 else "warn", "disk",
            "磁盘剩余 %.1f%%（阈值 %.0f%%）" % (f, th["disk_free_pct"]),
            "清理 %s 下旧报告/缓存；确认日志轮转生效" % paths.DATA_DIR))

    rss = (s.get("process") or {}).get("rss_mb")
    if rss is not None and rss > th["rss_mb"]:
        alerts.append(_alert("warn", "memory", "进程 RSS %.0fMB（阈值 %.0fMB）"
                             % (rss, th["rss_mb"]), "考虑重启服务释放内存"))

    feed = s.get("feed") or {}
    age = feed.get("last_poll_age_sec")
    if age is None:
        pass  # 没有采集记录就不报，避免冷启动误报
    elif age > th["feed_stale_sec"]:
        alerts.append(_alert(
            "critical" if age > th["feed_stale_sec"] * 3 else "warn", "feed_stale",
            "实时流已 %.0fs 未更新（阈值 %.0fs）" % (age, th["feed_stale_sec"]),
            "查采集线程是否卡死；看 watchdog 日志有无重启记录"))
    if feed.get("ever_polled") and feed.get("thread_alive") is False:
        alerts.append(_alert("critical", "feed_dead",
                             "采集线程已消失（此前有采集记录 %s）"
                             % (feed.get("last_poll_at") or "?"),
                             "重启服务；检查 --no-live 参数是否误开"))

    h = s.get("http") or {}
    if h.get("requests", 0) >= 20 and h.get("err_rate_pct", 0) > th["err_rate_pct"]:
        alerts.append(_alert("warn", "err_rate",
                             "HTTP 错误率 %.1f%%（%d/%d，阈值 %.0f%%）"
                             % (h["err_rate_pct"], h["errors"], h["requests"],
                                th["err_rate_pct"]),
                             "看 /api/health 与 errlog 定位失败接口"))
    if h.get("samples", 0) >= th["latency_min_samples"] and \
            h.get("p95_ms", 0) / 1000.0 > th["latency_p95_sec"]:
        alerts.append(_alert("warn", "latency",
                             "请求 P95 %.2fs（阈值 %.0fs）"
                             % (h["p95_ms"] / 1000.0, th["latency_p95_sec"]),
                             "看 top_routes 里最慢的接口；问答类可调 AISEC_QA_BUDGET"))

    # 日志侧：已接轮转的日志超过硬上限才算异常；没接轮转的（rotating=False）
    # 且体积偏大则提醒接入 —— 那是"迟早会吃满磁盘"的隐患。
    lg = s.get("logs") or {}
    if lg.get("over_limit_count"):
        alerts.append(_alert("warn", "log_over_limit",
                             "%d 个日志文件已超轮转阈值（正在切分，磁盘占用可控）"
                             % lg["over_limit_count"],
                             "正常现象，确认 .1/.2 世代在生成即可"))
    quiet_big = [x for x in (lg.get("files") or [])
                 if not x.get("rotating") and x.get("total_bytes", 0) > 50 * 1024 * 1024]
    if quiet_big:
        alerts.append(_alert("warn", "log_unrotated",
                             "%d 个日志未接轮转且已超 50MB（%s）"
                             % (len(quiet_big), "、".join(x["name"] for x in quiet_big[:3])),
                             "检查是否绕过了 tools/_run_server_logged.py 直接启动服务"))

    overall = "ok"
    for a in alerts:
        if SEV_ORDER.get(a["level"], 0) > SEV_ORDER.get(overall, 0):
            overall = a["level"]
    return alerts, overall


def report():
    """给 /api/metrics 用的完整快照。"""
    s = snapshot()
    alerts, overall = evaluate(s)
    s["alerts"] = alerts
    s["alert_level"] = overall
    s["healthy"] = overall != "critical"
    s["thresholds"] = THRESHOLDS
    return s


# ── Prometheus 文本格式（能直接被现成采集器抓走）───────────────────
def prometheus():
    """导出 Prometheus 文本格式。缺失指标不臆造（直接不输出该行）。"""
    s = snapshot()
    lines = []

    def g(name, val, labels="", typ="gauge"):
        if val is None:
            return
        try:
            lines.append("aisec_%s%s %s" % (name, labels, val))
        except Exception:  # noqa: BLE001
            return

    g("uptime_seconds", s["uptime_sec"])
    g("threads", s["threads"])
    lines.append("aisec_up 1")
    g("process_rss_mb", (s.get("process") or {}).get("rss_mb"))
    g("process_cpu_pct", (s.get("process") or {}).get("cpu_pct"))
    d = s.get("disk") or {}
    g("disk_free_bytes", d.get("free_bytes"))
    g("disk_used_pct", d.get("used_pct"))
    feed = s.get("feed") or {}
    g("feed_poll_age_seconds", feed.get("last_poll_age_sec"))
    g("feed_fresh_last_round", feed.get("fresh_last_round"))
    g("feed_ok_count", feed.get("feed_ok"))
    h = s.get("http") or {}
    g("http_requests_total", h.get("requests"))
    g("http_errors_total", h.get("errors"))
    g("http_latency_p95_ms", h.get("p95_ms"))
    for r, v in (h.get("top_routes") or {}).items():
        lbl = '{route="%s"}' % r.replace('"', "'")
        g("http_requests", v.get("n"), lbl)
        g("http_errors", v.get("err"), lbl)
    try:
        g("log_total_bytes", (s.get("logs") or {}).get("total_bytes"))
        for x in (s.get("logs") or {}).get("files") or []:
            lbl = '{name="%s"}' % str(x["name"]).replace('"', "'")
            g("log_file_bytes", x["total_bytes"], lbl)
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import json
    r = report()
    print(json.dumps(r, ensure_ascii=False, indent=2))
    print("--- prometheus ---")
    print(prometheus())