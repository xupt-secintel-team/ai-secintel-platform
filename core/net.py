# -*- coding: utf-8 -*-
"""网络自适应层：让程序在「直连 / 代理 / 代理端口变了 / 代理 MITM 证书」各种环境下都能跑。

背景（2026-09-30）：
  本机出网必须走代理，但代理端口**会变**（这次是 2484，上次是 33252，Clash 默认 7890）。
  启动脚本只认 7890/7897 两个端口 → 拿不到代理 → 快车道退化成「12 个源 · 直连」→
  连国内源（CSDN / 安全客 / 先知 / 绿盟）都全军覆没，日志里一片 GET failed。
  另外代理做 TLS 中间人时，urllib 会抛 CERTIFICATE_VERIFY_FAILED（KEV 那一行）。

本模块提供三件事：
  1. detect_proxy()  —— 主动找出「当前真能出网」的代理（环境变量 → 本机监听端口实测）
  2. channel_for()   —— 记住每个站点上次走通的是直连还是代理，下次直接用对的那种
  3. ssl_fallback()  —— 证书校验失败时用不校验上下文重试一次（MITM 代理环境必需）

所有探测结果缓存在 data/net_state.json，不会每请求都扫一遍端口。
"""

import json
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.request
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FP = os.path.join(ROOT, "data", "net_state.json")

# 探测目标：返回 204 的最小请求，几乎不耗流量。
# ★ 第一个目标 google.com 在**境内必然超时**（走满 PROBE_TIMEOUT），
#   所以每一次探测都是"满额等完"而不是"快速失败"。这正是
#   detect_proxy 曾要 19~46s 的根源（4 段 × 2 URL × 4s + 46 个监听端口）。
#   现在由 DETECT_BUDGET 兜住总耗时；不要试图"优化"这里的顺序来省时间 ——
#   有人的环境确实需要用能否直连 google 来判断网络类型。
PROBE_URLS = ("https://www.google.com/generate_204", "https://api.github.com")
# 常见代理端口（先试这些，再扫本机 LISTENING）
COMMON_PORTS = (7890, 7891, 7896, 7897, 7898, 33252, 2484, 2080, 2081, 8080, 8888,
                1080, 1081, 10809, 20171, 51837, 33210)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"

_LOCK = threading.Lock()
_CACHE = {"ts": 0, "proxy": "", "direct_ok": None, "host_mode": {}, "loaded": False}
_TTL = 180          # 探测结果有效期（秒）；代理换端口后最多 3 分钟自动跟上
PROBE_TIMEOUT = 4   # 单次探测超时（秒）
# ★ 整轮探测的总预算（2026-10-07 加）。
#   单次超时挡不住累积：扫端口时每个端口要试 len(PROBE_URLS) 个 URL，
#   端口数 = 本机 LISTENING 数量（本机实测 20+），8 线程并发，
#   最坏 = 20/8 × 2 × 4s ≈ 20 秒。调用方是**启动路径**时这已经是灾难
#   （实测把服务卡到端口都绑不上）。
#   超预算就当"没找到"，返回一个可继续运行的答案，绝不让调用方无限等。
DETECT_BUDGET = float(os.environ.get("AISEC_PROXY_BUDGET", "8") or 8)


# ---------------- 状态存取 ----------------
def _load():
    if _CACHE.get("loaded"):
        return
    try:
        with open(STATE_FP, "r", encoding="utf-8") as f:
            d = json.load(f)
        _CACHE.update({k: v for k, v in d.items() if k in ("ts", "proxy", "direct_ok", "host_mode")})
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/net.py:51", _sw_e)
    _CACHE["loaded"] = True


def _save():
    try:
        os.makedirs(os.path.dirname(STATE_FP), exist_ok=True)
        tmp = STATE_FP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({k: _CACHE.get(k) for k in ("ts", "proxy", "direct_ok", "host_mode")},
                      f, ensure_ascii=False)
        os.replace(tmp, STATE_FP)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/net.py:64", _sw_e)


def _env_proxy():
    for k in ("AISEC_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
              "HTTP_PROXY", "http_proxy"):
        v = (os.environ.get(k) or "").strip()
        if v:
            return v
    return ""


def _config_proxy():
    """读 config.json 的 proxy 字段（用户在网页控制台/文件里设置的代理）。

    优先级最高：这是"用户显式指定"，比环境变量和自动探测都更该被尊重。
    文件不存在 / 字段缺失 / 为空都返回 ""（走后续探测）。"""
    try:
        fp = os.path.join(ROOT, "config.json")
        if os.path.isfile(fp):
            with open(fp, "r", encoding="utf-8") as f:
                d = json.load(f)
            return (d.get("proxy") or "").strip()
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/net.py:_config_proxy", _sw_e)
    return ""


def set_proxy(value):
    """运行时设置代理：原子写入 config.json 的 proxy 字段 + 立即使缓存生效。

    网页控制台「代理」按钮、或任何运行期配置入口都走这里，**无需重启**。
    返回 True/False。空值 = 清除显式代理（回到自动探测）。"""
    try:
        fp = os.path.join(ROOT, "config.json")
        cfg = {}
        if os.path.isfile(fp):
            with open(fp, "r", encoding="utf-8") as f:
                cfg = json.load(f) or {}
        cfg["proxy"] = (value or "").strip()
        tmp = fp + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, fp)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/net.py:set_proxy", _sw_e)
        return False
    _val = cfg.get("proxy") or ""
    # 同步到 os.environ：live.py / httpcompat / local_embedder / translator 等
    # 是直接读 AISEC_PROXY 环境变量的，只有这里同步了它们才跟着生效/清除。
    if _val:
        os.environ["AISEC_PROXY"] = _val
    else:
        os.environ.pop("AISEC_PROXY", None)
    with _LOCK:
        _CACHE.update(ts=time.time(), proxy=_val)
        _save()
    return True


def current_proxy():
    """当前生效的代理（config.json > AISEC_PROXY env > 探测缓存）。只读、不触发探测。"""
    p = _config_proxy() or (os.environ.get("AISEC_PROXY") or "").strip()
    return p or (_CACHE.get("proxy") or "")


def _listening_ports():
    """本机 127.0.0.1 / 0.0.0.0 上正在 LISTENING 的端口（供代理探测用）。"""
    ports = []
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=8,
                             creationflags=0x08000000 if os.name == "nt" else 0)
        txt = (out.stdout or b"").decode("utf-8", "replace")
        for line in txt.splitlines():
            if "LISTENING" not in line.upper():
                continue
            m = re.search(r"[:\.](\d{2,5})\s+\S*\s*$", line.strip())
            if not m:
                m = re.search(r"(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]):(\d{2,5})", line)
            if m:
                p = int(m.group(1))
                if 1000 < p < 65536:
                    ports.append(p)
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("core/net.py:94", _sw_e)
    # 去重保序：常用端口优先
    seen, ordered = set(), []
    for p in list(COMMON_PORTS) + sorted(set(ports)):
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered[:60]


def _curl_ok(url, proxy=None, timeout=PROBE_TIMEOUT, insecure=False):
    cmd = ["curl", "-sS", "-o", os.devnull, "-w", "%{http_code}", "--max-time", str(timeout),
           "-A", UA, url]
    if proxy:
        cmd += ["--proxy", proxy]
    if insecure:
        cmd += ["-k"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 3,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        code = (p.stdout or b"").decode("utf-8", "replace").strip()[:3]
        return code in ("200", "204", "301", "302", "403")
    except Exception:  # noqa: BLE001
        return False


def _can_direct(timeout=None):
    """直连能不能出网。timeout 给 None 时用默认值（供老调用方兼容）。"""
    t = timeout or PROBE_TIMEOUT
    return any(_curl_ok(u, timeout=t) for u in PROBE_URLS)


def _try_proxy(port, deadline=None):
    """试某个本机端口能不能当代理。

    ★ deadline（2026-10-07 加）：整轮扫描有总预算，单个端口必须**自己看预算**。
      原来只在取结果之后比对 deadline —— 但 ThreadPoolExecutor.map 会**阻塞**
      等第一个结果返回（单端口最坏 2 URL × 4s = 8s），等它返回时预算早超了。
      所以要把剩余时间传给 curl（--max-time），并用 min() 压低单次上限。
    """
    px = f"http://127.0.0.1:{port}"
    tmo = PROBE_TIMEOUT
    if deadline is not None:
        left = deadline - time.time()
        if left <= 0.5:              # 预算耗尽，连试都不值得
            return ""
        tmo = max(1, int(min(tmo, left)))
    return px if any(_curl_ok(u, proxy=px, timeout=tmo) for u in PROBE_URLS) else ""


def detect_proxy(force=False, verbose=False):
    """返回当前真能出网的代理地址；没有就返回 ""（此时应当直连）。

    顺序：环境变量 → 上次成功的代理 → 扫本机监听端口实测。
    结果缓存 3 分钟，代理换端口后会自动重新发现。

    ★ 三段探测**共用一个总预算** DETECT_BUDGET（2026-10-07 加）。
      原来每段各自用自己的 4s 超时，累加起来远超预期：
        环境变量 2×4s + 上次代理 2×4s + 直连 2×4s + 扫 46 端口 ≈ 19s
      而调用方在**启动路径**上（m1 启动钩子里的 blog_feeds），
      实测把这个主线程堵到"端口都绑不上"。
      现在每段都按"剩余预算"压低单次 curl --max-time，用完就返回，
      保证总耗时不超过 DETECT_BUDGET（默认 8s，可用 AISEC_PROXY_BUDGET 调）。
    """
    _load()
    with _LOCK:
        now = time.time()
        # ★ 命中判断必须按 ts 而不是 proxy（2026-10-18）：
        #   探测结果为空（本机没有可用代理）也写进了缓存（ts=now, proxy=""），
        #   但原判据 `_CACHE.get("proxy")` 对空字符串恒为假 → 缓存永不命中，
        #   无代理环境下每次 http_get 都重新全量扫端口 8~10s，
        #   快车道一轮被拖到 1~3 分钟、大响应源全部逼近超时。
        if not force and (_CACHE.get("ts") or 0) \
                and now - float(_CACHE.get("ts") or 0) < _TTL:
            return _CACHE.get("proxy") or ""

        # 整轮预算的截止时刻：下面三段探测共用
        _deadline = time.time() + DETECT_BUDGET

        def _tmo():
            """这一段还能用多少秒做单次 curl（至少 1 秒）。"""
            return max(1, int(min(PROBE_TIMEOUT, _deadline - time.time())))

        env = _env_proxy()
        # ★ 显式代理（config.json 的 proxy 字段，或 secrets.env / 环境变量的
        #   AISEC_PROXY）直接信任，不做 google/github 探针"二次验证"（2026-10-18）。
        #   原因：本机代理可能是**选择性代理**——能通 NVD / arXiv / CISA，但
        #   google / github 被上游拦截。若仍拿 google/github 当验收探针，会误判
        #   "代理不可用"→ 退回直连 → 境外源 45s 超时逐个拖垮全量同步（一轮 2~3 小时）。
        #   用户显式配了就该信它。
        _explicit = _config_proxy() or (os.environ.get("AISEC_PROXY") or "").strip()
        if _explicit:
            _CACHE.update(ts=now, proxy=_explicit)
            _save()
            if verbose:
                print(f"[net] 代理（显式配置）：{_explicit}", flush=True)
            return _explicit

        if env and any(_curl_ok(u, proxy=env, timeout=_tmo()) for u in PROBE_URLS):
            _CACHE.update(ts=now, proxy=env)
            _save()
            if verbose:
                print(f"[net] 代理（环境变量）：{env}", flush=True)
            return env

        last = _CACHE.get("proxy") or ""
        if last and any(_curl_ok(u, proxy=last, timeout=_tmo()) for u in PROBE_URLS):
            _CACHE.update(ts=now, proxy=last)
            _save()
            if verbose:
                print(f"[net] 代理（沿用上次）：{last}", flush=True)
            return last

        if _can_direct(_tmo()):                # 直连就通 —— 没必要找代理
            _CACHE.update(ts=now, proxy="", direct_ok=True)
            _save()
            if verbose:
                print("[net] 直连可用，无需代理", flush=True)
            return ""

        from concurrent.futures import ThreadPoolExecutor
        _w = 8
        try:                              # 性能档位：慢机器少开线程扫端口
            from envprofile import T
            _w = T.workers(8)
        except Exception:
            pass
        # ★ 扫端口段复用函数入口算好的 _deadline（已含前面两段花掉的时间）。
        #   关键是**把 deadline 传进每个探测**（_try_proxy 里据此压低
        #   curl --max-time），而不是在这里等结果回来再判断 ——
        #   map 是惰性的，等第一个结果就可能已经超支 8 秒。
        _best = ""
        _ports = list(_listening_ports())
        try:
            with ThreadPoolExecutor(_w) as _ex:
                _futs = [_ex.submit(_try_proxy, p, _deadline) for p in _ports]
                for _f in _futs:
                    try:
                        px = _f.result(timeout=max(0.5, _deadline - time.time()))
                    except Exception:  # noqa: BLE001
                        px = ""
                    if px:
                        _best = px
                        break
                    if time.time() > _deadline:
                        break
        except Exception as e:  # noqa: BLE001
            if verbose:
                print("[net] 代理扫描异常：%s" % str(e)[:80], flush=True)
        if time.time() > _deadline and verbose and not _best:
            print("[net] 代理扫描超过 %.0fs 预算，放弃（不影响服务启动）"
                  % DETECT_BUDGET, flush=True)
        if _best:
            _CACHE.update(ts=now, proxy=_best, direct_ok=False)
            _save()
            if verbose:
                print(f"[net] 代理（端口探测）：{_best}", flush=True)
            return _best

        _CACHE.update(ts=now, proxy="", direct_ok=False)
        _save()
        if verbose:
            print("[net] 未发现可用代理，且直连不通 —— 抓取将失败，但服务本身照常运行", flush=True)
        return ""


# ---------------- 每站点通道记忆 ----------------
def channel_for(host):
    """该站点上次走通的是 'proxy' 还是 'direct'；没记录返回 ''。"""
    _load()
    return (_CACHE.get("host_mode") or {}).get(host, "")


def remember(host, mode):
    _load()
    with _LOCK:
        (_CACHE.setdefault("host_mode", {}))[host] = mode
        _save()


def forget(host):
    """清除某个站点的通道记忆（走记忆通道失败时调用，下轮重新双候选探测）。

    网络环境会变（代理换端口、断网、公司网切换），记忆错了就得能纠正，
    否则该站点会一直只试一条走不通的路。
    """
    _load()
    with _LOCK:
        hm = _CACHE.get("host_mode") or {}
        if host in hm:
            hm.pop(host, None)
            _save()
            return True
    return False


def ssl_fallback(exc):
    """判断异常是否为证书校验失败（代理 TLS 中间人的典型症状）。"""
    s = str(exc).lower()
    return ("certificate_verify_failed" in s or "certificate verify failed" in s
            or "hostname mismatch" in s)


def opener(proxy="", verify=True):
    """构造 urllib opener：可选代理 + 可选跳过证书校验（MITM 代理环境）。"""
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


if __name__ == "__main__":
    px = detect_proxy(verbose=True)
    print("detect_proxy =>", px or "(直连)")
    print("direct ok    =>", _can_direct())
