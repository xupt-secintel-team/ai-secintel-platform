# -*- coding: utf-8 -*-
"""
性能基线.py —— 一次性性能体检脚本（只读，不改数据）

用法：
    python tools/性能基线.py            # 全部接口
    python tools/性能基线.py search     # 只跑检索类

输出：每个接口的 端到端耗时（含序列化+传输）中位数/最小值，
以及接口自报的服务端计算耗时（elapsed_ms）—— 两者之差就是序列化 + 传输开销。
"""
import io
import json
import statistics
import sys
import time
import urllib.parse
import urllib.request
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

BASE = "http://127.0.0.1:8848"
N = 5


def fetch(path, gzip_ok=False, timeout=180):
    req = urllib.request.Request(BASE + path)
    if gzip_ok:
        req.add_header("Accept-Encoding", "gzip")
    t0 = time.perf_counter()
    r = urllib.request.urlopen(req, timeout=timeout)
    body = r.read()
    if r.headers.get("Content-Encoding") == "gzip":
        import gzip as _gz
        body = _gz.decompress(body)
    return (time.perf_counter() - t0) * 1000, len(body), body


def bench(label, path, gzip_ok=False, n=N):
    ts, sizes, self_ms, body = [], [], None, None
    for _ in range(n):
        ms, size, body = fetch(path, gzip_ok)
        ts.append(ms)
        sizes.append(size)
    try:
        d = json.loads(body)
        if isinstance(d, dict) and d.get("elapsed_ms") is not None:
            self_ms = d["elapsed_ms"]
    except Exception as _sw_e:  # noqa: BLE001
        _swallow("tools/性能基线.py:47", _sw_e)
    med = statistics.median(ts)
    extra = f"  服务端自报 {self_ms:.1f}ms" if self_ms is not None else ""
    print(f"{label:<26} 中位 {med:>7.1f}ms  最快 {min(ts):>7.1f}ms  "
          f"响应 {sizes[-1]:>9,}B{extra}")


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    q = lambda s: urllib.parse.quote(s)
    print("=" * 78)
    print("AI-SecIntel 性能基线  （端到端含序列化+传输；服务端自报=纯计算）")
    print("=" * 78)
    if only in ("", "static"):
        print("\n[静态资源]")
        bench("GET / (gzip)", "/", gzip_ok=True)
        bench("GET app.js (gzip)", "/app.js?v=9", gzip_ok=True)
        bench("GET styles.css (gzip)", "/styles.css?v=8", gzip_ok=True)
    if only in ("", "api"):
        print("\n[核心接口]")
        bench("GET /api/stats", "/api/stats")
        bench("GET /api/credibility", "/api/credibility")
        bench("GET /api/latest?n=22", "/api/latest?n=22")
        bench("GET /api/live", "/api/live")
        bench("GET /api/suggest?q=oll", "/api/suggest?q=oll")
    if only in ("", "search"):
        print("\n[检索]")
        bench("search 空查询", "/api/search?q=&size=12")
        bench("search 中文", "/api/search?q=" + q("提示词注入的修复建议"))
        bench("search 算子", "/api/search?q=" + q("product:ollama cvss>=9 kev:yes"))
        bench("search 带筛选", "/api/search?q=&size=12&severity=CRITICAL&exploited=1")
        bench("search sort=trust", "/api/search?q=ollama&size=12&sort=trust")
        bench("search 分页末段", "/api/search?q=&size=12&page=3000")
    if only in ("", "detail"):
        print("\n[详情 / 关联]")
        d = json.loads(fetch("/api/latest?n=3")[2])
        cid = d["items"][0]["id"]
        bench("GET /api/detail", "/api/detail?id=" + urllib.parse.quote(cid, safe=""))
        bench("GET /api/related", "/api/related?id=" + urllib.parse.quote(cid, safe=""))
        bench("GET /api/graph", "/api/graph?id=" + urllib.parse.quote(cid, safe=""))
        bench("GET /api/assets", "/api/assets?id=" + urllib.parse.quote(cid, safe=""))
    if only in ("", "big"):
        print("\n[大响应]")
        bench("GET /api/corpus (gzip)", "/api/corpus", gzip_ok=True, n=3)
        bench("GET /api/corpus (无压缩)", "/api/corpus", n=2)
    print("\n完成。")


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    main()
