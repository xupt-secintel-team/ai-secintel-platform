"""索引构建体检：分阶段打印耗时与进程内存峰值，定位启动期崩溃点。

用法： python tools/_diag_index.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def rss_mb():
    try:
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

        c = PMC()
        c.cb = ctypes.sizeof(PMC)
        ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.windll.kernel32.GetCurrentProcess(),
                                                 ctypes.byref(c), c.cb)
        return c.WorkingSetSize / 1048576.0, c.PeakPagefileUsage / 1048576.0
    except Exception:
        return -1.0, -1.0


def mem_total():
    try:
        import ctypes
        from ctypes import wintypes

        class MS(ctypes.Structure):
            _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        m = MS()
        m.dwLength = ctypes.sizeof(MS)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return (m.ullTotalPhys / 1073741824.0, m.ullAvailPhys / 1073741824.0,
                m.ullTotalPageFile / 1073741824.0, m.ullAvailPageFile / 1073741824.0)
    except Exception:
        return (0, 0, 0, 0)


def mark(tag, t0):
    rss, pf = rss_mb()
    print(f"[{tag}]  {time.time()-t0:6.1f}s   RSS={rss:8.0f}MB  提交峰值={pf:8.0f}MB", flush=True)


def main():
    t0 = time.time()
    tp, ap, tpf, apf = mem_total()
    print(f"系统物理内存 总 {tp:.1f}GB / 可用 {ap:.1f}GB ；提交(含页面文件) 总 {tpf:.1f}GB / 可用 {apf:.1f}GB", flush=True)
    mark("start", t0)

    import json
    CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "corpus.json")
    print(f"corpus: {CORPUS}  {os.path.getsize(CORPUS)/1048576:.0f}MB", flush=True)
    with open(CORPUS, "r", encoding="utf-8") as f:
        corpus = json.load(f)
    mark("json.load", t0)
    print(f"  records={len(corpus.get('records', []))} knowledge={len(corpus.get('knowledge', []))}", flush=True)
    del corpus
    import gc
    gc.collect()
    mark("freed", t0)

    from core.engine import SearchEngine
    eng = SearchEngine(CORPUS)
    mark("build_index", t0)
    print(f"  N={eng.N} df={len(eng.df)} phrase_df={len(eng.phrase_df)}", flush=True)
    print("OK —— 索引构建未崩溃", flush=True)


if __name__ == "__main__":
    main()
