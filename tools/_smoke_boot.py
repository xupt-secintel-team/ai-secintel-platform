# -*- coding: utf-8 -*-
"""_smoke_boot.py —— 真起一次服务并打一次接口（自收自撤，不留后台进程）

## 为什么不用 shell 后台跑

`python core/server.py &` 在本环境里会被**会话回收**掉，进程悄悄消失、
日志停在"装载模块"就没了，看起来像启动失败，其实是被回收。
所以必须**前台阻塞 + 定时打接口 + 主动关闭**，才能拿到可信结论。

用法： py tools/_smoke_boot.py [端口]
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

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def hit(path, timeout=20):
    r = urllib.request.urlopen(BASE + path, timeout=timeout)
    return r.status, r.read()[:120]


def main() -> int:
    print("起服务：%s core/server.py %d" % (PYEXE, PORT))
    p = subprocess.Popen([PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
                         cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         bufsize=0, universal_newlines=True,
                         encoding="utf-8", errors="replace")
    # 服务冷启动要加载语料 + 建索引（实测 8s 命中缓存，量大了更久），给足 180s
    ok = False
    deadline = time.time() + 180
    lines = []
    # 后台线程把子进程输出搬进 lines —— 必须在 Popen 之后立刻起，
    # 否则 PIPE 缓冲区写满会让子进程**卡在 write 上永不退出**（表现就是"超时"）。
    def pump():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:  # noqa: BLE001
            pass
    t = threading.Thread(target=pump, daemon=True)
    t.start()

    while time.time() < deadline:
        if p.poll() is not None:
            print("★ 进程提前退出，返回码 %s" % p.returncode)
            break
        try:
            st, body = hit("/api/health", timeout=8)
            print("  /api/health → %s  %s" % (st, body[:80]))
            ok = True
            break
        except Exception:
            time.sleep(2)
    if ok:
        for path in ("/api/latest?n=2", "/api/stats"):
            try:
                st, body = hit(path)
                print("  %-22s → %s  %s" % (path, st, body[:60]))
            except Exception as e:  # noqa: BLE001
                print("  %-22s → ERR %s" % (path, e))
    else:
        print("180s 内没就绪。服务输出最后 30 行：")
        for l in lines[-30:]:
            print("   " + l)
    # 自收自撤
    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:  # noqa: BLE001
        p.kill()
    print("\n已关闭测试实例（端口 %d）" % PORT)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
