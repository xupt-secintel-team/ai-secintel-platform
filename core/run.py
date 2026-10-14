# -*- coding: utf-8 -*-
"""
run.py — 自动重启启动脚本
Python 在 Windows 上偶发崩溃，崩了就自动重启，直到成功起来。

用法： python run.py [port]
"""
import os
import subprocess
import sys
import time

MAX_RETRIES = 10


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    port = sys.argv[1] if len(sys.argv) > 1 else "8848"
    for i in range(MAX_RETRIES):
        print(f"\n=== 第{i + 1}次启动服务器 ===")
        proc = subprocess.run(
            [sys.executable, "-B", "server.py", port],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        )
        print(f"服务器退出，返回码: {proc.returncode}")
        if proc.returncode == 0:
            break
        time.sleep(1)     # 崩溃了等 1 秒再拉起
    else:
        print("启动失败次数过多，退出")


if __name__ == "__main__":
    main()
