# -*- coding: utf-8 -*-
"""_start_detached.py —— 后台常驻启动服务（脱离启动它的终端）

为什么需要它：
  用 `python core/server.py 8848 &` 起服务时，进程挂在启动它的 shell 会话下，
  一旦那个会话结束（比如自动化工具收工、终端窗口关闭），服务会跟着被杀掉 ——
  表现就是「日志停在『加载语料并构建索引 ...』，进程无声无息消失，没有 traceback」。
  这里用 DETACHED_PROCESS + CREATE_NEW_PROCESS_GROUP 让服务脱离父进程，
  父进程启动完立即退出，服务继续常驻。

用法：
  python tools/_start_detached.py 8848        # 后台常驻启动（默认 8848）
  python tools/_start_detached.py 8848 --no-modules   # 其余参数原样透传

日志：测试报告/运行日志_<端口>.log（追加，带启动/退出标记）
停止：netstat -ano | findstr "8848.*LISTENING"  →  taskkill /F /PID <pid>
"""

import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
args = [a for a in sys.argv[1:]]
PORT = args[0] if args else "8848"
LOG = os.path.join(ROOT, "测试报告", f"运行日志_{PORT}.log")
os.makedirs(os.path.dirname(LOG), exist_ok=True)

# ---- 环境：加载 secrets.env（只取变量名，值不打印）+ 编码与代理兜底 ----
env = dict(os.environ)
secrets = os.path.join(ROOT, "secrets.env")
loaded = []
if os.path.exists(secrets):
    with open(secrets, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
            loaded.append(k.strip())
env["NO_PROXY"] = "127.0.0.1,localhost"
env["no_proxy"] = "127.0.0.1,localhost"
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUNBUFFERED"] = "1"

lf = open(LOG, "a", encoding="utf-8", errors="replace")
lf.write(f"\n\n===== 启动（后台常驻）{time.strftime('%Y-%m-%d %H:%M:%S')} · 端口 {PORT} =====\n")
lf.flush()

flags = 0
if os.name == "nt":
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

proc = subprocess.Popen(
    [sys.executable, "-u", "core/server.py"] + args,
    cwd=ROOT, env=env,
    stdout=lf, stderr=subprocess.STDOUT,
    stdin=subprocess.DEVNULL,
    creationflags=flags, close_fds=True,
)
print(f"[_start_detached] 已后台启动 PID={proc.pid} 端口={PORT}")
print(f"[_start_detached] 日志 → {LOG}")
print(f"[_start_detached] secrets.env 变量名：{loaded}（值不打印）")
