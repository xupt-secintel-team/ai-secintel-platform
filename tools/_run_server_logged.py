# -*- coding: utf-8 -*-
"""_run_server_logged.py —— 「带日志启动」：加载 secrets.env（值不打印）后启动服务，输出落盘。

两种启动方式，按需选：
  · 双击 `启动服务.bat`        → 日志打在它自己的窗口里（演示时看得到滚动），不落盘
  · py -3 tools/_run_server_logged.py [端口]  → 日志落盘 `测试报告/运行日志_<端口>.log`
    （带「===== 启动 … =====」与「===== 进程退出，返回码 N =====」两端标记，适合留证/事后排查）

它多做三件 .bat 不做的事：PYTHONIOENCODING=utf-8（中文不乱码）、PYTHONUNBUFFERED=1（日志实时落盘）、
NO_PROXY 兜底（本机回环不走代理）。参数透传给 core/server.py，例如 `--no-live`、`--no-modules`。
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
from logrotate import RotatingLog  # noqa: E402

PORT = sys.argv[1] if len(sys.argv) > 1 else "8848"
LOG = os.path.join(ROOT, "测试报告", f"运行日志_{PORT}.log")
# 上限 8MB × 保留 5 世代 = 单日志最多约 48MB。原先是裸 append 无上限，
# 常驻几周会把磁盘吃满，而磁盘写满正是"服务起不来"的典型诱因（自锁死）。
MAX_MB = int(os.environ.get("AISEC_LOG_MAX_MB", "8") or 8)
KEEP = int(os.environ.get("AISEC_LOG_KEEP", "5") or 5)

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

print(f"[_run_server_logged] 端口 {PORT} · 日志 {LOG}")
print(f"[_run_server_logged] 从 secrets.env 载入的变量名：{loaded}（值不打印）")

os.makedirs(os.path.dirname(LOG), exist_ok=True)
# 轮转不能靠"把句柄直接传给子进程"：Windows 上 os.replace 无法搬动
# 仍被子进程持有的文件。所以改成 管道 → 父进程线程 → RotatingLog，
# 由父进程独占写入权，轮转时才不会卡在"文件被占用"。
rl = RotatingLog(LOG, max_bytes=MAX_MB * 1024 * 1024, keep=KEEP)
rl.write("\n\n===== 启动 %s · 端口 %s · 日志上限 %dMB×%d 份 =====\n"
         % (time.strftime("%Y-%m-%d %H:%M:%S"), PORT, MAX_MB, KEEP))
rl.flush()


def _pump(stream, sink):
    """把子进程输出按行搬进轮转日志。bytes → str 解码用 replace，
    子进程万一输出非法字节序列也不会把日志线程带崩。"""
    try:
        for raw in iter(stream.readline, b""):
            sink.write(raw.decode("utf-8", "replace"))
        sink.flush()
    except Exception as e:  # noqa: BLE001
        sink.write("[_run_server_logged] 日志搬运线程结束：%s\n" % str(e)[:120])


proc = subprocess.Popen([sys.executable, "-u", "core/server.py", str(PORT)],
                        cwd=ROOT, env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, bufsize=0)
import threading  # noqa: E402

_t = threading.Thread(target=_pump, args=(proc.stdout, rl), daemon=True,
                      name="log-pump")
_t.start()
print(f"[_run_server_logged] 服务进程 PID={proc.pid}")
rc = proc.wait()
_t.join(timeout=5)
rl.write("\n===== 进程退出，返回码 %s（%s）· 本次日志轮转 %d 次 =====\n"
         % (rc, time.strftime("%Y-%m-%d %H:%M:%S"), rl.rotations))
rl.close()
st = None
try:
    sys.path.insert(0, os.path.join(ROOT, "core"))
    import logrotate
    st = logrotate.logs_overview(ROOT)
except Exception:  # noqa: BLE001
    pass
print(f"[_run_server_logged] 服务已退出，返回码 {rc}（详情见 {LOG}）")
if st:
    for x in st:
        if "运行日志" in x["name"]:
            print("[_run_server_logged] 日志占用 %s（%d 个世代，%s）"
                  % (x["total_human"], x["generations"],
                     "已超限" if x["over_limit"] else "轮转中"))
sys.exit(rc)
