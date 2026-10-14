# -*- coding: utf-8 -*-
"""组合启动器：在同一进程命名空间内同时拉起
  · 假文章服务器 tools/_e2e_article_server_v2.py  → 127.0.0.1:8892
  · 主服务 core/server.py <port>                 → 127.0.0.1:<port>
目的：让主服务（提交链接即时收录）能直连到同命名空间的假文章服务器做端到端验证。
NO_PROXY 兜底本机回环不走代理；secrets.env 按需注入。
用法：py -3 tools/_run_v5_with_fake.py [端口]
"""
import os
import subprocess
import sys
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = sys.argv[1] if len(sys.argv) > 1 else "8848"
PY = sys.executable

env = dict(os.environ)
env["NO_PROXY"] = "127.0.0.1,localhost"
env["no_proxy"] = "127.0.0.1,localhost"
env["PYTHONIOENCODING"] = "utf-8"
env["PYTHONUNBUFFERED"] = "1"
env["PYTHONDONTWRITEBYTECODE"] = "1"

secrets = os.path.join(ROOT, "secrets.env")
if os.path.exists(secrets):
    with open(secrets, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()

# 1) 假文章服务器（与主服务同命名空间，主服务可直连 8892）
fake = subprocess.Popen([PY, "tools/_e2e_article_server_v2.py"],
                        cwd=ROOT, env=env)
# 2) 主服务
srv = subprocess.Popen([PY, "-u", "core/server.py", PORT],
                       cwd=ROOT, env=env)
print(f"[combo] fake pid={fake.pid} (8892) · server pid={srv.pid} ({PORT})", flush=True)
try:
    rc = srv.wait()
finally:
    try:
        fake.terminate()
    except Exception as _sw_e:
        _swallow("tools/_run_v5_with_fake.py:46", _sw_e)
sys.exit(rc if rc is not None else 0)
