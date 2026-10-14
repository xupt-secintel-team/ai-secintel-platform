# -*- coding: utf-8 -*-
"""_smoke_port_hit.py —— 端口工单「有命中场景」真服务冒烟

为什么单独写这个（而不塞进 _smoke_new_endpoints.py）：
  主冒烟的 port_scan 用回环临时 listener，服务不主动推 banner，且端口
  不是已知指纹端口 → correlate 拿到 cve_hits=0、WO=False，这是「无风险
  不派单」的正确行为，但**测不到 WO-xxx 工单条目在真实 HTTP 路由下是否
  真的生成**。离线回归 _test_round9_night.py 已用 OpenSSH 8.2p1 + Tomcat
  9.0.30 验证了 correlate/workorder_markdown 的产物，缺的是「真起服务 →
  POST /api/port_scan → 假 SSH banner → GET ?md=1 出 WO-」这一整条路由。

做法：
  起一个假 SSH 服务（accept 后立即 send 一行 "SSH-2.0-OpenSSH_8.2p1 Ubuntu"），
  端口随机。端口扫描的 _probe 是被动 recv banner，会收到这行并识别出
  OpenSSH 8.2p1（高置信），correlate 命中本地情报库里的 CVE → 工单报告
  应出现 WO- 条目、SLA、验收标准。

前台阻塞 + 主动关闭，自收自撤。用法：
  py tools/_smoke_port_hit.py [端口]
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable

# ★ 目标选 Tomcat 9.0.30（真引擎命中 40 条：16 CRITICAL + 24 HIGH + 2 KEV），
#   而不是 OpenSSH 8.2p1 —— 后者在情报库里只命中 1 条中危 CVE-2026-59998，
#   按"中危列入跟踪、不出 WO 工单"的设计，本就不该生成 WO-，用它测工单是选错目标。
#   真服务路由下的 WO- 生成必须用一个**确定命中高危/KEV** 的指纹来验证。
FAKE_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"   # 保留：验证指纹识别本身
FAKE_HTTP_SERVER = b"Apache Tomcat/9.0.30"                     # 命中 16 CRITICAL + 2 KEV


def hit(path, timeout=30):
    r = urllib.request.urlopen(BASE + path, timeout=timeout)
    return r.status, r.read()


def post_json(path, payload, timeout=60):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.status, r.read()


def fake_ssh_server(banner: bytes):
    """返回 (port, 停止函数)。accept 后立刻发 banner 再关，模拟 SSH 服务。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(banner)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    def _stop():
        stop.set()
        try:
            srv.close()
        except OSError:
            pass

    return port, _stop


def fake_http_server(port: int, server_header: bytes):
    """监听固定端口，收到 HEAD 后回 HTTP 响应带 Server 头（模拟 Tomcat）。

    必须用固定端口（8080）且在 _HTTP_PROBE_PORTS 里，_http_probe 才会对它
    发 HEAD 探测；随机高位端口不会触发 HTTP 指纹探测。
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(0.5)
    stop = threading.Event()
    resp = (b"HTTP/1.0 200 OK\r\nServer: " + server_header + b"\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n")

    def _loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.recv(4096)          # 读掉 HEAD 请求
                conn.sendall(resp)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    t = threading.Thread(target=_loop, daemon=True)
    t.start()

    def _stop():
        stop.set()
        try:
            srv.close()
        except OSError:
            pass

    return _stop


def main() -> int:
    # 用 Tomcat 9.0.30（命中 16 CRITICAL + 2 KEV）验证 WO- 工单真服务路由生成。
    # 固定 8080：必须在 _HTTP_PROBE_PORTS 里，_http_probe 才会发 HEAD 拿指纹。
    fstop = fake_http_server(8080, FAKE_HTTP_SERVER)
    print("假 Tomcat 服务（Server: Apache Tomcat/9.0.30）监听 127.0.0.1:8080")

    p = subprocess.Popen(
        [PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace")

    lines = []

    def pump():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=pump, daemon=True).start()

    ok = False
    deadline = time.time() + 240
    while time.time() < deadline:
        if p.poll() is not None:
            print("★ 服务提前退出，返回码 %s" % p.returncode)
            break
        try:
            st, _ = hit("/api/health", timeout=8)
            print("  /api/health → %s" % st)
            ok = True
            break
        except Exception:
            time.sleep(2)

    results = {}
    if ok:
        try:
            st, body = post_json("/api/port_scan",
                                 {"host": "127.0.0.1", "ports": "8080"})
            data = json.loads(body.decode("utf-8"))
            corr = data.get("correlation") or {}
            ops = data.get("open_ports") or []
            hit_port = next((p for p in ops if p.get("port") == 8080), {})
            results["port_scan"] = {
                "status": st,
                "open_count": data.get("open_count"),
                "product": hit_port.get("product"),
                "version": hit_port.get("version"),
                "ident_conf": hit_port.get("ident_conf"),
                "risk_level": hit_port.get("risk_level"),
                "cve_hits": corr.get("cve_hits"),
                "critical": corr.get("critical"),
                "high": corr.get("high"),
                "exploited": corr.get("exploited"),
                "kev_ids": (corr.get("kev_ids") or [])[:5],
            }
            # GET ?md=1 → 工单报告
            st2, body2 = hit("/api/port_scan?md=1", timeout=30)
            md = body2.decode("utf-8", "ignore")
            import re as _re
            wo_ids = _re.findall(r"(WO-[A-Za-z0-9\-_]+)", md)
            results["workorder"] = {
                "status": st2, "bytes": len(body2),
                "has_wo": "WO-" in md,
                "wo_count": len(wo_ids),
                "has_sla": "SLA" in md,
                "has_accept": "验收标准" in md,
                "has_rescan": "复测计划" in md,
                "has_cve": "CVE-" in md,
            }
            print("  port_scan → %s open=%s 指纹=%s %s(%s) 风险=%s cve=%s"
                  % (st, data.get("open_count"),
                     hit_port.get("product"), hit_port.get("version"),
                     hit_port.get("ident_conf"), hit_port.get("risk_level"),
                     corr.get("cve_hits")))
            print("  工单 md=%dB WO=%s 条数=%s SLA=%s 验收=%s 复测=%s CVE=%s"
                  % (len(body2), results["workorder"]["has_wo"],
                     results["workorder"]["wo_count"],
                     results["workorder"]["has_sla"],
                     results["workorder"]["has_accept"],
                     results["workorder"]["has_rescan"],
                     results["workorder"]["has_cve"]))
        except Exception as e:  # noqa: BLE001
            results["port_scan"] = "ERR %s" % e
            print("  port_scan → ERR %s" % e)
    else:
        print("240s 内没就绪。服务输出最后 40 行：")
        for ln in lines[-40:]:
            print("   " + ln)

    fstop()
    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:  # noqa: BLE001
        p.kill()

    print("\n已关闭测试实例（端口 %d）" % PORT)
    print("=== 有命中冒烟结果 ===")
    print(json.dumps(results, ensure_ascii=False, indent=2))

    # 判定：真服务路由下应生成 WO- 工单
    w = results.get("workorder") or {}
    if ok and w.get("has_wo") and w.get("has_sla") and w.get("has_accept"):
        print("✅ 有命中场景工单生成成功")
        return 0
    print("❌ 有命中场景未生成工单（见上方明细）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
