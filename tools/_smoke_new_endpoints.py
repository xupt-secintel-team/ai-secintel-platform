# -*- coding: utf-8 -*-
"""_smoke_new_endpoints.py —— 真起服务，端到端冒烟本轮改动

覆盖：
  1. GET  /api/trend_stats?period=weekly   → 高频漏洞统计（上轮功能不回归）
  2. POST /api/port_scan   回环真扫        → 开放端口 + 情报关联 + GET ?md=1 工单报告
  3. POST /api/project_scan octet-stream   → 大包二进制直传路径（本冒烟用小 zip 验证协议）
  4. POST /api/chat/stream 真实 LLM 流式   → 阶段/令牌事件 + done 契约 + 计时拆解

前台阻塞 + 主动关闭（自收自撤，不留后台进程）。
用法： py tools/_smoke_new_endpoints.py [端口] [--no-llm]
"""
from __future__ import annotations

import base64
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))
import loopback  # noqa: E402

loopback.enable()

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
NO_LLM = "--no-llm" in sys.argv
BASE = "http://127.0.0.1:%d" % PORT
PYEXE = sys.executable


def hit(path, timeout=30):
    r = urllib.request.urlopen(BASE + path, timeout=timeout)
    return r.status, r.read()


def post_json(path, payload, timeout=60):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.status, r.read()


def post_raw(path, data: bytes, headers: dict, timeout=120):
    req = urllib.request.Request(BASE + path, data=data,
                                 headers=headers, method="POST")
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.status, r.read()


def make_zip() -> bytes:
    """内存构造一个含 log4j-core 2.14.1 的 maven 项目 zip"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pom.xml", """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""")
        z.writestr("README.md", "# demo\n")
    return buf.getvalue()


def sse_chat(question: str, timeout=90) -> dict:
    """打 /api/chat/stream，收齐帧，返回 {stages, tokens, done, err} + 计时。"""
    body = json.dumps({"q": question}).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/api/chat/stream", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    out = {"stages": [], "tokens": "", "done": None, "err": None,
           "t_first_token": None, "t_total": None}
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        buf = b""
        while True:
            chunk = resp.read(1024)
            if not chunk:
                break
            buf += chunk
            while b"\n\n" in buf:
                frame, buf = buf.split(b"\n\n", 1)
                ev, data = "", ""
                for ln in frame.decode("utf-8", "ignore").split("\n"):
                    if ln.startswith("event:"):
                        ev = ln[6:].strip()
                    elif ln.startswith("data:"):
                        data += ln[5:].strip()
                if not ev or not data:
                    continue
                try:
                    payload = json.loads(data)
                except ValueError:
                    continue
                if ev == "stage":
                    out["stages"].append(payload.get("stage"))
                elif ev == "token":
                    if payload.get("t") == "\0":
                        continue
                    if out["t_first_token"] is None:
                        out["t_first_token"] = round(time.time() - t0, 1)
                    out["tokens"] += payload.get("t", "")
                elif ev == "done":
                    out["done"] = payload
                elif ev == "error":
                    out["err"] = payload.get("error")
    out["t_total"] = round(time.time() - t0, 1)
    return out


def main() -> int:
    print("起服务：%s core/server.py %d" % (PYEXE, PORT))
    p = subprocess.Popen(
        [PYEXE, "-u", os.path.join("core", "server.py"), str(PORT)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=0, universal_newlines=True, encoding="utf-8", errors="replace",
    )
    lines = []

    def pump():
        try:
            for ln in p.stdout:
                lines.append(ln.rstrip())
        except Exception:  # noqa: BLE001
            pass

    t = threading.Thread(target=pump, daemon=True)
    t.start()

    ok = False
    deadline = time.time() + 240
    while time.time() < deadline:
        if p.poll() is not None:
            print("★ 进程提前退出，返回码 %s" % p.returncode)
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
        # 1) 高频漏洞统计（上轮功能不回归）
        try:
            st, body = hit("/api/trend_stats?period=weekly", timeout=60)
            data = json.loads(body.decode("utf-8"))
            results["trend_stats"] = {"status": st, "top_cwe_n": len(data.get("top_cwe", []))}
            print("  trend_stats → %s  top_cwe=%d" % (st, results["trend_stats"]["top_cwe_n"]))
        except Exception as e:  # noqa: BLE001
            results["trend_stats"] = "ERR %s" % e
            print("  trend_stats → ERR %s" % e)

        # 2) 端口扫描 + 情报关联 + 工单 md
        try:
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            probe_port = srv.getsockname()[1]
            st, body = post_json("/api/port_scan", {"host": "127.0.0.1", "ports": str(probe_port)})
            data = json.loads(body.decode("utf-8"))
            corr = data.get("correlation") or {}
            results["port_scan"] = {"status": st, "open_count": data.get("open_count"),
                                    "cve_hits": corr.get("cve_hits")}
            # GET ?md=1 工单报告
            st2, body2 = hit("/api/port_scan?md=1", timeout=30)
            md = body2.decode("utf-8", "ignore")
            results["port_workorder"] = {
                "status": st2, "bytes": len(body2),
                "has_wo": "WO-" in md, "has_sla": "SLA" in md,
                "has_accept": "验收标准" in md,
            }
            print("  port_scan → %s open=%s cve=%s；工单 md=%sB WO=%s SLA=%s"
                  % (st, data.get("open_count"), corr.get("cve_hits"),
                     len(body2), results["port_workorder"]["has_wo"],
                     results["port_workorder"]["has_sla"]))
            srv.close()
        except Exception as e:  # noqa: BLE001
            results["port_scan"] = "ERR %s" % e
            print("  port_scan → ERR %s" % e)

        # 3) 项目扫描 octet-stream 直传协议（小 zip 验证协议形态）
        try:
            zdata = make_zip()
            st, body = post_raw("/api/project_scan?name=smoke-demo.zip", zdata, {
                "Content-Type": "application/octet-stream",
                "X-Project-Name": "smoke-demo.zip",
            })
            data = json.loads(body.decode("utf-8"))
            comps = data.get("components", []) if isinstance(data, dict) else []
            findings = [f.get("id") for c in comps for f in (c.get("findings") or [])]
            results["project_stream"] = {"status": st, "components": len(comps),
                                         "findings": findings[:5]}
            print("  project(octet-stream) → %s 组件=%d findings=%s"
                  % (st, len(comps), findings[:5]))
        except Exception as e:  # noqa: BLE001
            results["project_stream"] = "ERR %s" % e
            print("  project(octet-stream) → ERR %s" % e)

        # 4) 流式问答（真实 LLM；--no-llm 则只验证模板路径仍通）
        if not NO_LLM:
            try:
                s = sse_chat("最近被在野利用的高危漏洞有哪些？")
                done = s.get("done") or {}
                results["qa_stream"] = {
                    "stages": s["stages"], "err": s["err"],
                    "t_first_token": s["t_first_token"], "t_total": s["t_total"],
                    "answer_chars": len(done.get("answer") or ""),
                    "conclusion_chars": len(done.get("conclusion") or ""),
                    "conclusion_eq_answer": (done.get("conclusion") == done.get("answer")),
                    "mode": (done.get("agent") or {}).get("mode"),
                    "used_llm": done.get("used_llm"),
                    "conclusion_has_bold_mark": "**" in (done.get("conclusion") or ""),
                }
                print("  qa_stream → 首字 %ss / 总 %ss / mode=%s / 答案 %d 字 / 结论 %d 字 / 裸**=%s"
                      % (s["t_first_token"], s["t_total"],
                         results["qa_stream"]["mode"],
                         results["qa_stream"]["answer_chars"],
                         results["qa_stream"]["conclusion_chars"],
                         results["qa_stream"]["conclusion_has_bold_mark"]))
            except Exception as e:  # noqa: BLE001
                results["qa_stream"] = "ERR %s" % e
                print("  qa_stream → ERR %s" % e)
        else:
            try:
                st, body = post_json("/api/chat", {"q": "Ollama 有哪些远程代码执行漏洞",
                                                   "no_llm": True})
                d = json.loads(body.decode("utf-8"))
                results["qa_no_llm"] = {"status": st, "used_llm": d.get("used_llm"),
                                        "answer_len": len(d.get("answer") or "")}
                print("  qa(no_llm) → %s used_llm=%s" % (st, d.get("used_llm")))
            except Exception as e:  # noqa: BLE001
                results["qa_no_llm"] = "ERR %s" % e
    else:
        print("240s 内没就绪。服务输出最后 40 行：")
        for ln in lines[-40:]:
            print("   " + ln)

    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:  # noqa: BLE001
        p.kill()

    print("\n已关闭测试实例（端口 %d）" % PORT)
    print("=== 冒烟结果 ===")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
