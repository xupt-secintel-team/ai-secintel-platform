# -*- coding: utf-8 -*-
"""无头 Edge + CDP：截多视图 / 双主题 / 窄屏，并收集控制台 error。

用法： py -3.13 测试报告/_ui_shot.py [前缀]
产物： 测试报告/_ui_shots/<前缀>_*.png
"""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import websocket

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
OUT = os.path.join(ROOT, "测试报告", "_ui_shots")
BASE = "http://127.0.0.1:8848"
PORT = 9411


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=30, max_size=80 * 1024 * 1024)
        self.i = 0
        self.events = []

    def send(self, method, params=None, wait=True):
        self.i += 1
        mid = self.i
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        if not wait:
            return None
        t0 = time.time()
        while time.time() - t0 < 40:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                return msg
            if "method" in msg:
                self.events.append(msg)
        return None

    def pump(self, secs):
        t0 = time.time()
        self.ws.settimeout(1.0)
        while time.time() - t0 < secs:
            try:
                msg = json.loads(self.ws.recv())
            except Exception:
                continue
            if "method" in msg:
                self.events.append(msg)
        self.ws.settimeout(30)

    def js(self, expr):
        r = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                           "awaitPromise": True})
        try:
            return r["result"]["result"].get("value")
        except Exception:
            return None

    def shot(self, path):
        r = self.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        data = r["result"]["data"]
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))
        return os.path.getsize(path)

    def errors(self):
        out = []
        for e in self.events:
            m = e.get("method")
            if m == "Runtime.exceptionThrown":
                d = e["params"]["exceptionDetails"]
                out.append("EXC " + str(d.get("text")) + " " + str(d.get("exception", {}).get("description", ""))[:220])
            elif m == "Log.entryAdded":
                en = e["params"]["entry"]
                if en.get("level") in ("error",):
                    out.append("LOG " + str(en.get("text"))[:220])
            elif m == "Runtime.consoleAPICalled":
                if e["params"].get("type") == "error":
                    args = " ".join(str(a.get("value", a.get("description", "")))[:160]
                                    for a in e["params"].get("args", []))
                    out.append("CONSOLE " + args)
        return out


def free_port(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "shot"
    os.makedirs(OUT, exist_ok=True)
    prof = tempfile.mkdtemp(prefix="edgecdp_")
    port = PORT
    while not free_port(port):
        port += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         f"--remote-debugging-port={port}", "--remote-allow-origins=*",
         f"--user-data-dir={prof}", "--window-size=1600,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ws_url = None
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                targets = json.loads(r.read().decode())
            for t in targets:
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    ws_url = t["webSocketDebuggerUrl"]
                    break
            if ws_url:
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not ws_url:
        print("FAIL: 拿不到调试目标")
        proc.kill()
        return 1

    c = CDP(ws_url)
    c.send("Page.enable")
    c.send("Runtime.enable")
    c.send("Log.enable")

    def go(view, theme=None, w=1600, h=1000, name=None):
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})
        c.send("Page.navigate", {"url": f"{BASE}/?view={view}"})
        c.pump(6.0)
        if theme:
            c.js(f"(function(){{var m=localStorage.getItem('asi-theme-mode');"
                 f"if(m!=='{theme}'){{document.getElementById('themebtn').click();}}}})()")
            c.pump(2.2)
        p = os.path.join(OUT, f"{prefix}_{name or view}.png")
        sz = c.shot(p)
        print("  shot", os.path.basename(p), sz)
        return p

    # 深色四视图
    for v in ("search", "monitor", "enrich", "ask"):
        go(v)
    # 浅色（切一次主题）
    c.send("Page.navigate", {"url": f"{BASE}/?view=search&mode=skim"})
    c.pump(6.0)
    got = c.js("document.documentElement.getAttribute('data-theme')")
    print("  当前主题:", got)
    if got != "light":
        c.js("document.getElementById('themebtn').click()")
        c.pump(2.5)
    print("  切换后:", c.js("document.documentElement.getAttribute('data-theme')"))
    c.shot(os.path.join(OUT, f"{prefix}_search_light.png"))
    print("  shot", f"{prefix}_search_light.png")
    # 窄屏（1100 宽，检查器转浮层）
    c.js("document.getElementById('themebtn').click()")
    c.pump(1.5)
    c.send("Emulation.setDeviceMetricsOverride",
           {"width": 1100, "height": 900, "deviceScaleFactor": 1, "mobile": False})
    c.send("Page.navigate", {"url": f"{BASE}/?view=search"})
    c.pump(6.0)
    c.shot(os.path.join(OUT, f"{prefix}_search_narrow.png"))
    print("  shot", f"{prefix}_search_narrow.png")
    # 移动端（620 宽）
    c.send("Emulation.setDeviceMetricsOverride",
           {"width": 560, "height": 900, "deviceScaleFactor": 1, "mobile": True})
    c.send("Page.navigate", {"url": f"{BASE}/?view=monitor"})
    c.pump(6.0)
    c.shot(os.path.join(OUT, f"{prefix}_monitor_mobile.png"))
    print("  shot", f"{prefix}_monitor_mobile.png")

    errs = c.errors()
    print("\n控制台 error 数：", len(errs))
    for e in errs[:20]:
        print("   ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
