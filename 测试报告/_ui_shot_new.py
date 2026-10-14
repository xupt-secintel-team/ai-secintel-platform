# -*- coding: utf-8 -*-
"""截取 AI-SecIntel 新版前端 UI 截图（用于替换竞赛报告旧图）。

用法： D:\\python\\python.exe 测试报告/_ui_shot_new.py
产物： 交付物/图/new_*.png
"""
import base64, json, os, socket, subprocess, sys, tempfile, time, urllib.request

ROOT = r"E:\aisec-D_3\aisec-D_2.0(1)\aisec-D_2.0"
sys.path.insert(0, os.path.join(ROOT, "测试报告"))
import websocket  # 系统 python 3.14 自带

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(EDGE):
    EDGE = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
OUT = os.path.join(ROOT, "交付物", "图")
BASE = "http://127.0.0.1:8848"
PORT = 9422


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
        r = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        try:
            return r["result"]["result"].get("value")
        except Exception:
            return None

    def shot(self, path):
        r = self.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["result"]["data"]))
        return os.path.getsize(path)


def free_port(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p)); return True
    except OSError:
        return False
    finally:
        s.close()


def main():
    os.makedirs(OUT, exist_ok=True)
    prof = tempfile.mkdtemp(prefix="edgecdp_")
    port = PORT
    while not free_port(port):
        port += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1", "--disable-features=msEdgeFirstRunExperience",
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
                    ws_url = t["webSocketDebuggerUrl"]; break
            if ws_url: break
        except Exception:
            pass
        time.sleep(0.5)
    if not ws_url:
        print("FAIL: no debug target"); proc.kill(); return 1
    c = CDP(ws_url)
    c.send("Page.enable"); c.send("Runtime.enable"); c.send("Log.enable")

    def viewport(w, h):
        c.send("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})

    def nav(url, wait=6.0):
        c.send("Page.navigate", {"url": url}); c.pump(wait)

    viewport(1600, 1000)

    # 1. 检索工作区主界面
    nav(f"{BASE}/?view=search", 7.0)
    c.shot(os.path.join(OUT, "new_search.png")); print("shot new_search")

    # 2. 漏洞详情（openDetail CVE-2024-37032）
    c.js("openDetail('CVE-2024-37032')"); c.pump(5.0)
    c.shot(os.path.join(OUT, "new_detail.png")); print("shot new_detail")

    # 3. 监测台
    nav(f"{BASE}/?view=monitor", 7.0)
    c.shot(os.path.join(OUT, "new_monitor.png")); print("shot new_monitor")

    # 4. 富化界面
    nav(f"{BASE}/?view=enrich", 7.0)
    c.shot(os.path.join(OUT, "new_enrich.png")); print("shot new_enrich")

    # 5-7. 富化案例（详情面板滚动上/中/下）
    nav(f"{BASE}/?view=search", 5.0)
    c.js("openDetail('CVE-2024-37032')"); c.pump(5.0)
    c.shot(os.path.join(OUT, "new_case_top.png")); print("shot case_top")
    c.js("var db=$('db'); db.scrollTop = Math.floor(db.scrollHeight*0.5);"); c.pump(1.5)
    c.shot(os.path.join(OUT, "new_case_mid.png")); print("shot case_mid")
    c.js("var db=$('db'); db.scrollTop = db.scrollHeight;"); c.pump(1.5)
    c.shot(os.path.join(OUT, "new_case_bot.png")); print("shot case_bot")

    # 8. 问答界面
    nav(f"{BASE}/?view=ask", 7.0)
    c.shot(os.path.join(OUT, "new_ask.png")); print("shot new_ask")

    errs = []
    for e in c.events:
        m = e.get("method")
        if m == "Runtime.exceptionThrown":
            errs.append("EXC " + str(e["params"]["exceptionDetails"].get("text")))
        elif m == "Log.entryAdded" and e["params"]["entry"].get("level") == "error":
            errs.append("LOG " + str(e["params"]["entry"].get("text"))[:160])
    print("\nconsole errors:", len(errs))
    for e in errs[:15]:
        print("  ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
