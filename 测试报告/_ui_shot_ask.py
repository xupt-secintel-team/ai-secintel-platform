# -*- coding: utf-8 -*-
"""补截问答演示图：ask 视图真实提问 → 等回答渲染 → 截图。"""
import base64, json, os, socket, subprocess, sys, tempfile, time, urllib.request

ROOT = r"E:\aisec-D_3\aisec-D_2.0(1)\aisec-D_2.0"
import websocket

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(EDGE):
    EDGE = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
OUT = os.path.join(ROOT, "交付物", "图")
BASE = "http://127.0.0.1:8848"
PORT = 9433


class CDP:
    def __init__(self, url):
        self.ws = websocket.create_connection(url, timeout=30, max_size=80 * 1024 * 1024)
        self.i = 0; self.events = []

    def send(self, method, params=None, wait=True):
        self.i += 1; mid = self.i
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        if not wait: return None
        t0 = time.time()
        while time.time() - t0 < 60:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid: return msg
            if "method" in msg: self.events.append(msg)
        return None

    def pump(self, secs):
        t0 = time.time(); self.ws.settimeout(1.0)
        while time.time() - t0 < secs:
            try: msg = json.loads(self.ws.recv())
            except Exception: continue
            if "method" in msg: self.events.append(msg)
        self.ws.settimeout(60)

    def js(self, expr):
        r = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        try: return r["result"]["result"].get("value")
        except Exception: return None

    def shot(self, path):
        r = self.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": False})
        with open(path, "wb") as f: f.write(base64.b64decode(r["result"]["data"]))
        return os.path.getsize(path)


def free_port(p):
    s = socket.socket()
    try: s.bind(("127.0.0.1", p)); return True
    except OSError: return False
    finally: s.close()


def main():
    prof = tempfile.mkdtemp(prefix="edgecdp_")
    port = PORT
    while not free_port(port): port += 1
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
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws_url = t["webSocketDebuggerUrl"]; break
            if ws_url: break
        except Exception: pass
        time.sleep(0.5)
    if not ws_url:
        print("FAIL"); proc.kill(); return 1
    c = CDP(ws_url)
    c.send("Page.enable"); c.send("Runtime.enable"); c.send("Log.enable")
    c.send("Emulation.setDeviceMetricsOverride", {"width": 1600, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
    c.send("Page.navigate", {"url": f"{BASE}/?view=ask"}); c.pump(7.0)

    # 填入问题并发送
    q = "Ollama 有哪些远程代码执行漏洞？"
    c.js(f"var ta=$('qa-q'); ta.value={json.dumps(q)}; ta.dispatchEvent(new Event('input'));")
    c.pump(0.8)
    c.js("$('qa-go').click()")
    print("已发送提问，等待回答渲染 ...")
    # 轮询等待：#qa-msgs 出现足够长的回答（真实 LLM 结论远长于提示文案），最长 120s
    ans_len = 0
    for i in range(40):
        c.pump(3.0)
        busy = c.js("var b=$('qa-go'); b?(b.disabled||b.classList.contains('busy')):true")
        ans_len = c.js("var m=$('qa-msgs'); m?(m.innerText||'').length:0") or 0
        print(f"  poll{i}: busy={busy} msgs_len={ans_len}")
        if not busy and ans_len > 500:
            break
    # 收起模型设置面板（如被自动展开）
    c.js("var f=$('qa-cfg'); if(f) f.classList.remove('on');")
    c.pump(2.0)
    sz = c.shot(os.path.join(OUT, "new_ask_demo.png"))
    print("shot new_ask_demo", sz)
    try: c.ws.close()
    except Exception: pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
