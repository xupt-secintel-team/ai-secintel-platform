# -*- coding: utf-8 -*-
"""v12 窄屏响应式快照：复用 _ui_snap 的静态服务 + CDP，只拍检索视图在 820px / 390px 两档。
用完可删。"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
sys.argv = ["_fx_narrow", "v12n"]
spec = importlib.util.spec_from_file_location("uisnap", os.path.join(ROOT, "测试报告", "_ui_snap.py"))
snap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snap)
ushot = snap.ushot
CDP, EDGE, OUT, free_port = ushot.CDP, ushot.EDGE, ushot.OUT, ushot.free_port


def main():
    os.makedirs(OUT, exist_ok=True)
    port = 8899
    while not free_port(port):
        port += 1
    snap.start_static(port)
    base = "http://127.0.0.1:%d/frontend/index.html" % port

    prof = tempfile.mkdtemp(prefix="edgecdpn_")
    dport = 9451
    while not free_port(dport):
        dport += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         "--remote-debugging-port=%d" % dport, "--remote-allow-origins=*",
         "--user-data-dir=%s" % prof, "--window-size=900,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    ws_url = None
    for _ in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/json" % dport, timeout=2) as r:
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws_url = t["webSocketDebuggerUrl"]
                        break
            if ws_url:
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not ws_url:
        print("FAIL no target")
        proc.kill()
        return 1

    c = CDP(ws_url)
    c.send("Page.enable")
    c.send("Runtime.enable")

    def go(w, h, name):
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 700})
        c.send("Page.navigate", {"url": base + "?view=search"})
        c.pump(3.0)
        c.js(snap.MOCK)
        c.pump(2.2)
        p = os.path.join(OUT, "v12n_%s.png" % name)
        print("  [%s] ready=%s shot=%s" % (name, c.js("!!window.__snapReady"), c.shot(p)))

    go(820, 1000, "w820")
    go(390, 844, "w390")
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
