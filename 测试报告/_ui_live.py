# -*- coding: utf-8 -*-
"""截图（轮询等待真实数据渲染完成 + 强制到目标主题）。
用法： py -3.13 测试报告/_ui_live.py [前缀]
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
spec = importlib.util.spec_from_file_location("uishot", os.path.join(ROOT, "测试报告", "_ui_shot.py"))
ushot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ushot)
CDP, EDGE, OUT, BASE, free_port = ushot.CDP, ushot.EDGE, ushot.OUT, ushot.BASE, ushot.free_port

prefix = sys.argv[1] if len(sys.argv) > 1 else "live"
W_SEARCH = ("document.querySelectorAll('#results .rcard,#results .row,#results article').length>0 "
            "|| (document.getElementById('answer')&&document.getElementById('answer').innerHTML.length>200)")
W_MON = "document.querySelectorAll('#monboard .kpi').length>=3"
W_ENR = "document.querySelectorAll('#enrichboard .enrow').length>0"
W_ASK = "(document.getElementById('askdock')||{}).childElementCount>0"


def wait_js(c, expr, secs=90, step=0.5):
    t0 = time.time()
    while time.time() - t0 < secs:
        try:
            if c.js(expr):
                return True
        except Exception:
            pass
        c.pump(step)
    return False


def main():
    os.makedirs(OUT, exist_ok=True)
    prof = tempfile.mkdtemp(prefix="edgecdpl_")
    port = 9421
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
        print("FAIL 拿不到调试目标")
        proc.kill()
        return 1
    c = CDP(ws_url)
    c.send("Page.enable")
    c.send("Runtime.enable")
    c.send("Log.enable")

    def go(view, name, w=1600, h=1000, want="dark", wait=None, mobile=False):
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": mobile})
        c.send("Page.navigate", {"url": f"{BASE}/?view={view}"})
        c.pump(5.0)
        got = None
        for _ in range(5):     # 主题是三态循环，点一次不一定到位 → 轮到目标为止
            got = c.js("document.documentElement.getAttribute('data-theme')")
            if got == want or got is None:
                break
            c.js("document.getElementById('themebtn').click()")
            c.pump(1.3)
        print(f"   [{name}] theme={got}")
        if wait:
            print(f"   [{name}] wait={wait_js(c, wait, 90)}")
        p = os.path.join(OUT, f"{prefix}_{name}.png")
        print("  shot", os.path.basename(p), c.shot(p))

    go("search", "search", wait=W_SEARCH)
    go("search", "search_light", want="light", wait=W_SEARCH)
    go("monitor", "monitor", wait=W_MON)
    go("enrich", "enrich", wait=W_ENR)
    go("ask", "ask", want="light", wait=W_ASK)
    go("search", "narrow", w=1100, h=900, wait=W_SEARCH)
    go("monitor", "mobile", w=560, h=900, mobile=True, wait=W_MON)

    errs = c.errors()
    print("\n控制台 error 数：", len(errs))
    for e in errs[:15]:
        print("   ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
