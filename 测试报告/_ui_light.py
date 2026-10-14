# -*- coding: utf-8 -*-
"""量浅色主题下的实际取值（排查「切了主题但某些块没变」）。"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from _ui_shot import CDP, EDGE  # noqa: E402

BASE = "http://127.0.0.1:8848"
SEL = {
    "html": "document.documentElement",
    "body": "document.body",
    "rail": ".rail",
    "sidepanel": ".sidepanel",
    "card": ".side .card",
    "cardh3": ".side .card > h3",
    "cmdbar": ".cmdbar",
    "searchbar": ".searchbar",
    "res": ".res",
    "inspector": ".inspector",
}


def main():
    prof = tempfile.mkdtemp(prefix="edgel_")
    port = 9533
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", f"--remote-debugging-port={port}", "--remote-allow-origins=*",
         f"--user-data-dir={prof}", "--window-size=1600,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ws_url = None
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws_url = t["webSocketDebuggerUrl"]
            if ws_url:
                break
        except Exception:
            pass
        time.sleep(0.5)
    c = CDP(ws_url)
    c.send("Page.enable")
    c.send("Runtime.enable")
    c.send("Page.navigate", {"url": f"{BASE}/?view=search"})
    c.pump(7)
    c.js("document.getElementById('themebtn').click()")
    c.pump(2.5)
    print("theme =", c.js("document.documentElement.getAttribute('data-theme')"))
    print("--bg   =", c.js("getComputedStyle(document.documentElement).getPropertyValue('--bg')"))
    print("--bg-2 =", c.js("getComputedStyle(document.documentElement).getPropertyValue('--bg-2')"))
    for name, sel in SEL.items():
        expr = ("(function(){var e=document.querySelector(%s);if(!e)return null;var s=getComputedStyle(e);"
                "return JSON.stringify({bg:s.backgroundColor,img:(s.backgroundImage||'').slice(0,60),"
                "color:s.color,bd:s.borderTopColor})})()" % json.dumps(sel))
        print(f"{name:11s} {c.js(expr)}")
    c.ws.close()
    proc.kill()


if __name__ == "__main__":
    main()
