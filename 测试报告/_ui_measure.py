# -*- coding: utf-8 -*-
"""量真实计算样式（验证 v5 规则确实生效，而不是被旧规则压住）。"""
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

PROBES = {
    "cmdbar": [".cmdbar", ["height", "paddingLeft", "gap"]],
    "cmdbar-bg": [".cmdbar", ["backgroundColor", "backdropFilter"]],
    "topstat": [".top-stat", ["height", "borderTopWidth", "borderRadius", "backgroundColor", "paddingLeft"]],
    "topstat-kv": [".top-stat .kv", ["borderLeftWidth", "paddingLeft"]],
    "sidepanel": [".sidepanel", ["backgroundColor", "borderRightWidth"]],
    "main": [".view[data-view='search'] .main", ["paddingTop", "paddingLeft", "rowGap"]],
    "card": [".side .card", ["backgroundImage", "borderRadius", "boxShadow", "borderColor"]],
    "res": [".res", ["backgroundImage", "borderRadius", "boxShadow", "paddingTop", "paddingLeft"]],
    "searchbar": [".searchbar", ["borderRadius", "backgroundImage", "paddingTop", "boxShadow"]],
    "kpi": [".kpi", ["borderRadius", "backgroundImage", "boxShadow"]],
    "rail": [".rail", ["width", "backgroundColor"]],
    "panel-header": [".panel > header", ["fontSize", "fontWeight", "textTransform", "color"]],
    "stage": [".stage", ["gridTemplateColumns", "width"]],
}


def main():
    prof = tempfile.mkdtemp(prefix="edgem_")
    port = 9521
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

    for name, (sel, props) in PROBES.items():
        expr = ("(function(){var e=document.querySelector(%s);if(!e)return null;"
                "var s=getComputedStyle(e);var o={};%s.forEach(function(p){o[p]=s[p]});"
                "var r=e.getBoundingClientRect();o._w=Math.round(r.width);o._h=Math.round(r.height);"
                "return JSON.stringify(o)})()" % (json.dumps(sel),
                                                  json.dumps(props)))
        v = c.js(expr)
        print(f"{name:14s} {sel:34s} {v}")

    print("\n-- 检索视图主区宽度 / 窗口 --")
    print(c.js("JSON.stringify({win:innerWidth,stage:document.getElementById('stage').getBoundingClientRect().width,"
               "main:document.querySelector('.view[data-view=\\'search\\'] .main').getBoundingClientRect().width,"
               "side:document.getElementById('sidepanel').getBoundingClientRect().width})"))
    print("-- 顶栏结构 --")
    print(c.js("JSON.stringify([].slice.call(document.querySelector('.cmdbar').children).map(function(e){return e.className+':'+Math.round(e.getBoundingClientRect().width)}))"))
    print("-- 主区是否横向溢出 --")
    print(c.js("JSON.stringify({sw:document.querySelector('.main').scrollWidth,cw:document.querySelector('.main').clientWidth,"
               "bodySW:document.body.scrollWidth,bodyCW:document.body.clientWidth})"))
    c.ws.close()
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
