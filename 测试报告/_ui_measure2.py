# -*- coding: utf-8 -*-
"""量一下 .viewhead / .vh-ghost 的真实盒模型与字号（真浏览器）。"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ui_shot import CDP, EDGE, BASE, free_port  # noqa: E402

port = 9455
while not free_port(port):
    port += 1
prof = tempfile.mkdtemp(prefix="edgecdpl_")
proc = subprocess.Popen(
    [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
     "--no-first-run", "--force-device-scale-factor=1",
     f"--remote-debugging-port={port}", "--remote-allow-origins=*",
     f"--user-data-dir={prof}", "--window-size=1600,1000", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ws = None
for _ in range(60):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
            for t in json.loads(r.read().decode()):
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    ws = t["webSocketDebuggerUrl"]
                    break
        if ws:
            break
    except Exception:
        pass
    time.sleep(0.5)

c = CDP(ws)
c.send("Page.enable")
c.send("Runtime.enable")
c.send("Emulation.setDeviceMetricsOverride", {"width": 1600, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
c.send("Page.navigate", {"url": f"{BASE}/?view=search"})
c.pump(5.0)
print(c.js("""
(function(){
  var r=function(el){if(!el)return null;var b=el.getBoundingClientRect();var s=getComputedStyle(el);
    return {x:Math.round(b.x),y:Math.round(b.y),w:Math.round(b.width),h:Math.round(b.height),
            minH:s.minHeight,fs:s.fontSize,pad:s.padding,mt:s.marginTop};};
  var vh=document.querySelector('.view.on .viewhead')||document.querySelector('.viewhead');
  var gh=document.querySelector('.view.on .vh-ghost')||document.querySelector('.vh-ghost');
  return JSON.stringify({viewhead:r(vh),ghost:r(gh),ghostText:gh?gh.textContent:null,
    sheets:[].slice.call(document.styleSheets).map(function(s){return s.href;})},null,1);
})()
"""))
try:
    c.ws.close()
except Exception:
    pass
proc.kill()
