# -*- coding: utf-8 -*-
"""诊断探针：镜像 e2e 序列，复现「富化台偶发 0 行」与「t 键不切主题」。"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ui_shot import CDP, EDGE  # noqa: E402

BASE = "http://127.0.0.1:8848"


def main():
    prof = tempfile.mkdtemp(prefix="edgeprobe3_")
    port = 9581
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", f"--remote-debugging-port={port}", "--remote-allow-origins=*",
         f"--user-data-dir={prof}", "--window-size=1600,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ws = None
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws = t["webSocketDebuggerUrl"]
            if ws:
                break
        except Exception:
            pass
        time.sleep(0.5)
    c = CDP(ws)
    c.send("Page.enable")
    c.send("Runtime.enable")
    c.send("Log.enable")
    c.send("Page.navigate", {"url": BASE + "/"})
    c.pump(9)
    js = c.js

    print("=== A. 富化台复现（镜像 e2e：先搜、开着详情、再切 monitor→enrich）===")
    js("document.getElementById('q').value='Ollama 远程代码执行';")
    js("document.getElementById('go').click();")
    for _ in range(20):
        c.pump(1.0)
        if js("document.querySelectorAll('#results .res').length>0"):
            break
    js("document.querySelector('#results .res').click();")
    c.pump(3.0)
    js("document.getElementById('dx') && document.getElementById('dx').click();")
    c.pump(1.0)
    js("document.querySelector('.rail-item[data-view=\"monitor\"]').click();")
    c.pump(4.0)
    print("  monitor kpi:", js("document.querySelectorAll('#monboard .kpi').length"))
    js("document.querySelector('.rail-item[data-view=\"enrich\"]').click();")
    for i in range(20):
        c.pump(1.0)
        n = js("document.querySelectorAll('#enrichboard .enrow').length")
        if i in (0, 1, 2, 3, 5, 8, 13, 19):
            inner = js("(document.querySelector('#enrichboard')||{}).innerHTML") or ""
            txt = js("(document.querySelector('#enrichboard')||{}).textContent") or ""
            print(f"  enrich t={i+1}s enrow={n} innerLen={len(inner)} text[0:70]={txt[:70]!r}")
        if n:
            break
    print("  enrich ok? enrow=", js("document.querySelectorAll('#enrichboard .enrow').length"))
    print("  页面内 fetch 该接口:", js("""(async()=>{const t0=performance.now();
      try{const r=await fetch('/api/search?size=16&sort=risk&q=');const j=await r.json();
      return 'http='+r.status+' ms='+Math.round(performance.now()-t0)+' results='+((j.results||[]).length);}
      catch(e){return 'ERR '+e.message;}})()"""))

    print("\n=== B. t 键切主题诊断 ===")
    js("document.activeElement && document.activeElement.blur();")
    c.pump(0.3)
    print("  activeElement:", js("document.activeElement && (document.activeElement.id||document.activeElement.tagName)"))
    print("  theme-mode(localStorage):", js("localStorage.getItem('asi-theme-mode')"))
    print("  data-theme 前:", js("document.documentElement.getAttribute('data-theme')"))
    print("  themebtn 存在:", js("!!document.getElementById('themebtn')"))
    # 直接派发 t
    js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'t',bubbles:true}));")
    c.pump(1.6)
    print("  data-theme 后:", js("document.documentElement.getAttribute('data-theme')"))
    print("  theme-mode 后:", js("localStorage.getItem('asi-theme-mode')"))
    # 对照：直接点主题按钮
    js("document.getElementById('themebtn').click();")
    c.pump(1.6)
    print("  点按钮后 data-theme:", js("document.documentElement.getAttribute('data-theme')"))
    print("  点按钮后 theme-mode:", js("localStorage.getItem('asi-theme-mode')"))

    errs = c.errors()
    print("\n控制台 error:", len(errs))
    for e in errs[:10]:
        print("   ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
