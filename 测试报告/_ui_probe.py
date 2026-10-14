# -*- coding: utf-8 -*-
"""聚焦探针：复现富化台候选列表为空的原因。"""
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
    prof = tempfile.mkdtemp(prefix="edgeprobe_")
    port = 9577
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

    # 在页面里直接量 /api/search 往返耗时（排除前端问题）
    js = c.js
    print("== 页面内直连 /api/search?size=16&sort=risk&q= ==")
    print(js("""(async()=>{
      const t0=performance.now();
      try{
        const r=await fetch('/api/search?size=16&sort=risk&q=');
        const j=await r.json();
        return 'ok=1 http='+r.status+' ms='+Math.round(performance.now()-t0)+' total='+(j.total)+' results='+((j.results||[]).length);
      }catch(e){return 'ERR '+e.message+' ms='+Math.round(performance.now()-t0);}
    })()"""))

    print("\n== 切到富化视图，逐秒观察 ==")
    js("document.querySelector('.rail-item[data-view=\"enrich\"]').click();")
    for i in range(30):
        c.pump(1.0)
        n = js("document.querySelectorAll('#enrichboard .enrow').length")
        inner = js("(document.querySelector('#enrichboard')||{}).innerHTML")
        first = js("(document.querySelector('#enrichboard')||{}).textContent")
        if i in (0, 1, 2, 3, 5, 8, 12, 20, 29):
            print(f"  t={i+1}s enrow={n} | innerLen={len(inner or '')} | text[:90]={(first or '')[:90]!r}")
        if n and n > 0:
            break

    print("\n== 富化台区块 id 清单 ==")
    print(js("Array.from(document.querySelectorAll('#enrichboard .en-sec')).map(e=>e.id)"))

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
