# -*- coding: utf-8 -*-
"""聚焦探针 2：点开漏洞条目，验证检查器里的资产 / POC 富化区块是否正常挂载。"""
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
    prof = tempfile.mkdtemp(prefix="edgeprobe2_")
    port = 9579
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

    js("document.getElementById('q').value='CVE-2026-39773';")
    js("document.getElementById('go').click();")
    for _ in range(20):
        c.pump(1.0)
        if js("document.querySelectorAll('#results .res').length>0"):
            break
    print("结果数:", js("document.querySelectorAll('#results .res').length"))
    print("首条 id:", js("(document.querySelector('#results .res')||{}).dataset ? document.querySelector('#results .res').dataset.id : '?'"))

    js("document.querySelector('#results .res').click();")
    for i in range(20):
        c.pump(1.0)
        has = js("!!document.getElementById('assetsPanel') || !!document.getElementById('pocPanel')")
        if i in (0, 1, 2, 4, 7, 12, 19):
            print(f"  t={i+1}s assetsPanel/pocPanel={has} | sec={js('document.querySelectorAll(\"#db .sec\").length')}")
        if has:
            break

    print("\nassetsPanel 存在:", js("!!document.getElementById('assetsPanel')"))
    print("pocPanel 存在:", js("!!document.getElementById('pocPanel')"))
    ap = js("(document.getElementById('assetsPanel')||{}).textContent")
    print("assetsPanel 文本[:200]:", (ap or "")[:200])
    print("检查器 #db 文本片段[:200]:", (js("(document.getElementById('db')||{}).textContent") or "")[:200])

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
