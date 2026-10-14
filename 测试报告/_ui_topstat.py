# -*- coding: utf-8 -*-
"""顶栏测量：多宽度下 top-stat 胶囊是否裁切内容、fresh 日期格是否完整可见。
判据：topstat.scrollWidth <= clientWidth；freshkv 显示时其 right <= topstat.right；
     cmdbar 不裁最右元素。用法：py -3.13 测试报告/_ui_topstat.py"""
import json, os, subprocess, sys, tempfile, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ui_shot import CDP, EDGE, BASE, PORT, free_port  # noqa: E402

JS = """
(() => {
  const ts = document.getElementById('topstat');
  if (!ts) return {err: 'no topstat'};
  const fk = document.getElementById('freshkv');
  const ft = document.getElementById('freshtxt');
  const r = ts.getBoundingClientRect();
  const out = {
    vw: innerWidth,
    clip: ts.scrollWidth > ts.clientWidth + 1,
    sw: ts.scrollWidth, cw: ts.clientWidth,
  };
  if (fk) {
    const cs = getComputedStyle(fk);
    const fr = fk.getBoundingClientRect();
    out.fresh = {display: cs.display, txt: ft ? ft.textContent : '',
                 right: Math.round(fr.right), tright: Math.round(r.right),
                 inside: fr.right <= r.right + 1, stale: fk.classList.contains('stale')};
  }
  const cb = document.getElementById('cmdbar');
  out.cmdbarClip = Math.max(...[...cb.children].map(el => el.getBoundingClientRect().right))
                 > cb.getBoundingClientRect().right + 1;
  return out;
})()
"""

def main():
    prof = tempfile.mkdtemp(prefix="edgecdp_")
    port = PORT
    while not free_port(port):
        port += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         f"--remote-debugging-port={port}", "--remote-allow-origins=*",
         f"--user-data-dir={prof}", "--window-size=1700,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ws_url = None
    for _ in range(60):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as r:
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws_url = t["webSocketDebuggerUrl"]; break
            if ws_url: break
        except Exception:
            pass
        time.sleep(0.5)
    if not ws_url:
        print("FAIL: 拿不到调试目标"); proc.kill(); return 1

    c = CDP(ws_url)
    c.send("Page.enable"); c.send("Runtime.enable")
    bad = 0
    rows = []
    for w in (1700, 1600, 1500, 1440, 1366, 1281, 1100):
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": w, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
        c.send("Page.navigate", {"url": f"{BASE}/?view=search"})
        c.pump(4.0)
        v = c.js(JS)
        rows.append((w, v))
    for w, v in rows:
        if not isinstance(v, dict) or v.get('err'):
            print(f'{w}: ERROR {v}'); bad += 1; continue
        fk = v.get('fresh')
        line = f"{w}: topstat {'CLIP!' if v['clip'] else 'ok'}(sw={v['sw']}/cw={v['cw']}) cmdbarClip={v['cmdbarClip']}"
        if fk:
            line += (f" | fresh[{fk['display']}] \"{fk['txt']}\" "
                     f"right={fk['right']}<={fk['tright']} inside={fk['inside']} stale={fk['stale']}")
        ok = (not v['clip']) and (not v['cmdbarClip']) and (
            fk is None or fk['display'] == 'none' or (fk['inside'] and fk['txt'] and fk['txt'] != '—'))
        bad += 0 if ok else 1
        print(('PASS ' if ok else 'FAIL ') + line)
    print(f'\n结论：{len(rows)-bad}/{len(rows)} 宽度通过')
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 1 if bad else 0

if __name__ == '__main__':
    sys.exit(main())
