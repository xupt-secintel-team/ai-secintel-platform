# -*- coding: utf-8 -*-
"""加载态截图：整页启动页 + 七种加载反馈总览（真实 CSS / 真实类名）。

用法： py -3.13 测试报告/_ui_load.py [前缀]
产出： _ui_shots/<前缀>_boot.png / _gallery.png / _gallery_light.png
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
spec = importlib.util.spec_from_file_location("uishot", os.path.join(ROOT, "测试报告", "_ui_shot.py"))
ushot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ushot)
CDP, EDGE, OUT, free_port = ushot.CDP, ushot.EDGE, ushot.OUT, ushot.free_port

prefix = sys.argv[1] if len(sys.argv) > 1 else "load"

MODULES = [
    ("m0_ops", "智能编排", [("ops.css", 0), ("ops.js", 1)]),
    ("m1_monitor", "情报监测", [("daily.css", 0), ("daily.js", 1), ("panel.js", 1)]),
    ("m2_enrich", "情报富化", [("panel.css", 0), ("panel.js", 1)]),
    ("m3_qa", "情报问答", [("panel.css", 0), ("panel.js", 1)]),
]


def module_tags():
    ids = [{"id": m, "name": n, "owner": ""} for m, n, _ in MODULES]
    out = ["<script>window.AISEC_MODULES=" + json.dumps(ids, ensure_ascii=False) + ";</script>"]
    for m, _n, files in MODULES:
        for fn, is_js in files:
            url = "/modules/%s/web/%s" % (m, fn)
            out.append('<script src="%s"></script>' % url if is_js
                       else '<link rel="stylesheet" href="%s">' % url)
    return "\n".join(out)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/frontend/", "/frontend", "/frontend/index.html"):
            fp = os.path.join(ROOT, "frontend", "index.html")
            html = open(fp, encoding="utf-8").read().replace("<!--@modules-->", module_tags())
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------- 画廊
def ring(p, cls="", num=None):
    n = ('<span class="num">%s</span>' % num) if num is not None else ""
    return ('<span class="ring %s" style="--p:%s">'
            '<svg viewBox="0 0 48 48" aria-hidden="true">'
            '<circle class="track" cx="24" cy="24" r="20"></circle>'
            '<circle class="ind" cx="24" cy="24" r="20"></circle></svg>%s</span>') % (cls, p, n)


def card(no, title, sub, body, wide=False):
    return ('<div class="skcard" style="margin:0%s">'
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">'
            '<span style="font-family:var(--mono);font-size:10px;color:var(--accent-2)">%s</span>'
            '<b style="font-size:12.5px;color:var(--txt)">%s</b>'
            '<span style="margin-left:auto;font-size:10.5px;color:var(--txt-4)">%s</span></div>'
            '<div style="color:var(--txt-3);font-size:12px">%s</div></div>') % (
        ";grid-column:1/-1" if wide else "", no, title, sub, body)


GALLERY = (
    '<div id="gal" style="position:fixed;inset:0;z-index:9500;background:var(--bg);'
    'overflow:auto;padding:32px 40px">'
    '<div style="max-width:1100px;margin:0 auto">'
    '<div style="font-family:var(--mono);font-size:10.5px;letter-spacing:.32em;'
    'color:var(--txt-4);text-transform:uppercase;margin-bottom:6px">v10 · loading system</div>'
    '<h1 style="font-size:25px;margin:0 0 6px;color:var(--txt)">加载反馈 · 七种形态</h1>'
    '<p style="margin:0 0 22px;color:var(--txt-4);font-size:12px">'
    '按「等待时长是否可量化」分工：能算进度就给条/给环，算不出就给转圈；内容结构已知就先摆骨架。</p>'
    '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(316px,1fr));gap:14px">'

    + card("01", "旋转加载圈 Spinner", "时长不可量化",
           '<div style="display:flex;align-items:center;gap:18px">'
           '<span class="spinner lg"></span><span class="spinner"></span>'
           '<span class="spinner sm"></span>'
           '<span style="color:var(--txt-4)">正在检索…</span></div>')

    + card("02", "横向进度条 ProgressBar", "进度可量化",
           '<div class="pbarline"><div class="pbar"><i class="fill" style="width:62%"></i></div>'
           '<span class="pct">62%</span></div>'
           '<div class="pbarline" style="margin-top:12px"><div class="pbar indet"><i class="fill"></i></div>'
           '<span class="pct" style="color:var(--txt-4)">—&nbsp;&nbsp;</span></div>')

    + card("03", "圆形进度环 Ring", "紧凑区域 / 卡片内",
           '<div style="display:flex;align-items:center;gap:20px">'
           + ring("0.72", "", "72%") + ring("0.35", "lg", "35%") + ring("0.9", "sm", "90%")
           + '</div>')

    + card("04", "骨架屏 Skeleton", "结构已知 · 不跳布局",
           '<div class="skcard" style="margin:0;background:transparent;border:0;padding:0">'
           '<div class="skhead"><span class="skdot"></span><div class="skmeta">'
           '<div class="skl w50 tall" style="margin:0 0 6px"></div>'
           '<div class="skl w35" style="margin:0"></div></div></div>'
           '<div class="skl w90"></div><div class="skl w70"></div></div>')

    + card("05", "流光 Shimmer", "叠在骨架上左右扫（右为定格帧）",
           '<div class="skgrid"><div class="sktile"></div>'
           '<div class="sktile" style="background-image:linear-gradient(100deg,transparent 22%,'
           'var(--sk-sweep) 50%,transparent 78%)"></div>'
           '<div class="sktile"></div></div>')

    + card("06", "按钮加载态 Button", "锁死防重复点击",
           '<div style="display:flex;align-items:center;gap:12px">'
           '<button class="btn primary loading" style="min-width:112px">生成报告</button>'
           '<button class="btn loading" style="min-width:92px">同步</button>'
           '<span style="color:var(--txt-4);font-size:11.5px">← 内容隐去、只剩转圈，'
           '期间不可再点</span></div>')

    + '<div class="skcard" style="margin:0;grid-column:1/-1">'
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">'
      '<span style="font-family:var(--mono);font-size:10px;color:var(--accent-2)">07</span>'
      '<b style="font-size:12.5px;color:var(--txt)">整页加载 Boot</b>'
      '<span style="margin-left:auto;font-size:10.5px;color:var(--txt-4)">首屏一次 · 备好即淡出</span></div>'
      '<div style="display:flex;align-items:center;gap:22px;flex-wrap:wrap">'
      '<div style="position:relative;display:grid;place-items:center">'
      '<span style="position:absolute;color:var(--accent-2)">'
      '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" '
      'stroke-width="1.5" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6l7-3z"></path>'
      '<path d="M8.6 12.2l2.2 2.2 4.6-4.8"></path></svg></span>'
      + ring("0.68", "lg", "68%") + '</div>'
      '<div><div style="font-family:var(--mono);font-size:12px;letter-spacing:.42em;'
      'color:var(--txt-2);text-transform:uppercase">AI-SecIntel</div>'
      '<div style="font-family:var(--mono);font-size:11px;color:var(--txt-4);margin-top:6px">'
      '正在加载界面样式…</div></div></div></div>'

    + '</div></div></div>'
)


def main():
    os.makedirs(OUT, exist_ok=True)
    port = 8911
    while not free_port(port):
        port += 1
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/frontend/index.html" % port

    prof = tempfile.mkdtemp(prefix="edgecdpl_")
    dport = 9445
    while not free_port(dport):
        dport += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         "--remote-debugging-port=%d" % dport, "--remote-allow-origins=*",
         "--user-data-dir=%s" % prof, "--window-size=1600,1000", "about:blank"],
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
        print("FAIL 拿不到调试目标")
        proc.kill()
        return 1

    c = CDP(ws_url)
    c.send("Page.enable")
    c.send("Runtime.enable")
    c.send("Log.enable")
    c.send("Emulation.setDeviceMetricsOverride",
           {"width": 1600, "height": 1000, "deviceScaleFactor": 1, "mobile": False})

    c.send("Page.navigate", {"url": base})
    c.pump(3.2)

    # ① 整页加载：强制把 boot 收回可见（真实静态模式下 app.js 早已把它淡出）
    c.js("var b=document.getElementById('boot'); if(b){b.classList.remove('out');}")
    c.pump(0.5)
    p = os.path.join(OUT, "%s_boot.png" % prefix)
    print("  [boot] shot=%s" % c.shot(p))

    # ② 画廊（深色）
    c.js("var b=document.getElementById('boot'); if(b) b.remove();"
         "var g=document.createElement('div'); g.innerHTML=%s;"
         "document.body.appendChild(g.firstElementChild);" % json.dumps(GALLERY))
    c.pump(0.7)
    p = os.path.join(OUT, "%s_gallery.png" % prefix)
    print("  [gallery] shot=%s" % c.shot(p))

    # 证明扫光动画确实挂在伪元素上（截图只能抓一帧，看不出"在动"）
    anim = c.js("(function(){var t=document.querySelector('.sktile');if(!t)return 'no-tile';"
                "var s=getComputedStyle(t,'::after');"
                "return s.animationName+' '+s.animationDuration+' '+s.animationIterationCount;})()")
    print("  [verify] .sktile::after animation =", anim)

    # ③ 画廊（浅色）
    for _ in range(5):
        got = c.js("document.documentElement.getAttribute('data-theme')")
        if got == "light":
            break
        c.js("document.getElementById('themebtn').click()")
        c.pump(1.0)
    c.pump(0.8)
    p = os.path.join(OUT, "%s_gallery_light.png" % prefix)
    print("  [gallery_light] shot=%s" % c.shot(p))

    errs = c.errors()
    print("\n控制台 error 数：", len(errs))
    for e in errs[:8]:
        print("   ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
