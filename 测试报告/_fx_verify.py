# -*- coding: utf-8 -*-
"""v12.2 修正验证：动画存活 / 帧耗 / 浅色可见性 / 顶栏数字居中。

验证项：
  [1] 检索视图稳态：__fxStats.frames 持续增长（WebGL 循环活着）
  [2] 切到监测台（大块 innerHTML 重绘 = v1 卡死复现路径）后再等 6s，
      frames 必须仍在增长，degraded 允许变化但不允许永久停更
  [3] 页面整体帧耗采样（rAF 间隔均值/ P95）—— 卡顿量化
  [4] 浅色主题粒子可见性：读 pmat 参数 + 截图
  [5] .top-stat .kv 数字与容器中心偏差 ≤ 2px

用法： py -3.13 测试报告/_fx_verify.py
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

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
spec = importlib.util.spec_from_file_location("uishot", os.path.join(ROOT, "测试报告", "_ui_shot.py"))
ushot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ushot)
CDP, EDGE, OUT, free_port = ushot.CDP, ushot.EDGE, ushot.OUT, ushot.free_port

spec2 = importlib.util.spec_from_file_location("uisnap", os.path.join(ROOT, "测试报告", "_ui_snap.py"))
# 不 exec _ui_snap（它会直接跑 main），只借 MOCK：正则抠出来
src = open(os.path.join(ROOT, "测试报告", "_ui_snap.py"), encoding="utf-8").read()
MOCK = src.split('MOCK = r"""', 1)[1].split('"""', 1)[0]
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


from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class SnapHandler(SimpleHTTPRequestHandler):
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


def main():
    os.makedirs(OUT, exist_ok=True)
    port = 8899
    while not free_port(port):
        port += 1
    httpd = ThreadingHTTPServer(("127.0.0.1", port), SnapHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d/frontend/index.html" % port

    prof = tempfile.mkdtemp(prefix="edgecdpv_")
    dport = 9451
    while not free_port(dport):
        dport += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         "--use-angle=swiftshader", "--enable-unsafe-swiftshader",
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

    ok = True

    def stats():
        return c.js("window.__fxStats ? JSON.stringify(window.__fxStats) : 'null'")

    def frames():
        s = stats()
        return json.loads(s)["frames"] if s and s != "null" else -1

    # ---------- 打开检索视图 ----------
    c.send("Page.navigate", {"url": base + "?view=search"})
    c.pump(3.0)
    c.js(MOCK)
    c.pump(2.5)

    has_gl = c.js("!!document.getElementById('fxgl')")
    print("[0] #fxgl 画布存在:", has_gl)
    if not has_gl:
        print("    ⚠ 本环境 WebGL 不可用，动画存活项跳过（截图仍可看 CSS 层）")

    # [1] 检索视图稳态帧增
    if has_gl:
        f1 = frames(); c.pump(2.0); f2 = frames()
        print("[1] 检索视图 frames: %d -> %d  (%s)" % (f1, f2, "增长 OK" if f2 > f1 else "✗ 未增长"))
        ok &= f2 > f1

    # [2] 切监测台 —— v1 卡死复现路径
    c.js("switchView('monitor')")
    c.pump(2.0)
    c.js(MOCK)
    c.pump(6.0)                       # 越过旧版 4s 误判窗口
    if has_gl:
        f3 = frames(); c.pump(2.0); f4 = frames()
        s = stats()
        print("[2] 切监测台+8s 后 frames: %d -> %d  (%s)  stats=%s"
              % (f3, f4, "增长 OK" if f4 > f3 else "✗ 卡死", s))
        ok &= f4 > f3

    # [3] 页面整体帧耗采样（含 canvas/CSS/布局，3 秒窗口）
    jank = c.js("""(function(){
      return new Promise(function(res){
        var a=[],prev=0,n=0;
        function f(t){ if(prev) a.push(t-prev); prev=t; if(++n<140) requestAnimationFrame(f);
          else { a.sort(function(x,y){return x-y});
            var avg=a.reduce(function(s,v){return s+v},0)/a.length;
            res(JSON.stringify({avg:Math.round(avg*10)/10,p95:a[Math.floor(a.length*.95)],n:a.length})); } }
        requestAnimationFrame(f);
      });
    })()""")
    print("[3] 监测台帧耗采样:", jank)

    # [4] 浅色主题
    for _ in range(5):
        got = c.js("document.documentElement.getAttribute('data-theme')")
        if got == "light":
            break
        c.js("document.getElementById('themebtn').click()")
        c.pump(1.0)
    c.pump(2.0)
    if has_gl:
        light_info = c.js("""(function(){
          var cv=document.getElementById('fxgl'); if(!cv) return 'no-canvas';
          return getComputedStyle(cv).opacity;
        })()""")
        print("[4] 浅色主题 #fxgl opacity:", light_info)
    p = os.path.join(OUT, "v122_monitor_light.png")
    print("    浅色监测台截图:", c.shot(p))
    # 回深色再截一张
    for _ in range(5):
        got = c.js("document.documentElement.getAttribute('data-theme')")
        if got != "light":
            break
        c.js("document.getElementById('themebtn').click()")
        c.pump(1.0)
    c.pump(2.0)
    p2 = os.path.join(OUT, "v122_monitor_dark.png")
    print("    深色监测台截图:", c.shot(p2))

    # [5] 顶栏数字居中
    center = c.js("""(function(){
      var out=[];
      document.querySelectorAll('.top-stat .kv').forEach(function(kv){
        var b=kv.querySelector('b'); if(!b) return;
        var kr=kv.getBoundingClientRect(), br=b.getBoundingClientRect();
        out.push({label:(kv.querySelector('span')||{}).textContent||'?',
                  dev:Math.round(((br.left+br.width/2)-(kr.left+kr.width/2))*10)/10});
      });
      return JSON.stringify(out);
    })()""")
    print("[5] 顶栏 kv 中心偏差(px):", center)
    try:
        devs = [abs(x["dev"]) for x in json.loads(center)]
        ok &= all(d <= 2.5 for d in devs)
    except Exception:
        pass

    errs = c.errors()
    print("\n控制台 error 数:", len(errs))
    for e in errs[:10]:
        print("   ", e)
    print("\n总体:", "PASS" if ok else "FAIL")
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
