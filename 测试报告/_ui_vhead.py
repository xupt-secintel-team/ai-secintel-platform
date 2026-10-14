# -*- coding: utf-8 -*-
"""量页头盒模型，检测「幽灵字 vs 右上控件」是否重叠（不靠肉眼看缩放截图）。

用法： py -3.13 测试报告/_ui_vhead.py
输出： 每视图 × 每宽度的元素 rect + 两两相交报告
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
CDP, EDGE, BASE, free_port = ushot.CDP, ushot.EDGE, ushot.BASE, ushot.free_port

JS = r"""
(function(){
  function R(el){var r=el.getBoundingClientRect();
    return {x:Math.round(r.x),y:Math.round(r.y),w:Math.round(r.width),h:Math.round(r.height)};}
  var v=document.querySelector('.view.on')||document.querySelector('.view');
  var vh=v && v.querySelector('.viewhead');
  if(!vh) return {err:'no viewhead'};
  var items=[];
  var g=vh.querySelector('.vh-ghost');
  if(g && getComputedStyle(g).display!=='none'){
    var e=g.querySelector('em'), b=g.querySelector('b');
    if(e && e.offsetParent!==null) items.push(Object.assign({name:'ghost-em('+e.textContent+')'},R(e)));
    if(b && b.offsetParent!==null) items.push(Object.assign({name:'ghost-num('+b.textContent+')'},R(b)));
  }
  Array.prototype.forEach.call(vh.children,function(el){
    if(el.classList.contains('vh-ghost')) return;
    if(getComputedStyle(el).display==='none') return;
    if(el.tagName==='DIV' && el.querySelector('h2')){
      /* ★ 只有「装着 h2 的那块」才是标题块；.seg#enfilt 同样是 DIV，
         早期版本把它一起吞掉了 → 富化台的幽灵字 vs 分段器**根本没被检测**。 */
      var h2=el.querySelector('h2'),p=el.querySelector('p');
      if(h2) items.push(Object.assign({name:'h2'},R(h2)));
      if(p) items.push(Object.assign({name:'p'},R(p)));
    } else {
      items.push(Object.assign({name:'ctrl:'+(el.id||el.className)},R(el)));
    }
  });
  var hits=[];
  for(var i=0;i<items.length;i++)for(var j=i+1;j<items.length;j++){
    var a=items[i],b=items[j];
    var ox=Math.min(a.x+a.w,b.x+b.w)-Math.max(a.x,b.x);
    var oy=Math.min(a.y+a.h,b.y+b.h)-Math.max(a.y,b.y);
    if(ox>0&&oy>0) hits.push(a.name+' × '+b.name+'  重叠 '+ox+'×'+oy+'px');
  }
  var rb=R(vh);
  return {vw:innerWidth, headH:rb.h, items:items, hits:hits};
})()
"""


def main():
    prof = tempfile.mkdtemp(prefix="edgevh_")
    port = 9431
    while not free_port(port):
        port += 1
    proc = subprocess.Popen(
        [EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-proxy-server",
         "--no-first-run", "--force-device-scale-factor=1",
         "--remote-debugging-port=%d" % port, "--remote-allow-origins=*",
         "--user-data-dir=%s" % prof, "--window-size=1600,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ws = None
    for _ in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/json" % port, timeout=2) as r:
                for t in json.loads(r.read().decode()):
                    if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                        ws = t["webSocketDebuggerUrl"]
                        break
            if ws:
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not ws:
        print("FAIL 拿不到调试目标")
        proc.kill()
        return 1
    c = CDP(ws)
    c.send("Page.enable")
    c.send("Runtime.enable")
    bad = 0
    for w, h in ((1600, 1000), (1281, 900), (1100, 900)):
        for v in ("monitor", "enrich", "search", "ask"):
            c.send("Emulation.setDeviceMetricsOverride",
                   {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})
            c.send("Page.navigate", {"url": BASE + "/?view=" + v})
            c.pump(5.5)
            r = c.js(JS)
            print("\n===== %dpx  view=%s  innerWidth=%s  页头高=%s =====" % (
                w, v, (r or {}).get("vw"), (r or {}).get("headH")))
            if not r or r.get("err"):
                print("   ", r)
                continue
            for it in r["items"]:
                print("   %-30s x=%5d y=%4d w=%5d h=%4d  right=%5d bottom=%4d" % (
                    it["name"], it["x"], it["y"], it["w"], it["h"],
                    it["x"] + it["w"], it["y"] + it["h"]))
            if r["hits"]:
                bad += len(r["hits"])
                for x in r["hits"]:
                    print("   *** 重叠:", x)
            else:
                print("   OK 无重叠")
    print("\n重叠总数：", bad)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
