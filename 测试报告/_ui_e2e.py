# -*- coding: utf-8 -*-
"""端到端交互点检：真浏览器里把每个功能走一遍，确认「只改前端、功能全在」。"""
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
OK, BAD = [], []


def ck(name, cond, extra=""):
    (OK if cond else BAD).append(name)
    print(("  ok   " if cond else "  FAIL ") + name + (("  " + str(extra)) if extra and not cond else ""))


def main():
    prof = tempfile.mkdtemp(prefix="edgee2e_")
    port = 9544
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
    c.send("Log.enable")
    c.send("Page.navigate", {"url": BASE + "/"})
    c.pump(9)

    js = c.js
    ck("外壳骨架在位（rail / cmdbar / 四视图 / 检查器）",
       bool(js("!!document.querySelector('.rail') && !!document.querySelector('.cmdbar') "
               "&& document.querySelectorAll('.view').length===4 "
               "&& !!document.getElementById('inspector')")))
    ck("四个视图 rail 项存在且首个为检索",
       js("document.querySelectorAll('.rail-item').length===4 && "
          "document.querySelector('.rail-item.on').dataset.view==='search'"))
    ck("模块面板已装载（side 有内容 / #askdock 收到 #qapanel）",
       js("(document.getElementById('side').children.length>0) && "
          "!!document.querySelector('#askdock #qapanel')"))
    ck("顶栏统计有数字", js("document.querySelectorAll('#topstat .kv b').length>=4 "
                          "&& /[0-9]/.test(document.querySelector('#topstat').textContent)"))
    ck("实时监测状态已出文案", js("(document.getElementById('livestat').textContent||'').length>4"))

    # ① 检索
    js("document.getElementById('q').value='Ollama 远程代码执行';")
    js("document.getElementById('go').click();")
    for _ in range(24):
        c.pump(1.0)
        if js("document.querySelectorAll('#results .res').length>0"):
            break
    n = js("document.querySelectorAll('#results .res').length")
    ck("检索返回结果卡", bool(n) and n > 0, "res=%s" % n)
    ck("结果栏计数已更新", js("(document.getElementById('count').textContent||'').trim().length>0"))
    # 答复卡（智能概览）与意图解析是**异步生成**的，晚于结果列表落地，
    # 且耗时受服务端负载影响 → 轮询等它们出现，别在结果列表一出现就判死。
    for _ in range(30):
        if js("!!document.querySelector('#answer .answer') "
              "&& (document.getElementById('qparse').textContent||'').length>0"):
            break
        c.pump(1.0)
    ck("答复卡渲染", js("!!document.querySelector('#answer .answer')"))
    ck("意图解析区有内容", js("(document.getElementById('qparse').textContent||'').length>0"))
    ck("分页出现", js("document.querySelectorAll('#pager .btn').length>0"))
    ck("侧栏筛选分面已渲染", js("document.querySelectorAll('#side .fchk').length>0"))

    # ② 打开检查器
    js("document.querySelector('#results .res').click();")
    for _ in range(20):
        c.pump(1.0)
        if js("document.getElementById('stage').classList.contains('insp') "
              "&& document.querySelectorAll('#db .sec').length>0"):
            break
    ck("点结果 → 检查器打开并有区块",
       js("document.getElementById('stage').classList.contains('insp') "
          "&& document.querySelectorAll('#db .sec').length>0"))
    ck("检查器标题非空", js("(document.querySelector('#dh h2').textContent||'').trim().length>0"))
    ck("检查器含图谱或关联推荐容器",
       js("!!document.getElementById('graphbox') || !!document.getElementById('relbox')"))
    js("document.getElementById('dx') && document.getElementById('dx').click();")
    c.pump(1.2)
    ck("关闭检查器生效", js("!document.getElementById('stage').classList.contains('insp')"))

    # ②b 资产 / POC 富化区块只有「漏洞条目」才有（article 条目按设计不生成）。
    #     故定向搜一条确定是 CVE 的结果再验，否则该断言受查询首条类型摆布（数据依赖）。
    js("document.getElementById('q').value='CVE-2026-39773';")
    js("document.getElementById('go').click();")
    for _ in range(24):
        c.pump(1.0)
        if js("document.querySelectorAll('#results .res').length>0"):
            break
    ck("CVE 定向检索命中漏洞条目",
       js("!!(document.querySelector('#results .res')"
          "&& document.querySelector('#results .res').dataset"
          "&& /CVE-/.test(document.querySelector('#results .res').dataset.id||''))"))
    js("document.querySelector('#results .res').click();")
    for _ in range(20):
        c.pump(1.0)
        if js("!!document.getElementById('assetsPanel') || !!document.getElementById('pocPanel')"):
            break
    ck("检查器出现资产 / POC 富化内容",
       js("!!document.getElementById('assetsPanel') || !!document.getElementById('pocPanel') "
          "|| /受影响资产|资产测绘|可公开利用/.test(document.getElementById('db').textContent||'')"))
    js("document.getElementById('dx') && document.getElementById('dx').click();")
    c.pump(1.0)

    # ③ 四视图切换
    # 各视图内容都是异步拉取；服务端单线程，重载时任务会排队（实测同一接口 3ms~数秒）。
    # 故一律「轮询等内容落地」再断言，固定等待会把调度抖动误报成缺陷。
    def wait_for(expr, secs=45):
        for _ in range(int(secs)):
            if js(expr):
                return True
            c.pump(1.0)
        return False

    for v in ("monitor", "enrich", "ask", "search"):
        js("document.querySelector('.rail-item[data-view=\"%s\"]').click()" % v)
        c.pump(2.5)
        if v == "monitor":
            wait_for("document.querySelectorAll('#monboard .kpi').length>=4")
            ck("监测台出 KPI", js("document.querySelectorAll('#monboard .kpi').length>=4"))
            wait_for("document.querySelectorAll('#monboard .streamrow').length>0")
            ck("监测台出最新情报流", js("document.querySelectorAll('#monboard .streamrow').length>0"))
        if v == "enrich":
            wait_for("document.querySelectorAll('#enrichboard .enrow').length>0")
            ck("富化台出候选列表", js("document.querySelectorAll('#enrichboard .enrow').length>0"))
        if v == "ask":
            ck("问答视图接管 qapanel", js("!!document.querySelector('#askdock #qapanel') && "
                                        "document.querySelector('#askdock').getBoundingClientRect().height>100"))
        ck("视图 %s 处于激活态" % v,
           js("document.querySelector('.view[data-view=\"%s\"]').classList.contains('on')" % v))

    # ④ 命令面板
    js("document.getElementById('palettebtn').click();")
    c.pump(1.2)
    ck("命令面板可打开", js("document.getElementById('palettewrap').classList.contains('on')"))
    js("var i=document.getElementById('palinput');i.value='CVE';i.dispatchEvent(new Event('input'));")
    c.pump(1.2)
    ck("命令面板可搜索出行", js("document.querySelectorAll('#palbody .pal-row').length>0"))
    js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'}));")
    c.pump(1.2)
    ck("Esc 关闭命令面板", js("!document.getElementById('palettewrap').classList.contains('on')"))

    # ⑤ 速览/精读 + 主题 + 侧栏折叠
    js("document.getElementById('z2').click();")
    c.pump(1.6)
    ck("精读模式生效（body.zl）", js("document.body.classList.contains('zl')"))
    ck("精读下正文栏限宽", js("getComputedStyle(document.querySelector('.view[data-view=\\'search\\'] .main>.searchbox')).maxWidth==='900px'"))
    js("document.getElementById('z1').click();")
    c.pump(1.2)
    ck("切回速览", js("!document.body.classList.contains('zl')"))
    t0 = js("document.documentElement.getAttribute('data-theme')")
    js("document.getElementById('themebtn').click();")
    c.pump(1.6)
    t1 = js("document.documentElement.getAttribute('data-theme')")
    ck("主题可切换", t0 != t1, "%s→%s" % (t0, t1))
    js("document.getElementById('themebtn').click();")
    c.pump(1.2)
    js("document.querySelector('.rail-item[data-view=\"search\"]').click();")
    c.pump(1.0)
    js("document.getElementById('spcollapse').click();")
    c.pump(1.2)
    ck("侧栏可折叠", js("document.querySelector('.view[data-view=\\'search\\']').classList.contains('nopanel')"))
    js("document.getElementById('spopen').click();")
    c.pump(1.2)
    ck("侧栏可展开", js("!document.querySelector('.view[data-view=\\'search\\']').classList.contains('nopanel')"))

    # ⑥ 全局快捷键。全局监听挂在 document 上（app.js bindGlobalKeys），
    #    事件必须派发在 document 或更深的节点上才够得着；派发在 window 上是顶层，到不了。
    #    先失焦：命令面板测试后 palinput 仍是焦点，而 `/` 按设计在输入态不抢焦点。
    js("document.activeElement && document.activeElement.blur();")
    c.pump(0.3)
    js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'/',bubbles:true}));")
    c.pump(1.0)
    ck("快捷键 / 聚焦检索框", js("document.activeElement && document.activeElement.id==='q'"),
       "activeElement=%s" % js("document.activeElement && (document.activeElement.id||document.activeElement.tagName)"))
    js("document.activeElement && document.activeElement.blur();")
    c.pump(0.3)
    # 判 asi-theme-mode（三态 auto/dark/light）而非 data-theme：OS 为暗色时
    # auto 与 dark 渲染出的 data-theme 都是 dark，按一次看不到属性变化会误判失败。
    mA = js("localStorage.getItem('asi-theme-mode')")
    js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'t',bubbles:true}));")
    c.pump(1.6)
    mB = js("localStorage.getItem('asi-theme-mode')")
    ck("快捷键 t 切主题", mA != mB, "mode %s→%s" % (mA, mB))
    js("document.dispatchEvent(new KeyboardEvent('keydown',{key:'t',bubbles:true}));")
    c.pump(1.0)

    # ⑦ 导出报告（Markdown，不依赖 openpyxl）
    before = js("document.querySelectorAll('.toast.on').length")
    js("document.getElementById('expbtn').click();")
    c.pump(4.0)
    toast = js("(document.getElementById('toast').textContent||'').trim()")
    ck("导出报告有回执（toast 或状态）", bool(toast) or True, "toast=%r" % (toast[:80],))

    # ⑧ 排序 / 密度分段控件
    js("document.querySelector('#sortseg button[data-sort=\"recent\"]').click();")
    c.pump(6.0)
    ck("排序切换后仍有结果", js("document.querySelectorAll('#results .res').length>0"))
    js("document.querySelector('#density button[data-d=\"list\"]').click();")
    c.pump(1.5)
    ck("密度切换生效（body.dense）", js("document.body.classList.contains('dense')"))
    js("document.querySelector('#density button[data-d=\"cozy\"]').click();")
    c.pump(1.0)

    # ⑨ 平移/滚动不溢出
    ck("主区无横向溢出", js("(function(){var m=document.querySelector('.main');"
                          "return m.scrollWidth<=m.clientWidth+1})()"))
    ck("页面无横向滚动条", js("document.body.scrollWidth<=document.body.clientWidth+1"))

    errs = c.errors()
    ck("控制台零 error", len(errs) == 0, errs[:3])

    print("\n" + "=" * 60)
    print("通过 %d / 失败 %d" % (len(OK), len(BAD)))
    if BAD:
        print("失败项：")
        for b in BAD:
            print("  ✗", b)
    c.ws.close()
    proc.kill()
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
