# -*- coding: utf-8 -*-
"""静态快照截图（服务不可用时的视觉验证通道）。

背景：本机 .venv 指向不存在的 D:\\python、可用 Python 都缺 faiss 等依赖，
      会话内起不了后端 → 无法用 _ui_live.py 打真实接口截图。
做法：起一个只读静态服务（项目根），打开 /frontend/index.html，
      用真实 app.js 的渲染函数 + 构造数据把界面画出来，再截图。
      这样 CSS 与真实 DOM 结构的配合能被真实验证（只有数据是造的）。

用法： py -3.13 测试报告/_ui_snap.py [前缀]
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
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
spec = importlib.util.spec_from_file_location("uishot", os.path.join(ROOT, "测试报告", "_ui_shot.py"))
ushot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ushot)
CDP, EDGE, OUT, free_port = ushot.CDP, ushot.EDGE, ushot.OUT, ushot.free_port

prefix = sys.argv[1] if len(sys.argv) > 1 else "snap"


# ---------------------------------------------------------------- 构造数据
MOCK = r"""
(function () {
  var T = (t) => t;
  S.stats = {
    total: 169328, vulnerabilities: 68460, knowledge: 37774, exploited: 535, poc: 17362,
    papers: 721, paper_linked: 610, terms: 118388,
    category: [
      {name:'① Web应用与API安全', count:39730, color:'#e3b04b'},
      {name:'② 系统与二进制安全', count:21978, color:'#2fbf9e'},
      {name:'③ AI应用与智能体', count:13322, color:'#e8913c'},
      {name:'④ 模型与数据层', count:7998, color:'#f2c94c'},
      {name:'⑤ AI供应链与平台', count:7454, color:'#b9a284'},
      {name:'⑥ 身份与访问管理', count:6734, color:'#5edcbb'},
      {name:'⑦ 网络与协议安全', count:3882, color:'#a8843c'},
      {name:'⑧ 数据安全与隐私', count:3689, color:'#cf8a6a'},
      {name:'⑨ 云原生与容器', count:3221, color:'#8fd6c0'},
      {name:'⑩ 工控与物联网', count:2104, color:'#c9a05a'},
      {name:'⑪ 移动与终端安全', count:1508, color:'#9c8f77'}
    ],
    severity: [['CRITICAL',39644],['HIGH',22891],['MEDIUM',31120],['LOW',12003],['UNKNOWN',3210]],
    source: [['NVD',68210],['CISA KEV',12004],['GitHub Advisory',31002],['arXiv',15008],
             ['CSDN',18003],['安全博客',12005],['安全社区',8140],['厂商公告',4956]],
    scope: [['通用安全',77336],['AI安全',31992]],
    products: [['android',2101],['debian linux',1519],['gitlab',1447],['internet_explorer',977],
               ['chrome',952],['windows',880],['ollama',611],['kubernetes',540]],
    kb_type: [['vulnerability',68460],['article',30004],['paper',15008],['repo',12003],['advisory',4956]],
    generated_at: '2026-10-09T19:48'
  };

  function ev(term, w) { return {term: term, weight: w}; }
  S.last = {
    total: 109328, page: 1, pages: 9111, size: 12,
    query: {raw: 'Ollama 有哪些远程代码执行漏洞？', terms: {ollama: 3, rce: 2},
            phrases: ['remote code execution'], cn_terms: ['远程代码执行']},
    answer: {
      intent: '漏洞检索', ops: ['AND'], must_not: [], did_you_mean: [],
      expansion: [{from: 'rce', to: ['remote code execution', '远程代码执行']}],
      concepts: ['模型服务', '容器逃逸', '依赖链'],
      stats: {total: 109328, critical_high: 39644, exploited: 535, poc: 17362, papers: 721},
      summary: [
        '命中 109328 条 AI 安全情报（其中高危/严重 39644 条），已按相关性与可信度排序。',
        '535 条已被 CISA 列入在野利用清单，建议优先处置；含公开 POC 的有 17362 条。',
        '涉及组件 Top：android(2101)、debian linux(1519)、gitlab(1447)、ollama(611)。'
      ],
      plan: ['升级 Ollama 至厂商最新稳定版本，关闭对外暴露的 gRPC 端口。',
             '对模型服务启用令牌鉴权，限制 /api/pull 与 /api/generate 的调用来源。',
             '在边界设备上拦截来自公网的 11434 端口访问。']
    },
    results: [
      {type:'vulnerability', id:'CVE-2026-98384', title:'Ollama 远程代码执行漏洞（bpf 子系统越界写）',
       category:'② 系统与二进制安全', category_color:'#2fbf9e',
       cvss:{severity:'CRITICAL', score:9.8}, exploited:true, trust_label:'高可信', trust_score:91,
       cross_label:'3 源一致', confidence:0.93, cross_verified:true, exploit_score:8, poc_count:4, paper_count:1,
       published:'2026-10-09', snippet:'攻击者可通过构造恶意的模型清单触发边界条件，在目标主机的模型服务进程中执行任意代码。受影响版本 ≤ 0.3.14，厂商已在 0.3.15 修复。',
       products:['ollama','linux kernel'], cwe:[{id:'CWE-787'}], sources:['NVD','GitHub Advisory'],
       why:'标题与摘要同时命中「ollama」「远程代码执行」；CVSS 9.8 高于门槛；两源交叉确认。',
       evidence:[ev('ollama',9),ev('remote code execution',7)]},
      {type:'vulnerability', id:'CVE-2026-98383', title:'Linux kernel bpf 校验器缺陷可致本地提权',
       category:'② 系统与二进制安全', category_color:'#2fbf9e',
       cvss:{severity:'HIGH', score:7.5}, exploited:false, trust_label:'高可信', trust_score:86,
       cross_label:'2 源一致', confidence:0.88, cross_verified:true, exploit_score:6, poc_count:2, paper_count:0,
       published:'2026-10-08', snippet:'bpf 校验器在特定指令序列下会错误放行越界访问，本地低权用户可借机提升至 root。',
       products:['linux kernel'], cwe:[{id:'CWE-416'}], sources:['NVD'],
       why:'标题命中「linux kernel」「提权」；可信度 86/100。',
       evidence:[ev('linux kernel',8),ev('提权',5)]},
      {type:'article', id:'CSDN-1892004', title:'从 Ollama 到 vLLM：本地大模型服务的攻击面梳理与加固',
       category:'③ AI应用与智能体', category_color:'#e8913c', views:28400,
       trust_label:'中可信', trust_score:72, cross_label:'单源', confidence:0.64,
       risk_tags:['模型服务','加固'], snippet:'系统梳理了本地推理服务常见的鉴权缺失、端口暴露与依赖投毒三类风险，并给出配置加固清单。',
       products:[], cwe:[], sources:['CSDN'],
       why:'标题与摘要命中「Ollama」「攻击面」；社区文章，可信度按单源计。',
       evidence:[ev('ollama',6),ev('本地大模型',4)]},
      {type:'repo', id:'GH-amd64-bpf-poc', title:'ollama-rce-poc —— 公开的概念验证利用脚本',
       category:'⑤ AI供应链与平台', category_color:'#b9a284', language:'Python', stars:1284,
       trust_label:'高可信', trust_score:80, cross_label:'2 源一致', confidence:0.8, cross_verified:true, exploit_score:7, poc_count:1,
       snippet:'复现 CVE-2026-98384 的最小化 PoC，含 Docker 环境与逐步说明。',
       products:['ollama'], cwe:[], sources:['GitHub'],
       why:'仓库名与描述命中「ollama」「poc」；星标 1284 说明社区关注度高。',
       evidence:[ev('ollama',7),ev('poc',6)]}
    ]
  };

  /* 最新情报（侧栏 + 监测台左列） */
  var latest = [
    ['LIVE:BLOG:1','vuln','CVE-2026-98384 In the Linux kernel, the following vulnerability has been resolved: bpf: Fix','2026-10-09','9.8',1],
    ['LIVE:CSDN:2','article','Ollama 模型服务加固实践：鉴权、限流与端口收敛','2026-10-09',null,1],
    ['CVE-2026-98383','vuln','Linux kernel bpf 校验器缺陷可致本地提权','2026-10-08','7.5',0],
    ['LIVE:ARXIV:3','paper','Prompt Injection in Tool-Using Agents: A Systematic Study','2026-10-08',null,1],
    ['CVE-2026-98382','vuln','vLLM 反序列化漏洞导致远程代码执行','2026-10-08','8.1',0],
    ['LIVE:BLOG:4','article','Detecting Model Supply Chain Poisoning at Scale','2026-10-07',null,0],
    ['CVE-2026-98381','vuln','Kubernetes admission webhook 鉴权绕过','2026-10-07','6.5',0],
    ['LIVE:GH:5','repo','awesome-llm-security —— 大模型安全资源合集','2026-10-07',null,1],
    ['CVE-2026-98380','vuln','Chrome V8 类型混淆可致沙箱逃逸','2026-10-06','8.8',0]
  ];
  var items = latest.map(function (x) {
    var isCve = x[1] === 'vuln';
    return {id:x[0], type: isCve ? 'vulnerability' : (x[0].indexOf('ARXIV')>0?'paper':(x[0].indexOf('GH:')>0?'repo':'article')),
            title:x[2], published:x[3], cvss:x[4], exploited:x[5]===1, is_new:x[5]===1, severity:x[5]===1?'HIGH':'MEDIUM',
            sources:[x[0].indexOf('ARXIV')>0?'arXiv':(x[0].indexOf('GH:')>0?'GitHub':(x[0].indexOf('CSDN')>0?'CSDN':'BLOG'))]};
  });

  /* ---- mock fetch：让 renderMonitor / loadLatest 这些真函数能拿到"数据" ---- */
  var _f = window.fetch;
  window.fetch = function (u) {
    var url = String(u);
    var d = {};
    if (url.indexOf('/api/stats') >= 0) d = S.stats;
    else if (url.indexOf('/api/latest') >= 0) d = {items: items};
    else if (url.indexOf('/api/live') >= 0) d = {enabled:true, interval:15, age_sec:57, last_ms:31913,
      feed_ok:12, feed_total:14, live_docs:1782, added_total:535,
      per_source:{csdn:0, blog:0, anquanke:0, xz:0, nvd:0, kev:0, arxiv:0}};
    else if (url.indexOf('/api/sources') >= 0) d = {channels:[], archive_total_gb:3.24, target_gb:10};
    else if (url.indexOf('/api/trend_stats') >= 0) d = {error:'（快照无趋势数据）'};
    else if (url.indexOf('/api/ops/') >= 0 || url.indexOf('/api/metrics') >= 0) d = null;
    return Promise.resolve({ok:true, json:function(){return Promise.resolve(d);},
                            text:function(){return Promise.resolve('');}});
  };

  /* ---- 画出来 ---- */
  try { renderTop(); } catch (e) { console.warn('renderTop', e); }
  try { renderSide(); } catch (e) { console.warn('renderSide', e); }
  try { renderResults(S.last); renderPager(S.last); renderParse(S.last); renderAnswer(S.last); }
  catch (e) { console.warn('search', e); }
  window.__snapReady = true;
})();
"""


# 复现 core/server.py 的 <!--@modules--> 注入（模块面板实际引用 /modules/<id>/web/*）
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


class SnapHandler(SimpleHTTPRequestHandler):
    """静态只服务项目根；index.html 走注入路径。"""

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


def start_static(port):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), SnapHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main():
    os.makedirs(OUT, exist_ok=True)
    port = 8899
    while not free_port(port):
        port += 1
    start_static(port)
    base = "http://127.0.0.1:%d/frontend/index.html" % port

    prof = tempfile.mkdtemp(prefix="edgecdps_")
    dport = 9431
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

    def go(view, name, w=1600, h=1000, want="dark"):
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 700})
        c.send("Page.navigate", {"url": base + "?view=" + view})
        c.pump(3.0)
        # 主题三态循环：轮到目标为止
        for _ in range(5):
            got = c.js("document.documentElement.getAttribute('data-theme')")
            if got == want or got is None:
                break
            c.js("document.getElementById('themebtn').click()")
            c.pump(1.2)
        c.pump(1.5)
        c.js(MOCK)
        c.pump(2.2)
        # 切到目标视图后再画一次（switchView 会清空/重挂）
        if view != "search":
            c.js("switchView('%s')" % view)
            c.pump(2.0)
            c.js(MOCK)
            c.pump(2.5)
        ready = c.js("!!window.__snapReady")
        errs = 0
        p = os.path.join(OUT, "%s_%s.png" % (prefix, name))
        print("  [%s] ready=%s shot=%s" % (name, ready, c.shot(p)))
        return errs

    go("search", "search")
    go("search", "search_light", want="light")
    go("monitor", "monitor")
    go("enrich", "enrich")

    errs = c.errors()
    print("\n控制台 error 数：", len(errs))
    for e in errs[:12]:
        print("   ", e)
    try:
        c.ws.close()
    except Exception:
        pass
    proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
