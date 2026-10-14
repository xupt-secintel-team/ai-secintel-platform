# -*- coding: utf-8 -*-
"""端到端测试用的假文章服务器：在 127.0.0.1:8891 提供一篇安全文章 HTML。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTML = """<!DOCTYPE html><html><head>
<meta property="og:title" content="Prompt Injection 实战：大模型越狱与防护">
<meta property="article:published_time" content="2026-09-30T08:30:00Z">
<meta name="author" content="Lolcat">
</head><body>
<h1>Prompt Injection 实战：大模型越狱与防护</h1>
<p>本文梳理 Prompt Injection（提示词注入）在大模型应用中的典型攻击面，涵盖
直接注入、间接注入、多轮越狱（jailbreak）与 Agent 编排场景下的利用链。</p>
<p>结合 RAG 检索增强与 MCP 协议暴露面的真实案例，给出输入清洗、权限最小化、
护栏（guardrail）与输出审计的防御方案，并附带 HuggingFace 投毒与模型窃取的关联风险。</p>
</body></html>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", 8891), H)
    srv.serve_forever()
