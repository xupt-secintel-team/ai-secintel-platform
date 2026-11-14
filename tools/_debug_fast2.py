# -*- coding: utf-8 -*-
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
R = os.path.abspath(".")
sys.path.insert(0, os.path.join(R, "modules", "m3_qa", "backend"))
from qa.agent import fast_route, execute_tool
qs = ["Ollama 有哪些远程代码执行漏洞？","ollama 有多少个高危漏洞（CVSS≥7）？","CVE-2026-94627（vLLM）有哪些关联的研究论文？",
      "已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？","GitLab 相关的、已被在野利用的漏洞有哪些？","最近有哪些新的 AI 安全漏洞？"]
for q in qs:
    fr = fast_route(q)
    ok = None
    if fr:
        r = execute_tool(fr[0], fr[1]); ok = (r.get("ok"), r.get("n"))
    print(repr(q), "->", fr, "exec=", ok)
