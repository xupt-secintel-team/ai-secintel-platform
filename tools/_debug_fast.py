# -*- coding: utf-8 -*-
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
R = os.path.abspath(".")
sys.path.insert(0, os.path.join(R, "modules", "m3_qa", "backend"))
from qa.agent import fast_route, execute_tool
for q in ["Ollama 有哪些远程代码执行漏洞？","已被在野利用（KEV）且 CVSS 恰好 10 分的漏洞有哪些？","Ollama 有多少个高危漏洞（CVSS≥7）？","GitLab 相关的、已被在野利用的漏洞有哪些？"]:
    fr = fast_route(q)
    ok = execute_tool(fr[0], fr[1]).get("ok") if fr else None
    print(repr(q), "->", fr, "tool_ok=", ok)
