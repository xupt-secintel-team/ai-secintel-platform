# -*- coding: utf-8 -*-
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
R = os.path.abspath(".")
sys.path.insert(0, os.path.join(R, "modules", "m3_qa", "backend"))
from qa.agent import fast_route
for q in ["LangChain 的提示词注入问题怎么防？","提示词注入的攻击原理是什么？","Ollama 有哪些远程代码执行漏洞？","CVE-2024-37032 影响哪些版本？"]:
    print(repr(q), "->", fast_route(q))
