# -*- coding: utf-8 -*-
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
R = os.path.abspath(".")
sys.path.insert(0, os.path.join(R, "modules", "m3_qa", "backend"))
from qa.agent import execute_tool
for name, args in [("search_keyword", {"query":"ollama","top_k":8}), ("search_exact", {"query":"vllm cvss>=7","top_k":8})]:
    r = execute_tool(name, args)
    print(name, "ok=", r.get("ok"), "n=", r.get("n"), "ms=", r.get("ms"), "err=", (r.get("error") or "")[:120])
