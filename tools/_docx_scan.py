# -*- coding: utf-8 -*-
import io, sys, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from docx import Document
p = r"AI-SecIntel_竞赛技术报告.docx"
doc = Document(p)
targets = ["72%", "48 个", "48源", "48 源", "情报源"]
hits = []
for i, para in enumerate(doc.paragraphs):
    t = para.text or ""
    for kw in ("72%", "48"):
        if kw in t:
            hits.append((i, kw, t[:160], len(para.runs)))
            break
print("paragraphs:", len(doc.paragraphs), "tables:", len(doc.tables))
for h in hits[:40]:
    print(h[0], "|", h[1], "|", h[3], "runs |", h[2].replace("\n"," "))
