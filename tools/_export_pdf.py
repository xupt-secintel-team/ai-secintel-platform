# -*- coding: utf-8 -*-
"""用 Word COM 刷新目录域、重排页码并导出 PDF。

用法： <系统 python> tools/_export_pdf.py [docx路径]
"""
import os
import sys

import win32com.client as win32

DOCX = sys.argv[1] if len(sys.argv) > 1 else r"D:\111111\备份\AI-SecIntel_2.2_竞赛技术报告_终稿.docx"
PDF = os.path.splitext(DOCX)[0] + ".pdf"

word = win32.gencache.EnsureDispatch("Word.Application")
word.Visible = False
try:
    word.DisplayAlerts = 0
except Exception:
    pass

try:
    doc = word.Documents.Open(DOCX, ReadOnly=False)
    # 1) 刷新目录
    doc.Fields.Update()
    n_toc = doc.TablesOfContents.Count
    for i in range(1, n_toc + 1):
        doc.TablesOfContents(i).Update()
    # 2) 重排页码
    doc.Repaginate()
    pages = doc.ComputeStatistics(2)          # wdStatisticPages
    words = doc.ComputeStatistics(0)          # wdStatisticWords
    print("目录域数量: %d | 页数: %d | 字数: %d" % (n_toc, pages, words))
    doc.Save()
    # 3) 导出 PDF（17 = wdFormatPDF）
    doc.SaveAs2(PDF, FileFormat=17)
    doc.Close(0)
finally:
    word.Quit()

print("PDF →", PDF, "%.2f MB" % (os.path.getsize(PDF) / 1024 / 1024))
