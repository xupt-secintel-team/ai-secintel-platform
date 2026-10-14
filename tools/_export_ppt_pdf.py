# -*- coding: utf-8 -*-
"""用 PowerPoint COM 把改造后的 PPT 另存为 PDF，保证与 pptx 完全一致。

为什么要走 COM 而不是 LibreOffice/纯 Python：
  pptx 里大量使用了主题色、阴影、渐变和形状图层顺序，
  只有 PowerPoint 自身的渲染引擎能 100% 还原，导出的 PDF 才可用于提交。

注意：需要 pywin32。本机 D:\\python\\python.exe 才有，
      工作区 venv（python-pptx 那个）没装 pywin32，别用错解释器。
"""
import os
import win32com.client as win32

PPTX = r"D:\111111\备份\AI-SecIntel_2.0_技术讲解_终稿.pptx"
PDF = r"D:\111111\备份\AI-SecIntel_2.0_技术讲解_终稿.pdf"
ppSaveAsPDF = 32

if os.path.exists(PDF):
    os.remove(PDF)

app = win32.Dispatch("PowerPoint.Application")
pres = app.Presentations.Open(PPTX, WithWindow=False)
pres.SaveAs(PDF, ppSaveAsPDF)
pages = pres.Slides.Count
pres.Close()
app.Quit()

size = os.path.getsize(PDF) / 1024 / 1024
print("PPT PDF ok %.2f MB | %d 页" % (size, pages))
