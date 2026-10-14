# -*- coding: utf-8 -*-
"""把技术讲解 PPT 导出成 1920x1080 的 PNG 序列，供视频合成使用。"""
import os
import sys

import pymupdf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PDF = os.path.join(ROOT, "交付物", "AI-SecIntel_2.0_技术讲解.pdf")
OUT = os.path.join(ROOT, "测试报告", "_video_frames")
os.makedirs(OUT, exist_ok=True)

doc = pymupdf.open(PDF)
for i, page in enumerate(doc):
    pix = page.get_pixmap(matrix=pymupdf.Matrix(1920 / page.rect.width,
                                                1920 / page.rect.width))
    pix.save(os.path.join(OUT, "slide_%02d.png" % i))
print("导出 %d 页 → %s" % (doc.page_count, OUT))
