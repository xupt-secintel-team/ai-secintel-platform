# -*- coding: utf-8 -*-
"""把「改前 / 改后」并排拼成一张对比图。

用法：
    py 测试报告/_ui_compare.py [改前前缀] [改后前缀] [输出名]
默认： before  v7a  compare_v4_v7.png
"""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
SHOT = os.path.join(ROOT, "测试报告", "_ui_shots")

PRE = sys.argv[1] if len(sys.argv) > 1 else "before"
POST = sys.argv[2] if len(sys.argv) > 2 else "v7a"
OUTNAME = sys.argv[3] if len(sys.argv) > 3 else "compare_v4_v7.png"
OUT = os.path.join(SHOT, OUTNAME)

PAIRS = [
    (f"{PRE}_search.png",  f"{POST}_search.png",  "检索工作区"),
    (f"{PRE}_monitor.png", f"{POST}_monitor.png", "实时监测台"),
]
W, H = 780, 488
TITLE_H = 34
GAPX, GAPY = 18, 16
PAD = 20
TOP = 62

font_path = r"C:\Windows\Fonts\msyh.ttc"
try:
    f_big = ImageFont.truetype(font_path, 26)
    f_mid = ImageFont.truetype(font_path, 19)
    f_sm = ImageFont.truetype(font_path, 16)
except Exception:
    f_big = f_mid = f_sm = ImageFont.load_default()

cols = 2
rows = len(PAIRS)
Wtot = PAD * 2 + W * cols + GAPX * (cols - 1)
Htot = TOP + PAD + (TITLE_H + H) * rows + GAPY * (rows - 1)
canvas = Image.new("RGB", (Wtot, Htot), (9, 11, 20))
d = ImageDraw.Draw(canvas)

d.text((PAD, 18), f"AI-SecIntel 前端改版对比：改前（{PRE}）  →  改后（{POST}）", fill=(236, 239, 251), font=f_big)
d.text((PAD, 48), "只改前端（CSS + HTML 骨架），未改任何 JS 逻辑与功能", fill=(131, 142, 168), font=f_sm)

y = TOP
for i, (b, a, label) in enumerate(PAIRS):
    pb, pa = os.path.join(SHOT, b), os.path.join(SHOT, a)
    if not (os.path.exists(pb) and os.path.exists(pa)):
        print("MISS", pb if not os.path.exists(pb) else pa)
        continue
    im_b = Image.open(pb).convert("RGB").resize((W, H))
    im_a = Image.open(pa).convert("RGB").resize((W, H))
    x = PAD
    for tag, im in ((f"改前 {PRE}", im_b), (f"改后 {POST}", im_a)):
        d.rectangle([x, y, x + W, y + TITLE_H - 6], fill=(17, 21, 35))
        d.text((x + 10, y + 3), f"{label} · {tag}", fill=(121, 168, 255), font=f_mid)
        canvas.paste(im, (x, y + TITLE_H))
        d.rectangle([x, y + TITLE_H, x + W - 1, y + TITLE_H + H - 1], outline=(40, 48, 72))
        x += W + GAPX
    y += TITLE_H + H + GAPY

canvas.save(OUT)
print("saved", OUT, os.path.getsize(OUT), canvas.size)
