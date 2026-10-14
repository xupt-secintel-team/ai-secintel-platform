# -*- coding: utf-8 -*-
"""输出模块 CSS 中 #fff / 关键 hex 的上下文，避免误替换。"""
import re, os, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'
TARGETS = {'#fff', '#ffffff', '#eafff4', '#d6f5e4', '#cde8da', '#9ecfb8',
           '#c7d2e8', '#dfe1ff', '#a8adb5', '#b6bcc4', '#d29922', '#e5484d'}
for rel in [r'modules\m0_ops\web\ops.css', r'modules\m1_monitor\web\daily.css',
            r'modules\m2_enrich\web\panel.css', r'modules\m3_qa\web\panel.css']:
    s = open(os.path.join(R, rel), encoding='utf-8').read()
    print('=' * 70); print(rel)
    for i, line in enumerate(s.split('\n'), 1):
        low = line.lower()
        if any(t in low for t in TARGETS):
            print(f'  {i}: {line.strip()[:150]}')
