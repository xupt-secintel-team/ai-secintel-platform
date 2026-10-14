# -*- coding: utf-8 -*-
"""index.html 剩余 v11 骨架替换（单次读写，避免并行 Edit 丢改动）。"""
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
P = r'C:\Users\丁\Desktop\aisec-D_2.0\frontend\index.html'
s = open(P, encoding='utf-8').read()
orig = s

REPL = [
    # 幽灵字 → 承载数字
    ('<span class="vh-ghost" aria-hidden="true">MONITOR</span>',
     '<span class="vh-ghost" aria-hidden="true"><em>MONITOR</em><b data-ghost="live"></b></span>'),
    ('<span class="vh-ghost" aria-hidden="true">ENRICH</span>',
     '<span class="vh-ghost" aria-hidden="true"><em>ENRICH</em><b data-ghost="exploited"></b></span>'),
    ('<span class="vh-ghost" aria-hidden="true">ASK</span>',
     '<span class="vh-ghost" aria-hidden="true"><em>ASK</em><b data-ghost="knowledge"></b></span>'),
    # 检查器拖拽手柄（M4）
    ('<aside class="inspector" id="inspector" aria-label="情报检查器">\n        <div class="insp-head" id="dh"></div>',
     '<aside class="inspector" id="inspector" aria-label="情报检查器">\n'
     '        <div class="insp-grip" id="inspgrip" title="拖拽调宽 · 双击复位" aria-hidden="true"></div>\n'
     '        <div class="insp-head" id="dh"></div>'),
    # toast → 堆叠容器（M5）
    ('<div class="toast" id="toast"></div>',
     '<div class="toastwrap" id="toastwrap" role="status" aria-live="polite" aria-atomic="false"></div>'),
    # 版本号递增（静态资源缓存 10 分钟）
    ('styles.css?v=19', 'styles.css?v=20'),
    ('app.js?v=16', 'app.js?v=17'),
]

for a, b in REPL:
    n = s.count(a)
    if n != 1:
        print(f'!! 命中 {n} 次（期望 1）：{a[:60]}')
        continue
    s = s.replace(a, b)
    print('ok  →', b.split('\n')[0][:78])

if s != orig:
    open(P, 'w', encoding='utf-8', newline='').write(s)
    print('已写入', P, f'(Δ{len(s)-len(orig):+d}B)')
