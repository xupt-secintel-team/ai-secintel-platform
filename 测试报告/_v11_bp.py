# -*- coding: utf-8 -*-
"""R2 断点收敛：把散落在增强层里的旧断点(1500/1180/700)归并进 6 档
   (1440/1400/1200/1024/980/768)，保证全文件按宽度降序、无 ad-hoc 档。"""
import io, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
P = r'C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css'
s = open(P, encoding='utf-8').read()
orig = s

reps = [
    # 1500 → 1440（与主档对齐）
    ('@media (max-width:1500px){.crumb-sub{display:none}}',
     '@media (max-width:1440px){.crumb-sub{display:none}}'),
    # 1180 → 1200（并入 1200 档）
    ('@media (max-width:1180px){.vh-ghost{display:none}}',
     '@media (max-width:1200px){.vh-ghost{display:none}}'),
    # 700 档与新的 768 档完全重复 → 删除
    ("""@media (max-width:700px){
  .viewhead{padding:var(--sp-4) var(--sp-4) var(--sp-3);border-radius:var(--r-md)}
  .viewhead::before{left:12px;right:12px}
}
""", ''),
]
for a, b in reps:
    assert a in s, '未命中: ' + a[:60]
    s = s.replace(a, b, 1)

assert s != orig
open(P, 'w', encoding='utf-8', newline='\n').write(s)
print('[styles.css] 断点收敛：1500→1440、1180→1200、删除 700（重复 768）')

# 复核
import re
mq = re.findall(r'@media[^{]+', s)
w = [int(m.group(1)) for m in re.finditer(r'@media \(max-width:(\d+)px', s)]
print('剩余 max-width 档：', sorted(set(w), reverse=True))
open_w = [int(m.group(1)) for m in re.finditer(r'@media \(min-width:(\d+)px', s)]
print('min-width 档：', sorted(set(open_w)))
