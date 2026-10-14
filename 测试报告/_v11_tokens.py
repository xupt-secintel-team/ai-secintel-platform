# -*- coding: utf-8 -*-
"""修复模块 CSS 里 4 个**引用不存在令牌**（浏览器会静默回落到继承值，肉眼难察）：
   --txt-1（应为 --txt）· --line-1（应为 --line/--line-2）· --r-2（应为 --r-sm）· --bad（应为 --danger）。"""
import io, sys, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'
JOBS = {
    r'modules\m0_ops\web\ops.css': [
        ('var(--txt-1,var(--txt))', 'var(--txt)'),
        ('var(--bad)', 'var(--danger)'),
    ],
    r'modules\m2_enrich\web\panel.css': [
        ('var(--line-1, rgba(255,255,255,.22))', 'var(--line-2)'),
        ('var(--line-1, rgba(255,255,255,.2))', 'var(--line-2)'),
        ('var(--line-1, rgba(255,255,255,.09))', 'var(--line)'),
        ('var(--r-2, 8px)', 'var(--r-sm)'),
        ('var(--txt-1)', 'var(--txt)'),
    ],
}
for rel, subs in JOBS.items():
    p = os.path.join(R, rel)
    s = open(p, encoding='utf-8').read()
    o = s
    for a, b in subs:
        n = s.count(a)
        s = s.replace(a, b)
        print(f'  {rel.split(chr(92))[-1]}: {a[:44]:46s} ×{n} → {b}')
    if s != o:
        open(p, 'w', encoding='utf-8', newline='').write(s)
print('完成')
