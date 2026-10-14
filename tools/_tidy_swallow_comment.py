# -*- coding: utf-8 -*-
"""把改写后的 except 头注释规范化：`#noqa: X :` -> `# noqa: X`。"""
import os
import re

SKIP = {'.git', 'node_modules', '__pycache__', '.workbuddy',
        'venv', '.venv', 'env', 'build', 'dist', 'data', 'frontend'}
PAT = re.compile(r'^(.*?as _sw_e:\s*)(#.*)$')

n = nf = 0
for dp, dn, fn in os.walk('.'):
    dn[:] = [d for d in dn if d not in SKIP]
    for f in fn:
        if not f.endswith('.py'):
            continue
        p = os.path.join(dp, f)
        lines = open(p, encoding='utf-8').read().split('\n')
        ch = False
        for i, ln in enumerate(lines):
            if 'as _sw_e' not in ln or '#' not in ln:
                continue
            if not re.match(r'^\s*(except|\)|\) as)', ln):
                continue  # 不是 except 头（可能是注释/字符串里恰好出现这些字样）
            m = PAT.match(ln)
            if not m:
                continue
            code, com = m.group(1), m.group(2)
            body = com.lstrip('#').strip().rstrip(':').strip()
            new = code.rstrip() + '  # ' + body
            if new != ln:
                lines[i] = new
                ch = True
                n += 1
        if ch:
            nf += 1
            open(p, 'w', encoding='utf-8', newline='\n').write('\n'.join(lines))
print('规范化注释：%d 个文件、%d 行' % (nf, n))
