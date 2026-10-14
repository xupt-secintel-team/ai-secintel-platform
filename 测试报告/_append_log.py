# -*- coding: utf-8 -*-
import io, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'
src = os.path.join(R, '测试报告', '_v11_log.md')
dst = os.path.join(R, '.workbuddy', 'memory', '2026-10-09.md')
add = open(src, encoding='utf-8').read()
cur = open(dst, encoding='utf-8').read()
if 'v11 落地' in cur:
    print('已存在，跳过')
else:
    open(dst, 'a', encoding='utf-8', newline='\n').write(add)
    print('appended', len(add), 'chars; total', len(open(dst, encoding='utf-8').read()))
