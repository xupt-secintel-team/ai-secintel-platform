# -*- coding: utf-8 -*-
import io, os, re, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'

s = open(os.path.join(R, 'frontend', 'styles.css'), encoding='utf-8').read()
body = re.sub(r'/\*.*?\*/', '', s, flags=re.S)
# 删掉所有 :root{...} 令牌定义块（非贪婪到第一个 }）
def strip_root(t):
    out, i = [], 0
    while True:
        j = t.find(':root', i)
        if j < 0:
            out.append(t[i:]); break
        out.append(t[i:j])
        k = t.find('{', j)
        if k < 0:
            out.append(t[j:]); break
        depth, p = 1, k + 1
        while p < len(t) and depth:
            if t[p] == '{': depth += 1
            elif t[p] == '}': depth -= 1
            p += 1
        i = p
    return ''.join(out)

rest = strip_root(body)
hexes = sorted({m.lower() for m in re.findall(r'#[0-9a-fA-F]{3,8}\b', rest)})
print('散落 hex（非 :root 令牌定义）: %d 个' % len(hexes))
for h in hexes:
    print('   ', h)

m2 = open(os.path.join(R, 'modules', 'm2_enrich', 'web', 'panel.css'), encoding='utf-8').read()
print('\n--- m2 panel.css 代码行里的 hex（排除注释） ---')
for i, l in enumerate(m2.split('\n'), 1):
    code = re.sub(r'/\*.*?\*/', '', l)
    if re.search(r'#[0-9a-fA-F]{3,8}\b', code):
        print(i, l.strip()[:120])
