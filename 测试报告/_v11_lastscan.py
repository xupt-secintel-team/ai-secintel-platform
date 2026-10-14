# -*- coding: utf-8 -*-
import io, os, re, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'

print('== 1) 任何文件里的内联裸字号（.js/.html/.css，排除 SVG data URI）==')
hits = 0
for dp, dn, fn in os.walk(R):
    if '.venv' in dp or '.git' in dp or 'node_modules' in dp:
        continue
    for f in fn:
        if not f.endswith(('.js', '.html', '.css')):
            continue
        p = os.path.join(dp, f)
        try:
            s = open(p, encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        for i, l in enumerate(s.split('\n'), 1):
            if 'data:image/svg' in l:
                continue
            if re.search(r'font-size\s*:\s*\d', l):
                print('  ', os.path.relpath(p, R), i, l.strip()[:100])
                hits += 1
print('  内联裸字号命中：', hits)

print('\n== 2) 断点单调性（降序且每档唯一）==')
s = open(os.path.join(R, 'frontend', 'styles.css'), encoding='utf-8').read()
w = [int(m.group(1)) for m in re.finditer(r'@media \(max-width:(\d+)px', s)]
print('  出现序列：', w)
print('  是否单调不增：', all(w[i] >= w[i + 1] for i in range(len(w) - 1)))
print('  唯一档位：', sorted(set(w), reverse=True))

print('\n== 3) 令牌引用率 ==')
used = set(re.findall(r'var\((--[\w-]+)', s))
print('  被引用令牌数：', len(used))
print('  --sp-1..8 全部被引用：', all('--sp-%d' % i in used for i in range(1, 9)))
print('  --fs-* 被引用：', sorted(x for x in used if x.startswith('--fs-')))
print('  --lh-* 被引用：', sorted(x for x in used if x.startswith('--lh-')))
print('  --tk-* 被引用：', sorted(x for x in used if x.startswith('--tk-')))
