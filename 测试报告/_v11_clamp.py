# -*- coding: utf-8 -*-
"""R5 修正：.viewhead p 的 line-clamp 原先有 4 条互相冲突（1/2/3/4），
   级联后 hover:none 的 4 行胜出 → 移动端页头仍高。收敛为单一契约：
   · 默认 1 行，hover / focus-within 展开 5 行（桌面）
   · ≤980px 移动端 2 行
"""
import io, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
P = r'C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css'
s = open(P, encoding='utf-8').read()
orig = s

# 1) 删掉 768 块里那条（与 ≤980 重复）
a1 = '  .viewhead p{-webkit-line-clamp:2}\n  /* M6：触屏目标'
b1 = '  /* M6：触屏目标'
assert a1 in s, '1 未命中'
s = s.replace(a1, b1, 1)

# 2) ≤980 的 3 行 → 2 行（R5：移动端 1~2 行）
a2 = '  .viewhead p{-webkit-line-clamp:3}\n'
b2 = '  .viewhead p{-webkit-line-clamp:2}   /* R5：移动端页头收到 2 行 */\n'
assert a2 in s, '2 未命中'
s = s.replace(a2, b2, 1)

# 3) 删掉 hover:none 里那条 4 行（与上面冲突且过宽）
a3 = '@media (hover:none){\n  .res .why{max-height:none}\n  .viewhead p{-webkit-line-clamp:4}\n}\n'
b3 = '@media (hover:none){\n  .res .why{max-height:none}\n}\n'
assert a3 in s, '3 未命中'
s = s.replace(a3, b3, 1)

assert s != orig
open(P, 'w', encoding='utf-8', newline='\n').write(s)
print('[styles.css] .viewhead p clamp 收敛：桌面 1(→hover 5) / ≤980 移动 2')

import re
for m in re.finditer(r'[^\n]*viewhead p[^\n]*', s):
    t = m.group(0).strip()
    if 'clamp' in t:
        print('   ', t)
