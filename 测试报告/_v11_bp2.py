# -*- coding: utf-8 -*-
"""R1/R2 收口：让 max-width 断点在**文件里**也严格降序。
   ① 把散落在增强层里的 1200 / 980 规则并回主响应式节；
   ② 把 768 档整体移到文件末尾 —— 保证「最窄档永远最后、永远赢」，
      避免 980 档在它之后把移动端覆盖掉。"""
import io, os, re, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
P = r'C:\Users\丁\Desktop\aisec-D_2.0\frontend\styles.css'
s = open(P, encoding='utf-8').read()
orig = s


def take_block(text, start_marker):
    """从 start_marker 起，取出直到花括号配平结束（含尾随换行）。"""
    i = text.index(start_marker)
    j = text.index('{', i)
    depth, p = 0, j
    while p < len(text):
        if text[p] == '{':
            depth += 1
        elif text[p] == '}':
            depth -= 1
            if depth == 0:
                break
        p += 1
    k = p + 1
    while k < len(text) and text[k] == '\n':
        k += 1
    return i, k, text[i:k]


# ---------- ①a：vh-ghost 的 1200 档并回主 1200 块 ----------
a = '@media (max-width:1200px){.vh-ghost{display:none}}\n'
assert a in s, 'vh-ghost 未命中'
s = s.replace(a, '', 1)
anchor1200 = '  .top-stat .kv:nth-child(n+2){display:none}\n  .refstat{display:none}\n'
assert anchor1200 in s, '1200 锚点未命中'
s = s.replace(anchor1200,
              '  .top-stat .kv:nth-child(n+2){display:none}\n  .refstat{display:none}\n'
              '  .vh-ghost{display:none}\n'
              '  .insp-grip{display:none}   /* 检查器浮层模式下不拖宽 */\n', 1)

# ---------- ①b：删掉末尾孤立的 insp-grip 1200 块 ----------
a = '@media (max-width:1200px){ .insp-grip{display:none} }   /* 浮层模式不拖 */\n'
assert a in s, 'insp-grip 未命中'
s = s.replace(a, '', 1)

# ---------- ①c：窄屏 viewhead 的 980 档并回主 980 块 ----------
a = """@media (max-width:980px){
  .viewhead{min-height:0;padding:var(--sp-5) var(--sp-5) var(--sp-4)}
  .viewhead::before{left:16px;right:16px}
}
"""
assert a in s, 'viewhead 980 未命中'
s = s.replace(a, '', 1)
anchor980 = '  .help-grid{grid-template-columns:1fr auto}\n}\n'
assert anchor980 in s, '980 锚点未命中'
s = s.replace(anchor980,
              '  .help-grid{grid-template-columns:1fr auto}\n'
              '  .viewhead{min-height:0;padding:var(--sp-5) var(--sp-5) var(--sp-4)}\n'
              '  .viewhead::before{left:16px;right:16px}\n}\n', 1)

# ---------- ②：768 档整体移到文件末尾 ----------
mk = '/* ★ v11：原 700 / 620 两档合并为 768 一档（断点收敛） */'
i, k, block = take_block(s, mk)
s = s[:i] + s[k:]
s = s.rstrip('\n') + '\n\n' + block.rstrip('\n') + '\n'

assert s != orig
open(P, 'w', encoding='utf-8', newline='\n').write(s)

# ---------- 复核 ----------
w = [int(m.group(1)) for m in re.finditer(r'@media \(max-width:(\d+)px', s)]
print('max-width 出现的文件顺序：', w)
print('是否严格单调不增：', all(w[i] >= w[i + 1] for i in range(len(w) - 1)))
print('唯一档位：', sorted(set(w), reverse=True))
print('文件末尾 12 行：')
for l in s.rstrip('\n').split('\n')[-12:]:
    print('   ', l)
