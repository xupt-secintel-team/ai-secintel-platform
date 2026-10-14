# -*- coding: utf-8 -*-
"""v11 收尾：内联字号收敛(T1/T4) + 顶栏数字分工(H1) + 字号下限抬档(T4)。"""
import io, os, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'

A = os.path.join(R, 'frontend', 'app.js')
C = os.path.join(R, 'frontend', 'styles.css')
I = os.path.join(R, 'frontend', 'index.html')

# ---------- styles.css：T4 字号下限抬到 11.5px ----------
s = open(C, encoding='utf-8').read()
before = s
s = s.replace('--fs-micro:11px;', '--fs-micro:11.5px;')
# 断点里断言太小处（若有 10px 裸值）—— 记录
assert s != before, 'styles.css micro token 未命中'
open(C, 'w', encoding='utf-8', newline='\n').write(s)
print('[styles.css] --fs-micro -> 11.5px')

# ---------- app.js ----------
a = open(A, encoding='utf-8').read()
orig = a

# (1) T1/T4：5 处内联裸字号 → 令牌
repl = [
    ('<i class="chip" style="font-size:10px">',
     '<i class="chip" style="font-size:var(--fs-micro)">'),
    ('<span style="font-family:var(--mono);font-size:12px">',
     '<span style="font-family:var(--mono);font-size:var(--fs-xs)">'),
    ('style="margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--txt-4)"',
     'style="margin-left:auto;font-family:var(--mono);font-size:var(--fs-micro);color:var(--txt-4)"'),
    ('<span style="font-size:10.5px;color:var(--txt-4);font-family:var(--mono)">',
     '<span style="font-size:var(--fs-micro);color:var(--txt-4);font-family:var(--mono)">'),
    ('<div class="desc-p" style="margin-top:10px;font-size:13px">',
     '<div class="desc-p" style="margin-top:10px;font-size:var(--fs-sm)">'),
]
for x, y in repl:
    assert x in a, '未命中: ' + x[:50]
    a = a.replace(x, y)

# (2) H1：顶栏由 5 个全局量收为 3 个（总量 / 规模 / 警报），
#     其余数字交给监测台（全量）与答复卡（本次查询相关），不再三处重复。
old_top = """  const kpi = (v, l, cls) => `<div class="kv${cls ? ' ' + cls : ''}"><b data-n="${v}">0</b><span>${esc(l)}</span></div>`;
  $('topstat').innerHTML = [
    kpi(s.vulnerabilities, '情报条目'),
    kpi(s.knowledge, '知识条目'),
    kpi(s.total, '语料总量'),
    kpi(s.exploited, '在野利用'),
    kpi(s.poc, '含 POC'),
  ].join('') + `<div class="kv" style="display:flex;align-items:center;gap:7px;justify-content:flex-end">"""
new_top = """  const kpi = (v, l, cls) => `<div class="kv${cls ? ' ' + cls : ''}"><b data-n="${v}">0</b><span>${esc(l)}</span></div>`;
  /* ★ v11（H1）：同一组数字原先在「顶栏 / 答复卡 / 监测台」三处重复，焦点被稀释。
     现在三处分工：
       · 顶栏（常驻）—— 只留 3 个全局量：总量 / 规模 / 警报；
       · 监测台 —— 保留全量 6 项（那里才有分类与趋势的上下文）；
       · 答复卡 —— 只显示「本次查询相关」的命中口径。
     顶栏去掉的「知识条目 / 含 POC」在监测台与答复卡里都有，不丢信息。 */
  $('topstat').innerHTML = [
    kpi(s.total, '语料总量'),
    kpi(s.vulnerabilities, '情报条目'),
    kpi(s.exploited, '在野利用'),
  ].join('') + `<div class="kv" style="display:flex;align-items:center;gap:7px;justify-content:flex-end">"""
assert old_top in a, 'H1 顶栏块未命中'
a = a.replace(old_top, new_top)

assert a != orig
open(A, 'w', encoding='utf-8', newline='\n').write(a)
print('[app.js] 内联字号收敛 5 处 + 顶栏数字分工 (H1)')

print('\n完成。')
