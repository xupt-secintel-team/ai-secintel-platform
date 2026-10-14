# -*- coding: utf-8 -*-
"""
v11 视觉纪律改造 · 机械替换层
------------------------------------------------------------
对 5 个 CSS 文件执行三项"收敛"，全部按文件分组：读一次 → 顺序替换 → 写一次。
  ① font-size  : 28 个裸值 → 8 级尺度令牌 var(--fs-*)
  ② padding/gap: 41/24 个裸值 → 6+2 档 4px 网格 var(--sp-*)
  ③ hex 颜色   : 模块硬编码色（含冷灰/紫蓝残留）→ 核心令牌；var(--x,#hex) 去掉 fallback
保护措施：先备份；`:root` 里的 `--x:...;` 变量定义整体占位，不参与替换。
"""
import re, os, io, sys, shutil, time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
R = r'C:\Users\丁\Desktop\aisec-D_2.0'
FILES = [
    r'frontend\styles.css',
    r'modules\m0_ops\web\ops.css',
    r'modules\m1_monitor\web\daily.css',
    r'modules\m2_enrich\web\panel.css',
    r'modules\m3_qa\web\panel.css',
]

# ---------------- 备份 ----------------
BK = os.path.join(R, '测试报告', '_v11_backup_' + time.strftime('%Y%m%d_%H%M%S'))
for rel in FILES:
    src = os.path.join(R, rel)
    dst = os.path.join(BK, rel.replace('\\', '__'))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
print('已备份 →', BK)

# ---------------- ① 字号档位 ----------------
def fs_bucket(x):
    if x <= 10.5:  return 'micro'
    if x <= 12.0:  return 'xs'
    if x <= 13.2:  return 'sm'
    if x <= 14.6:  return 'body'
    if x <= 17.2:  return 'h3'
    if x <= 24.5:  return 'h2'
    if x <= 36.0:  return 'h1'
    return 'display'

# ---------------- ② 间距档位（0/1/2/3 视为微调值，保留） ----------------
SP = [(4, 5, '1'), (6, 9, '2'), (10, 13, '3'), (14, 18, '4'),
      (19, 25, '5'), (26, 38, '6'), (39, 56, '7'), (57, 88, '8')]
def sp_token(x):
    if x < 3.5:
        return None                    # 0/1/2/3 保留原值
    for lo, hi, name in SP:
        if lo <= x <= hi:
            return f'var(--sp-{name})'
    return None                        # >88px 保留

# ---------------- ③ 颜色映射 ----------------
CMAP = {
    # 灰阶（模块自带冷灰 → 核心暖灰四级）
    '#8a8f98': 'var(--txt-3)', '#9aa0a6': 'var(--txt-3)', '#8b949e': 'var(--txt-3)',
    '#767e8a': 'var(--txt-3)', '#8a929c': 'var(--txt-3)', '#a8adb5': 'var(--txt-3)',
    '#62666d': 'var(--txt-4)', '#6f7780': 'var(--txt-4)',
    '#c9ccd1': 'var(--txt-2)', '#b8bcc4': 'var(--txt-2)', '#b6bcc4': 'var(--txt-2)',
    '#c5bda9': 'var(--txt-2)',
    '#e6e8ea': 'var(--txt)', '#e9ecef': 'var(--txt)', '#e8eaed': 'var(--txt)',
    '#f7f8f8': 'var(--txt)', '#ffffff': 'var(--txt)', '#c7d2e8': 'var(--txt-3)',
    '#dfe1ff': 'var(--accent-3)',
    # 语义 · 绿
    '#4acc8a': 'var(--ok)', '#30a46c': 'var(--ok)', '#3fbf7a': 'var(--ok)',
    '#9ecfb8': 'var(--ok)', '#d6f5e4': 'var(--ok)', '#eafff4': 'var(--ok)',
    '#cde8da': 'var(--ok)',
    # 语义 · 红
    '#ff5a52': 'var(--danger)', '#ff5c5c': 'var(--danger)', '#ff7b72': 'var(--danger)',
    '#ff7b81': 'var(--danger)', '#e5484d': 'var(--danger)', '#c02b26': 'var(--danger)',
    '#ff9289': 'var(--danger)',
    # 语义 · 橙 / 黄
    '#ff8a3d': 'var(--high)', '#f0a72e': 'var(--warn)', '#d29922': 'var(--warn)',
    '#f2c94c': 'var(--med)', '#e8913c': 'var(--viz-3)',
    # 品牌
    '#e3b04b': 'var(--accent)', '#f0cd7a': 'var(--accent-2)', '#f6e3ae': 'var(--accent-3)',
    '#e8c76e': 'var(--accent-2)', '#d9a441': 'var(--accent)', '#eec876': 'var(--accent-2)',
    '#191204': 'var(--accent-ink)', '#1a1305': 'var(--accent-ink)',
    # 青玉 / 铜（紫蓝残留一律归位）
    '#2fbf9e': 'var(--cyan)', '#5edcbb': 'var(--cyan-2)',
    '#b8823a': 'var(--iris)', '#b18bff': 'var(--iris)', '#7170ff': 'var(--iris)',
    '#4c8dde': 'var(--cyan)', '#2b52bf': 'var(--iris)', '#2f5ee0': 'var(--iris)',
    # 底 / 面
    '#111316': 'var(--elev-1)', '#0b0c0e': 'var(--bg)', '#1b1e23': 'var(--bg-2)',
    '#23262b': 'var(--elev-1)', '#2b2f36': 'var(--elev-2)', '#0b0906': 'var(--bg)',
    '#b9a284': 'var(--viz-7)',
}

FS_RX   = re.compile(r'(font-size\s*:\s*)([^;}]+)')
PAD_RX  = re.compile(r'(\b(?:padding|padding-top|padding-right|padding-bottom|padding-left)\s*:\s*)([^;}]+)')
GAP_RX  = re.compile(r'(\b(?:gap|row-gap|column-gap)\s*:\s*)([^;}]+)')
VARDEF  = re.compile(r'--[\w-]+\s*:[^;{}]*;')
VARFALL = re.compile(r'var\(\s*(--[\w-]+)\s*,\s*#[0-9a-fA-F]{3,8}\s*\)')
HEX_RX  = re.compile(r'#[0-9a-fA-F]{3,8}\b')

def conv_fs(v):
    if re.search(r'var\(|calc\(|clamp\(|\bem\b|%|inherit|initial|unset', v):
        return v
    def rep(m):
        x = float(m.group(1))
        return f'var(--fs-{fs_bucket(x)})'
    return re.sub(r'(?<![\w.-])(\d+(?:\.\d+)?)px\b', rep, v)

def conv_sp(v):
    if re.search(r'var\(|calc\(|clamp\(|auto|%|em', v):
        return v
    parts = [p for p in re.split(r'(\s+)', v.strip()) if p]
    for i, p in enumerate(parts):
        m = re.fullmatch(r'(-?)(\d+(?:\.\d+)?)px', p)
        if not m:
            continue
        x = float(m.group(2)) * (-1 if m.group(1) else 1)
        tok = sp_token(abs(x))
        if tok:
            parts[i] = ('-' + tok) if x < 0 else tok
    return ''.join(parts)

report = {}
for rel in FILES:
    p = os.path.join(R, rel)
    s = open(p, encoding='utf-8').read()
    orig = s

    # 保护 :root / 变量定义（整体占位）
    saves = []
    def stash(m):
        saves.append(m.group(0))
        return f'\x00{len(saves)-1}\x00'
    s = VARDEF.sub(stash, s)

    # ① var(--x, #hex) 去 fallback
    s = VARFALL.sub(lambda m: f'var({m.group(1)})', s)
    # ② 字号 / 间距
    s = FS_RX.sub(lambda m: m.group(1) + conv_fs(m.group(2)), s)
    s = PAD_RX.sub(lambda m: m.group(1) + conv_sp(m.group(2)), s)
    s = GAP_RX.sub(lambda m: m.group(1) + conv_sp(m.group(2)), s)
    # ③ 剩余 hex
    def rep_hex(m):
        h = m.group(0).lower()
        return CMAP.get(h, m.group(0))
    s = HEX_RX.sub(rep_hex, s)

    # 还原
    s = re.sub(r'\x00(\d+)\x00', lambda m: saves[int(m.group(1))], s)

    if s != orig:
        open(p, 'w', encoding='utf-8', newline='').write(s)
    # 统计剩余
    left_fs = sorted({float(x) for x in re.findall(r'font-size\s*:\s*(\d+(?:\.\d+)?)px', s)})
    left_hx = sorted({m.lower() for m in HEX_RX.findall(s)})
    report[rel] = (len(s) - len(orig), left_fs, len(left_hx))
    print(f'{rel}: Δ{len(s)-len(orig):+d}B 剩余裸字号{left_fs} 剩余hex {len(left_hx)}色')
print('\n全部完成。')
