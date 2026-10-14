# -*- coding: utf-8 -*-
"""v11 改造前扫描：列出各 CSS 的 font-size / padding / gap / hex 取值清单。"""
import re, collections, os, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
FILES = [
    r"frontend\styles.css",
    r"modules\m0_ops\web\ops.css",
    r"modules\m1_monitor\web\daily.css",
    r"modules\m2_enrich\web\panel.css",
    r"modules\m3_qa\web\panel.css",
]

FS = re.compile(r"font-size\s*:\s*([^;{}/]+)")
PAD = re.compile(r"\bpadding(?:-(?:top|right|bottom|left))?\s*:\s*([^;{}/]+)")
GAP = re.compile(r"\b(?:gap|row-gap|column-gap)\s*:\s*([^;{}/]+)")
HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
ACT = re.compile(r":active\b")
HOV = re.compile(r":hover\b")

for rel in FILES:
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        print("MISSING", rel); continue
    s = open(p, encoding='utf-8').read()
    print("=" * 70)
    print(rel, len(s), "bytes")

    def nums(rx, label):
        vals = []
        for m in rx.finditer(s):
            v = m.group(1).strip()
            if 'var(' in v or 'calc(' in v or 'clamp(' in v or 'inherit' in v or 'em' in v:
                continue
            for tok in re.findall(r"-?\d+(?:\.\d+)?", v):
                vals.append(float(tok))
        c = collections.Counter(vals)
        print(f"  {label}: {len(vals)} 处 / {len(c)} 个取值")
        print("   ", sorted(c.items(), key=lambda x: x[0]))

    nums(FS, "font-size")
    nums(PAD, "padding")
    nums(GAP, "gap")
    hx = collections.Counter(m.group(0).lower() for m in HEX.finditer(s))
    print(f"  hex: {sum(hx.values())} 处 / {len(hx)} 色")
    print("   ", sorted(hx.items(), key=lambda x: -x[1]))
    print("  :hover", len(HOV.findall(s)), " :active", len(ACT.findall(s)))
