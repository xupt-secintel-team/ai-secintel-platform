# -*- coding: utf-8 -*-
"""设计系统审计：量化「排版尺度 / 间距 / 圆角 / 颜色 / 动效 / 死代码」的一致性。

用法： py -3.13 测试报告/_ui_audit.py
"""
import io
import os
import re
from collections import Counter

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
FILES = [
    ("核心", os.path.join(ROOT, "frontend", "styles.css")),
    ("m0_ops", os.path.join(ROOT, "modules", "m0_ops", "web", "ops.css")),
    ("m1_monitor", os.path.join(ROOT, "modules", "m1_monitor", "web", "daily.css")),
    ("m2_enrich", os.path.join(ROOT, "modules", "m2_enrich", "web", "panel.css")),
    ("m3_qa", os.path.join(ROOT, "modules", "m3_qa", "web", "panel.css")),
]


def strip_comments(s):
    return re.sub(r"/\*.*?\*/", "", s, flags=re.S)


def nums(css, prop):
    """收集某属性的裸数值（带 px / 不带单位都算）"""
    out = []
    for m in re.finditer(r"(?<![\w-])" + prop + r"\s*:\s*([^;{}]+)", css):
        v = m.group(1).strip()
        for mm in re.finditer(r"(-?\d*\.?\d+)(px|rem|em)?", v):
            if mm.group(1) in ("0",):
                continue
            if mm.group(2) == "px" or (prop == "font-size" and mm.group(2) is None):
                out.append(float(mm.group(1)))
    return out


def report():
    print("=" * 74)
    print("AI-SecIntel 前端 · 设计系统一致性审计")
    print("=" * 74)
    for tag, path in FILES:
        if not os.path.isfile(path):
            print(f"\n[{tag}] 缺文件: {path}")
            continue
        raw = io.open(path, encoding="utf-8").read()
        css = strip_comments(raw)
        print(f"\n----- [{tag}] {os.path.basename(path)}  ({len(raw.encode('utf-8'))} 字节, "
              f"{raw.count(chr(10))+1} 行) -----")

        # 字号谱系
        fs = nums(css, "font-size")
        c = Counter(fs)
        print(f"  font-size 出现 {len(fs)} 次，{len(c)} 个不同取值：")
        for v, n in sorted(c.items(), reverse=True):
            print(f"      {v:>6.1f}px  ×{n}")

        # 圆角
        br = nums(css, "border-radius")
        print(f"  border-radius 裸值 {len(br)} 次，{len(set(br))} 个不同取值"
              f"（另有 {css.count('var(--r-')} 处用令牌）")

        # 间距（padding / margin / gap 的横竖组合）
        for prop in ("padding", "gap"):
            vs = nums(css, prop)
            cc = Counter(vs)
            print(f"  {prop} 裸值 {len(vs)} 次，{len(cc)} 个不同取值；高频: "
                  + ", ".join(f"{v:g}({n})" for v, n in cc.most_common(8)))

        # 颜色：硬编码 vs 令牌
        hexes = re.findall(r"#[0-9a-fA-F]{3,8}\b", css)
        rgbas = re.findall(r"rgba?\([^)]*\)", css)
        varc = len(re.findall(r"var\(--", css))
        print(f"  颜色：硬编码 hex {len(hexes)} 处（{len(set(hexes))} 色）、rgba {len(rgbas)} 处；"
              f"var(--) 引用 {varc} 处")

        # 动效
        print(f"  动效：@keyframes {len(re.findall(chr(64)+'keyframes', css))} 个；"
              f"transition {css.count('transition')} 处；animation {css.count('animation')} 处")

        # 危险信号
        print(f"  信号：!important {css.count('!important')} 处；"
              f":hover {css.count(':hover')} 处；:focus-visible {css.count(':focus-visible')} 处；"
              f":active {css.count(':active')} 处")

    # 核心文件的死令牌检测
    core = io.open(FILES[0][1], encoding="utf-8").read()
    print("\n" + "=" * 74)
    print("死令牌检测（定义了但全项目没人 var() 引用）")
    print("=" * 74)
    defined = re.findall(r"(--[a-z0-9-]+)\s*:", core)
    alldef = set(defined)
    allcss = ""
    for _, p in FILES:
        if os.path.isfile(p):
            allcss += io.open(p, encoding="utf-8").read()
    for name in sorted(alldef):
        if name.startswith(("--fs-", "--sp-", "--r-", "--lh-", "--tk-", "--ease", "--sh")):
            if f"var({name})" not in allcss:
                print(f"  未被引用: {name}")


if __name__ == "__main__":
    report()
