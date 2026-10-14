# -*- coding: utf-8 -*-
"""模块 JS 面板的散落色 → 黑金（源 + 组装副本一起改，保持组装一致）"""
import glob
import io
import os

ROOT = r"C:\Users\丁\Desktop\aisec-D_2.0"
FE = os.path.join(ROOT, "frontend")

PAIRS = [
    # m1_monitor/daily.js：方向卡片兜底色（对应 core/daily_digest.py 的 _DIR_COLOR_FALLBACK）
    ("#7c5cff", "#d9a441"),   # dir_infra  紫 → 金
    ("#00b8d9", "#2fbf9e"),   # dir_model  青 → 玉
    ("#36b37e", "#e8913c"),   # dir_appagent 绿 → 橙
    ("#ffab00", "#f2c94c"),   # dir_supply 黄 → 亮黄
    # m1_monitor/panel.js：严重度色 + 订阅错误色
    ("{ CRITICAL: '#ff6369', HIGH: '#f5a524', MEDIUM: '#6ea8fe', LOW: '#30a46c', UNKNOWN: '#62666d' }",
     "{ CRITICAL: '#ff5a52', HIGH: '#f0a72e', MEDIUM: '#d9a441', LOW: '#4acc8a', UNKNOWN: '#968e79' }"),
    ("rgba(255,99,105,.12)", "rgba(255,90,82,.12)"),
    ("rgba(255,99,105,.42)", "rgba(255,90,82,.42)"),
    ("color: '#ff6369'", "color: '#ff5a52'"),
    # m2_enrich/panel.js
    ("#e5534b", "#ff5a52"),
]

files = sorted(set(
    glob.glob(os.path.join(ROOT, "modules", "*", "web", "*.js")) +
    glob.glob(os.path.join(FE, "modules", "*", "*.js"))
))

total = 0
for p in files:
    s = io.open(p, encoding="utf-8", newline="").read()
    o = s
    hits = 0
    for a, b in PAIRS:
        c = s.count(a)
        if c:
            s = s.replace(a, b)
            hits += c
    if s != o:
        io.open(p, "w", encoding="utf-8", newline="").write(s)
        print(f"  写入 {os.path.relpath(p, ROOT):<44} {hits} 处")
        total += hits
print(f"  合计 {total} 处")
