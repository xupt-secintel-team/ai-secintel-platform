# -*- coding: utf-8 -*-
"""v9 降噪 · 模板改写：把监测台右栏 3 个长面板 <div class="panel"> 改成可折叠的 <details class="panel">。

为什么用脚本而不是手改：
  · 三个面板内容都很长（含嵌套 <div>），手改闭合标签极易错位；
  · Python 按"div 深度归零"定位每个面板的闭合 </div>，确定且可复跑。
规则：只改这 3 处（按 animation-delay 唯一定位），其余一字不动。
"""
import io
import re
import sys

APP = r"C:\Users\丁\Desktop\aisec-D_2.0\frontend\app.js"

# 三处 panel 的开标签（animation-delay 唯一）+ 对应 header 文本（唯一）
PANELS = [
    ("animation-delay:90ms",
     "<header>快车道实时监测 <span class=\"ph-sub\">${liveOk ? (stale ? '数据偏旧' : '运行中') : '未启用'}</span></header>"),
    ("animation-delay:140ms",
     "<header>风险分类分布 <span class=\"ph-sub\">语料口径</span></header>"),
    ("animation-delay:190ms",
     "<header>语料类型 / 严重度 / 归档 <span class=\"ph-sub\">/api/stats · /api/sources</span></header>"),
]


def find_panel_close(s, start):
    """从 start（<details ...> 之后）起按 div 深度归零找闭合 </div> 的下标。"""
    depth = 0
    i = start
    while i < len(s):
        m = re.compile(r"<div\b|</div>").search(s, i)
        if not m:
            return -1
        if m.group(0) == "<div":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.start()
        i = m.end()
    return -1


def main():
    s = io.open(APP, encoding="utf-8").read()
    log = []
    for delay, header in PANELS:
        open_old = '<div class="panel" style="%s">' % delay
        open_new = '<details class="panel" style="%s">' % delay
        if open_new in s and open_old not in s:
            log.append(("SKIP", delay, "已是 details"))
            continue
        if open_old not in s:
            log.append(("MISS", delay, "未找到 <div class=panel>"))
            continue
        s = s.replace(open_old, open_new, 1)

        if header not in s:
            log.append(("MISS", delay, "未找到 header"))
            continue
        s = s.replace(header, header.replace("<header>", "<summary>").replace("</header>", "</summary>"), 1)

        start = s.index(open_new) + len(open_new)
        c = find_panel_close(s, start)
        if c < 0:
            log.append(("MISS", delay, "未找到闭合 </div>"))
            continue
        s = s[:c] + "</details>" + s[c + len("</div>"):]
        log.append(("OK", delay, "panel 已改为可折叠"))

    bad = [x for x in log if x[0] == "MISS"]
    for st, delay, msg in log:
        print("  [%s] %-18s %s" % (st, delay, msg))
    if bad and "--force" not in sys.argv:
        print("!! 有未命中项，未写盘（加 --force 可强制写入）")
        return 1

    io.open(APP, "w", encoding="utf-8", newline="").write(s)
    print("已写盘：", APP)
    return 0


if __name__ == "__main__":
    sys.exit(main())
