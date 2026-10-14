# -*- coding: utf-8 -*-
"""把 v11 修正（幽灵字重叠）追加到今日工作日志。"""
import os

P = r"C:\Users\丁\Desktop\aisec-D_2.0\.workbuddy\memory\2026-10-09.md"

ADD = """

---

## v11 修正 · 页头「幽灵字」与右上控件文字重叠（用户报：这两个地方的右上角文字重叠了）

**现象**：实时监测台页头右上「1,782 / 109,328」与「刷新视图」按钮糊在一起；情报富化台右上「在野利用 / 含 POC」分段器与「ENRICH 535」叠成一团。

**根因（3 个，全是"写了却不生效"）**
1. **O3 幽灵字锚在右上角**（`.vh-ghost{top:14px;right:26px}`），而监测台 / 富化台的页头右侧**本来就有控件**（`#monrefresh` 按钮、`#enfilt` 分段器），两者共用同一条横带 → 必然撞。搜索 / 问答视图的右侧 `.tagline` 被 `display:none` 收掉了，所以**只有这两个视图出问题** —— 与用户两张截图完全对上。
2. `.vh-ghost em{transform:translateY(6px)}` 把英文视图名下压 6px，正好压进下方数字的描边里（MONITOR / ENRICH 与数字糊在一起）。
3. **★ 级联又踩同一坑**：v11 节 `.vh-ghost{display:flex}`（无条件、行 1948）把 `@media(max-width:1200px)` 里的 `.vh-ghost{display:none}`（行 1294）**整条吃掉** → 1100px 窄屏幽灵字照常显示、数字顶进页头描述文字。（同类：更早 `.viewhead{min-height:152px}` 被 v9 的 `min-height:0` 覆盖。）

**修法**
- `.vh-ghost` 改锚**右下角**（`top:auto;bottom:var(--sp-3);right:var(--sp-5)`）：控件占右上、数字占右下，垂直分离；底部收边线右侧 22% 本就渐隐透明，数字落在那段空白上不打架。
- 去掉 `em` 的 `translateY(6px)`；`gap` 1px→2px、`text-align:right`。
- `.viewhead{padding-bottom:var(--sp-5)}` 拉开上下两条带的净空。
- 窄屏隐藏改 `display:none!important`，拿回被无条件声明吃掉的控制权。
- **顺手修 JS**：`fetchStats` 回调里硬编码 `updateGhost('search')` → 改为 `updateGhost()`（当前视图）。否则**深链 / 先切视图后到数据**时，富化台与问答台的幽灵数字永远是空的（实测 `ghost-num` 宽高为 0）。

**★ 判据沉淀**
28. **「幽灵字 / 水印」这类绝对定位装饰，与「功能性控件」抢同一个角 = 必然重叠**。放装饰前先问：这个角落有没有控件？有 → 装饰换角（本项目定为：控件右上、数字右下）。
29. **级联胜负只看"谁在文件里更靠后"**（第 3 次踩）：`@media(max-width:1200px) .vh-ghost{display:none}` 输给后面**无条件**的 `.vh-ghost{display:flex}`。窄屏隐藏这类"条件态"规则，若对应属性在文件更靠后还有无条件声明，必须 `!important`，或把声明整体挪到更后面。
30. **布局重叠必须真浏览器量，不能看缩放截图**：新建 `测试报告/_ui_vhead.py`（复用 `_ui_shot.py` 的 CDP），量 `.viewhead` 内所有子元素 `getBoundingClientRect` 并做两两相交检测，直接输出「重叠总数」。★ **检测脚本本身有盲区**：`.seg#enfilt` 也是 `DIV`，被"是 DIV 就当标题块"的分支吞掉 → 富化台的关键重叠**一开始根本没被检测到**；分类要按"是否含 h2"而不是按 tagName。
31. **深链视图的数据时序**：`/?view=enrich` 时"切视图"发生在 stats 返回**之前** → 那一刻写 ghost 必空；凡"数据到达后刷新 UI"的回调，**必须刷新当前视图**，不能硬编码某个视图。
"""

with open(P, "a", encoding="utf-8", newline="\n") as f:
    f.write(ADD)
print("appended", len(ADD), "chars; total", os.path.getsize(P))
