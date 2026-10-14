# -*- coding: utf-8 -*-
"""把「v11 修正：幽灵字重叠」追加到 v11 落地对照文档。"""
P = r"C:\Users\丁\Desktop\aisec-D_2.0\测试报告\前端v11_落地对照.md"

ADD = """

---

## 附二 · v11 修正：页头「幽灵字」与右上控件重叠（用户反馈）

**反馈**：实时监测台、情报富化台两处的页头右上角文字相互重叠。

### 根因（3 条，均为"写了却不生效"）

| # | 根因 | 说明 |
|---|---|---|
| 1 | 幽灵字锚在**右上角**，与页头右侧既有控件同处一条横带 | 监测台右上是「刷新视图」按钮、富化台右上是「在野利用 / 含 POC / 严重·高危」分段器；搜索 / 问答视图右侧那条 `.tagline` 已被 `display:none` 收掉 —— 所以**只有这两个视图**出问题 |
| 2 | `.vh-ghost em{transform:translateY(6px)}` | 把英文视图名下压 6px，正好压进下方数字的描边里 |
| 3 | `.vh-ghost{display:flex}`（无条件、文件行 1948）吃掉 `@media(max-width:1200px)` 里的 `.vh-ghost{display:none}`（行 1294） | 级联只看"谁在文件里更靠后"，与断点宽度无关 → 1100px 窄屏幽灵字照常显示、数字顶进页头描述文字 |

### 顺带修掉的第 4 个缺陷（JS）

`fetchStats` 回调里硬编码 `updateGhost('search')` → 改为 `updateGhost()`（刷新**当前视图**）。
此前**深链打开富化台 / 问答台**时，stats 到达晚于视图切换，此后无人回头补 —— 右下角只剩一个孤零零的英文视图名、数字恒为空（实测该 `<b>` 元素宽高为 0）。

### 改法

| 项 | 内容 |
|---|---|
| 锚点 | `.vh-ghost` 由「右上」改「**右下**」：`top:auto;bottom:var(--sp-3);right:var(--sp-5)` —— 控件占右上、数字占右下，垂直分离 |
| 去重叠 | 删掉 `em` 的 `translateY(6px)`；`gap` 1px→2px |
| 净空 | `.viewhead{padding-bottom:var(--sp-5)}` 拉开上下两条带 |
| 窄屏 | `.vh-ghost{display:none!important}`，拿回被无条件声明吃掉的控制权 |
| 时序 | `updateGhost()` 改为刷新当前视图 |

### 验证（真浏览器量盒模型，不看缩放截图）

`测试报告/_ui_vhead.py`：4 个视图 × 3 个宽度（1600 / 1281 / 1100）量 `.viewhead` 内全部子元素的 `getBoundingClientRect` 并做两两相交检测 → **重叠总数 0**；1100px 下幽灵字已完全不出现。

其余：组装一致 ✅ ｜ `node --check` 全过 ｜ 对比度 9 / 0 / 0 ｜ 7 视图实时截图 0 控制台 error。
"""

with open(P, "a", encoding="utf-8", newline="\n") as f:
    f.write(ADD)
print("appended", len(ADD), "chars")
