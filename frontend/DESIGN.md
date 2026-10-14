# frontend/DESIGN.md —— 控制台设计系统 v4（骨架重写版）

> 这份文档回答三个问题：**这一版长什么样、为什么这么长、以及怎么在不动逻辑的前提下改它。**
> 想改样式先读这里，再动 `index.html` / `styles.css` / `app.js`。

---

## 1. 一句话定位

**石墨灰画布 + 单一信号色（钢蓝）+ 发丝描边 + 亮度堆叠层次**，外面套一层「桌面软件」式的
固定外壳：左侧图标导航栏 → 顶部命令栏 → 三视图工作区 → 右侧情报检查器。

和上一版（v3）最大的区别不是配色，而是**信息架构换了**：

| | v3 | v4（本版） |
|---|---|---|
| 骨架 | 顶栏 + 左筛选栏 + 中结果 + 右抽屉 | 图标栏 + 命令栏 + **四视图** + **就地检查器** |
| 详情 | 整屏浮层抽屉（盖住一切） | 右侧检查器（>1200px 内联，≤1200px 退化为浮层） |
| 导航 | 无（只有检索一条主线） | 检索 / 监测 / 富化 / 问答 四个平级视图 |
| 命令 | 无 | **⌘K 命令面板**（跳视图 / 执行操作 / 直达情报） |
| 键盘 | `/` 聚焦搜索框 | `/` `⌘K` `j/k` `↵` `Esc` `[` `]` `t` |
| 强调色 | 靛紫 `#5e6ad2 / #7170ff` | 钢蓝 `#4d7cfe`（去掉紫色 = 去掉"AI 模板味"） |
| 主题 | 仅深色 | 深色 / 浅色 / 跟随系统（View Transitions 交叉淡入） |
| 密度 | 单一卡片列表 | 舒适 / 紧凑两种密度（紧凑一屏看两倍条目） |

```
┌────┬──────────────────────────────────────────────────────────────────────┐
│    │  命令栏：品牌 · 视图名 · ⌘K 触发器 · 实时监测 · 深度同步 · 统计 · 译 · 字号   │
│ 图 ├───────────┬──────────────────────────────────────┬───────────────────┤
│ 标 │ 筛选与语境 │  检索工作区 / 监测台 / 富化台 / 问答   │  情报检查器        │
│ 栏 │ 语料构成   │  （视图之间交叉淡入切换）              │  关键指标 · 资产    │
│    │ 模块卡片   │                                      │  可信度 · 图谱      │
└────┴───────────┴──────────────────────────────────────┴───────────────────┘
                  312px              自适应                 452px（可收起）
```

---

## 2. 设计令牌（改色只改这里）

全部颜色/圆角/缓动都来自 `styles.css` 顶部的 `:root`，浅色主题只是 `:root[data-theme="light"]`
覆盖同一组变量。**模块面板引用的变量名是公共 API（`--accent` `--line-2` `--txt-3` …），不要改名**，
否则三个模块的面板会失色。

```css
/* 画布与亮度堆叠（深色界面里投影几乎看不见，堆亮度才是有效层次）
   v8「黑曜石 & 香槟金」：底色刻意不用蓝 —— 蓝紫渐变是最典型的"AI 生成感" */
--bg:#0b0a08  --bg-2:#16130f  --elev-1:#1d1913  --elev-2:#282218
--surface-1:rgba(255,236,198,.072)  --surface-2:.118  --surface-3:.168  --surface-4:.228
/* 发丝描边（暖金灰） */
--line:rgba(255,231,186,.145)  --line-2:.245  --line-3:.40
/* 文本四级（暖白，与金色同族） */
--txt:#f6f2e7  --txt-2:#c9c3b4  --txt-3:#9a927e  --txt-4:#877f6d
/* 主强调色：香槟金 —— 交互、焦点、选中、KPI 大数。
   注意 --accent-ink 是深墨色：#fff 叠在金色上对比度只有 ~2，不可读，金底必须配深字 */
--accent:#e3b04b  --accent-2:#f0cd7a  --accent-3:#f6e3ae  --accent-ink:#1a1305
/* 次强调色：青玉 —— 只用于"实时 / 在线 / 活数据"（金玉并置，唯一的冷色锚点） */
--cyan:#2fbf9e  --cyan-2:#5edcbb
/* 语义色（严重度）：暖色系，靠色相/饱和度与主色金区分 */
--crit:#ff5a52  --high:#ff8a3d  --med:#f2c94c  --low:#4acc8a
/* 数据可视化专用色（只在图表里出现，界面不使用）—— 整组暖金主导 */
--viz-1:#e3b04b  --viz-2:#2fbf9e  --viz-3:#e8913c  --viz-4:#f2c94c  --viz-5:#b8603c  --viz-6:#ff5a52  --viz-7:#b9a284
/* 缓动：出场快起慢收 / 位移丝滑收尾 / 弹性回弹（按压与弹出） */
--ease:cubic-bezier(.32,.72,0,1)  --ease-out:cubic-bezier(.16,1,.3,1)  --spring:cubic-bezier(.34,1.56,.64,1)
```

**分类色（11 类，`core/taxonomy.py`）**：同样是界面配色的一部分 —— 它们在检索结果卡、
分布条、方向卡上以"色点 + 色条"出现。v8 一并从蓝紫青换成暖金调色板
（金 / 玉 / 橙 / 亮黄 / 橙红 / 古铜 / 陶土 / 浅玉 / 暖卡其 / 红 / 橄榄），
兜底值见 `core/daily_digest.py:_DIR_COLOR_FALLBACK`。

**为什么只有一个彩色**：v3 之前的教训是「每个功能一个颜色」（青、紫、薄荷、琥珀、粉…），
那是默认模板的观感来源。现在只有强调色是彩色，其余靠灰阶 + 严重度语义色（红/橙/黄/绿）表达状态。

---

## 3. 借鉴来源（都来自公开的 GitHub 项目/设计系统）

| 借了什么 | 出处 | 落在本项目的哪里 |
|---|---|---|
| 「窄图标栏 + 内容区」应用外壳、全局搜索命令 | [satnaing/shadcn-admin](https://github.com/satnaing/shadcn-admin)、[shadcn/ui](https://github.com/shadcn-ui/ui) | `.rail` / `.shell` / `.cmdbar` |
| ⌘K 命令面板（分组列表、键盘导航、行内高亮）与它的弹性入场曲线 | [beUI command-palette](https://beui.dev/components/blocks/command-palette) | `#palettewrap` / `PAL`（`stiffness 560 / damping 40` 换成等价 CSS 曲线） |
| 指示器在选项之间**滑移**（layout animation，而不是重画一个高亮） | Radix/Base UI Tabs 的 `layoutId` 思路、[Kinetik 的 Fluid Tabs](https://www.kinetik.ink/) | `.rail-pill`（FLIP）、`.seg-thumb`（`offsetLeft`+`offsetWidth`） |
| 卡片阶梯入场、指针跟随柔光、按压回弹 | [Kinetik / Kinetics](https://kinetics.colorion.co/) 的 motion primitives | `.res` 的 `--i` 延迟、`--mx/--my` spotlight、`:active{scale}` |
| 严重度语义色取值（红/橙/黄/绿四档）与等宽数字排版 | [GitHub Primer](https://primer.style/foundations/primitives/color) | `.badge.CRITICAL…LOW`、`.cve`、所有数字格子 |
| 近黑画布 + 亮度分层 + 发丝描边的层次法 | [Linear](https://linear.app)（其公开的设计讨论） | 全站 `--surface-*` / `--line-*` 用法 |
| 中性灰阶与 `tabular-nums` 的数据排版 | [Vercel Geist](https://github.com/vercel/geist-font) | `--mono` + `font-variant-numeric` |
| 图谱「连线描出来、节点弹进来」的入场 | 通用 SVG 描线技法（`pathLength=1` + `stroke-dashoffset`） | `graphSVG()` 的 `.gedge` / `.gnode` / `.gping` |

**刻意不借的**：紫→青渐变大标题、极光模糊光晕、点阵噪点、玻璃拟态卡片、圆角 24px 的大色块。
这些是「一眼 AI 生成」的高频特征。

---

## 4. 动效清单（16 处，全部只动 `transform` / `opacity`）

| # | 动效 | 实现 | 为什么这样实现 |
|---|---|---|---|
| 1 | 图标栏指示块滑移 | JS 读 `getBoundingClientRect()` 写 `translateY`（FLIP） | 真实位移，比重画一个高亮"顺" |
| 2 | 视图切换交叉淡入 + 主区前几块阶梯上浮 | `.view` 状态机 + `.main>*` 的 `nth-child` 延迟 | 只动 `opacity/transform`，切视图不掉帧 |
| 3 | 结果卡阶梯入场 | `--i` 内联变量 → `animation-delay` | 上限 14 级，长列表不会"永远在动" |
| 4 | 卡片指针跟随柔光 | `pointermove` 写 `--mx/--my`，rAF 节流 | 径向渐变随指针移动，不触发重排 |
| 5 | 悬停抬升 + 描边变亮 | `translateY(-2px)` + 变量 | 深色下投影无效，靠描边+亮度表达 |
| 6 | 检查器滑入 + 区块阶梯 | 网格轨道宽度过渡 + `.sec` 延迟 | 主区"让位"而不是被盖住 |
| 7 | 命令面板弹性入场 | `scale(.975)→1` + 遮罩淡入 | 频繁打开的浮层必须"瞬间但顺" |
| 8 | 面板行内高亮 | 绝对定位高亮块 + `palOn` | 键盘上下移动时视线跟得住 |
| 9 | 分段控件指示块滑移 | `offsetLeft/offsetWidth` → `translateX/width` | 排序/密度/富化筛选三处共用 |
| 10 | 统计数字滚动 | rAF 补间（`easeOutExpo`，`dataset.v` 记住上次值） | **不用 MutationObserver**：v3 曾因它和 30s 刷新互相触发把数字显示成中间值 |
| 11 | 条形图生长 | 先 `data-w` 0 宽渲染，下一帧写目标宽度 | 让 CSS 的 `width` 过渡真正播出来 |
| 12 | 关系图谱描线 + 节点弹入 + 雷达环 | `pathLength=1` + `stroke-dashoffset`、`transform-box:fill-box` | 让"关系"这件事被看见 |
| 13 | 明暗主题交叉淡入 | `document.startViewTransition`（不支持则直接切） | 原生、零依赖，退化无副作用 |
| 14 | 结果栏吸顶 | `position:sticky` + 滚动阈值加 `.stuck` 描边 | 主区独立滚动，滚动条只出现在该出现的地方 |
| 15 | 复制回执 | 点 CVE 号 → `✓` 闪一下 | 比弹 toast 更轻，不打断阅读 |
| 16 | 实时点呼吸 + 同步按钮旋转 | `livering` / `spin` | 状态可感知 |

全部动效受 **`@media (prefers-reduced-motion: reduce)` 总开关**约束（最后一段 CSS 一次性压掉）。

---

## 5. 性能与取舍（实测数字）

| 指标 | v3 | v4 |
|---|---|---|
| 外壳原始体积 | 95,697 B | 166,002 B |
| 外壳 gzip 体积 | 29,285 B | 46,870 B |
| 首屏阻塞的外部资源 | 0 | 0 |
| 大面积 `filter:blur` | 0 | 0 |
| 常驻动画元素 | 2 | 3（呼吸点、雷达环、同步旋转） |

体积增长来自**新增的能力**：两个新视图（监测台 / 富化台）+ 命令面板 + 快捷键帮助 + 详情区块重写。
没有引入任何框架、字体、图表库；所有网络请求仍只有 `styles.css` / `app.js` / `modules/*` 三类静态资源。

其他规则：
- 结果卡 `content-visibility:auto` + `contain-intrinsic-size`，屏外不渲染；
- 检查器 `contain:layout paint`；
- 不引外部字体（本机演示常离线，外链样式表会阻塞首屏）；柔和感交给**静态** `radial-gradient`；
- 服务端 gzip + ETag/304（改完刷新即生效，没生效 Ctrl+F5）。

---

## 6. 布局的硬约束（踩过的坑，改前必读）

外壳是「桌面软件」式固定高度，三块区域各自独立滚动。**任何一层漏掉 `minmax(0,1fr)` 都会炸**：

```
.app     grid-template-columns: 58px minmax(0,1fr)     ← 图标栏 | 其余
.shell   grid-template-columns: minmax(0,1fr)          ← 必须显式声明列！
         grid-template-rows:    auto minmax(0,1fr)
.stage   grid-template-columns: minmax(0,1fr) 检查器宽度
         grid-template-rows:    minmax(0,1fr)
.workspace / .view / .main / .sidepanel 都要 min-height:0
```

> 为什么 `.shell` 必须显式写列：网格的**隐式列是 `auto`**，会被命令栏里 `white-space:nowrap`
> 的那串统计数字撑到 2000px+（实测 2037px），于是整页横向溢出、右栏检查器跑到屏幕外、
> 各栏也不再滚动。`minmax(0,1fr)` 把轨道钉死在可用宽度上。

≤980px 时整套约束交还给文档流：`body` 恢复滚动、`.app/.shell/.stage/.workspace` 改 `display:block`、
`.view` 变竖向 flex 且 `.main` 排在 `.sidepanel` 之前（窄屏先给检索与结果）。

### 6.1 flex 列里的卡片必须锁死 `flex:0 0 auto`（第二个坑）

`.side` 与 `.main` 都是 `display:flex;flex-direction:column` 的滚动容器。flex 子项的
**自动最小尺寸**在子项自身 `overflow` 不是 `visible` 时会退化成 **0** —— 而 `.card` 正是
`overflow:hidden`。结果：侧栏内容一超过一屏，所有卡片会被等比例**压扁并裁掉**，
表现为「多源归档 / 高发组件 TOP 这些卡片看着是空的、而且侧栏怎么都翻不动」
（因为内容被压缩后恰好等于容器高，`scrollHeight == clientHeight`，容器压根不需要滚动）。

实测（修复前 → 修复后，同一份数据）：

| 卡片 | 内容真实高 | 修复前卡片高 | 修复后 |
|---|---|---|---|
| 实时监测 · 最新情报 | 299px | **46px**（只剩标题） | 338px |
| 语料构成 | 4268px（120 个来源全列） | **566px** | 441px（前 8 + 展开） |
| 多源归档 | 134px | **24px**（只剩标题） | 173px |
| 高发组件 TOP | 288px | **55px** | 324px |
| `.side` 可滚动距离 | — | **0** | 1437px |

规则：**任何 `flex-direction:column` 的滚动容器，都要给子项显式 `flex:0 0 auto`**
（`.side>*` / `.main>*` / `#results>*` / `.res` / `.fchk` 都已加）；同时长清单不要一次全渲染，
用 `<details class="foldmore">` 只露头部几条（语料构成 8 条、高发组件 6 条），
上百项的选择列表用 `.fbody.tall`（限高 + 内部滚动）。

---

## 7. 改样式/改主题的三种改法

1. **只换配色**：改 `:root` 与 `:root[data-theme="light"]` 里的变量，全站（含三个模块面板）一起变。
2. **改某个视图的排版**：`styles.css` 里按节找（每节都有 `/* ==== n. 标题 ==== */`），
   `app.js` 里对应 `renderXxx()`。视图 HTML 骨架在 `index.html`，四段各有注释。
3. **加一个视图**：在 `index.html` 的 `#railnav` 加一个 `.rail-item[data-view=xxx]`，
   在 `.workspace` 里加 `<section class="view" data-view="xxx">`，
   在 `app.js` 的 `switchView()` 里挂载渲染函数即可（`PAL_VIEWS` 顺手加一行，命令面板就有了）。

---

## 8. 怎么验证（不用靠肉眼）

本机没有前端构建，验证靠「无头 Edge + CDP」：

```bash
# 1) 起服务
py -3 core/server.py 8848

# 2) 无头 Edge 截图（注意要 --virtual-time-budget 等 JS 跑完）
msedge.exe --headless=new --disable-gpu --hide-scrollbars \
  --user-data-dir=<scratch>/prof --virtual-time-budget=9000 \
  --window-size=1600,1000 --screenshot=shots/wide.png http://127.0.0.1:8848/

# 3) 需要交互/看控制台报错时，用 CDP 驱动（websocket-client 已装）：
#    打开 --remote-debugging-port=9222 --remote-allow-origins=*，
#    Runtime.evaluate 执行 openPalette()/switchView('monitor')/openDetail(id)，
#    Page.captureScreenshot 存图，Runtime.exceptionThrown / Log.entryAdded 收报错。
```

必查项：**控制台零 error**、`.stage` 宽度等于窗口宽减 58、四个视图都能出内容、
检查器里有模块 2 的 `#assetsPanel` / `#pocPanel`、`#askdock` 里接住了模块 3 的 `#qapanel`。
