# frontend/ —— 控制台前端（唯一前端根）· v4 骨架重写版

服务**只服务这一个目录**（`core/paths.py` 的 `WEB_DIR = <项目根>/frontend`）。
交付/交接时「前端」就是这一个文件夹，不必再满仓库找文件。

```
frontend/
├─ index.html                 控制台外壳骨架（图标栏 / 命令栏 / 四视图 / 检查器 / 命令面板）
├─ styles.css                 设计系统 v4（全部样式：令牌、四视图、动效、响应式）
├─ app.js                     外壳逻辑（视图切换 / 检索 / 详情 / 监测台 / 富化台 / 命令面板）
├─ DESIGN.md                  ★ 设计系统说明：令牌、借鉴来源、动效清单、布局硬约束、验证方法
└─ modules/<id>/panel.js|.css 模块面板（**自动生成**，见下）
```

> 上一版整套已备份在项目根的 `frontend_v3_backup/`（含当时的模块面板副本）。
> **回滚**：`rm -rf frontend && cp -r frontend_v3_backup frontend` 即可，服务/端口/启动方式都不用改。

## 改前端：两条路，别搞混

| 想改什么 | 改哪里 | 改完做什么 |
|---|---|---|
| **样式 / 布局 / 交互**（多数情况） | 直接改 `frontend/styles.css`、`frontend/app.js`、`frontend/index.html` | 刷新浏览器（静态资源带 ETag，改完立即生效；没生效就 Ctrl+F5） |
| **某个模块自己的面板 UI** | 改 `modules/<id>/web/panel.js|panel.css`（模块自治，整包替换不受影响） | 跑一次 `py -3 tools/组装前端.py` 同步进 `frontend/modules/` |
| **配色 / 主题** | `styles.css` 顶部 `:root` 与 `:root[data-theme="light"]` 两组变量 | 全站（含模块面板）一起变 |

`frontend/modules/*` **不要手改**：文件头写着「自动生成」，跑一次同步就会被模块源覆盖。

```bash
py -3 tools/组装前端.py            # 同步（幂等，没变化时输出「本次写入 0 个」）
py -3 tools/组装前端.py --check    # 只检查是否一致（合并前核查可挂这一步）
py -3 tools/组装前端.py --dry-run  # 只打印计划
```

## 这一版是什么结构（一句话）

**左侧图标导航栏（4 个平级视图）+ 顶部命令栏（⌘K 命令面板）+ 全宽工作区 + 右侧情报检查器**，
深浅两套主题，动效 16 处且全部只动 `transform/opacity`。视觉取向是
**石墨灰 + 单一信号色（钢蓝）+ 发丝描边 + 亮度堆叠**，刻意避开紫色渐变/极光光晕/点阵噪点
这类「AI 模板味」元素。完整设计说明与借鉴来源见 **[DESIGN.md](DESIGN.md)**。

四个视图与它们的数据来源：

| 视图 | 内容 | 谁提供数据 |
|---|---|---|
| 检索工作区 | 自然语言检索、意图解析、答复卡、结果列表、分面筛选 | 主体 `core` |
| 实时监测台 | KPI、最新情报流、快车道状态、分类分布、归档体量 | 主体渲染，数据来自模块 1 的 `/api/live` `/api/latest` `/api/sources` |
| 情报富化台 | 富化候选列表（在野利用 / 含 POC / 严重高危），点开即看富化详情 | 主体渲染，数据来自 `/api/search`；**富化结果本身在检查器里由模块 2 提供** |
| 情报问答 | RAG 多轮问答、引用来源 | **模块 3 自带面板**（外壳把它搬进 `#askdock`，不改模块源码） |

## 模块怎么接进来（契约一个字都没改）

模块仍然只通过 `AISEC.register({id, init, sideSections, sideMounted, detailSections, detailMounted})`
挂载；外壳提供的全局能力（`$ · esc · toast · S · TYPE_META · openDetail · doSearch · renderTop ·
renderSide · link`）与固定 id（`livewrap/livestat · refbtn/refstat · side · dh/db · mask · toast ·
q/expcbx/go/hints/qparse/sug`）全部保留，所以 **三个模块的 `web/` 源码一行都不用动**。

v4 新增的一层只是「**模块坞适配层**」（`styles.css` 第 18 节 + `app.js` 的 `adoptModulePanels()`）：

- 模块 1 的侧栏卡片照旧按 `anchor: top / after-corpus` 落在左筛选栏里；
- 模块 3 自己插在检索区之后的 `#qapanel`，被外壳**整体搬到「问答」视图**里（只搬 DOM 节点，
  模块内部的事件、类名、样式一律不动；`#askdock` 只给容器级的高度/宽度调整）；
- 模块 2 的详情区块照旧按 `anchor: before-trust / end` 落进检查器的对应位置。

面板类名一律带模块前缀（`lat-*` / `sv-*` / `qa-*`），引用主体变量时**照旧写兜底值**：

```css
border-color: var(--line-2, rgba(255,255,255,.10));   /* 面板单独打开也能看 */
```

## 键盘与命令

| 键 | 作用 |
|---|---|
| `⌘K` / `Ctrl+K` | 打开命令面板（跳视图 / 执行操作 / 直达 CVE） |
| `/` | 聚焦检索框 |
| `↑ ↓` 或 `k j` | 在结果列表里上下移动 |
| `↵` | 打开选中情报的检查器 |
| `Esc` | 收起命令面板 / 检查器 / 建议 |
| `[` `]` | 收起、展开左侧筛选栏 / 右侧检查器 |
| `t` | 切换明暗主题 |
| `⌘/Ctrl+M` | 切换浏览方式（速览 ⇄ 精读） |

## 性能：这一版新增了什么、砍掉了什么

- **新增**（所以体积涨了）：三个新视图（监测台 / 富化台 + 问答坞）、命令面板、快捷键帮助、
  详情区块重写、明暗双主题令牌。外壳 95.7KB → 166.0KB（gzip 29.3KB → 46.9KB）。
- **没有引入**：任何框架、字体、图表库。网络请求仍只有 `styles.css` / `app.js` / `modules/*`。
- **保留 v3 的性能纪律**：不引外部字体（演示常离线，外链样式表阻塞首屏）；不用大面积
  `filter:blur`；结果卡 `content-visibility:auto` + `contain-intrinsic-size`；检查器
  `contain:layout paint`；服务端 gzip + ETag/304。
- **只动 `transform/opacity`**：16 处动效全部合成层友好，并受
  `prefers-reduced-motion: reduce` 总开关约束。

## 色板（改色只改这里）

```css
/* 深色（默认）—— 画布 / 亮度堆叠 / 描边 / 文本四级 */
--bg:#0a0b0c  --bg-2:#0d0f11  --elev-1:#111316  --elev-2:#16191d
--surface-1/2/3/4: rgba(255,255,255,.024/.042/.064/.092)
--line / -2 / -3:  rgba(255,255,255,.072/.115/.185)
--txt / -2 / -3 / -4: #e9ecef #aeb5bf #767e8a #545b65
/* 唯一强调色：钢蓝（不是 AI 紫） */
--accent:#4d7cfe  --accent-2:#6b93ff  --accent-3:#93b1ff
--accent-soft:rgba(77,124,254,.13)  --accent-line:rgba(77,124,254,.36)
/* 语义色 / 严重度 */
--ok:#3fb950  --warn:#d29922  --danger:#f0555d
--crit:#f0555d  --high:#f0883e  --med:#d4a72c  --low:#3fb950
/* 数据可视化专用色（只在图表里出现） */
--viz-1…#viz-7
/* 浅色主题 = :root[data-theme="light"] 覆盖同一组变量 */
```

## 顶栏那两个小按钮（容易被当成装饰）

| 按钮 | 行为 | 本地预览能验证吗 |
|---|---|---|
| **速览 / 精读（浏览方式）** | **两套阅读排版，不是调字号**：<br>**速览**＝条目紧凑（结果卡 12px/16px 内距、摘要 12.5px 两行截断）、内容满宽 1560px；<br>**精读**＝标题 20px、摘要 17px 且**全文展开不截断**、行距 1.95~2.05、检索视图**正文栏限宽 900px 居中**，侧栏与详情区块同步放大。<br>选择写入 `localStorage.asi-zoom`，快捷键 `⌘/Ctrl+M`，深链 `?mode=read` / `?mode=skim`（旧的 `?zoom=1` 仍兼容） | ✅ 能。切换后单条结果高度 192px → 277px（**+44%**），标题 14 → 20px、摘要 12.5 → 17px，并弹一句「浏览方式：精读（大字距 · 摘要全文 · 正文栏限宽）」 |
| **译（AI 辅助翻译）** | 把英文情报（结果标题/摘要、检查器里的正文）译成中文，插在原文下方（`.trl` 块，带「AI译」角标），译文按文本哈希缓存进 `localStorage.asi-trc-v1`。<br>**走本机后端 `/api/qa/translate`**（Helsinki-NLP/opus-mt-en-zh，CPU 推理）：零 token、**正文不出本机**、离线可用 | ✅ **能，且是本地方案的强项**。<br>模型已就绪 → 直接译；<br>模型未下载 → 探测 `/api/qa/mt_status` 后弹「模型未就绪 —— 双击 `下载翻译模型.bat`（约 300MB，一次性，免费）」并自动弹回未选中态，不会铺一屏「AI 翻译中…」。已是中文/过短的条目由后端判定 `skipped` 原样返回 |

**为什么不用云 LLM 翻译**：本项目处理的是安全情报正文，把 CVE 描述、受害资产信息发到第三方云端不可接受；第二版以前曾挂
`@tencent-ai/workbuddy-cloud-sdk`（CDN 外链 + 前端硬编码 publishableKey），**这两处都已移除**——
既断网即废，也构成事实上的数据外发。现在整套翻译链路从页面到模型全在本机进程内闭环。

答辩若被问「翻译是不是摆设」：它是真接了本地机器翻译模型（术语对齐见后端 `qa/translator.py` 的安全词典），
失败原因分得清（`mt_not_ready` / `mt_downloading` / `timeout` / `http_404`，见 `TR_MSG()`）；
唯一门槛是模型要一次性下载约 300MB，下完永久离线可用。

## 改这版前端前，先看一眼这四条

1. **布局硬约束**：外壳是固定高度 + 三块独立滚动区，`.shell/.stage/.workspace/.view/.main`
   的 `minmax(0,1fr)` 与 `min-height:0` 一个都不能少 —— 漏掉就会整页横向溢出、
   检查器跑到屏幕外、各栏不再滚动（v4 开发时踩过，详见 `DESIGN.md` 第 6 节）。
2. **flex 列里的卡片要锁 `flex:0 0 auto`**：`.side` / `.main` / `#results` 都是 flex 列，
   而 `.card` 带 `overflow:hidden` → 它的自动最小尺寸会退化成 0 → 内容一超高就被压扁裁掉，
   侧栏的表现就是「下面的卡片看着是空的、还怎么都翻不动」。新增卡片或列表时别忘锁 flex；
   长清单用 `<details class="foldmore">` 只露头部几条，上百项的选择列表用 `.fbody.tall` 限高内滚
   （详见 `DESIGN.md` 第 6.1 节）。
3. **动效安全线**：新增动效只动 `transform/opacity`；**不要给统计数字加 MutationObserver 驱动的
   滚动特效**（v3 曾因它与 30s 自动刷新互相触发，把数字显示成中间值）。
4. **别漏按钮的绑定**：外壳重写时曾把 `#z1 / #z2`（字号）和 `#trtgl`（译）的 `onclick` 漏掉 ——
   按钮长得还像个按钮，但点了没反应，最容易被当成"假按钮"。改外壳后用
   `grep -n "onclick" ../frontend_v3_backup/app.js` 与新版逐个比对交互绑定，别只看视觉。
