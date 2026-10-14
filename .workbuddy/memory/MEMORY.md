# AI-SecIntel 2.0 · 长期笔记
> 细节见 `memory/YYYY-MM-DD.md`；此处只留跨会话致命判据。

## 交付/环境
- 交付前 `运行CI.bat`(9 步)+`tools/组装前端.py --check` 须"一致"；**改 `modules/*/web/*.js|css` 必跑组装**；改算法/模型必失效缓存。
- ★★ **CI 不能从 AI 会话执行**：项目路径 `aisec-D_2.0(1)` 的括号被 cmd 吞掉→bat 直接报"不是内部或外部命令"；只能用户双击，或原生复刻各步（venv python 逐测试 / node / 组装 --check / compileall / 检查对比度 / _test_portability / _fix_bat_encoding --check / _test_startup_block / 评测门禁）。
- ★★ **CI 既有假失败基线**（10-10 实证，非回归）：`_test_cmdb_perf`(语料实时新增 CVE→总命中漂移，link 不参与匹配)、`_test_cvss_primary`(语料分 vs NVD 实时 API)、`_test_daily_digest`(m1_monitor 台账 10-07 停产→days[0]≠today→通知计数恒 0→1； dispositions 熔断记录→m0_ops 有产出)、`_test_digest_directions_api`(测试服务器状态污染，停掉即过)、`_test_live_atom_content`(vLLM proto 预发布正文天然短)、`_test_ops_observability`(扫 测试报告/*.log 人工产物，rotate_once 无人调用)。**失败先对照基线再查代码**。
- ★★ modules/ 是 namespace pkg → `from modules.X import` 要求**项目根在 sys.path**（曾只插 core/ → 服务进程 `No module named 'modules'`、LLM Key 读不到）。排障 `AISEC_SWALLOW_LOG=1`。
- 报告导出依赖(openpyxl/markdown)缺=**报错非降级**；改依赖同步 requirements/bootstrap/Dockerfile/检查依赖。
- 常驻服务**用户双击** `启动服务.bat`；AI 会话内起的服务结束即回收→`_smoke_boot.py`。**启动路径禁网络调用**。
- 探针 `AISEC_EVAL_BASE`→`AISEC_MAIN_SERVER`→`127.0.0.1:8848`；打本机必 `import loopback; loopback.enable()`(core 入 sys.path)；中文 query 必 urlencode。
- ★★ 下载=`req.send(..., filename=)` 必传 filename（只设 ctype 会内联渲染）。

## ★ 数据口径
- ★★ **NVD CVSS**：数组顺序不保证 Primary 在前；Primary 可能只在老版 V2；多版本可同标 Primary。**唯一正确写法：按版本从新到旧扫，首个带 Primary 的即取**；无 Primary 不比对。
- ★★ 每个百分比写清分子分母；**判据与实现必须同源**。
- ★ `published` 与 `published_at` 同口径(本机时区)：`_norm_date(x)==_norm_datetime(x)[:10]`；实时流按 published、日报按 fetched_at。
- 先按源去重再累加；日期过真实日历；Atom `<content>` 须解析，**616 条源无正文**。改语料大小→`.idxcache` 失效→重建 775s。字段类型先 `_to_int()`；分页重复用**标题归一**。

## ★ QA / m0_ops / LLM
- QA `history` 须 `[{role,content}]`；角度词不进检索式；正则尾管道=空分支；`strong_terms` 非空≠命中。闸门 `VECTOR_FLOOR=.89`/`BM25_MIN=8.0`。
- m0_ops 闸门**必须多路**(kev/cvss≥9/CVE/紧急词)；缩写带**字母边界**(**不能 `\b`**，中文是 `\w`)；富化用 CVE 编号；**404≠无资产**。
- LLM：`handle_chat_get` 曾传 `llm_config=None`→GET 永远模板(已统一 `env_llm_config()`)；`AISEC_LLM_API_KEY=` **值为空**→`env_key:false` 是**正确行为**(看值长度)；改 Key 须重启。无 CVE 用 `cvss>=9` 兜底；`_ver_from_links` 别取 compare 链首个版本。
- 翻译：`strip_dangling()`→`no_repeat_ngram_size`→`is_degenerate()` 保原文；改完同步 `app.js` 的 `TR.TRV`＋`isBadDst()`。

## ★ 前端（设计系统 v11）
- ★★ **JS 断点常量必须与 CSS `@media` 逐字对齐**：`isNarrow()`(app.js) 与 `@media (max-width:1200px)`(styles.css) 曾一个 1280 一个 1200 → 1201~1280px 区间遮罩压住内联检查器(z:1)→整屏变暗（火狐窗口/缩放常落该区间，用户报"查看详情整个屏幕非常暗"）。检查器桌面态 z-index:100（palette 120/help 130/toast 200 仍更高）。改一处必须 grep 另一处。
- 三坑：引用不存在变量静默回落；**文字色当底色**(底用 `--accent-ink`)；≤11px 用 `--txt-3`。自检 `检查对比度.py`(**解析失败静默跳过整条规则**)。
- ★★ **改前端后必提醒 Ctrl+F5**；`styles.css?v=N` 递增(头号嫌疑是缓存)。★**同一消息内多个 Edit 打同一文件会静默丢改动**(并行/同批都中过)→**同文件多处改必须串行、改后 grep 验证落盘**；★**内联 `style="font-size:Xpx"` 是令牌盲区**，收尾须 grep 全 .js/.html。
- ★**背景动画层(WebGL/rAF)的降级判据禁用「累计窗口 fps」**：切视图的大块 innerHTML 重绘=主线程长任务，会把窗口 fps 拉穿阈值误判成渲染慢→永久停循环(必须刷新才恢复)。正解=逐帧 EMA+丢弃 >250ms 长帧+分级降级(全量→半粒子→隔帧)+**可逆回升**+暴露 `__fxStats` 探针，点检脚本 `测试报告/_fx_verify.py` 验证「切视图后 frames 仍在涨」。
- ★**`backdrop-filter` 与「每帧都在动的背景层」同屏=合成风暴**(浏览器每帧对所有毛玻璃区重采样模糊→全局掉帧)。毛玻璃只给瞬态小浮层(调色板/toast/建议层)，常驻大件(页头/搜索框)用近实色底。
- ★**浅色主题的粒子/发光体必须换压暗色板**(亮金亮玉在白底普通混合下隐形)，线框透明度按主题分两档(深 .07~.10 / 浅 .22~.30)。
- ★**换主色必同步 `--accent-ink`**(金底白字仅 ~2；深色 `#1a1305`、浅色 `#fff`)。★伪元素新态须显式重置继承(`.btn.loading::after` 曾继承 `.btn::after` 的 `opacity:0` 而隐身)。
- ★**模块样式实际引用 `/modules/<id>/web/*.css`(源目录)**；分类色在 `core/taxonomy.py`，改了要重启。
- 设计系统 v11：**黑曜石&香槟金**(`#0b0a08`/`#e3b04b`/青玉`#2fbf9e`)；降噪=**折叠>缩小>删除**；字号/间距各 8 档·断点 6 档**严格降序**。
- ★★ **同名属性靠后者胜(与宽度无关)**，且**无条件声明会整条吃掉媒体查询里的条件态**(v11 节 `.vh-ghost{display:flex}` 吃掉窄屏 `display:none`→1100px 照显并顶进描述文字；同类 `.viewhead{min-height:152px}` 被 `min-height:0` 吃掉)→收敛前 grep 全部位置；条件态被无条件声明压住时用 `!important`。
- ★**绝对定位装饰别与功能性控件抢同一个角**(幽灵字撞「刷新视图」/「在野利用分段器」→装饰改锚右下)；**重叠必真浏览器量**：`测试报告/_ui_vhead.py`(元素 rect 两两相交)。★该脚本曾**漏检** `.seg`(也是 DIV，被"是 DIV 就当标题块"的分支吞掉)→**分类按"是否含 h2"**。
- 深链视图的数据时序：stats 到达回调须 `updateGhost()`(**当前视图**)，硬编码某视图 → 富化台/问答台数字恒空。
- 截图/点检用系统 Python313；服务起不来→`_ui_snap.py` 静态快照(静态 404 属预期)、`_ui_load.py` 画廊。间距必须 `getBoundingClientRect`。
- v12 视觉层：`frontend/fx.js` + styles.css 第 25 节（纯加法）。Three.js 走**本地 vendor**（`frontend/vendor/three.min.js` r150，**禁 CDN**）；3D 降级链 RM→无 THREE/WebGL→fps<26 减半→<20 停帧；浅色主题粒子换 NormalBlending。★**滚动渐入只补 .kpi**（其余元素 v11 已有 cardIn，重复补会打架），且播完必须**回收 .fx-pre/.fx-in 类名**归还 hover 过渡。★补 `:active` 时 transition 要与原声明**逐条合并**再加 transform。★注入装饰元素前先查目标的伪元素与裸标签占用（.kpi 的 ::after/i/b/span 全被占了→用 div.fx-sheen）。

## ★ 可移植/指标/评测
- ★★ `tools/_选解释器.bat`：候选 env→.venv→py→python，**每候选真跑 `-c "print(1)"`**；**禁写死 `py -3.<数字>`**。★**py 侧禁写死 `.venv`**→`PYEXE=sys.executable`，`_test_portability.py` [2b]/[2c] 拦截；bat 统一 GBK 无 BOM。
- `_fix_bat_encoding.py` 判据**必须反向**(须"严格 UTF-8 可解码即转")。
- ★**LLM 无 Key 的降级刻意不拉低 `/api/health` 的 ok**；**宁可漏报不可误报**。
- `circuit.py` FAIL=3/COOLDOWN=300s；★**空结果≠源挂**→"持续空>180s"才升级。
- ★**测试失败归因必须做对照实验**。`secrets.env`(gitignore)；`工具/配置密钥.py` **就地更新**；SMTP 填**授权码**。
