# AI-SecIntel · aisec-D 2.3（主体 + 四模块 彻底分离版）
> 📌 **口径说明**（2026-09-27 统一）：文中的语料规模、向量索引条数、情报源数、自测项数均为**当日实测快照**；实时监测会持续入库，**实时值以 `GET /api/stats`、`GET /api/live` 为准**。历史版本对比中出现的旧数字（如 82,488）已单独标注为基线值。目录名 `aisec-D_2.0` 为历史沿袭（自测/核查脚本沿用），**当前交付版本号为 2.2**。权威数字以 `交付总览.md` 开头「数字口径统一表」为准。



> 智能体驱动的**全领域网络安全 + AI 安全**知识情报系统
> 检索 / 可信度 / 关系图谱 / 报告导出 / **情报问答** / **快车道实时监测（15s）** / **受影响资产定位** / **POC·EXP 搜索**

**这一版解决的问题**：以前三个人一人一个模块，但主体和模块混在一起，每次合并都要手工融合
`server.py`、`web/app.js`，一不留神就丢功能（"阉割"）。
现在**主体只管宿主与骨架，模块各自带后端接口 + 前端面板 + 数据 + 文档**，
合并 = **把模块文件夹拷进来**；要撤掉某个模块 = **禁用或删掉那个文件夹**，主体照跑。

> 📌 **第一次接触这个项目（人或 AI）先读 [`交付总览.md`](交付总览.md)**：30 秒看懂 + 3 步跑起来 + 交付物地图 + 实测成绩。

---

## 一、目录结构

```
aisec-D_2.0/
├─ core/                        ← 主体（引擎 / 宿主 / 骨架 / 核查脚本）
│   ├─ server.py                 HTTP 宿主 + 路由注册表 + 静态资源（含 /api/modules）
│   ├─ registry.py               模块发现与加载、路由分发、启动钩子
│   ├─ paths.py                  全项目唯一的路径解析（数据目录在这里定）
│   ├─ engine.py taxonomy.py atlas.py augment.py credibility.py
│   │  graph_data.py report_export.py papers.py paper_kb.py data_security_kb.py
│   │  fetch_corpus.py extra_sources.py evaluate.py     ← 被模块共用的算法/管道基座
│   ├─ self_test.py              端到端自测（78 项）
│   ├─ run.py                    便捷启动封装
│   ├─ docs/ API接口文档 · API测试报告 · 答辩话术
│   └─ 测试报告/
├─ frontend/                    ← ★ 前端唯一根（服务只服务这一个目录；改样式/布局只动这里）
│   ├─ index.html · styles.css · app.js       控制台外壳（图标栏 + 命令栏 + 四视图 + 检查器）
│   ├─ DESIGN.md                              ★ 设计系统：令牌 / 借鉴来源 / 动效清单 / 布局硬约束
│   ├─ modules/<id>/panel.js|css              ← 自动生成，跑 tools/组装前端.py 从模块 web/ 同步
│   └─ README.md                              结构 / 模块接入契约 / 改法（改前端先看这份）
├─ modules/                     ← 四个模块，各自独立、互不干扰
│   ├─ m0_ops/       智能编排（v2.2 事件驱动多智能体，v2.4 升级为五智能体含决策）
│   │   ├─ module.json · api.py  （GET /api/ops/status|events|briefs|trace|decisions、POST /api/ops/scan_now|decide_now）
│   │   ├─ backend/              orchestrator.py（感知/编排/富化执行/研判/决策五 Agent）+ test_orchestrator.py（离线 13 项）
│   │   └─ docs/编排说明.md      五 Agent 分工 / 状态文件 / 实弹演练复跑 / 已知边界
│   ├─ m1_monitor/   情报监测（成员A）
│   │   ├─ module.json           模块清单：id/名称/负责人/路由/前端文件/开关
│   │   ├─ api.py                对外接口注册（GET /api/live、/api/sources、GET|POST /api/refresh）
│   │   ├─ backend/              monitor.py live.py harvest_*.py merge_*.py build_data.py …
│   │   ├─ web/panel.js          侧栏「实时监测·最新情报」「多源归档」+ 顶栏「深度同步」
│   │   └─ docs/                 模块文档（自测脚本与实现放一起，见协作规范）
│   ├─ m2_enrich/    情报富化（成员B）
│   │   ├─ api.py                （GET /api/assets、GET|POST /api/poc、GET|POST /api/asset_scan、
│   │   │                         GET /api/asset_search(|/status)、/api/subscribe*、GET /api/remediation、
│   │   │                         GET /api/stix、GET /taxii2/**、GET|POST /api/vuln_env）
│   │   ├─ backend/              poc_scraper.py affected_assets.py asset_locator.py
│   │   │                        asset_scan.py（★ 资产风险体检：word/excel/txt 上传 → 抽资产 → 比对情报库）
│   │   │                        asset_search.py（★ 测绘实查：FOFA/Shodan/Quake/ZoomEye 暴露量+国家分布，无 Key 走演示模式）
│   │   │                        alert_subscribe.py（★ 预警订阅：增量匹配 → 前端通知栏 + Webhook 推送）
│   │   │                        remediation.py（★ 修复方案：LLM/模板双模式，升级路径+配置加固+缓解+验证）
│   │   │                        stix_export.py（★ STIX 2.1 / TAXII 2.1 导出：确定性 uuid5、三集合订阅）
│   │   │                        vuln_env.py（★ 复现环境生成器：compose+verify zip，不在本机跑 Docker）
│   │   ├─ web/panel.css + panel.js  「资产风险体检」「测绘实查」「预警订阅」「STIX 导出」区块（富化台视图）
│   │   │                        + 详情抽屉「受影响资产定位」「互联网资产测绘语法」「POC / EXP 搜索」「修复方案生成」「处置工具箱」
│   │   └─ docs/
│   └─ m3_qa/        情报问答（成员C）
│       ├─ api.py                （GET|POST /api/chat、GET /api/qa/status、GET|POST /api/qa/build_vector、GET /api/qa/vector_probe、GET /api/hybrid_search）
│       ├─ backend/qa/           retriever / multi_hop / generator / vector_store / local_embedder …
│       ├─ web/panel.js + panel.css   ★ 对话面板（本次新增，之前只有后端没入口）+ 语义索引状态条
│       └─ docs/
├─ data/                        ← 共享数据（语料 220MB + 索引缓存 220MB + 采集缓存 + vector_store/ 语义索引）
├─ tools/
│   ├─ verify_integrity.py       ★ 「防阉割」一致性核查（合并前跑）
│   ├─ 配置密钥.py               ★ 「设置密钥.bat」背后的交互脚本（写本机 secrets.env）
│   ├─ 评测检索.py               ★ ③ 检索/问答量化评测（40+10 题，可 --compare 出前后对比）
│   ├─ 评测强标记修复.py          ★ 强标记路由/算子增强的 A/B 实测（同路径只切开关，四组数字）
│   ├─ 自测智能体.py              ★ 智能体工具编排 + 强标记路由离线自测（26 项，不联网零 token）
│   ├─ 评测问答深度.py            ★ 问答生成侧五维量化（准确率/可回溯/保真/覆盖/结构，10 题）
│   ├─ 评测POC.py                ★ ② POC 排序优化前 vs 优化后（同一批结果，不循环自证）
│   ├─ 评测POC覆盖率.py          ★ ② POC 覆盖率对比（离线武器化源 vs 完整源，带 force 真实重跑）
│   ├─ 建向量库.py               ★ ① 全量语义索引建库入口（本地免费模型，断点续跑）
│   ├─ 组装前端.py               ★ 把各模块 web/ 面板同步进 frontend/modules/（--check 校验一致）
│   ├─ 评测富化准确率.py          ★ v2.2 富化五维准确率（对独立真值：NVD 缓存/KEV 全量/论文摘要）
│   ├─ 评测多跳推理.py            ★ v2.2 跨文档多跳推理 12 题 8 类（逐 CVE 回查判题）
│   ├─ 评测时效性.py              ★ v2.2 发布→入库→可检索端到端时效（节拍/直测/处置时效/--watch）
│   ├─ watchdog.py               ★ v2.2 看门狗：单实例锁 + 崩溃重启（退避）+ 挂起检测
│   ├─ 自测守护.py                ★ 看门狗离线自测（9 项，不联网）
│   ├─ _run_server_logged.py     ★ 带日志启动：加载 secrets.env 并把输出落盘 测试报告/运行日志_<端口>.log
│   │                              （双击 启动服务.bat 时日志在它自己的窗口里，不落盘）
│   └─ stress_search.py          重活检索压测（排障用）
├─ config.json                  端口 / 数据目录 / 模块开关 / 定时增量周期
├─ 启动服务.bat · 启动服务_守护.bat · 运行自测.bat · 合并前核查.bat · 设置密钥.bat
│                               ★ 守护.bat = watchdog 守护模式（崩溃自愈/单实例锁）；密钥/代理只写本机 secrets.env（.gitignore 已排除）
├─ 安装语义依赖.bat · 下载嵌入模型.bat    ★ ① 语义召回开箱即用（装 torch 依赖 + 补下嵌入模型）
├─ 交付总览.md                    ★★ 唯一入口：给人/给 AI 都能立刻看懂（先读这份）
├─ 技术方案与系统设计文档.md       ★ v2.2 正式设计文档：需求→架构→选型否决→智能体拓扑→可靠性→评测总表
├─ 架构设计图.md                  ★ 五张图：总体架构 / 采集流水线 / Agentic RAG 决策流 / 模块注册时序 / 多智能体事件驱动链路
├─ 结构说明与协作规范.md          ★ 模块契约、模块文件夹速查、**模块更新（交回来怎么合）**、未完成事项
├─ 版本核查报告.md                ★ 1.3 / 1.3.2 合并完整性审查结论
├─ 缺口补齐对照表.md              ★ 对着《模块完成度与缺口分析》逐条验收
├─ 加强说明.md                    ★ 2.1 加强版增量：4 个硬伤修复 + 8 处口径统一（冲 95 分的改动清单）
├─ 加强说明_v2.2.md               ★ 2.2 加强版增量：85 分扣项逐条处置（多智能体/自愈/三项新评测/深度问答层/文档收敛）
├─ 演示脚本_5分钟.md              ★ 逐分钟演示脚本 + 评委追问口径
└─ data/数据说明.md               ★ 哪些数据必需、哪些可删（含两个省钱大缓存）
```

> ⚠️ 四个 `.bat` 是 **GBK(cp936) + CRLF** 编码（这样在 Windows 控制台里中文不乱码，
> 命令行也能正确解析）。用编辑器改完务必存回「ANSI/GBK + CRLF」——存成 UTF-8 会导致
> 命令被截断、报一堆「不是内部或外部命令」。

---

## 二、跑起来

### 依赖（换机器先跑一次自检，30 秒）

```bat
py -3 tools\检查依赖.py            :: 打印：缺什么 / 缺了会降级成什么
py -3 tools\检查依赖.py --install  :: 只打印一键安装命令
pip install -r requirements.txt       :: 核心依赖（requests / urllib3）
```

> **零依赖也能跑主体**（检索 / 监测 / 图谱 / 导出 / 中文问答模板）。
> 缺 `requests` 时富化模块会自动降级到标准库实现 `core/httpcompat.py`（**不崩、可用**，
> 但连接复用与部分重试策略弱于 requests）；装了才是满血。分档说明见 `requirements.txt`，
> 修复背景见 `修复说明.md`。启动脚本已内置这一步自检。

> **① 语义召回（混合检索）开箱即用**：嵌入模型已随包附带在 `data/models/multilingual-e5-small/`，
> 只需一条命令装好运行时依赖即可启用 `GET /api/hybrid_search` 的「关键词 + 语义」融合：
> ```bat
> 安装语义依赖.bat            :: 装 torch(CPU) + transformers + sentencepiece（一次性，约 200 MB）
> :: 若模型文件被精简掉了，再双击「下载嵌入模型.bat」补下（约 450 MB，ModelScope 直连）
> ```
> 装好后零 token、不联网、数据不出本机；没装也**不影响任何其他功能**（自动降级纯关键词）。

```bat
启动服务.bat                 :: 默认 8848，读 config.json
启动服务.bat 8899            :: 换端口
启动服务.bat --no-live       :: 不起实时监测线程（自测/低内存时用）
启动服务.bat --no-modules    :: 只起主体，排障用
启动服务_守护.bat            :: v2.2 守护模式：watchdog 单实例锁 + 崩溃自愈 + 挂起重启
运行自测.bat 8899            :: 另开一个窗口，78 项端到端自测
合并前核查.bat               :: 与基线的功能/文件/函数/前端逐项比对
```

浏览器打开 `http://127.0.0.1:8899/`。启动日志会打印模块装载情况：

```
装载模块 ...
  · 智能编排(m0_ops)：5 个接口 · 负责人 组长
  · 情报监测(m1_monitor)：4 个接口 · 负责人 成员A
  · 情报富化(m2_enrich)：3 个接口 · 负责人 成员B
  · 情报问答(m3_qa)：14 个接口 · 负责人 成员C
  快车道实时监测：每 15s 轮询 · 46 个博客/公告源（直连；境外源抓不到就设 AISEC_PROXY） · 新信息约 15s 内可见
  定时增量同步：每 6.0 小时自动抓一轮新漏洞（config.json 的 auto_refresh_hours 可调，0=关闭）
控制台已启动： http://127.0.0.1:8899/
```

---

## 二·补、环境适配：任何机器都能跑起来

三条硬性保证，逐条都有代码落点（不写在文档里，写在能跑的东西里）：

### ① 2012 年以后的操作系统都能运行

| 平台 | 启动方式 | 最低版本 |
|------|----------|----------|
| Windows 7 SP1 / 8 / 10 / 11 | 双击 `启动服务.bat` | Python 3.7+ |
| macOS 10.9+ | 双击 `start.command`（或 `./start.sh`） | Python 3.7+ |
| Ubuntu 14.04+ / CentOS 7+ | `./start.sh` | Python 3.7+ |

- 版本下限卡在 **3.7**：41 个文件用了 `from __future__ import annotations`、
  `m2_enrich` 用了 `dataclasses`，这两样都是 3.7 才有的（见 `README_安装.md` 第六节）。
- 3.7 上缺的 3.8/3.9 API 由 **`core/compat.py`** 兜底：`cached_property`、
  `importlib.metadata`、`str.removeprefix/suffix`、Windows GBK 控制台 UTF-8 输出。
- 平台差异也收在同一处：端口排查命令（`netstat` / `lsof` / `ss`）、
  打开文件、符号链接、长路径、大小写敏感文件系统——**没有一处写死 Windows 命令**。

### ② 慢电脑也能跑（开机自动降档）

启动第一行就会打印本机画像与档位：

```
[env] 环境画像：Windows AMD64 / CPU 8 核 / 内存 31.6GB / 可用磁盘 22.2GB
      性能档位：high（高配）（自动判定）
      生效策略：超时 ×1.0 · 并发上限 8 · 预热查询 6 条 · 语义模型预热 开
```

判定与缩放规则全在 **`core/envprofile.py`** 一张表里：

| 项目 | low（CPU≤2核/内存<4GB） | high |
|------|------------------------|------|
| 网络超时 | ×2.0 | ×1.0 |
| 并发上限 | 2 | 8 |
| 语义模型预热（torch 470MB） | 关 | 开 |
| 快车道轮询 | 60s | 15s |
| 自动增量同步 | 关闭 | 5 分钟 |
| 图谱默认跳数 | 1 跳 | 2 跳 |

业务代码不写 `if 慢机器`，统一调 `T.timeout(20)` / `T.workers(8)`。
手工强制档位：`set AISEC_PERF_TIER=low` 或 `./start.sh --low`。
单看画像：`python core/envprofile.py`（`--json` 输出机器可读）。

### ③ 环境不合适就自动配置

双击 **`安装.bat`**（Windows）/ **`安装.command`**（macOS）/ `./安装.sh`（Linux），
或跑 `python bootstrap.py`，五步全自动：

1. 体检（版本 / OS / CPU / 内存 / 磁盘 → 档位）
2. 建项目内虚拟环境 `.venv`（不污染系统 Python）
3. 并发探测清华 / 阿里 / 腾讯 / 中科大 / 官方源，挑**最快可达**的
4. 按档装依赖（低配只装 `requests`+`urllib3`，高配才建议 torch）
5. 逐个 import 自检，写 `.aisec_env.json` 环境档案

首次双击 `启动服务.bat` 也会自动触发同一套流程，之后不再重复。

### ④ 做成安装包分发

```bat
python tools\build_installer.py              :: 打代码包（约 1 MB）
python tools\build_installer.py --with-data  :: 连语料一起打（1.8 GB+，很慢）
```

产出 `dist/AI-SecIntel_v2.0_安装包_YYYYMMDD.zip`。解压后顶层就是
`安装.bat` / `安装.command` / `安装.sh` 三个入口 + `README_安装.md`，
拿到的人双击即可完成全部配置。`.command` 与 `.sh` 在打包时已置 755 权限位
（zipfile 默认不给权限位，否则 macOS 双击会报无执行权限）。

> 语料（274MB + 索引缓存 286MB）默认**不打进包**，安装后联网抓取
> 或直接拷入 `data/` 即可——详见 `README_安装.md`。

---

### 环境变量（可选，**Key 一律不要写进代码**）

**最快的方式：双击「设置密钥.bat」** —— 它会逐项问你要不要填（大模型 Key / GitHub Token / 代理），
只写进本机的 `secrets.env`，`启动服务.bat` 下次自动读取：
- `secrets.env` 已被 `.gitignore` 排除，**不会进仓库**；
- 启动横幅只会报「已配置 / 未配置」，**不打印密钥本身**；
- 想换或想删，重跑一次「设置密钥.bat」或直接删掉 `secrets.env`（问答退回模板模式）。

手工设（等价的）环境变量：

| 变量 | 作用 |
|---|---|
| `AISEC_LLM_API_KEY` | 问答模块的大模型 Key（DeepSeek 等 OpenAI 兼容接口）。配了 → 页面不填也能出自然语言答案；兼容 `DEEPSEEK_API_KEY` |
| `AISEC_LLM_BASE_URL` / `AISEC_LLM_MODEL` | 接口地址（默认 `https://api.deepseek.com`）与模型（默认 `deepseek-chat`） |
| `AISEC_GITHUB_TOKEN` | POC 完整搜索的 GitHub 速率 10/分钟 → 30/分钟；兼容 `GITHUB_TOKEN` |
| `AISEC_PROXY` | 抓境外情报源用的代理；`启动服务.bat` 会自动探测本机 7890/7897（Clash）并设好 |

> 代理策略是**按站点**来的：国内源（xz.aliyun / 安全客 / 绿盟 / 四维创智 / Seebug / 先知…）直连，
> 境外源走代理；某个站走代理失败会自动再试一次直连。
> 实测（本机 Clash 7890）：直连时 43 个源里只有 4 个轮到且全失败；配代理后 **40~44/46 源成功**（境外源偶发超时，以 `/api/live` 为准），只剩 Project Zero。

**不想花 token 时**：问答接口支持显式降级 —— `POST /api/chat {"q": "...", "no_llm": true}` 或
`GET /api/chat?q=...&no_llm=1`，只返回检索证据模板；**自测脚本已默认走这条路**，跑一遍自测不消耗任何大模型额度。
前端状态行会写明是「大模型生成（deepseek-chat）」还是「检索证据模板」，调用失败时也会显示失败原因并自动降级。

---

## 三、合并只需要两步（这是本次改造的核心）

```bat
:: 1) 把某人的模块文件夹整体覆盖进来（只覆盖他自己那个目录）
xcopy /E /Y  D:\他的交付\m2_enrich  modules\m2_enrich\

:: 2) 合并前核查：与基线逐项比对，确认谁都没丢东西
合并前核查.bat
::    结论：通过，功能无缺失 ✅        ← 才允许合并
```

**再也不需要动 `core/server.py`、`frontend/app.js`**。
模块新增接口 → 在 `modules/<id>/api.py` 里 `ctx.route("GET", "/api/xxx", handler)`；
模块新增前端 → 在 `modules/<id>/web/panel.js` 里 `AISEC.register({...})`。
详见 `结构说明与协作规范.md`。

---

## 四、验证结果（本机实测）

| 检查 | 结果 |
|---|---|
| `core/self_test.py`（**78 项**：接口/检索/可信度/图谱/导出/问答/监测/归档/模块注册表/模块接口/测绘语法/源健康度/问答自检/向量库状态/建库进度/POC 分级/编排接口/深度问答规则/看门狗/评测工具与交付物） | **通过 78 / 失败 0** |
| 语料规模（与 1.2 报告一致） | 文档 **86,704** 条 · 词项 **499,557** · 论文 21 · 语义索引 **87,180** 条 |
| `tools/verify_integrity.py`（对比基线 1.3.2） | **失败 0 项**：16 条路由、44 个源码文件、全部函数、前端 47 个 JS 函数一个不少 |
| 重活检索压测（大结果查询 ×36） | 全部成功，单次 0.2~0.8s |
| 情报源实测 | 新增 26 个源**逐个探测**（HTTP 200 且确含 `<item>/<entry>`）后才写入源清单；配代理后单轮 **43/44 源成功**（直连时境外源全灭），实测 `+134 条` 新情报 |
| 启动脚本 | `启动服务.bat` 实测：读取 `secrets.env` → 打印代理/密钥配置自检 → 起服务 → `/api/qa/status` 的 `env_key=true`；哑值测过认证失败时问答照样给 5 条引用（不 500、不崩） |
| 受影响互联网资产测绘语法 | Ollama → `body="Ollama is running"`、Jenkins → `header="X-Jenkins"`、ES → `body="You Know, for Search"`、log4j → `app="Apache-Log4j"`（含 `vuln:"CVE-xxx"` 与版本收窄） |

---

## 五、注意事项（踩过的坑）

1. **一个端口只跑一个实例**（主体已内置预检）：Windows 的 `SO_REUSEADDR` 会让第二个进程"假启动成功"，
   请求却落到旧实例上，表现极诡异。现在启动时**会主动探测端口并拒绝启动**：
   ```
   !! 端口 8848 上已有服务在监听，本实例不再启动（避免两个实例叠在同一端口）。
      查看占用：netstat -ano | findstr :8848     停止：taskkill /F /PID <PID>
      换端口： py -3 core/server.py 8899        确实要强制： 加 --force
   ```
2. **内存**：约 8.7 万条语料常驻约 **2.3 GB**。本机 16 GB 内存在同时跑两个实例 / 多个大户进程时
   会触发解释器级崩溃（见 `版本核查报告.md` 第七节）。**建议同时只跑一个实例**，自测时加 `--no-live`。
3. **本地请求要走 no_proxy**：全局代理会劫持 `127.0.0.1` 的请求并返回 502。
   `启动服务.bat` / `运行自测.bat` 已自动设好 `NO_PROXY=127.0.0.1,localhost`。
4. **不要提交 `__pycache__` / `*.pyc`**：源码改了但字节码残留会出现"行号对不上"的诡异 500。
   启动脚本已设 `PYTHONDONTWRITEBYTECODE=1`，`.gitignore` 也已排除。
5. **数据目录只有一份**：`config.json` 的 `data_dir`（默认 `./data`，也可指到别处，如
   `D:/ai_sec_shared/data`）。队友换机器只需改这一行，不必再复制几百 MB。
6. **本地嵌入模型已随包附带**：`data/models/multilingual-e5-small/`（intfloat/multilingual-e5-small，约 470 MB，开源免费）。
   换位置就设 `AISEC_EMBED_MODEL_DIR`；若交付包未带模型，双击 `下载嵌入模型.bat` 从 ModelScope 直连补下。
   语义检索还要 `torch + transformers`（双击 `安装语义依赖.bat` 一键装）；没装/没模型时问答自动降级为纯关键词，不崩。

---

## 六、从「功能齐全」到「拿高分」：③ 评测 → ② 精度 → ① 语义召回

功能对齐《模块完成度与缺口分析》之后，真正决定分数的三件事是**可量化的效果、精度、演示材料**。
这一节就是这三块的交付与复现命令（全部零成本；① 也不再需要任何付费 Key）。

### ③ 评测尺子 + 演示脚本（先有尺子，后面的提升才能报出数字）

| 交付物 | 用途 |
|---|---|
| `tools/评测检索.py` | 40 道检索题（AI 组件定向 / 约束式 / 中文源 / 语义改写 / 在野利用）+ 10 道问答题，输出命中率@1/3/5/10、MRR、P50/P95；`--compare` 直接比出「改动前 vs 改动后」 |
| `测试报告/检索评测.md` | 人看的报告（含未命中题诊断 + 改进优先级） |
| `测试报告/检索评测_v1_baseline.json` | 基线快照（① 做完后用同一套题对比） |
| `演示脚本_5分钟.md` | 逐分钟演示脚本 + 评委追问应答口径 + 演示前检查清单 |

**实测（40 题，两条路径同题对比）**：纯关键词 命中率 @1 **80.0%** / @3 85.0% / @5 87.5% / @10 90.0%，MRR **0.834**；
**混合检索（+语义召回）@1 82.5% / @3 87.5% / @5 90.0% / @10 90.0%，MRR 0.856**（语义改写类 @10 +12.5，约束式查询 100% 不掉；**「在野利用」类 @10 −16.7，已知弱项**）；
时延 纯关键词 P50 923 ms，混合 P50 1013 ms（约束式 6~128 ms）；问答首条引用相关性 **9/10**（`no_llm` 模板模式，零 token）。
分类最弱的是「语义改写」（@1 62.5%）与「在野利用」（@1 33.3%），正是 ①② 要补的方向。

```bash
py -3 tools/评测检索.py                       # 跑一遍，刷新报告
py -3 tools/评测检索.py --compare 测试报告/检索评测_v1_baseline.json   # 与基线比
```

### ② POC / EXP 抓取精度（把「官方仓库、无关项目」压下去）

- 模块侧：`poc_scraper._match_tier()` 给每条结果打 **A/B/C/D** 匹配等级
  （A=仓库名或抓到的代码含该 CVE 号，或来自 Metasploit/Nuclei/Exploit-DB/PacketStorm；
  B=描述提 CVE、或仓库名带产品名+漏洞词、或 PoC 合集仓库；C=只是提及该组件；D=官方组件仓库/噪声），
  `_score_results()` 以等级为第一关键字重排；前端按等级分组、C/D 折叠；
  `POST /api/poc` 的返回里多了 `tiers` 与 `precise` 两个字段。
- 评测侧：`tools/评测POC.py` 对每个 CVE 跑真实完整搜索，用**脚本自己的独立判据**打真值标签
  （不读模块的 `match_tier`，避免自证），再算「上一版排序规则」与「本版分级重排」的 precision@3/5/10。
- 报告：`测试报告/POC精度评测.md`（含每题的 Top-5 顺序对照，能直接看到噪声被压到了哪里）。

```bash
py -3 tools/评测POC.py                        # 默认 6 个 CVE（约 15~25 分钟，含 GitHub 实抓）
py -3 tools/评测POC.py --quick                # 只走离线武器化源（秒级冒烟）
```

> GitHub Token 走环境变量 `AISEC_GITHUB_TOKEN`（`secrets.env` 里配一次即可）：
> 代码抓取额度从 60 次/时提到 5000 次/时，完整搜索从「经常超时」变成 3~4 分钟出结果。

### ① 全量语义召回（**走本地免费方案，不花钱、数据不出本机**）

- 模型：`intfloat/multilingual-e5-small`（118M 参数、384 维、多语，中英混语料都吃得下），
  纯 CPU 编码，实测 **约 20 条/秒**（与建库任务并发时），全量 86,704 条约 **60~70 分钟**；**增量补建会跳过已编码**（实测补 3,698 条约 2 分钟）；
  断点续跑，中途关掉再跑不会重算。
- 代码：`modules/m3_qa/backend/qa/local_embedder.py`（编码器，自动加 e5 的 `query:`/`passage:` 前缀）
  + `qa/vector_store.py`（把原来只有 TODO 的建库/检索接口真正实现，落 `data/vector_store/`：
  一个 `embeddings.npy` 矩阵 + 一个 `meta.jsonl`，比 Chroma 更抗「强杀后索引损坏」，检索 30~60 ms）。
- 入口：`POST /api/qa/build_vector`（GET 查进度，返回 processed/rate/ETA/count），
  命令行等价工具 `tools/建向量库.py`，问答面板里也有状态条与「建索引」按钮。
- 未建库时**自动降级为纯关键词检索**，功能不受影响；建完后 `retriever.py` 自动做「关键词 + 语义」融合。

```bash
py -3 tools/建向量库.py --status         # 看当前向量库条数/模型
py -3 tools/建向量库.py --limit 2000     # 先小样验证（约 2 分钟）
py -3 tools/建向量库.py                  # 全量建库（可中断重跑）
py -3 tools/评测检索.py --tag v2_vector --compare 测试报告/检索评测_v1_baseline.json   # 建库后复测对比
```

**免费 vs 付费 embedding 的结论（本项目口径）**：
① 中文为主的语料上，本地多语模型（e5 / bge 系）在**中文检索**上通常不输 `text-embedding-3-small`，
差的是极端长文本与少数跨语言边角；② 付费方案还有个硬门槛——**DeepSeek 不提供 embeddings 接口**，
要另配一把 Key、按 token 计费、受速率限制；③ 本地方案**零费用、离线可跑、数据不出本机**
（对安全情报产品本身就是卖点），而且效果差异用 `tools/评测检索.py --compare` 就能量出来。
故本项目**默认本地免费方案**，若某天评测显示语义召回仍不够，再按同一套题去比付费 API 的增益即可。
