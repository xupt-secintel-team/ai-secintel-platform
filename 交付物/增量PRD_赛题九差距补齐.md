# 增量 PRD · 赛题九差距补齐

> **文档类型**：增量 PRD（**只描述本次变更**，不重写既有 PRD / 不重述系统全貌）
> **作者**：许清楚（产品经理）
> **日期**：2026-10-13
> **项目**：AI-SecIntel（微内核 `core/` + 四模块 `m0_ops` / `m1_monitor` / `m2_enrich` / `m3_qa`）
> **基线版本**：2.2 / 2.3
> **上游输入**：`_gap_analysis_20261013.md`（8 条差距 G1~G8，全部带实测证据）、`E:/_qax_topic9.txt`（赛题九原文）、`交付总览.md`、`core/docs/API接口文档.md`
> **写作语言**：简体中文。需求动词口径：**必须**（P0）/ **应该**（P1）/ **可以**（P2）。

---

## 一、一句话定位

> **本次增量交付的是「把 AI-SecIntel 从'能盯、能加料、能回答'升级为'合规可依、优先级可裁决、沉默失败可见'的赛题九达标版本」——补 5 项 P0 能力（标准/法规知识底座、EPSS 富化、源健康缺失告警、MCP/Agentic 独立风险类、赛题四类风险聚合），并附带 2 项 P1 与 3 项 P2。**

本次**不新增模块、不改变微内核 + 四模块架构、不引入必装第三方依赖**；全部改动落在既有 `core/` 与 `modules/*` 内，沿用既有 `ctx.route()` 路由约定、`paths.py` 路径解析与 `module.json` 契约。

---

## 二、产品目标（对齐赛题评分表）

三个目标**互相正交**：分别补「知识面（广度）」「决策深度（准确度）」「工程韧性（稳定性）」——不重叠、不互相顶替。

| 目标 | 目标陈述 | 撬动的赛题评分大项（档位） | 主要覆盖差距 |
|---|---|---|---|
| **目标 A · 知识底座与风险分类骨架** | 把"AI 安全知识底座"从**静态 4 条法规**扩为**可检索、可增量、带版本与生效日期的标准/法规体系**，并把赛题四类 AI 风险（含 MCP/Agentic）做成**显式映射与可聚合口径** | 功能①情报监测完整性 **15 分档**（多源覆盖 ≥7 类且含实时监测）<br>功能③情报问答完整性 **15 分档**（知识覆盖范围 + 跨文档推理）<br>文档质量 **15 分** | G1、G4、G5 |
| **目标 B · 富化与推理深度** | 把富化从"信号齐（CVSS+KEV）"升级为"**优先级可裁决**"（CVSS/EPSS/KEV/可达性四元组），并把散落的 CWE→ATLAS→战术数据升级为**可回答"这个漏洞的攻击链是什么"**的推理接口 | 功能②情报富化完整性 **15 分档**（富化准确且含自动关联推理）<br>性能②富化准确率 **5 分档**（≥95% 优秀）<br>性能③问答深度 **5 分档**（多跳推理 ≥85% 优秀）<br>功能③ **15 分档**（跨文档推理与深度分析） | G2、G6 |
| **目标 C · 工程韧性与可问责** | 把"**缺数据不会报警**"这一产业级盲点补掉：源健康度可查、停产源必告警、进程掉线可自愈；并让处置动作**可归人、可留痕** | 优化②系统自动化程度 **10 分档**（全流程自动化 + 自愈能力）<br>性能①监测时效性 **5 分档**（停产源会静默拉低时效）<br>优化①智能体架构设计 **15 分档**（自主决策可解释/可追溯）<br>决赛"容器化部署 + 日志监控"**10 分档** | G3、G8、G7 |

> **一句话对照**：目标 A 解决"评委问'标准法规在哪'"；目标 B 解决"评委问'AI 漏洞你凭什么定优先级'"；目标 C 解决"评委问'你的源停了你知道吗'"。

---

## 三、用户故事

编号对应差距编号（G1~G8），供架构师做需求追溯。

| # | 用户故事 | 对应差距 |
|---|---|---|
| US-1 | **作为**安全合规负责人，**我希望**系统能直接检索到 NIST AI RMF / ISO/IEC 42001 / EU AI Act / TC260 / 《生成式人工智能服务管理暂行办法》等**结构化标准与法规条目**（带版本、生效日期、适用主体），**以便**我在出漏洞简报时能一并给出合规依据，而不是自己去翻文件。 | G1 |
| US-2 | **作为**漏洞运营分析师，**我希望**每条漏洞详情里能看到 **EPSS 利用概率**并与 CVSS、KEV、可达性并列成"优先级四元组"，**以便**我在 AI/agentic 漏洞上不被失真的 CVSS 单信号误导（CVSS↔EPSS 相关仅 0.17）。 | G2 |
| US-3 | **作为**值班运维，**我希望**系统能告诉我"**哪个情报源已经停产 / 多久没出数据 / 缺了多少条**"，并在超期时主动告警，**以便**我不必等日报生成失败才知道源已经死了。 | G3 |
| US-4 | **作为**AI 安全研究员，**我希望** MCP Server / Agentic AI 风险是**独立风险类**（而不是被塞进"AI 基础设施"里），**以便**我一眼看到这一年 CVE 增速最快的攻击面（MCP Server 一年 95 条 CVE，agentic 子类 +255.4%）。 | G4 |
| US-5 | **作为**安全管理者，**我希望**有一个面板把全部情报按**赛题四类 AI 风险**（①基础设施/推理框架、②模型与数据层、③AI 应用与智能体、④供应链）聚合展示，**以便**我做风险态势汇报时不需要人工统计。 | G5 |
| US-6 | **作为**应急响应工程师，**我希望**输入一个 CVE 就能得到"**数据污染→智能体越权→凭据泄露→数据外传**"式的有序攻击链，且每一跳都能点开证据，**以便**我向业务方解释这条链会怎么打穿。 | G6 |
| US-7 | **作为**值班运维，**我希望**服务进程掉线后能被**自动拉起**、且探活失败会留下告警记录，**以便**演示现场不会因为一个未捕获异常而全程空屏。 | G8 |
| US-8 | **作为**合规审计员，**我希望**每一次导出、改配置、下处置决定都记录**操作主体（人 / Agent 角色）与时间**，**以便**我满足"审计留痕 + human oversight"要求，并区分 agent 与人类操作。 | G7 |

---

## 四、需求池

### 4.0 需求总览

| 需求编号 | 标题 | 优先级 | 对应差距 | 对应赛题评分项 | 涉及模块 |
|---|---|---|---|---|---|
| **P0-1** | AI 安全标准与政策法规知识底座（含自动采集） | P0 必须 | G1 | 功能①15 / 功能③15 / 文档15 | `core/data_security_kb.py`、新增 `core/standards_kb.py`、`core/server.py`、`m1_monitor`、`m3_qa`、`frontend` |
| **P0-2** | EPSS 富化维度与漏洞优先级四元组 | P0 必须 | G2 | 功能②15 / 性能②5 | `m2_enrich/backend/enrich_dims.py`、`m2_enrich/api.py`、`core/taxonomy.py`（如需算子）、`m3_qa`（引用展示）、`frontend` |
| **P0-3** | 情报源健康度与数据缺失监测告警 | P0 必须 | G3 | 优化②10 / 性能①5 / 决赛监控10 | `m1_monitor/backend/live.py`、`m1_monitor/api.py`、`core/circuit.py`、`core/metrics.py`、`frontend` |
| **P0-4** | MCP Server / Agentic AI 独立风险类 | P0 必须 | G4 | 功能①15 / 功能③15 / 演示效果 | `core/taxonomy.py`、`m1_monitor/backend/build_data.py`、`m3_qa`、`frontend` |
| **P0-5** | 赛题四类 AI 风险显式映射与态势聚合 | P0 必须 | G5 | 功能③15 / 演示效果 / 文档15 | `core/taxonomy.py`、`core/server.py`（或模块 `api.py`）、`frontend` |
| **P1-1** | 攻击链（attack chain）推理接口 | P1 应该 | G6 | 功能③15 / 性能③5 | `core/atlas.py`、`core/graph_data.py`、`m3_qa/api.py`、`frontend` |
| **P1-2** | 存活探活与监控告警—自愈闭环 | P1 应该 | G8 | 优化②10 / 决赛监控10 | 新增 `core/health_probe.py`、`启动服务_守护.bat`、`core/metrics.py`、`frontend` |
| **P2-1** | 决策审计留痕与可问责归人 | P2 可以 | G7 | 优化①15 / 文档15 | `m0_ops/api.py`、`core/server.py`、`frontend/modules/m0_ops` |
| **P2-2** | 合规条款 ←→ 修复建议联动 | P2 可以 | G1（延伸） | 功能③15 / 演示效果 | `m2_enrich/backend/remediation.py`、`m3_qa` |
| **P2-3** | 增量能力同步进技术报告与演示脚本 | P2 可以 | G1~G8（交付完整性） | 文档质量15 / 演示效果 | `技术报告_AI-SecIntel_v2.2.md`、`交付总览.md`、`演示脚本_5分钟.md`、`core/docs/API接口文档.md` |

> **范围控制声明（硬约束）**：P0 限定为 **5 个需求簇**，每簇均要求"可在本次单次自动化执行内实现完 + 带可客观判定的验收用例 + 进 `core/self_test.py` 回归"。**超出 5 簇的、或需要新增必装依赖的、或需要重写 `data/` 大文件的诉求一律下沉到 P1/P2 或标注为范围外**（见附录 B）。

---

### 4.1 P0-1 · AI 安全标准与政策法规知识底座（含自动采集）

| 字段 | 内容 |
|---|---|
| **需求编号** | P0-1 |
| **对应差距** | **G1** ★★★ |
| **对应赛题评分项** | 功能① **15 分档**（多源覆盖 ≥7 类且含实时监测）· 功能③ **15 分档**（问答知识覆盖范围）· 文档质量 15 分 |
| **涉及模块** | `core/data_security_kb.py`（现状）→ 新增 `core/standards_kb.py`；`core/server.py`（静态索引并入）；`m1_monitor`（增量采集）；`m3_qa`（检索/问答命中）；`frontend`（面板） |

**描述**：
现有 `core/data_security_kb.py` 仅 **17 条** KB、法规 **4 条**（REG01 数据安全法 / REG02 个保法 / REG03 GDPR / REG04 数据出境），**全部为静态硬编码字符串，无版本、无生效日期、无自动更新**；语料 `data/corpus.json` 中 **无任何"技术标准/政策法规"类目**，对 `ISO/IEC 42001`、`EU AI Act`、`NIST AI RMF`、`TC260`、`CNNVD AIVD` 的命中均为 **0**。

本次**必须**新增独立的**标准/法规结构化知识底座**，形成可被 `/api/search` 直接命中的 `kind` 类目，并提供增量采集入口：

1. **结构化条目模型**（每条至少含）：`id`（前缀 `STD:` 标准 / `REG:` 法规）、`title`、`title_en`、`issuer`（发布机构）、`region`（CN/EU/US/INTL）、`kind`（技术标准 / 政策法规 / 行业规范 / 供应链合规）、`version`、`effective_date`、`status`（现行/草案/已废止）、`applies_to`（适用主体）、`key_requirements[]`（关键义务要点，逐条可引用）、`refs[]`（官方链接）、`tags[]`。
2. **覆盖面下限**：**≥ 40 条**结构化条目，其中中国法规 ≥ 12 条、国际标准 ≥ 12 条、行业/框架规范 ≥ 8 条、供应链合规 ≥ 8 条；**必须**包含赛题点名与行业调研点名的全部对象：NIST AI RMF、ISO/IEC 42001、EU AI Act（含 Annex III 高风险义务 2026-08-02 生效）、TC260 系列、《生成式人工智能服务管理暂行办法》、《人工智能生成合成内容标识办法》、《网络产品安全漏洞管理规定》（7×24 监测义务）、《数据安全法》、《个人信息保护法》、OWASP LLM Top 10 / Agentic Top 10、CNNVD AIVD、《智能体规范应用与创新发展实施意见》。
3. **自动采集**：**必须**提供独立于漏洞抓取的标准/法规巡检任务（默认并入 `m1_monitor` 巡检节拍或独立低频节拍），对官方/权威来源做增量比对，**新增/变更/失效**写入知识底座并记录 `fetched_at`；**离线或来源不可达时必须降级**为"使用内置基线条目 + 标记 `stale`"，**不得因抓取失败而清空或报错**。
4. **落库口径**：条目并入 `data/corpus.json` 的 `knowledge` 集合（沿用 `DSKB:` 风格，条数增量明确、不重写既有条目），并进语义索引（`POST /api/qa/build_vector` 可增量补建）。
5. **接口**：`GET /api/standards`（支持 `q` / `kind` / `region` / `status` / `size`），`POST /api/standards/refresh`（触发增量采集）；同时在 `/api/search` 的 `facets` 中新增 `kind` 维度，使标准/法规可被既有检索链路直接筛出。

**验收标准（可客观判定）**：
- AC-1：`GET /api/stats` 中 `knowledge` 集合存在 `kind ∈ {技术标准, 政策法规}` 的计数，且**两者合计 ≥ 40**。
- AC-2：`GET /api/search?q=ISO/IEC 42001`、`q=EU AI Act`、`q=NIST AI RMF`、`q=TC260`、`q=生成式人工智能服务管理暂行办法` **各返回 ≥ 1 条且首条命中为结构化条目**（现状全部为 0）。
- AC-3：`GET /api/standards?kind=政策法规&region=CN` 返回 **≥ 12** 条，且每条含非空 `issuer` / `effective_date` / `key_requirements`。
- AC-4：断网（或屏蔽来源）后执行 `POST /api/standards/refresh`，接口返回 `degraded: true` 且 **HTTP 200、条目数不减少**（降级不崩、不清库）。
- AC-5：`/api/search` 的 `facets` 中出现 `kind` 维度，且 `kind=技术标准` 可筛出结果。

---

### 4.2 P0-2 · EPSS 富化维度与漏洞优先级四元组

| 字段 | 内容 |
|---|---|
| **需求编号** | P0-2 |
| **对应差距** | **G2** ★★★ |
| **对应赛题评分项** | 功能② **15 分档**（富化维度 ≥5 种且含自动关联推理）· 性能② **5 分档**（准确率 ≥95% 优秀） |
| **涉及模块** | `modules/m2_enrich/backend/enrich_dims.py`、`modules/m2_enrich/api.py`、`core/taxonomy.py`（检索算子）、`modules/m3_qa`（答复引用）、`frontend` |

**描述**：
全仓 `EPSS` 字样命中 **1 次**（仅 `m3_qa/backend/qa/deep_answer.py` 说明性文本）；`ENRICH_DIMENSIONS` 现 **16 维**，**无 EPSS**。而行业实证：agentic CVE 集内 CVSS 与 EPSS 的 Spearman 相关仅 **0.17**（非 agentic 0.30、2025 基线 0.40）——**CVSS 单信号在 AI 漏洞上尤其失真**。

本次**必须**：

1. 在 `ENRICH_DIMENSIONS` 新增 **EPSS 维度**（`key="epss"`，`label="EPSS 利用概率"`），并在 `/api/enrich/dimensions` 上报**真实计数**（非占位 0）。
2. 新增**漏洞优先级四元组** `priority`：`cvss`（严重度）、`epss`（利用概率）、`kev`（在野利用）、`reachability`（可达性/互联网暴露面，复用既有 `/api/assets` + 测绘能力），输出**归一化优先级分**与**可解释理由串**（如"CVSS 9.8 + EPSS 0.71 + 已入 KEV ⇒ 立即处置"）。
3. EPSS 数据来源为 **FIRST EPSS 公开 API（无 Key）**；**必须**带本地缓存与陈旧阈值；**无网时必须降级**为"缓存值 + `status=degraded`"，且 EPSS 维度**仍出现在维度清单中**（不允许因无网而整维消失）。
4. `/api/detail` 返回 `priority` 四元组（4 个字段齐全，缺失项以 `null` + 原因标注，不得静默省略）。
5. 检索侧**应该**新增算子与排序：`epss>=0.5`、`kev:yes and epss>=0.1`、`sort=priority`（复用既有算子解析框架，不新造语法）。

**验收标准（可客观判定）**：
- AC-1：`GET /api/enrich/dimensions` 返回列表中包含 `key="epss"`，且其 `count ≥ 200`（真实计数，非 0/非估算）。
- AC-2：对 ≥ 20 条已入 KEV 的 CVE，`GET /api/detail?id=<CVE>` 的 `priority` 中 `cvss/epss/kev/reachability` **4 项字段全部存在**（可为 null 但键必须齐），且 ≥ 80% 的条目 `epss` 非空。
- AC-3：对同一 CVE，`priority` 给出的**处置优先级**与"KEV 命中 ⇒ 最高档"不矛盾（KEV=yes 的条目优先级档不得低于未命中 KEV 的条目）。
- AC-4：屏蔽外网后调用 EPSS 相关接口，返回 `status="degraded"` 且 **HTTP 200**；`/api/enrich/dimensions` 中 `epss` 维度仍存在。
- AC-5：`GET /api/search?q=epss>=0.5` 返回结果总数 = 语料中 EPSS ≥ 0.5 条目数（可交叉核算，误差 0）。

---

### 4.3 P0-3 · 情报源健康度与数据缺失监测告警

| 字段 | 内容 |
|---|---|
| **需求编号** | P0-3 |
| **对应差距** | **G3** ★★★ |
| **对应赛题评分项** | 优化② **10 分档**（全流程自动化 + 自愈能力）· 性能① **5 分档**（监测时效性）· 决赛"容器化 + 日志监控"10 分档 |
| **涉及模块** | `modules/m1_monitor/backend/live.py`、`modules/m1_monitor/api.py`、`core/circuit.py`、`core/metrics.py`、`frontend/modules/m1_monitor` |

**描述**：
现状只有 `core/circuit.py` 的**熔断**（FAIL=3 / COOLDOWN=300s），即响应"**异常数据**"。项目自有文档已如实记录：`m1_monitor` 台账 **10-07 起停产、10-08 起 `_test_daily_digest` 必败，直到测试失败才暴露（缺乏存活探活/告警）**；且**无任何 `source_health` / 数据缺失告警接口**。产业佐证（CSA《The Dual Visibility Crisis》）：NVD 富化自 2024-02 崩塌、2026-04 后约 **80% 新 CVE 不再获得 NVD 富化**，"most detection logic responds to anomalous data rather than **absent data**"——**缺失数据不会触发任何告警**。

本次**必须**把"沉默失败"变成"可见 + 可告警 + 可闭环"：

1. **源健康度记账**：对现有 **46 个情报源**（40 直连 + 6 仅代理）逐源记录 `last_success_at` / `last_item_at` / `expected_interval`（按源类型设期望节拍）/ `consecutive_failures` / `items_24h` / `items_7d_avg`。
2. **缺失判定**：当 `now - last_item_at > k × expected_interval`（默认 k=3）或 `items_24h == 0 且历史均值 > 0` 时，判定为 **`stale`（停产）**；当 `items_24h` 低于历史均值的 30% 时判定为 **`degraded`（缩水）**。**这是"对缺失数据"而不是"对异常数据"的判定**，是本需求的核心增量。
3. **告警落盘与接口**：告警以 JSONL 追加写 `data/alerts.jsonl`（字段：`ts` / `level` / `source` / `reason` / `evidence` / `state`）；新增 `GET /api/source_health`（逐源健康表 + 汇总计数）与 `GET /api/coverage_gaps`（缺失清单）。
4. **前端**：`/api/live` 返回体新增 `stale_sources[]`；面板给停产源打**红色 `STALE` 徽标**并显示"已停产时长"。
5. **自愈联动**：`stale` 达阈值时**应该**触发一次该源的强制重连（复用既有重试/熔断框架），失败后升级告警级别；**不允许**静默只写日志。

**验收标准（可客观判定）**：
- AC-1：`GET /api/source_health` 返回源数 = `GET /api/live` 的 `feed_total`（46），每源含 `last_item_at` / `expected_interval` / `state ∈ {ok, degraded, stale, disabled}`。
- AC-2：**可复现停产**：以既有停产台账（`_test_daily_digest` / 10-07 停产源）为输入，`GET /api/source_health` **必报出 ≥ 1 个 `state="stale"`**，且 `GET /api/coverage_gaps` 中该源在列。
- AC-3：告警落盘：出现 stale 后 `data/alerts.jsonl` **追加 ≥ 1 条**记录，含 `ts` / `source` / `reason`，且 `GET /api/source_health` 汇总里 `alerts_total ≥ 1`。
- AC-4：`GET /api/live` 返回体含 `stale_sources` 字段（可为空数组，但键必须存在），停产时非空。
- AC-5：**不引入必装依赖**；接口在无网环境返回 HTTP 200。

---

### 4.4 P0-4 · MCP Server / Agentic AI 独立风险类

| 字段 | 内容 |
|---|---|
| **需求编号** | P0-4 |
| **对应差距** | **G4** ★★ |
| **对应赛题评分项** | 功能① **15 分档**（AI 专项覆盖）· 功能③ **15 分档**· 答辩亮点/演示效果 |
| **涉及模块** | `core/taxonomy.py`、`modules/m1_monitor/backend/build_data.py`（分类落库）、`modules/m3_qa`（检索/问答）、`frontend` |

**描述**：
`core/taxonomy.py` 目前只把 `"mcp server"` / `"model context protocol"` 放进 `AI_DESC_KEYWORDS`（行 23）与 `SYNONYMS`（行 616、1123），**未进入产品→分类映射，也无独立风险子类**；`RISK_CATEGORIES` 的 ①~④ 未覆盖 MCP。而 Trend Micro《State of AI Security Report 2026》显示：**MCP Servers 是 2025 年才出现的新类别，一年 95 条 CVE**；agentic AI 子类 CVE 从 74 → 263（**+255.4%**，八类中增幅最高）。

本次**必须**：

1. 在 `RISK_CATEGORIES` 建立 **MCP / Agentic 独立风险类**（建议：`① AI基础设施与推理框架` 之下新增可聚合的子类标签 `MCP Server` 与 `Agentic AI`，**并**在分类体系中给出显式命名与 `desc`，颜色沿用现有暖色系）。**保持既有 ①~⑪ 的编号不被破坏**（分类号一旦位移会打散历史统计与面板），新增一律以**子类/标签**形式挂载，并在 `RISK_CATEGORIES` 中显式登记。
2. **产品→分类映射补全**：把 MCP 生态组件（MCP Server / MCP Client / Model Context Protocol 实现、常见 MCP 宿主工具）与 agentic 组件（Agent 编排框架、工具调用层、多智能体框架）纳入 `AI_PRODUCTS`/关键词映射，使相关条目**能被自动归类**而不是靠人工打标。
3. **无 CVE 编号的 AI 风险归类**：行业实证"大量 agentic AI 漏洞根本没有 CVE 编号，只存在于厂商公告/研究博客中"——本次**应该**让该类条目（`GHSA-*` / 博客 / 厂商公告）同样能落入该风险类并被索引（依赖既有 46 源快车道，不新增源）。
4. **可视化**：风险分类面板中 `MCP Server` / `Agentic AI` 作为**独立可点选筛选项**出现在分类 faceting 中。

**验收标准（可客观判定）**：
- AC-1：`core/taxonomy.py` 的 `RISK_CATEGORIES`（或其子类登记表）中出现显式的 `MCP Server` 与 `Agentic AI` 条目，且 **①~⑪ 编号与既有 `short` 名称零变更**（可用既有自测项回归比对）。
- AC-2：语料中经自动分类落入 `MCP Server` 类的条目 **≥ 30 条**（当前为 0，可用 `/api/search?category=` 核实）。
- AC-3：`GET /api/search?q=mcp server` 的 `facets.category` 中**出现**该类且计数 = AC-2 的数值。
- AC-4：至少 **1 条**无 CVE 编号（`GHSA-*` 或厂商公告来源）的 MCP/agentic 条目被成功归类并可检索到。
- AC-5：既有分类回归零失败（`core/self_test.py` 中与分类相关的既有项全绿）。

---

### 4.5 P0-5 · 赛题四类 AI 风险显式映射与态势聚合

| 字段 | 内容 |
|---|---|
| **需求编号** | P0-5 |
| **对应差距** | **G5** ★★ |
| **对应赛题评分项** | 功能③ **15 分档**（知识覆盖 + 深度分析）· 演示效果（"风险分类覆盖度"一眼可见）· 文档质量 15 分 |
| **涉及模块** | `core/taxonomy.py`（映射表）、`core/server.py` 或新增模块 `api.py` 路由、`frontend` |

**描述**：
`taxonomy.RISK_CATEGORIES` 的 ①~④ AI 类在**语义上**可与赛题四类对应，但**无任何显式映射声明**，也**无任何按赛题四类聚合的接口或面板**。实测语料分类计数（已成事实、可作为回归对照）：**①414 · ②741 · ③1139 · ④538（AI 类合计 2,832 / 70,529 条）**。

本次**必须**：

1. 在 `core/taxonomy.py` 增加**显式映射常量**（如 `EXAM_RISK_MAP`），逐条声明：赛题四类 ↔ 本项目分类号 ↔ 判定关键词/产品集。映射必须**双向可查**（给定赛题类别能列出本项目类别；反之亦然）。
2. 新增聚合接口 **`GET /api/risk_overview`**：返回赛题四类的条目计数、占比、时间趋势（近 7/30 天）、严重度分布、Top 受影响组件、含 POC/KEV 的比例；同时返回**映射表本身**（让评审能自证映射不是硬凑）。
3. 聚合口径**必须可与 `/api/stats` 对账**：四类计数之和 = 该映射覆盖的 AI 类条目总数，接口返回 `reconcile: {expected, actual, ok}` 字段。
4. **前端**：控制台新增"赛题四类风险态势"面板（四类环形/柱状 + 点击下钻到 `/api/search?category=`）。

**验收标准（可客观判定）**：
- AC-1：`GET /api/risk_overview` 返回 4 个赛题类别，每类含 `count` / `pct` / `severity_dist` / `top_products` / `poc_ratio` / `kev_ratio`。
- AC-2：对账通过——`reconcile.ok == true`，且四类计数之和与 `/api/stats` 中对应本项目分类号的计数合计**完全一致**（误差 0）。
- AC-3：映射表随接口返回（`mapping[]`），每条含"赛题类别 ↔ 本项目分类号 ↔ 判定依据"，**可被评审逐条核验**。
- AC-4：前端面板可见四类计数，且点击任一类别可下钻到带对应 `category` 筛选的检索结果（下钻结果数 = AC-1 的 `count`）。
- AC-5：①~④ 既有单类计数**不因新增映射而改变**（回归对照 414 / 741 / 1139 / 538，允许因新增 MCP 类归类产生的**增量**，但不得减少）。

---

### 4.6 P1-1 · 攻击链（attack chain）推理接口

| 字段 | 内容 |
|---|---|
| **需求编号** | P1-1 |
| **对应差距** | **G6** ★★ |
| **对应赛题评分项** | 功能③ **15 分档**（跨文档推理与深度分析）· 性能③ **5 分档**（多跳推理） |
| **涉及模块** | `core/atlas.py`、`core/graph_data.py`、`modules/m3_qa/api.py`、`frontend/modules/m3_qa` |

**描述**：
`core/atlas.py` 已存在 `CWE_TO_TECH`（文件头自称"可解释的攻击链富化维度"）、`core/graph_data.py` 已有 tactic 节点（行 259-264），但**没有任何对外接口能回答"这个漏洞的攻击链是什么"**——`/api/graph` 是实体关系图（非链路推理），`/api/detail` 只给 atlas 数组。

本次**应该**新增 **`GET /api/attack_chain?id=<情报编号>`**：输出**有序**链路（阶段 → 技术 → 证据），每跳必须带 `evidence[]`（可 `/api/detail` 打开的引用），并对链路给出**可解释说明**（为什么这一跳成立）；同时把该能力接入 `/api/chat` 的答复（问"这个漏洞的攻击链"时直接给链路 + 引用）。

**验收标准（可客观判定）**：
- AC-1：对 ≥ 10 个已知 AI 组件（Ollama / vLLM / LangChain / Dify / Open WebUI 等）的 CVE，`/api/attack_chain` **≥ 8 个返回 ≥ 3 跳**的链路。
- AC-2：每跳含 `stage`（战术阶段）、`technique`（ATLAS 技术 id+name）、`evidence[]`（≥1 条可打开的引用 id）。
- AC-3：接口返回 `explain` 字段（非空字符串），对每一跳给出一条可读理由。
- AC-4：`/api/chat` 问"<某 CVE> 的攻击链是什么"时，答复中含 ≥ 2 跳且引用可点开（沿用既有引用可回溯率口径）。
- AC-5：无 ATLAS 映射的条目返回**明确空结果 + 原因**（HTTP 200，`chain: []`, `reason` 非空），不报错。

---

### 4.7 P1-2 · 存活探活与监控告警—自愈闭环

| 字段 | 内容 |
|---|---|
| **需求编号** | P1-2 |
| **对应差距** | **G8** ★ |
| **对应赛题评分项** | 优化② **10 分档**（全流程自动化 + 自愈）· 决赛"容器化部署 + 日志监控"10 分档 |
| **涉及模块** | 新增 `core/health_probe.py`、`启动服务_守护.bat`（现有）、`core/metrics.py`、`core/logrotate.py`、`frontend` |

**描述**：
已有 `Dockerfile`、`docker-compose.yml`、`.github/workflows/ci.yml`、`core/logrotate.py`、`core/metrics.py`、看门狗；但**无存活探活告警、无自动重启**，`/api/health` 仅自检。

本次**应该**：新增 `GET /api/health/live`（存活探活：返回 `alive` / `pid` / `uptime` / `pidfile` / `last_poll_age` / `index_writable`），探活失败或 `last_poll_age` 超阈值时**写告警**（复用 P0-3 的 `data/alerts.jsonl` 通道）并由守护脚本在 **≤ 60s 内拉起**；探活结果进 `core/metrics.py` 指标。

**验收标准（可客观判定）**：
- AC-1：`GET /api/health/live` 返回 `alive: true` 与 `pid` / `uptime_sec` / `pidfile`。
- AC-2：**受控演练**：杀掉服务进程后，守护机制在 **≤ 60s** 内使 `GET /api/health/live` 重新可达，且 `data/alerts.jsonl` 留有对应记录。
- AC-3：`/api/health/live` 在索引目录不可写时返回 `alive: true` 但 `index_writable: false`（不误判为死亡）。
- AC-4：`core/self_test.py` 新增探活回归项，且既有 **78 项**不因本需求失败（已知 3 项既有失败保持原状态）。

---

### 4.8 P2 需求（本轮不阻塞，时间允许再做）

| 编号 | 标题 | 描述（要点） | 验收标准（简） | 对应差距 |
|---|---|---|---|---|
| **P2-1** | 决策审计留痕与可问责归人 | `core/server.py` 现无鉴权，六维分析评 C+："所有操作都以'系统/自动'名义，无法区分谁导出/谁改配置"。为处置/导出/改配置类接口引入**轻量操作主体标识**（如请求头 `X-Actor` + Agent 角色名，缺省记为 `anonymous/auto`），写审计流水；`/api/ops/decisions` 增加 `actor` / `actor_kind(human/agent)` 字段。 | 审计链可导出；任一处置记录含 `actor` 与 `ts`；区分 human/agent 计数可查。 | G7 |
| **P2-2** | 合规条款 ←→ 修复建议联动 | 从 P0-1 的标准/法规条目抽出 `key_requirements`，在 `/api/detail` 的 `remediation` 与问答答复中标注**适用合规依据**（如"KEV 命中的对外服务漏洞 ⇒ 触发《网络产品安全漏洞管理规定》7×24 监测义务"）。 | 对 ≥ 5 条法规能给出可复现的联动示例；答复中合规依据可引用溯源。 | G1 延伸 |
| **P2-3** | 增量能力同步进技术报告与演示脚本 | 把 P0/P1 的新能力写入 `技术报告_AI-SecIntel_v2.2.md`、`交付总览.md`（数字口径表）、`演示脚本_5分钟.md`、`core/docs/API接口文档.md`（新接口补章节）、`README.md`。 | 新接口在 API 文档中 100% 有章节；交付总览口径表新增行；演示脚本含新增面板的演示步骤。 | G1~G8 |

---

## 五、UI 变更点

> **强制提醒（硬约束）**：`frontend/styles.css` / `frontend/app.js` 改完**必须递增 `frontend/index.html` 里的 `?v=` 版本号**（后端静态资源 `max-age=600`，不递增会拿到旧缓存）。
> **当前值**：`styles.css?v=38` → **`?v=39`**；`app.js?v=29` → **`?v=30`**；`fx.js?v=6` 如改动则递增。
> 模块面板由 `tools/组装前端.py` 从 `modules/<id>/web/` 同步到 `frontend/modules/<id>/`，**改完必须重跑组装**。

| 文件 | 变更点 | 需求 |
|---|---|---|
| `frontend/index.html` | 新增"标准 / 法规"面板容器与入口按钮；新增"赛题四类风险态势"面板容器；**递增 `?v=`** | P0-1、P0-5 |
| `frontend/app.js` | 新增 `renderStandards()` / `renderRiskOverview()` / `renderSourceHealth()` 挂载点；检索框算子提示补 `epss>=` / `sort=priority`；分类 faceting 显示 `MCP Server` / `Agentic AI` | P0-1、P0-2、P0-4、P0-5 |
| `frontend/styles.css` | 标准/法规条目卡片、赛题四类图表、源健康徽标（`STALE` 红 / `degraded` 黄）样式；沿用既有色调变量，不新增主题 | P0-1、P0-3、P0-5 |
| `frontend/modules/m1_monitor/panel.js`（源 `modules/m1_monitor/web/panel.js`） | **源健康度看板**：逐源表 + 停产源红标 + 缺失告警列表 + "已停产时长" | P0-3、P1-2 |
| `frontend/modules/m2_enrich/panel.js`（源 `modules/m2_enrich/web/panel.js`） | 富化维度清单新增 **EPSS** 行与真实计数；详情页新增"优先级四元组"小卡（CVSS/EPSS/KEV/可达性） | P0-2 |
| `frontend/modules/m3_qa/panel.js`（源 `modules/m3_qa/web/panel.js`） | **攻击链可视化**（复用既有内联 SVG 径向渲染，零外部图表库）；答复中新增"合规依据"引用段 | P1-1、P2-2 |
| `frontend/modules/m0_ops/ops.js`（源 `modules/m0_ops/web/ops.js`） | 审计留痕列表（`actor` / `actor_kind` 展示与筛选） | P2-1 |

**UI 通用约束**：渲染外部数据一律走既有 `esc()` 白名单转义（`m2_enrich/panel.js:190` 已记录过属性逃逸坑），新增面板**不得**直接拼 HTML 插值；分类短标签沿用 `/api/... 四、风险分类编号对照` 的既有 `short` 值。

---

## 六、验收指标（可量化口径）

> 以下为**本次增量的独立验收口径**；既有 78 项自测、检索评测（@1 85.0% / MRR 0.885）、富化五维（均值 96.4%）、多跳 12/12 为**回归不劣化基线**，不得下降。

| 维度 | 指标 | 目标值 | 判定方式 |
|---|---|---|---|
| 知识底座 | 标准/法规**结构化条目数** | **≥ 40 条** | `GET /api/stats` / `GET /api/standards` 计数 |
| 知识底座 | 赛题点名对象的精确命中 | `ISO/IEC 42001`、`EU AI Act`、`NIST AI RMF`、`TC260`、《生成式人工智能服务管理暂行办法》**各 ≥ 1 条**（现状 0） | 逐词 `/api/search` |
| 知识底座 | 法规/标准可被检索命中 | 100% 条目可被 `/api/search` 命中（抽 10 条全中） | 抽样复跑 |
| 富化 | EPSS 维度出现在维度清单 | `key="epss"` 存在且 **count ≥ 200** | `GET /api/enrich/dimensions` |
| 富化 | 优先级四元组字段完整性 | KEV CVE 抽样 20 条，4/4 字段键齐全；`epss` 非空率 **≥ 80%** | `GET /api/detail` 遍历 |
| 富化 | EPSS 降级不崩 | 无网时 HTTP 200 + `status="degraded"`，维度不消失 | 断网复跑 |
| 源健康 | 源覆盖 | `source_health` 源数 = `feed_total`（46） | 两个接口对账 |
| 源健康 | **能报出停产源** | 以既有停产台账复现，`state="stale"` **≥ 1 个** | 受控注入 + 接口复跑 |
| 源健康 | 缺失告警落盘 | `data/alerts.jsonl` 追加 **≥ 1 条**，含 `ts/source/reason` | 文件核对 |
| 源健康 | `/api/live` 字段 | `stale_sources` 键存在，停产时非空 | 接口 schema 断言 |
| 风险分类 | MCP/Agentic 独立类 | 类目存在且归类条目 **≥ 30 条**；①~⑪ 编号零变更 | `category` faceting + 回归 |
| 风险分类 | 四类态势对账 | `/api/risk_overview` 四类之和 = `/api/stats` 对应计数，**`reconcile.ok = true`（误差 0）** | 接口自对账 |
| 攻击链（P1） | 链路可用率 | 10 个 AI 组件 CVE 中 **≥ 8 个**返回 ≥3 跳 | 抽样复跑 |
| 攻击链（P1） | 可解释性 | 100% 跳含 `evidence` 且 `explain` 非空 | schema 断言 |
| 自愈（P1） | 探活恢复 | 杀进程后 **≤ 60s** 内 `/api/health/live` 恢复可达 | 受控演练 |
| 工程 | 依赖 | **新增必装依赖数 = 0**；缺库路径全部降级 | `tools/检查依赖.py` + 断网复跑 |
| 工程 | 回归 | `core/self_test.py` **既有 78 项不因本次改动新增失败**（既有 3 项已知失败保持原状） | `NO_PROXY=127.0.0.1,localhost python core/self_test.py 8848` |
| 工程 | 前端缓存失效 | `styles.css` / `app.js` 的 `?v=` **已递增** | `frontend/index.html` 核对 |

**既有 3 项已知失败（勿误判为本次回归）**：① `测试报告/检索评测.md` 不存在 ② `测试报告/POC覆盖率对比.md` 不存在 ③ `v2.2 深度层⇕条件链降噪过滤` 保留=['A','C']。

---

## 七、待确认问题

| # | 问题 | 影响 | 建议默认处置（若无人工指示则按此执行） |
|---|---|---|---|
| Q1 | **EPSS 在无网环境的降级口径**：仅用缓存会随时间失真，是否接受"缓存值 + 明确 `degraded` 标记"？缓存的**最长可接受陈旧时长**（建议 7 天）由谁定？ | P0-2 AC-4 的判定方式 | 接受"缓存 + degraded 标记"；陈旧阈值取 **7 天**，超期在 UI 上标黄 |
| Q2 | **标准/法规条目的人工审核责任**：自动采集可能引入失效/错误条目（如已废止法规）。是否需要人工审核位（`review_status`）？谁负责签核？ | P0-1 的条目可信度与 AC-2 精确命中 | 增加 `review_status ∈ {auto, reviewed}`，**默认 `auto`**，由需求方后续人工复核 |
| Q3 | **MCP/Agentic 分类的实现方式**：新增**独立分类号 ⑫** 还是挂在 ① 之下的**子类标签**？前者会打散既有 ①~⑪ 统计与历史面板口径。 | P0-4 AC-1、P0-5 AC-5 的回归口径 | 采用**子类/标签**挂载，**不动 ①~⑪ 编号**；若需求方坚持独立编号，需同步接受历史统计口径变更 |
| Q4 | **赛题四类与 ①~④ 的映射是否需要"一一对应"**：赛题四类中的"AI 应用与智能体"实际横跨本项目 ③ 与部分 ②、⑪，强行一一对应会失真。 | P0-5 AC-3 的映射表形态 | 允许**多对一/一对多**映射，接口返回映射表本身供评审核验，不追求表面整齐 |
| Q5 | **告警通道**：`data/alerts.jsonl` 之外是否需要外部通道（邮件/Webhook）？既有 `m2_enrich/backend/alert_subscribe.py`、`mailer.py` 是否复用？ | P0-3 AC-3、P2 范围 | 本轮**只做落盘 + 接口 + 面板**，外部推送到 P2（复用既有订阅/邮件能力需额外凭据，超出本轮） |
| Q6 | **`data/alerts.jsonl` 的落盘位置与轮转**：`data/` 下大文件"不要随意重写"是硬约束，新增 JSONL 是否需要纳入 `core/logrotate.py` 轮转策略？ | P0-3 工程合规性 | 新增小文件、追加写、纳入 `logrotate` 轮转；**不改动任何既有大文件** |

---

## 附录 A · 差距 ↔ 需求 ↔ 赛题评分项 对照

| 差距 | 严重度 | 需求编号 | 赛题评分项（档位） | 本次是否在范围内 |
|---|---|---|---|---|
| G1 标准/法规知识底座缺失 | ★★★ | P0-1（+P2-2） | 功能①15 / 功能③15 / 文档15 | ✅ P0 |
| G2 EPSS 富化维度缺失 | ★★★ | P0-2 | 功能②15 / 性能②5 | ✅ P0 |
| G3 源完整性/缺失监测告警缺失 | ★★★ | P0-3 | 优化②10 / 性能①5 | ✅ P0 |
| G4 MCP 未成独立风险类 | ★★ | P0-4 | 功能①15 / 功能③15 | ✅ P0 |
| G5 赛题四类无显式映射与聚合 | ★★ | P0-5 | 功能③15 / 演示效果 | ✅ P0 |
| G6 攻击链推理未成产品能力 | ★★ | P1-1 | 功能③15 / 性能③5 | 🔶 P1 |
| G7 处置决策不可归人 | ★ | P2-1 | 优化①15 | 🔷 P2 |
| G8 监控告警与自愈未闭环 | ★ | P1-2 | 优化②10 / 决赛监控10 | 🔶 P1 |

## 附录 B · 明确不做（范围外，防止实现膨胀）

| 不做项 | 原因 |
|---|---|
| 新增独立模块或改动微内核 + 四模块拓扑 | 架构稳定性优先；赛题不要求拓扑变更 |
| 引入必装第三方依赖（EPSS 客户端库、图表库、鉴权框架等） | 违反硬约束"零依赖也能跑主体"；一律自行实现 + 缺库降级 |
| 重写 `data/corpus.json` / 重建向量索引全量 | 硬约束"`data/` 下大文件不要随意重写"；只做增量并入 |
| 为 `core/server.py` 引入完整认证/授权体系 | 超出本轮；P2-1 只做"轻量操作主体标识 + 审计留痕" |
| 外部告警推送（邮件 / Webhook / IM） | 依赖外部凭据与网络；本轮只做落盘 + 接口 + 面板 |
| 新增情报源（超出既有 46 源） | G3 的目标是"看到源是否活着"，不是"源更多"；扩源另立需求 |
| 前端主题/设计系统重构 | 无收益；只做增量面板与徽标 |

---

*文档结束 · 增量 PRD v1.0 · 2026-10-13 · 作者：许清楚（产品经理）*
