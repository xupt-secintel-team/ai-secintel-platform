# 赛题九差距补齐 · 独立 QA 验证报告

> **验证人**：严过关（Yan）· QA 工程师
> **验证日期**：2026-10-13
> **被验证对象**：赛题九差距补齐增量改造（`core/standards_kb.py`、`core/priority.py`、`core/alert_log.py`、`modules/m2_enrich/backend/epss.py`、`modules/m1_monitor/backend/source_health.py` + 若干修改文件）
> **验证原则**：**证伪优先**。工程师自测报告 `_t9_impl_notes.md` 仅作线索，**所有数字均为本人独立复算所得**，不引用其结论。
> **服务**：`core/server.py 8848`（QA 自起，PID 17648 / 重启后 28388），测试完毕后已关闭。
> **回归基线**：89 通过 / 3 失败（3 项已知与本改造无关）。

---

## 一、总体结论

| 判定 | 说明 |
|---|---|
| **整体判定：有条件通过** | 11 项验证中 **9 项完全通过**，**2 项存在问题**（1 项需求缺口、1 项排序缺陷）；无 500 崩溃、无回归。 |
| **必须修复** | **F1（AC-2 覆盖率缺口）**：KEV CVE 的 `epss` 非空率实测仅 72%（25 抽样）/ 39.9%（全量 536），**低于 AC-2 要求的 ≥80%**。 |
| **建议修复** | **F2（检索首条）**：`q=生成式人工智能服务管理暂行办法` 首条命中为 CSDN 文章（结构化条目排第 2），严格不满足 P0-1 AC-2「首条命中为结构化条目」。 |
| **可选/观察** | F3 告警文件被单测污染；F4 `kind` 字段命名空间与既有语料冲突；F5 冷启动探活声明在架构上不可观测。 |

---

## 二、断言表（项目 / 期望 / 实测 / 判定）

| # | 验证项 | 期望 | 实测（本人复算） | 判定 |
|---|---|---|---|---|
| 1 | **EPSS 算子正确性** | `/api/search?q=epss>=0.5` 命中数 = 语料中 `epss>=0.5` 条数 | **API total=104**；独立 oracle（`/api/corpus` 全量 id ∩ `epss_cache.json`，复刻 `attach_epss` 逻辑）**=104**，**误差 0**。阈值 0.9/0.1/<0.05：API 62/153/47 vs oracle 62/153/47，**全部精确一致**。104 条结果 id **0 假阳性**（唯一且每条 cache 值 ≥0.5），前 20 条 epss 值全 ≥0.5（最小 0.60522） | ✅ 通过（强） |
| 2 | **优先级单调性** | `sort=priority` 返回的 score 非增；KEV 不低于非 KEV | 40 条 score=95,94,94,90,87,87,79,78,67,66,64,…,40 **严格非增**；KEV 21 条**最小 46**，非 KEV 16 条**最大 40** ⇒ KEV 全部 ≥ 非 KEV | ✅ 通过 |
| 3 | **detail priority 四键完整性** | ≥20 条 CVE（≥5 KEV）四键齐；epss 非空率 ≥80% | 22 条 CVE（含 8 KEV）**四键 100% 齐全**（无缺键）；但 **epss 非空率：整体 3/22=14%，KEV 组 18/25=72%** | ⚠️ 键完整✅ / **覆盖率 ❌（见 F1）** |
| 4 | **标准/法规真实性（防编造）** | 逐条比对事实表，0 条不符；EU AI Act 高风险义务并列两表述+需人工确认 | 逐条比对 **25 条标准级条目**（共 60 条=25 标准级+35 义务级）全部可对应事实表行；**未发现事实表不存在的编号/机构/日期**；`REG:EU-AI-ACT` 与 `REG:EU-2026-1744` **同时含 2026-08-02、2027-12-02 两种日期表述 + 「需人工确认」** | ✅ 通过（25/25 吻合） |
| 5 | **检索首条命中（AC-2）** | 5 个查询首条为 `STD:`/`REG:` 或 kind∈{技术标准,政策法规} | ISO/IEC 42001→`STD:ISO-42005`✅；EU AI Act→`REG:EU-AI-ACT`✅；NIST AI RMF→`STD:NIST-AI-RMF`✅；TC260→`REG:TC260-AI-GOV-FRAME`✅；**生成式人工智能服务管理暂行办法→`CSDN:163326798`（CSDN 文章）❌**，结构化条目 `REG:GENAI-INTERIM-MEASURES` 排第 **2** | ⚠️ 4/5 通过（见 F2） |
| 6 | **kind facet** | `/api/search` facets 含 kind；`/api/stats.kind_counts` 合计 ≥40 | facets 键含 `kind`✅（`q=安全&kind=技术标准` facet=[[技术标准,16]]）；kind_counts 合计=**41375**✅（其中 技术标准 27+政策法规 30=57 ≥40） | ✅ 通过（附 F4 观察） |
| 7 | **源健康与缺失判定** | source_health 源数 = live.py 静态源表；排查 stale/unknown；alerts.jsonl 同源同态唯一 | source_health **total=57** = 静态源表 **57**（BLOG_FEEDS 42+代理 6+ARXIV 2+SOURCES 7，去重后 57）✅；**stale=3、unknown=9、ok=45**；`data/alerts.jsonl` **4 条**，`(source,state)` 组合 **4/4 唯一（无重复）**✅ | ✅ 通过（附 F3 观察） |
| 8 | **降级路径（AC-4）** | 无缓存/无网时 epss 维度不消失、HTTP 200、不崩 | 临时改名 `data/epss_cache.json` 后：`/api/enrich/dimensions` **epss 维度仍在**（`data_file_exists=false, count=null`，dim_count=14/assoc=3）✅；`/api/enrich/priority?id=未在缓存CVE` **HTTP 200**、`epss=null` 且 `missing.why="无网且无缓存"`✅；`/api/detail` 同✅。**测试后已恢复文件（800 条）** | ✅ 通过 |
| 9 | **`/api/health/live` 冷启动** | 引擎未加载完时即返回 200 | 端点确返回 `alive/pid/uptime_sec/index_writable`✅；**但「引擎未加载完时的 200」在本架构下不可观测**——`main()` 先 `get_engine()`(1575行) 后 `bind`(1627行)，端口加载完才监听。连续探测首个 200 **engine_loaded 已 =True**（uptime 282.9s） | ⚠️ 端点✅ / 冷启动口径存疑（见 F5） |
| 10 | **回归** | `self_test.py` 保持 89/3；既有接口不回归 | **通过 89 / 失败 3**，与基线逐字一致；3 项失败=检索评测.md 缺失 / POC覆盖率对比.md 缺失 / 深度层条件链降噪；dimension_count 13→**14**、association_count **3**；`/api/stats`、`/api/search?q=AI`、`/api/detail`、`/api/live` 均正常 | ✅ 通过（无回归） |
| 11 | **边界与错误路径** | 不得 500 | `enrich/priority?id=不存在`→**404**；`/api/attack_chain`→**404 unknown api**；`standards?kind=不存在`→**200**；`search?q=epss>=abc`→**200**；`search?q=epss:>=x`→**200**；risk_overview/coverage_gaps→**200** | ✅ 通过（无 500） |

**补充（P0-5 对账）**：`/api/risk_overview` → `reconcile={expected:32082, actual:32082, ok:true}`✅，4 类均含 `count/pct/severity_dist/top_products/poc_ratio/kev_ratio`，`mapping[]` 4 条。

---

## 三、发现的问题（按源码 Bug / 测试 Bug 分类）

### 🔴 F1 · 源码/需求缺口（高优先级）——AC-2 的 KEV CVE `epss` 覆盖率不达标

- **现象**：AC-2 要求「对 ≥20 条已入 KEV 的 CVE，≥80% 的条目 `epss` 非空」。实测：
  - 25 条 KEV CVE 抽样（`/api/search?exploited=1` 取前 25）：**18/25 = 72% 非空**（7 条为空：CVE-2026-104286 / 102489 / 76504 / 86950 / 88772 / 71362 / 5430）。
  - 全量口径（`/api/corpus` 中 `exploited=true` 共 **536** 条）：**仅 214/536 = 39.9% 有 epss**。
- **根因**：`modules/m2_enrich/backend/epss.py:130` 的 `default_cves(maxn=800)` 只取 `kev_cache.json`（共 **1721** 个 CVE 键）的前 **800** 个建缓存；而语料中 KEV CVE 与这 800 个的交集仅 **214**。即 EPSS 缓存条数上限（800）< KEV 总量（1721），导致覆盖率被硬顶在 ~46% 附近。
- **文件:行号**：`modules/m2_enrich/backend/epss.py:130`（`def default_cves(maxn: int = 800)`）、调用点 `:235`（`targets = list(cves) if cves else default_cves()`）
- **复现命令**：
  ```
  # 1) 取 KEV CVE 并逐条查 detail.priority.epss
  NO_PROXY=127.0.0.1,localhost ./.venv/Scripts/python.exe -c "
  import urllib.request,json,urllib.parse
  g=lambda p:json.load(urllib.request.urlopen('http://127.0.0.1:8848'+p,timeout=60))
  # 见随附验证脚本：对 exploited=1 的 CVE 统计 priority.epss 非空比例"
  ```
- **期望 vs 实际**：期望 KEV CVE `epss` 非空率 ≥80%；实际 72%（抽样）/ 39.9%（全量）。
- **建议**：将 `default_cves` 上限提升至覆盖全部 KEV（≥1721），或改从语料实际 KEV CVE 集合定向抓取；重跑 `POST /api/enrich/epss/refresh` 后复验。
- **路由**：**→ 工程师（Alex）**

### 🟠 F2 · 源码/排序缺陷（中低优先级）——P0-1 AC-2 首条命中不满足

- **现象**：`GET /api/search?q=生成式人工智能服务管理暂行办法` 首条命中为 `CSDN:163326798`（kind=CSDN 社区文章），结构化条目 `REG:GENAI-INTERIM-MEASURES` 排在**第 2 位**（total=5331，OR 语义）。
- **文件:行号**：排序主逻辑 `core/engine.py:1767-1781`（BM25 relevance）；该条目的 `desc` 与查询串的判别度不足以压过 CSDN 语料。属排序权重问题，非检索不可达（结构化条目**可被命中**，仅非首位）。
- **复现命令**：
  ```
  NO_PROXY=127.0.0.1,localhost ./.venv/Scripts/python.exe -c "
  import urllib.request,json,urllib.parse
  r=json.load(urllib.request.urlopen('http://127.0.0.1:8848/api/search?'+urllib.parse.urlencode({'q':'生成式人工智能服务管理暂行办法','size':'10'})))
  print([x['id'] for x in r['results'][:3]])"   # → ['CSDN:163326798','REG:GENAI-INTERIM-MEASURES', ...]
  ```
- **期望 vs 实际**：期望首条为结构化条目（`STD:`/`REG:`）；实际首条为 CSDN 文章（结构化条目 #2）。
- **建议**：对「标准/法规类目」查询加轻量加权，或在 `knowledge` 条目的 `title` 精确/短语命中时提权。
- **路由**：**→ 工程师（Alex）**（可评估是否接受「结构化条目在首位附近」的宽松口径）

### 🟡 F3 · 轻微/测试卫生——`data/alerts.jsonl` 被单元测试污染

- **现象**：`data/alerts.jsonl` 共 4 条，其中 1 条为 `{"source":"TEST-SRC","reason":"单测告警","level":"warn"}`（单测产物），仅 3 条为真实停产告警（Google 安全博客 / GitLab / The Hacker News）。`source_health.summary.alerts_total=3` 与文件 4 行不一致。
- **去重判定（正面结论）**：`(source,state)` 组合 4/4 唯一，**同源同态确未重复写**，去重逻辑正确。
- **建议**：单测使用临时 `ALERT_FP` 或独立测试文件，勿写生产告警文件。
- **路由**：**→ 工程师（Alex）**（低优先）

### 🔵 F4 · 设计观察——`kind` 字段命名空间与既有语料冲突

- **现象**：`core/standards_kb.to_doc` 把 `kind` 设为 `技术标准/政策法规/行业规范/供应链合规`；但既有语料文档**本就有 `kind` 字段**（如 `CSDN:163326798` 的 `kind="CSDN 社区文章"`）。因此 `/api/stats.kind_counts` 达 **41375** 项（含 ~70 种来源型 kind），`facets.kind` 亦被来源型 kind 填充。
- **影响**：AC-1/AC-5 要求的「kind 维度存在 + `kind=技术标准` 可筛」均满足（精确匹配），功能性无碍；但语义上 `kind` 不再是「标准/法规专有维度」，评测可能质疑其纯度。
- **路由**：**观察项**（无需修复；如需纯净，可为标准/法规另起独立字段如 `doc_kind`）

### ⚪ F5 · 方法学说明——`/api/health/live` 冷启动声明不可观测

- **事实**：`core/server.py:main()` **先加载引擎（1575 行 `get_engine()`）后绑定端口（1627 行）**。故在引擎加载期间端口根本未监听，**任何请求都不可达**，「引擎未加载完即返回 200」在单进程架构下**无法被观测**（QA 连续探测首个 200 时 `engine_loaded` 已为 True，uptime 282.9s）。
- **可证实的部分**：处理器确实**不触达 `get_engine()`**（置于 938 行，早于 1028 行的 `eng=get_engine()`），一旦端口可达即**立即**返回，不被引擎阻塞——这一**设计意图已达成**。
- **路由**：**不计为 Bug**（工程师笔记已诚实标注该架构事实）；建议对外表述为「端口可达后即时返回」而非「冷启动未加载完即 200」。

---

## 四、未验证 / 无法验证项（如实列出）

1. **真·断网降级（`POST /api/enrich/epss/refresh` / `POST /api/standards/refresh`）**：本人以「临时移除缓存文件」模拟无缓存，**未真实施加网络隔离**去触发 `fetch()` 的网络失败分支（`status="degraded"`）。即 AC-4 中「屏蔽外网后返回 degraded」的**真实网络失败路径未端到端复现**（降级不崩、维度不消失这一**结果**已验证）。
2. **AC-4 的「条目数不减少」**：`standards_kb.refresh()` 有该语义，但未在受控断网下执行 `POST /api/standards/refresh` 复验。
3. **EPSS 实网抓取正确性**：未验证 `api.first.org` 实际返回与缓存落盘的一致性（缓存为既有产物，本人只校验了缓存→引擎→API 的链路一致性）。
4. **P1 项（`/api/attack_chain`）**：未实现（返回 404）。按 PRD 属 P1「应该」项、且工程师笔记声明本轮未做，**不计为本轮回归**。
5. **前端**：PRD 要求的前端面板（标准/法规、四类态势、源健康徽标、`?v=` 递增）**本轮不做、未验证**。
6. **`core/circuit.py` 持续 stale 强制重连**：工程师已声明本期跳过，未验证。

---

## 五、与工程师自测笔记的口径差异（重点）

| 项 | 工程师笔记 | 本人实测 | 差异说明 |
|---|---|---|---|
| **AC-2 epss 覆盖率** | 仅报告「四键完整」；**未报告 80% epss 非空率** | KEV CVE epss 非空率 **72%（抽样）/ 39.9%（全量）** | **关键不一致**：自测「全绿」掩盖了覆盖率不达标。键完整 ≠ 覆盖率达标。 |
| **检索首条（生成式暂行办法）** | 笔记 #14 只验了 `ISO/IEC 42001` 首条 | `生成式人工智能服务管理暂行办法` **首条为 CSDN**（结构化 #2） | 自测未覆盖该查询，遗漏 1/5 失败。 |
| `/api/search?q=epss>=0.5` | #11 total=104 | **104，一致**（复算 oracle=104，误差 0） | 一致；但需澄清：104 ≠ 缓存 `>=0.5` 原始条数 **362**——因 800 缓存 CVE 中**仅 214 在语料**，搜索作用域是「语料文档」。 |
| 源数 / 状态 | #4 total=57，首轮 unknown=57，后 ok45/stale3/unknown9 | **一致**（57；ok45/stale3/unknown9） | 一致。 |
| `enrich/priority` 示例 | #9 CVE-2026-94127 → epss 0.02226 / score 53 / P0 | **一致**（重启后复现） | 一致。 |
| dimension 计数 | #7 dimension_count=14 / association_count=3 | **一致** | 一致。 |
| risk_overview 对账 | #3 reconcile 32082=32082 ok | **一致** | 一致。 |
| 文档总数 | 笔记记 docs=108341 | 实测 111904→111908 | 运行期快车道增量所致，属预期。 |

> **一句话**：工程师自测在「结构正确性」维度基本可信，但在「覆盖度指标」（AC-2 的 80% 非空率）与「全量首条命中」两处**过度乐观**——这正是本次独立验证的价值所在。

---

## 六、环境与复现备注

- 起服务：`cd "…/aisec-D_2.0" && NO_PROXY=127.0.0.1,localhost PYTHONDONTWRITEBYTECODE=1 ./.venv/Scripts/python.exe -B core/server.py 8848`
- 自测：`NO_PROXY=127.0.0.1,localhost ./.venv/Scripts/python.exe core/self_test.py 8848`
- 本机引擎加载实测约 **150~285s**（受并发进程影响），端口在引擎加载完成后才监听。
- 本次 QA 服务进程**已关闭**；临时改名过的 `data/epss_cache.json` **已恢复**（800 条，meta 完好）。
- 附：本次实测的原始返回已记录于报告正文；`tmp/qa_coldstart.txt` 为冷启动探测流水（可删）。

*报告结束 · 严过关（QA）· 2026-10-13*
