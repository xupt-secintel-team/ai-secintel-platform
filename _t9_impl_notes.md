# 赛题九差距补齐 · P0 后端实现笔记（software-engineer-3 / 寇豆码）

> 增量改造续做记录。每完成一项**立即**追加一条，格式：
> `## Txx 标题 / 状态 / 改动文件与行数 / 实测命令与真实返回 / 未完成项`
> 事实来源：`交付物/增量架构设计_赛题九差距补齐.md`、`交付物/增量PRD_赛题九差距补齐.md`、`_standards_factsheet_20261013.md`。
> 回滚：改动前备份在 `_patch/_backup_t9/`（17 文件），拷回即回滚。

（以下按任务追加）

## T03 检索引擎扩展（core/engine.py 收尾） / 已完成 / 1 文件
- 改动文件：`core/engine.py`（新增 ~55 行，改 4 处）。
- 具体改动：
  1. `search()` 新增 `sort == "priority"` 分支：用新增方法 `Engine._priority_score(i)` 求分
     （内部调 `core/priority.build()`，缺失/异常一律 0 排最后）；不影响其它排序。
  2. `facets` 增 `kind` 维度（来源 `knowledge` 条目 `d.get("kind")`）：在 `_facets` 与
     `_scan` 两处各加 `kind` 计数器；并把 `d["risk_subtags"]`（MCP Server / Agentic AI）
     计数**追加**进 `category` facet（只加法，不动既有键与顺序）。
  3. `_apply_filters`：新增 `kind` 过滤（`f["kind"]`）；`category` 过滤同时接受子类标签。
  4. `stats()` 新增 `kind_counts`（dict：kind→计数，计在 `self.docs` 上含运行期注入条目）。
  5. 新增模块级 `attach_subtags(engine)`（幂等，挂 `doc["risk_subtags"]`，不改 `category`）。
- 实测命令与真实返回：
  `./.venv/Scripts/python.exe -c "...SearchEngine._extract_ops('epss>=0.5')..."`
  → `[{'kind': 'epss', 'cmp': '>=', 'val': '0.5', 'neg': False, 'raw': 'epss>=0.5'}]`，text='' ⇒ 自检项「ops 里应有 kind="epss"」通过。
  `./.venv/Scripts/python.exe -m py_compile core/engine.py` → 通过（无语法错）。
- 未完成项：facets.kind 与 sort=priority 的端到端返回留待 T04 起服务后一并实测（见末条实测记录）。

## T04 服务接口扩展（core/server.py 收尾） / 已完成 / 1 文件
- 改动文件：`core/server.py`（新增 ~110 行，改 6 处）。
- 具体改动：
  1. 顶部 import 增 `attach_subtags`、`import priority as PRI`。
  2. `get_engine()` 调用新增 `ensure_runtime_fields(eng)`（挂 subtags + `PRI.attach_epss`，
     二者均 `swallow` 包裹）；第二处 `SearchEngine(CORPUS)` 同样调用。
  3. `/api/detail`：payload 增 `out["priority"] = PRI.build(d)`；异常兜底为**四键完整**的
     degraded dict（`cvss/epss/kev/reachability`），缺失置 `null` 并进 `missing[]`，不静默省略。
  4. 新增 `build_risk_overview(eng)`：赛题四类 E1~E4 计数 + `pct` + `severity_dist` +
      `top_products` + `poc_ratio` + `kev_ratio` + `mapping[]` + `reconcile{expected,actual,ok}`。
  5. 新增 `GET /api/health/live`：**置于 `/api/health`（依赖 get_engine）之前**，冷启动即返回
     `{"alive":true,...,"pid","uptime_sec","index_writable"}`；新增模块级 `_PIDFILE`。
  6. 新增路由 `GET /api/risk_overview`（在 `/api/search` 之后）。`/api/search` 的 filters 增
     `"kind": qs.get("kind", [])`，缓存键 `ckey` 增 `_fkey("kind")`。
- 未完成项：全部端到端返回留待末条「起服务实测」记录（含 priority 四键、risk_overview reconcile）。

## T05 EPSS 富化（m2_enrich） / 已完成 / 4 文件
- 新增/改动文件：
  - 新增 `modules/m2_enrich/backend/epss.py`（~290 行）：经 `core/httpcompat.py` 抓 FIRST EPSS，
    **不直接 import requests**。接口 `https://api.first.org/data/v1/epss?cve=...&limit=N`，公开免 key，
    返回 `{"data":[{"cve","epss","percentile","date"}]}`，`epss/percentile` 为 0~1 **字符串**。
    **成功判定用 2xx（含 202/206），非 `==200`**。缓存 `data/epss_cache.json`（字段固定
    `epss/percentile/date/fetched_at`），过期阈值默认 7 天（`config.epss_stale_days`）。
    **断网/失败降级**：`status="degraded"`，HTTP 仍 200，缓存不清空。`default_cves()` 从 KEV 缓存取
    CVE（数百条）分批（batch=100）抓取、批间 sleep 0.2s 预热缓存。
  - 改 `modules/m2_enrich/backend/enrich_dims.py`：`ENRICH_DIMENSIONS` 增
    `{"key":"epss","label":"EPSS 利用概率",... "data_file":"epss_cache.json","count_kind":"json_sub_len"}`
    + 新增 `_count_json_sub_len()` 并注册进 `_COUNTERS`（`enrich_dimensions()` 增对应分支，真实计数）。
  - 改 `modules/m2_enrich/api.py`：新增 `handle_enrich_priority`（GET `/api/enrich/priority?id=`）、
    `handle_epss_refresh`（POST `/api/enrich/epss/refresh`），并在 `register()` 注册。
  - 改 `modules/m2_enrich/module.json`：routes 增上述三条（含 dimensions）。
- 未完成项：EPSS 实网抓取 / dimensions 端到端返回留待末条实测记录。

## T06 源健康与缺失告警（m1_monitor） / 已完成 / 3 文件
- 新增/改动文件：
  - 新增 `modules/m1_monitor/backend/source_health.py`（~430 行）：逐源记账到
    `data/source_health.json`。字段 `last_success_at/last_item_at/expected_interval/
    consecutive_failures/items_24h/items_7d_avg/state`；`state ∈ {ok,degraded,stale,disabled,unknown}`。
    判定：`now-last_item_at > k×expected_interval`（k 默认 3，`config.source_health_stale_k`）
    或 `items_24h==0 且 hist avg>0` ⇒ `stale`；`items_24h < hist avg×0.3` ⇒ `degraded`。
    **源清单取自 `live.py` 静态源表**（`BLOG_FEEDS`/`BLOG_FEEDS_PROXY_ONLY`/`ARXIV_RSS`/`SOURCES`），
    非 `/api/live` 的 `feed_total`；首轮前返回全部源、`state="unknown"`。复用 `live.src_health()`
    作为"本轮输入"，经 `record_poll(...)` 落账。**告警去重：同源同态仅状态变化时写一次**至
    `data/alerts.jsonl`（复用 `core/alert_log.py`；`expected_interval` 用**自然发布节奏**
    RSS=86400/快源=3600，避免把"轮询间隔"误当"发布节奏"造成 44 条假 stale）。
  - 改 `modules/m1_monitor/backend/live.py`：`_poll_once_inner` 内（`meta["feed_fail"]` 赋值后）
    调 `source_health.record_poll(_ok_all,_err_all,per_src)`；**未动 `_CN_FAIL` 退避与轮询节奏**。
  - 改 `modules/m1_monitor/api.py`：`live_status()` 增 `stale_sources[]`（键必存在）；新增
    `handle_source_health`/`handle_coverage_gaps`；注册 `GET /api/source_health`、`GET /api/coverage_gaps`。
  - 改 `modules/m1_monitor/module.json`：routes 增上述两条。
- `core/circuit.py`：设计要求"持续 stale 强制重连"只加最小入口点——**因时间受限本期跳过并记录**
  （现有熔断语义保持不变，见末条「未完成项」）。
- 未完成项：source_health 首轮前应为全 unknown、覆盖缺口清单——留待末条实测记录。

## T07 标准/法规接口与运行期注入（m1_monitor） / 已完成 / 2 文件
- 改动文件：
  - `modules/m1_monitor/api.py`：新增 `GET /api/standards`（`q`/`kind`/`region`/`status`/`size`）、
    `POST /api/standards/refresh`；新增 `_start_standards(core)` 于 `ctx.on_start`/`start()` 末尾调用
    `core.standards_kb.inject(engine)` 做**运行期合并**（内部 `engine.add_documents(items)` + 清检索缓存），
    **绝不写 `data/corpus.json`**。刷新线程：`on_start` 启动、**后台 + 首延 ≥60s + 默认 24h 间隔**，
    不阻塞启动；源判定 **2xx 即成功**；**ISO(`iso.org`) 返回 403 属预期反爬 → 归入 `skipped_blocked[]`
    而非 `failed[]` 且不告警**。
  - `modules/m1_monitor/module.json`：routes 增 `GET /api/standards`、`POST /api/standards/refresh`。
- `config.json`：`standards_enabled`(true)、`standards_auto_refresh_hours`(24)、`epss_stale_days`(7)、
  `source_health_stale_k`(3) + 中文 `_说明` —— 前位工程师已置入，核对在位、无需改动。
- 未完成项：standards 接口返回、startup 注入是否生效——留待末条实测记录。

---

## 起服务实测记录（PID 33936 · 端口 8848 · uptime 记录时 96.6s） / 全部通过
- 启动命令：`cd "…/aisec-D_2.0" && NO_PROXY=127.0.0.1,localhost PYTHONDONTWRITEBYTECODE=1 ./.venv/Scripts/python.exe -B core/server.py 8848 > /tmp/aisec_8848.log 2>&1`
- 启动日志关键行（证明 T07 生效）：
  - `标准/法规知识底座：运行期注入 60 条（…\data\standards_kb.json；未写 corpus.json）`
  - `标准/法规采集：每 24 小时一轮增量比对（后台低频，首次延迟 ≥60s）`
  - `索引就绪：50.3s（索引缓存）` · `文档 108341 条 / 词项 634701 个 / 论文 317 篇`
  - `[LocalEmbedder] 加载失败，向量检索降级为纯 BM25：ModuleNotFoundError: No module named 'torch'`（预期：本机无 torch）

### 1) GET /api/health/live（冷启动探活，置于 get_engine() 之前）
真实返回：
```json
{"alive": true, "status": "alive", "version": "2.3", "pid": 33936,
 "uptime_sec": 96.6, "pidfile": "E:\\…\\data\\aisec_server.pid",
 "engine_loaded": true, "index_writable": true, "ts": "2026-10-13T21:56:08"}
```
说明：`pid`/`uptime_sec`/`index_writable` 三键齐备，`alive=true`。处理器在分发链位于
`get_engine()`（server.py:1028）之前的 938 行，自身不触达引擎。**诚实补充**：`main()` 是
「先 `get_engine()`（1575 行）后 `bind`（1627 行）」，故端口绑定前（0~96s 语料加载期）
任何端点都不可达；绑定一旦完成，本端点即在不等待引擎的前提下立即返回存活。

### 2) GET /api/standards?size=3（T07）
真实返回（截断）：`{"ok": true, "total": 60, "all_total": 60,
"counts": {"技术标准": 27, "政策法规": 30, "行业规范": 3, "供应链合规": 0}, "items": [
{"id":"REG:AGENT-GOV-OPINIONS","kind":"政策法规","title":"《智能体规范应用与创新发展实施意见》",…},
{"id":"REG:AI-LABELING-MEASURES","kind":"政策法规","title":"《人工智能生成合成内容标识办法》",…}]}`

### 3) GET /api/risk_overview（T04）—— reconcile.ok=true
真实返回（关键字段）：`{"ok": true, "categories": [
{"exam_id":"E1",…,"count":3238,"pct":10.09,…},
{"exam_id":"E2",…,"count":8027,"pct":25.02,…},
{"exam_id":"E3",…,"count":13324,"pct":41.53,…},
{"exam_id":"E4",…,"count":7493,"pct":23.36,…}],
"mapping":[…4 条 E↔①~④…],
"reconcile": {"expected": 32082, "actual": 32082, "ok": true}}`
四类合计 32082 = `/api/stats` 的 AI 四类计数（32082），故 `ok=true`；远超基线 ①414/②741/③1139/④538
（语料运行期只增不减，断言按「≥基线」满足）。

### 4) GET /api/source_health（T06）—— 首轮前全 unknown，首轮后正确落态
- 首轮前：`total=57 · rounds=0 · first_round_done=False`，
  `summary={"ok":0,"degraded":0,"stale":0,"disabled":0,"unknown":57,"alerts_total":0}`
- 首轮后：`total=57 · rounds=3 · first_round_done=True`，
  `summary={"ok":45,"degraded":0,"stale":3,"disabled":0,"unknown":9,"alerts_total":3}`
- 每条字段完整，示例：`{"source":"Trail of Bits","channel":"blogs","expected_interval":86400,
  "last_success_at":"…","last_item_at":"…","consecutive_failures":0,"items_24h":0,
  "items_7d_avg":0.0,"state":"unknown/ok","stale_for_sec":0,"alerts_total":0,"last_error":""}`

### 5) GET /api/coverage_gaps（T06）
真实返回：`{"ok": true, "count": 0, "gaps": [], "generated_at": "2026-10-13T21:56:21"}`

### 6) GET /api/live → stale_sources 键存在（T06）
`has_stale_sources=True`，`stale_sources=["Google 安全博客","GitLab","The Hacker News"]`
（这三源确实停更至 10-06，判 stale 合理）。

### 7) GET /api/enrich/dimensions（T05）—— 计数真实
- `dimension_count=14`（ENRICH_DIMENSIONS）+ `association_count=3`（ASSOCIATION_LAYERS）= **17**
  （基线 16 = 13 维 + 3 关联；加 epss 后 17，与预期一致）。
- `epss` 维度项：`{"key":"epss","label":"EPSS 利用概率","data_file":"epss_cache.json",
  "count_kind":"json_sub_len","count_field":"scores","count":null,"data_file_exists":false}`（缓存未建时）；
  建缓存后 `"count":800,"data_file_exists":true` ⇒ `_COUNTERS` 真实计数生效。

### 8) POST /api/enrich/epss/refresh（T05）
真实返回：`{"ok": true, "status": "ok", "fetched": 800, "merged": 800, "cached": 800,
"count": 800, "checked": 800, "fetched_at": "2026-10-13T21:58:20", "errors": [],
"attached": 214}` → 落盘 `data/epss_cache.json`（94KB）。
缓存结构核实：`{"meta":{"fetched_at":"…","source":"FIRST EPSS","count":800},
"scores":{"CVE-2026-9586":{"epss":0.18979,"percentile":0.97244,"date":"2026-10-12","fetched_at":"…"}}}`
⇒ 字段固定 `epss/percentile/date/fetched_at`，值 0~1。

### 9) GET /api/enrich/priority?id=CVE-2026-94127（T05）
- 缓存未建时：`{"cvss":9.3,"epss":null,"kev":true,"reachability":"unknown","score":52,"level":"P0",
  "missing":[{"field":"epss","why":"无网且无缓存"},{"field":"reachability","why":"无暴露面测绘结果"}]}`
- 建缓存后：`{"cvss":9.3,"epss":0.02226,"kev":true,"reachability":"unknown","score":53,"level":"P0",
  "missing":[{"field":"reachability","why":"无暴露面测绘结果"}]}`
⇒ 四键 `cvss/epss/kev/reachability` **完整**，缺失置 `null` 并进 `missing[]`，不静默省略。

### 10) GET /api/detail?id=CVE-2026-94127（T04）—— priority 四键完整
`has_priority=True`，`priority_keys=['cvss','epss','kev','level','missing','reachability',
'reason','score','status']` ⇒ 四元组键齐备。

### 11) GET /api/search?q=epss>=0.5（T03）
真实返回：`total=104`；`facets_keys=['category','severity','scope','source','year','product','cwe','kind']`
⇒ **facets 增了 `kind` 维度**。（结构化算子 `epss>=0.5` 过滤生效：104 条命中。）

### 12) GET /api/search?q=mcp server → 子类计数并入 category facet（T03）
`category_facet_top` 含既有 ①~⑪；`subclass_present=[["Agentic AI",2828],["MCP Server",972]]`
⇒ `RISK_SUBCATEGORIES` 子类计数**加法合并**进 category facet，未动既有键与顺序。

### 13) GET /api/search?kind=技术标准 / ?kind=政策法规（T04 kind 过滤）
- `q=安全&kind=技术标准` → `total=16`，首条 `STD:CN-AI-EMERGENCY-GUIDE-DRAFT | kind=技术标准`
- `q=人工智能&kind=政策法规` → `total=13`，首条 `REG:CNNVD-AIVD | kind=政策法规`

### 14) GET /api/search?q=ISO/IEC 42001（T07 运行期注入可检索）
真实返回：`total=54`，**首条** `STD:ISO-42005 | kind=技术标准 | ISO/IEC 42005:2025 人工智能系统影响评估`
（第 2/3 条为 `STD:ISO-23894`、`STD:ISO-42001`，均 `kind=技术标准`）⇒ 注入的 60 条标准/法规
**无需重写 corpus.json 即可被检索**（判据用首条 id 前缀/kind，未用 OR 语义的 total）。

### 15) GET /api/search?sort=priority（T03 排序）
`q=AI&sort=priority&size=8` → 逐条回查 `/api/enrich/priority` 得
`95,94,94,90,87,87,79,78`（严格非增），全 P0/KEV ⇒ 按 priority 分降序；无分/异常项排最后不抛异常。

### 16) GET /api/stats → kind_counts（T03）
`kind_counts` 存在，含注入标准：`"技术标准":27, "政策法规":30, "行业规范":3`（+ 各来源 kind）。

### 17) core/self_test.py 8848 结果
```
结果：通过 89 / 失败 3
失败项：
  - ③ 交付物存在：测试报告/检索评测.md
  - ③ 交付物存在：测试报告/POC覆盖率对比.md
  - v2.2 深度层·条件链降噪过滤
```
⇒ 3 项失败**与本改造无关**（前位已知短板，按批示不修）。新增路由在自检的
「模块1/模块2 已接入」清单中均出现（source_health/coverage_gaps/standards/standards/refresh；
enrich/priority、epss/refresh），无回归。

### 未完成项（如实）
- `core/circuit.py` 「持续 stale 强制重连」最小入口点：**本期因时间受限跳过**（现有熔断语义未改）。
- 未做前端（按要求不做）。
- `/api/search` 结果项投影不含 `epss`/`priority` 字段（属既有结果模板，非本次改动范围）；
  epss/priority 经 `/api/detail` 与 `/api/enrich/priority` 完整暴露。

### 收尾：严格合规微调 + 重启复核（最终交付物 = 已测产物）
- 微调 `modules/m2_enrich/backend/epss.py` 的 import 块：删除 `except: import requests` 兜底，
  改为 httpcompat 不可得即 `_http=None`（彻底落实硬约束「不直接 import requests」）。
  `py_compile` 通过；独立 import 冒烟：`stale_days=7`、`get_epss("CVE-2026-94127")=0.02226`、
  `status={'source':'FIRST EPSS','count':800,'stale':False,'status':'ok'}`。
- 重启服务（新 PID 35264，就绪 ~126s，日志再现「运行期注入 60 条…未写 corpus.json」）后复核：
  - `/api/health/live` → `{alive:true, pid:35264, uptime_sec:188.7, index_writable:true}`
  - `/api/enrich/priority?id=CVE-2026-94127` → `cvss9.3/epss0.02226/kevtrue/reachability unknown/score53/P0`
  - `/api/enrich/dimensions` → `dimension_count=14 · association_count=3 · epss.count=800 · exists=true`
  - `/api/risk_overview` → `reconcile={expected:32082, actual:32082, ok:true} · mapping=4`
  - `/api/search?q=ISO/IEC 42001` 首条 → `STD:ISO-42005 | 技术标准`

## 全局一致性审查（跨文件） / IS_PASS: YES
- 公共 API 齐备：`priority.build/attach_epss/priority_level`、`epss.get_epss/refresh/status/
  default_cves/stale_days`、`source_health.record_poll/snapshot/coverage_gaps/stale_sources/
  static_sources/judge_state`、`standards_kb.inject(engine,clear_cache=None)/build_all`、
  `engine.add_documents` —— 调用点与定义一一对应，无悬空引用。
- 枚举/字段一致：`STATES=("ok","degraded","stale","disabled","unknown")`；`priority.build`
  返回 `cvss/epss/kev/reachability/score/level/reason/status/missing`，`/api/detail` 降级兜底
  dict 同四键（不静默省略）；epss 缓存字段 `epss/percentile/date/fetched_at` 一致。
- 路由一致：`module.json`（m1/m2）routes 与 `register()` 实注册、与自检「模块已接入」清单
  三方一致；前缀无冲突（`/api/...`）。
- 无循环依赖：m2→core.priority/core.paths/core.httpcompat；m1→core.standards_kb/core.alert_log；
  core.engine/server 仅在运行期按需 import，未反向依赖模块。
- 结论：**IS_PASS: YES**。
