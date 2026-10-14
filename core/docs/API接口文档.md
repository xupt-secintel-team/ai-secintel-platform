# AI-SecIntel 后端 API 接口文档 v2.2

> 服务地址：`http://127.0.0.1:8848`（端口可用启动参数覆盖）
> 所有接口返回 UTF-8 编码，支持 gzip 压缩和 CORS 跨域。
> v2.1 新增：`/api/chat`（情报问答）、`/api/live`（快车道实时监测，15s 节拍）、
> `/api/sources`（多源归档体量）、检索排序 `sort=trust`（可信度优先）。
> v2.2（aisec-D_1.3.2 合并版）新增：`/api/assets`（受影响资产定位）、
> `GET/POST /api/poc`（POC / EXP 搜索后台任务）。

---

## 一、接口总览

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/stats` | 语料库全局统计 |
| GET | `/api/search` | 自然语言检索（核心，支持 `sort=trust`） |
| GET | `/api/detail` | 单条情报全量详情 |
| GET | `/api/suggest` | 搜索框自动补全 |
| GET | `/api/latest` | 最新情报 feed |
| GET | `/api/corpus` | 轻量清单（离线筛选用） |
| GET | `/api/related` | 相关情报推荐 |
| GET | `/api/graph` | 情报关系图谱 |
| GET | `/api/credibility` | 可信度统计 |
| GET | `/api/export` | 导出 Markdown 报告 |
| GET | `/api/chat` | **[v2.1]** 情报问答（GET 简版） |
| POST | `/api/chat` | **[v2.1]** 情报问答（支持 history / 自定义 LLM 配置） |
| GET | `/api/live` | **[v2.1]** 快车道实时监测状态（15s 节拍） |
| GET | `/api/sources` | **[v2.1]** 多源归档体量 |
| GET | `/api/assets` | **[v2.2]** 受影响资产定位（NVD / LLM / CPE 三路提取） |
| GET | `/api/poc` | **[v2.2]** POC 搜索任务状态查询 |
| POST | `/api/poc` | **[v2.2]** 触发 POC / EXP 搜索（后台任务） |
| GET/POST | `/api/refresh` | 深度增量同步状态 / 触发同步 |

---

## 二、核心接口详情

### 1. GET /api/search —— 自然语言检索

**参数：**

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `q` | string | "" | 搜索词（自然语言，支持中英文与结构化算子） |
| `size` | int | 12 | 每页条数（最大60） |
| `page` | int | 1 | 页码 |
| `sort` | string | relevance | 排序：`relevance` / `risk`（CVSS） / **`trust`（可信度）** / `recent`（最新） |
| `expand` | 0/1 | 1 | 是否启用同义词扩展 |
| `scope` | string | | 情报范围（可多传）：AI安全 / 通用安全 |
| `severity` | string | | 严重度筛选（可多传）：CRITICAL/HIGH/MEDIUM/LOW |
| `category` | string | | 分类筛选（可多传） |
| `source` | string | | 来源筛选（可多传） |
| `exploited` | 0/1 | 0 | 仅看在野利用 |
| `poc` | 0/1 | 0 | 仅看有验证代码 |
| `paper` | 0/1 | 0 | 仅看有关联论文 |
| `cvss_min` | float | | 最低CVSS分数 |
| `year_from` | int | | 起始年份 |
| `year_to` | int | | 截止年份 |

**检索增强语法：**

```
gradio 漏洞                     自然语言
product:ollama severity:HIGH    结构化算子（-算子 取反）
cvss>=9 year:2024-2025 kev:yes  比较算子 / 区间
prompt* / *jail*                通配符（对索引词典展开）
-log4j -"remote code"           否定项（结果必须不含）
```

**返回结构：**

```json
{
  "query": { "raw": "gradio 漏洞", "intent": "漏洞检索", "terms": {}, "phrases": [], "ops": [] },
  "browse": false,
  "total": 42,
  "page": 1,
  "page_size": 12,
  "pages": 4,
  "elapsed_ms": 8.3,
  "answer": {
    "intent": "漏洞检索",
    "stats": {
      "total": 42,
      "critical_high": 5,
      "exploited": 1,
      "poc": 8,
      "papers": 3
    },
    "summary": ["..."],
    "plan": ["步骤1...", "步骤2..."]
  },
  "facets": {
    "severity": [["HIGH", 20], ["MEDIUM", 15]],
    "category": [["① AI基础设施与推理框架", 10]],
    "product": [["gradio", 42]],
    "source": [["NVD", 40]],
    "year": [["2024", 30]]
  },
  "results": [ /* 情报卡片，字段见下 */ ]
}
```

**results 单条字段（搜索卡片）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 情报编号（CVE-xxxx / GHSA-xxxx / DSKB:xxxx / ARXIV:xxxx） |
| `title` | string | 情报标题 |
| `cvss.score` | float/null | CVSS评分 |
| `cvss.severity` | string/null | 严重度：CRITICAL/HIGH/MEDIUM/LOW |
| `products` | string[] | 受影响组件 |
| `cwe` | object[] | 弱点类型（id + name，已过滤非 dict 脏元素） |
| `category` | string | 风险分类（①~⑪） |
| `scope` | string | 情报范围：AI安全 / 通用安全 |
| `published` | string | 发布日期（前 10 位） |
| `sources` | string[] | 数据来源 |
| `why` | string | 命中原因说明 |
| **可信度字段** | | |
| `trust_score` | int | 数据源可信度 0-100 |
| `trust_label` | string | 可信度等级：官方权威/厂商公告/学术支撑/社区来源 |
| `cross_count` | int | 独立来源数量 |
| `cross_label` | string | 交叉验证状态：三源交叉确认/双源交叉验证/单源情报(待验证) |
| `cross_verified` | bool | 是否多源验证（≥2 独立源） |
| `exploit_score` | float | 可利用性评分 0-10 |
| `exploit_label` | string | 可利用性等级 |
| `confidence` | float | 综合置信度 0-100（可信度50% + 交叉20% + 可利用性15% + 时效15%） |
| `freshness` | float | 时效因子 0.7-1.0 |
| `poc_count` / `patch_count` / `paper_count` | int | 验证代码 / 补丁 / 关联论文数量 |
| `atlas` | object[] | MITRE ATLAS 攻击技术（id + name） |
| `mitigation_count` | int | ATLAS 缓解措施数量 |
| `evidence` | object[] | 命中证据（term + weight） |
| `snippet` | string | 高亮片段（HTML） |

---

### 2. GET /api/detail —— 单条情报全量详情

**参数：** `id` = 情报编号

**返回：** 在搜索卡片基础上额外包含：

| 字段 | 说明 |
|------|------|
| `cvss.vector` | CVSS向量字符串 |
| `cvss.exploitability` | CVSS可利用性子分 |
| `cvss.impact` | CVSS影响子分 |
| `refs` | 完整参考链接（url + tags） |
| `patch_links` | 补丁链接 |
| `advisory_links` | 安全公告链接 |
| `atlas` | MITRE ATLAS攻击技术映射（id/name/tactics/description） |
| `atlas_mitigations` | ATLAS缓解措施 |
| `atlas_cases` | ATLAS 关联真实案例 |
| `papers` | 关联学术论文（title/authors/summary/url） |
| `cpe` | 受影响资产（厂商/产品/版本区间） |
| `remediation` | 修复建议列表 |
| `exploit_signals` | 可利用性评分信号明细 |
| `cross_sources` | 交叉验证各源详情 |

---

### 3. GET /api/related —— 相关情报推荐

**参数：** `id` = 情报编号

**返回（按关联维度分组，各组最多 6 条）：**

```json
{
  "source_id": "CVE-2024-XXXX",
  "source_title": "...",
  "top_overall": [
    {"id": "CVE-...", "rel_score": 5.6, "rel_reasons": ["共享组件:gradio", "同弱点:CWE-78"],
     "trust_label": "官方权威", "confidence": 91.2}
  ],
  "same_product": [], "same_cwe": [], "atlas_related": [], "same_category": [],
  "counts": {"same_product": 3, "same_cwe": 2, "atlas_related": 1, "same_category": 4}
}
```

> 实现说明：服务端按「组件 / 弱点 / 攻击技术 / 分类」建倒排候选桶（`graph_data.build_neighbor_index`），
> 只对命中桶打分，避免 8 万级语料下的全库扫描。

---

### 4. GET /api/graph —— 情报关系图谱

**参数：** `id` = 情报编号

**返回图数据（节点 + 边 + 分类）：**

```json
{
  "nodes": [{"id": "CVE-...", "name": "CVE-...", "kind": "vulnerability",
             "category": 0, "symbolSize": 55, "cvss": 9.8}],
  "links": [{"source": "CVE-...", "target": "CWE-78", "label": "弱点类型"}],
  "categories": [{"name": "漏洞情报"}, {"name": "弱点(CWE)"}, {"name": "受影响组件"},
                 {"name": "攻击技术(ATLAS)"}, {"name": "战术阶段"}, {"name": "验证代码"},
                 {"name": "缓解措施"}, {"name": "学术研究"}],
  "stats": {"nodes": 14, "links": 13}
}
```

> 控制台内置**内联 SVG 径向布局**渲染（零外部图表库依赖）；如需 ECharts，
> `nodes/links/categories` 与 ECharts `graph` 系列字段对齐，可直接 setOption。

---

### 5. GET /api/credibility —— 可信度统计

**参数：** 无

**返回：**

```json
{
  "trust_distribution": [["官方权威", 25000], ["厂商公告", 3000]],
  "cross_distribution": [["双源交叉验证", 12000], ["单源情报(待验证)", 10000]],
  "exploit_distribution": [["无公开利用", 20000], ["中等可利用性", 3000]],
  "confidence_distribution": [["高置信(≥85)", 8000], ["中置信(65-84)", 15000]],
  "avg_confidence": 78.5,
  "high_confidence_count": 8000,
  "cross_verified_count": 12000
}
```

---

### 6. GET /api/export —— 导出报告

**参数：**
- `q` = 搜索词（可加 `size`，默认 30，最大 60）→ 导出该搜索结果的完整情报报告
- `id` = 情报编号 → 导出单条详情报告

**返回：** `text/markdown` 文件（带 Content-Disposition 下载头），浏览器直接触发下载。

搜索报告含六章：报告概要 / 风险总览 / 重点情报 / 情报明细 / 处置建议 / 来源免责。

---

### 7. GET /api/stats —— 全局统计

返回语料库总量、分类分布、来源分布、严重度分布、ATLAS统计、KEV/POC/论文计数等。

### 8. GET /api/suggest —— 自动补全

**参数：** `q` = 输入前缀

**返回：** `{"cves": [], "products": [], "terms": [], "cn_terms": []}`

### 9. GET /api/latest —— 最新情报

**参数：** `n` = 条数（默认14，最大60）

返回按发布/更新时间倒序的情报列表。

### 10. GET /api/corpus —— 轻量清单

返回全部情报的轻量字段（id/published/score/severity/category/products/exploited），
适合前端加载后做纯客户端筛选。

---

### 11. GET /api/live —— 快车道实时监测（v2.1）

**参数：** 无

**返回：**

```json
{
  "enabled": true,
  "interval": 30,
  "last_poll": "17:05:12",
  "last_ms": 4210,
  "last_batch": 3,
  "added_total": 128,
  "per_source": {"blogs": 2, "nvd": 1, "anquanke": 0},
  "age_sec": 12,
  "error": null,
  "recent": [{"id": "...", "title": "...", "source": "Snyk", "published": "2026-09-24", "ts": "17:05:12"}]
}
```

> 快车道每 `interval` 秒执行一轮：多源并行抓取 → 富化（挂可信度字段）→
> 增量入索引（不重建、不重启）。新信息公开后约 1 分钟内即可被检索到。
> `last_ms` 为上轮实际耗时，`age_sec` 为距上轮完成的时间，可用于观察真实节拍。

---

### 12. POST /api/chat —— 情报问答（v2.1）

**请求体：**

```json
{
  "q": "Ollama 有哪些高危漏洞？",
  "history": [{"role": "user", "content": "你好"}],
  "base_url": "https://api.openai.com/v1",
  "api_key": "sk-...",
  "model": "gpt-4o-mini"
}
```

`base_url` / `api_key` / `model` 均可省略——省略时按「环境变量 → qa/config.py」顺序取值；
全部缺失则自动降级为**模板模式**（答案完全由检索证据拼装，不调用大模型、不产生幻觉）。

**返回：** `{"answer": "...", "sources": [...], "used_llm": false, ...}`

> **[v2.4/v2.5]** 除 `answer` / `sources` 外，返回体还带结构化答案：
> `conclusion`（结论，≤3600 字）+ `conclusion_chars` / `conclusion_limit` / `conclusion_truncated`
> + `evidence[]`（原始详细资料，点开由 `/api/detail` 补全文）+ `evidence_total`。
> 模板模式下 `conclusion` 分两层：**① 结论（内容要点）** 由 `qa/content_answer.py` 从命中资料
> 正文/处置字段抽取编号要点（回答"资料说了什么"）；**② 情报汇总（来源与风险统计）** 由
> `qa/report.py::summarize()` 统计（命中数 / 风险分布 / 时间跨度 / 数据来源）。
> 详细字段说明见 `modules/m3_qa/docs/问答模块API.md`。

---

### 13. GET /api/sources —— 多源归档体量（v2.1）

**返回：**

```json
{
  "archive_dir": "D:/ai_sec_raw",
  "archive_total_gb": 6.42,
  "target_gb": 10,
  "channels": [{"key": "arxiv", "label": "AI 安全论文（arXiv，元数据 + PDF 全文）", "gb": 2.1}],
  "corpus": {"documents": 86704, "terms": 499557},   // 示例：实时值见 GET /api/stats
  "updated_at": "2026-09-24T17:05:12"
}
```

归档目录可用环境变量 `AI_RAW_DIR` 覆盖。

---

### 14. GET /api/assets —— 受影响资产定位（v2.2）

**参数：** `id` = 情报编号

**说明：** 从漏洞描述中提取受影响资产（厂商/产品/受影响版本/不受影响版本），
NVD API → DeepSeek LLM → CPE 字典三路提取合并去重，按置信度排序；命中缓存秒出。

**返回：**

```json
{
  "id": "CVE-2024-XXXX",
  "count": 3,
  "assets": [
    {"vendor": "ollama", "product": "ollama", "affected_versions": ["< 0.1.30"],
     "unaffected_versions": [">= 0.1.30"], "confidence": "high",
     "extraction_method": "nvd_api", "cpe": "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*"}
  ],
  "hint": "未配置 DeepSeek Key，LLM 提取路径已跳过（NVD 结果不受影响）"
}
```

> 未配置 DeepSeek Key 时自动跳过 LLM 提取路径，NVD / CPE 结果不受影响。

---

### 15. GET/POST /api/poc —— POC / EXP 搜索（v2.2）

**POST 参数：** `id` = CVE 编号；`quick` = 0/1（默认 1，快速搜索跳过 GitHub 慢路径）

**说明：** 由后台线程执行 poc_scraper.search_poc（Exploit-DB 本地镜像 / Metasploit /
PacketStorm / Nuclei / GitHub 多源搜索），同一 CVE 正在搜索或已出结果时直接返回现有任务。

**POST 返回：**

```json
{"started": true, "running": true, "id": "CVE-2024-XXXX", "quick": 1}
```

**GET 返回（轮询任务状态）：**

```json
{
  "id": "CVE-2024-XXXX",
  "running": false, "done": true, "quick": 1,
  "results": [
    {"title": "...", "url": "...", "source": "Exploit-DB", "poc_type": "exploit_code",
     "reliability": "高", "relevance_score": 0.95, "code_content": "...", "publish_date": "..."}
  ],
  "error": null
}
```

---

## 三、前端对接建议

### 3.1 可信度标识展示

| trust_label | 建议颜色 |
|-------------|---------|
| 官方权威 | 绿色/蓝色 |
| 厂商公告 | 青色 |
| 学术支撑 | 紫色 |
| 社区来源 | 橙色/灰色 |

`cross_label` 可作为小图标展示（多源=盾牌勾，单源=问号）。
控制台已按此实现：卡片上「◆ 可信度」「✔ 多源交叉」「高可利用性」三个徽标。

### 3.2 可利用性展示

`exploit_score`（0-10）可用进度条或星级展示：
- ≥8 红色（极高可利用性）
- 6-8 橙色（高可利用性）
- 3-6 黄色（中等）
- <3 灰色

### 3.3 关系图谱

控制台用内联 SVG 径向布局渲染，无需任何外部图表库：

```javascript
// 若改用 ECharts graph 系列：
echarts.init(dom).setOption({
  series: [{ type: 'graph', layout: 'force', data: res.nodes,
             links: res.links, categories: res.categories, roam: true }]
});
```

### 3.4 报告导出

直接用 `location.href = '/api/export?q=' + encodeURIComponent(q)` 即可触发下载；
控制台已在结果栏（导出检索报告）与详情抽屉（导出本条报告）提供入口。

---

## 四、风险分类编号对照

| 编号 | 分类 | 短标签 |
|------|------|--------|
| ① | AI基础设施与推理框架 | 推理框架 |
| ② | 模型与数据层 | 模型数据 |
| ③ | AI应用与智能体 | 应用智能体 |
| ④ | AI供应链与平台 | 供应链 |
| ⑤ | Web应用与API安全 | Web安全 |
| ⑥ | 系统与二进制安全 | 系统二进制 |
| ⑦ | 网络与协议安全 | 网络协议 |
| ⑧ | 云原生与容器安全 | 云原生 |
| ⑨ | 身份与访问管理 | 身份访问 |
| ⑩ | 恶意代码与威胁活动 | 恶意代码 |
| ⑪ | 数据安全与密码学 | 数据密码 |

---

## 五、数据来源说明

| 来源标识 | 名称 | 类型 |
|---------|------|------|
| NVD | 美国国家漏洞数据库 | 官方 |
| CISA KEV | 在野利用目录 | 官方 |
| GitHub Advisory / OSV/GHSA | 开源供应链安全公告 | 厂商 |
| arXiv | 学术论文 | 学术 |
| MITRE ATLAS | AI 对抗战术技术知识库 | 权威 |
| GitHub | 公开代码仓库 | 社区 |
| HuggingFace | 模型 / 数据集卡片 | 社区 |
| Snyk / Wiz / Unit42 / CISA / 微软 / AWS 等 | 厂商公告与安全博客 | 厂商 |
| CSDN / 安全客 / 先知 | 中文社区技术文章 | 社区 |
| 数据安全知识库 | 系统内置（法规/技术/AI 数据安全/案例） | 权威 |

---

*文档版本 v2.2 · 2026-09 · AI-SecIntel 合并增强版 aisec-D_1.3.2*

