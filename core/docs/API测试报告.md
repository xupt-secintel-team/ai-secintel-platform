# AI-SecIntel 后端测试报告
测试时间：2026-09-24 12:41:38
服务器：http://127.0.0.1:8848

## 1. 数据规模统计
- 总文档数：58227
- 漏洞情报：58210
- 数据安全知识库：17
- 论文数：21
- 在野利用(KEV)：464
- 含PoC/EXP：15877
- 索引词项：314928
- 响应时间：202ms

## 2. 检索功能测试（5条代表性查询）
### 查询：'prompt injection'（英文技术查询）
- 命中总数：6076，响应：76ms
- 检索意图：综合检索
  1. [CVE-2024-5565] The Vanna library uses a prompt function to present the user | CVSS=8.1(HIGH) | 可信度=官方权威 | 置信度=68.8
  2. [CVE-2025-36730] A prompt injection vulnerability exists in Windsurft version | CVSS=4.6(MEDIUM) | 可信度=官方权威 | 置信度=68.4
  3. [CVE-2024-12366] PandasAI uses an interactive prompt function that is vulnera | CVSS=9.8(CRITICAL) | 可信度=官方权威 | 置信度=69.2

### 查询：'log4j'（组件名查询）
- 命中总数：29，响应：20ms
- 检索意图：综合检索
  1. [CVE-2026-34479] The Log4j1XmlLayout from the Apache Log4j 1-to-Log4j 2 bridg | CVSS=6.9(MEDIUM) | 可信度=官方权威 | 置信度=72.2
  2. [CVE-2025-68161] The Socket Appender in Apache Log4j Core versions 2 | CVSS=6.3(MEDIUM) | 可信度=官方权威 | 置信度=72.2
  3. [CVE-2026-34481] Apache Log4j's JsonTemplateLayout https://logging | CVSS=6.3(MEDIUM) | 可信度=官方权威 | 置信度=72.9

### 查询：'数据安全法'（中文政策查询）
- 命中总数：17，响应：1ms
- 检索意图：综合检索
  1. [DSKB:REG01] 《中华人民共和国数据安全法》核心条款解读 | CVSS=None() | 可信度=其他来源 | 置信度=37.4
  2. [DSKB:TECH05] 数据安全审计与行为分析 | CVSS=None() | 可信度=其他来源 | 置信度=37.4
  3. [DSKB:AI01] AI训练数据安全风险与防护 | CVSS=None() | 可信度=其他来源 | 置信度=37.4

### 查询：'CVE-2024-5565'（CVE精确查询）
- 命中总数：1，响应：14ms
- 检索意图：综合检索
  1. [CVE-2024-5565] The Vanna library uses a prompt function to present the user | CVSS=8.1(HIGH) | 可信度=官方权威 | 置信度=68.8

### 查询：'machine learning adversarial attack'（英文学术查询）
- 命中总数：6809，响应：76ms
- 检索意图：综合检索
  1. [CVE-2026-31229] The Adversarial Robustness Toolbox (ART) thru 1 | CVSS=9.8(CRITICAL) | 可信度=官方权威 | 置信度=72.2
  2. [CVE-2026-44688] In Eclipse Theia versions prior to 1 | CVSS=8.4(HIGH) | 可信度=官方权威 | 置信度=69.2
  3. [CVE-2025-11281] A vulnerability has been found in Frappe LMS 2 | CVSS=1.3(LOW) | 可信度=官方权威 | 置信度=71.4

## 3. 关联推荐与图谱测试
以 CVE-2024-5565 为源节点测试：
- 关联推荐：top_overall=8条, same_product=0条, same_cwe=6条, atlas_related=0条
- 响应：240ms
- 关系图谱：nodes=4个, links=3条, categories=8类
- 响应：29ms

## 4. 可信度系统全局统计
- 平均置信度：70.2/100
- 高置信度条目：802
- 多源交叉验证条目：913
- 信任等级分布：[['官方权威', 58210], ['其他来源', 17]]
- 响应：61ms

## 5. 报告导出测试
- 状态码：200
- Content-Type：text/markdown; charset=utf-8
- 文件大小：10292 字符
- 下载文件名：attachment; filename="secintel_search.md"

## 6. 最新情报流测试
- 返回 5 条最新情报，响应 42ms
  - [CVE-2026-97055] 2026-09-24 | SigNoz from v0
  - [CVE-2026-96773] 2026-09-24 | A weakness has been identified in Intelliants Subr
  - [CVE-2026-93577] 2026-09-24 | GitLab has remediated an issue in GitLab CE/EE aff

## 7. 检索引擎评测结果（42条查询集）
| 架构 | P@5 | P@10 | R@20 | MRR@10 | nDCG@10 | 首条命中均位 | 零命中数 |
|------|-----|------|------|--------|---------|------------|---------|
| Full（词法+短语+概念+重排） | 0.7857 | 0.7429 | 0.2620 | 0.8579 | 0.7928 | 1.38 | 2 |
| - 去概念层 | 0.6762 | 0.6643 | 0.2352 | 0.7619 | 0.6965 | 2.18 | 4 |
| - 去概念层与术语扩展（纯BM25） | 0.4571 | 0.4381 | 0.1819 | 0.5024 | 0.4751 | 3.73 | 16 |

---
结论：全部API端点响应正常，数据完整，系统可交付。