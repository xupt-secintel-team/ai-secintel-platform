# POC / EXP 抓取精度评测（优化前 vs 优化后）

- 生成时间：2026-10-20 21:45:45　·　服务：http://127.0.0.1:8848
- 模式：快速（仅离线武器化源）
- 样本：3 个 CVE 有结果 / 共 6 个；结果集 11 条

## 一、结论

| 指标 | 优化前（旧排序规则） | 原始抓取顺序（参考） | 优化后（分级重排） | 变化 |
|---|---|---|---|---|
| 精度 @3 | 100.0% | 100.0% | **100.0%** | +0.0 |
| 精度 @5 | 100.0% | 100.0% | **100.0%** | +0.0 |
| 精度 @10 | 100.0% | 100.0% | **100.0%** | +0.0 |

「优化前」= 上一版排序规则（相关性评分降序 → 综合得分 → star），**同一批抓取结果、同一套外部判据**，
只改排序，所以差异全部来自本次优化；「原始抓取顺序」是各数据源返回的先后顺序，仅作参考。

## 二、逐 CVE 明细

| CVE | 结果数 | 判为相关 | 分级分布 | @3 前→后 | @5 前→后 | @10 前→后 |
|---|---|---|---|---|---|---|
| CVE-2024-37032 | 1 | 1 | A:1 | 100.0% → 100.0% | 100.0% → 100.0% | 100.0% → 100.0% |
| CVE-2021-44228 | 9 | 9 | A:9 | 100.0% → 100.0% | 100.0% → 100.0% | 100.0% → 100.0% |
| CVE-2025-15063 | 0 | — | — | — | — | — |
| CVE-2026-26190 | 1 | 1 | A:1 | 100.0% → 100.0% | 100.0% → 100.0% | 100.0% → 100.0% |
| CVE-2026-81265 | 0 | — | — | — | — | — |
| CVE-2026-41486 | 0 | — | — | — | — | — |

## 三、Top-5 顺序对照（看噪声是否被压下去）

### CVE-2024-37032（受影响组件：ollama）

| # | 优化前 | 优化后 |
|---|---|---|
| 1 | Ollama Model Registry Path Traversal RCE | Ollama Model Registry Path Traversal RCE |
| 2 | — | — |
| 3 | — | — |
| 4 | — | — |
| 5 | — | — |

### CVE-2021-44228（受影响组件：6bk1602-0aa12-0tp0_firmware, 6bk1602-0aa22-0tp0_firmware, 6bk1602-0aa32-0tp0_firmware, 6bk1602-0aa42-0tp0_firmware, 6bk1602-0aa52-0tp0_firmware, active_iq_unified_manager, advanced_malware_protection_virtual_private_cloud_appliance, automated_subsea_tuning, broadworks, brocade_san_navigator, business_process_automation, capital）

| # | 优化前 | 优化后 |
|---|---|---|
| 1 | MobileIron Core Unauthenticated JNDI Injection RCE (via Log4Shell) | MobileIron Core Unauthenticated JNDI Injection RCE (via Log4Shell) |
| 2 | Log4Shell HTTP Header Injection | Log4Shell HTTP Header Injection |
| 3 | UniFi Network Application Unauthenticated JNDI Injection RCE (via Log4Shell) | UniFi Network Application Unauthenticated JNDI Injection RCE (via Log4Shell) |
| 4 | VMware vCenter Server Unauthenticated JNDI Injection RCE (via Log4Shell) | VMware vCenter Server Unauthenticated JNDI Injection RCE (via Log4Shell) |
| 5 | Apache Log4j2 Remote Code Injection (critical) | Apache Log4j2 Remote Code Injection (critical) |

### CVE-2026-26190（受影响组件：milvus）

| # | 优化前 | 优化后 |
|---|---|---|
| 1 | Milvus - Unauthenticated Metrics API Access (critical) | Milvus - Unauthenticated Metrics API Access (critical) |
| 2 | — | — |
| 3 | — | — |
| 4 | — | — |
| 5 | — | — |

## 四、判据与口径

- 真值标签由**评测脚本独立实现**（来源属于武器化/模板库、仓库名或抓到的代码含目标 CVE 编号、
  仓库名/描述带 PoC 类关键词且提到受影响组件），**不读取模块给出的 `match_tier`**，因此不是自证。
- 官方组件仓库（如 `ollama/ollama`、`open-webui/open-webui`）无论多热门都判为**不相关**：
  它们是「受影响组件本身」，不是利用代码；模块里被单独分级（D），前端默认折叠。
- 「快速搜索」不含 GitHub，故该模式下相关条数天然偏少（离线源本身都是武器化材料，精度接近 100%）。
- 抓取结果受 GitHub 速率限制影响，重复运行的条数会有波动；**同一轮内的前/后对比**才是本报告的结论依据。
