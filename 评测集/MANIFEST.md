# 标注评测集 v1

- 生成时间：2026-10-08T12:54:13
- 样本量：300（随机种子 20261008，同种子可复现）
- 文件指纹（sha256 前 16 位）：`d44f9bde5ce44460`
- 真值源：`data/nvd_cache.json`（NVD 官方 API 原始响应，池 36293 条）
  + `data/kev_snapshot.json`（CISA KEV 官方 JSON，1734 条）

## 有权威真值的维度

- `cvss`
- `severity`
- `cwe`
- `kev`
- `products`

## 明确不标注的维度（避免伪标注）

- `paper_relevance`：论文与漏洞的相关性无权威判定源，需人工标注，本版本不生成（评测时只报覆盖度，不报准确率）
- `qa_answer_quality`：答案质量无唯一正解，本版本只做时延与召回评测
- `assets_exposure`：资产暴露与否依赖企业自身资产台账，不在语料范围

> 变更标注集请新建版本（`--version v2`），不要覆盖旧版本 ——
> 评测分数只在同一版本内可比。
