# 情报问答模块（模块3）前端对接说明

## 接口地址
`POST http://127.0.0.1:8848/api/chat`

## 请求参数（JSON Body）
```json
{
  "q": "用户的问题，比如：最近vLLM有哪些高危漏洞",
  "history": [
    {"role": "user", "content": "上一个问题"},
    {"role": "assistant", "content": "上一个回答"}
  ],
  "base_url": "LLM接口地址，可选，用户在设置页填",
  "api_key": "LLM API Key，可选，用户在设置页填",
  "model": "模型名称，可选，用户在设置页填"
}
```

**参数说明**：
- `q`：必填，用户提问的文本
- `history`：可选，多轮对话历史，最近的放最后，最多传最近6条（3轮对话）
- `base_url` / `api_key` / `model`：可选，用户自己配置的LLM参数，不填就用系统默认的（演示用）

## 返回格式
```json
{
  "answer": "给用户看的回答文本，带CVE编号引用",
  "sources": [
    {
      "id": "CVE-2024-1234",
      "title": "漏洞标题",
      "cvss": 8.1,
      "severity": "HIGH"
    }
  ],
  "used_llm": true
}
```

**字段说明**：
- `answer`：回答内容（Markdown 全文：结论 + 资料清单），向后兼容，旧前端直接渲染也不出错
- `sources`：引用的漏洞列表，旧契约（评测脚本在读），保留
- `used_llm`：true=用了大模型生成，false=用了模板模式（没配LLM时降级）

### v2.4 新增：结论 + 原始详细资料

```json
{
  "conclusion": "**直接给出的结论**（上限 3600 字，超出截断并标注）",
  "conclusion_chars": 934,
  "conclusion_limit": 3600,
  "conclusion_truncated": false,
  "evidence": [
    {
      "id": "CVE-2021-22893",
      "title": "Pulse Connect Secure 9",
      "type": "vulnerability",
      "cvss": 10.0,
      "severity": "CRITICAL",
      "published": "2021-04-23",
      "products": ["connect_secure"],
      "cwe": ["CWE-287", "CWE-416"],
      "exploited": true,
      "poc_count": 0,
      "sources": ["NVD", "CISA KEV"],
      "trust_label": "官方权威",
      "confidence": 83.8,
      "category": "⑨ 身份与访问管理",
      "summary": "一句话摘要（约 180 字）"
    }
  ],
  "evidence_total": 8
}
```

- `conclusion`：**结论先行**的正文，上限 3600 字（`qa/config.py` 的 `ANSWER_CONFIG.conclusion_limit`，
  可用环境变量 `AISEC_QA_CONCLUSION_LIMIT` 覆盖）。模板模式下它由两层拼成（LLM 模式下就是模型答案，
  同样受上限约束）：

  | 层 | 产出模块 | 回答的问题 | 内容 |
  |---|---|---|---|
  | ① 结论（内容要点） | `qa/content_answer.py` | 资料**说了什么** | 直答句 + 编号要点，逐条标注来源编号 |
  | ② 情报汇总（来源与风险统计） | `qa/report.py::summarize()` | 这批资料**是什么** | 命中数 / 风险分布 / KEV / POC / 最高 CVSS / 组件与弱点分布 / 时间跨度 / 处置优先级 |

  **① 内容要点（v2.5 新增）**：把命中资料的内容当唯一素材做**抽取式**归纳 ——
  清单式正文（`desc` 里的 `(1)(2)(3)`）按条款拆成要点；同一资料的多句正文归并为一个要点；
  CVE/仓库类条目正文是英文时，回访 `/api/detail` 取中文 `remediation` 作"处置"要点
  （跨条目重复的模板句合并成一句「共性处置」）。硬约束：只用原文片段（只做断句与标点清理）、
  每条带来源编号、不满足相关性闸门就整段不出现（宁可少说，不编）。因此**同一问题的 conclusion
  可能只有②没有①** —— 那是素材不足，不是漏渲染。
- `evidence`：**原始详细资料**清单（默认最多 12 条，可用 `AISEC_QA_EVIDENCE_LIMIT` 覆盖）。
  每条自带关键字段与摘要；点开详情由前端懒加载 `GET /api/detail?id=<编号>` 补齐全文。
- `evidence_total`：证据池去重后的总条数（可能大于 `evidence` 长度）。
- 兼容性：两条路径（智能体 / 多跳+生成器）的答案都经 `qa/report.py::finalize()` 收口，
  缺字段自动补齐；老前端只读 `answer` / `sources` 也照常工作。
- 前端渲染约定：conclusion 里的编号（`CVE-` / `GHSA-` / `DSKB:` / `CSDN:` / `XZ:` / `AQK:` /
  `GH-PROJ:`）会被渲染成可点按钮，点击即打开该条情报详情；编号列表按 `<ol>` 渲染（续行归入同一项）。

## 错误返回
```json
{
  "error": "错误信息",
  "answer": "系统暂时繁忙，请稍后再试",
  "sources": [],
  "used_llm": false
}
```
HTTP状态码：400=参数错，500=服务异常

## 多轮对话示例
1. 用户问："CVE-2024-1234影响什么？"
   请求body：`{"q": "CVE-2024-1234影响什么？"}`
2. 后端返回answer，前端把这个问答加到history里
3. 用户追问："那它怎么修？"
   请求body：
   ```json
   {
     "q": "那它怎么修？",
     "history": [
       {"role": "user", "content": "CVE-2024-1234影响什么？"},
       {"role": "assistant", "content": "...刚才的回答..."}
     ]
   }
   ```

## 设置页建议
前端做个简单的设置弹窗：
- LLM供应商下拉（DeepSeek/豆包/通义/自定义）
- API Key输入框（密码类型）
- 模型名称输入框
- 保存后存在localStorage里，每次请求带上这三个参数
