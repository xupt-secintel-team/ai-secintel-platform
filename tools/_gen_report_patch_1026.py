# -*- coding: utf-8 -*-
import io, sys, shutil, os
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from docx import Document
from docx.shared import Pt

SRC = r"AI-SecIntel_竞赛技术报告.docx"
DST = r"AI-SecIntel_竞赛技术报告_20261026.docx"
doc = Document(SRC)

def repl_para(p, old, new):
    if old not in (p.text or ""):
        return False
    for r in p.runs:
        if old in r.text:
            r.text = r.text.replace(old, new)
            return True
    full = (p.text or "").replace(old, new)
    if not p.runs:
        return False
    p.runs[0].text = full
    for r in p.runs[1:]:
        r.text = ""
    return True

changed = []
paras = doc.paragraphs
edits = [
    ("接入 48 个主流情报源", "接入 57 个注册情报源（48 个 RSS/社区源 + NVD/KEV/arXiv/OSV 等权威库通道）"),
    ("从 48 个源抓取原始数据", "从 57 个注册源抓取原始数据"),
    ("情报从 48 个源进入双通道采集", "情报从 57 个注册源进入双通道采集"),
    ("系统接入 48 个情报源，按类型分为五组", "系统接入 57 个注册情报源（48 个 RSS/社区源 + NVD/KEV/arXiv/OSV/GitHub 等），按类型分为五组"),
    ("归档源 48 个", "注册源 57 个"),
]
for old, new in edits:
    for p in paras:
        if repl_para(p, old, new):
            changed.append(old)

# 9.11 标题与正文：如实描述源健康状态
for p in paras:
    t = p.text or ""
    if t.strip().startswith("9.11  信息源健康检查"):
        repl_para(p, "（48 源）", "（57 源）")
        changed.append("9.11-heading")
    if t.startswith("系统对全部 48 个情报源做健康检查"):
        new_text = ("系统对 57 个注册源做健康检查，状态分三档并如实呈现：13 个正常（ok）、"
                    "38 个 stale（该源本轮没有新文章，不等于不可用）、6 个熔断（NVD/KEV/arXiv 的"
                    "快车道轮询受网络与限流限制，实际数据由 6 小时深度同步兜底）。深度同步成功后"
                    "回写源健康账本（source_health.mark_success），因此 last_success_at 反映真实产出；"
                    "快车道失败仍按 30s→60s→120s→300s 指数退避并回退上一轮快照，保证监测面不缩水。"
                    "（2026-10-26 修补：此前账本只记快车道，深度同步产出未回写，导致看板长期误报熔断。）")
        repl_para(p, t, new_text)
        changed.append("9.11-body")

# 表 27：论文关联准确率口径
for t in doc.tables:
    for row in t.rows:
        cells = row.cells
        if len(cells) >= 2 and (cells[0].text or "").strip() == "富化论文关联准确率":
            for p in cells[1].paragraphs:
                repl_para(p, "约 72%",
                          "三口径：构建期强特征 100% / 当前库复现 55% / 词面代理 65.3%（2026-10-26 复测，口径见附录 D）")
            changed.append("table-72")

# 附录 D
doc.add_paragraph("")
h = doc.add_paragraph("附　录 D　2026-10-26 修补与复测记录")
for r in h.runs:
    r.bold = True
    r.font.size = Pt(15)

def body(txt, bold=False):
    p = doc.add_paragraph(txt)
    if bold:
        for r in p.runs:
            r.bold = True
    return p

body("本节记录 2026-10-26 评分复核后所做的六项修补与其复测结果，正文中与之冲突的旧口径以本节为准。", True)
body("D.1 检索融合与相关度闸门。混合检索此前在混合候选池上无法计算 BM25 断层线，"
     "口语化提问会整池被清空：40 题实测 @10 仅 80.0%，低于纯关键词路 92.5%。修补后"
     "（混合池断层线 + 绝对分强信号 + 混合池 BM25 命中放行）复测 @1=92.5%、@3=95.0%、"
     "@5=95.0%、@10=95.0%、MRR=0.938，P50 1078 ms、P95 1590 ms；同批纯关键词路仍为 @10=92.5%。"
     "零命中诚实化不受影响：不存在术语、无关提问仍返回 0 条。")
body("D.2 多跳条件链。B 型题（在野利用 + 精确 CVSS、POC + 区间 + 实体）此前把 kev/poc 当软约束，"
     "答案混入不满足条件的 CVE。修补为「数值或实体条件同时存在时 kev/poc 转硬约束」，并把数值型"
     "CVSS 条件翻成引擎算子（cvss:10 / cvss>=9）；论文类问题直达详情（详情接口带 papers 字段），"
     "计数类问题交给新增的 count_intel 工具（取引擎 total，不再按命中列表条数估算）。"
     "13 题多跳复测：模板模式 84.6% → 100%，LLM/Agent 模式 69.2% → 100%，B 型两题在两种模式下均通过。")
body("D.3 问答时延。此前 LLM 深答 P50 9.1 s、P90 38.3 s（1,882 次真实日志）。修补三项："
     "① 意图快路扩面（实体+列表、单 CVE 属性、KEV/POC+实体/数值），省掉规划轮 LLM 往返；"
     "② 结果缓存（同题同模式 6 小时，时效题 10 分钟）；③ 启动预热向量库与检索引擎。"
     "复测四个典型问题为 5.1 s / 4.1 s / 4.1 s / 4.4 s；10 题复测中位 2.8 s、P90 7.7 s"
     "（未命中缓存的冷问 1.8–4.1 s，需多轮分析的概念题 7.6–7.7 s），同题重复命中缓存 2–3 ms。")
body("D.4 富化覆盖率。新增 GET /api/enrich/coverage，以漏洞类文档为分母逐维给覆盖率："
     "CVSS 98.2%、CWE 82.0%、受影响组件 77.3%、POC 链接 23.1%、内置修复建议 99.2%、"
     "KEV 标记 0.7%、关联论文 0.9%；按需维度缓存覆盖 EPSS 2.16%、受影响资产 0.16%、"
     "修复方案 0.09%、POC 实抓 0.06%。「维度全」与「覆盖全」从此分开陈述。")
body("D.5 源健康与实时流。深度同步成功后回写源健康账本（新增 mark_success），"
     "看板区分 ok / stale / 熔断三档语义；实时流写入按 id 去重（此前 5,486 行里 624 行重复），"
     "并在首次写入时加载已有 id 集合。")
body("D.6 复跑命令。py tools/评测检索.py --base http://127.0.0.1:8848；"
     "py tools/评测多跳推理.py --base http://127.0.0.1:8848；"
     "curl http://127.0.0.1:8848/api/enrich/coverage。")

doc.save(DST)
print("saved", DST, "changed:", changed)
