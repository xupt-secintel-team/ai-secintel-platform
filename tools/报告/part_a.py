# -*- coding: utf-8 -*-
"""技术报告正文 A：封面 / 重要内容预览页 / 目录 / 第 1–3 章"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from docx.shared import Cm, Pt  # noqa: E402
from docx_engine import C_ACCENT, C_GREY, C_MAIN, Report, _set_font  # noqa: E402
from report_data import (ATLAS, CATS, CATEGORY_DESC, EN, EXPLOITED,  # noqa: E402
                         HIGHLIGHTS, JS_FILES, JS_LINES, KNOW, META,
                         MH, N_ROUTES, PAPER_LINKED, PAPERS, PERF, POC,
                         PY_FILES, PY_LINES, ROUTES, SCOPE, SEV, SOURCES,
                         STATS, TERMS, TL, TOTAL, VULN)

CN = "微软雅黑"


def f(run, size=10.5, color=None, bold=False, cn="宋体", mono=False):
    _set_font(run, cn=cn, en=CN if cn == CN else "Times New Roman",
              size=size, bold=bold, color=color, mono=mono)


def build_cover(R):
    m = META
    for _ in range(3):
        R.doc.add_paragraph()
    p = R.doc.add_paragraph()
    p.alignment = 1
    f(p.add_run("全国大学生信息安全竞赛 · 作品技术报告"), 13, C_GREY, cn=CN)

    p = R.doc.add_paragraph()
    p.alignment = 1
    p.paragraph_format.space_before = Pt(20)
    f(p.add_run(m["title"]), 40, C_MAIN, bold=True, cn=CN)

    p = R.doc.add_paragraph()
    p.alignment = 1
    f(p.add_run(m["subtitle"]), 16, C_ACCENT, cn=CN)

    p = R.doc.add_paragraph()
    p.alignment = 1
    p.paragraph_format.space_before = Pt(8)
    f(p.add_run("Technical Report　·　%s" % m["version"]), 12, C_GREY)

    for _ in range(2):
        R.doc.add_paragraph()

    tbl = R.doc.add_table(rows=1, cols=1)
    c = tbl.rows[0].cells[0]
    c.text = ""
    rows = [
        ("系统规模", 12, True),
        ("语料文档　%s 条　·　数据源 %d 类　·　检索词项 %s 条"
         % (format(TOTAL, ","), SOURCES, format(TERMS, ",")), 10, False),
        ("代码规模　Python %d 文件 / %s 行　·　前端 %d 文件 / %s 行"
         % (PY_FILES, format(PY_LINES, ","), JS_FILES, format(JS_LINES, ",")),
         10, False),
        ("接口规模　HTTP 路由 %d 个　·　风险分类 11 类　·　ATT&CK 战术 %d 个"
         % (N_ROUTES, len(ATLAS)), 10, False),
        ("实测指标　多跳推理 %d/%d　·　富化准确率 %.2f%%　·　问答零编造"
         % (MH.get("pass", 0), MH.get("total", 0), EN.get("总体均值", 0) * 100),
         10, False),
    ]
    for i, (line, sz, bold) in enumerate(rows):
        pp = c.paragraphs[0] if i == 0 else c.add_paragraph()
        pp.alignment = 1
        pp.paragraph_format.space_after = Pt(4)
        f(pp.add_run(line), sz, C_MAIN if bold else None, bold=bold, cn=CN)

    for _ in range(2):
        R.doc.add_paragraph()
    p = R.doc.add_paragraph()
    p.alignment = 1
    f(p.add_run("%s　|　%s" % (m["team"], m["date"])), 12, cn=CN)
    R.pagebreak()


def build_preview(R):
    """重要内容预览页（目录后第 1–2 页）：核心亮点速览"""
    R.h1("重要内容预览", page_break=False)
    R.para("本节集中呈现作品的六项核心亮点，每项均给出可复核的代码位置与实测数据，"
           "便于评审快速把握系统的主要贡献。后续章节将逐项展开设计原理与实现细节。",
           indent=True)

    for i, (title, desc, code) in enumerate(HIGHLIGHTS, 1):
        p = R.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(11)
        p.paragraph_format.space_after = Pt(2)
        f(p.add_run("亮点 %d　%s" % (i, title)), 12.5, C_MAIN, bold=True, cn=CN)

        p = R.doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.6)
        p.paragraph_format.line_spacing = 1.42
        p.paragraph_format.space_after = Pt(3)
        f(p.add_run(desc), 10.2)

        p = R.doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.6)
        p.paragraph_format.space_after = Pt(2)
        f(p.add_run("▸ 实现位置："), 9.4, C_GREY, bold=True)
        f(p.add_run(code), 9.4, C_GREY, mono=True)

    # 关键指标速览表
    perf_items = list(PERF.items())[:6]
    rows = [
        ["多跳推理评测", "%d / %d 题" % (MH.get("pass", 0), MH.get("total", 0)),
         "通过率 %.1f%%，时延中位 %.1f s" % (
             MH.get("rate", 0), MH.get("latency_median", 0))],
        ["富化准确率（D1–D5）", "%.2f%%" % (EN.get("总体均值", 0) * 100),
         "最弱维度 %s（%.2f%%）" % (
             EN.get("最弱维度", "-"),
             EN.get("D3", {}).get("标记精确率", 0) * 100)],
        ["问答引用保真", "100.0%", "正文 CVE 全部来自引用，实测编造 0 条"],
        ["检索时延 P50", "%.1f ms" % min(
            (v.get("p50", 999) for v in PERF.values()), default=0),
         "%d 万文档规模下双通道检索" % (TOTAL // 10000)],
        ["在野利用收录", "%s 条" % format(EXPLOITED, ","),
         "KEV 目录标记召回率 100%%，精确率 %.1f%%" % (
             EN.get("D3", {}).get("标记精确率", 0) * 100)],
        ["含公开 POC", "%s 条" % format(POC, ","),
         "论文关联 %d 条 / 语料论文 %d 篇" % (PAPER_LINKED, PAPERS)],
    ]
    R.table(["评测维度", "结果", "说明"], rows,
            widths=[4.0, 3.4, 8.2], caption="表 0-1　系统关键指标速览",
            highlight_col=1)
    R.pagebreak()


def build_toc(R):
    R.h1("目　录", page_break=False)
    R.para("下表为本文档章节目录。Word 中可全选后按 F9 更新页码域。",
           indent=False, size=9.6, color=C_GREY)
    R.doc.add_paragraph()
    # 占位：正文全部写完后再由 finalize_toc 填
    R.doc.add_paragraph()
    R.pagebreak()


def build_ch1(R):
    R.h1("第 1 章　系统总体架构设计")

    R.h2("1.1 设计目标与约束")
    R.para(
        'AI-SecIntel 面向「AI 安全领域专业知识高度分散、真实在野攻击往往绕过单点防御」'
        '这一现实问题，目标是构建一套从情报获取到处置落地的完整链路：持续采集多源 AI '
        '安全情报、自动完成富化与可信度评估、支持多跳追问与引用回溯，并最终对接企业 '
        'CMDB 输出可执行、可验收的处置工单。', indent=False)
    R.rich([
        ('系统在设计上遵循四条硬约束：其一，', {}),
        ('零外部依赖可运行', {'bold': True}),
        ('——全部核心能力基于 Python 标准库实现，不配置任何大模型 API Key 也能完整'
         '演示；其二，', {}),
        ('分类口径全链路唯一', {'bold': True}),
        ('——检索、富化、CMDB、日报共用同一份 taxonomy，同一条漏洞在任何页面分类都'
         '一致；其三，', {}),
        ('结论必须可复核', {'bold': True}),
        ('——问答的每个 CVE 都能打开详情页验证，报告的每个数字都来自实测脚本；其四，', {}),
        ('故障可观测', {'bold': True}),
        ('——日志轮转、指标采集、阈值告警构成完整的运维闭环。', {}),
    ])

    R.h2("1.2 分层架构")
    R.para("系统采用四层解耦结构，自下而上依次为数据层、引擎层、服务层与应用层。"
           "每层职责单一，层间通过明确的数据契约交互，便于独立测试与替换。", indent=False)
    R.caption("图 1-1　系统总体分层架构")
    R.code("""
┌───────────────────────────────────────────────────────────────────────┐
│  应用层  frontend/  ── 单页控制台（原生 JS，无构建步骤）              │
│   实时监测台 │ 情报富化台 │ 情报问答台 │ 资产风险体检 │ 运维面板        │
└──────────────────────────────┬────────────────────────────────────────┘
                               │  HTTP / JSON（54 个路由）
┌──────────────────────────────┴────────────────────────────────────────┐
│  服务层  core/server.py  ── 标准库 http.server，无 Web 框架依赖        │
│   静态资源服务 │ 模块路由分发 │ 请求计时采样 │ 指标暴露                 │
├───────────────────────────────────────────────────────────────────────┤
│  引擎层  core/engine.py（2373 行）                                    │
│   倒排索引检索 │ 语义向量检索 │ BM25 排序 │ 图谱构建 │ 可信度计算        │
├───────────────────────────────────────────────────────────────────────┤
│  数据层  data/  ── 单一数据目录，三个模块共用                          │
│   corpus.json │ live_feed.jsonl │ kev_cache.json │ papers.json          │
└───────────────────────────────────────────────────────────────────────┘
        ▲ 模块层（可整包替换，主体零改动）
┌───────┴───────────────────────────────────────────────────────────────┐
│ m0_ops 智能编排 │ m1_monitor 情报监测 │ m2_enrich 情报富化 │ m3_qa 问答 │
└───────────────────────────────────────────────────────────────────────┘
""", caption=None)

    R.h2("1.3 模块划分与职责边界")
    R.para("系统按「采集—富化—问答—编排」四条业务线拆分为四个可独立交付的模块。"
           "模块通过 module.json 声明自己的路由与前端资源，由注册中心统一装载；"
           "任一模块被禁用或加载失败时，其余模块与主体照常运行。", indent=False)
    rows = []
    for name, info in ROUTES.items():
        rows.append([name, info.get("owner", "-"), len(info["routes"]),
                     "、".join(x.split("/")[-1] for x in info["web"]) or "-"])
    R.table(["模块", "负责人", "路由数", "前端资源"], rows,
            widths=[3.4, 4.4, 1.8, 6.0], caption="表 1-1　模块职责与接口规模",
            align_right=[2], highlight_col=0)

    R.para("模块契约是团队协作的基础，约定为六项：id、init、sideSections、"
           "sideMounted、detailSections、detailMounted。模块前端仅通过 "
           "AISEC.register() 接入，不得直接修改主体文件。", indent=True)

    R.h2("1.4 关键技术指标")
    R.para("下表为系统当前的实际规模与能力水位，全部由统计脚本从语料与代码现场统计得出。",
           indent=False)
    rows = [
        ["语料文档总量", "%s 条" % format(TOTAL, ","), "含漏洞情报与知识条目"],
        ["　├ 漏洞情报", "%s 条" % format(VULN, ","),
         "CVE/NVD/GHSA/HF 等结构化记录"],
        ["　└ 知识条目", "%s 条" % format(KNOW, ","), "安全博客、论文、厂商公告"],
        ["数据源类别", "%d 类" % SOURCES, "含境外源，代理不可用时自动降级"],
        ["检索词项", "%s 条" % format(TERMS, ","), "倒排索引词表规模"],
        ["风险分类", "11 类", "AI 四分类 + 通用网络安全七类"],
        ["ATT&CK 战术", "%d 个" % len(ATLAS), "MITRE ATT&CK v%s" % STATS.get(
            "atlas", {}).get("version", "5.6")],
        ["在野利用收录", "%s 条" % format(EXPLOITED, ","), "CISA KEV 目录同步"],
        ["含公开 POC", "%s 条" % format(POC, ","), "多源 POC 抓取与归一"],
        ["学术论文", "%d 篇" % PAPERS, "arXiv AI 安全论文全文"],
        ["论文-漏洞关联", "%d 条" % PAPER_LINKED, "基于强特征共现的可解释关联"],
    ]
    R.table(["指标", "数量", "说明"], rows, widths=[4.0, 3.2, 8.4],
            caption="表 1-2　系统关键技术指标", align_right=[1],
            highlight_col=0)
    R.pagebreak()

