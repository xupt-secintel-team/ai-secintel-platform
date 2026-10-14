# -*- coding: utf-8 -*-
"""按校内初赛作品提交要求，对技术报告 docx 做定点增补。

改动清单（对应提交要求十项）：
  A. 目录后插入「重要内容预览页」（核心亮点 + 指标看板 + 评审导航）  —— 硬性建议
  B. 2.2 节末插「图 2-1 系统总体架构图」                            —— 系统总体架构设计
  C. 新增 2.12 关键技术选型说明（表 2-3 选型对照）                 —— 关键技术选型说明
  D. 新增 2.13 系统工作流程图（图 2-2）                            —— 系统工作流程图
  E. 第 4 章：四智能体 → 六智能体（表 4-1 / 4.2 正文 / 审接口表述）
     新增 4.8 决策智能体、4.9 红蓝自博弈、4.10 处置闭环回填、4.11 溯源归因与多跳图谱
     并在 4.2 后插「图 4-1 六智能体工作流程图」                   —— 智能体方案设计
  F. 9.7 自测 78 项 → 92 项
  G. 第 10 章创新点由 5 个扩到 9 个
  H. 新增第 12 章「核心代码说明」（5 段源码 + 讲解）               —— 核心代码说明

用法： <py> tools/_patch_report.py
输出： D:\\111111\\备份\\AI-SecIntel_2.2_竞赛技术报告_终稿.docx
"""
import copy
import os
import sys

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from docx.table import Table
from docx.text.paragraph import Paragraph

SRC = r"D:\111111\备份\AI-SecIntel_2.2_竞赛技术报告_终稿(1).docx"
DST = r"D:\111111\备份\AI-SecIntel_2.2_竞赛技术报告_终稿.docx"
FIGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_report_figs")
BODY_W = 15.25   # Letter 纸 + 3.17cm 左右边距 → 正文净宽

doc = Document(SRC)

# ══════════════════════════════════════════════════════════════════
# 辅助：定位与插入
# ══════════════════════════════════════════════════════════════════
def find_heading(text, level=None, start=0):
    """按文本前缀找标题段落，返回 (idx, paragraph)。"""
    for i, p in enumerate(doc.paragraphs):
        if i < start:
            continue
        if level and p.style.name != "Heading %d" % level:
            continue
        if p.text.strip().startswith(text):
            return i, p
    raise KeyError("未找到标题：%s" % text)


def find_para(text, start=0):
    for i, p in enumerate(doc.paragraphs):
        if i < start:
            continue
        if text in p.text:
            return i, p
    raise KeyError("未找到段落：%s" % text)


def find_caption(prefix):
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip().startswith(prefix):
            return i, p
    raise KeyError("未找到题注：%s" % prefix)


H1 = doc.paragraphs[find_heading("第 1 章", 1)[0]]
H2 = doc.paragraphs[find_heading("1.1", 2)[0]]
BODY = doc.paragraphs[find_para("传统情报平台的模式是")[0]]      # 普通正文段


class Cursor:
    """在一个锚点元素之后顺序追加内容的游标。"""

    def __init__(self, anchor_p):
        self.cur = anchor_p
        self.parent = anchor_p._parent

    def _append(self, el):
        self.cur._p.addnext(el)
        self.cur = Paragraph(el, self.parent)

    def para(self, text, ref=None, bold=False, style=None):
        el = copy.deepcopy((ref or BODY)._p)
        self._append(el)
        p = self.cur
        runs = p.runs
        if runs:
            for r in runs[1:]:
                r._r.getparent().remove(r._r)
            runs[0].text = text
            if bold:
                runs[0].font.bold = True
        else:
            r = p.add_run(text)
            r.font.bold = bold
        return p

    def h1(self, text):
        return self.para(text, ref=H1)

    def h2(self, text):
        return self.para(text, ref=H2)

    def caption(self, text):
        idx, cap = find_caption("表 3-1")
        return self.para(text, ref=cap)

    def code(self, lines):
        """代码块：等宽字体 + 浅灰底纹，每行一段。"""
        out = []
        for ln in lines:
            el = OxmlElement("w:p")
            self._append(el)
            p = self.cur
            pf = p.paragraph_format
            pf.space_before = Pt(0)
            pf.space_after = Pt(0)
            pf.line_spacing = 1.0
            pf.left_indent = Cm(0.4)
            pPr = p._p.get_or_add_pPr()
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), "F4F4F4")
            pPr.append(shd)
            r = p.add_run(ln if ln.strip() else " ")
            r.font.name = "Consolas"
            r.font.size = Pt(8.5)
            r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
            out.append(p)
        return out

    def picture(self, img, width_cm, caption=None):
        el = OxmlElement("w:p")
        self._append(el)
        p = self.cur
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        p.add_run().add_picture(img, width=Cm(width_cm))
        if caption:
            idx, cap = find_caption("图 3-1")
            self.para(caption, ref=cap)
        return p

    def table(self, data, src_tbl, head_bold=True, widths=None, compact=False):
        """按 data(二维列表) 重建一张与 src_tbl 同款的表格。

        widths：各列宽度（cm）。不传则沿用模板列宽（仅在列数一致时可靠）。
        增删列后必须传 widths——否则 gridCol 宽度不会重算，
        表格会缩到页面一半宽、文字疯狂换行、页数暴涨。
        compact：把单元格段落的段前/段后间距清零、行距压到单倍。
        """
        n_rows = len(data)
        n_cols = len(data[0])

        tbl_el = copy.deepcopy(src_tbl._tbl)
        anchor_el = self.cur._p
        anchor_el.addnext(tbl_el)
        tbl = Table(tbl_el, self.parent)

        # ── 调整列数（必须同步 tblGrid，否则 Word 渲染会异常） ──
        grid = tbl_el.find(qn("w:tblGrid"))
        cur_cols = len(tbl.columns)
        for _ in range(max(0, cur_cols - n_cols)):
            for tr in tbl_el.findall(qn("w:tr")):
                tcs = tr.findall(qn("w:tc"))
                if tcs:
                    tr.remove(tcs[-1])
            gcs = grid.findall(qn("w:gridCol"))
            if gcs:
                grid.remove(gcs[-1])
        for _ in range(max(0, n_cols - cur_cols)):
            gcs = grid.findall(qn("w:gridCol"))
            if gcs:
                grid.append(copy.deepcopy(gcs[-1]))
            for tr in tbl_el.findall(qn("w:tr")):
                tcs = tr.findall(qn("w:tc"))
                if tcs:
                    tr.append(copy.deepcopy(tcs[-1]))
        # ── 调整行数 ──
        for _ in range(max(0, n_rows - len(tbl.rows))):
            trs = tbl_el.findall(qn("w:tr"))
            tbl_el.append(copy.deepcopy(trs[-1]))
        for _ in range(max(0, len(tbl.rows) - n_rows)):
            trs = tbl_el.findall(qn("w:tr"))
            tbl_el.remove(trs[-1])

        # ── 固定列宽（必须同时改 tblLayout / gridCol / cell.width 才生效） ──
        if widths:
            tblPr = tbl_el.find(qn("w:tblPr"))
            if tblPr is None:
                tblPr = OxmlElement("w:tblPr")
                tbl_el.insert(0, tblPr)
            for tag in ("w:tblLayout", "w:tblW"):
                for old in tblPr.findall(qn(tag)):
                    tblPr.remove(old)
            lay = OxmlElement("w:tblLayout")
            lay.set(qn("w:type"), "fixed")
            tblPr.append(lay)
            tw = OxmlElement("w:tblW")
            tw.set(qn("w:type"), "dxa")
            tw.set(qn("w:w"), str(int(sum(widths) * 567)))
            tblPr.append(tw)
            gcs = grid.findall(qn("w:gridCol"))
            for gc, w in zip(gcs, widths):
                gc.set(qn("w:w"), str(int(w * 567)))
            for row in tbl.rows:
                for cell, w in zip(row.cells, widths):
                    cell.width = Cm(w)

        for ri, row in enumerate(data):
            for ci, val in enumerate(row):
                cell = tbl.cell(ri, ci)
                paras = cell.paragraphs
                for extra in paras[1:]:
                    extra._p.getparent().remove(extra._p)
                p0 = paras[0]
                if compact:
                    pPr = p0._p.get_or_add_pPr()
                    for tag in ("w:spacing",):
                        for old in pPr.findall(qn(tag)):
                            pPr.remove(old)
                    sp = OxmlElement("w:spacing")
                    sp.set(qn("w:before"), "0")
                    sp.set(qn("w:after"), "0")
                    sp.set(qn("w:line"), "240")
                    sp.set(qn("w:lineRule"), "auto")
                    # w:spacing 在 pPr 里必须排在 w:ind 之前，否则 Word 会报 XML 顺序错误
                    ind = pPr.find(qn("w:ind"))
                    if ind is not None:
                        ind.addprevious(sp)
                    else:
                        pPr.append(sp)
                runs = p0.runs
                if runs:
                    for r in runs[1:]:
                        r._r.getparent().remove(r._r)
                    runs[0].text = val
                    if head_bold and ri == 0:
                        runs[0].font.bold = True
                else:
                    r = p0.add_run(val)
                    if head_bold and ri == 0:
                        r.font.bold = True
        self.cur = Paragraph(tbl_el, self.parent)
        return tbl


# ══════════════════════════════════════════════════════════════════
# A. 重要内容预览页（插在「第 1 章」之前）
# ══════════════════════════════════════════════════════════════════
SRC_TBL3 = doc.tables[2]     # 3 列 Table Grid
SRC_TBL5 = doc.tables[27]    # 5 列 Table Grid

def build_preview():
    h1_ch = doc.paragraphs[find_heading("第 1 章", 1)[0]]

    # 以「第 1 章」的前一个元素为锚，把预览页内容顺序追加到它后面
    prev_el = h1_ch._p.getprevious()
    if prev_el is not None and prev_el.tag.endswith("}p"):
        anchor = Paragraph(prev_el, h1_ch._parent)
    else:
        anchor = h1_ch

    c = Cursor(anchor)
    c.h1("重要内容预览")
    c.para("本页面向评审专家，把作品的核心亮点、关键指标与报告导航集中呈现，便于快速建立整体认知；"
           "系统完整的架构设计、实现细节与验证过程见后续各章。本页所有量化结论均为本机实测所得，"
           "可通过 测试报告/ 目录下的验证工具复跑复现。")

    c.h2("一、作品核心亮点")
    c.table([
        ["核心亮点", "一句话说明", "量化证据"],
        ["六智能体主动盯梢", "感知→编排→富化执行→研判→决策→质疑，事件驱动闭环",
         "60s 节拍；阈值 CVSS≥9.0 / KEV / AI"],
        ["红蓝自博弈决策", "质疑智能体（红方）对抗审视决策，命中盲区就地修正",
         "CVSS 9.8 误判 P1 自动升档 P0"],
        ["处置闭环回填", "同 CVE 秒判、同组件关联复用，系统越用越准",
         "DispositionStore 落盘；自测 17/17"],
        ["CTI 多跳知识图谱", "CVE 沿「组件→资产→攻击技术→战术」多跳游走",
         "/api/graph?hops=N；一次关联 6 个 CVE"],
        ["溯源归因", "威胁主体画像（含置信度）+ ATT&CK 战术链路",
         "置信度 0.71；三类证据可解释"],
        ["四级评分检索引擎", "BM25 叠加领域短语、概念空间与业务信号",
         "检索中位 15ms；强筛选查询 2.8ms"],
        ["双通道情报监测", "15 秒快车道 + 分钟级深同步；质量过滤前置于落盘",
         "48 个情报源；提交收录 < 3s"],
        ["索引缓存尾部增量", "破解「持续收录→缓存失效→全量重建」死循环",
         "冷启动 355s → 8.9s；A/B 逐项一致"],
        ["静默失效工程化治理", "扫描→治理→留痕→实测四步方法论",
         "覆盖 6 类缺陷模式；异常全部点名"],
        ["跨环境自适应", "硬件画像三档自动降配 + 一键配置环境",
         "自测 92/92；安装包 187 文件"],
    ], SRC_TBL3, widths=[3.5, 6.9, 4.85], compact=True)

    c.h2("二、关键指标看板")
    c.table([
        ["48", "104,055", "15 ms", "8.9 s", "92 / 92"],
        ["接入情报源", "语料条目", "检索中位时延", "冷启动耗时", "自测通过"],
    ], SRC_TBL5, head_bold=False, widths=[3.05] * 5, compact=True)

    c.h2("三、评审要点导航")
    c.table([
        ["提交要求条目", "对应章节"],
        ["系统总体架构设计", "第 2 章（2.2 总体架构、图 2-1、2.3 模块注册、2.4 HTTP 服务层）"],
        ["智能体方案设计", "第 4 章（4.2 六智能体链路、4.3 角色设计、4.8 决策、4.9 红蓝自博弈、图 4-1）"],
        ["情报监测模块详细设计", "第 5 章（5.2 双通道采集、5.3 情报源、5.6 秒级收录、5.7 质量分级与双过滤）"],
        ["情报富化模块详细设计", "第 6 章（6.2 POC 五源实抓、6.3 资产三路提取、6.4 测绘语法）"],
        ["情报问答模块详细设计", "第 7 章（7.2 混合检索、7.4 自建向量库、7.5 工具调用、7.6 多跳、7.7 溯源）"],
        ["关键技术选型说明", "2.12（表 2-3 全系统选型对照与取舍）"],
        ["系统工作流程图", "图 2-1 总体架构、图 2-2 系统工作流程、图 4-1 六智能体工作流程"],
        ["系统实现细节", "2.3 模块注册、2.4 HTTP 服务层、3.7 网络层、3.9 索引缓存三级判定、3.11 请求处理"],
        ["核心代码说明", "第 12 章（12.1 四级评分、12.2 尾部增量、12.3 红蓝自博弈、12.4 溯源归因、12.5 处置回填）"],
        ["各功能模块实现效果展示", "3.1.4 检索效果、5.10 实时监测、6.6 富化三连图、7.8 问答演示（合计 9 张实证截图）"],
        ["性能测试结果与分析", "第 9 章（9.3 实际运行指标、9.4 稳定性验证、9.7—9.12 各专项验证）"],
        ["创新点总结", "第 10 章（6 个方向性创新 + 九大具名创新点）"],
    ], SRC_TBL3, widths=[3.7, 11.55], compact=True)

    return c


build_preview()
print("[A] 重要内容预览页 已插入")


# ══════════════════════════════════════════════════════════════════
# 通用：段落文本替换 / 表格单元格替换
# ══════════════════════════════════════════════════════════════════
def set_para_text(p, text, bold=None):
    runs = p.runs
    if not runs:
        r = p.add_run(text)
        if bold is not None:
            r.font.bold = bold
        return
    runs[0].text = text
    if bold is not None:
        runs[0].font.bold = bold
    for r in runs[1:]:
        r._r.getparent().remove(r._r)


def replace_in_doc(old, new, limit=0):
    n = 0
    for p in doc.paragraphs:
        if old in p.text:
            set_para_text(p, p.text.replace(old, new))
            n += 1
            if limit and n >= limit:
                break
    return n


def replace_in_tables(pairs):
    """pairs: [(old, new)]，在全部表格单元格内替换。"""
    n = 0
    for t in doc.tables:
        for row in t.rows:
            for c in row.cells:
                if any(o in c.text for o, _ in pairs):
                    txt = c.text
                    for o, nw in pairs:
                        txt = txt.replace(o, nw)
                    paras = c.paragraphs
                    set_para_text(paras[0], txt)
                    for extra in paras[1:]:
                        extra._p.getparent().remove(extra._p)
                    n += 1
    return n


# ══════════════════════════════════════════════════════════════════
# B. 图 2-1 系统总体架构图（插在 2.3 之前，即 2.2 节末）
# ══════════════════════════════════════════════════════════════════
def add_arch_figure():
    _, h = find_heading("2.3", 2)
    prev = h._p.getprevious()
    anchor = Paragraph(prev, h._parent) if prev is not None and prev.tag.endswith("}p") else h
    c = Cursor(anchor)
    c.picture(os.path.join(FIGS, "arch.png"), 15.0,
              "图 2-1  系统总体架构图（五层单向依赖 + 横切关注点）")
    c.para("图 2-1 展示了系统的五层结构：应用层、智能体层、业务模块层、核心宿主层与数据层，"
           "自上而下单向依赖；性能画像降档、跨平台兼容、静默异常留痕、并发写锁等横切关注点贯穿全部五层。")


add_arch_figure()
print("[B] 图 2-1 总体架构图 已插入")


# ══════════════════════════════════════════════════════════════════
# C + D. 2.12 关键技术选型说明 ／ 2.13 系统工作流程图（插在第 3 章之前）
# ══════════════════════════════════════════════════════════════════
def add_tech_selection():
    h3 = doc.paragraphs[find_heading("第 3 章", 1)[0]]
    prev = h3._p.getprevious()
    anchor = Paragraph(prev, h3._parent) if prev is not None and prev.tag.endswith("}p") else h3
    c = Cursor(anchor)

    c.h2("2.12  关键技术选型说明")
    c.para("系统的技术选型围绕四条原则展开：其一，零外部依赖优先——评审机器、断网环境也应能双击即跑；"
           "其二，可离线、可解释——关键评分与决策不依赖云端 Key，结论可现场复现；"
           "其三，可复跑验证——每项能力都配有验证工具（见第 9 章）；"
           "其四，跨环境自适应——同一份代码覆盖 Windows / Linux / macOS 与高、中、低三档硬件配置。"
           "核心选型与取舍见表 2-3。")

    c.caption("表 2-3  关键技术选型对照（选型理由与落地位置）")
    c.table([
        ["技术点", "本项目选型", "常见备选", "选型理由", "落地位置"],
        ["Web 服务", "Python 标准库 http.server + 自研路由", "Flask / FastAPI + uvicorn",
         "零第三方依赖，双击即跑；评审机与离线环境无需安装任何 Web 框架", "core/server.py"],
        ["检索引擎", "自研四级评分 BM25（纯 Python）", "Elasticsearch / Whoosh",
         "十万级语料无需 ES 的运维与内存成本；评分权重可解释、可现场调参", "core/engine.py"],
        ["向量检索", "自建 NumPy 向量库（余弦相似）", "FAISS / Milvus",
         "免 GPU、免常驻服务进程；本语料规模下内存占用与召回率均可控", "m3_qa/qa/vector_store.py"],
        ["语义模型", "可选 transformers，缺依赖时自动降级", "强制依赖大模型 API",
         "无 Key、无 GPU 也能完整演示；有则增强，不依赖则不阻塞", "m3_qa/qa/local_embedder.py"],
        ["大模型调用", "兼容 OpenAI 协议 + 本地零 token 兜底", "绑定单一厂商 SDK",
         "可自由更换供应商；无网络时由多跳规划器接管，问答链路不中断", "m3_qa/qa/multi_hop.py"],
        ["前端", "单页 HTML + 原生 JS + 本地化 ECharts", "React / Vue + 构建链",
         "无 Node.js 构建步骤，改完刷新即见效；彻底去掉部署门槛", "frontend/"],
        ["数据存储", "JSON / JSONL 明文明码文件", "SQLite / PostgreSQL",
         "可离线审计、可随代码一起归档；无数据库进程与端口占用", "data/"],
        ["并发模型", "ThreadPoolExecutor（IO 密集场景）", "asyncio / Celery",
         "采集与检索均为 IO 密集，线程模型调试直观、异常栈完整", "core/extra_sources.py"],
        ["性能适配", "启动时硬件画像 + low/mid/high 三档", "人工手写配置文件",
         "同一份代码在 2 核 4G 到 8 核 32G 都能跑，慢机器自动降配", "core/envprofile.py"],
        ["跨平台", "标准库 + 自研兼容层 compat.py", "散落的 if 平台判断",
         "一套代码覆盖 Windows / Linux / macOS，Python 3.7+ 均可运行", "core/compat.py"],
    ], SRC_TBL5, widths=[2.0, 3.4, 3.0, 4.85, 2.0])

    c.para("有两处取舍值得单独说明。其一，检索引擎没有采用 Elasticsearch 而是自研四级评分 BM25："
           "本平台语料规模为十万级，ES 带来的运维、内存与端口成本大于收益，而自研实现让评分权重、"
           "结构化查询操作符与 AI 相关性闸门都能在代码层直接解释与调整，"
           "答辩现场「当场改一个权重再看结果」是可执行的。"
           "其二，前端未引入任何框架与构建链，单个 HTML 配合原生 JS 与本地化 ECharts，"
           "既保证了改完即见效的开发效率，也把「必须先装 Node.js」这一部署门槛彻底移除。")

    c.h2("2.13  系统工作流程图")
    c.para("图 2-2 给出系统端到端的完整工作流程，按「采集准入 — 索引与服务 — 能力主线 — 智能编排 — 浏览器端」"
           "五个环节展开：情报从 48 个源进入双通道采集，先经质量分级、双过滤与 AI 相关性闸门，"
           "再以统一 schema 原子落盘；落盘内容经倒排索引与三级缓存判定后由统一 HTTP 网关对外服务，"
           "形成监测、富化、问答三条能力主线；智能编排闭环持续消费快车道情报流，"
           "六智能体以 60 秒节拍自动盯梢、富化、研判、决策并做红蓝对抗；最终由浏览器端单页控制台呈现。")
    c.picture(os.path.join(FIGS, "flow.png"), 15.2,
              "图 2-2  系统工作流程图（端到端）")


add_tech_selection()
print("[C+D] 2.12 关键技术选型 / 2.13 系统工作流程图 已插入")


# ══════════════════════════════════════════════════════════════════
# E. 第 4 章：四智能体 → 六智能体
# ══════════════════════════════════════════════════════════════════
def patch_chapter4():
    # E1. 表 4-1 标题
    replace_in_doc("表 4-1  四智能体职责划分（据技术报告第二章）",
                   "表 4-1  六智能体职责划分（据技术报告第二章）")
    # E2. 表 4-1 实体：补 ⑤ 决策、⑥ 质疑 两行，TraceRecorder 保留
    _, cap41 = find_caption("表 4-1")
    t41 = None
    for t in doc.tables:
        head = " / ".join(c.text.strip() for c in t.rows[0].cells)
        if head.startswith("智能体") and "关键产出" in head:
            t41 = t
            break
    if t41 is not None:
        data = [
            ["智能体", "职责", "关键产出"],
            ["① Perception 感知", "监听实时情报流，按阈值筛出候选", "候选情报事件（含筛选依据）"],
            ["② Orchestrator 编排", "定优先级、限流分派、维护状态机", "分派指令与全局进度"],
            ["③ EnrichExecutor 富化执行", "资产定位 + POC 缓存查询", "富化结果（成功/失败均记录）"],
            ["④ BriefAnalyst 研判", "汇总证据、生成研判简报", "结论 + 依据 + 处置建议"],
            ["⑤ DecisionAgent 决策", "给出 P0/P1/P2 优先级与动作清单，附可解释推理链",
             "处置决策卡（信号 + 动作 + 推理步骤）"],
            ["⑥ ChallengerAgent 质疑", "以攻击者视角挑战决策，命中盲区就地修正（红蓝自博弈）",
             "质疑清单、抗辩记录与修正后的决策"],
            ["（贯穿）TraceRecorder", "记录编排全过程", "可审计的协作留痕"],
        ]
        anchor = t41._tbl.getprevious()
        t41._tbl.getparent().remove(t41._tbl)
        if anchor is not None and anchor.tag.endswith("}p"):
            c = Cursor(Paragraph(anchor, doc.paragraphs[0]._parent))
        else:
            c = Cursor(cap41)
        c.table(data, SRC_TBL3, widths=[3.8, 6.2, 5.25])

    # E3. 4.2 正文：链路描述
    for p in doc.paragraphs:
        if p.text.strip().startswith("orchestrator.py 实现了一条"):
            set_para_text(p, "orchestrator.py 实现了一条「感知 → 编排 → 富化执行 → 研判 → 决策 → 质疑」的"
                             "六智能体链路：前四个角色负责「发现与理解」，后两个角色负责「决策与自我博弈」。"
                             "每轮节拍的完整过程为：")
            break
    # E4. 4.2 列表补两项（决策、质疑）
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip().startswith("研判：研判体汇总证据链"):
            c = Cursor(p)
            c.para("决策：决策智能体把研判结论转化为可执行的处置决策，输出 P0/P1/P2 优先级、"
                   "动作清单与逐条推理依据，并对同一漏洞复用历史处置经验；",
                   ref=doc.paragraphs[find_para("感知：从快车道情报流")[0]])
            c.para("质疑：质疑智能体以攻击者视角对决策做对抗审视，逐条提出并可被反驳，"
                   "命中盲区即在出口前就地修正——即「红蓝自博弈」。",
                   ref=doc.paragraphs[find_para("感知：从快车道情报流")[0]])
            break

    # E5. 图 4-1（放在 4.3 之前）
    _, h43 = find_heading("4.3", 2)
    prev = h43._p.getprevious()
    anchor = Paragraph(prev, h43._parent) if prev is not None and prev.tag.endswith("}p") else h43
    c = Cursor(anchor)
    c.picture(os.path.join(FIGS, "agents.png"), 15.2,
              "图 4-1  六智能体工作流程图（含红蓝自博弈与处置回填闭环）")

    # E6. 编排器状态接口表述：四智能体在列 → 六智能体在列
    for p in doc.paragraphs:
        if "四智能体在列" in p.text:
            set_para_text(p, p.text.replace("四智能体在列", "六智能体在列"))
    # E7. 2.2 节正文里的「承载四智能体编排」
    replace_in_doc("承载四智能体编排", "承载六智能体编排")
    # E8. 附录 A 源码索引
    replace_in_tables([("四智能体编排", "六智能体编排")])


patch_chapter4()
print("[E] 第 4 章 六智能体同步 完成")


# ══════════════════════════════════════════════════════════════════
# E9. 新增 4.8—4.11（插在第 5 章之前）
# ══════════════════════════════════════════════════════════════════
def add_agent_sections():
    h5 = doc.paragraphs[find_heading("第 5 章", 1)[0]]
    prev = h5._p.getprevious()
    anchor = Paragraph(prev, h5._parent) if prev is not None and prev.tag.endswith("}p") else h5
    c = Cursor(anchor)

    c.h2("4.8  决策智能体：从研判结论到可执行处置决策")
    c.para("研判智能体回答的是「发生了什么」，决策智能体回答的是「现在该做什么」。"
           "DecisionAgent 消费研判简报与富化结果，输出三件事：处置优先级（P0 立即处置 / P1 24 小时内 / P2 排期加固）、"
           "动作清单（排查、收敛暴露面、打补丁、加检测规则、持续跟踪 EXP 动态等），"
           "以及**逐条可解释的推理依据**。")
    c.para("推理依据采用「规则 — 证据 — 结论」三元组结构回传前端，这是可解释人工智能（XAI）在本系统的落点："
           "例如一条 CVSS 9.8 且已入 CISA KEV 的漏洞，推理链会明确写出"
           "「规则：CVSS ≥ 9.5 且 KEV 在野利用 → 证据：CVSS 9.8、kev=true → 结论：P0 立即处置」。"
           "决策不是黑箱打分，而是可以被评审逐条追问的推导过程。")
    c.para("决策智能体还负责与处置记忆库对接：同 CVE 再次出现时直接复用历史结论，"
           "同组件漏洞则关联历史经验作为参照，具体见 4.10。")

    c.h2("4.9  质疑智能体：多智能体红蓝自博弈")
    c.para("多智能体系统最容易被质疑的一点是「几个 Agent 会不会只是互相点头」。"
           "为此系统引入第六个智能体 ChallengerAgent，站在**攻击者视角**对决策做对抗审视，"
           "形成「决策（蓝方）— 质疑（红方）」的红蓝自博弈。")
    c.para("红方按固定规则生成尖锐质疑清单，典型质疑包括："
           "已有公开 POC 但缺少明确修复方案时，仅给 P1 是否过于乐观？"
           "高危且多类资产暴露时，是否遗漏了「先收敛互联网暴露面」的前置动作？"
           "CVSS 已达极端高危但未入 KEV 时，是否仍应按 P0 立即处置？"
           "无 POC、无资产暴露的中危条目，动作清单是否在空转？"
           "存在同组件历史处置时，是否可以复用既有路径而非从零研判？")
    c.para("蓝方随后逐条抗辩，产出结论有三种：采纳并修正决策、部分采纳并标注残余风险、"
           "经抗辩后维持原判（标注「已通过对抗审视」）。实测中，"
           "一条 CVSS 9.8 但初判 P1 的漏洞被红方质疑命中并自动升档为 P0——"
           "这正是红蓝对抗的价值：把可能被评审或攻击者挑出的漏洞，在决策出口前就压下去。"
           "全部质疑与抗辩记录随决策一并落盘，可通过 /api/ops/decisions 审计。")

    c.h2("4.10  处置闭环回填：让系统越用越准")
    c.para("处置不是终点。系统提供处置记忆库 DispositionStore（落盘 data/dispositions.json），"
           "把人工确认的处置结论回填进知识库，形成自我进化闭环，包含三种复用方式：")
    c.para("其一，同 CVE 秒判——同一漏洞再次出现在情报流中时，决策智能体直接复用历史处置结论，"
           "跳过重复研判，输出「秒判」标记与历史依据。")
    c.para("其二，同组件关联——组件名经过归一化处理（去除括号内的版本区间、去除比较符号与版本号、统一小写），"
           "并采用双向子串匹配，使「Ollama」与「ollama < 0.5.0」能够正确归为同一组件；"
           "同组件的其他漏洞进入决策时，会自动追加「另有 N 个同组件经验可参照」的提示。")
    c.para("其三，闭环统计——记忆库提供统计接口，实时反映已修复、已验证、误报三类沉淀量，"
           "使「决策 → 回填 → 复用 → 更准决策」的闭环可被度量，而不是一句口号。")

    c.h2("4.11  溯源归因与 CTI 多跳图谱")
    c.para("决策链路此前止步于「这个漏洞有多严重、该怎么处置」。溯源归因模块再往前推一层，"
           "回答安全分析师更本质的问题：是谁在利用它？他们走的是一条怎样的攻击链？")
    c.para("模块依据 CWE 类型、KEV 在野利用状态、描述关键词以及受影响产品的高价值程度，"
           "推断最可能的威胁主体画像（勒索组织 / APT 定向攻击组织 / 供应链投毒者 / 机会型脚本小子等，"
           "每条推断附带置信度与证据），并把漏洞映射到一条有序的 MITRE ATT&CK 战术链路"
           "（如 Initial Access → Execution → Impact），与平台已有的 ATLAS 攻击技术映射互补，"
           "补足传统 ATT&CK 视角。全部推断均为确定性规则驱动，零外部依赖，无 Key 也能完整演示。")
    c.para("与溯源归因配套的是 CTI 多跳关联图谱。传统关系图谱只在「一条漏洞」的邻居内展开，"
           "本系统以 CVE 为起点，沿「组件 → 资产 → 攻击技术 → 战术」多跳游走，"
           "并把同组件、同攻击技术的相邻 CVE 一并并入图中，通过 /api/graph?hops=N 返回可解释的多跳路径。"
           "实测中，以 CVE-2026-9198 为起点做 2 跳关联，可一次带出 6 个同组件漏洞，"
           "并给出形如「CVE-2026-9198 —同组件(langflow)→ CVE-2026-10561」的可读路径。"
           "这一步把「单点漏洞情报」升级为「威胁面情报」，是 CTI（网络威胁情报）与普通漏洞库的分界线。")


add_agent_sections()
print("[E9] 4.8—4.11 新增 完成")


# ══════════════════════════════════════════════════════════════════
# F. 9.7 自测 78 项 → 92 项
# ══════════════════════════════════════════════════════════════════
def patch_selftest():
    replace_in_doc("9.7  系统自测（core/self_test.py，78 项）",
                   "9.7  系统自测（core/self_test.py，92 项）")
    replace_in_doc("78 项自测 + 27 项端到端", "92 项自测 + 27 项端到端")
    replace_in_tables([("78 项", "92 项")])


patch_selftest()
print("[F] 自测 78 → 92 完成")


# ══════════════════════════════════════════════════════════════════
# G. 第 10 章：创新点由 5 个扩到 9 个（插在第 11 章之前）
# ══════════════════════════════════════════════════════════════════
def add_innovations():
    h11 = doc.paragraphs[find_heading("第 11 章", 1)[0]]
    prev = h11._p.getprevious()
    anchor = Paragraph(prev, h11._parent) if prev is not None and prev.tag.endswith("}p") else h11
    c = Cursor(anchor)

    c.h2("10.12  创新点六：可验证的工程严谨性")
    c.para("本项目的一个基本立场是：「我们说它对」和「你能跑出来它是对的」是两件事，本项目选择后者。"
           "所有关键能力都配了可复跑的验证工具，形成完整的验证矩阵：")
    c.caption("表 10-1  能力与对应验证工具矩阵")
    c.table([
        ["能力", "验证工具", "结论"],
        ["系统整体", "core/self_test.py", "92 项全通过"],
        ["索引增量正确性", "tools/_test_index_incremental.py", "A/B 逐项一致"],
        ["近重检测", "tools/_test_similarity.py", "隔离单测通过"],
        ["提交收录全链路", "tools/_e2e_submit_v3.py", "27 项全通过"],
        ["决策智能体", "tools/_test_decision.py", "12 项全通过"],
        ["处置闭环回填", "tools/_test_disposition.py", "17 项全通过"],
        ["三项核心创新", "tools/_test_innovation.py", "20 项全通过"],
        ["代码缺陷", "tools/_bugscan.py", "6 类模式 0 处残留"],
    ], SRC_TBL3, widths=[3.2, 6.0, 6.05])
    c.para("这套验证矩阵的意义在于：报告里的每一个量化结论，评审都可以在本地复跑复现，"
           "而不是只能选择相信——这正是工程严谨性的可验证表达。")

    c.h2("10.13  创新点七：处置闭环回填 · 自我进化")
    c.para("多数安全工具的处置结论是一次性的：这一次分析完，下一次同样的漏洞还要重新分析一遍。"
           "本系统把处置结论沉淀为可复用的记忆资产（DispositionStore，落盘 data/dispositions.json）："
           "同 CVE 秒判复用、同组件关联复用、闭环统计可度量。"
           "其技术难点不在存储，而在**组件名的正确归一化**——初版只做双向子串匹配，"
           "导致「Ollama」与「ollama < 0.5.0」这类带版本区间的写法匹配不上；"
           "修正方案是双端归一化（去括号版本区间、去比较符与版本号、统一小写）后再双向子串匹配，"
           "使跨来源的组件名能够正确归并。这一步让「越用越聪明」从愿景变成了可验证的事实。")

    c.h2("10.14  创新点八：CTI 多跳图谱 + 溯源归因 + 红蓝自博弈")
    c.para("这三项能力共同把系统从「漏洞情报库」推向「威胁情报系统」："
           "多跳图谱解决「一个漏洞还牵连哪些漏洞」，溯源归因解决「是谁在用、走了哪条攻击链」，"
           "红蓝自博弈解决「我们的判断经不经得起对抗」。三者都不是概念演示，"
           "而是有接口、有落盘、有自测的工程实现："
           "/api/graph?hops=N 返回可解释多跳路径；attribution 模块输出带置信度的主体画像与 ATT&CK 战术链；"
           "ChallengerAgent 的质疑与抗辩记录随决策一并落盘，可逐条审计。"
           "三项创新合计 20 项自测用例，全部通过。")

    c.h2("10.15  创新点九：跨环境自适应与一键环境配置")
    c.para("安全工具在评审机上跑不起来，是最常见也最致命的失败方式。"
           "本系统把「跨环境可用」当作与功能同等重要的工程目标，落地为三层机制：")
    c.para("第一层是**版本与平台兼容层**（core/compat.py）：统一兜底 Python 3.7 之后的各版本差异"
           "（cached_property、importlib.metadata、removeprefix/removesuffix 等），"
           "并处理 Windows GBK 控制台编码、跨平台端口排查命令（netstat / lsof / ss）、长路径与符号链接等平台差异，"
           "使同一份代码覆盖 Windows、Linux 与 macOS。")
    c.para("第二层是**运行时性能画像**（core/envprofile.py）：服务启动时自动探测 CPU 核数、内存、磁盘与网络，"
           "划分 low / mid / high 三档并打印生效策略。低配档自动放大网络超时（×2.0）、压低并发（上限 2）、"
           "关闭语义模型预热（省下约 470MB 内存与 16 秒启动时间）、拉长快车道轮询间隔，"
           "使同一份代码在 2 核 4G 的老机器上依然能跑起来。业务代码不写「如果是慢机器」这类分支，"
           "统一调用 T.timeout() / T.workers() 由画像层决定实际值。")
    c.para("第三层是**一键环境配置**（bootstrap.py）：自动完成 Python 版本体检、创建独立虚拟环境、"
           "并发探测可达的 pip 镜像（国内源优先）、按档安装依赖并做导入自检，"
           "同时提供 Windows / macOS / Linux 三个双击入口（安装.bat / 安装.command / 安装.sh）。"
           "在环境确实不适合的机器上，会给出该平台对应的 Python 安装指引，而不是抛出一段无解的报错。")


add_innovations()
print("[G] 第 10 章创新点扩至 9 个 完成")


# ══════════════════════════════════════════════════════════════════
# H. 新增第 12 章「核心代码说明」（插在参考文献之前）
# ══════════════════════════════════════════════════════════════════
def add_code_chapter():
    href = doc.paragraphs[find_heading("参考文献", 1)[0]]
    prev = href._p.getprevious()
    anchor = Paragraph(prev, href._parent) if prev is not None and prev.tag.endswith("}p") else href
    c = Cursor(anchor)

    c.h1("第 12 章  核心代码说明")
    c.para("本章摘录系统中最能体现设计取舍的五段核心代码，逐段说明其解决的问题、关键实现与验证方式。"
           "代码均取自项目实际源码，行号可能因版本迭代略有偏移。")

    # 12.1
    c.h2("12.1  四级评分检索引擎的概念空间层（core/engine.py）")
    c.para("检索引擎在经典 BM25 之上叠加三层领域信号，其中「概念空间层」负责把查询词映射到领域概念，"
           "使「模型投毒」这类说法能命中「数据投毒 / data poisoning」概念下的全部别名。"
           "核心实现是一次正则扫描得到命中别名集合，再按各概念的命中别名数加权：")
    c.code([
        "# core/engine.py —— 构建文档的概念向量（概念空间层）",
        "blob = \" \".join([f[\"title\"], f[\"desc\"][:6000], f[\"product\"], f[\"vendor\"],",
        "                 f[\"cwe\"], f[\"tags\"], f[\"category\"], f[\"kev\"], f[\"atlas\"][:2500]]).lower()",
        "matched = _match_set(CONCEPT_MATCHER, blob)      # 组合正则一次扫描",
        "cvec = defaultdict(float)",
        "for cid, c in CONCEPTS.items():",
        "    if c[\"kind\"] == \"category\":",
        "        continue",
        "    hit = len(_CONCEPT_ALIAS_SETS[cid] & matched)   # 命中的别名数",
        "    if hit:",
        "        cvec[cid] = min(1.0, 0.5 + 0.25 * hit)      # 命中越多权重越高，饱和于 1.0",
        "for cid, c in CONCEPTS.items():                     # 分类字段直接满权重",
        "    if c[\"kind\"] == \"category\" and c[\"cat\"] == d.get(\"category\"):",
        "        cvec[cid] = 1.0",
        "# 短语文档频次：df 语义为「包含该短语的文档数」，按文档去重",
        "phrase_hits = _match_set(PHRASE_MATCHER, title_lo + \"\\n\" + desc_lo)",
    ])
    c.para("这段代码解决了同义改写查询的召回问题。用一次性正则扫描而非逐概念循环匹配，"
           "把概念层的时间开销压到可忽略；权重采用「0.5 + 0.25 × 命中别名数」的线性增长并饱和于 1.0，"
           "既避免了长文档因命中大量别名而过度加分，也保证了命中越精准排序越靠前。"
           "实测十万级语料下检索中位时延 15ms，带强筛选的查询（如 cvss>=9 且已入 KEV）为 2.8ms。")

    # 12.2
    c.h2("12.2  索引缓存的三级判定与尾部增量（core/engine.py）")
    c.para("索引构建是分钟级操作，因此必须落盘缓存；但平台「持续收录新情报」的常态会让缓存频繁失效，"
           "形成「每次重启全量重建」的死循环。解决方案是把缓存命中细化为三级：精确命中、前缀命中 + 尾部增量、"
           "全量重建。核心判定逻辑如下：")
    c.code([
        "# core/engine.py —— 缓存命中判定（节选）",
        "#   ① 精确命中：文档集合完全没变 → 走原有的 key 校验（含 id 顺序指纹）",
        "#   ② 前缀命中 + 尾部增量：语料只是在末尾追加了少量新情报",
        "#      （本平台的常态：快车道/定时同步每轮都会 append 新 CVE）",
        "#      旧口径下只要条数变了就整个缓存作废，下次启动必吃 355s 全量重建；",
        "#      改成「复用旧索引 + 只给尾部增量建索引」，把启动压到秒级~十几秒。",
        "n_now = len(self.docs)",
        "n_keep = len(_keep)              # 可复用的基数（缓存里「还在」的那些）",
        "dropped = _n_order - n_keep      # 缓存里有、当前语料中已消失的条数",
        "added = n_now - n_keep           # 当前语料新增、缓存中没有的条数",
        "if added > self.INDEX_CACHE_TAIL_LIMIT:      # 增量过多则整体重建更划算",
        "    self._cache_reject = (",
        "        \"新增 %d 条，超过尾部增量上限 %d 条（整体重建更划算）\"",
        "        % (added, self.INDEX_CACHE_TAIL_LIMIT))",
        "    self.docs = before",
        "    return False",
        "if dropped == 0 and added == 0:",
        "    # ① 精确命中：文档集合完全没变 → 走原有的 key 校验",
        "    ...",
    ])
    c.para("关键洞察是：缓存的本质约束是「下标对齐」，而不是「文件一模一样」。"
           "只要保证前缀下标一一对应（由 _reorder_docs 保证并校验），尾部新增完全可以走同一套增量写入通道。"
           "INDEX_CACHE_TAIL_LIMIT 取 5000，是因为增量条数过多时，增量路径的常数开销会逼近整体重建，"
           "此时直接重建更划算。该优化把冷启动从 355 秒压到 8.9 秒，"
           "并通过 A/B 对照验证（全量重建 vs 尾部增量）逐项一致，正确性没有让步。")

    # 12.3
    c.h2("12.3  质疑智能体：红蓝自博弈的质疑生成（orchestrator.py）")
    c.para("质疑智能体（红方）以攻击者视角对决策（蓝方）发起挑战。"
           "质疑并非随机生成，而是围绕安全运营中最容易出错的地方设计成固定规则，每条质疑都附带严重度与命中依据：")
    c.code([
        "# modules/m0_ops/backend/orchestrator.py —— ChallengerAgent._challenge（节选）",
        "def _challenge(self, event, enrich, dec):",
        "    \"\"\"生成质疑清单（红方攻击视角）。返回 [(质疑, 严重度, 命中依据)]。\"\"\"",
        "    challenges = []",
        "    sig = dec.get(\"signals\") or {}",
        "    pri = dec.get(\"priority\") or \"P2\"",
        "    kev = bool(sig.get(\"kev\")); cvss = sig.get(\"cvss\") or 0",
        "    poc_n = sig.get(\"poc_available\") or 0",
        "    asset_n = sig.get(\"assets_exposed\") or 0",
        "    remediation = sig.get(\"remediation\")",
        "",
        "    # 质疑①：有 POC 且无加固/升级方案时，P1 是否低估？",
        "    if poc_n and not remediation and pri == \"P1\":",
        "        challenges.append((",
        "            \"已有公开 POC 但缺少明确修复方案，仅 24h 内评估是否过于乐观？\",",
        "            \"high\", f\"{poc_n} 条 POC 可用，但 remediation 信号缺失\"))",
        "",
        "    # 质疑③：CVSS 极高但未列 KEV，是否被低估为 P1？",
        "    if cvss >= 9.5 and not kev and pri != \"P0\":",
        "        challenges.append((",
        "            \"CVSS 已达极端高危，纵使未见 KEV，是否仍应按 P0 立即处置？\",",
        "            \"high\", f\"CVSS {cvss} >= 9.5 但被判 {pri}\"))",
        "    ...  # 另有资产暴露、动作空转、同组件复用等三条质疑规则",
        "    return challenges",
    ])
    c.para("这段代码体现的设计原则是「用确定性规则做对抗审查」。质疑规则不依赖任何大模型，"
           "意味着无 Key、无 GPU 的环境也能完整演示红蓝对抗全过程，且每条质疑的触发条件都可解释、可复现。"
           "质疑生成后由蓝方逐条抗辩，产出「采纳并修正 / 部分采纳 / 维持原判」三类结论，"
           "全部记录随决策落盘。实测中红方命中一条 CVSS 9.8 误判 P1 的决策，"
           "使其自动升档为 P0，这是红蓝自博弈产生实际价值的直接证据。")

    # 12.4
    c.h2("12.4  溯源归因：威胁主体画像与 ATT&CK 战术链（attribution.py）")
    c.para("溯源归因模块回答「是谁在利用它、走的哪条攻击链」。"
           "实现上先用关键词规则库对漏洞描述与标题做打分，选出得分最高的主体画像（无命中则回落为机会型攻击者），"
           "再由 CWE 类型推导有序的 ATT&CK 战术链，并为每个战术阶段生成一句可解释说明：")
    c.code([
        "# modules/m0_ops/backend/attribution.py —— attribute（节选）",
        "def attribute(rec):",
        "    \"\"\"对一条漏洞情报做溯源归因。返回 {actor, kill_chain, confidence, evidence}。\"\"\"",
        "    text = (rec.get(\"desc\", \"\") or \"\") + \" \" + (rec.get(\"title\", \"\") or \"\")",
        "    products = rec.get(\"products\", []) or []",
        "    cwe_ids = [w.get(\"id\") for w in (rec.get(\"cwe\", []) or [])",
        "               if isinstance(w, dict) and w.get(\"id\")]",
        "    kev = bool(rec.get(\"kev\"))",
        "",
        "    actor = _pick_actor(text, products, cwe_ids, kev)   # 主体画像 + 置信度 + 证据",
        "    chain = _pick_kill_chain(cwe_ids)                   # 由 CWE 推导 ATT&CK 战术链",
        "",
        "    # 链路落点：结合 CWE 名称给每个阶段一句可解释说明",
        "    chain_steps = []",
        "    for stage in chain:",
        "        chain_steps.append({",
        "            \"tactic\": stage,",
        "            \"tactic_name\": TACTIC_NAMES.get(stage, stage),",
        "            \"note\": _stage_note(stage, cwe_ids, products),",
        "        })",
        "    return {\"actor\": actor, \"kill_chain\": chain_steps,",
        "            \"cwe\": cwe_ids[:4], \"kev\": kev}",
    ])
    c.para("主体画像规则库覆盖勒索组织、APT 定向攻击组织、供应链投毒者等类别，"
           "每条规则由关键词集合、主体标签、权重与说明构成；置信度由命中规则的加权得分归一化得到，"
           "因此「判定为有组织利用者，置信度 0.71」这类结论是可解释、可追问的，而非黑箱输出。"
           "归因结果作为决策智能体的上游富化信号注入决策卡，使处置建议不只说明「怎么做」，"
           "也说明「在防谁」。")

    # 12.5
    c.h2("12.5  跨环境自适应：性能画像与降档（envprofile.py）")
    c.para("为了让同一份代码在高配工作站与低配笔记本上都能运行，"
           "系统把「按硬件降配」收敛到统一的档位对象上，业务代码只声明基准值，由画像层决定实际值：")
    c.code([
        "# core/envprofile.py —— 档位对象的缩放计算",
        "def timeout(self, base, minimum=None):",
        "    \"\"\"按档放大超时；minimum 用于给「再慢也不能无限等」的场景兜底下限。\"\"\"",
        "    v = float(base) * float(self.cfg.get(\"timeout_scale\") or 1.0)",
        "    if minimum is not None:",
        "        v = max(v, float(minimum))",
        "    return round(v, 1)",
        "",
        "def workers(self, base, minimum=1):",
        "    \"\"\"按档压低并发；绝不超过档位上限，也不低于 minimum。\"\"\"",
        "    cap = int(self.cfg.get(\"worker_cap\") or 2)",
        "    try:",
        "        base = int(base)",
        "    except Exception:",
        "        base = cap",
        "    return max(int(minimum), min(base, cap))",
        "",
        "# 业务侧调用示例（不出现任何「如果是慢机器」的分支）：",
        "#   timeout = T.timeout(20)        # 低配档自动变成 40",
        "#   workers = T.workers(8)         # 低配档自动变成 2",
        "#   if T.enabled(\"embed_warmup\"):  # 低配档跳过语义模型预热",
        "#       warm_embedding_model()",
    ])
    c.para("这段代码的关键设计是「调用点不变，行为随环境变」。"
           "所有并发与超时调用点都改写成 T.timeout() / T.workers() 形式，"
           "由档位对象统一施加缩放，避免了在 11 处并发点里散落条件分支。"
           "低配档对后台负载类配置（自动刷新间隔、向量同步周期）采用强制覆盖——"
           "这不是偏好问题而是可用性问题：若沿用高配参数，机器会在加载十万级语料时长时间无响应。"
           "中高配档则只补充用户未显式配置的项，保留手工调优的空间。")


add_code_chapter()
print("[H] 第 12 章 核心代码说明 完成")


# ══════════════════════════════════════════════════════════════════
# I. 分页：预览页独立成页、第 1 章另起一页
# ══════════════════════════════════════════════════════════════════
def set_page_breaks():
    """只给「第 1 章」加分页：正文节本来就从新页开始，预览页紧随其后；
    预览页若再加分页会在正文第 1 页留下空白页。"""
    n = 0
    for p in doc.paragraphs:
        if p.style.name != "Heading 1":
            continue
        if p.text.strip().startswith("第 1 章"):
            pPr = p._p.get_or_add_pPr()
            for old in pPr.findall(qn("w:pageBreakBefore")):
                pPr.remove(old)
            pPr.insert(0, OxmlElement("w:pageBreakBefore"))
            n += 1
    return n


print("[I] 设置分页:", set_page_breaks(), "处")

# ══════════════════════════════════════════════════════════════════
# J. 兜底：全量清掉「四智能体」旧表述（正文 + 表格）
#    前面各节是定点替换，难免漏掉零散句（如第 1 章概述里的一句），
#    这里做一次全局收口，确保全文不再出现四智能体。
# ══════════════════════════════════════════════════════════════════
n_par = replace_in_doc("四智能体", "六智能体")
n_tbl = 0
for _tbl in doc.tables:
    for _row in _tbl.rows:
        for _c in _row.cells:
            for _p in _c.paragraphs:
                if "四智能体" in _p.text:
                    set_para_text(_p, _p.text.replace("四智能体", "六智能体"))
                    n_tbl += 1
print("[J] 四智能体 → 六智能体：正文 %d 处 / 表格 %d 处" % (n_par, n_tbl))

doc.save(DST)
print("已保存 →", DST)

