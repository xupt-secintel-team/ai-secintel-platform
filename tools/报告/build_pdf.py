# -*- coding: utf-8 -*-
"""技术报告 → PDF（.pdf）生成器

**关键设计：内容源直接读回已生成的 .docx**，而不是重新写一遍正文。
理由：两套内容源必然漂移（改了一处忘了另一处，Word 与 PDF 内容就不一致）。
从 docx 遍历段落与表格渲染，天然保证两个交付物内容完全一致。

三个实测踩过的坑（都在下面代码注释里标了★）
------------------------------------------------
1. **不能用样式名判标题**：docx 生成器统一用 Normal + 直接设字号，
   样式名全是 Normal。
2. **不能只看"单列多段落"判代码块**：封面的「系统规模」框也是单列多段落，
   误判成代码块会用 Consolas 渲染 → Consolas 无中文字形 → 整块中文变空白。
   正确判据是**底纹色**（代码块 F4F6F9 / 提示框 EAF1FB / 数据表无底纹）。
3. **代码块里的中文会丢**：Consolas 没有中文字形。必须做**混排** ——
   ASCII 用 Consolas，中文用微软雅黑，且中文字号要放大到「正好 2 个半角宽」
   （Consolas 半角 = 0.5498em，2 个 = 1.0996em），这样框线图才对得齐。
"""
import os
import re
import sys

from docx import Document
from docx.oxml.ns import qn
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                                PageBreak, PageTemplate, Paragraph,
                                Preformatted, Spacer, Table, TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(ROOT, "output", "AI-SecIntel2.0_技术报告.docx")
OUT = os.path.join(ROOT, "output", "AI-SecIntel2.0_技术报告.pdf")

C_MAIN = colors.HexColor("#1F3A6E")
C_ACCENT = colors.HexColor("#2E6DD4")
C_GREY = colors.HexColor("#555F6D")
C_CODE_BG = colors.HexColor("#F4F6F9")
C_CODE_LINE = colors.HexColor("#D8DEE9")
C_TBL_HEAD = colors.HexColor("#1F3A6E")
C_TBL_ALT = colors.HexColor("#F2F5FA")
C_LINE = colors.HexColor("#BFC8D6")
C_CALLOUT_BG = colors.HexColor("#EAF1FB")
C_COVER_BG = colors.HexColor("#F5F8FC")

FONTS = "msyh"
MONO = "consola"

# 代码块字号：ASCII 用 Consolas，中文用微软雅黑并放大到 2 个半角宽
CODE_ASC = 7.0
CODE_CN = round(CODE_ASC * 2 * 0.5498, 2)      # ≈ 7.70
CODE_LEAD = 10.3

# 版面（A4 / 与 docx 一致：上下 2.5·2.3，左右 2.6·2.4）
# 模块级而非 build() 局部 —— _code_flow 要用正文高度决定是否 KeepTogether
PW, PH = A4
LM, RM, TM, BM = cm * 2.6, cm * 2.4, cm * 2.5, cm * 2.3
BODY_H = PH - TM - BM

# docx 里的底纹色 → 语义（★ 这是判别单列表格用途的唯一可靠依据）
FILL_CODE = "F4F6F9"        # 代码块 / 框线图
FILL_CALLOUT = "EAF1FB"     # 提示框
FILL_COVER = "F5F8FC"       # 封面信息框


def register_fonts():
    pairs = [
        (FONTS, "C:/Windows/Fonts/msyh.ttc", 0),
        (MONO, "C:/Windows/Fonts/consola.ttf", 0),
    ]
    for name, path, idx in pairs:
        if not os.path.exists(path):
            print("  字体缺失 %s：%s" % (name, path))
            continue
        try:
            pdfmetrics.registerFont(TTFont(name, path, subfontIndex=idx))
        except Exception as e:  # noqa: BLE001
            print("  字体注册失败 %s: %s" % (name, e))


def S(name, size, leading=None, color=colors.black, align=TA_JUSTIFY,
      space_before=0, space_after=3, indent=0):
    return ParagraphStyle(name, fontName=FONTS, fontSize=size,
                          leading=leading or size * 1.62,
                          textColor=color, alignment=align,
                          spaceBefore=space_before, spaceAfter=space_after,
                          firstLineIndent=indent)


def esc(t):
    return (str(t).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


_CJK = re.compile(r"[\u2e80-\u9fff\uff00-\uffef\u3000-\u303f]")


def _mono_markup(line):
    """一行文本 → 中英混排的 Paragraph markup。

    ★ Consolas 没有中文字形，中文直接丢（实测：13 个代码块的中文注释
      全部消失）。这里做 run 级混排：ASCII 走 Consolas，中文走微软雅黑，
      且中文 size 取 CODE_CN（= 2 个 Consolas 半角宽），保证框线图不错位。
    """
    out = []
    buf = ""
    buf_cjk = None
    for ch in line:
        is_cjk = bool(_CJK.match(ch))
        if buf_cjk is None:
            buf_cjk = is_cjk
        if is_cjk != buf_cjk:
            out.append(_run(buf, buf_cjk))
            buf = ""
            buf_cjk = is_cjk
        buf += ch
    if buf:
        out.append(_run(buf, bool(buf_cjk)))
    return "".join(out)


def _run(txt, is_cjk):
    if not txt:
        return ""
    esc_txt = esc(txt)
    if is_cjk:
        return '<font name="%s" size="%.2f">%s</font>' % (FONTS, CODE_CN, esc_txt)
    # ASCII：空格必须转 &nbsp;，否则 reportlab 会折叠
    esc_txt = esc_txt.replace(" ", "&nbsp;")
    return '<font name="%s" size="%.2f">%s</font>' % (MONO, CODE_ASC, esc_txt)


def build():
    register_fonts()
    if not os.path.exists(SRC):
        print("找不到源 docx：%s" % SRC)
        return None
    doc = Document(SRC)

    # 版面常量在模块级（PW/PH/LM/RM/TM/BM）——_code_flow 也要用 BODY_H
    def on_page(canv, docu):
        canv.saveState()
        canv.setFont(FONTS, 8)
        canv.setFillColor(C_GREY)
        canv.drawCentredString(PW / 2, cm * 1.2,
                               "第 %d 页 · AI-SecIntel 2.0 技术报告" % docu.page)
        canv.restoreState()

    pdf = BaseDocTemplate(
        OUT, pagesize=A4, leftMargin=LM, rightMargin=RM,
        topMargin=TM, bottomMargin=BM,
        title="AI-SecIntel 2.0 技术报告",
        author="AI-SecIntel 项目组", subject="技术报告")
    frame = Frame(LM, BM, PW - LM - RM, PH - TM - BM, id="body",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    pdf.addPageTemplates([PageTemplate(id="main", frames=[frame],
                                       onPage=on_page)])

    st_body = S("body", 10.2)
    st_h1 = S("h1", 16, 22, C_MAIN, TA_LEFT, 10, 9)
    st_h2 = S("h2", 12.6, 18, C_MAIN, TA_LEFT, 11, 4)
    st_h3 = S("h3", 11.2, 16, C_ACCENT, TA_LEFT, 8, 3)
    st_cap = S("cap", 8.6, 13, C_GREY, TA_CENTER, 3, 5)
    st_tbl = S("tbl", 8.6, 12, colors.black, TA_LEFT, 0, 0)
    st_tblh = S("tblh", 8.6, 12, colors.white, TA_CENTER, 0, 0)
    st_td = S("td", 8.6, 12, colors.black, TA_LEFT, 0, 0)
    st_tdc = S("tdc", 8.6, 12, C_MAIN, TA_CENTER, 0, 0)

    # ── 收集 docx 块（保持文档顺序）──
    from docx.table import Table as DTable
    from docx.text.paragraph import Paragraph as DPara
    items = []
    for child in doc.element.body.iterchildren():
        if child.tag.endswith("}p"):
            items.append(("p", DPara(child, doc)))
        elif child.tag.endswith("}tbl"):
            items.append(("t", DTable(child, doc)))

    # ── 定位"目录区"：目　录 标题之后、正文第 1 章之前 ──
    # 目录里的章节名和正文标题长得一模一样（都是 "1.1 xxx"），
    # 不隔离出来会被 _head_size 判成真标题 → 每个都触发 PageBreak，
    # 目录直接散成 10 页（实测踩过）。
    # ★ 结束边界不能用"下一个 '第 1 章'" —— 目录自己的第一条就是它，
    #   会把区间缩成 0 行。真正的边界是**正文前的显式分页符段落**
    #   （docx_engine.h1 用 WD_BREAK.PAGE 生成）。
    toc_start = toc_end = None
    for i, (kind, obj) in enumerate(items):
        if kind != "p":
            continue
        t = obj.text.strip()
        if toc_start is None and t == "目　录":
            toc_start = i
        elif toc_start is not None and toc_end is None and _has_page_break(obj):
            toc_end = i
            break
    if toc_start is not None and toc_end is None:
        toc_end = len(items)
    in_toc = lambda i: (toc_start is not None and toc_end is not None
                        and toc_start < i < toc_end)

    story = []
    n_tbl = n_code = n_h = n_para = n_toc = 0
    stats = {"callout": 0, "cover": 0}

    i = 0
    total = len(items)
    while i < total:
        kind, obj = items[i]
        # 目录条目：走紧凑目录样式，且不触发分页
        if in_toc(i):
            raw = obj.text.strip()
            if not raw or raw.startswith("（在 Word") \
                    or raw.startswith("下表为本文档"):
                i += 1
                continue
            lv = _toc_level(raw)
            if not lv:
                i += 1
                continue
            # 保留 H3 的 '· ' 标记（视觉上区分三级），靠样式缩进体现层级
            txt = raw.lstrip("　 \t")
            story.append(Paragraph(esc(txt), _toc_style(lv)))
            n_toc += 1
            i += 1
            continue
        if kind == "t":
            n_tbl += 1
            flow, kindtag = _render_table(obj, st_tblh, st_td, st_tdc, st_cap)
            if kindtag == "code":
                n_code += 1
            elif kindtag in stats:
                stats[kindtag] += 1
            if flow:
                story.append(flow)
            i += 1
            continue
        txt = obj.text.strip()
        if not txt:
            i += 1
            continue
        sz = _head_size(obj, txt)
        if sz == 1:
            if story:
                story.append(PageBreak())
            story.append(Paragraph(esc(txt), st_h1))
            n_h += 1
        elif sz == 2:
            story.append(Paragraph(esc(txt), st_h2))
            n_h += 1
        elif sz == 3:
            story.append(Paragraph(esc(txt), st_h3))
            n_h += 1
        elif txt.startswith("（在 Word") or txt.startswith("下表为本文档章节目录"):
            pass
        elif _is_caption(txt):
            story.append(Paragraph(esc(txt), st_cap))
        else:
            story.append(Paragraph(esc(txt), st_body))
            n_para += 1
        i += 1

    n_story = len(story)
    pdf.build(story)
    print("已生成：%s" % OUT)
    print("  流对象 %d 项 / 标题 %d 个 / 正文段 %d 段 / 目录行 %d 条"
          % (n_story, n_h, n_para, n_toc))
    print("  表格 %d 个（代码块 %d / 提示框 %d / 封面框 %d / 数据表 %d）"
          % (n_tbl, n_code, stats["callout"], stats["cover"],
             n_tbl - n_code - stats["callout"] - stats["cover"]))
    return OUT


def _toc_style(lv):
    """目录条目样式：比正文标题小、无 spaceBefore，避免目录占满整页。"""
    if lv == 1:
        return ParagraphStyle("toc1", fontName=FONTS, fontSize=11.2,
                              leading=15, textColor=C_MAIN,
                              alignment=TA_LEFT, spaceBefore=6, spaceAfter=1)
    if lv == 2:
        return ParagraphStyle("toc2", fontName=FONTS, fontSize=9.8,
                              leading=13, textColor=colors.black,
                              alignment=TA_LEFT, spaceBefore=0, spaceAfter=0,
                              leftIndent=13)
    return ParagraphStyle("toc3", fontName=FONTS, fontSize=9.2, leading=12.4,
                          textColor=C_GREY, alignment=TA_LEFT,
                          spaceBefore=0, spaceAfter=0, leftIndent=30)


def _has_page_break(p):
    """段落里是否有显式分页符（docx_engine.h1 / pagebreak 生成）。"""
    xml = p._p.xml
    return 'w:br' in xml and 'type="page"' in xml


def _strip_indent(t):
    """剥掉目录条目前缀的缩进标记（全角空格 U+3000 与 '· '）。

    ★ docx 的静态目录给每级加了缩进：'　1.1 xxx'（U+3000）、
      '　· 2.3.1 xxx'。不剥掉的话 `^\\d+\\.\\d+` 锚定失败 →
      _toc_level 全部返回 0 → 目录一行都不渲染。
    """
    return t.lstrip("　 \t·")


def _toc_level(t):
    t = _strip_indent(t)
    if re.match(r"^第\s*\d+\s*章", t):
        return 1
    if re.match(r"^\d+\.\d+\.\d+[\s　]", t):
        return 3
    if re.match(r"^\d+\.\d+[\s　]", t):
        return 2
    return 0


def _head_size(p, txt):
    """判断标题层级。

    ★ 不能只看样式名 —— docx 生成器用的是 Normal + 直接设置字号/加粗，
      样式名全是 Normal。必须用**文本特征**判定，否则目录里的章节名
      会被当成真标题（每个都触发 PageBreak，目录散成 10 页）。
    """
    t = txt.strip()
    if re.match(r"^第\s*\d+\s*章", t):
        return 1
    if t in ("重要内容预览", "目　录"):
        return 1
    if re.match(r"^\d+\.\d+\.\d+\s+\S", t) and len(t) < 46:
        return 3
    if re.match(r"^\d+\.\d+\s+\S", t) and len(t) < 46:
        return 2
    return 0


def _is_caption(t):
    """题注：表 x-y / 图 x-y / 代码清单 x-y"""
    return bool(re.match(r"^(表|图|代码清单)\s*\d+\s*[-－]\s*\d+", t.strip()))


def _cell_fill(cell):
    tcPr = cell._tc.find(qn("w:tcPr"))
    if tcPr is None:
        return None
    shd = tcPr.find(qn("w:shd"))
    if shd is None:
        return None
    return shd.get(qn("w:fill"))


def _is_code_block(txt):
    """保留给表格外的段落判据（当前正文里没有裸代码段，逻辑同 _render_table）。"""
    lines = txt.split("\n")
    if len(lines) < 3:
        return False
    ind = sum(1 for l in lines if l.startswith("    "))
    sym = sum(1 for l in lines if any(
        c in l for c in ("def ", "class ", "import ", "return", "()", "=")))
    return ind >= 2 and sym >= 2


def _code_flow(txt):
    """代码块 / 框线图：逐行 Paragraph + 中英混排。

    为什么不用 Preformatted：Preformatted 只能一个字体，Consolas 无中文
    字形 → 中文整段丢（实测 13 个代码块全中招）。
    为什么不用「整块一个 Paragraph」：reportlab 会把换行当空格，
    框线图会挤成一行。逐行 Paragraph 才保得住竖线对齐。
    """
    lines = txt.replace("\t", "    ").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return None, None
    st = ParagraphStyle("code", fontName=MONO, fontSize=CODE_ASC,
                        leading=CODE_LEAD, alignment=TA_LEFT,
                        spaceBefore=0, spaceAfter=0,
                        splitLongWords=0, allowWidows=0, allowOrphans=0,
                        wordWrap=None)
    flows = []
    for ln in lines:
        flows.append(Paragraph(_mono_markup(ln if ln.strip() else " "), st))
    # 超过大半屏的代码块不能 KeepTogether，否则 reportlab 因为放不下会把它
    # 整体推到下一页，前一页留大片空白。
    # ★ KeepTogether 不能放进 Table 单元格（reportlab 会算出 16777223pt
    #   的假高度并抛 LayoutError），所以单元格内始终是 Paragraph 列表。
    big = len(lines) * CODE_LEAD > BODY_H * 0.55
    t = Table([[flows]], colWidths=[cm * 15.0], splitByRow=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.6, C_CODE_LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    if big:
        return [Spacer(1, 3), t, Spacer(1, 5)], "code"
    return KeepTogether([Spacer(1, 3), t, Spacer(1, 5)]), "code"


def _vis(txt):
    """字符串的视觉宽度：中文/全角按 2，其余按 1。"""
    return sum(2 if ord(c) > 0x2E80 else 1 for c in str(txt))


def _col_widths(rows, ncol, avail=15.0):
    """按视觉宽度分配列宽，并保证每列不超过内容实际需要。

    关键是"夹逼"：先按内容宽度按比例分配，再对超出预算的列按比例削减、
    把省下的宽度补给还有富余的列。这样长文本列不会折行，短列也不会被撑开。
    """
    # 每列的「最长单元格」视觉宽度（取内容，不取表头 —— 表头通常较短，
    # 但若表头比内容还长则必须计入）
    need = []
    for ci in range(ncol):
        longest = max(_vis(r.cells[ci].text or "") for r in rows)
        need.append(max(2.0, min(longest + 1.5, avail * 0.55)))
    # 首列是"行标签"列，给保底宽度（否则「① AI基础设施与推理框架」这类
    # 标签会被折成两行，表格变得很难读）
    need[0] = max(need[0], 3.6)
    tot = sum(need)
    if tot <= avail:
        # 有富余：按比例放大（保持相对关系，不浪费版面）
        return [avail * w / tot for w in need]
    # 超预算：先给每列最小 1.6cm，剩余按 need 比例分配
    floor = [1.6] * ncol
    room = avail - sum(floor)
    out = [floor[i] + room * need[i] / tot for i in range(ncol)]
    return out


def _render_table(tb, st_tblh, st_td, st_tdc, st_cap=None):
    """返回 (flow, kindtag)。

    ★ 单列表格有三种完全不同的用途，靠**底纹色**区分，不能靠"列数 + 段落数"：
      - F4F6F9 → 代码块 / 框线图（等宽 + 中英混排）
      - EAF1FB → 提示框（微软雅黑，首行加粗深蓝 + 浅蓝底）
      - 无底纹 → 封面信息框
      实测踩过：早期版本只判"单列多段落=代码块"，把封面的中文信息框
      判成代码块 → Consolas 无中文字形 → 封面中文整块变空白。
    """
    rows = tb.rows
    if not rows:
        return None, None
    ncol = len(rows[0].cells)
    cell0 = rows[0].cells[0]
    fill = _cell_fill(cell0)
    ps = [p.text for p in cell0.paragraphs]
    txt = "\n".join(ps)

    if ncol == 1:
        if fill == FILL_CODE or (fill is None and _is_code_block(txt)):
            return _code_flow(txt)
        if fill == FILL_CALLOUT:
            return _callout_flow(ps), "callout"
        if fill == FILL_COVER or fill is None:
            return _cover_flow(ps), "cover"

    data = []
    for ri, r in enumerate(rows):
        cells = []
        for ci, c in enumerate(r.cells):
            ct = "\n".join(p.text for p in c.paragraphs if p.text.strip())
            if ri == 0:
                cells.append(Paragraph(esc(ct) or "&nbsp;", st_tblh))
            else:
                cells.append(Paragraph(esc(ct) or "&nbsp;",
                                       st_tdc if ci == 0 and ncol > 2 else st_td))
        data.append(cells)

    # 列宽按**实际渲染宽度**分配，不是按字符数。
    # ★ 用 len() 分配列宽有两个真实问题（都踩过）：
    #   ① 中文字符数少但渲染宽，英文数字多但渲染窄 —— 「语料条目数」(5 字)
    #      会比「① AI基础设施与推理框架」(13 字符) 宽，导致列宽分配反了；
    #   ② 分配完总宽固定 15cm，若某列文字超出就自动折行，首列被折成两行。
    # 改为按"字符视觉宽度"（中文按 2 计）排序，并给首列保底宽度。
    widths = _col_widths(rows, ncol)
    t = Table(data, colWidths=[cm * x for x in widths], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_TBL_HEAD),
        ("GRID", (0, 0), (-1, -1), 0.4, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    for ri in range(1, len(data)):
        if ri % 2 == 0:
            style.append(("BACKGROUND", (0, ri), (-1, ri), C_TBL_ALT))
    t.setStyle(TableStyle(style))
    return KeepTogether([Spacer(1, 2), t, Spacer(1, 6)]), "table"


def _callout_flow(ps):
    """提示框：首行标题（深蓝加粗）+ 其余正文（雅黑），浅蓝底 + 左侧深色条。"""
    st_t = ParagraphStyle("cot", fontName=FONTS, fontSize=9.8, leading=14,
                          textColor=C_MAIN, alignment=TA_LEFT,
                          spaceBefore=0, spaceAfter=2)
    st_p = ParagraphStyle("cop", fontName=FONTS, fontSize=9.4, leading=13.6,
                          textColor=colors.black, alignment=TA_JUSTIFY,
                          spaceBefore=0, spaceAfter=0)
    flows = []
    for i, line in enumerate(ps):
        if not line.strip():
            continue
        flows.append(Paragraph(esc(line), st_t if i == 0 else st_p))
    if not flows:
        return None
    t = Table([[flows]], colWidths=[cm * 15.0])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CALLOUT_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 2.6, C_ACCENT),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9DBF2")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return KeepTogether([Spacer(1, 3), t, Spacer(1, 6)])


def _cover_flow(ps):
    """封面信息框：雅黑 + 浅底 + 细边（绝不能走等宽路径）。"""
    st = ParagraphStyle("cov", fontName=FONTS, fontSize=9.6, leading=14.6,
                        alignment=TA_LEFT, spaceBefore=0, spaceAfter=1)
    st_k = ParagraphStyle("covk", parent=st, textColor=C_MAIN)
    flows = []
    for i, line in enumerate(ps):
        if not line.strip():
            continue
        head = line.strip().split("　")[0][:6]
        is_key = bool(re.match(r"^(系统规模|语料文档|数据源|检索词项|代码规模|"
                               r"接口规模|实测指标|风险分类|附件)$", head))
        flows.append(Paragraph(esc(line), st_k if is_key else st))
    if not flows:
        return None
    t = Table([[flows]], colWidths=[cm * 15.0])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_COVER_BG),
        ("BOX", (0, 0), (-1, -1), 0.7, C_ACCENT),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return KeepTogether([Spacer(1, 6), t, Spacer(1, 8)])


if __name__ == "__main__":
    build()
