# -*- coding: utf-8 -*-
"""技术报告 → Word（.docx）生成器

设计要点
--------
1. **代码块逐行保留**：Word 里代码必须"一段一行"且等宽，否则复制出来全是一坨。
   python-docx 默认会把整个段落当一行，所以每行单独 add_run 并换行。
2. **中文字体必须显式设置**：不设 eastAsia 字体时 Word 会用宋体渲染代码，
   等宽失效。
3. **目录用域代码**：插入 TOC 域，打开文档按 F9 才会展开页码。
   同时给一份静态目录兜底（有些阅读器不展开域）。
"""
import os
import sys

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

# ── 主题色（与系统控制台一致的学术蓝）──
C_MAIN = RGBColor(0x1F, 0x3A, 0x6E)      # 深蓝：标题
C_ACCENT = RGBColor(0x2E, 0x6D, 0xD4)    # 亮蓝：强调
C_GREY = RGBColor(0x55, 0x5F, 0x6D)      # 灰：注释
C_CODE_BG = "F4F6F9"
C_TBL_HEAD = "1F3A6E"
C_TBL_ALT = "F2F5FA"

FONT_CN = "微软雅黑"
FONT_CN_BODY = "宋体"
FONT_EN = "Times New Roman"
FONT_MONO = "Consolas"


def _set_font(run, cn=FONT_CN_BODY, en=FONT_EN, size=10.5, bold=False,
              color=None, mono=False):
    """字体必须三处都设：name / eastAsia / ascii，否则中文回退宋体。"""
    name = FONT_MONO if mono else en
    r = run.font          # run.font 本身就是 Font 对象
    r.name = name
    r.size = Pt(size)
    r.bold = bold
    if color is not None:
        r.color.rgb = color
    rPr = run._element.get_or_add_rPr()
    rf = rPr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts")
        rPr.append(rf)
    rf.set(qn("w:ascii"), FONT_MONO if mono else en)
    rf.set(qn("w:hAnsi"), FONT_MONO if mono else en)
    rf.set(qn("w:eastAsia"), cn)


def _shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:color"), "auto")
    sh.set(qn("w:fill"), hexcolor)
    tcPr.append(sh)


def _borders(tbl, color="BFC8D6", sz=4):
    tblPr = tbl._tbl.tblPr
    bd = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement("w:" + edge)
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), str(sz))
        e.set(qn("w:color"), color)
        bd.append(e)
    tblPr.append(bd)


class Report:
    """报告文档构建器"""

    def __init__(self):
        self.doc = Document()
        self.toc_entries = []
        self._setup()
        self.page_no = 0

    def _setup(self):
        d = self.doc
        for s in d.sections:
            s.page_width = Cm(21.0)      # A4
            s.page_height = Cm(29.7)
            s.left_margin = Cm(2.6)
            s.right_margin = Cm(2.4)
            s.top_margin = Cm(2.5)
            s.bottom_margin = Cm(2.3)
        st = d.styles["Normal"]
        st.font.name = FONT_EN
        st.font.size = Pt(10.5)
        st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT_CN_BODY)
        st.paragraph_format.line_spacing = 1.5
        st.paragraph_format.space_after = Pt(4)

    # ── 页眉页脚 ──
    def _footer(self, section):
        p = section.footer.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run("第 ")
        _set_font(r, size=9, color=C_GREY)
        # PAGE 域
        fld = OxmlElement("w:fldSimple")
        fld.set(qn("w:instr"), "PAGE")
        p._p.append(fld)
        r = p.add_run(" 页 · AI-SecIntel 2.0 技术报告")
        _set_font(r, size=9, color=C_GREY)

    def new_section(self, restart=False):
        s = self.doc.add_section(WD_SECTION.NEW_PAGE)
        if restart:
            s.footer.is_linked_to_previous = False
            p = s.footer.paragraphs[0]
            for r in list(p.runs):
                r._element.getparent().remove(r._element)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run("第 ")
            _set_font(r, size=9, color=C_GREY)
            fld = OxmlElement("w:fldSimple")
            fld.set(qn("w:instr"), "PAGE")
            p._p.append(fld)
            r = p.add_run(" 页 · AI-SecIntel 2.0 技术报告")
            _set_font(r, size=9, color=C_GREY)
        return s

    # ── 标题 ──
    def h1(self, text, page_break=True):
        if page_break:
            self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(10)
        r = p.add_run(text)
        _set_font(r, cn=FONT_CN, en=FONT_CN, size=17, bold=True, color=C_MAIN)
        # 下划线
        pPr = p._p.get_or_add_pPr()
        bd = OxmlElement("w:pBdr")
        bt = OxmlElement("w:bottom")
        bt.set(qn("w:val"), "single")
        bt.set(qn("w:sz"), "12")
        bt.set(qn("w:space"), "4")
        bt.set(qn("w:color"), "2E6DD4")
        bd.append(bt)
        pPr.append(bd)
        self.toc_entries.append((1, text))
        return p

    def h2(self, text):
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(5)
        r = p.add_run(text)
        _set_font(r, cn=FONT_CN, en=FONT_CN, size=13.5, bold=True, color=C_MAIN)
        self.toc_entries.append((2, text))
        return p

    def h3(self, text):
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(text)
        _set_font(r, cn=FONT_CN, en=FONT_CN, size=11.5, bold=True, color=C_ACCENT)
        self.toc_entries.append((3, text))
        return p

    def para(self, text, size=10.5, indent=True, align="just", color=None,
             bold=False, italic=False):
        p = self.doc.add_paragraph()
        p.alignment = {"just": WD_ALIGN_PARAGRAPH.JUSTIFY,
                       "left": WD_ALIGN_PARAGRAPH.LEFT,
                       "center": WD_ALIGN_PARAGRAPH.CENTER}[align]
        p.paragraph_format.first_line_indent = Cm(0.74) if indent else Cm(0)
        p.paragraph_format.line_spacing = 1.5
        r = p.add_run(text)
        _set_font(r, size=size, color=color, bold=bold)
        r.italic = italic
        return p

    def rich(self, parts, indent=True, size=10.5):
        """parts = [(text, {bold/color/mono}), ...] 混排（行内代码、加粗）"""
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.first_line_indent = Cm(0.74) if indent else Cm(0)
        p.paragraph_format.line_spacing = 1.5
        for text, opt in parts:
            r = p.add_run(text)
            _set_font(r, size=opt.get("size", size), bold=opt.get("bold", False),
                      color=opt.get("color"), mono=opt.get("mono", False),
                      cn=FONT_CN if opt.get("mono") else FONT_CN_BODY)
        return p

    def bullet(self, text, level=0, size=10.5):
        p = self.doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.75 + level * 0.62)
        p.paragraph_format.line_spacing = 1.4
        p.paragraph_format.space_after = Pt(2)
        marks = ["● ", "○ ", "▪ "]
        r = p.add_run(marks[min(level, 2)] + text)
        _set_font(r, size=size)
        return p

    def numbered(self, idx, text, size=10.5):
        p = self.doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.8)
        p.paragraph_format.line_spacing = 1.45
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run("%s %s" % (idx, text))
        _set_font(r, size=size)
        return p

    def caption(self, text):
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(8)
        r = p.add_run(text)
        _set_font(r, size=9, bold=True, color=C_GREY)
        return p

    def code(self, code_text, caption=None, size=8.6):
        """代码块：每行一个**独立段落**，缩进与等宽都保留。

        为什么不用「一个段落 + run 内\\n」：那样 Word 存的是一个段落里多个 run，
        复制出来会粘行、字号失控，回读校验也不好断言行数。独立段落最稳。
        """
        if caption:
            self.caption(caption)
        tbl = self.doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        _borders(tbl, color="D8DEE9")
        cell = tbl.rows[0].cells[0]
        _shade(cell, C_CODE_BG)
        cell.text = ""
        first = True
        for line in code_text.rstrip("\n").split("\n"):
            p = cell.paragraphs[0] if first else cell.add_paragraph()
            first = False
            pf = p.paragraph_format
            pf.line_spacing = 1.06
            pf.space_after = Pt(0)
            pf.space_before = Pt(0)
            r = p.add_run(line if line.strip() else " ")
            _set_font(r, cn=FONT_MONO, en=FONT_MONO, size=size, mono=True)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return tbl

    def table(self, headers, rows, widths=None, caption=None, size=9.2,
              align_right=None, highlight_col=None):
        if caption:
            self.caption(caption)
        tbl = self.doc.add_table(rows=1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        _borders(tbl)
        align_right = align_right or []
        # 表头
        for i, h in enumerate(headers):
            c = tbl.rows[0].cells[i]
            _shade(c, C_TBL_HEAD)
            c.text = ""
            p = c.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.space_before = Pt(1)
            r = p.add_run(str(h))
            _set_font(r, cn=FONT_CN, en=FONT_CN, size=size, bold=True,
                      color=RGBColor(0xFF, 0xFF, 0xFF))
        # 数据行
        for ri, row in enumerate(rows):
            cells = tbl.add_row().cells
            for i, v in enumerate(row):
                c = cells[i]
                if ri % 2 == 1:
                    _shade(c, C_TBL_ALT)
                c.text = ""
                p = c.paragraphs[0]
                p.paragraph_format.space_after = Pt(1)
                p.paragraph_format.space_before = Pt(1)
                p.paragraph_format.line_spacing = 1.15
                if i in align_right:
                    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
                r = p.add_run(str(v))
                bold = (highlight_col is not None and i == highlight_col)
                _set_font(r, size=size, bold=bold,
                          color=C_MAIN if bold else None)
        if widths:
            for row in tbl.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Cm(w)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return tbl

    def callout(self, title, text, color="EAF1FB", bar="2E6DD4"):
        """提示框：单元格 + 左侧色条"""
        tbl = self.doc.add_table(rows=1, cols=1)
        _borders(tbl, color=bar, sz=4)
        c = tbl.rows[0].cells[0]
        _shade(c, color)
        c.text = ""
        p = c.paragraphs[0]
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(title)
        _set_font(r, cn=FONT_CN, en=FONT_CN, size=10, bold=True, color=C_MAIN)
        p2 = c.add_paragraph()
        p2.paragraph_format.line_spacing = 1.4
        r2 = p2.add_run(text)
        _set_font(r2, size=9.6)
        self.doc.add_paragraph().paragraph_format.space_after = Pt(2)
        return tbl

    def pagebreak(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def save(self, path):
        self.doc.save(path)
        return path
