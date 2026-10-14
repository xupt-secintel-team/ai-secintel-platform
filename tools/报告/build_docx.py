# -*- coding: utf-8 -*-
"""技术报告主装配：生成 .docx

用法：
    <venv-python> tools/报告/build_docx.py
    （venv-python 为装了 python-docx 的解释器，见 bootstrap.py）
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from docx_engine import C_MAIN, Report, _set_font  # noqa: E402
import part_a  # noqa: E402
import part_b  # noqa: E402
import part_c  # noqa: E402
import part_d  # noqa: E402
import part_e  # noqa: E402
import part_f  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "output", "AI-SecIntel2.0_技术报告.docx")


def finalize_toc(R, toc_anchor):
    """把占位段落替换成静态目录（带域代码，Word 里按 F9 可更新页码）。"""
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    from docx.shared import Pt

    para = toc_anchor
    body = para._p.getparent()
    idx = list(body).index(para._p)

    # 域代码目录（Word 打开后 F9 展开）
    fld_p = para.insert_paragraph_before()
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), r'TOC \o "1-2" \h \z \u')
    inner = OxmlElement("w:r")
    t = OxmlElement("w:t")
    t.text = "（在 Word 中全选后按 F9 可自动生成带页码的目录）"
    inner.append(t)
    fld.append(inner)
    fld_p._p.append(fld)

    # 静态目录
    for lv, text in R.toc_entries:
        if lv == 1 and text in ("目　录", "重要内容预览"):
            continue
        p = para.insert_paragraph_before()
        pf = p.paragraph_format
        pf.left_indent = Pt(0 if lv == 1 else 14)
        pf.space_after = Pt(3 if lv == 1 else 1)
        pf.space_before = Pt(7 if lv == 1 else 0)
        prefix = "" if lv == 1 else ("　" if lv == 2 else "　· ")
        r = p.add_run(prefix + text)
        _set_font(r, cn="微软雅黑", en="微软雅黑", size=11.5 if lv == 1 else 10,
                  bold=(lv == 1), color=C_MAIN if lv == 1 else None)

    body.remove(para._p)


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    R = Report()

    part_a.build_cover(R)
    part_a.build_preview(R)

    # 目录占位（正文写完后回填）
    part_a.build_toc(R)
    toc_anchor = R.doc.paragraphs[-1]

    part_a.build_ch1(R)
    part_b.build_ch2(R)
    part_b.build_ch3(R)
    part_c.build_ch4(R)
    part_c.build_ch5(R)
    part_d.build_ch6(R)
    part_d.build_ch7(R)
    part_e.build_ch8(R)
    part_f.build_ch9(R)      # 第 9 章：各功能模块实现效果展示（实测数据）
    part_e.build_ch9(R)      # 第 10 章：创新点总结
    part_e.build_ch10(R)     # 第 11 章：结论与展望

    finalize_toc(R, toc_anchor)
    R.save(OUT)
    print("已生成：%s" % OUT)
    print("  章节条目 %d 条（H1 %d / H2 %d / H3 %d）" % (
        len(R.toc_entries),
        sum(1 for e in R.toc_entries if e[0] == 1),
        sum(1 for e in R.toc_entries if e[0] == 2),
        sum(1 for e in R.toc_entries if e[0] == 3)))


if __name__ == "__main__":
    main()
