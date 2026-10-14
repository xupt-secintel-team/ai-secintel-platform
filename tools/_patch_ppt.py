# -*- coding: utf-8 -*-
"""按校内初赛提交要求，同步更新技术讲解 PPT。

改动：
  1. 封面后插入「成果预览」页（九项核心亮点，3×3 卡片）—— 呼应提交要求的"重要内容预览页"
  2. slide 3 架构页：四智能体 → 六智能体
  3. slide 4 智能体页：四角色方块 → 六角色方块（重排坐标）
  4. slide 17 创新页：六个创新点 → 六个方向性创新 + 九大具名创新点
  5. 全量页码标记 NN / 16 → (NN+1) / 总页数

用法： <系统 python> tools/_patch_ppt.py
输出： D:\\111111\\备份\\AI-SecIntel_2.0_技术讲解_终稿.pptx
"""
import copy
import re

from pptx import Presentation
from pptx.util import Emu, Pt

SRC = r"D:\111111\备份\AI-SecIntel_2.0_技术讲解_终版优化3.0_视频位(1).pptx"
DST = r"D:\111111\备份\AI-SecIntel_2.0_技术讲解_终稿.pptx"

prs = Presentation(SRC)


def set_text(shape, text, size=None):
    """替换文本框内容，保留首个 run 的格式；size 为 pt 时覆盖字号。"""
    tf = shape.text_frame
    for p in tf.paragraphs[1:]:
        p._p.getparent().remove(p._p)
    p0 = tf.paragraphs[0]
    runs = p0.runs
    if runs:
        runs[0].text = text
        for r in runs[1:]:
            r._r.getparent().remove(r._r)
        if size:
            runs[0].font.size = Pt(size)
    else:
        r = p0.add_run()
        r.text = text
        if size:
            r.font.size = Pt(size)


def set_lines(shape, lines, size=None):
    """多行文本：首段保留格式，其余段落深拷贝首段。"""
    tf = shape.text_frame
    for p in tf.paragraphs[1:]:
        p._p.getparent().remove(p._p)
    p0 = tf.paragraphs[0]
    if p0.runs:
        p0.runs[0].text = lines[0]
        for r in p0.runs[1:]:
            r._r.getparent().remove(r._r)
    else:
        p0.add_run().text = lines[0]
    if size:
        for r in p0.runs:
            r.font.size = Pt(size)
    cur = p0._p
    for ln in lines[1:]:
        newp = copy.deepcopy(p0._p)
        cur.addnext(newp)
        cur = newp
    tf2 = shape.text_frame
    for i, ln in enumerate(lines):
        p = tf2.paragraphs[i]
        if p.runs:
            p.runs[0].text = ln
            for r in p.runs[1:]:
                r._r.getparent().remove(r._r)
        else:
            p.add_run().text = ln
        if size:
            for r in p.runs:
                r.font.size = Pt(size)


def is_blank(sh):
    return (not sh.has_text_frame) or (not sh.text_frame.text.strip())


def clone(shape, spTree):
    el = copy.deepcopy(shape._element)
    spTree.append(el)
    return el


# ══════════════════════════════════════════════════════════════════
# 2. slide 3 架构页
# ══════════════════════════════════════════════════════════════════
def patch_slide3():
    for sh in prs.slides[2].shapes:
        if sh.has_text_frame and "四智能体" in sh.text_frame.text:
            set_text(sh, "六智能体事件驱动编排 · 感知→编排→富化→研判→决策→质疑")
            print("  [3] →", sh.text_frame.text)


# ══════════════════════════════════════════════════════════════════
# 4. slide 17 创新页
# ══════════════════════════════════════════════════════════════════
def patch_slide17():
    for sh in prs.slides[16].shapes:
        if not sh.has_text_frame:
            continue
        t = sh.text_frame.text.strip()
        if t == "六个创新点":
            set_text(sh, "六个方向性创新 · 九大具名创新点")
            print("  [17] 标题 →", sh.text_frame.text)
        elif t.startswith("三个做得比别人深"):
            set_text(sh, "三个做得比别人深 + 三个把专业度做扎实，合计九个具名创新点")
            print("  [17] 副标题 →", sh.text_frame.text)
        elif "四智能体事件驱动编排" in t:
            set_text(sh, "六智能体事件驱动编排，决策/质疑红蓝对抗，trace 全链路留痕可审计")
            print("  [17] ⑤ →", sh.text_frame.text)
        elif t.startswith("五项关键能力各配可复跑验证工具"):
            set_text(sh, "五项关键能力各配可复跑验证工具，系统自测 92/92 全通过")
            print("  [17] ⑥ →", sh.text_frame.text)


# ══════════════════════════════════════════════════════════════════
# 3. slide 4：四角色方块 → 六角色方块
# ══════════════════════════════════════════════════════════════════
ROLES = [
    ("感知", "消费监测流\n筛选高价值事件"),
    ("编排", "事件驱动调度\n节拍 60s/轮"),
    ("富化执行", "调用富化能力\nPOC/资产/论文"),
    ("研判", "生成研判简报\n可借问答深解释"),
    ("决策", "P0/P1/P2 处置\n可解释推理链"),
    ("质疑", "红蓝自博弈\n命中即就地修正"),
]
X0, STEP, CW = 1043787, 1712020, 1544020


def patch_slide4():
    sl = prs.slides[3]
    spTree = sl.shapes._spTree

    bgs = [sh for sh in sl.shapes if is_blank(sh) and 1700000 < (sh.top or 0) < 1800000
           and 1500000 < (sh.width or 0) < 3000000]
    tbs = [sh for sh in sl.shapes if not is_blank(sh) and 1880000 < (sh.top or 0) < 1960000]
    dbs = [sh for sh in sl.shapes if not is_blank(sh) and 2330000 < (sh.top or 0) < 2420000]
    ars = [sh for sh in sl.shapes if is_blank(sh) and 2250000 < (sh.top or 0) < 2320000]
    bgs.sort(key=lambda s: s.left or 0)
    tbs.sort(key=lambda s: s.left or 0)
    dbs.sort(key=lambda s: s.left or 0)
    ars.sort(key=lambda s: s.left or 0)
    print("  [4] 分组：背景 %d / 标题 %d / 说明 %d / 箭头 %d" % (len(bgs), len(tbs), len(dbs), len(ars)))

    # 补足到 6 组（用第 3、4 组作模板）
    while len(bgs) < 6:
        clone(bgs[2], spTree)
        clone(tbs[2], spTree)
        clone(dbs[2], spTree)
        bgs = [sh for sh in sl.shapes if is_blank(sh) and 1700000 < (sh.top or 0) < 1800000
               and 1500000 < (sh.width or 0) < 3000000]
        tbs = [sh for sh in sl.shapes if not is_blank(sh) and 1880000 < (sh.top or 0) < 1960000]
        dbs = [sh for sh in sl.shapes if not is_blank(sh) and 2330000 < (sh.top or 0) < 2420000]
        bgs.sort(key=lambda s: s.left or 0)
        tbs.sort(key=lambda s: s.left or 0)
        dbs.sort(key=lambda s: s.left or 0)
    while len(ars) < 5:
        clone(ars[0], spTree)
        ars = [sh for sh in sl.shapes if is_blank(sh) and 2250000 < (sh.top or 0) < 2320000]
        ars.sort(key=lambda s: s.left or 0)

    # 重排 6 个方块
    for i in range(6):
        x = X0 + i * STEP
        bgs[i].left, bgs[i].width = Emu(x), Emu(CW)
        tbs[i].left, tbs[i].width = Emu(x), Emu(CW)
        dbs[i].left, dbs[i].width = Emu(x + 90000), Emu(CW - 180000)
        set_text(tbs[i], ROLES[i][0], size=17)
        set_lines(dbs[i], ROLES[i][1].split("\n"), size=10.5)

    # 重排 5 个箭头（夹在方块之间）
    for i in range(5):
        x = X0 + i * STEP + CW + (STEP - CW) // 2
        ars[i].left = Emu(x - 137160)
        ars[i].width = Emu(274320)

    # 副标题：四智能体 → 六智能体（原稿用「，」分隔，不含 ⇄）
    for sh in sl.shapes:
        if sh.has_text_frame and "四智能体事件驱动" in sh.text_frame.text:
            set_text(sh, "感知 → 编排 → 富化执行 → 研判 → 决策 ←→ 质疑，六智能体事件驱动")
            print("  [4] 副标题 →", sh.text_frame.text)


# ══════════════════════════════════════════════════════════════════
# 1. 插入「成果预览」页（复制 slide 17 版式，改 3×3 九宫格）
# ══════════════════════════════════════════════════════════════════
HIGHLIGHTS = [
    ("六智能体主动盯梢", "感知→编排→富化→研判→决策→质疑，60s 节拍事件驱动"),
    ("红蓝自博弈决策", "质疑智能体对抗审视决策，CVSS 9.8 误判自动升档 P0"),
    ("处置闭环回填", "同 CVE 秒判、同组件关联复用，系统越用越准"),
    ("CTI 多跳知识图谱", "组件→资产→攻击技术→战术多跳游走，路径可解释"),
    ("溯源归因", "威胁主体画像（含置信度）+ ATT&CK 战术链路"),
    ("四级评分检索", "BM25 + 领域短语 + 概念空间 + 业务信号，中位 15ms"),
    ("双通道监测", "15 秒快车道 + 分钟级深同步，提交收录 < 3 秒"),
    ("索引尾部增量", "破解启动退化死循环，冷启动 355s → 8.9s"),
    ("跨环境自适应", "三档性能画像 + 一键环境配置，自测 92/92 全通过"),
]
CW2, CH2 = 3412405, 1166196
CX0, CSTEP = 777240, 3612405
CY0, RSTEP = 1701410, 1316196


def build_preview_slide():
    src = prs.slides[16]
    blank = prs.slide_layouts[6]
    new = prs.slides.add_slide(blank)
    for shp in src.shapes:
        new.shapes._spTree.append(copy.deepcopy(shp._element))

    # 移到第 2 位（封面之后）
    lst = prs.slides._sldIdLst
    ids = list(lst)
    lst.remove(ids[-1])
    lst.insert(1, ids[-1])

    sl = prs.slides[1]
    spTree = sl.shapes._spTree

    # 顶部文字
    for sh in sl.shapes:
        if not sh.has_text_frame:
            continue
        t = sh.text_frame.text.strip()
        if t == "08  创新":
            set_text(sh, "00  成果预览")
        elif t.startswith("六个方向性创新"):
            set_text(sh, "成果预览：九项核心亮点")
        elif t.startswith("三个做得比别人深"):
            set_text(sh, "功能 · 性能 · 工程可靠性 —— 每一项都有实测数据与自测用例支撑")
        elif t.startswith("用工程方法把"):
            set_text(sh, "监测 · 富化 · 问答全链路打通，并额外做到主动盯梢、自我进化与跨环境可用")
        elif re.match(r"^\d{1,2}\s*/\s*16$", t):
            set_text(sh, "02 / 20")

    # 取 6 组卡片元素并按类别收集（靠宽高特征区分，卡片共 3 行 × 2 列）
    def _cards():
        t = [sh for sh in sl.shapes if not is_blank(sh)
             and (sh.width or 0) < 900000 and (sh.height or 0) > 300000]
        ti = [sh for sh in sl.shapes if not is_blank(sh)
              and (sh.height or 0) < 400000 and 4000000 < (sh.width or 0) < 4500000]
        d = [sh for sh in sl.shapes if not is_blank(sh)
             and 500000 < (sh.height or 0) < 700000 and (sh.width or 0) < 6000000]
        b = [sh for sh in sl.shapes if is_blank(sh)
             and (sh.height or 0) > 1000000 and 4000000 < (sh.width or 0) < 6000000]
        for grp in (t, ti, d, b):
            grp.sort(key=lambda s: ((s.top or 0), (s.left or 0)))
        return t, ti, d, b

    tbs, titles, descs, bgs = _cards()
    print("  [预览页] 编号 %d / 标题 %d / 说明 %d / 背景 %d" % (len(tbs), len(titles), len(descs), len(bgs)))

    # 扩到 9 组
    while len(tbs) < 9:
        clone(tbs[0], spTree)
        clone(titles[0], spTree)
        clone(descs[0], spTree)
        clone(bgs[0], spTree)
        tbs, titles, descs, bgs = _cards()

    # 先把 9 个卡片背景压到文字层之下，否则后添加的背景会盖住卡片文字
    anchor_el = tbs[0]._element
    for bg in bgs:
        anchor_el.addprevious(bg._element)

    for i in range(9):
        r, c = divmod(i, 3)
        x = CX0 + c * CSTEP
        y = CY0 + r * RSTEP
        bgs[i].left, bgs[i].top = Emu(x), Emu(y)
        bgs[i].width, bgs[i].height = Emu(CW2), Emu(CH2)
        tbs[i].left, tbs[i].top = Emu(x + 215088), Emu(y + 81670)
        titles[i].left, titles[i].top = Emu(x + 809244), Emu(y + 81670)
        titles[i].width = Emu(CW2 - 1097280)
        descs[i].left, descs[i].top = Emu(x + 809244), Emu(y + 447430)
        descs[i].width = Emu(CW2 - 1097280)
        set_text(tbs[i], "①②③④⑤⑥⑦⑧⑨"[i], size=20)
        set_text(titles[i], HIGHLIGHTS[i][0], size=14)
        set_text(descs[i], HIGHLIGHTS[i][1], size=10)
    return sl


# ══════════════════════════════════════════════════════════════════
# 5. 页码标记 NN / 16 → (NN+1) / 总页数
# ══════════════════════════════════════════════════════════════════
def fix_page_numbers():
    """原稿页码 NN / 16 → 新稿 NN+1 / 总页数。

    注意：必须用「/ 16」这一原稿特征串来匹配，不能泛化成 \\d+/\\d+——
    否则会把性能页的 78/78 指标块误判成页码。
    """
    total = len(prs.slides._sldIdLst)
    pat = re.compile(r"^(\d{1,2})\s*/\s*16$")
    n = 0
    for idx, sl in enumerate(prs.slides):
        for sh in sl.shapes:
            if not sh.has_text_frame:
                continue
            t = sh.text_frame.text.strip()
            m = pat.match(t)
            if m:
                set_text(sh, "%02d / %d" % (int(m.group(1)) + 1, total))
                n += 1
    print("  页码更新 %d 处（分母 → %d）" % (n, total))


# ══════════════════════════════════════════════════════════════════
# 6. 旧版残留数字：78 项自测 → 92 项
# ══════════════════════════════════════════════════════════════════
def fix_residuals():
    """项目已从 78 项自测演进到 92 项，把 PPT 里残留的旧数字全部改掉。

    必须在 fix_page_numbers() 之后执行——本函数只认「78」，
    而页码归一化只认「/ 16」，两者互不干扰。
    """
    n = 0
    for sl in prs.slides:
        for sh in sl.shapes:
            if not sh.has_text_frame:
                continue
            t = sh.text_frame.text
            if "78" not in t:
                continue
            nt = (t.replace("78/78", "92/92")
                   .replace("系统自测 78项", "系统自测 92 项")
                   .replace("自测 78 项", "自测 92 项")
                   .replace("自测 78项", "自测 92 项"))
            if nt != t:
                set_lines(sh, nt.split("\n"))
                print("    ·", t.replace("\n", " | ")[:40], "→", nt.replace("\n", " | ")[:40])
                n += 1
    print("  残留修正 %d 处" % n)


patch_slide3()
patch_slide17()
patch_slide4()
build_preview_slide()
fix_page_numbers()
fix_residuals()

prs.save(DST)
print("已保存 →", DST, "| 共", len(prs.slides._sldIdLst), "页")
