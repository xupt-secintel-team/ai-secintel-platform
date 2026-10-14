# -*- coding: utf-8 -*-
"""报告渲染自检：抓 Markdown 表格错版、空单元格、裸 URL、数字自相矛盾。

为什么需要：报告正文是给人看的，「表格列数不齐」「单元格空白」「裸 URL 把
后面的字吞进链接」这类问题在终端看不出来（读源码是好的），只在渲染后的
Markdown 里才暴露。评审看的就是渲染结果。

★ 2026-10-05 首次跑就抓到 3 个真问题：
  1. 第五章「超变更窗口执行」行少一列 → 整表列数不一致，渲染后错位
  2. 附录 C 工单表「官方链接」列对内部编号是空串 → 出现 `| |` 空单元格
  3. 发现项明细里 36 处裸 URL → Markdown 渲染器把「｜」后内容吞进链接

用法：
    python tools/_check_report_render.py                 # 跑小样本并自检
    python tools/_check_report_render.py --md <路径>     # 自检已有 Markdown
"""
import argparse
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = r"E:\cmdb\csv"

# —— 小样本：够触发所有渲染分支，又不至于跑十几分钟 ——
SMOKE_FILES = [
    ("vulnerability.csv", 21), ("physical_server.csv", 101),
    ("ip_allocation.csv", 101), ("change_order.csv", 101),
    ("config_audit_log.csv", 101), ("ci_relation.csv", 201),
    ("ci_lifecycle_log.csv", 101), ("employee.csv", 51),
    ("api_endpoint.csv", 51), ("domain_cert.csv", 51),
    ("idc_room.csv", 11), ("cabinet.csv", 11),
]

STATES = {"待处置", "待确认（需人工复现）", "修复中", "已关闭", "已接受"}


def build_smoke_md(out_path):
    """用小样本数据跑一次完整流水线并返回 Markdown。"""
    import csv
    import itertools
    sys.path.insert(0, os.path.join(ROOT, "core"))
    sys.path.insert(0, os.path.join(ROOT, "modules", "m2_enrich", "backend"))
    import cmdb_scan as CS
    cfg = {"mode": "file", "name": "渲染自检（小样本）", "files": []}
    for fname, n in SMOKE_FILES:
        p = os.path.join(SRC, fname)
        if not os.path.isfile(p):
            continue
        with io.open(p, encoding="utf-8-sig") as fh:
            rows = list(itertools.islice(csv.reader(fh), n))
        body = "\n".join(
            ",".join('"%s"' % c.replace('"', '""') if ("," in c or '"' in c) else c
                     for c in r) for r in rows)
        cfg["files"].append({"filename": fname, "data": body.encode("utf-8")})
    res = CS.analyze(None, cfg)
    if not res.get("ok"):
        raise SystemExit("pipeline failed: %s" % res.get("error"))
    md = CS.report_to_markdown(res["report"])
    if out_path:
        with io.open(out_path, "w", encoding="utf-8") as f:
            f.write(md)
    return md


def audit(md):
    issues = []
    lines = md.splitlines()

    # —— 1. 表格列数一致（渲染错位最直接的原因）——
    i = 0
    while i < len(lines):
        if lines[i].startswith("|"):
            start = i
            counts = []
            while i < len(lines) and lines[i].startswith("|"):
                counts.append(lines[i].count("|"))
                i += 1
            if len(counts) >= 2:
                mode = max(set(counts), key=counts.count)
                for j in range(start, i):
                    if lines[j].count("|") != mode:
                        issues.append(
                            "表格列数不一致：行 %d 有 %d 个 |，同表其余是 %d 个 → %s"
                            % (j + 1, lines[j].count("|"), mode,
                               lines[j][:80]))
                        break
        else:
            i += 1

    # —— 2. 空单元格 ——
    for n, ln in enumerate(lines, 1):
        if ln.startswith("|") and "---" not in ln and re.search(r"\|\s*\|\s*$", ln):
            issues.append("空单元格：行 %d → %s" % (n, ln[:90]))

    # —— 3. 裸 URL（未写成 [文字](url)）——
    for m in re.finditer(r"(?<!\()https?://[^\s|）)]+", md):
        ln = md.count("\n", 0, m.start()) + 1
        issues.append("裸 URL（应写成 [文字](链接)）：行 %d → %s"
                      % (ln, m.group(0)[:70]))
        break                      # 只报第一处，避免刷屏

    # —— 4. 未替换的格式化占位符 ——
    for n, ln in enumerate(lines, 1):
        if not ln.startswith("|"):
            continue
        for pat in ("%s", "%d", "%.1f", "%.2f"):
            if pat in ln:
                issues.append("疑似未替换的占位符 %s：行 %d → %s"
                              % (pat, n, ln[:80]))
                break

    # —— 5. 重复单位（「30 天 天」）——
    for m in re.finditer(r"(\d+)\s*(天|条|台|个)\s*\1", md):
        ln = md.count("\n", 0, m.start()) + 1
        issues.append("重复单位：行 %d → %r" % (ln, m.group(0)))

    # —— 6. 七章齐全且顺序正确 ——
    secs = re.findall(r"^## ([一二三四五六七])、", md, re.M)
    if secs != list("一二三四五六七"):
        issues.append("七章不完整或顺序错：%s" % (secs or "无"))
    apps = re.findall(r"^# 附录 ([A-F]) ", md, re.M)
    if apps != list("ABCDEF"):
        issues.append("附录 A~F 不完整或顺序错：%s" % (apps or "无"))

    # —— 7. 发现项编号自洽 ——
    details = re.findall(r"^#### (CMDB-[0-9A-F]{1,4}-\d{3}) ", md, re.M)
    ids = set(re.findall(r"CMDB-[0-9A-F]{1,4}-\d{3}", md))
    if details and len(details) != len(set(details)):
        issues.append("发现编号重号：%d 条明细 / %d 个唯一编号"
                      % (len(details), len(set(details))))
    # ★ 不能要求「全文出现的编号 == 明细编号」：已闭环/已接受的条目排在
    #   6.3 附表里、故意不展开明细（派发表只列需要行动的）。2026-10-05 把
    #   已闭环项移出派发表后，这条老断言立刻报「差集」——是断言过时，不是报告错。
    #   改成：派发表（6.0）的编号必须有明细，6.3 附表编号允许只出现在表里。
    def _sec_ids(h):
        m = re.search(h, md, re.M)
        if not m:
            return set()
        nxt = re.search(r"^#{2,3} ", md[m.end():], re.M)
        seg = md[m.end():m.end() + nxt.start()] if nxt else md[m.end():]
        return set(re.findall(r"CMDB-[0-9A-F]{1,4}-\d{3}", seg))

    dispatch = _sec_ids(r"^### 6\.0 待派发工单")
    # ★ 派发表条数可以多于明细条数（明细有 20 条上限，被截断的已在 6.1 显式声明）——
    #   所以这里只查**反向**：明细里有、派发表里没有的（= 派发表漏了必须开工单的东西）。
    #   早期版本查的是 dispatch - details，方向错了：派发表 60 / 明细 20 是正常截断。
    if details and set(details) - dispatch:
        issues.append("明细里有编号但派发表没列（会被漏派单）：%s"
                      % sorted(set(details) - dispatch)[:3])
    lost = ids - set(details) - dispatch - _sec_ids(r"^### 6\.3 已闭环")
    if lost:
        issues.append("编号既无明细也不在派发/闭环表中（可能漏排）：%s"
                      % sorted(lost)[:3])

    # —— 8. 状态取值合法 ——
    states = set(re.findall(r"\| (%s) \|" % "|".join(map(re.escape, STATES)), md))
    stray = states - STATES
    if stray:
        issues.append("自造状态值：%s" % stray)

    # —— 9. 关键数字自洽 ——
    #   ★ 三个口径别混（2026-10-05 全量实测踩过两次）：
    #     「共 N 条发现项」     = 全部发现项（含已闭环）
    #     「待派发 M 条」        = 6.0 派发表行数 ← 该和表行数比的是这个
    #     「聚合为 K 条」        = 全量去重漏洞数，与上面两个都不同语义
    #   ★ 表行数要**按段统计**——6.0 派发表和 6.3 已闭环表都是 `| CMDB-` 开头，
    #     全文正则会把两段加起来（实测 6 + 14 = 20），然后和「待派发 6 条」对不上。
    _m60 = re.search(r"^### 6\.0 待派发工单", md, re.M)
    m_tab = 0
    if _m60:
        _nxt = re.search(r"^#{2,3} ", md[_m60.end():], re.M)
        _seg60 = md[_m60.end():_m60.end() + _nxt.start()] if _nxt else md[_m60.end():]
        m_tab = len(re.findall(r"^\| CMDB-[0-9A-F]{1,4}-\d{3} ", _seg60, re.M))
    m_disp = re.search(r"待派发 (\d+) 条", md)
    if m_disp and m_tab and int(m_disp.group(1)) != m_tab:
        issues.append("派发表行数 %d 与声明的「待派发 %s 条」不符"
                      % (m_tab, m_disp.group(1)))
    #   明细被截断时必须有显式声明，否则读者会以为剩下的不用管
    n_detail = len(re.findall(r"^#### CMDB-[0-9A-F]{1,4}-\d{3} ", md, re.M))
    if m_disp and int(m_disp.group(1)) > n_detail and "仅展开前" not in md:
        issues.append("明细只展开 %d 条但派发 %s 条，未声明截断"
                      % (n_detail, m_disp.group(1)))

    return issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--md", help="自检已有 Markdown（不给则跑小样本）")
    ap.add_argument("--save", default="", help="把小样本报告写到该路径")
    args = ap.parse_args()

    if args.md:
        md = io.open(args.md, encoding="utf-8").read()
        print("自检：%s（%d chars）" % (args.md, len(md)))
    else:
        md = build_smoke_md(args.save)
        print("已生成小样本报告：%d chars / %d lines%s"
              % (len(md), md.count("\n") + 1,
                 ("→ " + args.save) if args.save else ""))

    issues = audit(md)
    if not issues:
        print("\nOK  渲染自检通过：表格列数 / 空单元格 / 链接 / 占位符 / "
              "章节编号 / 发现编号 / 状态取值 / 数字自洽")
        return 0
    print("\n发现 %d 处问题：" % len(issues))
    for x in issues:
        print("  - %s" % x)
    return 1


if __name__ == "__main__":
    sys.exit(main())
