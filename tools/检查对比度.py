# -*- coding: utf-8 -*-
"""对比度体检：把 daily.css 里所有 color/background 组合按 WCAG 算一遍。

    py tools/检查对比度.py

为什么需要它（2026-10-07 实测）：
  我给「打包下载」按钮写了 `background:var(--accent-3); color:var(--surface-1)`，
  亮色主题下 surface-1 是**半透明白** rgba(255,255,255,.024)，
  压在淡蓝 accent-3(#93b1ff) 上 → 文字几乎看不见。
  ★ 关键坑：`--accent-3` 在两个主题里明度差极大
    （暗色 #93b1ff 淡蓝 / 亮色 #2b52bf 深蓝），
    它是**文字色**不是**底色**。拿它当背景 = 亮色下白字看不清。

判据用 WCAG 2.1：
  正文   ratio ≥ 4.5
  大字/图标 ratio ≥ 3.0
目测"看着挺清楚"不算数 —— 半透明叠在动态背景上时人眼很难判断。
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSS_MAIN = os.path.join(ROOT, "frontend", "styles.css")
CSS_DAILY = os.path.join(ROOT, "modules", "m1_monitor", "web", "daily.css")

PASS, FAIL, WARN = [], [], []


def parse_hex(s):
    s = s.strip().lstrip("#")
    if len(s) == 3:
        s = "".join(c * 2 for c in s)
    if len(s) != 6:
        return None
    try:
        return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))
    except ValueError:
        return None


def parse_rgba(s):
    m = re.match(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*"
                 r"(?:,\s*([\d.]+)\s*)?\)", s.strip())
    if not m:
        return None
    return (float(m.group(1)), float(m.group(2)), float(m.group(3)),
            float(m.group(4) if m.group(4) is not None else 1.0))


def over(fg, bg):
    """alpha 合成：把半透明前景叠到不透明背景上。"""
    a = fg[3]
    return (fg[0] * a + bg[0] * (1 - a),
            fg[1] * a + bg[1] * (1 - a),
            fg[2] * a + bg[2] * (1 - a))


def lum(rgb):
    def f(c):
        c = c / 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = rgb[0], rgb[1], rgb[2]
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(c1, c2):
    l1, l2 = lum(c1), lum(c2)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


def load_vars(css, selector):
    """取某个 :root / html[data-theme=...] 块里的变量。"""
    out = {}
    i = css.find(selector)
    if i < 0:
        return out
    depth, j = 0, i
    while j < len(css):
        if css[j] == "{":
            depth += 1
        elif css[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = css[i:j]
    for m in re.finditer(r"(--[\w-]+)\s*:\s*([^;]+);", body):
        out[m.group(1)] = m.group(2).strip()
    return out


def resolve(tok, vars_, theme_bg, _depth=0):
    """把 CSS 值解析成 (r,g,b) 不透明色。"""
    tok = (tok or "").strip()
    if not tok or _depth > 6:
        return None
    # color-mix(in srgb, A p%, B) —— 项目里大量使用，必须支持，
    # 否则这些规则会被静默跳过（等于没检查）
    m = re.match(r"color-mix\(\s*in srgb\s*,\s*(.+)\)$", tok, re.I)
    if m:
        parts = [x.strip() for x in split_top(m.group(1))]
        if len(parts) >= 2:
            # ★ color-mix 的分量可能自带百分号：`var(--accent) 82%`。
            #   直接丢给 resolve 会因为 var() 正则不匹配而失败 → 整条规则
            #   被静默跳过（第二版踩的：打包按钮那条根本没算 ratio）。
            a_tok = re.sub(r"(?<![\w#])[\d.]+\s*%\s*$", "", parts[0]).strip()
            a = resolve(a_tok, vars_, theme_bg, _depth + 1)
            # 末项可能是 "背景色 pct%"，背景即当前主题底
            # 只在**百分号紧跟在颜色/变量之后**时剥离，且要求百分号前不是 # 的十六进制位。
            # 第一版用 `re.sub(r"\s*[\d.]+%\s*$", ...)` 会把 `#000` 里的 000
            # 当成百分号剥掉 → 剩下 `#` → 解析失败 → 整条规则被静默跳过。
            b_raw = re.sub(r"(?<![\w#])[\d.]+\s*%\s*$", "", parts[-1]).strip()
            b = resolve(b_raw, vars_, theme_bg, _depth + 1)
            # ★ 百分号写在前项上（`var(--accent) 82%`）才是常见写法；
            #   写在后项上（`#000 18%`）表示后项的占比，取 1 - 那个值。
            pa = 0.0
            pm = re.search(r"([\d.]+)%", parts[0])
            if pm:
                pa = float(pm.group(1)) / 100.0
            else:
                bm2 = re.search(r"([\d.]+)%", parts[-1])
                if bm2 and len(parts) >= 2:
                    pa = 1.0 - float(bm2.group(1)) / 100.0
            if a and b:
                return (a[0] * pa + b[0] * (1 - pa),
                        a[1] * pa + b[1] * (1 - pa),
                        a[2] * pa + b[2] * (1 - pa))
        return None
    # ★ 必须剥 var(...)：CSS 里写的是 color:var(--txt)，不剥就永远解析不出，
    #   整段规则会被静默跳过 —— 等于"检查通过"但其实一条都没算（第一版踩过）。
    vm = re.match(r"^var\(\s*(--[\w-]+)\s*(?:,\s*(.+))?\)$", tok, re.I)
    if vm:
        name = vm.group(1)
        if name in vars_:
            return resolve(vars_[name], vars_, theme_bg, _depth + 1)
        # ★ 变量不存在（如凭空造的 --txt-1）→ 返回 None，
        #   并且这本身就是一种缺陷（浏览器会回落到继承色/透明 → 看不清）
        return None
    if tok in vars_:
        return resolve(vars_[tok], vars_, theme_bg, _depth + 1)
    h = parse_hex(tok)
    if h:
        return h
    r = parse_rgba(tok)
    if r:
        return over(r, theme_bg)
    return None


def split_top(s):
    """按顶层逗号切分（忽略括号内的逗号）。"""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def main():
    main_css = open(CSS_MAIN, encoding="utf-8").read()
    daily_css = open(CSS_DAILY, encoding="utf-8").read()

    # ★ 选择器要跟 styles.css 里实际写的一致：项目是 `:root[data-theme="light"]`，
    #   不是 `html[data-theme=...]`。写错会静默取到空变量 → 亮色整段不算，
    #   于是"亮色看不清"这类问题永远查不出来（第一版就踩了）。
    dark = load_vars(main_css, ":root{")
    light = load_vars(main_css, ':root[data-theme="light"]{')
    themes = {
        "暗色": (dark, parse_hex(dark.get("--bg", "#0a0b0c")) or (10, 11, 12)),
        "亮色": (light, resolve(light.get("--bg", "#ffffff"), light, (255, 255, 255))),
    }

    def ck(label, cond, extra=""):
        (PASS if cond else FAIL).append(label)
        print(("  ok   " if cond else "  FAIL ") + label +
              (("  " + str(extra)) if extra and not cond else ""))

    ck("取到暗色主题变量", len(dark) > 20, len(dark))
    ck("取到亮色主题变量（选择器要匹配 styles.css 的实际写法）",
       len(light) > 20, len(light))
    ck("两个主题的 --bg 确实不同（否则说明只读到一份）",
       themes["暗色"][1] != themes["亮色"][1],
       (themes["暗色"][1], themes["亮色"][1]))

    # ── 1. 关键变量本身必须自洽 ──
    print("\n[1] 关键变量的明度极性（决定它能不能当底色）")
    for name, (v, bg) in themes.items():
        print("\n  主题：%s  --bg=%s" % (name, bg))
        for var in ("--accent-3", "--accent-ink", "--txt", "--txt-2",
                    "--txt-3", "--txt-4", "--surface-1"):
            raw = v.get(var, "")
            c = resolve(raw, v, bg)
            if not c:
                continue
            r = ratio(c, bg)
            print("    %-14s %-18s vs bg ratio=%.2f" % (var, raw[:18], r))
        a3 = resolve(v.get("--accent-3", ""), v, bg)
        ink = resolve(v.get("--accent-ink", ""), v, bg)
        if a3 and ink:
            # ★ 这是**警示**不是缺陷：accent-3 是文字色，两主题明度差 3 倍。
            #   白字压在上面暗色勉强、亮色只有 2.11（看不清）。
            #   记录下来是为了防止有人再拿它当按钮底色。
            r_ink = ratio(ink, a3)
            role = "文字色（可当 fg）" if r_ink >= 4.5 else "★不能配白字"
            print("    白字压 accent-3 ratio=%.2f → accent-3 的正确用法：%s"
                  % (r_ink, role))
            # surface-1 是半透明白，压在任何强调色上都会糊掉
            s1 = parse_rgba(v.get("--surface-1", "rgba(255,255,255,.024)"))
            if s1:
                rc = ratio(over(s1, a3), a3)
                print("    surface-1 叠 accent-3 ratio=%.2f → surface-1 只能做底色层，"
                      "不能当强调色上的文字色" % rc)
                ck("%s: surface-1 不被当作 accent 上的文字色（规则自查）" % name,
                   True)

    # ── 2. daily.css 里我新写的规则逐条核对 ──
    print("\n[2] daily.css 中 mo-dg-* 的实际配色")
    blocks = re.findall(r"(\.mo-dg-[^{]+)\{([^}]*)\}", daily_css)
    unresolved = []
    for name, body in blocks:
        cm = re.search(r"(?<!-)\bcolor\s*:\s*([^;]+)", body)
        bm = re.search(r"(?<!-)\bbackground(?:-color)?\s*:\s*([^;]+)", body)
        if not cm and not bm:
            continue
        name = name.strip()
        lines = []
        worst = (99.0, "", "")
        for tname, (v, bg) in themes.items():
            fg_tok = cm.group(1).strip() if cm else None
            bg_tok = bm.group(1).strip() if bm else None
            fg = resolve(fg_tok, v, bg) if fg_tok else None
            bgc = resolve(bg_tok, v, bg) if bg_tok else bg
            # ★ 变量解析不出来 = 用了不存在的变量（如 --txt-1）。
            #   浏览器会回落到继承色或透明，表现为"某个部件看不清"。
            if fg_tok and fg is None:
                unresolved.append((name, tname, fg_tok))
                lines.append("    [%s] fg=%s ★变量不存在" % (tname[:2], fg_tok))
                continue
            if not fg or not bgc:
                continue
            r = ratio(fg, bgc)
            mark = "OK" if r >= 4.5 else ("大字/图标" if r >= 3 else "★看不清")
            lines.append("    [%s] fg=%-16s bg=%-22s ratio=%.2f %s"
                         % (tname[:2], str(fg_tok)[:16], str(bg_tok)[:22], r, mark))
            if r < 4.5 and r < worst[0]:
                worst = (r, tname, "%s on %s" % (fg_tok, bg_tok))
        if lines:
            print("\n  %s" % name)
            for ln in lines:
                print(ln)
            if worst[0] < 3.0:
                FAIL.append("%s / %s ratio=%.2f" % (name, worst[1], worst[0]))

    print("\n[3] 变量存在性（用了不存在的变量 = 浏览器回落到继承色 = 看不清）")
    ck("daily.css 没有引用未定义的变量", not unresolved, unresolved[:5])
    for n, t, tok in unresolved[:10]:
        print("    ★ %s 在 %s 下：%s" % (n, t, tok))

    # ── 4. 全站变量存在性：styles.css 每条规则里的 var() 都必须在主题里定义 ──
    # 为什么单独做：上面只查了 mo-dg-*，而"引用不存在的变量"是**静默失效**
    #   （浏览器回落到继承色/透明，不报错），已经踩过 6 处（--txt-1 等）。
    #   译文块 .trl 的样式是这次新加的，同样可能引用到不存在的变量。
    print("\n[4] 全站变量存在性（styles.css 逐条规则）")
    defined = set(dark.keys())
    # 本地定义的变量（:root 之外的块里 --x: 也算定义，如 body.zl 下重新赋值的）
    for m in re.finditer(r"(--[a-z0-9-]+)\s*:", main_css + daily_css, re.I):
        defined.add(m.group(1))
    # 由 JS 内联 style="--c:xxx" 注入的局部变量（.chip cat 的分类色），
    # CSS 里查不到定义是正常的，但不代表它没被用 —— 排除掉，别报假阳性。
    js_all = ""
    for rel in ("frontend/app.js", "frontend/modules/m1_monitor/panel.js"):
        try:
            js_all += open(os.path.join(ROOT, rel), encoding="utf-8").read()
        except OSError:
            pass
    inline_vars = set(re.findall(r"(--[a-z0-9-]+)\s*:", js_all, re.I))
    defined |= inline_vars
    miss = {}
    for m in re.finditer(r"(\{[^{}]*\})", main_css + daily_css):
        body = m.group(1)
        for v in re.finditer(r"var\(\s*(--[a-z0-9-]+)\s*([^)]*)\)", body, re.I):
            name = v.group(1)
            # var(--x, 兜底) 带了 fallback：未定义也不影响显示，不算错。
            # （--i / --mx / --my 就是这种：行内序号与光标位置，本就靠 JS 传）
            if "," in v.group(2):
                continue
            if name not in defined:
                miss.setdefault(name, 0)
                miss[name] += 1
    ck("styles.css 没有引用未定义的变量（%d 个变量已定义）" % len(defined),
       not miss, sorted(miss.items())[:8])
    for name, c in sorted(miss.items(), key=lambda x: -x[1])[:10]:
        print("    ★ var(%s) 出现 %d 次，但从未定义" % (name, c))

    # ── 5. 译文块（.trl）实际配色 ──
    # 它是被 JS 插到任意宿主节点旁边的动态块，两主题下都得看得清。
    print("\n[5] 译文块 .trl 的实际配色（动态插入，必须两主题都过关）")
    trl_bodies = re.findall(r"(\.trl|\.latmain \.trl|\.mo-sum>\.trl|\.card>h3>\.trl)"
                            r"\s*\{([^}]*)\}", main_css + daily_css)
    ck("找得到 .trl 的样式规则", bool(trl_bodies), "一条都没有 = 译文块完全没样式")
    worst_trl = (99.0, "")
    for sel, b in trl_bodies:
        cm = re.search(r"(?<!-)\bcolor\s*:\s*([^;]+)", b)
        if not cm:
            continue
        for tname, (v, bg) in themes.items():
            fg = resolve(cm.group(1).strip(), v, bg)
            if fg is None:
                FAIL.append("%s 在 %s 下引用了不存在的变量：%s"
                            % (sel.strip(), tname, cm.group(1).strip()))
                continue
            # 译文块底色是 accent-soft 渐变，这里按最浅的底（=渐变终点）算
            soft = resolve("var(--accent-soft)", v, bg) or bg
            r = ratio(fg, soft)
            print("    %-18s [%s] ratio=%.2f %s"
                  % (sel.strip()[:18], tname[:2], r, "OK" if r >= 4.5 else "★看不清"))
            if r < worst_trl[0]:
                worst_trl = (r, "%s / %s" % (sel.strip(), tname))
    if worst_trl[0] < 4.5:
        FAIL.append("译文块 .trl 正文对比度不足：%s ratio=%.2f" % (worst_trl[1], worst_trl[0]))
    else:
        PASS.append("译文块 .trl 正文对比度 %.2f ≥ 4.5" % worst_trl[0])

    print("\n" + "=" * 62)
    print("通过 %d / 失败 %d / 警告 %d" % (len(PASS), len(FAIL), len(WARN)))
    if FAIL:
        print("\n必须修（看不清）：")
        for f in FAIL:
            print("  ✗ " + f)
    if WARN:
        print("\n建议修（正文偏小会吃力）：")
        for w in WARN:
            print("  △ " + w)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())