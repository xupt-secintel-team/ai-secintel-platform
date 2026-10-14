#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""_fix_bat_encoding.py —— 把 .bat 统一成 GBK（无 BOM）+ CRLF

## 为什么是 GBK 而不是 UTF-8 BOM（2026-10-07 实测证伪后修正）

最初以为"加 UTF-8 BOM 就能让 cmd 按 UTF-8 解析"，**实测证明是错的**：

对照实验（同一段中文注释脚本，两种编码各跑一遍）：

    GBK 无 BOM  → 输出 GBK_OK，干净无报错          ✅
    UTF-8 BOM   → '锘緻echo' 不是内部或外部命令      ❌

关键证据：`EF BB BF`（BOM）被 GBK 显示成 `锘緻`，并且与 `@echo off`
连在一起被 cmd 当成**同一条命令**执行 —— `锘緻echo off`。
也就是说，**cmd 解析批处理文件用的是系统 ANSI（简体中文机器 = GBK/CP936），
根本不看 BOM**。BOM 不但没用，反而成了命令前缀的一部分。

所以正确修法是：

1. **把 .bat 存成 GBK（CP936）编码，不要 BOM**。中文注释用 GBK 字节写，
   cmd 按 GBK 解析时正好一一对应，不再产生半个汉字，也就不会出现伪命令。
2. 统一 CRLF（cmd 传统只认 CRLF；LF 在某些环境下会出问题）。
3. `chcp 65001` 那类切显示代码页的写法**不要**再用 —— 它改的是**显示**，
   改不了 cmd 解析文件用的编码，反而制造"看着是乱码/看着正常"的假象。

## 转换规则（只动编码，绝不改逻辑）

- 读进原始字节 → 按 UTF-8 解码（本项目所有 .bat 源文件都以 UTF-8 维护，
  这是唯一的源格式）→ 重新用 GBK 编码写出。
- 若某个中文字符 GBK 装不下（生僻字），返回报错并**拒绝改写**，绝不静默替换。
- 去掉任何旧 BOM，统一 CRLF。

★ 只改编码不改内容 —— 绝不在这里"顺手"重写逻辑，编码修复与逻辑变更必须分开，
  否则出问题时分不清是编码没修好还是逻辑写错了。
"""
from __future__ import annotations

import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOM = b"\xef\xbb\xbf"


def fix_one(path: str) -> tuple[bool, str]:
    """返回 (是否改动, 说明)。源文件按 UTF-8 读，目标按 GBK 无 BOM 写。"""
    with open(path, "rb") as f:
        raw = f.read()
    orig = raw

    # 1) 剥掉旧 BOM（无论是否已有）
    while raw.startswith(BOM):
        raw = raw[len(BOM):]

    # 2) 先按 UTF-8 解（本项目的 bat **源**以 UTF-8 维护）
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # 已经不是 UTF-8 了 —— 大概率是"已经是 GBK，只是换行/BOM 不对"。
        # ★ 2026-10-09：以前这里直接拒绝改写，于是"GBK 但用了 LF 换行"的文件
        #   永远修不了（被判 unhealthy、又叫不动修复），只能人工救。
        #   现在按 GBK 解出来重排换行，仍按 GBK 写回 —— 等价于"只修换行/BOM"。
        try:
            text = raw.decode("gbk")
        except UnicodeDecodeError as e:
            return False, "★既不是 UTF-8 也不是 GBK，拒绝改写（%s）" % e

    # 3) 统一换行为 CRLF
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    # 4) 重新编码为 GBK（无 BOM）。装不下的生僻字直接报错。
    try:
        out = text.encode("gbk")
    except UnicodeEncodeError as e:
        return False, "★含 GBK 装不下的字符，拒绝改写（%s）" % e

    if out == orig:
        return False, "已正确"
    with open(path, "wb") as f:
        f.write(out)
    return True, "已转 GBK 无 BOM"


def _healthy(raw: bytes) -> tuple[bool, bool, int, str]:
    """返回 (是否 GBK 无 BOM 且 CRLF, 是否有 BOM, 中文行数, 实际编码)

    ★ 2026-10-09 修正了一个**会导致漏检的判据错误**。

    原来判断"是不是 GBK"用的判据是"能不能被 GBK 解码"。但 GBK 的码位覆盖极广，
    **UTF-8 存的中文几乎都能被 GBK 成功解码**（只是解出来是乱码）—— 于是
    用 UTF-8 写的 bat 会被判成"健康的 GBK"，直接跳过转换；cmd 再按 GBK 一读，
    中文注释就变成伪命令（`'xxx' 不是内部或外部命令`）。

    正确判据要反过来：**能被 UTF-8 严格解码、且含非 ASCII 字节，那就是 UTF-8**，
    必须转。GBK 里的中文几乎不可能是合法 UTF-8 序列，所以不会误伤。
    """
    has_bom = raw.startswith(BOM)
    crlf = b"\r\n" in raw and raw.count(b"\n") == raw.count(b"\r\n")
    body = raw[len(BOM):] if has_bom else raw

    has_nonascii = any(b > 0x7F for b in body)
    try:
        body.decode("utf-8")
        utf8_ok = True
    except UnicodeDecodeError:
        utf8_ok = False
    try:
        body.decode("gbk")
        gbk_ok = True
    except UnicodeDecodeError:
        gbk_ok = False

    if not has_nonascii:
        enc = "ASCII"
    elif utf8_ok:
        enc = "UTF8"
    elif gbk_ok:
        enc = "GBK"
    else:
        enc = "?"

    n_cn = 0
    for line in body.split(b"\n"):
        s = line.strip()
        if s and any(c > 0x7F for c in s):
            n_cn += 1

    # 健康的定义：无 BOM + CRLF + 编码是 GBK（纯 ASCII 两者皆可，算健康）
    healthy = (not has_bom) and crlf and enc in ("GBK", "ASCII")
    return healthy, has_bom, n_cn, enc


def main() -> int:
    check_only = "--check" in sys.argv
    # 根目录的入口 bat + tools 下的内部 bat（如 _选解释器.bat）都要覆盖。
    # ★ 2026-10-09：原先只 glob 根目录，新加在 tools\ 下的 bat 会因为
    #   "不在扫描范围"而带着 UTF-8 编码混进交付包 —— 表现是双击后中文注释
    #   被 cmd 当成命令执行（`'xxx' 不是内部或外部命令`）。
    files = sorted(glob.glob(os.path.join(ROOT, "*.bat"))
                   + glob.glob(os.path.join(ROOT, "tools", "*.bat")))
    if not files:
        print("没有找到 .bat 文件")
        return 0

    print("=" * 68)
    print("批处理编码体检（应 GBK 无 BOM + CRLF，否则中文注释被当命令执行）")
    print("=" * 68)
    bad = []
    for p in files:
        name = os.path.basename(p)
        raw = open(p, "rb").read()
        healthy, has_bom, n_cn, enc = _healthy(raw)
        if not healthy:
            bad.append(name)
        print("  %-26s 编码=%-5s BOM=%-4s CRLF=%-4s 中文行=%-3d %s"
              % (name, enc, "有" if has_bom else "无",
                 "是" if b"\r\n" in raw else "否",
                 n_cn, "OK" if healthy else "★需修"))

    print("\n" + "=" * 68)
    if not bad:
        print("结论：全部 %d 个批处理编码正常 ✅" % len(files))
        return 0
    if check_only:
        print("结论：%d 个批处理编码有问题（%s）"
              % (len(bad), ", ".join(bad)))
        print("修复：py tools\\_fix_bat_encoding.py")
        print()
        print("★ 这件事会被反复触发：任何编辑工具按 UTF-8 写回 .bat，")
        print("  编码就从 GBK 变回 UTF-8 → 中文注释重新变成伪命令 → 双击刷屏。")
        print("  所以本检查已挂在 运行CI.bat，别手工绕过。")
        return 1

    print("开始修复 %d 个文件 ..." % len(bad))
    for p in files:
        if os.path.basename(p) not in bad:
            continue
        changed, why = fix_one(p)
        print("  %-26s %s" % (os.path.basename(p), why))

    # 复验
    print("-" * 68)
    still = []
    for p in files:
        raw = open(p, "rb").read()
        healthy, _, _, _ = _healthy(raw)
        if not healthy:
            still.append(os.path.basename(p))
    if still:
        print("结论：仍有 %d 个没修好：%s" % (len(still), ", ".join(still)))
        return 1
    print("结论：%d 个批处理全部已转 GBK 无 BOM + CRLF ✅" % len(files))
    print()
    print("提示：双击 .bat 正常即可；不要再给 .bat 加 UTF-8 BOM，")
    print("      也不要在 .bat 里用 chcp 65001（改了显示、改不了解析编码）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
