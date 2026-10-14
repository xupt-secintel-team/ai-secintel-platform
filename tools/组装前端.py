#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
组装前端 —— 把各模块自带的 web/ 面板资源同步进 frontend/modules/<模块id>/

背景（为什么要这个脚本）：
  · 运行期前端只有一个根：``frontend/``（主体外壳 index.html / styles.css / app.js
    都在这里，模块面板在 frontend/modules/<id>/ 里）。服务只服务这一个目录，
    不会再满仓库找文件 —— 交付时「前端就是 frontend/ 这一个文件夹」。
  · 但**模块的源文件仍然在各自模块里**：``modules/<id>/web/panel.js|panel.css``。
    这是协作约定：成员只改自己模块文件夹里的东西，改完整包替换。
  · 所以需要一步同步：模块源 → frontend/。这个脚本就是那一步。

用法：
    py -3 tools/组装前端.py            # 同步（模块源覆盖 frontend 里的副本）
    py -3 tools/组装前端.py --check    # 只检查是否同步，不写文件（合并前核查用）
    py -3 tools/组装前端.py --dry-run  # 打印将要做什么，不落盘

改前端的两种姿势（都支持）：
    A. 只想改样式/布局（多数情况）：直接改 ``frontend/`` 里的文件，改完刷新浏览器即可。
    B. 模块作者改自己面板：改 ``modules/<id>/web/``，然后跑一次本脚本同步进 frontend/。
       若同一文件两处都改过，本脚本以**模块源为准**（并在输出里标注差异）。
"""
import argparse
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(ROOT, "modules")
FRONTEND_DIR = os.path.join(ROOT, "frontend")

BANNER = {
    ".js": "// {rel}\n// ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/{mid}/web/{name}\n"
           "//   改完跑一次： py -3 tools/组装前端.py\n",
    ".css": "/* {rel}\n   ⚠ 自动生成，请勿直接改本文件 —— 源文件在 modules/{mid}/web/{name}\n"
            "   改完跑一次： py -3 tools/组装前端.py */\n",
}


def modules():
    """按目录顺序返回 [(mid, manifest)]，只取声明了 web 的模块"""
    out = []
    if not os.path.isdir(MODULES_DIR):
        return out
    for mid in sorted(os.listdir(MODULES_DIR)):
        mdir = os.path.join(MODULES_DIR, mid)
        mf = os.path.join(mdir, "module.json")
        if not (os.path.isdir(mdir) and os.path.isfile(mf)):
            continue
        try:
            with open(mf, "r", encoding="utf-8") as f:
                man = json.load(f)
        except Exception as e:
            print(f"  !! {mid}/module.json 读取失败：{type(e).__name__}: {e}", flush=True)
            continue
        out.append((mid, man, mdir))
    return out


def plan():
    """返回 [(mid, src, dst, rel)]"""
    items = []
    for mid, man, mdir in modules():
        for rel in (man.get("web") or []):
            src = os.path.join(mdir, rel.replace("/", os.sep))
            name = os.path.basename(rel)
            dst = os.path.join(FRONTEND_DIR, "modules", mid, name)
            if os.path.isfile(src):
                items.append((mid, src, dst, rel))
            else:
                print(f"  !! 模块 {mid} 声明的前端文件不存在：{rel}", flush=True)
    return items


def same(src, dst, mid, rel):
    """内容比较时**精确**剥掉自动生成头，只比较正文

    坑：不能靠「找到第一行再往后跳 N 个换行」——头部行数一变就错位，
    会误报「未同步」。按文件类型生成**完整**的期望头部，startswith 精确匹配后整段剥掉。

    ★ 2026-10-13 修（误报 bug）：头部与正文都按「行结尾无关」比较。
      BANNER 模板是 LF，而 Windows 编辑器/git autocrlf 常把整个副本文件（含头部）
      存成 CRLF —— startswith(want) 因此永远匹配不上，`want` 首行又确实出现在
      文件头，于是被判成「有头部但形态不符（老版本生成物）→ 待同步」。
      实测 m3_qa/panel.js 就是这么被误报的：内容逐字节相同，只差行结尾。
      行结尾是存储格式不是内容，比较前统一把 CRLF 折成 LF。
    """
    try:
        with open(src, "rb") as f:
            a = f.read()
        with open(dst, "rb") as f:
            b = f.read()
    except OSError:
        return False
    head = BANNER.get(os.path.splitext(src)[1].lower())
    if head:
        want = head.format(rel=rel, mid=mid, name=os.path.basename(rel)).encode("utf-8")
        for cand in (want, want.replace(b"\n", b"\r\n")):
            if b.startswith(cand):
                b = b[len(cand):]
                break
        else:
            if want.split(b"\n")[0] in b[:400]:
                return False          # 有头部但形态不符（老版本生成物）→ 视为待同步
    _norm = lambda x: x.strip().replace(b"\r\n", b"\n")
    return _norm(a) == _norm(b)


def main():
    ap = argparse.ArgumentParser(description="把 modules/<id>/web/ 的面板资源同步进 frontend/")
    ap.add_argument("--check", action="store_true", help="只检查是否同步（不写文件）")
    ap.add_argument("--dry-run", action="store_true", help="只打印计划")
    a = ap.parse_args()

    items = plan()
    if not items:
        print("没有找到任何模块前端资源（检查 modules/<id>/module.json 的 web 字段）")
        return 1

    os.makedirs(os.path.join(FRONTEND_DIR, "modules"), exist_ok=True)
    stale, ok, wrote = [], 0, 0
    for mid, src, dst, rel in items:
        if same(src, dst, mid, rel):
            ok += 1
            continue
        stale.append((mid, rel))
        if a.check:
            continue
        if a.dry_run:
            print(f"  will sync  {rel:26s} → frontend/modules/{mid}/{os.path.basename(src)}")
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(src, "rb") as f:
            body = f.read()
        head = BANNER.get(os.path.splitext(src)[1].lower())
        if head:
            body = head.format(rel=rel, mid=mid, name=os.path.basename(rel)).encode("utf-8") + body
        with open(dst, "wb") as f:
            f.write(body)
        wrote += 1
        print(f"  ✓ {rel:26s} → frontend/modules/{mid}/{os.path.basename(src)}  ({len(body):,} B)")

    print()
    if a.check or a.dry_run:
        print(f"模块前端资源 {len(items)} 个：已同步 {ok} 个 / 待同步 {len(stale)} 个")
        for mid, rel in stale:
            print(f"  · 待同步：{mid} ← {rel}")
    else:
        # 注意别把「刚写出去的文件」叫成待同步：stale 是「发现不同步」的清单，写模式下已全部落地
        print(f"模块前端资源 {len(items)} 个：已同步 {ok} 个 / 本次写入 {wrote} 个"
              + (f"（发现不同步 {len(stale)} 个，已全部写出）" if stale else ""))
    if a.check and stale:
        print("\n结论：frontend/ 与模块源**不一致**，跑一次 `py -3 tools/组装前端.py` 即可")
        return 2
    if a.check:
        print("结论：frontend/ 与模块源一致 ✅")
    print("\n提示：服务只服务 frontend/ 这一个目录；改完样式直接刷新浏览器（静态资源 10 分钟缓存，"
          "改了没生效就 Ctrl+F5）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
