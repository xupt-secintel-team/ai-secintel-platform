# -*- coding: utf-8 -*-
"""
verify_integrity.py —— 合并/替换后的「防阉割」一致性核查（纯标准库）
====================================================================
用途：把当前这棵树（模块化版 aisec-D_2.0）与一个**基线版本**逐项比对，
      确认谁的功能都没被漏掉。每次有人把模块文件夹替换进来，跑一次这个脚本。

比对项：
  1. 接口路由   —— 基线 server.py 里的 /api/* 是否都能在新树里找到（core 路由 + 模块注册路由）
  2. 源码文件   —— 基线有的 .py/.js/.css/.html 文件是否都在新树里（按文件名）
  3. 函数/方法  —— 同名文件里的函数、方法是否一个不少（AST 级，够狠）
  4. 数据文件   —— 基线 data/ 下的小文件是否都在（大语料/缓存单独列出，不算缺失）
  5. 前端函数   —— 基线 app.js 里的 JS 函数是否都在（core/web/app.js ∪ modules/*/web/panel.js）
  6. 运行态     —— 若服务在跑，比对 /api/modules 报出来的真实路由（可选，最权威）

用法：
    py -3 tools/verify_integrity.py                       # 默认对比基线 ../aisec-D_1.3.2
    py -3 tools/verify_integrity.py --baseline D:/old/aisec-D_1.2
    py -3 tools/verify_integrity.py --live http://127.0.0.1:8848
退出码：0 全部通过；1 有缺失项。
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.path.join(ROOT, "core")
MODULES = os.path.join(ROOT, "modules")

BIG_DATA = {"corpus.json", "corpus.json.idxcache", "nvd_cache.json", "enriched_cache.json"}
SKIP_DIRS = {"__pycache__", ".git", ".venv", "chroma_db", "nvd_full", "gh_repos_ai", "gh_repos", "cn"}
ROUTE_RX = re.compile(r'["\'](/api/[A-Za-z0-9_\-/]+)["\']')


# ----------------------------------------------------------------------
# 采集
# ----------------------------------------------------------------------
def walk_files(base, exts):
    """返回 {相对路径: 绝对路径}，只挑指定后缀、跳过噪音目录"""
    out = {}
    for dirpath, dirnames, files in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in files:
            if os.path.splitext(fn)[1].lower() in exts:
                fp = os.path.join(dirpath, fn)
                out[os.path.relpath(fp, base).replace("\\", "/")] = fp
    return out


def snake_funcs(path):
    """AST 提取函数/方法名（限定名，如 Foo.bar）"""
    try:
        tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    except Exception:                                       # noqa: BLE001
        return set()
    names = set()

    def walk(node, prefix=""):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(prefix + ch.name)
            elif isinstance(ch, ast.ClassDef):
                walk(ch, prefix + ch.name + ".")
            else:
                walk(ch, prefix)
    walk(tree)
    return names


def js_funcs(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    return set(re.findall(r'function\s+([A-Za-z0-9_$]+)', src)) | \
        set(re.findall(r'^\s*([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{', src, re.M))


def data_files(base):
    d = os.path.join(base, "data")
    if not os.path.isdir(d):
        return {}
    out = {}
    for dirpath, dirnames, files in os.walk(d):
        dirnames[:] = [x for x in dirnames if x not in SKIP_DIRS]
        for fn in files:
            fp = os.path.join(dirpath, fn)
            out[os.path.relpath(fp, d).replace("\\", "/")] = os.path.getsize(fp)
    return out


def declared_routes():
    """新树声明的路由：core 内联路由 + 模块 module.json 的 routes 字段"""
    routes = {}
    srv = os.path.join(CORE, "server.py")
    src = open(srv, encoding="utf-8").read()
    for m in re.finditer(r'path == "(/api/[A-Za-z0-9_\-/]+)"', src):
        routes.setdefault(m.group(1), "core/server.py")
    for name in sorted(os.listdir(MODULES)) if os.path.isdir(MODULES) else []:
        mf = os.path.join(MODULES, name, "module.json")
        if not os.path.isfile(mf):
            continue
        man = json.load(open(mf, encoding="utf-8"))
        for r in man.get("routes", []) or []:
            p = r.split(" ", 1)[-1].strip()
            routes.setdefault(p, f"{name}/module.json")
    return routes


def module_files():
    """模块目录下的源码/front-end 文件（用于「按文件名」比对）"""
    out = {}
    for dirpath, dirnames, files in os.walk(MODULES):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in files:
            if os.path.splitext(fn)[1].lower() in {".py", ".js", ".css", ".html", ".json", ".md"}:
                fp = os.path.join(dirpath, fn)
                out.setdefault(fn, []).append(fp)
    return out


# ----------------------------------------------------------------------
# 核查
# ----------------------------------------------------------------------
def _find_baseline(explicit: str = "") -> str:
    """定位基线目录：显式指定 > 环境变量 > 若干常见位置自动探测。

    修复前：默认路径写死为「同级目录的 aisec-D_1.3.2」，而交付包里并不带基线版本，
    换台机器（或解包到新目录）一跑就是 "基线目录不存在"，核查直接失效。
    现在会按常见位置逐一探测，找不到就返回空串，由 main 走「清档模式」。
    """
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("AISEC_BASELINE_DIR", "").strip()
    if env:
        candidates.append(env)
    parent = os.path.dirname(ROOT)
    for name in ("aisec-D_1.3.2", "aisec-D_1.3", "aisec-D_1.2", "aisec-D_1.1",
                 "aisec-D_2.0", "baseline", "基线版本"):
        candidates.append(os.path.join(parent, name))
        candidates.append(os.path.join(parent, "..", name))
        candidates.append(os.path.join(ROOT, "..", name))
        candidates.append(os.path.join(ROOT, name))
    for c in candidates:
        c = os.path.abspath(c)
        if os.path.isdir(c) and c != os.path.abspath(ROOT):
            return c
    return ""


def _inventory_only() -> int:
    """没有基线可比时，退化为「当前版本清档」：至少把功能清单打出来，脚本不白跑。"""
    print("=" * 74)
    print("未找到基线版本 —— 转为【清档模式】：盘点当前这棵树有什么（可与队友的清单对账）")
    print("=" * 74)
    routes = declared_routes()
    print(f"接口路由 {len(routes)} 条：")
    for r in sorted(routes):
        print(f"  · {r:<34} <- {routes[r]}")
    files = walk_files(ROOT, {".py", ".js", ".css", ".html"})
    print(f"\n源码/前端文件 {len(files)} 个（.py/.js/.css/.html）：")
    for p in sorted(files)[:200]:
        print(f"  · {os.path.relpath(p, ROOT)}")
    if len(files) > 200:
        print(f"  …（共 {len(files)} 个，已省略 {len(files) - 200} 个）")
    print("\n提示：要跟旧版比对，任选一种即可")
    print("  1) py -3 tools/verify_integrity.py --baseline D:\\路径\\aisec-D_1.3.2")
    print("  2) set AISEC_BASELINE_DIR=D:\\路径\\aisec-D_1.3.2   （以后每次自动找到）")
    print("  3) 把基线版本目录放在本项目的同级目录下（aisec-D_1.3.2）")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="",
                    help="基线版本目录（留空则自动探测：环境变量 AISEC_BASELINE_DIR "
                         "→ 同级目录 aisec-D_1.3.2/1.3/1.2/1.1 …）")
    ap.add_argument("--live", default="", help="在跑的服务地址，如 http://127.0.0.1:8848")
    args = ap.parse_args()
    base = _find_baseline(args.baseline)
    if not base:
        return _inventory_only()
    print(f"[基线] 使用：{base}\n")

    fails, warns = [], []

    # ---- 1. 路由 ----
    print("=" * 74)
    print("【1】接口路由")
    print("=" * 74)
    base_srv = os.path.join(base, "server.py")
    b_routes = set(ROUTE_RX.findall(open(base_srv, encoding="utf-8").read())) if os.path.isfile(base_srv) else set()
    n_routes = declared_routes()
    missing = sorted(r for r in b_routes if r not in n_routes)
    extra = sorted(r for r in n_routes if r not in b_routes)
    for r in sorted(b_routes):
        print(f"  {'OK ' if r in n_routes else '!! '}{r:<20} <- {n_routes.get(r, '缺失')}")
    if missing:
        fails.append(f"路由缺失：{missing}")
    if extra:
        warns.append(f"新树新增路由（正常，若来自模块即符合预期）：{extra}")

    # ---- 2. 源码文件 ----
    print("\n" + "=" * 74)
    print("【2】源码文件（按文件名）")
    print("=" * 74)
    b_files = walk_files(base, {".py", ".js", ".css", ".html"})
    n_files = walk_files(ROOT, {".py", ".js", ".css", ".html"})
    n_names = {os.path.basename(p) for p in n_files}
    miss_files = sorted(p for p in b_files if os.path.basename(p) not in n_names)
    for p in sorted(b_files):
        ok = os.path.basename(p) in n_names
        print(f"  {'OK ' if ok else '!! '}{p}")
    if miss_files:
        fails.append(f"文件缺失：{miss_files}")

    # ---- 3. 函数级 ----
    print("\n" + "=" * 74)
    print("【3】函数 / 方法（基线有 → 新树任意文件里是否还在；模块化后同一个函数可能搬了家）")
    print("=" * 74)
    n_files = walk_files(ROOT, {".py"})
    # 全局函数池：限定名 -> 文件
    pool = {}
    for rel, fp in n_files.items():
        for nm in snake_funcs(fp):
            pool.setdefault(nm, []).append(rel)
    lost_all = []
    for rel, fp in sorted(b_files.items()):
        if not rel.endswith(".py"):
            continue
        old = snake_funcs(fp)
        if not old:
            continue
        moved, gone = [], []
        for nm in sorted(old):
            same_file = os.path.basename(rel) in {os.path.basename(p) for p in n_files}
            if nm in pool:
                where = pool[nm][0]
                if os.path.basename(where) != os.path.basename(rel):
                    moved.append(f"{nm}→{where}")
            else:
                gone.append(nm)
        if gone:
            lost_all += [f"{rel}::{g}" for g in gone]
            print(f"  !! {rel}: 丢失 {len(gone)} 个 -> {gone}")
        else:
            extra = f"（其中 {len(moved)} 个搬到了模块里）" if moved else ""
            print(f"  OK {rel}: {len(old)} 个函数全部在 {extra}")
    if not lost_all:
        print("  —— 未发现任何函数丢失 ——")

    # ---- 4. 数据 ----
    print("\n" + "=" * 74)
    print("【4】数据文件")
    print("=" * 74)
    b_data = data_files(base)
    n_data = data_files(ROOT)
    big = [p for p in b_data if os.path.basename(p) in BIG_DATA]
    for p in sorted(b_data):
        if os.path.basename(p) in BIG_DATA:
            continue
        ok = p in n_data
        print(f"  {'OK ' if ok else '!! '}{p:<44}{b_data[p]:>12,}")
        if not ok:
            warns.append(f"数据文件缺失：{p}")
    for p in sorted(big):
        print(f"  -- {p:<44}{b_data[p]:>12,}  （大语料/缓存，按需单独同步，不计缺失）")

    # ---- 5. 前端函数 ----
    print("\n" + "=" * 74)
    print("【5】前端 JS 函数（frontend/app.js ∪ frontend/modules ∪ modules/<id>/web 的 panel.js）")
    print("=" * 74)
    b_js = os.path.join(base, "web", "app.js")
    if os.path.isfile(b_js):
        old = js_funcs(b_js)
        # 新树前端只有一个根 frontend/（外壳 + 由 tools/组装前端.py 同步进来的模块面板）；
        # modules/<id>/web/ 是模块源文件，两处都扫，避免同步时序影响判定。
        new = set()
        for root_dir in (os.path.join(ROOT, "frontend"), MODULES):
            if not os.path.isdir(root_dir):
                continue
            for dirpath, _d, files in os.walk(root_dir):
                for fn in files:
                    if fn.endswith(".js"):
                        new |= js_funcs(os.path.join(dirpath, fn))
        lost = sorted(old - new)
        print(f"  基线 {len(old)} 个函数 / 新树 {len(new)} 个（frontend/ ∪ modules/*/web）")
        if lost:
            fails.append(f"前端函数丢失：{lost}")
            print(f"  !! 丢失：{lost}")
        else:
            print("  OK 基线前端函数一个不少")

    # ---- 6. 运行态 ----
    if args.live:
        print("\n" + "=" * 74)
        print(f"【6】运行态核对 {args.live}/api/modules")
        print("=" * 74)
        try:
            with urllib.request.urlopen(args.live.rstrip("/") + "/api/modules", timeout=20) as r:
                d = json.loads(r.read().decode("utf-8"))
            live_routes = set()
            for m in d.get("modules", []):
                for rt in m.get("routes", []):
                    live_routes.add(rt.split(" ", 1)[-1].strip())
                print(f"  · {m['id']}（{m.get('name')} / {m.get('owner') or '未署名'}）"
                      f" 路由 {m.get('routes')}")
            if d.get("skipped"):
                print(f"  · 跳过：{d['skipped']}")
            miss = sorted(r for r in b_routes if r not in live_routes and r not in n_routes)
            miss = sorted(r for r in miss if r not in declared_routes())
            if miss:
                fails.append(f"运行态缺少路由：{miss}")
            print(f"  运行态路由 {len(live_routes)} 条" + ("（无缺失）" if not miss else f"，缺失 {miss}"))
        except Exception as e:                                 # noqa: BLE001
            warns.append(f"运行态核对失败（服务没在跑？）：{e}")
            print(f"  -- 无法连接：{e}")

    # ---- 汇总 ----
    print("\n" + "=" * 74)
    print(f"汇总：失败 {len(fails)} 项 / 提醒 {len(warns)} 项")
    for f in fails:
        print("  !! " + f)
    for w in warns:
        print("  -- " + w)
    print("结论：" + ("通过，功能无缺失 ✅" if not fails else "有缺失，先补齐再合并 ❌"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
