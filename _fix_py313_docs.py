# -*- coding: utf-8 -*-
"""一次性清理：把**文档 / docstring / 配置说明**里的示例命令 `py -3` 改成 `py -3`。

为什么：`py -3` 只在装了 CPython 3.13 的机器上成立。别人机器装的是
3.11/3.12/3.14 时该命令直接失败 —— 用户照着文档敲就报错，属于
"不同电脑打开不一样"的一部分（2026-10-09）。

保留策略：含"修复前/修复记录/原来/此前/原脚本/写死"的行是**历史记录**，
里面出现旧写法恰恰是要保留的证据，不动。

只动文本，不动任何逻辑；改完由调用方另行校验。
"""
from __future__ import annotations

import io
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
NEEDLE = "py -3"
REPL = "py -3"

EXPLICIT = [
    "README.md", "requirements.txt", "修复说明.md", "七章制报告改造说明.md",
    "交付总览.md", "加强说明.md",
    "frontend/DESIGN.md", "frontend/README.md",
    "modules/m3_qa/module.json",
    "modules/m0_ops/docs/编排说明.md",
]

SKIP = {
    # 这个测试文件里 py -3 是**被测对象/回归样本**，不能改
    "tools/_test_portability.py",
    # 编码转换器里 py -3 出现在"实测证伪"的说明中
    "tools/_fix_bat_encoding.py",
}
HIST = ("修复前", "修复记录", "原来", "此前", "原脚本", "写死")


def collect():
    out = list(EXPLICIT)
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel = os.path.relpath(dirpath, ROOT).replace("\\", "/")
        if rel != "." and any(rel.split("/")[0] == p or rel.startswith(p)
                              for p in (".venv", "data", "__pycache__", ".git",
                                        "测试报告", ".bat_bak", "output")):
            dirnames[:] = []
            continue
        if any(seg in ("__pycache__", ".venv") for seg in rel.split("/")):
            continue
        for fn in filenames:
            if fn.lower().endswith((".py", ".js", ".css")):
                out.append((rel + "/" + fn).lstrip("./"))
    # 去重保序
    seen, uniq = set(), []
    for x in out:
        k = x.replace("\\", "/")
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq


def main() -> int:
    total_files = 0
    total_lines = 0
    for rel in collect():
        if rel in SKIP:
            continue
        path = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.isfile(path):
            continue
        with io.open(path, "rb") as fh:
            raw = fh.read()
        if NEEDLE.encode() not in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("gbk")

        changed = 0
        kept = 0
        out = []
        for line in text.splitlines(True):
            if NEEDLE in line:
                if any(h in line for h in HIST):
                    kept += 1
                else:
                    line = line.replace(NEEDLE, REPL)
                    changed += 1
            out.append(line)
        if changed:
            with io.open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write("".join(out))
            total_files += 1
            total_lines += changed
            print("  %-52s 改 %-3d 行  保留历史 %d 行" % (rel, changed, kept))
        else:
            print("  %-52s 无需改（均属历史记录 %d 行）" % (rel, kept))

    print("\n小计：%d 个文件、%d 处 py -3 -> py -3" % (total_files, total_lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
