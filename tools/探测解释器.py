#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""探测解释器.py —— 一次性报出"这个解释器是谁、缺什么"（给 启动服务.bat 用）

## 为什么单独做成脚本（2026-10-07）

`启动服务.bat` 原来为了同一件事**连续启动 5 次解释器**：

    python -c "import sys;print(...)"     探版本
    python -c "import torch"              探 torch        ← 6.6 秒
    python -c "import transformers, ..."  探翻译三件套
    python -c "import openpyxl"           探 openpyxl

实测 `import torch` 单独就要 **6.6 秒**（Windows + 本机 CPU 推理栈的加载开销），
四行加起来把启动拖到 10 秒以上，而用户只是双击了个 bat。

本脚本把四件事**合并成一次进程启动**，并且：

★ **用 importlib.util.find_spec 查元数据，不真的 import**。
  find_spec 约 0.05~0.15 秒，import torch 约 6.6 秒，差两个数量级。
  判据上"装没装"就够 —— 真导不动时 server.py 会在启动时抛 ImportError，
  那比在这里提前 6 秒探测更明确，也不该让每次启动都付这个钱。

输出是**一行**纯文本，直接被 bat 的 `for /f` 接走：

    Python 3.13.12  缺torch

bat 侧据此拼提示。缺 openpyxl 也要报 —— 它缺了是**功能报错**
（cmdb_governance 读 xlsx 会静默返回空），不是优雅降级。
"""
from __future__ import annotations

import sys


def _has(mod: str) -> bool:
    """只查元数据，不 import。find_spec 失败（含缺依赖导致的父包异常）一律当作缺。"""
    try:
        import importlib.util as u
        return u.find_spec(mod) is not None
    except (ImportError, ValueError, AttributeError, ModuleNotFoundError):
        return False
    except Exception:  # noqa: BLE001  —— 探测绝不能自己把启动搞挂
        return False


def main() -> int:
    ver = ".".join(str(x) for x in sys.version_info[:3])
    miss = []
    if not _has("torch"):
        miss.append("缺torch")
    if not _has("transformers") or not _has("sentencepiece"):
        miss.append("缺transformers/sentencepiece")
    if not _has("sacremoses"):
        # MarianTokenizer 的必需项：缺了它 transformers 装了也用不了，
        # 且报错发生在推理时（很难定位），属于"装没装"必须看出来的依赖。
        miss.append("缺sacremoses")
    if not _has("openpyxl"):
        miss.append("缺openpyxl(报告导出xlsx会报错)")
    print("Python %s  %s" % (ver, " ".join(miss) if miss else "依赖齐全"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
