# -*- coding: utf-8 -*-
"""
paths.py —— 全项目统一的路径解析（核心层）
============================================================
所有模块都从这里取路径，**不要再用 os.path.join(HERE, "data") 这类写法**。
数据目录的解析优先级（从高到低）：

1. 环境变量 ``AISEC_DATA_DIR``
2. 项目根目录 ``config.json`` 的 ``data_dir`` 字段（相对路径按项目根解析）
3. 项目根目录下的 ``data/``（默认）

这样语料/缓存只有一份（几百 MB），三个模块与主体共用，
换机器时只改 config.json 一行即可。
"""
from __future__ import annotations

import json
import os
import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass


CORE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(CORE_DIR)                    # 项目根（core 的上一级）
# ── 前端只有一个根：ROOT/frontend/ ──────────────────────────────────────────
#   frontend/index.html + styles.css + app.js   —— 控制台外壳
#   frontend/modules/<id>/panel.js|panel.css    —— 各模块面板（由 tools/组装前端.py
#                                                  从 modules/<id>/web/ 同步进来）
# 模块自治不受影响：模块作者改 modules/<id>/web/，跑一次组装脚本即可。
FRONTEND_DIR = os.path.join(ROOT, "frontend")
WEB_DIR = FRONTEND_DIR
MODULES_DIR = os.path.join(ROOT, "modules")
CONFIG_FP = os.path.join(ROOT, "config.json")

_DEFAULT_CONFIG = {
    "port": 8848,
    "data_dir": "data",
    "fast_interval": 30,
    "auto_refresh_hours": 0,
    "modules": {},
}


def load_config():
    """读取项目根 config.json（缺省项自动补默认值；文件不存在也能跑）"""
    cfg = dict(_DEFAULT_CONFIG)
    try:
        with open(CONFIG_FP, "r", encoding="utf-8") as f:
            cfg.update(json.load(f) or {})
    except (OSError, ValueError) as _sw_e:
        _swallow("core/paths.py:49", _sw_e)
    return cfg


def resolve_data_dir(cfg=None):
    """解析共享数据目录（不存在则创建）"""
    cfg = cfg or load_config()
    p = os.environ.get("AISEC_DATA_DIR") or cfg.get("data_dir") or "data"
    if not os.path.isabs(p):
        p = os.path.join(ROOT, p)
    p = os.path.normpath(p)
    os.makedirs(p, exist_ok=True)
    return p


DATA_DIR = resolve_data_dir()
CORPUS_FP = os.path.join(DATA_DIR, "corpus.json")


def data_path(*parts):
    """拼一个数据目录下的路径（自动建父目录由调用方决定）"""
    return os.path.join(DATA_DIR, *parts)


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
    return p
