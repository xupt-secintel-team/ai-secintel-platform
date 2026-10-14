# -*- coding: utf-8 -*-
"""resume_extra.py —— 断点续跑：刷新 repo + CSDN，复用现有 GHSA 缓存。
用于 collect_all 在 CSDN 阶段崩溃后的恢复（避免 GitHub core API 重复消耗限额）。
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# —— 模块化结构：数据目录统一由 core/paths.py 解析（本文件可独立运行）——
import sys as _sys
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
for _p in (os.path.join(_ROOT, "core"), os.path.dirname(os.path.abspath(__file__))):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import paths  # noqa: E402
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):
            pass

# 依赖 paths / _swallow，必须放在两者定义之后
EXTRA = paths.data_path("extra_sources.json")
import extra_sources as X  # noqa: E402

# 安全 UTF-8 输出设置：用 reconfigure 而非重建 TextIOWrapper，
# 否则模块被 import 时会关闭原 stdout（合并/复用场景下的隐患）
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception as _sw_e:  # noqa: BLE001
    _swallow("modules/m1_monitor/backend/resume_extra.py:31", _sw_e)



def main():
    with open(EXTRA, encoding="utf-8") as f:
        extra = json.load(f)
    print("旧缓存：repo %d / article %d / GHSA独立 %d" % (
        len(extra.get("repos") or []), len(extra.get("articles") or []),
        len(extra.get("ghsa_standalone") or [])))

    repos = X.collect_repos()
    print("新仓库：%d" % len(repos))

    articles = X.collect_csdn()
    print("新文章：%d" % len(articles))

    extra["repos"] = repos
    extra["articles"] = articles
    meta = extra.setdefault("meta", {})
    meta["repos"] = len(repos)
    meta["articles"] = len(articles)

    tmp = EXTRA + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(extra, f, ensure_ascii=False, indent=1)
    os.replace(tmp, EXTRA)
    print("已写回 extra_sources.json")


if __name__ == "__main__":
    main()
