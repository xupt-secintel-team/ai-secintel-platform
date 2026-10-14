# -*- coding: utf-8 -*-
"""
alert_log.py —— 告警流水落盘通道（P0-3 / P1-2 共用 · 核心层）
==============================================================
为什么加这个
------------
P0-3（源缺失告警）与 P1-2（存活探活告警）都需要"把一条告警记下来、可查可核"，
而这两条链路分属不同层：
  · 源健康判定在 `modules/m1_monitor/backend/source_health.py`（模块层）；
  · 存活探活在 `core/health_probe.py`（核心层）。

若让核心层的探活去 import 模块层的 source_health，就会形成 core → modules 的
**反向依赖**（破坏微内核分层）。因此架构裁决 D 把落盘通道下沉到 core：
两侧都只依赖 `core/alert_log.py`，写同一条 `data/alerts.jsonl`。

设计约束
--------
  · **追加写**（禁止整读整写）—— 告警会长期累积，整读会在 GB 级时拖垮内存；
  · **轮转**：复用 `core/logrotate.py`，避免无限增长吃满磁盘（Q6）；
  · **不参与引擎索引**——它是运行期运行时的运维产物，不是情报语料；
  · 读用 `tail(n)`（从文件尾读 n 行），不做全量载入。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import paths  # noqa: E402 —— 数据目录统一解析（core/paths.py）
try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）
    from errlog import swallow as _swallow
except Exception:  # pragma: no cover
    try:
        from core.errlog import swallow as _swallow
    except Exception:
        def _swallow(tag, exc=None):  # type: ignore
            pass

try:
    import logrotate as _logrotate
except Exception:  # pragma: no cover —— 独立跑本文件时的兜底
    _logrotate = None  # type: ignore

# 落盘路径可经环境变量覆盖（测试卫生 F3）：单测把 AISEC_ALERT_FP 指向临时文件，
# 避免把测试告警写进生产 data/alerts.jsonl（此前 TEST-SRC 单测行污染了生产告警文件）。
ALERT_FP = os.environ.get("AISEC_ALERT_FP") or paths.data_path("alerts.jsonl")

# 单份 4MB、保留 3 个历史世代 —— 告警行的体量远小于运行日志，取更保守的阈值。
MAX_BYTES = 4 * 1024 * 1024
KEEP = 3

_LEVELS = ("warn", "critical")
_KINDS = ("source_missing", "health_probe")


def append_alert(level: str, source: str, reason: str,
                 evidence: Optional[Dict[str, Any]] = None,
                 state: str = "", kind: str = "") -> None:
    """追加一条告警到 data/alerts.jsonl（静默失败，绝不影响调用方主流程）。

    参数
    ----
    level    : ``warn`` / ``critical``（非法值归一到 warn）
    source   : 源名（源缺失类）或 ``core`` / 进程名（探活类）
    reason   : 人类可读原因
    evidence : 结构化证据，如 ``{"state":"stale","items_24h":0}``
    state    : 触发时状态（stale / degraded / down）
    kind     : ``source_missing``（P0-3）/ ``health_probe``（P1-2）
    """
    lv = level if level in _LEVELS else "warn"
    kd = kind if kind in _KINDS else (kind or "")
    import time as _t
    rec = {
        "ts": _t.strftime("%Y-%m-%dT%H:%M:%S"),
        "level": lv,
        "kind": kd,
        "source": str(source or ""),
        "reason": str(reason or ""),
        "evidence": evidence if isinstance(evidence, dict) else {},
        "state": str(state or ""),
    }
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    try:
        if _logrotate is not None:
            # 复用轮转（按大小切分 + 保留 KEEP 份），避免告警把磁盘吃满。
            rl = _logrotate.RotatingLog(ALERT_FP, max_bytes=MAX_BYTES, keep=KEEP)
            try:
                rl.write(line)
            finally:
                rl.close()
        else:  # pragma: no cover
            os.makedirs(os.path.dirname(ALERT_FP), exist_ok=True)
            with open(ALERT_FP, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError as e:
        _swallow("core/alert_log.py:append_alert", e)


def tail(n: int = 50) -> List[Dict[str, Any]]:
    """从文件尾读最近 n 条（不整读整写）。返回按时间正序（旧→新）的列表。"""
    n = max(1, min(2000, int(n or 50)))
    try:
        size = os.path.getsize(ALERT_FP)
    except OSError:
        return []
    lines: List[str] = []
    try:
        # 从尾部按块回读，凑够 n 行即停；单行最大 64KB 兜底防坏行。
        with open(ALERT_FP, "rb") as f:
            block = 65536
            buf = b""
            pos = size
            while pos > 0 and lines.__len__() <= n:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                lines = buf.split(b"\n")
            raw_lines = lines[-n:]
    except OSError as e:
        _swallow("core/alert_log.py:tail", e)
        return []
    out: List[Dict[str, Any]] = []
    for ln in raw_lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def count() -> int:
    """统计告警总条数（含历史世代，粗略：按行数）。"""
    total = 0
    files = [ALERT_FP] + ["%s.%d" % (ALERT_FP, i) for i in range(1, KEEP + 1)]
    for fp in files:
        try:
            with open(fp, "rb") as f:
                total += sum(1 for _ in f)
        except OSError:
            continue
    return total


def summary() -> Dict[str, Any]:
    """汇总：总条数 + 最近若干条（供 /api/source_health 的 alerts_total 用）。"""
    recent = tail(20)
    lv: Dict[str, int] = {}
    for r in recent:
        k = r.get("level") or "warn"
        lv[k] = lv.get(k, 0) + 1
    return {"total": count(), "recent_levels": lv, "recent": recent}
