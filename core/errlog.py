# -*- coding: utf-8 -*-
"""
errlog.py —— 静默异常统一登记（可观测性基础设施）
================================================================
【为什么要有这个模块】

本项目曾经有 112 处 `except ...: pass`。这种写法会把**结构性失效**
（方法名写错、属性不存在、依赖缺失、字段改名）伪装成"这次恰好没数据"：
日志干干净净，功能却悄悄全丢了。

已经真实发生过一次：
    similarity_to_existing() 被误写到了类外（嵌在模块级函数 _jaccard 里），
    调用方 self.similarity_to_existing(...) 抛 AttributeError，
    但外面包了一层 `except Exception: pass`，于是"近重过滤"全程静默失效，
    直到端到端测试才发现。

所以治理原则改成：**允许吞，但必须留痕。**

【用法】

    try:
        risky()
    except Exception as e:
        swallow("engine.py:1234", e)

【行为】

* 默认：以 DEBUG 级登记（几乎零开销，不刷屏）。
* 设环境变量 AISEC_SWALLOW_LOG=1：升级为 WARNING 级 + 打印栈，用于线上排障。
* 全程在内存里按 tag 计数，`stats()` / `dump()` 可导出统计，供体检脚本与报告使用。

【注意】
本模块必须零依赖、零副作用（不读配置、不建目录），
因为它会被塞进任何一个 except 分支里，不能反过来制造新的失败点。
"""
import collections
import logging
import os
import traceback

__all__ = ['swallow', 'stats', 'dump', 'reset']

_LOG = logging.getLogger('aisec.swallow')
_COUNTS = collections.Counter()          # tag -> 次数
_LAST = {}                               # tag -> 最近一次异常的文本

# 排障模式：把静默异常升级为 WARNING 并打印调用栈
_VERBOSE = os.environ.get('AISEC_SWALLOW_LOG') == '1'
if _VERBOSE and not _LOG.handlers:
    logging.basicConfig(level=logging.WARNING,
                        format='%(levelname)s %(name)s %(message)s')


def swallow(tag, exc=None):
    """登记一处"被吞掉的异常"。

    tag  : 形如 "core/engine.py:1234"，由 tools/_patch_swallow.py 自动写入
    exc  : 异常对象（可为 None）
    """
    _COUNTS[tag] += 1
    try:
        _LAST[tag] = '%s: %s' % (type(exc).__name__, exc)
    except Exception:
        _LAST[tag] = '<?>'
    if not _VERBOSE and not _LOG.isEnabledFor(logging.DEBUG):
        return
    msg = '静默异常 @%s | %s' % (tag, _LAST[tag])
    if _VERBOSE:
        _LOG.warning('%s\n%s' % (msg, ''.join(traceback.format_exc())))
    else:
        _LOG.debug(msg)


def stats():
    """返回 {tag: 次数}（按次数降序）。"""
    return dict(_COUNTS.most_common())


def dump(top=20):
    """返回 [(tag, 次数, 最近异常)]，便于写进报告或日志。"""
    return [(t, c, _LAST.get(t, '')) for t, c in _COUNTS.most_common(top)]


def reset():
    _COUNTS.clear()
    _LAST.clear()
