# -*- coding: utf-8 -*-
"""
静默异常全量治理器
================================================================
把代码里所有 `except ...: pass` 改写成"登记后再吞"：

    except Exception:
        pass
                    ↓
    except Exception as _sw_e:
        _swallow("modules/m1_monitor/api.py:406", _sw_e)

并在每个被改动的文件顶部插入一段零风险导入（两种 sys.path 布局都兼容，
最坏情况降级为 no-op，绝不引入新的失败点）。

为什么必须做：
  纯 pass 会把"结构性失效"伪装成"这次恰好没数据"。本项目已真实踩过一次：
  similarity_to_existing() 误写到类外 → AttributeError 被 pass 吞掉 →
  近重过滤全程静默失效，日志里毫无痕迹。治理后同类问题必然在日志里现形。

用法：
    python tools/_patch_swallow.py            # 干跑，只报会改哪些
    python tools/_patch_swallow.py --apply    # 真正改写（改完自动校验语法）

校验机制（三重，防止自动改写把代码改坏）：
  1) 改写后立即 ast.parse，语法不过就回滚该文件；
  2) 重新扫描，确认该文件只剩 0 处"纯 pass 的 except"；
  3) 全量 compileall（由调用方执行）。
"""
import ast
import json
import os
import re
import sys

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.workbuddy',
             'venv', '.venv', 'env', 'build', 'dist', 'data', 'frontend'}
SELF = os.path.basename(__file__)

# 插到文件顶部的导入片段：优先扁平导入（本项目 core/ 在 sys.path 上），
# 退回包导入，最后降级为 no-op —— 任何情况下都不会让原文件挂掉。
SNIPPET = (
    'try:  # aisec-swallow：静默异常统一登记（允许吞，但必须留痕）\n'
    '    from errlog import swallow as _swallow\n'
    'except Exception:  # pragma: no cover\n'
    '    try:\n'
    '        from core.errlog import swallow as _swallow\n'
    '    except Exception:\n'
    '        def _swallow(tag, exc=None):\n'
    '            pass\n'
)


def _bind_head(head):
    """给 except 头补上 `as _sw_e`；裸 except 顺带收窄为 Exception。

    head 形如 '    except:' / '    except KeyError:' / '    ):'
    """
    s = head.rstrip()
    if s.endswith(':'):
        s = s[:-1]
    if re.match(r'^\s*except\s*$', s):
        s = s + ' Exception'
    return s + ' as _sw_e:'


def _silent_handlers(tree):
    """找出 body 只有 pass 的 except 分支。"""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.ExceptHandler) and n.body \
                and all(isinstance(b, ast.Pass) for b in n.body):
            out.append(n)
    return out


def _patch_source(src, relpath):
    """改写单个文件的源码，返回 (新源码, 改动处数)。"""
    tree = ast.parse(src)
    targets = _silent_handlers(tree)
    if not targets:
        return src, 0
    lines = src.split('\n')
    # 从下往上改，保证上方行号始终有效
    for node in sorted(targets, key=lambda n: -n.lineno):
        ci = (node.type.end_lineno if node.type is not None else node.lineno) - 1
        raw = lines[ci]
        name = node.name or '_sw_e'
        call = '_swallow("%s:%d", %s)' % (relpath, node.lineno, name)
        m = re.match(r'^(.*?:)\s*pass\s*(#.*)?$', raw)      # 单行形式
        if m:
            head, comment = m.group(1), (m.group(2) or '')
            if not node.name:
                head = _bind_head(head)
            lines[ci] = head + ' ' + call + ('  ' + comment if comment else '')
        else:                                                # 多行形式
            if not node.name:
                lines[ci] = _bind_head(raw)
            indent = re.match(r'[ \t]*', lines[node.lineno - 1]).group(0)
            start = ci + 1
            end = node.end_lineno                            # 1-based 闭区间
            lines[start:end] = [indent + '    ' + call]
    # 顶部插入导入片段（放在最后做，避免打乱上面已算好的行号）
    last = 0
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            last = max(last, n.end_lineno)
    idx = last
    if not idx:                                              # 没有 import：插到 docstring 之后
        idx = 0
        b0 = tree.body[0] if tree.body else None
        if isinstance(b0, ast.Expr) and isinstance(getattr(b0, 'value', None), ast.Constant) \
                and isinstance(b0.value.value, str):
            idx = b0.end_lineno
    lines[idx:idx] = SNIPPET.rstrip('\n').split('\n')
    return '\n'.join(lines), len(targets)


def main():
    apply = '--apply' in sys.argv
    roots = [a for a in sys.argv[1:] if not a.startswith('--')] or ['.']
    total, touched, manifest = 0, 0, []
    for root in roots:
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            for f in sorted(fn):
                if not f.endswith('.py') or f == SELF:
                    continue
                p = os.path.join(dp, f)
                try:
                    src = open(p, encoding='utf-8').read()
                except Exception:
                    continue
                if 'aisec-swallow' in src:
                    continue
                try:
                    tree = ast.parse(src)
                except SyntaxError:
                    continue
                n = len(_silent_handlers(tree))
                if not n:
                    continue
                rel = os.path.relpath(p, '.').replace('\\', '/')
                try:
                    new, cnt = _patch_source(src, rel)
                    compile(new, p, 'exec')                       # 校验 1：语法
                    left = len(_silent_handlers(ast.parse(new)))  # 校验 2：清零
                except Exception as e:
                    print('  !! 跳过（改写后校验失败）%s: %s' % (rel, e))
                    continue
                if left or cnt != n:
                    print('  !! 跳过（数量对不上）%s: %d -> %d' % (rel, n, cnt))
                    continue
                total += cnt
                touched += 1
                manifest.append({'file': rel, 'sites': cnt})
                print('  %-46s %d 处' % (rel, cnt))
                if apply:
                    open(p, 'w', encoding='utf-8', newline='\n').write(new)
    print('-' * 60)
    print('%s：%d 个文件、%d 处静默异常待治理' % ('已改写' if apply else '干跑', touched, total))
    if apply:
        json.dump(manifest, open('测试报告/_swallow_manifest.json', 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        print('已写出改动清单：测试报告/_swallow_manifest.json')


if __name__ == '__main__':
    main()
