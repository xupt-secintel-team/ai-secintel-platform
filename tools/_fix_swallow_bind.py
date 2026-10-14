# -*- coding: utf-8 -*-
"""
修补 + 校验 _swallow 改写点
================================================================
背景：_patch_swallow.py 的第一版在"except 头带尾注释"时会把 `as _sw_e`
追加到注释后面（例如 `except Exception as _sw_e:  # noqa: BLE001 :`），
语法仍然合法、compileall 也过，但变量根本没绑定 —— 一旦真触发就是 NameError。

本脚本做两件事：
  1) 修复：把 `as _sw_e` 从注释里挪回冒号前；
  2) 校验（AST 级）：凡是 body 里调用 _swallow(tag, X) 的 except 分支，
     必须真的绑定了 X（node.name 存在且与实参同名），否则报错并列出。
"""
import ast
import os
import re
import sys

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.workbuddy',
             'venv', '.venv', 'env', 'build', 'dist', 'data', 'frontend'}


def fix_line(line):
    """把落在注释里的 `as _sw_e` 挪回冒号前。"""
    if '#' not in line or 'as _sw_e' not in line:
        return line, False
    i = line.index('#')
    code, comment = line[:i].rstrip(), line[i:]
    if 'as _sw_e' in code:                 # 已经在代码部分，正常
        return line, False
    if 'as _sw_e' not in comment:           # 注释里也没有，无需处理
        return line, False
    comment = comment.replace('as _sw_e', '').replace('#  ', '#').replace('# ', '#', 1)
    if code.endswith(':'):
        s = code[:-1]
        if re.match(r'^\s*except\s*$', s):
            s += ' Exception'
        code = s + ' as _sw_e:'
    elif not code.endswith(':'):
        code = code + ' as _sw_e:'
    return code + '  ' + comment, True


def check(src, path):
    """返回未绑定实参的 (行号, 实参名) 列表。"""
    tree = ast.parse(src)
    bad = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.ExceptHandler):
            continue
        for st in n.body:
            if not isinstance(st, ast.Expr) or not isinstance(st.value, ast.Call):
                continue
            fn = st.value.func
            if getattr(fn, 'id', None) != '_swallow':
                continue
            args = st.value.args
            if len(args) < 2 or not isinstance(args[1], ast.Name):
                continue
            if n.name != args[1].id:       # 没绑定 → 运行时必 NameError
                bad.append((st.lineno, args[1].id))
    return bad


def main():
    apply = '--apply' in sys.argv
    nfix = nfile = 0
    bad_all = []
    for dp, dn, fn in os.walk('.'):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in sorted(fn):
            if not f.endswith('.py'):
                continue
            p = os.path.join(dp, f)
            src = open(p, encoding='utf-8').read()
            if '_swallow(' not in src:
                continue
            lines = src.split('\n')
            changed = False
            for i, ln in enumerate(lines):
                if 'except' in ln and '#' in ln and 'as _sw_e' in ln \
                        and re.match(r'^\s*(except|\)|\) as)', ln):
                    new, ok = fix_line(ln)
                    if ok:
                        lines[i] = new
                        changed = True
                        nfix += 1
            if changed:
                nfile += 1
                src = '\n'.join(lines)
                if apply:
                    open(p, 'w', encoding='utf-8', newline='\n').write(src)
            try:
                bad = check(src, p)
            except SyntaxError as e:
                bad_all.append((p, '语法错误 %s' % e))
                continue
            for ln, nm in bad:
                bad_all.append((p, 'L%d 实参 %s 未绑定' % (ln, nm)))
    print('修补：%d 个文件、%d 行' % (nfile, nfix))
    if bad_all:
        print('!! 仍有 %d 处未绑定：' % len(bad_all))
        for p, m in bad_all[:40]:
            print('   ', p, m)
    else:
        print('校验通过：所有 _swallow 调用点的实参都已正确绑定')


if __name__ == '__main__':
    main()
