# -*- coding: utf-8 -*-
"""代码体检：静态扫描常见缺陷模式。

覆盖六类最容易"静默出错"的模式：
  · syntax_error    —— 语法错误（文件根本加载不了）
  · silent_except   —— except 分支只有 pass，异常被彻底吞掉（本次就靠它揪出过
                       "similarity_to_existing 被误放到 _jaccard 内部、AttributeError 被吞"
                       导致过滤全程失效的事故）
  · bare_except     —— 裸 except / except BaseException，会连 KeyboardInterrupt 一起吞
  · mutable_default —— 函数用 [] / {} 作默认参数（跨调用共享，经典陷阱）
  · misplaced_method—— 模块级函数却被 self.xxx() 调用：说明本该是类方法却写到了类外，
                       调用点会抛 AttributeError（同类事故的根因，专门加的检测）
  · risky_eval      —— 使用 eval/exec/os.system 等动态执行，存在注入与不可控风险

用法：
    python tools/_bugscan.py [目录] [输出json]
"""
import ast
import json
import os
import sys

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.workbuddy',
             'venv', '.venv', 'env', 'build', 'dist'}


def scan(root='.', out=None):
    issues = []
    nfiles = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if not f.endswith('.py'):
                continue
            p = os.path.join(dp, f)
            nfiles += 1
            try:
                src = open(p, encoding='utf-8').read()
                tree = ast.parse(src)
            except SyntaxError as e:
                issues.append({'file': p, 'line': e.lineno or 0,
                               'kind': 'syntax_error', 'detail': str(e.msg)})
                continue
            except Exception:
                continue
            for node in ast.walk(tree):
                # except 分支
                if isinstance(node, ast.ExceptHandler):
                    real = [n for n in node.body if not isinstance(n, ast.Pass)]
                    if not real:
                        issues.append({
                            'file': p, 'line': node.lineno, 'kind': 'silent_except',
                            'detail': 'except 分支只有 pass：异常被吞掉且不落任何日志'})
                    if node.type is None:
                        issues.append({
                            'file': p, 'line': node.lineno, 'kind': 'bare_except',
                            'detail': '裸 except：会一并吞掉 KeyboardInterrupt/SystemExit'})
                    else:
                        base = getattr(node.type, 'id', None)
                        if base == 'BaseException':
                            issues.append({
                                'file': p, 'line': node.lineno, 'kind': 'bare_except',
                                'detail': 'except BaseException：会一并吞掉 KeyboardInterrupt/SystemExit'})
                # 动态执行
                if isinstance(node, ast.Call):
                    fname = getattr(node.func, 'id', None)
                    if fname in ('eval', 'exec', 'compile'):
                        issues.append({
                            'file': p, 'line': node.lineno, 'kind': 'risky_eval',
                            'detail': '调用 %s()：存在注入与不可控风险，需确认来源可控' % fname})
                    if isinstance(node.func, ast.Attribute) \
                            and isinstance(node.func.value, ast.Name) \
                            and node.func.value.id in ('os', 'subprocess', 'commands'):
                        risky = {'os': {'system', 'popen'},
                                 'subprocess': {'call', 'Popen', 'run'},
                                 'commands': {'getoutput', 'getstatusoutput'}}
                        if node.func.attr in risky.get(node.func.value.id, ()):
                            issues.append({
                                'file': p, 'line': node.lineno, 'kind': 'risky_eval',
                                'detail': '调用 %s.%s()：命令注入风险，需确认参数不含外部输入'
                                          % (node.func.value.id, node.func.attr)})
                # 可变默认参数
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defs = list(node.args.defaults) + \
                           [d for d in (node.args.kw_defaults or []) if d]
                    for d in defs:
                        if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                            issues.append({
                                'file': p, 'line': node.lineno, 'kind': 'mutable_default',
                                'detail': '函数 %s() 使用可变默认参数' % node.name})
            # 类方法被误放到模块级：self.xxx() 调用了模块级同名函数 → 调用点必抛 AttributeError
            self_calls = set()
            cls_methods = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                        and isinstance(node.func.value, ast.Name) \
                        and node.func.value.id == 'self':
                    self_calls.add(node.func.attr)
                if isinstance(node, ast.ClassDef):
                    for b in node.body:
                        if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            cls_methods.add(b.name)
            if self_calls:
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                            and node.name in self_calls and node.name not in cls_methods:
                        issues.append({
                            'file': p, 'line': node.lineno, 'kind': 'misplaced_method',
                            'detail': '模块级函数 %s() 却被 self.%s() 调用：可能误放到类外，'
                                      '调用点会抛 AttributeError' % (node.name, node.name)})
    print('扫描 %d 个 .py 文件，发现 %d 处可疑' % (nfiles, len(issues)))
    by_kind = {}
    for it in issues:
        by_kind[it['kind']] = by_kind.get(it['kind'], 0) + 1
    for k, v in sorted(by_kind.items()):
        print('  %-16s %d' % (k, v))
    print('--- 明细 ---')
    for it in issues:
        rel = os.path.relpath(it['file'], root)
        print('  %-40s L%-5d %-16s %s' % (rel[:40], it['line'], it['kind'],
                                          it['detail'][:70]))
    if out:
        json.dump(issues, open(out, 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        print('已写出：%s' % out)
    return issues


if __name__ == '__main__':
    scan(sys.argv[1] if len(sys.argv) > 1 else '.',
         sys.argv[2] if len(sys.argv) > 2 else None)
