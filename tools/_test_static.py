# -*- coding: utf-8 -*-
"""静态校验：函数 return 的元组元素个数是否与签名声明一致。

为什么需要（2026-10-05 实际踩坑）：给 _load_assets 增加 loc_index 返回值时，
改了签名和 12 个 return，漏了最后 1 个 inline 分支的 return → 运行时报
`not enough values to unpack (expected 6, got 5)`，且只在 inline 模式触发，
全量 file 模式的离线验证测不到。手工数 return 靠不住，用 AST 静态查。

同时检查：同一函数被定义两次（后者会静默覆盖前者，之前 _priority_label
就中过这个招，新阈值不生效、被旧定义覆盖）。

★ 2026-10-05 新增第 3 类检查：模块内「集合/字典的成员判定大小写不一致」。
  实测 _fetch_loc_index_sqlite 里 `cols = set(colmap)`（PRAGMA 返回小写列名），
  却被 `if "IDC_NAME" in cols` 这样的大写字面量判定 → 恒假 → 机房名/城市/机柜号
  一个都没 SELECT 出来，报告位置列全渲染成「未登记」。这类 bug 不报错、不抛异常，
  只在真实数据上表现为「字段为空」，纯靠人眼看不出来，静态查最省事。

用法：python tools/_check_return_arity.py [文件路径...]
"""
import ast
import os
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = [
    os.path.join(ROOT, "modules", "m2_enrich", "backend", "cmdb_scan.py"),
    os.path.join(ROOT, "modules", "m2_enrich", "backend", "asset_scan.py"),
    os.path.join(ROOT, "modules", "m2_enrich", "backend", "cmdb_audit.py"),
    os.path.join(ROOT, "modules", "m2_enrich", "backend", "cmdb_governance.py"),
]
# ★ 测试脚本自身也必须过静态检查（2026-10-05 踩坑）：
#   在 _test_report_adversarial.py 里删了一行 `def _r5():`，
#   函数体留下变成 IndentationError。而这个脚本**只被 运行CI.bat 的通配执行**，
#   没有语法预检 —— 结果是"对抗测试静默不跑、CI 仍显示绿灯"，
#   最危险的一种失败：验证层自己坏了但没人知道。
#   所以：把本文件之外的所有 tools/_test_*.py 纳入检查。
try:
    _tdir = os.path.join(ROOT, "tools")
    _self = os.path.normcase(os.path.abspath(__file__))
    DEFAULT += [os.path.join(_tdir, n) for n in sorted(os.listdir(_tdir))
                if n.startswith("_test_") and n.endswith(".py")
                and os.path.normcase(os.path.abspath(
                    os.path.join(_tdir, n))) != _self]
except OSError:
    pass


def tuple_arity(node):
    """ast 表达式 → 元组元素个数；非字面元组返回 None（不检查）。"""
    if isinstance(node, ast.Tuple):
        return len(node.elts)
    if isinstance(node, ast.Constant) and isinstance(node.value, tuple):
        return len(node.value)
    return None


class Checker(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.fn = "<module>"
        self.declared = None
        self.observed = None
        self.problems = []
        self.returns = []          # (lineno, arity or None)

    def visit_FunctionDef(self, node):
        self._check(node)

    def visit_AsyncFunctionDef(self, node):
        self._check(node)

    def _check(self, node):
        outer = (self.fn, self.declared, self.observed, self.returns)
        self.fn = node.name
        # 签名里的 Tuple[X, Y, ...] → 声明的元素个数
        self.declared = None
        ann = node.returns
        if isinstance(ann, ast.Subscript):
            base = ast.unparse(ann.value)
            if base in ("Tuple", "tuple"):
                inner = ann.slice
                if isinstance(inner, ast.Tuple):
                    self.declared = len(inner.elts)
                else:
                    self.declared = 1     # Tuple[X] 不是我们关心的多返回
        self.observed = None
        self.returns = []
        self.generic_visit(node)
        for ln, ar in self.returns:
            if ar is None:
                continue
            if self.declared is not None and ar != self.declared:
                self.problems.append(
                    (ln, node.name, "签名声明 %d 元组，return 只有 %d 个" % (self.declared, ar)))
            elif self.declared is None:
                if self.observed is None:
                    self.observed = ar
                elif ar != self.observed:
                    self.problems.append(
                        (ln, node.name, "同函数内 return 元组个数不一致：%d vs %d"
                         % (self.observed, ar)))
        self.fn, self.declared, self.observed, self.returns = outer


def check_file(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src, filename=path)
    c = Checker(path)
    c.visit(tree)
    dup = {k: v for k, v in Counter(
        n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ).items() if v > 1}
    return (c.problems, dup, check_case_mismatch(src), find_bad_percent(src),
            find_escaped_percent_in_plain(src), find_arity_mismatch(src),
            find_free_name(src))


# 「小写化集合里混入大写字面量」模式。
#   真实 bug 形态一：cols = set(colmap)      （PRAGMA 返回小写列名）
#                然后 if "IDC_NAME" in cols  → 恒假
#   真实 bug 形态二：extra = [colmap[c] for c in ("IDC_NAME", "IDC_CODE", ...)]
#                小写集合里查大写字面量 → 全部落空
# 两种都靠「大写标识符字面量 + 附近存在小写化集合」来判定。
_MEMBERSET_RE = re.compile(
    r"^\s*(\w+)\s*=\s*set\(\s*(\w+(?:\.\w+)*)\s*\)", re.M)
# 大写标识符字面量（形如 "IDC_NAME" / "CAB_CODE"，允许中间有 _）
_UPPER_LIT_RE = re.compile(r"""["']([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)["']""")
_ALLOW_UPPER = {"SELECT", "GROUP_BY", "ORDER_BY", "PRAGMA_TABLE_INFO"}


def check_case_mismatch(src):
    """检出「小写化集合被大写字面量查询」的大小写错配（静默失效型 bug）。

    ★ 必须先剥掉注释：修复说明里常引用旧代码（"IDC_NAME" 大写）作为反例，
      不剥离会把说明文字当成 bug 报出来（实测踩过）。
    """
    code_only = _strip_comments(src)
    hits = []
    for sm in _MEMBERSET_RE.finditer(code_only):
        var, arg = sm.group(1), sm.group(2)
        if not re.search(r"lower|colmap|_cols$|^cols$|names|keys|idx", arg, re.I):
            continue
        rest = code_only[sm.end():]
        depth_end = rest.find("\ndef ")
        window = rest[:depth_end] if depth_end > 0 else rest
        for um in _UPPER_LIT_RE.finditer(window):
            lit = um.group(1)
            if lit in _ALLOW_UPPER or lit == var:
                continue
            lineno = code_only.count("\n", 0, sm.end() + um.start()) + 1
            snippet = window[max(0, um.start() - 40):um.end() + 20].replace("\n", " ")
            hits.append((lineno, '"%s" 出现在小写化集合 %s（源自 %s）之后：%s'
                         % (lit, var, arg, snippet.strip())))
            break            # 每个集合只报第一处，避免刷屏
    return hits


# ★ 2026-10-05 新增第 4 类检查：% 格式化串里的字面量百分号未转义。
#   实测踩坑：A("...审批时间 100% 非空，..." % x) 运行到那行抛
#   ValueError: unsupported format character —— 报告渲染整段崩掉。
#   语法合法，编译期查不出来，只有真跑到那行才炸。
#   ★ 实现要点（试过三版才做对）：不要用「% 后面跟什么」的正则判断——
#     无论怎么写都会在「%.1f%%」这种收尾转义上报错。改成**把合法占位符全部
#     剥离**，剩下的 % 才是裸的。占位符模式来自 str.__mod__ 的官方语法：
#       %s / %d / %.1f / %05d / %-10s / %*d / %(name)s / %%
_FMT_CONV = "sdrfxXoeEfFgGcnlLh"
_FMT_PLACEHOLDER = re.compile(
    r"%"
    r"(?:%"                # %% 转义成字面 %
    r"|\([^)]*\)[#0\- +]*[\d*]*(?:\.\d+)?[hlL]?[" + _FMT_CONV + "]"   # %(name)s
    r"|[#0\- +]*[\d*]*(?:\.\d+)?[hlL]?[" + _FMT_CONV + "]"             # %s/%.1f/%05d
    r")")


def find_bad_percent(src):
    """检出「用 % 格式化但串里有裸百分号」——运行到该行会抛 ValueError。"""
    hits = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mod):
            continue
        left = node.left
        if not (isinstance(left, ast.Constant) and isinstance(left.value, str)):
            continue
        rest = _FMT_PLACEHOLDER.sub("<P>", left.value)
        i = rest.find("%")
        if i < 0:
            continue
        hits.append((node.lineno,
                     "%% 格式化串里有未转义的 %%（原文 %r，应写成 %%%%）"
                     % left.value[max(0, i - 8):i + 8]))
    return hits


def find_escaped_percent_in_plain(src):
    """检出「不参与 % 格式化的字符串里写了 %%」——不会抛异常，但会原样输出两个百分号。

    ★ 为什么单列一类：第 4 类管的是「该转义没转义」（运行时报错），
      这一类反过来——`"漂移率 ≤ 5%%"` 写在 `cond ? "…%s…" % x : "…%%…"` 的
      **未格式化分支**里，Python 不会报错，但报告会印出「≤ 5%%」，
      评审时一眼就能看出是 bug（2026-10-05 对抗测试抓到）。
    ★ 实现要点：判定「该常量是否参与 % 格式化」不能只看它在不在三元里——
      要看它所在的常量节点自身有没有被 BinOp(Mod) 的左操作数引用。
      这里用「收集所有参与格式化的字符串节点 id」做差集，够用且不误报。
    ★ 不能传 _strip_comments(src)：那会把 docstring 里的示例文字变成裸代码，
      中文说明直接 SyntaxError（实测踩过）。docstring 天然不在 BinOp(Mod) 里，
      但会被本检查命中——所以额外按「是否 docstring」排除。
    """
    tree = ast.parse(src)
    formatted = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            for sub in ast.walk(node.left):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    formatted.add(id(sub))
    # docstring 节点集合
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docs.add(id(body[0].value))
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in formatted or id(node) in docs:
            continue
        v = node.value
        if "%%" not in v:
            continue
        hits.append((node.lineno,
                     "不参与格式化的字符串里出现 %%%%，会原样输出（原文 %r）" % v[:70]))
    return hits


def _strip_comments(src):
    """把 # 行注释与 docstring 换成空行（保持行号不变，便于定位）。

    不用 tokenize：docstring 在本文件里大量出现且都带中文说明，
    tokenize 方案要额外处理缩进；正则按行处理足够，且只用于「找字面量」这种
    宽松用途——宁可漏报也不误报。
    """
    out = []
    in_str = False
    for line in src.splitlines():
        if not in_str:
            m = re.search(r'("""|\'\'\')', line)
            if m:
                in_str = m.group(1)
                out.append("")
                continue
            h = line.find("#")
            out.append(line[:h] if h >= 0 else line)
        else:
            out.append("")
            if line.find(in_str) >= 0:
                in_str = False
    return "\n".join(out)


def find_arity_mismatch(src):
    """检出「调用点传 N 个参数，但被调函数签名不是 N 个」。

    ★ 真实 bug（2026-10-05 抓）：`_audit_chapter_five(aud, A)` 想改签名成
      `(rep, A)`，改了定义和调用点，**却漏改了函数体第一行**——
      体内仍写 `aud = rep.get(...)` 之外的 `rep.get("audit")`，
      报 `NameError: name 'rep' is not defined`。
      编译期不报（Python 允许先定义后调用），只有运行到那一行才炸，
      而这一行正好是「没传治理表」这种**低频分支**——
      主路径（小样本 smoke 有 audit）永远走不到。
    ★ 与已有的「return 元组元数一致性」互补：那条管函数**内部**自己写的返回值，
      这条管**模块内**函数定义的形参个数 vs 实际调用点数。
      仅限同文件（跨文件要看 import，成本高收益低）。
    """
    tree = ast.parse(src)
    defs = {}
    for node in tree.body:                      # 只看模块级函数
        if isinstance(node, ast.FunctionDef):
            a = node.args
            n_pos = len(a.posonlyargs) + len(a.args)
            n_kw = len(a.kwonlyargs)
            n_max = n_pos + n_kw
            # 必填数 = 全部形参 - 有默认值的（kw_defaults 里的 None 也算「必填」）
            n_def = n_max - len(a.defaults) - sum(
                1 for d in a.kw_defaults if d is not None)
            defs[node.name] = (n_def, n_max, a.vararg is not None,
                               a.kwarg is not None, node.lineno)
    hits = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        info = defs.get(node.func.id)
        if not info:
            continue
        n_def, n_max, has_var, has_kw, dln = info
        if has_var or has_kw:                   # *args/**kwargs 形参无法静态判定
            continue
        if any(k.arg is None for k in node.keywords):   # **kwargs 展开
            continue
        n_call = len(node.args) + len(node.keywords)
        if not (n_def <= n_call <= n_max):
            hits.append((node.lineno,
                         "调用 %s() 传 %d 个参数，但定义在第 %d 行只接受 %d~%d 个"
                         % (node.func.id, n_call, dln, n_def, n_max)))
    return hits


def find_free_name(src):
    """检出「函数体里用了模块里根本不存在��名字」→ 运行到该行必抛 NameError。

    ★ 真实 bug（2026-10-05 抓）：把 `_audit_chapter_five(aud, A)` 的签名
      改成 `(rep, A)`（为了拿 audit_err），改了定义和调用点，
      **却漏改了函数体内那一行** `aud = rep.get("audit")` 里的 `rep`——
      它是新签名里的形参名，所以形参/定义/调用三处都对得上，
      任何「签名 vs 调用」「形参 vs 引用」的检查都抓不到，
      只有真正跑一次才炸（`NameError: name 'rep' is not defined`）。
      而这行恰好在「没传治理表」的低频分支里，
      小样本 smoke 有 audit 数据、主路径永远走不到。
    ★ 这类 bug 只能靠「作用域分析」抓：收集一个函数体内所有
      **自由变量引用**（Load 上下文且不在局部/参数/模块级定义/内建里），
      逐个对照模块级定义集。
    ★ 实现要点（都实测踩过）：
      1. 必须收集**所有**绑定名（赋值 / for 目标 / with / except as /
         推导式变量 / 嵌套 def&class / import / global&nonlocal 声明），
         少收一类就误报一片。
      2. 局部集合要**逐函数**算，不能全文件合并——否则 A 函数里的
         局部变量会「豁免」B 函数里的同名非法引用。
      3. 只查模块级函数的函数体；类方法体、lambda 暂不查（易误报）。
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    import builtins
    bset = set(dir(builtins))
    # 模块级绑定
    module_names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for al in node.names:
                module_names.add((al.asname or al.name).split(".")[0])
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                module_names |= _bind_names(t)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            module_names |= _bind_names(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            module_names |= _bind_names(node.target)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for it in node.items:
                if it.optional_vars is not None:
                    module_names |= _bind_names(it.optional_vars)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            module_names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            module_names |= set(node.names)
    # ★ 还要收 try 块内的绑定：`try: from errlog import swallow as _swallow
    #   except: def _swallow(...): pass` 这种兜底导入挂在 ast.Try 下面，
    #   只扫 tree.body 会漏（实测 7 处误报）。
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module_names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for al in node.names:
                module_names.add((al.asname or al.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            module_names.add(node.name)
    known = module_names | bset

    hits = []
    for fn in [n for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        local = set()
        for a in (fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs):
            local.add(a.arg)
        if fn.args.vararg:
            local.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            local.add(fn.args.kwarg.arg)
        for node in ast.walk(fn):
            if node is fn:
                continue
            # ★ 嵌套 def/lambda 的形参**必须一并收进外层的 local**，
            #   否则 `def _has_risk(x): ... x.get(...)` 里的 x 会被当成
            #   「外层函数里的未定义自由变量」（实测误报一片）。
            #   两个分支都要收：def 收 name + 形参，lambda 只有形参。
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                local.add(node.name)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for a in (node.args.posonlyargs + node.args.args
                              + node.args.kwonlyargs):
                        local.add(a.arg)
                    if node.args.vararg:
                        local.add(node.args.vararg.arg)
                    if node.args.kwarg:
                        local.add(node.args.kwarg.arg)
            elif isinstance(node, ast.Lambda):
                for a in (node.args.posonlyargs + node.args.args
                          + node.args.kwonlyargs):
                    local.add(a.arg)
                if node.args.vararg:
                    local.add(node.args.vararg.arg)
                if node.args.kwarg:
                    local.add(node.args.kwarg.arg)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for al in node.names:
                    local.add((al.asname or al.name).split(".")[0])
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                local.add(node.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                local.add(node.name)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                local |= set(node.names)
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                                   ast.GeneratorExp)):
                for gen in node.generators:
                    local |= _bind_names(gen.target)
        for node in ast.walk(fn):
            if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                    and node.id not in known and node.id not in local):
                hits.append((node.lineno,
                             "函数 %s() 内引用了未定义的名字 %r → 运行到此处抛 "
                             "NameError" % (fn.name, node.id)))
    return hits


def _bind_names(target):
    """从一个赋值目标里收出所有被绑定的名字。"""
    out = set()
    for n in ast.walk(target):
        if isinstance(n, ast.Name):
            out.add(n.id)
    return out


def main():
    files = sys.argv[1:] or DEFAULT
    total = 0
    for p in files:
        if not os.path.isfile(p):
            print("跳过（不存在）：%s" % p)
            continue
        problems, dup, case_bad, pct_bad, pct_plain, arity, free = check_file(p)
        name = os.path.basename(p)
        for ln, fn, msg in problems:
            print("  %s:%d  %s  -> %s" % (name, ln, fn, msg))
        for fn, n in dup.items():
            print("  %s  %s 被定义 %d 次（后者会静默覆盖前者）" % (name, fn, n))
        for ln, msg in case_bad:
            print("  %s:%d  大小写错配  -> %s" % (name, ln, msg))
        for ln, msg in pct_bad:
            print("  %s:%d  %% 未转义    -> %s" % (name, ln, msg))
        for ln, msg in pct_plain:
            print("  %s:%d  %% 多余转义  -> %s" % (name, ln, msg))
        for ln, msg in arity:
            print("  %s:%d  参数元数    -> %s" % (name, ln, msg))
        for ln, msg in free:
            print("  %s:%d  自由变量    -> %s" % (name, ln, msg))
        total += (len(problems) + len(dup) + len(case_bad)
                  + len(pct_bad) + len(pct_plain) + len(arity) + len(free))
        if not (problems or dup or case_bad or pct_bad or pct_plain
                or arity or free):
            print("OK  %s" % name)
    if total:
        print("\n共 %d 处问题" % total)
        return 1
    print("\n全部通过：return 元组一致性 + 无重复定义 + 无大小写错配"
          " + % 格式化合法（未转义 / 多余转义）"
          " + 调用/定义元数一致 + 无未定义自由变量")
    return 0


if __name__ == "__main__":
    sys.exit(main())
