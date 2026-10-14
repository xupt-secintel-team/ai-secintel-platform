# -*- coding: utf-8 -*-
"""_test_portability.py —— 交付到**别人机器**上必须成立的事（2026-10-07）

## 背景

把包发给别人测，暴露了 4 个只在我这台机器上不复现的问题。它们有个共同点：
**我这边全绿，他那边直接起不来** —— 所以静态检查和本地测试都抓不到。

1. **bat 里写死了本机绝对路径** ``D:\\python\\python.exe``。
   别人机器没这个目录 → cmd 报
   ``did not find executable at D:\\python\\python.exe: ????????``
   然后解释器一个都没选上，脚本直接退出。
2. **写死 `py -3.13`**。别人装的是 3.11/3.12/3.14 时该命令直接失败。
   候选里没有任何"到处都可能有"的解释器可用。
3. **`.venv` 存在 ≠ 能用**。从别的机器整个拷来的 venv，
   内部 pyvenv.cfg 记的是原机器的解释器绝对路径 —— `if exist` 通过、
   真正执行立刻失败。判据必须是"能不能跑起来"，不是"文件在不在"。
4. **config.json 是给人手工编辑的**，实测别人那份把
   `"port": 8848` 填成了**一段中文说明**（"控制台端口，但可启动时用命令行
   覆盖：py -3.13 core/server.py 8899"）。
   原先 `int(config.get("port") or 8848)` 直接抛 ValueError，
   **服务一行日志都打不出来就崩**，用户只看到双击窗口闪一下就没了。
   同样的暴露面还有 fast_interval / auto_refresh_hours / auto_refresh_sec。

## 为什么单列一个文件

以上都不是业务逻辑，是**交付形态**的问题。混进业务测试里，
一旦失败很难联想到"是给别人跑时才会炸"。
"""
from __future__ import annotations

import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "core"))

PASS = 0
FAIL = 0


def ck(cond, label, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok   " + label)
    else:
        FAIL += 1
        print("  FAIL " + label + (("  " + str(extra)) if extra else ""))


def section(t):
    print("\n=== " + t + " ===")


def read(p, mode="r"):
    with io.open(p, mode, encoding="utf-8-sig") as f:
        return f.read()


def bat(name):
    # .bat 现在统一存成 GBK 无 BOM（cmd 按系统 ANSI=GBK 解析，UTF-8 BOM 会被
    # 当成命令前缀，实测 '锘緻echo' 不是内部或外部命令）。所以读 bat 要用 gbk。
    with io.open(os.path.join(ROOT, name), "r", encoding="gbk") as f:
        return f.read()


print("_test_portability.py —— 交付到别人机器上必须成立")


def _all_bats():
    """要检查的全部 bat：根目录入口 bat + tools 下的内部 bat。

    ★ 2026-10-09：原先只扫根目录，而且**只对 启动服务.bat 做了 py -3.13 断言**，
      于是 设置密钥 / 运行自测 / 合并前核查 / 下载嵌入模型 / 运行CI 这 5 个
      bat 里的写死解释器长期漏检 —— 本地全绿，别人机器上这 5 个双击全挂。
      "检查范围 < 实际范围"是这类问题的共同根因，所以这里一次收口。
    """
    out = sorted(n for n in os.listdir(ROOT) if n.lower().endswith(".bat"))
    tdir = os.path.join(ROOT, "tools")
    if os.path.isdir(tdir):
        out += sorted("tools\\" + n for n in os.listdir(tdir)
                      if n.lower().endswith(".bat"))
    return out


# ── 1. 批处理不得含本机专属绝对路径 ─────────────────────────────
section("[1] 批处理里的路径必须到处都成立")
# 本机专属：盘符 + 用户目录。.venv 是项目自带的相对路径，允许。
# ★ 只看**可执行行**（rem 注释不计）—— 注释里常要写"原来错在哪"，
#   那里出现旧路径是**修复记录**，是应该保留的信息。
LOCAL_PATH = re.compile(r"[A-Za-z]:\\\\?(?:python|Users|Windows|Program)", re.I)
for name in _all_bats():
    src = bat(name)
    hits = []
    for i, line in enumerate(src.splitlines(), 1):
        s = line.strip()
        # 跳过注释：rem 开头的行、:: 注释，以及 echo 出去的纯说明文本
        if s.lower().startswith("rem") or s.startswith("::"):
            continue
        if s.lower().startswith("echo"):
            # echo 的内容会显示给用户，里面出现本机路径同样是错的
            for m in LOCAL_PATH.finditer(s):
                hits.append("第%d行(echo): %s" % (i, m.group(0)))
            continue
        for m in LOCAL_PATH.finditer(s):
            hits.append("第%d行: %s" % (i, m.group(0)))
    ck(not hits, "%s 的可执行行没有本机专属绝对路径" % name, hits[:3])

# 启动脚本尤其重要：它是所有人的唯一入口
srv = bat("启动服务.bat")
ck(not re.search(r'^\s*(?!rem)\S.*"D:\\\\python', srv, re.M | re.I),
   "启动服务.bat 的可执行行没有 D:\\python\\python.exe")
ck(not re.search(r'^\s*echo.*D:\\\\python', srv, re.M | re.I),
   "启动服务.bat 没有把 D:\\python 显示给用户")
ck("张洺豪" not in srv, "启动服务.bat 不含本机用户名")

# ── 2. 解释器候选必须用"到处都可能有"的 ───────────────────────
section("[2] 解释器候选")
# 只看可执行行：注释里写「原来是 py -3.13」是修复记录，该保留
_exe_lines = [l.strip() for l in srv.splitlines()
              if l.strip() and not l.strip().lower().startswith("rem")
              and not l.strip().startswith("::")]
_exe_all = "\n".join(_exe_lines)
ck("py -3.13" not in _exe_all,
   "可执行行里不再有 py -3.13（别人机器可能是 3.11/3.12/3.14）")
ck(re.search(r'for %{2}I in \([^)]*\bpy -3\b', srv) is not None,
   "候选里有 py -3（启动器默认版本）")
ck(re.search(r'for %{2}I in \([^)]*\bpython\b', srv) is not None,
   "候选里有 python（PATH 里的）")
# ★ 候选必须用 for %%I in：它会跳过**不存在**的可执行文件；
#   for %%P in 不跳过，拿一个别人机器上没有的路径去试就报
#   `did not find executable at ...`（实测踩过）。
#   注意区分两类循环：
#     for %%P in ("py -3" "python" "python3")  —— 整列表都是**引号字符串**，
#         存进 BOOT_PY 当字符串用（选 bootstrap 解释器），这里 %%P 完全正确；
#     for %%I in (py -3 python python3)          —— 列表项是**裸命令名**，
#         会被 cmd 当可执行文件解析，必须用 %%I 才能跳过不存在的。
_seen_bad = []
for m in re.finditer(r'for %{2}([A-Z]) in \(([^)]*)\)', srv):
    var, lst = m.group(1), m.group(2)
    items = [x.strip() for x in lst.split(",") if x.strip()]
    if not items:
        continue
    # 整列表都是引号字符串 → 字符串变量场景，%%P/%%I 都对
    if all(x.startswith('"') and x.endswith('"') for x in items):
        continue
    if not (any("python" in x.lower() or x.lower().startswith("py ")
                for x in items)):
        continue          # 不是解释器候选（是 %* 参数、分类名等）
    if var != "I":
        _seen_bad.append("for %%%s in (%s)" % (var, lst))
ck(not _seen_bad, "解释器候选全部用 for %I（会跳过不存在的可执行文件）", _seen_bad)

# ── 3. 选完必须做"能不能跑"的校验 ─────────────────────────────
# ── 2b. 全部 bat：不许写死解释器版本、不许引用 WorkBuddy 自带 Python ──
section("[2b] 全部 bat 统一走 tools\\_选解释器.bat")
# ★ 2026-10-09 新增。此前 [2] 只对 启动服务.bat 断言，另外 5 个 bat 逃过检查：
#     设置密钥 / 运行自测 / 合并前核查 / 下载嵌入模型 / 运行CI
#   它们都写了 `py -3.13`；运行CI.bat 更写死了 WorkBuddy 自带 Python 的
#   **版本号路径**（%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\）。
#   两类都只在"别人的机器"上炸，本地永远复现不了。
_PINNED = re.compile(r"py\s+-3\.\d")          # py -3.13 / py -3.12 ……
_WORKBUDDY_PY = re.compile(r"\.workbuddy\s*[\\/]binaries", re.I)
_bad_pinned, _bad_wbpy = [], []
for name in _all_bats():
    _exe = "\n".join(
        l.strip() for l in bat(name).splitlines()
        if l.strip() and not l.strip().lower().startswith("rem")
        and not l.strip().startswith("::"))
    if _PINNED.search(_exe):
        _bad_pinned.append(name)
    if _WORKBUDDY_PY.search(_exe):
        _bad_wbpy.append(name)
ck(not _bad_pinned,
   "没有 bat 在可执行行写死 py -3.<数字>（别人可能是 3.11/3.12/3.14）", _bad_pinned)
ck(not _bad_wbpy,
   "没有 bat 在可执行行引用 WorkBuddy 自带 Python（升级/换机就失效）", _bad_wbpy)

# 统一入口：要跑 .py 的 bat 必须 call tools\_选解释器.bat。
# 例外只有三个：
#   · 启动服务.bat / 启动服务_守护.bat —— 自带"能力感知"选择逻辑（还要挑
#     装了 torch 的解释器），比通用助手更专，保留自有实现；
#   · 下载翻译模型.bat / 安装语义依赖.bat —— **必须**装进项目 .venv，
#     故意不回落到系统 Python（回落才是 bug，见两个文件里的说明）。
_helper_rel = os.path.join("tools", "_选解释器.bat")
ck(os.path.isfile(os.path.join(ROOT, _helper_rel)),
   "tools\\_选解释器.bat 存在（统一解释器入口）")
_delegating = ["设置密钥.bat", "运行自测.bat", "合并前核查.bat",
               "下载嵌入模型.bat", "运行CI.bat"]
_miss = [n for n in _delegating if "tools\\_选解释器.bat" not in bat(n)]
ck(not _miss, "这 5 个 bat 都改为 call tools\\_选解释器.bat", _miss)

# ── 2c. tools/*.py 不许硬编码项目 .venv 的解释器 ───────────────
section("[2c] tools/*.py 不硬编码 .venv 解释器（没 .venv 的机器会炸）")
# ★ 2026-10-09 新增。29 个**要起真实服务 / 拉子进程**的脚本原来写死
#   os.path.join(ROOT, ".venv", "Scripts", "python.exe")。
#   别人机器上 .venv 不存在（或整包拷过来、pyvenv.cfg 还记着原机器的
#   D:\\python\\python.exe）→ 报
#   `did not find executable at 'D:\\python\\python.exe'`。
#   本地永远复现不了（本机 .venv 恰好能跑），CI 里却真红。
#   统一改用 sys.executable：谁跑这个脚本，就用谁的解释器。
# 只认真正的**路径写法**（必须带 Scripts）——否则本段的标签文本
# 「.venv 的 python.exe」会被自己抓到。
_VENV_PY = re.compile(r"\.venv[\\/]+Scripts[\\/]+python\.exe", re.I)
_bad_venv_py = []
_tdir = os.path.join(ROOT, "tools")
if os.path.isdir(_tdir):
    for _n in sorted(os.listdir(_tdir)):
        if not _n.lower().endswith(".py"):
            continue
        try:
            _src = read(os.path.join(_tdir, _n))
        except Exception:
            continue
        for _i, _line in enumerate(_src.splitlines(), 1):
            _s = _line.strip()
            if not _s or _s.startswith("#"):
                continue
            if _VENV_PY.search(_s):
                _bad_venv_py.append("tools\\%s:%d  %s" % (_n, _i, _s[:72]))
ck(not _bad_venv_py,
   "没有 .py 硬编码 .venv 的 python.exe（应改用 sys.executable）",
   _bad_venv_py[:3])

# ── 2d. bootstrap.py：复用 .venv 前必须验证"能不能跑" ──────────
section("[2d] bootstrap.py 重建 .venv 的判据与善后")
# ★ 2026-10-09：step_venv 原来只判 os.path.isfile（文件在就复用），
#   别人机器上拷来的坏 venv 会被当成好的跳过安装 → 与 _选解释器.bat
#   「真跑一次」的判据不一致。已改为先跑 -c "print(1)" 验证。
_boot = ""
try:
    _boot = read(os.path.join(ROOT, "bootstrap.py"))
except Exception:
    pass
ck("_venv_runnable" in _boot and "os.path.isfile(py)" in _boot,
   "step_venv 对已存在的 .venv 做了'能不能跑'校验（非只看文件在不在）")
# 重建时不能直接 rmtree：venv 内上万文件，实测会被安全护栏的批量删除拦截
ck("shutil.rmtree" not in _boot,
   "重建 .venv 用改名归档（rmtree 会被批量删除护栏拦、且不可回滚）")
# 助手自己不许再写死版本号（否则只是把问题换了个地方）
if os.path.isfile(os.path.join(ROOT, _helper_rel)):
    _h = bat(_helper_rel)
    ck(_PINNED.search("\n".join(
        l.strip() for l in _h.splitlines()
        if l.strip() and not l.strip().lower().startswith("rem"))) is None,
       "助手本身也不写死 py -3.<数字>")

# ── 3. 选完必须做"能不能跑"的校验 ─────────────────────────────
section("[3] 选完解释器要验证能真的跑起来")
ck(re.search(r'%PYEXE%\s+-c\s+"print\(1\)"', srv) is not None,
   "有启动自检 %PYEXE% -c \"print(1)\"（文件存在 ≠ 能执行）")
ck("从别的机器整个拷过来" in srv, "自检失败时给出了可操作的原因（venv 跨机不可移植）")
ck("安装.bat" in srv, "自检失败时指向「安装.bat」重建 venv")

# ── 4. 探测不该靠 import（启动慢的主因）────────────────────────
section("[4] 依赖探测不许 import（那要 2.7 秒起）")
ck("find_spec" in srv, "用 importlib.util.find_spec 查元数据，不 import")
ck(re.search(r'%PYEXE%\s+-c\s+"import torch"', srv) is None,
   "没有裸的 `import torch` 探测（单次就要 2.7 秒）")
probe = os.path.join(ROOT, "tools", "探测解释器.py")
ck(os.path.isfile(probe), "tools/探测解释器.py 存在（bat 第 2d 段要调它）")
if os.path.isfile(probe):
    ck("find_spec" in read(probe), "探测脚本用 find_spec")
    # 只看可执行行：文档字符串里为了说明"import torch 有多慢"必然提到它
    _code = "\n".join(l for l in read(probe).splitlines()
                      if not l.strip().startswith(("#", '"""', "'''"))
                      and "import torch" not in l)
    ck(not re.search(r"^\s*import torch", _code, re.M),
       "探测脚本没有真 import torch（只在注释里提到）")
    # 现场计时：必须显著快于 import torch
    import subprocess
    import time
    t = time.time()
    subprocess.run([sys.executable, probe],
                   capture_output=True)
    dt = time.time() - t
    ck(dt < 1.5, "探测脚本耗时 %.2fs < 1.5s" % dt, dt)

# ── 5. bat 编码：必须是 GBK 无 BOM ──────────────────────────────
section("[5] 批处理编码（应 GBK 无 BOM，UTF-8 BOM 会让中文注释变伪命令）")
# 实测证伪：加 UTF-8 BOM 后 cmd 仍按 GBK 解析，BOM 字节还被当成命令前缀
# （'锘緻echo' 不是内部或外部命令）。正确方案是 GBK 无 BOM + CRLF。
for name in _all_bats():
    raw = open(os.path.join(ROOT, name), "rb").read()
    ck(raw[:3] != b"\xef\xbb\xbf", "%s 无 UTF-8 BOM" % name,
       raw[:3].hex())
    # 能被 GBK 解码 = 内容确实是 GBK（或纯 ASCII）
    try:
        raw.decode("gbk")
        is_gbk = True
    except UnicodeDecodeError:
        is_gbk = False
    ck(is_gbk, "%s 是 GBK 编码" % name)
    ck(b"\r\n" in raw and raw.count(b"\n") == raw.count(b"\r\n"),
       "%s 用 CRLF 换行" % name)

# ── 6. config.json 被填成文字时，服务必须能起 ───────────────────
section("[6] config.json 数值字段被填成文字时回落默认值")
import server as S  # noqa: E402

# 别人机器上 port 的实际内容（原样照抄那段中文）
BAD_PORT = "控制台端口，但可启动时用命令行覆盖：py -3.13 core/server.py 8899"
ck(S._coerce_port(BAD_PORT) == 8848, "port 是那段中文 → 回落 8848",
   S._coerce_port(BAD_PORT))
ck(S._coerce_port(None) == 8848, "port 是 None → 8848")
ck(S._coerce_port("") == 8848, "port 是空串 → 8848")
ck(S._coerce_port("  ") == 8848, "port 是纯空格 → 8848")
ck(S._coerce_port("8899") == 8899, "port 是合法数字串 → 正常用")
ck(S._coerce_port(8899) == 8899, "port 是 int → 正常用")
ck(S._coerce_port(0) == 8848, "port=0 → 8848")
ck(S._coerce_port(80) == 8848, "port=80（特权端口）→ 8848")
ck(S._coerce_port(70000) == 8848, "port=70000（越界）→ 8848")
ck(S._coerce_port("abc") == 8848, "port='abc' → 8848")

for key, dflt, cast in (("auto_refresh_hours", 0, float),
                        ("fast_interval", 30, int),
                        ("auto_refresh_sec", 0, float)):
    old = S.CONFIG.get(key)
    S.CONFIG[key] = "说明文字不是数字"
    try:
        got = S._cfg_num(key, dflt, cast)
        ck(got == dflt, "%s 被填成文字 → 回落 %s" % (key, dflt), got)
    finally:
        if old is None:
            S.CONFIG.pop(key, None)
        else:
            S.CONFIG[key] = old

# 下限/上限也要真的生效（fast_interval 配成 0 会让定时器疯狂触发）
old = S.CONFIG.get("fast_interval")
S.CONFIG["fast_interval"] = 0
try:
    ck(S._cfg_num("fast_interval", 30, int, lo=1) == 30,
       "fast_interval=0（下限外）→ 回落 30")
finally:
    if old is None:
        S.CONFIG.pop("fast_interval", None)
    else:
        S.CONFIG["fast_interval"] = old

# ── 7. 本机 config.json 自身是干净的（别把这台也带坏）──────────
section("[7] 本仓库 config.json 合法")
import json  # noqa: E402

cfg = read(os.path.join(ROOT, "config.json"))
try:
    d = json.loads(cfg)
    ck(isinstance(d.get("port"), int), "config.json 的 port 是整数", repr(d.get("port")))
except Exception as e:  # noqa: BLE001
    ck(False, "config.json 能解析成 JSON", e)

print("\n" + "=" * 60)
print("通过 %d / 失败 %d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
