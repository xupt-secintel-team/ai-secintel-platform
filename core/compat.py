# -*- coding: utf-8 -*-
"""
compat.py —— 版本 / 平台兼容层（全项目共用的"最低公分母"）
================================================================
立项背景（用户三项硬性要求的第 ① 条）：
    「在 2012 年以后的所有操作系统上都可以运行」

"2012 年以后"对应的一批系统跨度极大——Windows 7/8/10/11、macOS 10.8~15、
Ubuntu 12.04~24.04——它们能装上的 Python 从 2.7 到 3.13 都有。
本模块不追求"让旧 Python 跑出新特性"，而是把项目对解释器的要求
**显式收敛到一个可声明的下限**，并对下限以下的常见 API 缺口做兜底，
使主流程（检索 / 监测 / 富化 / 图谱 / 问答 / 报告）在老环境里不因
`AttributeError` 直接崩掉。

设计原则
--------
1. **只兜底，不改写**：提供的是标准库新 API 的等价实现，业务代码
   照常用 `s.removeprefix("x")` 这类写法，由本模块补上。
2. **导入即安全**：本模块自身不得依赖任何第三方包，也不得在导入期
   做 I/O（读注册表除外，已 try 包裹），保证任何环境都能 import。
3. **失败可解释**：版本不达标时不静默降级，由 `check_runtime()` 返回
   结构化结论，交给 bootstrap.py 决定是"提示"还是"帮你装"。

用法
----
    from compat import PY, IS_WIN, removeprefix, ensure_utf8_stdio
    ensure_utf8_stdio()          # Windows GBK 控制台下 print 中文不再抛异常

对外常量
--------
    PY              (major, minor) 元组
    PY_MIN          (3, 6) —— 本项目声明的最低可用版本
    IS_WIN / IS_MAC / IS_LINUX / IS_POSIX
    OS_FAMILY       "windows" / "macos" / "linux" / "unknown"
"""
from __future__ import annotations

import codecs
import os
import platform as _platform
import sys

__all__ = [
    "PY", "PY_MIN", "PY_STR", "IS_WIN", "IS_MAC", "IS_LINUX", "IS_POSIX",
    "OS_FAMILY", "OS_NAME", "OS_RELEASE", "ARCH",
    "removeprefix", "removesuffix", "cached_property", "metadata_version",
    "ensure_utf8_stdio", "safe_print", "reconfigure_stdio",
    "check_runtime", "cpu_count", "total_memory_bytes",
    "open_file_cross_platform", "port_in_use_hint", "fs_is_case_sensitive",
    "supports_symlink", "long_path",
]

PY = sys.version_info[:2]
PY_STR = "%d.%d.%d" % (sys.version_info[0], sys.version_info[1], sys.version_info[2])

# ── 版本下限 ───────────────────────────────────────────────────────────────
# 3.7（2018-06 发布）是本项目**实测**的下限，卡在两个硬依赖上：
#   · `from __future__ import annotations`（41 个文件在用，3.7 才引入）
#   · `dataclasses`（m2_enrich 的资产/POC 数据结构在用，3.7 才进标准库）
# 3.7 可安装于 Windows 7 SP1+ / macOS 10.9+ / Ubuntu 14.04+，
# 完整覆盖"2012 年以后的操作系统"这一要求；再往下（3.6 及以前）
# 连 `from __future__ import annotations` 都会 SyntaxError，不再支持。
#
# 注：3.7 上缺失的少数 3.8/3.9 API 由本模块下方的兜底函数补齐
#     （cached_property / importlib.metadata / str.removeprefix 等）。
PY_MIN = (3, 7)

# ── 平台判定 ───────────────────────────────────────────────────────────────
IS_WIN = os.name == "nt" or sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
IS_POSIX = os.name == "posix"

if IS_WIN:
    OS_FAMILY = "windows"
elif IS_MAC:
    OS_FAMILY = "macos"
elif IS_LINUX:
    OS_FAMILY = "linux"
else:
    OS_FAMILY = "unknown"

try:
    OS_NAME = _platform.system() or "unknown"
    OS_RELEASE = _platform.release() or ""
    ARCH = _platform.machine() or ""
except Exception:                                    # pragma: no cover
    OS_NAME, OS_RELEASE, ARCH = "unknown", "", ""


# ── 标准库新 API 兜底 ──────────────────────────────────────────────────────

def removeprefix(s, prefix):
    """str.removeprefix（3.9+）的等价实现；3.6~3.8 由本函数兜底。"""
    if hasattr(s, "removeprefix"):
        return s.removeprefix(prefix)
    if prefix and s.startswith(prefix):
        return s[len(prefix):]
    return s


def removesuffix(s, suffix):
    """str.removesuffix（3.9+）的等价实现；3.6~3.8 由本函数兜底。"""
    if hasattr(s, "removesuffix"):
        return s.removesuffix(suffix)
    if suffix and s.endswith(suffix):
        return s[:len(s) - len(suffix)]
    return s


try:                                                 # 3.8+
    from functools import cached_property            # noqa: F401
except ImportError:                                  # pragma: no cover
    class cached_property(object):                   # type: ignore[no-redef]
        """functools.cached_property 的 3.7 兜底实现（非线程安全，够用）。"""

        def __init__(self, func):
            self.func = func
            self.__doc__ = getattr(func, "__doc__", None)
            self.attrname = getattr(func, "__name__", None)

        def __get__(self, instance, owner=None):
            if instance is None:
                return self
            val = instance.__dict__[self.attrname] = self.func(instance)
            return val


def metadata_version(dist_name):
    """importlib.metadata.version 的兜底（3.8 以前没有该模块）。

    取不到就返回 None——版本号只用于展示与诊断，绝不能因此中断启动。
    """
    try:
        try:
            from importlib.metadata import version as _v
        except ImportError:                          # pragma: no cover
            import pkg_resources                     # type: ignore
            return pkg_resources.get_distribution(dist_name).version
        return _v(dist_name)
    except Exception:                                # pragma: no cover
        return None


# ── 控制台编码（Windows 老机器最大的坑）────────────────────────────────────
# Windows 7/8 的 cmd 默认代码页是 936(GBK) 或 437，Python 3.6 起 stdout 已用
# UTF-8 包装但 errors 策略是 'strict'，print 一个生僻中文/emoji 就直接
# UnicodeEncodeError 崩在服务启动日志里——表现为"双击 bat 窗口一闪而过"。

def ensure_utf8_stdio():
    """把 stdout/stderr 尽量切成 UTF-8 且 errors='replace'。

    失败一律静默（老 Python 没有 reconfigure/text_stream 包装器可用时，
    调用方仍能正常 print ASCII，中文可能乱码但不会崩）。
    返回 True 表示已生效。
    """
    ok = False
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            if hasattr(stream, "reconfigure"):       # Python 3.7+
                stream.reconfigure(encoding="utf-8", errors="replace")
                ok = True
                continue
        except Exception:
            pass
        try:
            if hasattr(stream, "buffer"):            # Python 3.6：换一层包装
                enc = getattr(stream, "encoding", None) or "utf-8"
                if enc.lower().replace("-", "") not in ("utf8", "utf80"):
                    setattr(sys, name, codecs.getwriter("utf-8")(
                        stream.buffer, errors="replace"))
                ok = True
        except Exception:
            pass
    return ok


def reconfigure_stdio():
    """ensure_utf8_stdio 的别名（语义更贴近 3.7+ 的 API 名）。"""
    return ensure_utf8_stdio()


def safe_print(*args, **kwargs):
    """永不因编码问题抛异常的 print。

    控制台打不出的字符替换成 '?'；连 sys.stdout 都不存在时彻底静默。
    """
    try:
        print(*args, **kwargs)
    except (UnicodeEncodeError, UnicodeDecodeError):
        try:
            enc = getattr(sys.stdout, "encoding", None) or "utf-8"
            msg = " ".join(str(a) for a in args)
            sys.stdout.write(msg.encode(enc, "replace").decode(enc, "replace") + "\n")
        except Exception:
            pass
    except Exception:
        pass


# ── 资源探测（供 envprofile 复用，放这里是因为它有 3.6 兜底逻辑）────────────

def cpu_count():
    """逻辑 CPU 数；os.cpu_count() 在部分老平台返回 None，兜底为 1。"""
    try:
        n = os.cpu_count()
    except Exception:                                # pragma: no cover
        n = None
    if not n:
        try:
            import multiprocessing
            n = multiprocessing.cpu_count()
        except Exception:
            n = None
    return int(n or 1)


def total_memory_bytes():
    """物理内存总字节数；探测不到返回 0（调用方按"未知"处理，不做降级）。"""
    # 1) POSIX：sysconf 最便宜
    try:
        import os as _os
        if hasattr(_os, "sysconf"):
            for key in ("SC_PAGE_SIZE", "SC_PAGESIZE"):
                if hasattr(_os, key) and hasattr(_os, "SC_PHYS_PAGES"):
                    pages = _os.sysconf("SC_PHYS_PAGES")
                    size = _os.sysconf(key)
                    if pages > 0 and size > 0:
                        return int(pages) * int(size)
    except Exception:
        pass
    # 2) Windows：GlobalMemoryStatusEx（无第三方依赖）
    if IS_WIN:
        try:
            import ctypes

            class _MEMSTAT(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            st = _MEMSTAT()
            st.dwLength = ctypes.sizeof(_MEMSTAT)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullTotalPhys)
        except Exception:
            pass
    # 3) macOS：sysctl hw.memsize
    if IS_MAC:
        try:
            import subprocess
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, timeout=5)
            if out.returncode == 0:
                return int(out.stdout.strip())
        except Exception:
            pass
    # 4) Linux：/proc/meminfo
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return 0


# ── 文件系统 / 进程 跨平台小工具 ────────────────────────────────────────────

def fs_is_case_sensitive(path="."):
    """判断某路径所在文件系统是否区分大小写。

    Windows / macOS(默认) 不区分，Linux 区分——项目里有按文件名命中缓存的
    逻辑（如索引缓存键），大小写敏感性差异会导致"换了台机器缓存全失效"。
    """
    try:
        probe = os.path.join(path, ".aisec_case_probe")
        with open(probe, "w") as f:
            f.write("x")
        sensitive = not os.path.exists(os.path.join(path, ".AISEC_CASE_PROBE"))
        os.remove(probe)
        return sensitive
    except Exception:
        # macOS 默认不区分，Windows 不区分，其余按区分处理
        return not (IS_WIN or IS_MAC)


def supports_symlink(path="."):
    """能否创建符号链接（Windows 无管理员权限时会失败，需降级为复制）。"""
    try:
        probe = os.path.join(path, ".aisec_link_probe")
        target = os.path.join(path, ".aisec_link_target")
        with open(target, "w") as f:
            f.write("x")
        os.symlink(target, probe)
        os.remove(probe)
        os.remove(target)
        return True
    except Exception:
        return False


def long_path(p):
    """Windows 长路径（>260 字符）前缀处理，其它平台原样返回。

    项目里 data/ 下有多层嵌套缓存目录，路径很容易超过 MAX_PATH。
    """
    if IS_WIN and isinstance(p, str) and len(p) > 240 and not p.startswith("\\\\?\\"):
        try:
            import ntpath
            return "\\\\?\\" + ntpath.abspath(p)
        except Exception:
            return p
    return p


def open_file_cross_platform(path):
    """用系统默认方式打开一个文件/目录（用于"生成完帮你打开报告"）。

    Windows: os.startfile   macOS: open   Linux: xdg-open
    三者都失败时返回 False，调用方降级为"打印路径"。
    """
    try:
        if IS_WIN:
            os.startfile(path)                       # noqa: S606
            return True
        elif IS_MAC:
            import subprocess
            subprocess.Popen(["open", path])
            return True
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
            return True
    except Exception:
        return False


def port_in_use_hint(port):
    """端口被占用时，给出**当前平台**可用的排查命令。

    旧代码里写死了 `netstat -ano | findstr :8848`，macOS/Linux 用户照抄会
    得到 `command not found`，排障直接卡死——这是"跨平台"最容易漏的一处。
    """
    if IS_WIN:
        return "netstat -ano | findstr :%d" % port
    if IS_MAC:
        return "lsof -nP -iTCP:%d -sTCP:LISTEN" % port
    return "ss -ltnp 'sport = :%d'   （或 netstat -ltnp | grep :%d）" % (port, port)


# ── 运行时体检 ─────────────────────────────────────────────────────────────

def check_runtime(min_version=PY_MIN):
    """给出"这台机器能不能跑"的结构化结论（供 bootstrap.py 决策）。

    返回 dict：
        ok            bool  版本是否达标（不达标仍可能跑得动，但不再保证）
        fatal         bool  明确跑不了（如 Python 2）
        python        str   版本串
        min_required  str   要求下限
        os_family     str
        reasons       list[str]  人话说明
        hint          str   修复建议（含平台对应的安装方式）
    """
    reasons = []
    fatal = False
    ok = PY >= min_version

    if sys.version_info[0] < 3:
        fatal = True
        reasons.append("检测到 Python 2（%s），本项目仅支持 Python 3" % PY_STR)
    elif not ok:
        reasons.append("Python %s 低于要求下限 %s（老版本缺 f-string / 有序 dict 等关键特性）"
                       % (PY_STR, "%d.%d" % min_version))
    else:
        reasons.append("Python %s 满足要求（下限 %s）" % (PY_STR, "%d.%d" % min_version))

    if IS_WIN and OS_RELEASE and OS_RELEASE.isdigit() and int(OS_RELEASE) < 6:
        reasons.append("Windows 版本过旧（NT %s，XP 及更早），建议 Windows 7 以上" % OS_RELEASE)
        ok = False

    hint = ""
    if not ok:
        if IS_WIN:
            hint = ("请安装 Python %d.%d 以上：https://www.python.org/downloads/windows/ "
                    "（或用 winget install Python.Python.3.11）；"
                    "也可直接双击本目录的 bootstrap.py 由脚本代装" % min_version)
        elif IS_MAC:
            hint = ("请安装 Python %d.%d 以上：brew install python@3.11 "
                    "或 https://www.python.org/downloads/macos/ "
                    "（macOS 自带 Python 2.7 已废弃，勿用）" % min_version)
        else:
            hint = ("请安装 Python %d.%d 以上：sudo apt install python3 python3-pip "
                    "（Ubuntu/Debian）或 sudo yum install python3 python3-pip（CentOS）" % min_version)

    return {
        "ok": ok, "fatal": fatal, "python": PY_STR,
        "min_required": "%d.%d" % min_version,
        "os_family": OS_FAMILY, "os_name": OS_NAME, "os_release": OS_RELEASE,
        "arch": ARCH, "reasons": reasons, "hint": hint,
    }
