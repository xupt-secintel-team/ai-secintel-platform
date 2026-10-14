@echo off
rem ============================================================
rem  _选解释器.bat —— 统一的「找一个真能跑的 Python」（被其它 bat 调用）
rem
rem  用法（在调用方 bat 里）：
rem      call "%~dp0tools\_选解释器.bat"
rem      if not defined PYEXE (
rem          echo [!] 没有可用的 Python，已中止。
rem          pause
rem          exit /b 1
rem      )
rem      %PYEXE% -u 你的脚本.py
rem
rem  为什么单列一个文件：以前每个 bat 各写各的候选，于是同一类问题
rem  反复出现，且修一个漏一个：
rem    ① 有的写死 py -3.13 —— 别人机器上装的是 3.11/3.12/3.14，
rem       该命令直接失败，而且失败码不是 9009，`if errorlevel 9009`
rem       的兜底根本不会触发；
rem    ② 有的写死本机路径 D:\python\python.exe —— 别人压根没这个目录；
rem    ③ 运行CI.bat 甚至写死了 WorkBuddy 自带 Python 的**版本号路径**
rem       （%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\...），
rem       WorkBuddy 一升级、或换台没装 WorkBuddy 的机器就找不到。
rem  统一到这里，只有一处需要维护。
rem
rem  ★ 判据是「能不能跑起来」，不是「文件在不在」：
rem    .venv 从别的机器整个拷过来时，pyvenv.cfg 里记的是**原机器**的
rem    解释器绝对路径 —— if exist 会通过，一执行立刻失败，报错还很难懂。
rem    所以每个候选都必须真的跑一次 -c "print(1)" 才算数。
rem
rem  候选顺序：AISEC_PYTHON（手工强制）→ 项目 .venv → py → python → python3
rem  结果写进环境变量 PYEXE（本文件**不使用 setlocal**，这样值留在
rem  调用方的作用域里，call 返回后就能用）。
rem  找不到时打印指引并 exit /b 1（PYEXE 保持未定义，调用方据此判断）。
rem ============================================================
set "PYEXE="

rem ── 1. 手工强制（排障用）：set AISEC_PYTHON=C:\路径\python.exe ──────
if defined AISEC_PYTHON (
    "%AISEC_PYTHON%" -c "print(1)" >nul 2>nul && set PYEXE="%AISEC_PYTHON%"
)

rem ── 2. 项目自带的 .venv（依赖最可能齐）─────────────────────────────
rem    相对路径，跟着项目走；换机器只要重新双击「安装.bat」即可。
if not defined PYEXE if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "print(1)" >nul 2>nul && set "PYEXE=.venv\Scripts\python.exe"
)

rem ── 3. 系统里「到处都可能有」的候选 ───────────────────────────────
rem    ★ 必须用 for %%I：列表项都是**裸命令名**，%%I 会跳过不存在的
rem      可执行文件；用 for %%P 不跳过，拿一个不存在的路径去试就会报
rem      `did not find executable at ...`（实测踩过，见启动服务.bat 注释）。
rem    ★ 不写 py -3.13：别人机器上装的可能是 3.11 / 3.12 / 3.14。
if not defined PYEXE (
    for %%I in (py -3 python python3) do if not defined PYEXE (
        %%~I -c "print(1)" >nul 2>nul && set "PYEXE=%%~I"
    )
)

if not defined PYEXE (
    echo [!] 没有找到可用的 Python 3（需要 3.7 及以上）。
    echo.
    echo     安装方式任选其一，装完重新双击本脚本：
    echo       1^) 官网下载： https://www.python.org/downloads/windows/
    echo          ^（安装时务必勾选 "Add Python to PATH"^)
    echo       2^) 命令行：   winget install Python.Python.3.11
    echo       3^) 或先双击「安装.bat」，它会引导建立项目 .venv
    echo.
    exit /b 1
)
exit /b 0
