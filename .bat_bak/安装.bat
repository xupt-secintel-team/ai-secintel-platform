@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 · 一键安装（Windows）
rem  ------------------------------------------------------------
rem  双击即可完成：
rem    ① Python 版本体检   ② 建虚拟环境 .venv
rem    ③ 自动选最快软件源 ④ 按机器档位装依赖
rem    ⑤ 安装后自检       ⑥ 生成 .aisec_env.json
rem
rem  命令行可选参数（在此文件上右键→编辑可改，或另开 cmd 运行 bootstrap.py）：
rem    安装.bat --full       连 torch / transformers 一起装（约 700MB）
rem    安装.bat --no-venv    装进系统 Python，不建虚拟环境
rem    安装.bat --offline    离线：只检测，不联网
rem ============================================================
setlocal enabledelayedexpansion
set PYTHONDONTWRITEBYTECODE=1

echo.
echo  ============================================================
echo    AI-SecIntel 2.0  ^|  一键安装
echo  ============================================================
echo.

rem ── 0. 找一个能用的 Python ────────────────────────────────────────────
set "PYEXE="
for %%P in ("py -3" "python" "python3") do (
    if not defined PYEXE (
        %%~P -c "import sys;sys.exit(0 if sys.version_info[:2]>=(3,7) else 1)" >nul 2>nul
        if !errorlevel!==0 set "PYEXE=%%~P"
    )
)
if not defined PYEXE (
    for %%P in ("py" ) do (
        if not defined PYEXE (
            %%~P -c "import sys;sys.exit(0 if sys.version_info[:2]>=(3,7) else 1)" >nul 2>nul
            if !errorlevel!==0 set "PYEXE=%%~P"
        )
    )
)

if not defined PYEXE (
    echo  [!] 没有找到 Python 3.7 及以上版本。
    echo.
    echo      请任选一种方式安装后，重新双击本文件：
    echo        1^) 官网下载： https://www.python.org/downloads/windows/
    echo           ^（安装时务必勾选 "Add Python to PATH"^)
    echo        2^) 命令行：   winget install Python.Python.3.11
    echo        3^) 应用商店： Microsoft Store 搜索 Python 3.11
    echo.
    pause
    exit /b 1
)

echo  [i] 使用解释器：%PYEXE%
echo.

rem ── 1. 交给 bootstrap.py 做体检 → 建环境 → 装依赖 → 自检 ──────────────
%PYEXE% bootstrap.py %*
set RC=%errorlevel%

echo.
if "%RC%"=="0" (
    echo  ============================================================
    echo    安装完成。下一步：双击「启动服务.bat」打开控制台
    echo  ============================================================
) else if "%RC%"=="2" (
    echo  ============================================================
    echo    Python 版本不达标，请先安装 Python 3.7+ 后重试
    echo  ============================================================
) else (
    echo  ============================================================
    echo    安装未完全成功，但系统可在降级模式下运行。
    echo    仍可直接双击「启动服务.bat」；要完整能力请手动执行：
    echo        pip install -r requirements.txt
    echo  ============================================================
)
echo.
pause
exit /b %RC%
