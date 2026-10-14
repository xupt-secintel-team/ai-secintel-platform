@echo off
cd /d "%~dp0"
rem ============================================================
rem  合并/替换模块前的「防阉割」一致性核查：
rem    接口路由 · 源码文件 · 函数级 · 数据文件 · 前端函数
rem  基线自动探测（环境变量 AISEC_BASELINE_DIR → 同级目录 aisec-D_*），也可显式给：
rem    合并前核查.bat --baseline ..\aisec-D_1.2\aisec-D_1.2
rem    合并前核查.bat --live http://127.0.0.1:8848     （服务在跑时更权威）
rem
rem  ★ 2026-10-09 可移植性修复：原来写死 `py -3.13` + `if errorlevel 9009`
rem    兜底；别人机器上是 3.11/3.12/3.14 时失败码不是 9009，兜底不触发。
rem    改为统一走 tools\_选解释器.bat。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1

call "%~dp0tools\_选解释器.bat"
if not defined PYEXE (
    echo.
    pause
    exit /b 1
)

%PYEXE% -u tools\verify_integrity.py %*
echo.
pause
