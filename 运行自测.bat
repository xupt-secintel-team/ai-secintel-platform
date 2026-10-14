@echo off
cd /d "%~dp0"
rem ============================================================
rem  端到端自测（需先启动服务）：默认 8848，可传端口：运行自测.bat 8899
rem  覆盖：接口连通、检索、可信度、图谱、导出、问答、实时监测、
rem        归档体量、模块注册表、模块 1/2/3 自有接口
rem
rem  ★ 2026-10-09 可移植性修复：原来写死 `py -3.13` + `if errorlevel 9009`
rem    兜底；别人机器上是 3.11/3.12/3.14 时失败码不是 9009，兜底不触发。
rem    改为统一走 tools\_选解释器.bat。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost
set PORT=%1
if "%PORT%"=="" set PORT=8848
echo [AI-SecIntel] 自测目标端口：%PORT%

call "%~dp0tools\_选解释器.bat"
if not defined PYEXE (
    echo.
    pause
    exit /b 1
)

%PYEXE% -u core\self_test.py %PORT%
echo.
pause
