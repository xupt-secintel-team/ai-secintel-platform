@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  端到端自测（需先启动服务）：默认 8848，可传端口：运行自测.bat 8899
rem  覆盖：接口连通、检索、可信度、图谱、导出、问答、实时监测、
rem        归档体量、模块注册表、模块 1/2/3 自有接口
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost
set PORT=%1
if "%PORT%"=="" set PORT=8848
echo [AI-SecIntel] 自测目标端口：%PORT%
py -3.13 -u core\self_test.py %PORT%
if errorlevel 9009 python -u core\self_test.py %PORT%
echo.
pause
