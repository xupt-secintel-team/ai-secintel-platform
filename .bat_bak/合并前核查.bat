@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  合并/替换模块前的「防阉割」一致性核查：
rem    接口路由 · 源码文件 · 函数级 · 数据文件 · 前端函数
rem  基线自动探测（环境变量 AISEC_BASELINE_DIR → 同级目录 aisec-D_*），也可显式给：
rem    合并前核查.bat --baseline ..\aisec-D_1.2\aisec-D_1.2
rem    合并前核查.bat --live http://127.0.0.1:8848     （服务在跑时更权威）
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
py -3.13 -u tools\verify_integrity.py %*
if errorlevel 9009 python -u tools\verify_integrity.py %*
echo.
pause
