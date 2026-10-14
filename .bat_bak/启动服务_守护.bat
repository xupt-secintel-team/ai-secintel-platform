@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.2 守护启动（watchdog：单实例锁 + 崩溃自愈 + 卡死重启）
rem  与「启动服务.bat」的区别：服务由 tools/watchdog.py 守护——
rem    · 崩溃自动拉起（5s/15s/60s 退避，每小时最多 10 次）
rem    · 每 30s 探活，连续 3 次不应答判卡死并重启
rem    · 同端口已有存活守护进程时拒绝二开（防实例叠加）
rem  留痕：测试报告/watchdog_<端口>.log + 运行日志_<端口>.log
rem  用法：启动服务_守护.bat           （默认 8848）
rem        启动服务_守护.bat 8899      （换端口）
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost

echo [AI-SecIntel] 守护模式启动（Ctrl+C 会一并停止服务）

rem ---------- 解释器：必须与「启动服务.bat」同一套能力感知逻辑 ----------
rem   ★ 关键：tools/watchdog.py 用 sys.executable 拉起服务进程，
rem     所以**这里选谁，就决定了服务跑在哪个解释器上**。
rem     此前首选 py -3.13（本机根本没装，必然先报一句"命令不存在"），
rem     回落时可能落到没有 torch 的解释器 → 翻译功能静默失效。
set "PYEXE="
if defined AISEC_PYTHON (
  "%AISEC_PYTHON%" -c "import numpy" >nul 2>nul && set "PYEXE=%AISEC_PYTHON%"
)
if not defined PYEXE if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import numpy, openpyxl, torch, transformers, sentencepiece, sacremoses" >nul 2>nul && set "PYEXE=.venv\Scripts\python.exe"
)
if not defined PYEXE (
  for %%P in (".venv\Scripts\python.exe" "D:\python\python.exe" "py -3.13" "python") do if not defined PYEXE %%~P -c "import numpy, torch" >nul 2>nul && set "PYEXE=%%~P"
)
if not defined PYEXE (
  for %%P in (".venv\Scripts\python.exe" "D:\python\python.exe" "py -3.13" "python") do if not defined PYEXE %%~P -c "import numpy" >nul 2>nul && set "PYEXE=%%~P"
)
if not defined PYEXE set "PYEXE=python"
echo [AI-SecIntel] 守护解释器：%PYEXE%
%PYEXE% -c "import torch" >nul 2>nul || echo [!] 该解释器缺 torch —— 本地翻译 / 语义检索会不可用（双击「安装语义依赖.bat」）

%PYEXE% -u tools\watchdog.py %*
echo.
echo [AI-SecIntel] 守护已退出。
pause
