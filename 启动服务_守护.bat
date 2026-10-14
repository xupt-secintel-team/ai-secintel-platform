@echo off
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
rem ★ 2026-10-07 可移植性修复（别人机器上实测）：
rem   原候选里写死了 "D:\python\python.exe"（本机专属路径，别人机器没这个
rem   目录 → 解释器一个都选不上 → 守护直接不启动）和 "py -3.13"（别人装的
rem   可能不是 3.13）。改为只用"到处都可能有"的候选，并用 for %%I
rem   （**会跳过不存在的可执行文件**，for %%P 不跳过，这正是
rem   `did not find executable at D:\python\python.exe` 的来源）。
rem   探测用 find_spec 而非 import —— `import torch` 单次就要 2.7 秒，
rem   这里原本要跑 4 次。
if not defined PYEXE if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import importlib.util as u,sys;sys.exit(0 if all(u.find_spec(m) for m in ['numpy','openpyxl','torch','transformers','sentencepiece','sacremoses']) else 1)" >nul 2>nul && set "PYEXE=.venv\Scripts\python.exe"
)
if not defined PYEXE (
  for %%I in (py -3 python python3) do if not defined PYEXE %%~I -c "import importlib.util as u,sys;sys.exit(0 if all(u.find_spec(m) for m in ['numpy','torch']) else 1)" >nul 2>nul && set "PYEXE=%%~I"
)
if not defined PYEXE (
  for %%I in (py -3 python python3) do if not defined PYEXE %%~I -c "import importlib.util as u,sys;sys.exit(0 if u.find_spec('numpy') else 1)" >nul 2>nul && set "PYEXE=%%~I"
)
if not defined PYEXE set "PYEXE=python"
rem 选定后验一次"能不能真跑"：.venv 从别的机器拷来时文件存在但跑不了
%PYEXE% -c "print(1)" >nul 2>nul
if errorlevel 1 (
  echo [!] 选中的解释器跑不起来：%PYEXE%
  echo [!] 若项目里有 .venv，多半是从别的机器整个拷过来的（内部记的是绝对路径）。
  echo [!] 删掉本项目的 .venv 文件夹后重新双击「安装.bat」即可。
  pause
  exit /b 1
)
echo [AI-SecIntel] 守护解释器：%PYEXE%
%PYEXE% tools\探测解释器.py 2>nul

%PYEXE% -u tools\watchdog.py %*
echo.
echo [AI-SecIntel] 守护已退出。
pause
