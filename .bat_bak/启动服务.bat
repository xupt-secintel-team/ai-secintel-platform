@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 一键启动（主体 + modules/ 下的全部模块）
rem  端口/数据目录/模块开关都在 config.json 里；也可命令行覆盖：
rem      启动服务.bat 8899            换端口
rem      启动服务.bat --no-live       不起 15s 实时监测线程
rem      启动服务.bat --no-modules    只起主体（排障用）
rem      启动服务.bat --low           强制低配档（慢机器 / 评审用笔记本）
rem
rem  首次运行会自动配置环境（建 .venv + 装依赖）；也可先双击「安装.bat」
rem  密钥/代理：双击「设置密钥.bat」填一次，之后本脚本自动读取 secrets.env
rem ============================================================
setlocal enabledelayedexpansion
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost

rem ── 0. 性能档位开关（--low / --mid / --high）──────────────────────────
rem    慢机器上自动降档已由 core/envprofile.py 完成；这里是手工强制覆盖，
rem    用于"评审现场临时降档"或"本机明明高配但想省资源"两种场景。
set "SRV_ARGS="
for %%A in (%*) do (
    if /i "%%A"=="--low"  (set "AISEC_PERF_TIER=low"  & echo [AI-SecIntel] 已强制低配档（慢机器友好）)
    if /i "%%A"=="--mid"  (set "AISEC_PERF_TIER=mid"  & echo [AI-SecIntel] 已强制中配档)
    if /i "%%A"=="--high" (set "AISEC_PERF_TIER=high" & echo [AI-SecIntel] 已强制高配档)
    if /i "%%A"=="--setup" (set "ONLY_SETUP=1")
)

rem ── 1. 首次运行：自动配置环境 ─────────────────────────────────────────
rem    判据：既没有 .venv 也没有 .aisec_env.json（由 bootstrap.py 生成）。
rem    之后每次启动不再重复配置，直接走启动流程。
if not exist ".venv\Scripts\python.exe" if not exist ".aisec_env.json" (
    echo [AI-SecIntel] 首次运行：开始自动配置环境（约 1-3 分钟，视网速而定）...
    echo.
    set "BOOT_PY="
    for %%P in ("py -3" "python" "python3") do if not defined BOOT_PY (
        %%~P -c "import sys;sys.exit(0 if sys.version_info[:2]>=(3,7) else 1)" >nul 2>nul
        if !errorlevel!==0 set "BOOT_PY=%%~P"
    )
    if defined BOOT_PY (
        !BOOT_PY! bootstrap.py
    ) else (
        echo [!] 未找到 Python 3.7+，跳过自动配置。请先安装： https://www.python.org/downloads/windows/
    )
    echo.
)

rem ── 2. 解释器选择：**能力感知**，不再无条件优先 .venv ──
rem    本机往往并存多个 Python。此前是「只要 .venv 存在就用它」，
rem    而 .venv 里往往只有 numpy + openpyxl（torch/transformers 装在
rem    另一个解释器里）→ 本地翻译永远 ready:false，页面上「译」点了没反应，
rem    而且**没有任何报错**。现在改成按能力挑，并如实告诉用户选了谁、缺什么。
rem    要强制指定就先给环境变量 AISEC_PYTHON（set AISEC_PYTHON=D:\python\python.exe）。
set "PYEXE="
if defined AISEC_PYTHON (
  "%AISEC_PYTHON%" -c "import numpy" >nul 2>nul && set "PYEXE=%AISEC_PYTHON%"
)
rem 2a 先在 .venv 里试「全栈」（numpy + openpyxl + 翻译四件套），全了就用它
if not defined PYEXE if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import numpy, openpyxl, torch, transformers, sentencepiece, sacremoses" >nul 2>nul && set "PYEXE=.venv\Scripts\python.exe"
)
rem 2b 否则在候选里挑第一个 numpy + torch 都有的
if not defined PYEXE (
  for %%P in (".venv\Scripts\python.exe" "D:\python\python.exe" "py -3.13" "python") do if not defined PYEXE %%~P -c "import numpy, torch" >nul 2>nul && set "PYEXE=%%~P"
)
rem 2c 再退到「只有 numpy 也认」（缺 torch 只是翻译/语义降级，不该不让启动）
if not defined PYEXE (
  for %%P in (".venv\Scripts\python.exe" "D:\python\python.exe" "py -3.13" "python") do if not defined PYEXE %%~P -c "import numpy" >nul 2>nul && set "PYEXE=%%~P"
)
if not defined PYEXE set "PYEXE=python"
if not defined PYEXE (
  echo [!] 未找到可用的 Python，请先安装 Python 3.7+： https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

rem 2d 如实说明选了谁 + 缺什么。这段不能省：翻译不工作是**静默**的
rem    （接口返回 ready:false + 原文照抄），不给提示用户只会觉得"翻译坏了"。
set "PYDESC="
%PYEXE% -c "import sys;print('Python %d.%d.%d' %% sys.version_info[:3])" >nul 2>nul && set "PYDESC=已探测"
%PYEXE% -c "import torch" >nul 2>nul || set "PYDESC=!PYDESC! 缺torch"
%PYEXE% -c "import transformers, sentencepiece" >nul 2>nul || set "PYDESC=!PYDESC! 缺transformers/sentencepiece"
%PYEXE% -c "import openpyxl" >nul 2>nul || set "PYDESC=!PYDESC! 缺openpyxl(报告导出xlsx会报错)"
echo [i] 本次解释器：%PYEXE%  !PYDESC!
if not "!PYDESC:缺=torch=!"=="!PYDESC!" (
  echo [!] 当前解释器缺 torch / transformers / sentencepiece —— **本地翻译与语义检索会不可用**。
  echo [!] 修复：双击「安装语义依赖.bat」（它会装进本项目 .venv，与本脚本选择一致）。
  echo [!] 若仍不通：set AISEC_PYTHON=指向装了 torch 的解释器，再双击本脚本。
)

rem ── 3. 打印环境画像：让"这台机器按什么档位跑"变成开机可见的信息 ──────
%PYEXE% core\envprofile.py 2>nul
echo.

rem ── 4. 依赖自检（只提示，缺依赖会说明降级行为，不阻断启动）
%PYEXE% tools\检查依赖.py 2>nul
if errorlevel 9009 (
  set "PYEXE=python"
  python tools\检查依赖.py
)

if defined ONLY_SETUP (
    echo [AI-SecIntel] --setup：只做环境配置，不启动服务。
    pause
    exit /b 0
)

rem ── 5. 读取本机 secrets.env（密钥 / 代理；该文件已被 .gitignore 排除，不进仓库）
rem    每行形如 NAME=value（不写 set 前缀、不加引号），支持 # 注释与空行
if exist "%~dp0secrets.env" (
  for /f "usebackq tokens=1,* delims==" %%A in (`findstr /v "^#" "%~dp0secrets.env"`) do (
    if not "%%A"=="" if not "%%B"=="" set "%%A=%%B"
  )
  echo [AI-SecIntel] 已加载本机 secrets.env（密钥 / 代理）
) else (
  echo [AI-SecIntel] 未发现 secrets.env —— 问答将以「检索证据模板」模式运行
  echo                （要开自然语言答案 / POC 提速：双击「设置密钥.bat」填一次）
)

rem ── 6. 代理：由 core\net.py 在运行时自动发现，不再硬编码端口 ──────────
rem    本机代理端口会漂（7890 / 33252 / 2484 / 6759 都出现过），bat 里写死必然漏判。
if defined AISEC_PROXY (
  echo [AI-SecIntel] 代理：%AISEC_PROXY% （手动指定）
) else (
  echo [AI-SecIntel] 代理：由程序自动探测（环境变量 ^|^| 本机监听端口），无需手工配置
)

rem ── 7. 配置自检：只报「有没有」，绝不打印密钥值 ───────────────────────
if defined AISEC_LLM_API_KEY (
  echo [AI-SecIntel] 大模型：已配置（模型 %AISEC_LLM_MODEL%，接口 %AISEC_LLM_BASE_URL%）
) else (
  echo [AI-SecIntel] 大模型：未配置 —— 问答走检索证据模板（配了就有自然语言答案）
)
if defined AISEC_GITHUB_TOKEN echo [AI-SecIntel] GitHub Token：已配置（POC 搜索速率 30/分钟）

echo [AI-SecIntel] 正在启动：主体 core/server.py + 全部模块 ...
echo [AI-SecIntel] 本窗口就是实时日志；想把日志落盘留证：py -3.13 tools\_run_server_logged.py 8848
echo [AI-SecIntel] 解释器：%PYEXE%

rem ── 8. 收集真正传给 server.py 的参数（剔除本脚本自己的 --low/--mid/--high/--setup）
for %%A in (%*) do (
    if /i not "%%A"=="--low" if /i not "%%A"=="--mid" if /i not "%%A"=="--high" if /i not "%%A"=="--setup" (
        set "SRV_ARGS=!SRV_ARGS! %%A"
    )
)

%PYEXE% -u core\server.py %SRV_ARGS%
if errorlevel 9009 (
  echo [!] %PYEXE% 不可用，改用默认 python 启动（若此时缺 numpy/torch，语义检索会降级为纯关键词） ...
  python -u core\server.py %SRV_ARGS%
)
echo.
echo [AI-SecIntel] 已退出。
pause
