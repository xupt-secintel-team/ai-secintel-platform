@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 -- 一键下载「本地免费翻译模型」（英文情报 -> 中文）
rem
rem 约 300 MB，一次性；下完之后翻译全在本机 CPU 上进行：
rem    - 不花 token、不消耗任何 API 额度（零成本）
rem    - 正文不出本机（不发给任何第三方云端）
rem    - 断网也能用（离线演示可翻）
rem  中断了重跑也没关系：会续传，已下好的文件自动跳过。
rem
rem 修正记录：
rem   2026-10-03 1) 原脚本首选 py -3.13，但本机压根没装 py 启动器，双击后
rem               必然先报「命令不存在」再回落。
rem   2026-10-07 2) ★ 解释器必须选**项目 .venv**。此前用的是系统 Python，
rem               而「启动服务.bat」挑的是 .venv —— 模型下载到 E:\models 了，
rem               服务那边却因为缺 torch/transformers 永远翻译不了。
rem               「装了却不能用」比「没装」更难查。
rem           3) sentencepiece + sacremoses 是 MarianTokenizer 的必需依赖，
rem               缺了表现是「已下载 300MB 但翻译不可用」，极像下载失败。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost

rem ---------- 1) 选解释器：优先项目 .venv（与服务一致），否则提示先装依赖 ----------
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (
  echo [!] 没找到项目 .venv。请先双击「安装.bat」，再双击「安装语义依赖.bat」。
  echo [!] 装到别的 Python 里没有用 —— 服务启动时挑的是 .venv。
  pause
  exit /b 1
)
echo [AI-SecIntel] 解释器: %PY%
%PY% --version

rem ---------- 2) 补齐翻译运行时依赖 ----------
echo.
echo [1/3] 检查翻译运行时依赖（torch / transformers / sentencepiece / sacremoses）...
%PY% -c "import torch, transformers, sentencepiece, sacremoses" >nul 2>nul
if errorlevel 1 (
  echo       缺失，正在安装（torch CPU 版约 130 MB，请耐心等待）...
  %PY% -m pip install --disable-pip-version-check torch --index-url https://download.pytorch.org/whl/cpu
  %PY% -m pip install --disable-pip-version-check transformers sentencepiece sacremoses
) else (
  echo       已就位，跳过
)

rem ---------- 3) 下载模型 ----------
echo.
echo [2/3] 正在下载本地免费翻译模型（约 300 MB，支持断点续传）...
%PY% -u modules\m3_qa\backend\qa\translator.py --download

rem ---------- 4) 自测一句 ----------
echo.
echo [3/3] 自测一句（应输出中文）：
%PY% modules\m3_qa\backend\qa\translator.py --text "Ollama allows remote code execution via a crafted GGUF model file."
echo.
echo 若上面译文是中文，说明本地免费翻译已可用（零成本、正文不出本机）。
echo 若仍是英文原文，请把上面这一段的输出发我 —— 那说明依赖或模型路径还有问题。
pause
