@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.1 —— 一键下载「本地免费嵌入模型」（语义召回用）
rem
rem  multilingual-e5-small，约 450 MB，一次性；ModelScope 镜像直连（不依赖代理）。
rem  下完之后语义检索全在本机 CPU 上进行：
rem    · 不花 token、不消耗任何 API 额度（零成本）
rem    · 数据不出本机（不发给任何第三方云端）
rem    · 断网也能用（离线演示可做语义检索）
rem  中断了重跑也没关系：会续传、已下好的文件跳过。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost
echo [AI-SecIntel] 正在下载本地免费嵌入模型 multilingual-e5-small（约 450 MB，支持断点续传）...
echo.
py -3.13 -u modules\m3_qa\backend\qa\local_embedder.py --download
if errorlevel 9009 (
  echo [!] 没找到 py -3.13，改用默认 python ...
  python -u modules\m3_qa\backend\qa\local_embedder.py --download
)
echo.
echo [AI-SecIntel] 下完可以自检一句（应输出 384 维编码，耗时几秒）：
echo     py -3.13 modules\m3_qa\backend\qa\local_embedder.py
echo.
pause
