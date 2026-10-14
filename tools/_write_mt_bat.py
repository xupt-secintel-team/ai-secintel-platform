# -*- coding: utf-8 -*-
"""重写「下载翻译模型.bat」。

为什么用脚本写而不是直接编辑：该 bat 是 GBK（无 BOM），直接以 UTF-8 写入
会让 cmd 里的中文全部变乱码。这里统一按 GBK 落盘，写完再回读校验一次。

★★ 2026-10-09 起**默认拒绝运行**（真要跑必须显式加 --force）★★

原因：本文件里的 BAT 模板停留在 2026-10-03 的设计 —— 用**系统 Python** 装依赖、
下载模型。而这个设计在 2026-10-07 已被推翻：「下载翻译模型.bat」现在**必须**
装进**项目 .venv**，否则会出现"依赖装成功、翻译依然不可用且不报错"。
换句话说，直接运行本脚本会把交付包里那份正确的 bat **降级覆盖**成已知有缺陷的
版本 —— 这正是"别处改好了、这里又给改回去"的那类回归。
磁盘上的 bat 现在直接维护；编码问题统一交给 tools/_fix_bat_encoding.py。
保留本文件只为留存当时"为什么用脚本写 bat"的理由与做法。
"""
import io
import os
import sys

if "--force" not in sys.argv:
    print(__doc__)
    print("=" * 68)
    print("已阻止执行：本脚本的 bat 模板已过期（见上方说明）。")
    print("确实要覆盖「下载翻译模型.bat」的话，显式加参数：--force")
    print("=" * 68)
    raise SystemExit(0)

BAT = r'''@echo off
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 -- 一键下载「本地免费翻译模型」（英文情报 -> 中文）
rem
rem  约 300 MB，一次性；下完之后翻译全在本机 CPU 上进行：
rem    - 不花 token、不消耗任何 API 额度（零成本）
rem    - 正文不出本机（不发给任何第三方云端）
rem    - 断网也能用（离线演示可翻）
rem  中断了重跑也没关系：会续传，已下好的文件自动跳过。
rem
rem  修正记录（2026-10-03）：
rem   1) 原脚本首选 py -3.13，但本机压根没装 py 启动器（实测 py NOT FOUND），
rem      双击后必然先报一句「命令不存在」再回落。改为先探测解释器再使用。
rem   2) 模型文件下完 != 能用：MarianMT 分词还需要 sentencepiece（+sacremoses），
rem      缺了它的表现是「已下载 300MB 但翻译不可用」——极像下载失败。
rem      因此下载前先补齐运行时依赖。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1
set NO_PROXY=127.0.0.1,localhost

rem ---------- 1) 选一个可用解释器 ----------
set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY (
  where python >nul 2>nul && set PY=python
)
if not defined PY (
  echo [!] 没找到 Python，请先安装 Python 并勾选 Add Python to PATH。
  pause
  exit /b 1
)
echo [AI-SecIntel] 解释器: %PY%
%PY% --version

rem ---------- 2) 补齐翻译运行时依赖 ----------
echo.
echo [1/3] 检查翻译运行时依赖（sentencepiece / sacremoses）...
%PY% -c "import sentencepiece, sacremoses" >nul 2>nul
if errorlevel 1 (
  echo       缺失，正在安装（约 2 MB）...
  %PY% -m pip install sentencepiece sacremoses
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
pause
'''

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DST = os.path.join(ROOT, "下载翻译模型.bat")

with io.open(DST, "w", encoding="gbk", newline="\r\n") as f:
    f.write(BAT)

# 回读校验：确认 cmd 能按 GBK 正常解析，且没有替换字符
with io.open(DST, "r", encoding="gbk") as f:
    back = f.read()
print("已写入:", DST)
print("字节数:", os.path.getsize(DST))
print("GBK 回读 OK:", "本地免费翻译模型" in back)
print("无替换字符:", "�" not in back)
print("含解释器探测:", "where py" in back)
print("含依赖安装:", "pip install sentencepiece" in back)
