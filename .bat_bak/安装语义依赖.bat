@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.1 —— 一键安装「语义检索 + 本地翻译」依赖
rem
rem  装上之后：
rem    ① 语义召回 / 混合检索（/api/hybrid_search）开箱可用
rem    ② 本地免费翻译（页面「译」按钮）开箱可用，零 token、正文不出本机
rem  模型文件：data\models\multilingual-e5-small 与 %AISEC_MT_MODEL_DIR%
rem            未随包附带时，分别双击「下载嵌入模型.bat」「下载翻译模型.bat」。
rem  没装这些依赖也不影响主体运行 —— 问答降级为纯关键词检索，翻译按钮空转。
rem
rem  ★ 必须装进「项目 .venv」，不能装到系统 Python。
rem    原因：「启动服务.bat」按能力挑解释器，装在系统 Python 里的话，
rem    服务挑的 .venv 依然缺 torch → 翻译永远不可用且**不报错**。
rem    这个坑已经踩过一次：依赖装成功、功能依然不工作。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1

rem ── 1. 选定目标解释器：有 .venv 就装 .venv，否则建一个 ──────────────
set "PYEXE="
if exist ".venv\Scripts\python.exe" set "PYEXE=.venv\Scripts\python.exe"
if not defined PYEXE (
    echo [AI-SecIntel] 未找到 .venv，正在创建...
    where py >nul 2>nul && ( py -3 -m venv .venv ) || ( python -m venv .venv )
    if exist ".venv\Scripts\python.exe" set "PYEXE=.venv\Scripts\python.exe"
)
if not defined PYEXE (
    echo [!] 无法创建 .venv。请先双击「安装.bat」完成基础安装。
    pause
    exit /b 1
)
echo [AI-SecIntel] 目标解释器：%PYEXE%
%PYEXE% -c "import sys;print('   Python %d.%d.%d' % sys.version_info[:3])"
echo.

rem ── 2. 先补 openpyxl：不装的话报告导出 xlsx 是**功能报错**而非优雅降级 ──
%PYEXE% -c "import openpyxl" >nul 2>nul
if errorlevel 1 (
    echo [1/3] 装 openpyxl（报告导出 xlsx 依赖）...
    %PYEXE% -m pip install --disable-pip-version-check openpyxl
) else (
    echo [1/3] openpyxl 已有，跳过。
)
echo.

rem ── 3. torch CPU 版 + transformers + sentencepiece + sacremoses ──────
rem     sacremoses 是 MarianTokenizer 的必需依赖，缺了它
rem     MarianTokenizer 初始化就报 "requires the sacremoses library"，
rem     表现为翻译永远 ready:false。
echo [2/3] 装 torch（CPU 版，约 130 MB）...
%PYEXE% -m pip install --disable-pip-version-check torch --index-url https://download.pytorch.org/whl/cpu
if errorlevel 1 (
    echo [!] torch 安装失败。若是网络问题，可改用国内源重试：
    echo     %PYEXE% -m pip install torch -i https://pypi.tuna.tsinghua.edu.cn/simple
) else (
    echo [3/3] 装 transformers / sentencepiece / sacremoses ...
    %PYEXE% -m pip install --disable-pip-version-check transformers sentencepiece sacremoses
)

echo.
echo [AI-SecIntel] 依赖安装结束，自检如下：
%PYEXE% -c "import importlib;[print(('  OK   ' if importlib.util.find_spec(m) else '  缺   ')+m) for m in ('torch','transformers','sentencepiece','sacremoses','openpyxl','numpy')]" 2>nul
echo.
echo [AI-SecIntel] 下一步：
echo     ① 若「翻译」不可用  → 双击「下载翻译模型.bat」  （约 300 MB，一次性）
echo     ② 若「语义检索」不可用 → 双击「下载嵌入模型.bat」（约 450 MB，一次性）
echo     ③ 然后重新双击「启动服务.bat」（改了解释器选择，必须重启才生效）。
echo.
pause
