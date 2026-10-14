@echo off
rem 本地一键 CI：离线测试全量 + 前端组装校验 + 一致性核查
rem 用法：双击 运行CI.bat，或 python tools\运行CI.py

setlocal
rem ============================================================
rem  ★ 2026-10-09 可移植性修复（这一条以前没人测到，因为它不在 启动服务.bat 里）
rem
rem  原来这里写死：
rem      set PY="%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
rem      if not exist %PY% set PY=py -3.13
rem  两个问题：
rem    ① WorkBuddy 自带 Python 的**版本号**写死在路径里 —— WorkBuddy 一升级、
rem       或换台没装 WorkBuddy 的机器，这个路径就不存在；
rem    ② 兜底是 `py -3.13` —— 别人机器上是 3.11/3.12/3.14 时该命令直接失败，
rem       而它不在 `if errorlevel 9009` 的兜底范围内，CI 第一步就挂。
rem  现在统一走 tools\_选解释器.bat（候选 py -3 / python / python3 / 项目 .venv）。
rem ============================================================
call "%~dp0tools\_选解释器.bat"
if not defined PYEXE (
    echo.
    echo  [!] 未找到可用的 Python，CI 无法运行。
    pause
    exit /b 1
)
set "PY=%PYEXE%"

echo ============================================
echo   AI-SecIntel 本地 CI 全量自检
echo ============================================
echo   解释器：%PY%
echo.

echo [1/9] 后端离线测试（Python）
set FAIL=0
for %%f in (tools\_test_*.py) do (
  echo   == %%f ==
  %PY% %%f >nul 2>&1 || (echo   [FAIL] %%f & set FAIL=1)
)
if "%FAIL%"=="1" (echo   ^> 有后端测试失败 & goto :end) else (echo   ^> 后端测试全部通过)

echo.
echo [2/9] 前端桩测试（Node）
rem ★ 2026-10-09：node 不是本项目运行时的必需依赖（服务是 Python 的）。
rem   别人机器上没装 node 时，原来这里会一路刷 [FAIL]，把 CI 判红，
rem   但那是「环境缺件」不是「代码有问题」。改为**明确跳过并说明**。
where node >nul 2>nul
if errorlevel 1 (
  echo   [!] 未找到 node，跳过前端桩测试（不影响后端与产品运行）
  echo       ^> 想跑这一步：装 Node.js https://nodejs.org/ 后重跑本脚本
) else (
  set FAIL=0
  for %%f in (tools\_test_*.js) do (
    echo   == %%f ==
    node %%f >nul 2>&1 || (echo   [FAIL] %%f & set FAIL=1)
  )
  if "%FAIL%"=="1" (echo   ^> 有前端测试失败 & goto :end) else (echo   ^> 前端测试全部通过)
)

echo.
echo [3/9] 前端组装一致性校验
%PY% tools\组装前端.py --check >nul 2>&1
if errorlevel 1 (echo   ^> 组装不一致（请先跑 组装前端.py） & goto :end) else (echo   ^> 组装一致)

echo.
echo [4/9] 语法编译检查（core + modules）
%PY% -m compileall -q core modules >nul 2>&1
if errorlevel 1 (echo   ^> 存在语法错误 & goto :end) else (echo   ^> 语法检查通过)

echo.
echo [5/9] 前端可读性检查（对比度 + 变量存在性）
rem 2026-07-07 加：用户报"前端有些部件看不清"，根因是①引用了不存在的
rem CSS 变量（--txt-1，项目里只有 --txt）②拿文字色 --accent-3 当按钮底色，
rem 亮色主题下白字 ratio 只有 2.11。两类问题**浏览器都不报错**，只能靠算。
%PY% tools\检查对比度.py >nul 2>&1
if errorlevel 1 (echo   ^> 存在看不清的部件（跑 tools\检查对比度.py 看详情） & goto :end) else (echo   ^> 对比度达标)

echo.
echo [6/9] 交付可移植性检查（别人机器上能不能跑）
rem 2026-10-07 加：发给别人测时才暴露的 4 个问题 —— bat 写死本机路径
rem D:\python\python.exe、写死 py -3.13、.venv 跨机不可移植却被 if exist 放过、
rem config.json 的 port 被填成中文说明导致 int() 崩溃。**本地全绿也抓不到。**
rem 2026-10-09 扩：本测试原**只查 启动服务.bat**，于是 设置密钥/运行自测/
rem 合并前核查/下载嵌入模型/运行CI 这 5 个 bat 里的 py -3.13 全部漏检。
rem 现已改为扫描全部根 bat + tools bat，并新增两项断言。
%PY% tools\_test_portability.py >nul 2>&1
if errorlevel 1 (echo   ^> 可移植性问题（跑 tools\_test_portability.py 看详情） & goto :end) else (echo   ^> 可移植性通过)

echo.
echo [7/9] 批处理编码检查（应 GBK 无 BOM，UTF-8 BOM 会被当命令前缀）
rem 2026-10-07 实测证伪：cmd 解析 bat 永远按系统 ANSI(GBK)，不看 BOM。
rem 加 UTF-8 BOM 反而让 BOM 字节(锘緻)和 @echo off 连成一条命令被当命令执行。
rem 正确做法：bat 统一存 GBK 无 BOM。**任何编辑器按 UTF-8 写回都会破坏**，
rem 所以这步不能省，改完 bat 请跑一次 tools\_fix_bat_encoding.py。
%PY% tools\_fix_bat_encoding.py --check >nul 2>&1
if errorlevel 1 (echo   ^> 批处理编码异常，跑 tools\_fix_bat_encoding.py 修复 & goto :end) else (echo   ^> 批处理编码正常)

echo.
echo [8/9] 启动阻塞检查（启动路径不许有网络调用）
rem 2026-10-07 加：m1 启动钩子在主线程同步调 blog_feeds() → detect_proxy()，
rem 而 detect_proxy 的开销是**累积**的（4 段 × 2 URL × 4s + 46 个监听端口，
rem 实测 19~46s）→ 主线程被堵 → 走不到 ThreadingHTTPServer →
rem **端口永远不绑定**（用户看到的是双击后长时间打不开）。
rem 探针第一个目标是 google.com，境内必然超时，每段都是满额等完。
%PY% tools\_test_startup_block.py >nul 2>&1
if errorlevel 1 (echo   ^> 启动路径有阻塞（跑 tools\_test_startup_block.py 看详情） & goto :end) else (echo   ^> 启动路径无阻塞)

echo.
echo [9/9] 统一评测门禁（富化准确率 / 检索召回 / 时延 P95）
rem 2026-10-08 加（评审失分点：指标无 ground-truth 自证）。
rem 跑 tools/评测门禁.py：对 评测集/gold_v*.json（NVD 官方原始响应为真值）
rem 逐字段比富化结果，并实测检索召回与时延；不达阈值返回非 0 → CI 变红。
rem
rem ★ 2026-10-09：这一步需要本机语料 data/corpus.json（283MB，**不在版本库里**，
rem   data/ 整个目录被 .gitignore 排除）。所以换台机器 fresh clone 出来跑，
rem   这里原本必然失败 → CI 恒红 → 那份"CI 全过"的截图在别人机器上复现不了。
rem   现在改为：没有语料就自动降级跑 tools/_test_goldset.py（标注集自洽性，
rem   只依赖仓库内的 评测集/gold_v1.json），并明确打印降级原因。
if not exist "data\corpus.json" (
  echo   [!] 未发现 data\corpus.json（283MB，不随仓库交付）—— 评测门禁跳过
  echo       降级跑标注集自洽性检查 tools\_test_goldset.py ...
  %PY% tools\_test_goldset.py >nul 2>&1
  if errorlevel 1 (echo   ^> 标注集自洽性检查失败 & goto :end) else (echo   ^> 标注集自洽性通过（未做全量门禁）)
) else (
  %PY% tools\评测门禁.py >nul 2>&1
  if errorlevel 1 (echo   ^> 评测门禁不达标（跑 tools\评测门禁.py 看详情） & goto :end) else (echo   ^> 评测门禁通过)
)

echo.
echo ============================================
echo   全部通过 [OK]
echo ============================================
goto :eof

:end
echo.
echo ============================================
echo   存在失败项，请查看上方输出
echo ============================================
exit /b 1
