@echo off
chcp 65001 >nul
rem 本地一键 CI：离线测试全量 + 前端组装校验 + 一致性核查
rem 用法：双击 运行CI.bat，或 py -3.13 tools\运行CI.py

setlocal
set PY="%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist %PY% set PY=py -3.13

echo ============================================
echo   AI-SecIntel 本地 CI 全量自检
echo ============================================

echo.
echo [1/5] 后端离线测试（Python）
set FAIL=0
for %%f in (tools\_test_*.py) do (
  echo   == %%f ==
  %PY% %%f >nul 2>&1 || (echo   [FAIL] %%f & set FAIL=1)
)
if "%FAIL%"=="1" (echo   ^> 有后端测试失败 & goto :end) else (echo   ^> 后端测试全部通过)

echo.
echo [2/5] 前端桩测试（Node）
set FAIL=0
for %%f in (tools\_test_*.js) do (
  echo   == %%f ==
  node %%f >nul 2>&1 || (echo   [FAIL] %%f & set FAIL=1)
)
if "%FAIL%"=="1" (echo   ^> 有前端测试失败 & goto :end) else (echo   ^> 前端测试全部通过)

echo.
echo [3/5] 前端组装一致性校验
%PY% tools\组装前端.py --check >nul 2>&1
if errorlevel 1 (echo   ^> 组装不一致（请先跑 组装前端.py） & goto :end) else (echo   ^> 组装一致)

echo.
echo [4/5] 语法编译检查（core + modules）
%PY% -m compileall -q core modules >nul 2>&1
if errorlevel 1 (echo   ^> 存在语法错误 & goto :end) else (echo   ^> 语法检查通过)

echo.
echo [5/5] 前端可读性检查（对比度 + 变量存在性）
rem 2026-07-07 加：用户报"前端有些部件看不清"，根因是①引用了不存在的
rem CSS 变量（--txt-1，项目里只有 --txt）②拿文字色 --accent-3 当按钮底色，
rem 亮色主题下白字 ratio 只有 2.11。两类问题**浏览器都不报错**，只能靠算。
%PY% tools\检查对比度.py >nul 2>&1
if errorlevel 1 (echo   ^> 存在看不清的部件（跑 tools\检查对比度.py 看详情） & goto :end) else (echo   ^> 对比度达标)

echo.
echo ============================================
echo   全部通过 ✓
echo ============================================
goto :eof

:end
echo.
echo ============================================
echo   存在失败项，请查看上方输出
echo ============================================
exit /b 1
