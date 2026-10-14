@echo off
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 设置本机密钥 / 代理（大模型 Key、GitHub Token、代理）
rem  真正干活的是 tools\配置密钥.py：只写本机 secrets.env，
rem  已被 .gitignore 排除、不打印密钥值、不发任何网络请求。
rem
rem  ★ 2026-10-09 可移植性修复：原来这里写死 `py -3.13`，并用
rem    `if errorlevel 9009` 兜底。但别人机器上装的是 3.11/3.12/3.14 时，
rem    `py -3.13` 的失败码并**不是** 9009（9009 只在"命令不存在"时出现），
rem    所以兜底不会触发，脚本直接报错退出。改为统一走
rem    tools\_选解释器.bat（候选 py -3 / python / python3 / 项目 .venv）。
rem ============================================================
set PYTHONDONTWRITEBYTECODE=1

call "%~dp0tools\_选解释器.bat"
if not defined PYEXE (
    echo.
    pause
    exit /b 1
)

%PYEXE% tools\配置密钥.py
echo.
pause
