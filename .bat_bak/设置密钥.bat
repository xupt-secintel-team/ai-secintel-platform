@echo off
chcp 65001 >nul 2>nul
cd /d "%~dp0"
rem ============================================================
rem  AI-SecIntel 2.0 设置本机密钥 / 代理（大模型 Key、GitHub Token、代理）
rem  真正干活的是 tools\配置密钥.py：只写本机 secrets.env，
rem  已被 .gitignore 排除、不打印密钥值、不发任何网络请求。
rem ============================================================
py -3.13 tools\配置密钥.py
if errorlevel 9009 (
  echo [!] 没找到 py -3.13，改用默认 python ...
  python tools\配置密钥.py
)
echo.
pause
