@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion
set PYTHONUTF8=1
set NO_PROXY=127.0.0.1,localhost
set no_proxy=127.0.0.1,localhost

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found, run install_venv.bat first.
    pause
    exit /b 1
)

call .\.venv\Scripts\activate.bat
echo [INFO] Loading configuration from secrets.env...
if exist "secrets.env" (
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /v /b "#" secrets.env`) do (
        if not "%%A"=="" if not "%%B"=="" set "%%A=%%B"
    )
) else (
    echo [WARN] secrets.env not found, offline features only.
)

set "PORT=8848"
if not "%1"=="" set "PORT=%1"
echo [INFO] Starting service on port %PORT%
echo [INFO] Web access: http://127.0.0.1:%PORT%
python -u core\server.py %PORT%
pause
