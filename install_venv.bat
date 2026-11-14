@echo off
chcp 65001 >nul
cd /d "%~dp0"
setlocal enabledelayedexpansion
set PYTHONUTF8=1

echo ============================================================
echo  AI-SecIntel v2.0 - One Click Installation
echo ============================================================

REM Detect valid Python 3.10-3.12
set "PYTHON_CMD="
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%v in ('python -c "import sys; print(1 if (3,10) <= sys.version_info[:2] <= (3,12) else 0)"') do set "PY_VER_VALID=%%v"
    if "!PY_VER_VALID!"=="1" set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    where py >nul 2>&1
    if %errorlevel% equ 0 (
        for /f "delims=" %%v in ('py -3.11 -c "import sys; print(1 if (3,10) <= sys.version_info[:2] <= (3,12) else 0)"') do set "PY_VER_VALID=%%v"
        if "!PY_VER_VALID!"=="1" set "PYTHON_CMD=py -3.11"
    )
)
if not defined PYTHON_CMD (
    echo [ERROR] Python 3.10-3.12 not found.
    echo Please install Python 3.11 and check "Add Python to PATH".
    pause
    exit /b 1
)
echo [INFO] Using Python: !PYTHON_CMD!

REM Create clean virtual environment
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Reuse existing virtual environment.
) else (
    echo [INFO] Creating virtual environment...
    !PYTHON_CMD! -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv.
        pause
        exit /b 1
    )
)

call .\.venv\Scripts\activate.bat

REM Create runtime directories
if not exist "data" mkdir data
if not exist "logs" mkdir logs

REM Create empty secrets template if not exist
if not exist "secrets.env" (
    echo # AI-SecIntel configuration template > secrets.env
    echo AISEC_LLM_API_KEY= >> secrets.env
    echo AISEC_LLM_BASE_URL= >> secrets.env
    echo AISEC_PROXY= >> secrets.env
    echo [INFO] Empty secrets.env template created.
)

REM Install core dependencies first, auto fallback mirrors
echo [INFO] Installing core dependencies...
set "MIRROR_LIST=https://mirrors.aliyun.com/pypi/simple/ https://pypi.mirrors.ustc.edu.cn/simple/ https://pypi.org/simple/"
set "INSTALL_SUCCESS=0"
for %%M in (%MIRROR_LIST%) do (
    if "!INSTALL_SUCCESS!"=="0" (
        echo [INFO] Trying mirror: %%M
        pip install requests urllib3 beautifulsoup4 numpy openpyxl markdown -i %%M --trusted-host %%~dM
        if not errorlevel 1 set "INSTALL_SUCCESS=1"
    )
)
if "!INSTALL_SUCCESS!"=="0" (
    echo [ERROR] Core dependencies install failed, check network.
    pause
    exit /b 1
)

REM Optional full install with local LLM models
if /i "%1"=="--full" (
    echo [INFO] Installing full dependencies with local embedding models...
    for %%M in (%MIRROR_LIST%) do (
        if "!INSTALL_SUCCESS!"=="1" (
            pip install openai torch transformers sentencepiece -i %%M --trusted-host %%~dM
            if not errorlevel 1 set "FULL_SUCCESS=1"
        )
    )
)

echo ============================================================
echo  Installation completed.
echo  1. Edit secrets.env to fill your API keys if needed
echo  2. Run start_service.bat to launch the service
echo  Optional full model install: install_venv.bat --full
echo ============================================================
pause
exit /b 0
