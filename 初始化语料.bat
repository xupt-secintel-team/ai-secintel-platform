@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONUTF8=1
call .\.venv\Scripts\activate.bat
echo [INFO] Start downloading public vulnerability corpus...
python -u core/fetch_corpus.py
echo [INFO] Corpus initialization finished.
pause
