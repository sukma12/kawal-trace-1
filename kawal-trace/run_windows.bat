@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Jalankan install_windows.bat terlebih dahulu.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
python main.py
if errorlevel 1 pause
