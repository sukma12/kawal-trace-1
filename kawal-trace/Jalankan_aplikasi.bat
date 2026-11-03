@echo off
setlocal
cd /d "%~dp0"
rem Satu klik: pasang dependensi bila belum ada, lalu buka aplikasi Kawal Trace.
if not exist .venv\Scripts\python.exe call install_windows.bat
if not exist .venv\Scripts\python.exe (
  echo Instalasi belum berhasil. Periksa pesan error di atas.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
python main.py
if errorlevel 1 pause
