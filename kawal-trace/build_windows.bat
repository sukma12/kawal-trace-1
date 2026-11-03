@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Jalankan install_windows.bat terlebih dahulu.
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt flet-cli==1.0.4
if errorlevel 1 goto :error
if exist build rmdir /s /q build
if exist dist\Kawal-Trace-Setup.exe del /q dist\Kawal-Trace-Setup.exe
flet build windows --build-number 13 --build-version 1.0.1 --python-version 3.13 --artifact Kawal-Trace
if errorlevel 1 goto :error
if not exist build\windows (
  echo [ERROR] Flet melaporkan selesai tetapi folder build\windows tidak ditemukan.
  goto :error
)
dir /s /b build\windows\*.exe
if errorlevel 1 (
  echo [ERROR] File EXE tidak ditemukan. Build tidak dianggap berhasil.
  goto :error
)
echo Build aplikasi Windows selesai. Versi 1.0.1, build 13.
pause
exit /b 0
:error
echo Build gagal. Pastikan Visual Studio 2022/2026 Desktop development with C++ dan prasyarat Flutter/Flet terpasang.
pause
exit /b 1
