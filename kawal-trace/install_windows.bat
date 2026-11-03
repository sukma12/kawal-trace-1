@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher tidak ditemukan. Instal Python 3.13 atau 3.14 dari python.org.
  pause
  exit /b 1
)
py -3.13 --version >nul 2>nul
if errorlevel 1 (
  echo Python 3.13 belum terpasang. Instal Python 3.13 atau edit skrip ini ke versi Python yang tersedia.
  pause
  exit /b 1
)
if not exist .venv py -3.13 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 goto :error
python -m pip install -r requirements.txt flet-cli==1.0.4
if errorlevel 1 goto :error
echo.
echo Instalasi selesai. Jalankan run_windows.bat.
pause
exit /b 0
:error
echo Instalasi gagal. Periksa koneksi internet atau pesan error di atas.
pause
exit /b 1
