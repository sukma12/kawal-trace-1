@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo Kawal Trace v1.0 - Android APK only
echo ==========================================
echo.
if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Membuat environment Python 3.13...
  py -3.13 -m venv .venv
  if errorlevel 1 goto :error
)
echo [1/3] Memasang dependensi aplikasi dan Flet CLI...
.venv\Scripts\python.exe -m pip install --upgrade pip
if errorlevel 1 goto :error
.venv\Scripts\python.exe -m pip install -r requirements.txt flet-cli==1.0.4
if errorlevel 1 goto :error
echo Flet akan memeriksa dan mengunduh Flutter, JDK, atau Android SDK yang belum ada. Pastikan internet aktif.
echo [2/3] Memeriksa kode Python...
.venv\Scripts\python.exe -m compileall -q main.py chainlog
if errorlevel 1 goto :error
echo.
if exist build rmdir /s /q build
echo [3/3] Membuat APK universal Kawal Trace...
.venv\Scripts\flet.exe build apk --build-number 13 --build-version 1.0.1 --python-version 3.13 --project kawaltrace --bundle-id id.kawaltrace.app --product "Kawal Trace" --org id.kawaltrace --artifact Kawal-Trace
if errorlevel 1 goto :error
echo.
where /r build *.apk >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Flet selesai tetapi APK tidak ditemukan. Build tidak dianggap berhasil.
  goto :error
)
echo [SELESAI] APK benar-benar ditemukan di bawah folder build.
echo Build internal 6. APK tetap perlu dipasang dan diuji pada Android nyata.
pause
exit /b 0
:error
echo.
echo [GAGAL] Build APK belum berhasil. Salin pesan error terakhir untuk diagnosis.
pause
exit /b 1
