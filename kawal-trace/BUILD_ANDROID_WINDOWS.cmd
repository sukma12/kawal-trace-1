@echo off
setlocal
cd /d "%~dp0"

echo ==========================================
echo Kawal Trace v1.0 - Build APK + Windows
echo ==========================================
echo.

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment .venv tidak ditemukan.
  echo Jalankan install_windows.bat terlebih dahulu.
  pause
  exit /b 1
)

set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
if exist "%JAVA_HOME%\bin\java.exe" set "PATH=%JAVA_HOME%\bin;%PATH%"

if not exist "%LOCALAPPDATA%\Android\Sdk\platforms\android-35\android.jar" (
  echo [ERROR] Android Platform 35 belum terpasang.
  echo Pasang lewat Android SDK Manager, lalu jalankan ulang.
  pause
  exit /b 1
)

echo [CHECK] Memeriksa Flutter SDK yang diketahui pengguna...
if exist "%USERPROFILE%\flutter\3.44.8\bin\flutter.bat" (
  for %%A in ("%USERPROFILE%\flutter\3.44.8\bin\flutter.bat") do set "FLUTTER_SIZE=%%~zA"
  if "%FLUTTER_SIZE%"=="0" (
    echo [ERROR] Flutter di %USERPROFILE%\flutter\3.44.8 rusak: flutter.bat 0 byte.
    echo Jangan build dulu. Ekstrak Flutter SDK stabil yang utuh ke C:\src\flutter.
    echo Lalu uji: C:\src\flutter\bin\flutter.bat --version
    pause
    exit /b 1
  )
)

echo.
if exist build rmdir /s /q build
if exist dist\Kawal-Trace-Setup.exe del /q dist\Kawal-Trace-Setup.exe
echo [1/2] Build Android APK...
.venv\Scripts\flet.exe build apk --build-number 13 --build-version 1.0.1 --python-version 3.13 --artifact Kawal-Trace
if errorlevel 1 (
  echo.
  echo [GAGAL] Build APK. Simpan pesan error terakhir untuk diagnosis.
  pause
  exit /b 1
)

where /r build *.apk >nul 2>nul
if errorlevel 1 (
  echo [GAGAL] Build selesai tanpa menemukan APK.
  goto :error
)
echo.
echo [2/2] Build Windows...
.venv\Scripts\flet.exe build windows --build-number 13 --build-version 1.0.1 --python-version 3.13 --artifact Kawal-Trace
if errorlevel 1 (
  echo.
  echo [GAGAL] Build Windows. Periksa Visual Studio 2022/2026 dengan workload Desktop development with C++.
  pause
  exit /b 1
)

echo.
if not exist build\windows (
  echo [GAGAL] Folder build\windows tidak ditemukan.
  goto :error
)
where /r build\windows *.exe >nul 2>nul
if errorlevel 1 (
  echo [GAGAL] Build selesai tanpa menemukan EXE.
  goto :error
)
echo [SELESAI] APK dan EXE ditemukan. Build internal 6.
echo Catatan: output harus diuji di perangkat Windows dan Android sebelum dibagikan.
pause
exit /b 0
