@echo off
title NetGuardian Installer
echo ============================================
echo   NetGuardian Installer
echo ============================================
echo.

python --version >nul 2>nul
if errorlevel 1 (
    echo Python doesn't seem to be installed properly.
    echo.
    echo If a Microsoft Store window just opened, that's a known Windows issue:
    echo a placeholder "python.exe" redirects to the Store instead of running
    echo real Python. Fix: Settings ^> Apps ^> Advanced app settings ^> App
    echo execution aliases - turn OFF "App Installer python.exe" and "python3.exe".
    echo Then install real Python from https://python.org/downloads and check
    echo "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)

echo Found Python. Installing NetGuardian's dependencies...
echo.
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Something went wrong installing dependencies. See the message above.
    pause
    exit /b 1
)

python -m pip install -e .
if errorlevel 1 (
    echo.
    echo Something went wrong installing NetGuardian itself. See the message above.
    pause
    exit /b 1
)

if exist "%~dp0netguardian_error.log" del "%~dp0netguardian_error.log"

echo.
echo ============================================
echo   Installation complete!
echo ============================================
echo.
echo Note: Windows Firewall may ask to allow network access the first time
echo you scan - click Allow so NetGuardian can see other devices.
echo.
echo Opening NetGuardian now...
timeout /t 2 >nul

where pythonw >nul 2>nul
if errorlevel 1 (
    start "" python "%~dp0NetGuardian.pyw"
) else (
    start "" pythonw "%~dp0NetGuardian.pyw"
)

timeout /t 3 >nul
if exist "%~dp0netguardian_error.log" (
    echo.
    echo NetGuardian hit a problem on startup:
    echo ============================================
    type "%~dp0netguardian_error.log"
    echo ============================================
    pause
) else (
    echo If a window didn't appear, double-click NetGuardian.pyw directly.
    pause
)
