@echo off
setlocal enabledelayedexpansion

echo ========================================
echo    System Scanner Background Launcher
echo ========================================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Warning: Not running as administrator. Some features may not work properly.
    echo.
)

echo Checking Python installation...
where python.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: python.exe not found! Please make sure Python is installed and in your PATH
    pause
    exit /b 1
)

where pythonw.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: pythonw.exe not found! Please make sure Python is installed and in your PATH
    pause
    exit /b 1
)

echo Python installation found successfully.
echo.

:: Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
    echo Virtual environment activated.
) else (
    echo No virtual environment found. Using system Python.
)
echo.

echo Installing/Updating required packages...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

:: Install Windows-specific packages
echo Installing Windows-specific packages...
python -m pip install --no-cache-dir pywin32==305
python -m pip install --no-cache-dir pystray

echo.
echo Attempting to configure pywin32...
python -c "import win32api; print('pywin32 is working')" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Configuring pywin32...
    python Scripts\pywin32_postinstall.py -install 2>nul
)

echo.
echo Checking if scanner is already running...
tasklist /FI "IMAGENAME eq pythonw.exe" /FI "WINDOWTITLE eq System Scanner*" 2>nul | find /I "pythonw.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo Scanner appears to be already running. 
    echo Check your system tray for the blue square icon.
    echo If you want to restart it, please stop the existing process first.
    pause
    exit /b 0
)

echo.
echo Starting Scanner in background mode...
echo This will run silently with a system tray icon.
echo Look for a blue square icon in your system tray (bottom right corner).
echo.

:: Start the scanner in background mode
start "" /MIN pythonw.exe main.py --background --scan-all

:: Wait a moment for the process to start
timeout /t 3 /nobreak >nul

:: Check if the process started successfully
tasklist /FI "IMAGENAME eq pythonw.exe" 2>nul | find /I "pythonw.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo ✓ Scanner started successfully in background mode!
) else (
    echo ✗ Failed to start scanner. Check the logs for errors.
    echo Check system_scanner.log.encrypted for detailed error information.
    echo.
    echo Troubleshooting tips:
    echo 1. Make sure all dependencies are installed correctly
    echo 2. Check if antivirus is blocking the application
    echo 3. Try running as administrator
    echo 4. Check the log file for specific error messages
)

echo.
echo Press any key to exit...
pause >nul 