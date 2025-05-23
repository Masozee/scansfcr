@echo off
echo Checking Python installation...

where pythonw.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: pythonw.exe not found! Please make sure Python is installed and in your PATH
    pause
    exit /b 1
)

echo Removing old pywin32 installations...
pip uninstall -y pywin32

echo Installing/Updating required packages...
python -m pip install -r requirements.txt

echo Installing pywin32 specifically...
python -m pip install --no-cache-dir pywin32==305

echo Attempting to repair pywin32 installation...
for %%p in (python.exe pythonw.exe) do (
    echo Checking %%p installation...
    where %%p >nul 2>&1
    if not errorlevel 1 (
        echo Running post-install script with %%p
        %%p Scripts/pywin32_postinstall.py -install
    )
)

echo Starting Scanner in background...
start "" pythonw.exe main.py --background --verbose

echo If no errors appeared above, the scanner is now running in the background.
echo Look for a red square icon in your system tray (bottom right corner).
echo If you don't see the icon, check the logs_checker.log file for errors.
timeout /t 5 