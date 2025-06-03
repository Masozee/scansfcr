# System Scanner Background Launcher - PowerShell Version
# This script provides better process management and Windows integration

param(
    [switch]$Force,
    [switch]$Verbose,
    [switch]$NoTray
)

# Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   System Scanner Background Launcher" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Warning: Not running as administrator. Some features may not work properly." -ForegroundColor Yellow
    Write-Host ""
}

# Function to check if Python is installed
function Test-PythonInstallation {
    try {
        $pythonVersion = python --version 2>&1
        $pythonwExists = Get-Command pythonw.exe -ErrorAction SilentlyContinue
        
        if ($pythonwExists) {
            Write-Host "✓ Python installation found: $pythonVersion" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ pythonw.exe not found in PATH" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Python not found in PATH" -ForegroundColor Red
        return $false
    }
}

# Function to check if scanner is already running
function Test-ScannerRunning {
    $processes = Get-Process -Name "pythonw" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*main.py*background*"
    }
    return $processes.Count -gt 0
}

# Function to stop existing scanner processes
function Stop-ExistingScanner {
    $processes = Get-Process -Name "pythonw" -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*main.py*"
    }
    
    if ($processes.Count -gt 0) {
        Write-Host "Stopping existing scanner processes..." -ForegroundColor Yellow
        $processes | ForEach-Object {
            try {
                $_.Kill()
                Write-Host "✓ Stopped process ID: $($_.Id)" -ForegroundColor Green
            } catch {
                Write-Host "✗ Failed to stop process ID: $($_.Id)" -ForegroundColor Red
            }
        }
        Start-Sleep -Seconds 2
    }
}

# Function to install dependencies
function Install-Dependencies {
    Write-Host "Installing/Updating required packages..." -ForegroundColor Yellow
    
    # Upgrade pip
    python -m pip install --upgrade pip
    
    # Install requirements
    if (Test-Path "requirements.txt") {
        python -m pip install -r requirements.txt
    } else {
        Write-Host "Warning: requirements.txt not found" -ForegroundColor Yellow
    }
    
    # Install Windows-specific packages
    python -m pip install --no-cache-dir pywin32==305
    python -m pip install --no-cache-dir pystray
    
    # Test pywin32 installation
    try {
        python -c "import win32api; print('pywin32 is working')" 2>$null
        Write-Host "✓ pywin32 configured successfully" -ForegroundColor Green
    } catch {
        Write-Host "Configuring pywin32..." -ForegroundColor Yellow
        python Scripts\pywin32_postinstall.py -install 2>$null
    }
}

# Function to start the scanner
function Start-Scanner {
    param([bool]$VerboseMode = $false)
    
    $arguments = @("main.py", "--background", "--scan-all")
    if ($VerboseMode) {
        $arguments += "--verbose"
    }
    
    try {
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "pythonw.exe"
        $processInfo.Arguments = $arguments -join " "
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        
        $process = [System.Diagnostics.Process]::Start($processInfo)
        
        # Wait a moment for the process to initialize
        Start-Sleep -Seconds 3
        
        # Check if process is still running
        if (-not $process.HasExited) {
            Write-Host "✓ Scanner started successfully in background mode!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Scanner process exited immediately. Check logs for errors." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Failed to start scanner: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution
try {
    # Check Python installation
    if (-not (Test-PythonInstallation)) {
        Write-Host "Please install Python and ensure it's in your PATH." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Check if virtual environment exists and activate it
    if (Test-Path "venv\Scripts\Activate.ps1") {
        Write-Host "Activating virtual environment..." -ForegroundColor Yellow
        & "venv\Scripts\Activate.ps1"
        Write-Host "✓ Virtual environment activated." -ForegroundColor Green
    } else {
        Write-Host "No virtual environment found. Using system Python." -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Check if scanner is already running
    if ((Test-ScannerRunning) -and (-not $Force)) {
        Write-Host "Scanner appears to be already running." -ForegroundColor Yellow
        Write-Host "Check your system tray for the blue square icon." -ForegroundColor Yellow
        $response = Read-Host "Do you want to restart it? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Stop-ExistingScanner
        } else {
            Write-Host "Exiting without changes." -ForegroundColor Yellow
            exit 0
        }
    } elseif ($Force) {
        Stop-ExistingScanner
    }
    
    # Install dependencies
    Install-Dependencies
    Write-Host ""
    
    # Start the scanner
    Write-Host "Starting Scanner in background mode..." -ForegroundColor Cyan
    if (Start-Scanner -VerboseMode $Verbose) {
        Write-Host "Scanner launched successfully!" -ForegroundColor Green
    } else {
        Write-Host "Failed to launch scanner. Check the logs for details." -ForegroundColor Red
        Write-Host ""
        Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
        Write-Host "1. Make sure all dependencies are installed correctly" -ForegroundColor White
        Write-Host "2. Check if antivirus is blocking the application" -ForegroundColor White
        Write-Host "3. Try running as administrator" -ForegroundColor White
        Write-Host "4. Check system_scanner.log.encrypted for specific error messages" -ForegroundColor White
        Write-Host "5. Try running with -Verbose flag for more details" -ForegroundColor White
    }
    
} catch {
    Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
} finally {
    Write-Host ""
    Read-Host "Press Enter to exit"
} 