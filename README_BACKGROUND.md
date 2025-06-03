# System Scanner - Background Execution Guide

This guide explains the various ways to run the System Scanner in the background on Windows systems.

## Overview

The System Scanner can run in the background using several methods:

1. **System Tray Application** - Runs with a system tray icon (easiest)
2. **Windows Service** - Runs as a proper Windows service (most robust)
3. **PowerShell Background** - Advanced PowerShell-based execution
4. **Batch File** - Simple batch file execution

## Method 1: System Tray Application (Recommended for Desktop Use)

### Quick Start
```bash
# Run the improved batch file
start_background.bat
```

### Manual Command
```bash
# Start with system tray icon
pythonw.exe main.py --background --scan-all

# Start with verbose output (for debugging)
pythonw.exe main.py --background --scan-all --verbose
```

### Features
- ✅ System tray icon (blue square)
- ✅ Right-click menu with options
- ✅ Show status, pause/resume, restart
- ✅ Graceful shutdown
- ✅ Automatic restart on failure
- ✅ No console window
- ✅ Encrypted logging

### System Tray Menu Options
- **Show Status** - Display current scanning status
- **Pause/Resume** - Temporarily stop/start scanning
- **Restart Scan** - Restart the scanning process
- **Exit** - Stop the scanner completely

## Method 2: Windows Service (Recommended for Server/Always-On Use)

### Installation
```bash
# Install the service (run as Administrator)
python install_service.py install

# Start the service
python install_service.py start
```

### Management Commands
```bash
# Check service status
python install_service.py status

# Stop the service
python install_service.py stop

# Restart the service
python install_service.py restart

# Remove the service
python install_service.py remove
```

### Features
- ✅ Starts automatically with Windows
- ✅ Runs without user login
- ✅ Automatic restart on crash
- ✅ Windows Event Log integration
- ✅ Service management through Windows Services console
- ✅ Most robust background execution method

### Windows Services Console
You can also manage the service through the Windows Services console:
1. Press `Win + R`, type `services.msc`, press Enter
2. Find "System Content Scanner" in the list
3. Right-click for options (Start, Stop, Restart, Properties)

## Method 3: PowerShell Background Execution

### Basic Usage
```powershell
# Run the PowerShell script
.\start_background.ps1

# Force restart if already running
.\start_background.ps1 -Force

# Run with verbose output
.\start_background.ps1 -Verbose
```

### Features
- ✅ Advanced process management
- ✅ Automatic dependency installation
- ✅ Process monitoring and restart
- ✅ Colored output and better error handling
- ✅ Virtual environment support

## Method 4: Direct Python Execution

### Background Mode
```bash
# Basic background execution
python main.py --background

# Background with all folders scanning
python main.py --background --scan-all

# Background with verbose logging
python main.py --background --scan-all --verbose
```

### Foreground Mode (for testing)
```bash
# Run in foreground with verbose output
python main.py --verbose --scan-all

# Run scanning only WhatsApp folders
python main.py --verbose
```

## Configuration Options

### Command Line Arguments
- `--background` - Run in background with system tray icon
- `--scan-all` - Scan all common folders (Downloads, Pictures, Documents, Desktop)
- `--verbose` - Enable verbose logging output
- `--encrypt-logs` - Encrypt log files for privacy
- `--decrypt-logs` - Decrypt existing encrypted log files
- `--password PASSWORD` - Password for log encryption/decryption

### Environment Variables
You can set these in your system environment:
- `TELEGRAM_BOT_TOKEN` - Your Telegram bot token
- `TELEGRAM_CHAT_ID` - Your Telegram chat ID
- `DETECTION_THRESHOLD` - Content detection threshold (0.0 to 1.0)

## Monitoring and Logs

### Log Files
- `system_scanner.log.encrypted` - Main encrypted log file
- `logs/service.log` - Windows service specific logs (if using service)
- `processed_images.json` - List of already processed images

### Decrypting Logs
```bash
# Decrypt logs for viewing
python main.py --decrypt-logs

# Decrypt with specific password
python main.py --decrypt-logs --password mypassword
```

### Viewing Logs
```bash
# Decrypt and view logs
python main.py --decrypt-logs
type system_scanner.log

# Or use the decrypt_files.py utility
python decrypt_files.py
```

## Troubleshooting

### Common Issues

#### 1. System Tray Icon Not Appearing
- Check if the process is running: `tasklist | findstr pythonw`
- Try running with `--verbose` flag to see error messages
- Ensure `pystray` package is installed: `pip install pystray`

#### 2. Service Won't Start
- Run as Administrator when installing/starting service
- Check Windows Event Viewer for service errors
- Ensure all dependencies are installed
- Check `logs/service.log` for detailed errors

#### 3. Scanner Stops Working
- Check the encrypted log file for errors
- Verify Telegram bot token and chat ID are correct
- Ensure internet connection is available
- Check if antivirus is blocking the application

#### 4. High CPU Usage
- Adjust scan frequency in the code if needed
- Ensure content detection model is loading correctly
- Check for infinite loops in error handling

### Debugging Steps

1. **Test Basic Functionality**
   ```bash
   python main.py --verbose
   ```

2. **Test Background Mode**
   ```bash
   python main.py --background --verbose
   ```

3. **Check Dependencies**
   ```bash
   pip install -r requirements.txt
   python -c "import win32api, pystray, transformers; print('All dependencies OK')"
   ```

4. **Check Telegram Configuration**
   ```bash
   # Test Telegram bot manually
   curl "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getMe"
   ```

## Performance Optimization

### For Better Performance
- Use SSD storage for faster file scanning
- Ensure adequate RAM (4GB+ recommended)
- Close unnecessary applications
- Use Windows Service method for best performance

### For Lower Resource Usage
- Increase scan intervals in the code
- Reduce the number of folders being scanned
- Use `--scan-all false` to scan only WhatsApp folders

## Security Considerations

### Log Encryption
- Logs are automatically encrypted for privacy
- Use strong passwords for log decryption
- Store decryption passwords securely

### Network Security
- Telegram communications are encrypted
- Consider using VPN if privacy is a concern
- Monitor network traffic if needed

### File System Security
- Scanner only reads files, never modifies them
- Processed images list prevents re-scanning
- No sensitive data is stored unencrypted

## Advanced Configuration

### Custom Folders
Edit the `_get_common_folders()` method in `main.py` to add custom scan locations.

### Custom Detection Threshold
Modify the `DETECTION_THRESHOLD` variable in `main.py` (default: 0.7).

### Custom Scan Intervals
Modify the sleep intervals in the `run()` method of `SystemScanner` class.

## Support

If you encounter issues:

1. Check this README for common solutions
2. Review the encrypted log files for error details
3. Test with verbose mode enabled
4. Ensure all dependencies are properly installed
5. Try running as Administrator if needed

## Best Practices

1. **For Desktop Use**: Use System Tray method
2. **For Server Use**: Use Windows Service method
3. **For Development**: Use foreground mode with verbose logging
4. **For Security**: Always use encrypted logs
5. **For Reliability**: Monitor logs regularly and set up automatic restarts 