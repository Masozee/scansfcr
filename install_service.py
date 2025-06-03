#!/usr/bin/env python3
"""
Windows Service Installer for System Scanner

This script installs the System Scanner as a Windows service that can:
- Start automatically with Windows
- Run in the background without user login
- Be managed through Windows Services console
- Restart automatically if it crashes

Usage:
    python install_service.py install    # Install the service
    python install_service.py remove     # Remove the service
    python install_service.py start      # Start the service
    python install_service.py stop       # Stop the service
    python install_service.py restart    # Restart the service
"""

import sys
import os
import time
import logging
import threading
from pathlib import Path

# Try to import Windows service modules
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32api
    import win32con
    WINDOWS_SERVICE_SUPPORT = True
except ImportError as e:
    print(f"Windows service modules not available: {e}")
    print("Please install pywin32: pip install pywin32")
    WINDOWS_SERVICE_SUPPORT = False
    sys.exit(1)

# Import our main scanner
try:
    from main import SystemScanner, shutdown_flag, setup_signal_handlers
except ImportError as e:
    print(f"Could not import main scanner module: {e}")
    sys.exit(1)

class SystemScannerService(win32serviceutil.ServiceFramework):
    """Windows service wrapper for the System Scanner"""
    
    _svc_name_ = "SystemScanner"
    _svc_display_name_ = "System Content Scanner"
    _svc_description_ = "Monitors WhatsApp and common folders for inappropriate content and sends alerts via Telegram"
    _svc_deps_ = None  # No dependencies
    
    def __init__(self, args):
        """Initialize the service"""
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.is_alive = True
        self.scanner = None
        self.scanner_thread = None
        
        # Setup logging for service
        self.setup_service_logging()
        
    def setup_service_logging(self):
        """Setup logging for the Windows service"""
        try:
            # Create logs directory if it doesn't exist
            log_dir = Path("logs")
            log_dir.mkdir(exist_ok=True)
            
            # Setup service-specific logging
            service_log_file = log_dir / "service.log"
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(service_log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger("SystemScannerService")
            self.logger.info("Service logging initialized")
            
        except Exception as e:
            # Fallback to event log if file logging fails
            servicemanager.LogErrorMsg(f"Failed to setup file logging: {e}")
    
    def SvcStop(self):
        """Stop the service"""
        try:
            self.logger.info("Service stop requested")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            
            # Signal shutdown
            self.is_alive = False
            shutdown_flag.set()
            
            # Stop the scanner
            if self.scanner:
                self.scanner.stop()
            
            # Wait for scanner thread to finish (with timeout)
            if self.scanner_thread and self.scanner_thread.is_alive():
                self.scanner_thread.join(timeout=10)
            
            # Signal the main service loop to stop
            win32event.SetEvent(self.hWaitStop)
            
            self.logger.info("Service stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping service: {e}")
            servicemanager.LogErrorMsg(f"Error stopping service: {e}")
    
    def SvcDoRun(self):
        """Main service execution"""
        try:
            # Log service start
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self.logger.info("System Scanner Service starting...")
            
            # Setup signal handlers
            setup_signal_handlers()
            
            # Initialize and start the scanner
            self.start_scanner()
            
            # Main service loop
            self.main_loop()
            
        except Exception as e:
            self.logger.error(f"Service execution error: {e}")
            servicemanager.LogErrorMsg(f"Service execution error: {e}")
        finally:
            # Log service stop
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, '')
            )
            self.logger.info("System Scanner Service stopped")
    
    def start_scanner(self):
        """Initialize and start the scanner in a separate thread"""
        try:
            self.logger.info("Initializing System Scanner...")
            
            # Initialize scanner (no verbose output, scan all folders)
            self.scanner = SystemScanner(verbose=False, scan_all=True)
            
            # Start scanner in a separate thread
            self.scanner_thread = threading.Thread(
                target=self.run_scanner,
                daemon=True,
                name="ScannerThread"
            )
            self.scanner_thread.start()
            
            self.logger.info("Scanner thread started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start scanner: {e}")
            raise
    
    def run_scanner(self):
        """Run the scanner (called in separate thread)"""
        try:
            self.logger.info("Scanner thread starting...")
            self.scanner.run()
        except Exception as e:
            self.logger.error(f"Scanner thread error: {e}")
            # If scanner fails, stop the service
            self.SvcStop()
    
    def main_loop(self):
        """Main service loop - wait for stop signal or scanner failure"""
        try:
            while self.is_alive:
                # Wait for stop signal or timeout (check every 30 seconds)
                result = win32event.WaitForSingleObject(self.hWaitStop, 30000)
                
                if result == win32event.WAIT_OBJECT_0:
                    # Stop signal received
                    self.logger.info("Stop signal received")
                    break
                elif result == win32event.WAIT_TIMEOUT:
                    # Timeout - check if scanner is still running
                    if self.scanner_thread and not self.scanner_thread.is_alive():
                        self.logger.error("Scanner thread died unexpectedly")
                        # Try to restart scanner
                        try:
                            self.start_scanner()
                            self.logger.info("Scanner restarted successfully")
                        except Exception as e:
                            self.logger.error(f"Failed to restart scanner: {e}")
                            break
                else:
                    self.logger.warning(f"Unexpected wait result: {result}")
                    
        except Exception as e:
            self.logger.error(f"Main loop error: {e}")

def install_service():
    """Install the Windows service"""
    try:
        print("Installing System Scanner Windows Service...")
        
        # Get the path to this script
        script_path = os.path.abspath(__file__)
        
        # Install the service
        win32serviceutil.InstallService(
            SystemScannerService._svc_reg_class_,
            SystemScannerService._svc_name_,
            SystemScannerService._svc_display_name_,
            description=SystemScannerService._svc_description_,
            startType=win32service.SERVICE_AUTO_START,  # Start automatically
            exeName=sys.executable,
            exeArgs=f'"{script_path}"'
        )
        
        print(f"✓ Service '{SystemScannerService._svc_display_name_}' installed successfully")
        print("✓ Service is set to start automatically with Windows")
        print("\nYou can now:")
        print("- Start the service: python install_service.py start")
        print("- Stop the service: python install_service.py stop")
        print("- Manage it through Windows Services console (services.msc)")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to install service: {e}")
        return False

def remove_service():
    """Remove the Windows service"""
    try:
        print("Removing System Scanner Windows Service...")
        
        # Stop the service first if it's running
        try:
            win32serviceutil.StopService(SystemScannerService._svc_name_)
            print("✓ Service stopped")
        except:
            pass  # Service might not be running
        
        # Remove the service
        win32serviceutil.RemoveService(SystemScannerService._svc_name_)
        print(f"✓ Service '{SystemScannerService._svc_display_name_}' removed successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to remove service: {e}")
        return False

def start_service():
    """Start the Windows service"""
    try:
        print("Starting System Scanner Service...")
        win32serviceutil.StartService(SystemScannerService._svc_name_)
        print("✓ Service started successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to start service: {e}")
        return False

def stop_service():
    """Stop the Windows service"""
    try:
        print("Stopping System Scanner Service...")
        win32serviceutil.StopService(SystemScannerService._svc_name_)
        print("✓ Service stopped successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to stop service: {e}")
        return False

def restart_service():
    """Restart the Windows service"""
    try:
        print("Restarting System Scanner Service...")
        win32serviceutil.RestartService(SystemScannerService._svc_name_)
        print("✓ Service restarted successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to restart service: {e}")
        return False

def show_status():
    """Show service status"""
    try:
        status = win32serviceutil.QueryServiceStatus(SystemScannerService._svc_name_)
        state = status[1]
        
        state_names = {
            win32service.SERVICE_STOPPED: "STOPPED",
            win32service.SERVICE_START_PENDING: "START_PENDING",
            win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
            win32service.SERVICE_RUNNING: "RUNNING",
            win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
            win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
            win32service.SERVICE_PAUSED: "PAUSED"
        }
        
        state_name = state_names.get(state, f"UNKNOWN({state})")
        print(f"Service Status: {state_name}")
        
        return True
        
    except Exception as e:
        print(f"✗ Failed to get service status: {e}")
        return False

def main():
    """Main entry point"""
    if not WINDOWS_SERVICE_SUPPORT:
        print("Windows service support not available")
        return 1
    
    if len(sys.argv) == 1:
        # No arguments - try to run as service
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(SystemScannerService)
            servicemanager.StartServiceCtrlDispatcher()
        except win32service.error as details:
            if details.winerror == 1063:  # The service process could not connect to the service controller
                print("This script should be run as a Windows service or with command line arguments")
                print("\nUsage:")
                print("  python install_service.py install    # Install the service")
                print("  python install_service.py remove     # Remove the service")
                print("  python install_service.py start      # Start the service")
                print("  python install_service.py stop       # Stop the service")
                print("  python install_service.py restart    # Restart the service")
                print("  python install_service.py status     # Show service status")
                return 1
            else:
                print(f"Service error: {details}")
                return 1
    else:
        # Handle command line arguments
        command = sys.argv[1].lower()
        
        if command == "install":
            return 0 if install_service() else 1
        elif command == "remove":
            return 0 if remove_service() else 1
        elif command == "start":
            return 0 if start_service() else 1
        elif command == "stop":
            return 0 if stop_service() else 1
        elif command == "restart":
            return 0 if restart_service() else 1
        elif command == "status":
            return 0 if show_status() else 1
        else:
            print(f"Unknown command: {command}")
            print("Valid commands: install, remove, start, stop, restart, status")
            return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 