#!/usr/bin/env python3
"""
Helper script to decrypt the encrypted files.
"""

import os
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import argparse

def get_default_password():
    """Get the default password (computer hostname)"""
    try:
        return platform.node()
    except:
        return "default_password"

def decrypt_file(input_file, password=None, output_file=None):
    """Decrypt a file using the given password"""
    # Use default password if none provided
    if password is None:
        password = get_default_password()
    
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode()
        
    # Use the same salt as in the main application
    salt = b"WhatsAppNSFWScanner"
    
    # Generate the key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    cipher = Fernet(key)
    
    # If no output file specified, remove .encrypted extension
    if output_file is None:
        if input_file.endswith('.encrypted'):
            output_file = input_file[:-10]
        else:
            output_file = input_file + ".decrypted"
    
    # Read and decrypt
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
        
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Write decrypted data
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
        
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Decrypt encrypted files")
    parser.add_argument("file", help="File to decrypt")
    parser.add_argument("--password", help="Password to use (default: computer hostname)")
    parser.add_argument("--output", help="Output file (default: remove .encrypted extension)")
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found")
        return
    
    try:
        output_file = decrypt_file(args.file, args.password, args.output)
        print(f"Successfully decrypted to: {output_file}")
        print(f"\nDefault password used (if none provided): {get_default_password()}")
    except Exception as e:
        print(f"Error decrypting file: {e}")
        print(f"\nNote: The default password is your computer's hostname: {get_default_password()}")

if __name__ == "__main__":
    main() 