import base64
import hashlib
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

def generate_key(passphrase: bytes, salt: bytes) -> bytes:
    # Generate a key using PBKDF2 key derivation function, turns a random password and salt into a fixed-size key. Hash the input multiple times
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10,
        backend=default_backend()
    )
    # Derive a key using the passphrase and salt
    fernet_seed = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return fernet_seed

def generate_hmac(message, key, hash_func=hashlib.sha256):
    # Generate HMAC for the message using the provided key, combine secret key with message and apply hash
    if isinstance(message, str):
        message = message.encode()

    if isinstance(key, str):
        key = key.encode()

    return hmac.new(key, message, hash_func).digest()

def verify_hmac(hmac_received, message, key, hash_func=hashlib.sha256):
    # Verify the HMAC received with the message against the computed HMAC using the same key
    computed_hmac = generate_hmac(message, key, hash_func)
    return hmac.compare_digest(computed_hmac, hmac_received)

class EncryptedLogger:
    # Class to log encrypted messages to a file
    def __init__(self, key, filepath):
        self.fernet = Fernet(key)  # Initialize Fernet cipher with the provided key
        self.filepath = filepath  # Set the filepath for the log file

    def log(self, message):
        # Log a message by encrypting it with Fernet and appending it to the log file
        message = message + ' , ' + str(datetime.now())  # Add timestamp to the message
        encrypted_message = self.fernet.encrypt(message.encode())  # Encrypt the message
        with open(self.filepath, "ab") as file:
            file.write(encrypted_message + b'\n')  # Append the encrypted message to the log file with a newline
