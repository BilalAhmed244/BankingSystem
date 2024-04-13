from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from secure_utils import generate_key  # Import custom function for generating keys

class EncryptedLogReader:
    def __init__(self, key, filepath):
        self.fernet = Fernet(key)  # Initialize Fernet cipher with the provided key
        self.filepath = filepath  # Set the filepath for the encrypted log file

    def read_logs(self):
        try:
            with open(self.filepath, "rb") as file:
                log_entries = file.readlines()  # Read all lines from the log file

            for entry in log_entries:
                decrypted_message = self.fernet.decrypt(entry).decode()  # Decrypt each log entry
                print(decrypted_message)  # Print the decrypted log message
        except Exception as e:
            print(f"Failed to read or decrypt log: {e}")  # Print error if reading or decryption fails

# Define passphrase and salt for key generation
passphrase = b'password'
salt = b'salt'
# Generate key using passphrase and salt
log_key = generate_key(passphrase=passphrase, salt=salt)
# Create instance of EncryptedLogReader with the generated key and log file path
logger = EncryptedLogReader(log_key, 'audit.log')
# Read and decrypt logs
logger.read_logs()