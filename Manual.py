from cryptography.fernet import Fernet

from secure_utils import generate_key

# Replace these values with the actual ones used during encryption
passphrase = b'password'
salt = b'salt'

key = generate_key(passphrase, salt)
cipher_suite = Fernet(key)

# Use one of the encrypted log entries from your file
encrypted_log_entry = b'gAAAAABmGH2BjM-USa3_PcHYrPXYcmAcTs6DFtjhDQuPydUuju200csTyOk2ilffcyatVOWYHLMXIyPHEz1sbGmCSxququ1G2eiGwZaARLIrR5VAykfMfVWq3H3JwchJPlAYm4rl66ZYGfR2XfW0Xmru2q9rtJ7THA=='

try:
    decrypted_log = cipher_suite.decrypt(encrypted_log_entry)
    print("Decrypted log entry:", decrypted_log.decode())
except Exception as e:
    print("Failed to decrypt:", str(e))
