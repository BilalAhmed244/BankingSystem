import socket
import time
from cryptography.fernet import Fernet
from secure_utils import generate_key, generate_hmac, verify_hmac
from random import randint

class ATM_Client:
    def __init__(self, host, port=1234):
        # Initialize client with host and port
        self.conn = socket.create_connection((host, port))
        self.sent_nonces = []  # List to store sent nonces
        self.received_nonces = []  # List to store received nonces
        print('[CONNECTION] CLIENT IS CONNECTED')

    def run_atm(self):
        # Handle initial handshake with the server
        self.handle_first_message()

        registered = False
        while True:
            # Prompt user to login or register
            ip = input("Have an exisiting account with us (Y/N)?: ")

            if (ip.lower() == 'n'):
                print('Please create an account')
                user_name = input("Enter a username: ")
                password = input("Enter a password: ")
                data = " | ".join(['r', user_name, password])  # Registration data
            else:
                user_name = input("Enter username: ")
                password = input("Enter password: ")
                data = " | ".join(['l', user_name, password])  # Login data

            # Send login/registration data to server
            self.send_message(data)
            message_arr = self.receive_message()

            if message_arr[1] == "Successful":
                break  # Break loop if login/registration is successful

        while True:
            # Prompt user for ATM actions
            print(
                "Please enter an action: d - Deposit, w - Withdrawal, b - Balance, e - Exit")
            action = input("Action: ")

            action = action.lower()
            value = None  # Initialize value

            match action:
                case "d":
                    value = float(
                        input("Deposit Amount: "))
                    if value <= 0:
                        print("Cannot deposit the amount specified")
                        continue

                case "w":
                    value = float(
                        input("Withdrawal Amount: "))
                    if value <= 0:
                        print("Cannot withdraw the amount specified")
                        continue

                case "b":
                    value = "Balance Check"

                case "e":
                    value = "e"
                    print("Thank you for using our service!")

                case _:
                    print("Invalid input.")
                    continue

            if value is not None:
                # Send ATM action and value to server
                data = " | ".join([str(action), str(value)])
                self.send_message(data)

                if action == "e":
                    break

                time.sleep(1)
                self.receive_message()
                time.sleep(1)
                
    def send_message(self, message: str):
        # Send encrypted message to server
        prev_nonce = self.received_nonces[-1]  # Get previous nonce
        new_nonce = self.generate_nonce()  # Generate new nonce
        string = " | ".join([message, prev_nonce, new_nonce])
        cipher_text = self.written_key.encrypt(string.encode())

        hmac = generate_hmac(string, self.secret_key)  # Generate HMAC for message

        self.conn.send(cipher_text)
        time.sleep(1.5)
        self.conn.send(hmac)

    def receive_message(self):
        # Receive and process message from server
        cipher_text = self.conn.recv(4096)

        while not cipher_text:
            cipher_text = self.conn.recv(4096)
            time.sleep(0.5)

        hmac_received = self.conn.recv(4096)

        message_bytes = self.written_key.decrypt(cipher_text)
        message_str = message_bytes.decode()
        print(f'[RECEIVED] {message_str}')
        message_arr = message_str.split(" | ")

        if verify_hmac(hmac_received, message_bytes, self.secret_key):
            print('[HMAC] Valid')
        else:
            print('[HMAC] Message Invalid')
            return True

        if (message_arr[-1] not in self.received_nonces):
            self.received_nonces.append(message_arr[-1])
            print(f'[NONCE] Valid')

        return message_arr

    def handle_first_message(self):
        # Handle the initial handshake with the server
        shared_key = 'sharedkey'.encode()
        prev_key = generate_key(passphrase=shared_key, salt=shared_key)
        shared_key = Fernet(prev_key)

        seed = self.generate_nonce(first=True).encode()
        cipher_text = shared_key.encrypt(seed)
        hmac_msg = generate_hmac(seed, prev_key)

        self.conn.send(cipher_text)
        time.sleep(1.5)
        self.conn.send(hmac_msg)

        rev_seed = seed[::-1]
        secret_key = generate_key(passphrase=seed, salt=seed)
        written_key = generate_key(passphrase=rev_seed, salt=rev_seed)
        self.secret_key = secret_key
        self.written_key = Fernet(written_key)
        self.receive_message()
        self.send_message("ACK")

    def generate_nonce(self, first=False) -> str:
        # Generate a nonce for message
        pin = "".join(str(randint(0, 9)) for _ in range(6))

        if not first:
            self.sent_nonces.append(pin)
        return pin

    def close_connection(self):
        # Close connection with server
        self.conn.close()
        print("[CONNECTION] closed.")


client = ATM_Client(host=socket.gethostname())  # Create client instance
client.run_atm()  # Run ATM client
client.close_connection()  # Close connection with server