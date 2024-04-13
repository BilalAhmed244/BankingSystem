import json
import socket
import time
import threading
import traceback
from cryptography.fernet import Fernet
from random import randint
from secure_utils import EncryptedLogger, generate_key, generate_hmac, verify_hmac

passphrase = b'password'  # Passphrase used for key generation
salt = b'salt'  # Salt used for key generation
log_key = generate_key(passphrase=passphrase, salt=salt)  # Generate encryption key for logging
logger = EncryptedLogger(log_key, 'audit.log')  # Create encrypted logger instance

# Define the ATM server class
class ATM_Server:
    # Initialize the server with default port 1234
    def __init__(self, port=1234):
        self.clients = {}  # Dictionary to store client connections
        # Create a TCP/IP socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the address and port
        self.server.bind((socket.gethostname(), port))
        # Listen for incoming connections
        self.server.listen(3)
        print(f"[LISTENING] on {socket.gethostname()}:{port}")

    # Start the server
    def start_server(self) -> None:
        self.running = True  # Flag to indicate if the server is running
        while self.running:
            try:
                # Accept a new connection
                conn, addr = self.server.accept()
                # Create a new thread to handle the client
                thread = threading.Thread(
                    target=self.handle_client, args=((conn, addr)))
                thread.start()  # Start the thread
            except:
                self.running = False
                thread.join()  # Wait for the thread to finish
                break
        self.running = False
        self.server.close()
        thread.join()

    # Handle each client connection
    def handle_client(self, conn: socket.socket, addr: any) -> None:
        print(f'[NEW CONNECTION] from {addr}')

        # Initialize client data
        self.clients[conn] = {
            'sent_nonces': [],  # List to store sent nonces
            'received_nonces': []  # List to store received nonces
        }

        # Handle the initial handshake with the client
        self.handle_first_message(conn)

        try:
            while True:
                # Receive encrypted message from the client
                cipher_text = conn.recv(4096)

                if cipher_text:
                    # Process the received message
                    exit = self.handle_receive_message(cipher_text, conn)
                else:
                    time.sleep(1.5)

                if exit:
                    break

        except Exception as e:
            # Handle any errors that occur during communication with the client
            print(f'[ERROR] Client: {addr} has closed connection or an error occurred: {e}')
            traceback.print_exc()
        finally:
            conn.close()  # Close the connection
            del self.clients[conn]  # Remove the client from the dictionary
            print(f'[CONNECTION CLOSED] with {addr}')

    # Handle receiving and processing messages from the client
    def handle_receive_message(self, cipher_text: bytes, conn: socket.socket) -> bool:
        hmac_received = conn.recv(4096)  # Receive HMAC from the client
        message_bytes = self.clients[conn]['written_key'].decrypt(cipher_text)  # Decrypt the message
        message_str = message_bytes.decode()  # Convert bytes to string
        print(f'[RECEIVED] {message_str}')

        # Split the message into components
        message_arr = message_str.split(" | ")

        # Verify the integrity of the message using HMAC
        secret_key = self.clients[conn]['secret_key']
        if verify_hmac(hmac_received, message_bytes, secret_key):
            print('[HMAC] Valid')
        else:
            print('[HMAC] Message Invalid')
            return True  # Indicate that the message is invalid

        # Check if the nonce is valid
        if (message_arr[-1] not in self.clients[conn]['received_nonces']):
            self.clients[conn]['received_nonces'].append(message_arr[-1])
            print(f'[NONCE] Valid')

        # Handle ATM functions based on the received message
        exit = self.handle_atm_functions(message_arr, conn)

        return exit

    # Handle sending messages to the client
    def handle_send_message(self, message: str, conn: socket.socket, first=False) -> None:
        if first:
            new_nonce = self.generate_nonce(conn)  # Generate a new nonce for the first message
            string = " | ".join([message, new_nonce])
        else:
            prev_nonce = self.clients[conn]['received_nonces'][-1]  # Get the previous nonce
            new_nonce = self.generate_nonce(conn)  # Generate a new nonce
            string = " | ".join([message, prev_nonce, new_nonce])

        print(f'[SENDING MESSAGE] {string}')
        cipher_text = self.clients[conn]['written_key'].encrypt(string.encode())  # Encrypt the message
        secret_key = self.clients[conn]['secret_key']

        hmac = generate_hmac(message=string, key=secret_key)  # Generate HMAC for the message

        conn.send(cipher_text)  # Send the encrypted message
        time.sleep(1.5)
        conn.send(hmac)  # Send the HMAC

    # Generate a nonce for the client
    def generate_nonce(self, conn):
        pin = "".join(str(randint(0, 9)) for _ in range(6))  # Generate a random PIN
        self.clients[conn]['sent_nonces'].append(pin)  # Add the PIN to the list of sent nonces
        return pin

    # Handle different ATM functions based on the received message
    def handle_atm_functions(self, message_arr: list[str], conn: socket.socket):
        action = message_arr[0]  # Get the action from the message

        # Perform actions based on the received action
        match action:
            case "l":
                act, user, pword, *nonces = message_arr
                self.handle_login(user, pword, conn)
            case "r":
                act, user, pword, *nonces = message_arr
                self.handle_register(username=user, password=pword, conn=conn)
            case "d":
                act, dollars, *nonce = message_arr
                dollars = float(dollars)
                self.handle_deposit(dollars, conn)
            case "w":
                act, dollars, *nonce = message_arr
                dollars = float(dollars)
                self.handle_withdrawal(dollars, conn)
            case "b":
                self.handle_check_balance(conn)
            case "e":
                return True  # Indicate that the client wants to exit

        return False

    # Handle the login process
    def handle_login(self, username: str, password: str, conn: socket):
        tmp = f'{username} attempted login '
        logger.log(tmp)

        with open('users.json', 'r') as f:
            data = json.load(f)

            if username in data and data[username]['password'] == password:
                self.clients[conn]['username'] = username
                self.clients[conn]['is_login'] = True
                s = "Successful"
            else:
                s = "Unsuccessful"

        tmp = f'{username} Login {s}'
        logger.log(tmp)
        self.handle_send_message(" | ".join(["[LOGIN]", s]), conn)

    # Handle the registration process
    def handle_register(self, username: str, password: str, conn: socket):
        with open('users.json', 'r') as f:
            data = json.load(f)

            if username not in data.keys():
                # Add new user to the database
                data[username] = {
                    'password': password,
                    'balance': 0
                }
                with open('users.json', 'w') as j:
                    logger.log(f'{username} registration successful')
                    json.dump(data, j)
                    self.clients[conn]['username'] = username
                    self.clients[conn]['is_login'] = True
                    self.handle_send_message(f'[REGISTRATION] | Successful', conn)
            else:
                logger.log(f'{username} registration unsuccesful')
                self.handle_send_message(f'[REGISTRATION] | Unsuccessful', conn)

    # Handle deposit process
    def handle_deposit(self, deposit: float, conn: socket):
        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)
                username = self.clients[conn]['username']
                data[username]['balance'] += deposit

                with open('users.json', 'w') as j:
                    json.dump(data, j)

                logger.log(f'{username} deposit: {deposit} successful')
                self.handle_send_message(f"[DEPOSIT] | Successful", conn)
        else:
            logger.log(f'{username} deposit failure')
            self.handle_send_message(f"[DEPOSIT] | Unsuccessful", conn)

    # Handle withdrawal process
    def handle_withdrawal(self, withdrawal: float, conn: socket):
        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                if (data[username]['balance'] - withdrawal >= 0):
                    data[username]['balance'] -= withdrawal

                    with open('users.json', 'w') as j:
                        json.dump(data, j)

                    self.handle_send_message(f"[WITHDRAWAL] | Successful", conn)
                    logger.log(f'{username} withdrawal: {withdrawal} successful')
                else:
                    logger.log(f'{username} Withdrawal failure')
                    self.handle_send_message(f"[WITHDRAWAL] | Unsuccessful: Insufficient funds", conn)
        else:
            self.handle_send_message("[DEPOSIT] Unsuccessful", conn)

    # Handle balance check process
    def handle_check_balance(self, conn: socket):
        if (self.clients[conn]['is_login']):
            with open('users.json', 'r') as f:
                data = json.load(f)

                username = self.clients[conn]['username']

                balance = data[username]['balance']
                self.handle_send_message(f"[BALANCE] {balance}", conn)

        else:
            self.handle_send_message(f"[BALANCE] | Unsuccessful")

        logger.log(f'{username} check balance')

    # Handle the initial handshake with the client
    def handle_first_message(self, conn: socket):
        shared_key = 'sharedkey'.encode()
        prev_key = generate_key(passphrase=shared_key, salt=shared_key)
        shared_key = Fernet(prev_key)

        # Receive the encrypted seed from the client
        cipher_text = conn.recv(4096)
        time.sleep(1.5)
        hmac_received = conn.recv(4096)
        seed = shared_key.decrypt(cipher_text)

        # Verify the HMAC of the received seed
        print(f'[VERIFYING HMAC] {verify_hmac(hmac_received, seed, prev_key)}')
        print(f'[MESSAGE] {seed.decode()}')

        rev_seed = seed[::-1]
        secret_key = generate_key(passphrase=seed, salt=seed)
        written_key = generate_key(passphrase=rev_seed, salt=rev_seed)
        self.clients[conn]['secret_key'] = secret_key
        self.clients[conn]['written_key'] = Fernet(written_key)

        self.handle_send_message("DONE", conn, first=True)
        time.sleep(0.5)

        cipher_text = conn.recv(4096)
        self.handle_receive_message(cipher_text, conn)


server = ATM_Server()  # Create an instance of the ATM server
server.start_server()  # Start the server
