import socket
import threading
import json

# Encryption
from cryptography.fernet import Fernet
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class MultiThreadedClient(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.chat_messages = []
        self.new_subject = ""
        self.username = ""
        self.messages = []
        self.found_player = False
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stop_flag = threading.Event() # Event to signal thread termination
        self.client_thread = threading.Thread(target=self.connect)
        
        self.chat_thread = threading.Thread(target=self.receive_messages_chat)
        self.stop_chat_flag = threading.Event()

        self.encryption = Client_Encryption()

    def connect(self):
        self.client_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")

        # Encryption
        self.server_public_key = RSA.import_key(self.client_socket.recv(1024)) # gets the server’s public encryption key
        self.client_socket.sendall(self.encryption.encrypt_symmetric_key(self.server_public_key)) # generates a symmetric key, encrypts it and sends it to the server

        self.receive_data()
        
    def disconnect(self):
        print("Client disconnected")
        self.stop_flag.set() # Set the stop flag to signal thread termination
        self.client_socket.close()

    def send_message(self, data):
        json_message = json.dumps(data)
        self.client_socket.send(json_message.encode())

    def receive_data(self):
        while not self.stop_flag.is_set(): # Check the stop flag in the loop
            try:
                data = self.client_socket.recv(1024)            
                msg = json.loads(data)
                if not msg:
                    break
                if type(msg) is list:
                    self.messages = msg
                    if (msg[0] == "login" or msg[0] == "signup") and msg[1] == "success":
                        self.username = msg[2]
                        
                    elif msg[0] == "game" and msg[1] == "chat":
                        if msg[2] == "joining":
                            self.found_player = True
                        else:
                            self.found_player = False
            except:
                self.client_socket.close()

    def connect_to_chat(self):
        """
        Initiates the connection to the chat by setting the stop flag and clearing the stop chat flag.
        Then starts a new thread to receive messages from the chat by calling the receive_messages_chat function.
        """
        self.stop_flag.set()
        self.stop_chat_flag.clear()
        self.chat_thread = threading.Thread(target=self.receive_messages_chat).start()

    def receive_messages_chat(self):
        """
        Receives messages from the chat.
        This function continuously receives messages from the chat server until the stop_chat_flag is set. 
        Each received message is parsed as a JSON object and stored in the chat_messages list. 
        The message gets check to see if it meets any of the following conditions:
        new round, kicking client.
        if it does, it updates the new_subject variable.
        . 
        """
        while not self.stop_chat_flag.is_set(): # Check the stop chat flag
            try:
                data = self.client_socket.recv(1024) # Receive data from the server
                msg = json.loads(data) # Reformatting the data from json to a list
                if msg[2] == "new round": # Check if the message is a new round message
                    self.new_subject = msg[3] # Update the new_subject variable
                elif msg[2] == "kicking client": # Check if the message is a kicking client message
                    self.new_subject = msg[2] # Using new_subject as a flag in order to kick the client
                    self.chat_messages.append(msg)
                else:
                    # Add the message to the chat_messages list
                    self.chat_messages.append(msg)
                    
            except Exception as e:
                break

    def leave_chat(self):
        """
        This function is responsible for cleaning up the chat session by resetting the necessary flags and starting a new thread to receive data. 
        The function is called when a user wants to leave the chat.
        """
        self.stop_flag.clear()
        self.stop_chat_flag.set()
        self.client_thread = threading.Thread(target=self.receive_data).start()

class Client_Encryption:
    def __init__(self):
        # Initialize any necessary variables or objects here
        self.symmetric_key = None
    
    def generate_symmetric_key(self):
        # Implement code to generate encryption key
        return Fernet.generate_key()
    
    def import_public_key(self, pem_key):
        return RSA.import_key(pem_key)
    
    def encrypt_data(self, plaintext):
        cipher = Fernet(self.symmetric_key)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext
    
    def decrypt_data(self, ciphertext):
        cipher = Fernet(self.symmetric_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    
    def encrypt_symmetric_key(self, server_public_key):
        self.symmetric_key = self.generate_symmetric_key()
        cipher = PKCS1_OAEP.new(server_public_key)
        chunk_size = 86 
        encrypted_key = b"" 
        for i in range(0, len(self.symmetric_key), chunk_size): # Encrypt in chunks
            chunk = self.symmetric_key[i:i + chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_key += encrypted_chunk
        return encrypted_key
    