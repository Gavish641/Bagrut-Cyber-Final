import socket
import select
from server_utils import UsersDB, ScoresDB, Message, Sorting_Numbers, Server_Encryption
from getmac import getmac
import json
import random
import hashlib
import os

# Get the directory where the current script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the client_config.json file
config_path = os.path.join(script_dir, '..', 'config.json')

# Open and read the config file
with open(config_path, 'r') as file:
    config = json.load(file)


class Server:

    def __init__(self, host, port):
        """
        Initializes the Server class with the specified host and port.
        - Creates a server socket using the provided host and port.
        - Initializes various data structures for user names, clients, chat players, and messages.
        - Loads associations from the 'associations.json' file.
        - Instantiates databases for users and scores.
        - Initializes lists for rlist, wlist, and xlist.
        """
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(config["max_connections"])
        self.message = Message()
        self.encryption = Server_Encryption()

        self.clients = [self.server_socket]
        self.clients_names = {}
        self.not_sent_msg_clients = {}
        self.sent_clients = []
        
        self.curr_asso_index = -1
        self.waiting_for_next_round = 0
        self.wfc = []
        self.chat_players = {}
        self.chat_messages = {}
        self.chat_players_flags = 0
        self.used_answers = []


        with open('./Server/associations.json', 'r') as file:
            self.associations = json.load(file)

        self.database = UsersDB()
        self.scores = ScoresDB()
        self.sorting_numbers = Sorting_Numbers()
        self.messages = {}

        # Initialize rlist, wlist, and xlist
        self.rlist = []
        self.wlist = []
        self.xlist = []

    def start(self):
        """
        Start the server and continuously listen for incoming connections.
        Accept new connections, handle data from existing clients, and manage disconnections.
        """
        print(f"Server is listening on {self.server_socket.getsockname()}")

        while True:
            # Copy the clients list to rlist for monitoring read events
            self.rlist = list(self.clients)
            rlist, _, _ = select.select(self.rlist, self.wlist, self.xlist)

            for sock in rlist:  
                if sock == self.server_socket:
                    # New connection, accept it
                    client_socket, client_address = self.server_socket.accept()
                    self.clients.append(client_socket)
                    print(f"New connection from {client_address}")

                    # GETTING THE SYMMETRIC KEY FROM THE CLIENT
                    serialized_public_key = self.encryption.public_key.export_key()
                    client_socket.sendall(serialized_public_key)
                    encrypted_symetric_key = client_socket.recv(1024)
                    self.encryption.encryption_keys[client_socket] = self.encryption.decrypt_symmetric_key(encrypted_symetric_key)

                    mac_address = getmac.get_mac_address(ip=client_address[0]).encode() # gets client's mac address
                    hashed_mac = hashlib.sha256(mac_address).hexdigest()
                    self.clients_names[client_socket] = [hashed_mac, ""]
                    if self.database.check_mac_address(hashed_mac): # checks if mac address saved in database
                        username = self.database.get_username_by_mac(hashed_mac) # gets username from database by the mac address
                        self.clients_names[client_socket][1] = username # saves the username in the clients_names dictionary
                        client_socket.send(self.message.encode_json(["remember me", username])) # sends a message and the username to the client
                else:
                    # Handle data from an existing client
                    try:
                        encoded_data = sock.recv(1024) # receives data from client
                        data = list(self.message.decode_json(encoded_data)) # decodes data
                        self.messages[sock] = data
                        result_msg = self.handle_messages()
                        if result_msg is not None:
                            if (result_msg[0] == "login" or result_msg[0] == "signup") and result_msg[1] == "success":
                                self.clients_names[sock][1] = result_msg[2]
                            result_json_msg = self.message.encode_json(result_msg)
                            sock.send(result_json_msg)

                    except:
                        # Client disconnected
                        username = self.clients_names[sock][1]
                        if username in self.chat_players: # if the client is in the chat players list then remove it 
                            self.chat_players.pop(username)
                            if len(self.wfc) != 0:
                                joining_player_socket = self.get_sock_by_username(self.wfc[0])
                                self.chat_players[joining_player_socket] = [self.wfc[0], 0]
                                self.clients_names[self.wfc[0]].send(self.message.encode_json(["game", "chat", "joining"]))
                        self.clients_names.pop(sock)
                        self.clients.remove(sock)
                        print("Server: Client has been disconnected")
                    
    def handle_messages(self):
        """
            A function to handle different types of messages received, such as login, signup, database queries, and game interactions.
            Manages login attempts, user registration, database checks, game actions like sorting numbers and chat functionality.
            The function processes the messages and returns appropriate responses accordingly.
        """
        for sock in self.messages:
            msg = self.messages[sock]
            if type(msg) is list:
                if msg[0] == "login":
                    # handle login requests
                    return self.handle_login(msg[1], msg[2], msg[3], sock) # username, password, remember_me, sock
                    
                if msg[0] == "signup":
                    # handle signup requests
                    return self.handle_signup(msg[1], msg[2], msg[3], sock) # username, password, remember_me, sock

                if msg[0] == "database":
                    # handle database queries
                    return self.handle_database_queries(msg, sock)
                
                if msg[0] == "game":
                    # handle game interactions
                    if msg[1] == "sorting numbers":
                        # handle sorting numbers game
                        return self.handle_sorting_numbers(msg, sock)
                    
                    if msg[1] == "chat":
                        # handle associations game
                        return self.handle_associations_game(msg, sock)

    def handle_login(self, username, password, remember_me, sock):
        '''
        Handles the login process for a user.
        Given the username, password, and the remember_me setting, it checks if the user exists and if the password is correct.
        '''
        for value in self.clients_names.values(): # checks if the user is already logged in
            if value[1] == username:
                self.messages.pop(sock)
                return ["login", "error", "user already logged in"]

        if not self.database.check_user_registered(username):
            # the username is not exists
            self.messages.pop(sock)
            return ["login", "error", "no user exists"]
        
        elif self.database.try_login(username, password, self.encryption.encryption_keys[sock]):
            # handleד login success
            if not bool(self.database.check_remember_me(username)) and remember_me:
                mac_address = self.clients_names[sock][0]
                self.database.update_other_users_mac_address(mac_address)
                self.database.remember_me_on(mac_address, username)
            self.messages.pop(sock)
            return ["login", "success", username] # msg[1] -> username
        else:
            # handle login failure
            self.messages.pop(sock)
            return ["login", "error", "incorrect password"]

    def handle_signup(self, username, encrypted_password, remember_me, sock):
        '''
        Handles the sign up process for a user.
        Given the username, password, and the remember_me setting, it checks if the user exists, if it doesn't, it inserts the user into the database.
        '''
        if not self.database.check_user_registered(username):
            # the username is not exists
            mac_address = self.clients_names[sock][0]
            decrypted_password = self.encryption.decrypt_data(eval(encrypted_password), self.encryption.encryption_keys[sock])
            if remember_me: # if remember me is on
                self.database.update_other_users_mac_address(mac_address)
                self.database.insert_user(username, decrypted_password, remember_me, str(mac_address))
            else: # if remember me is off
                self.database.insert_user(username, decrypted_password, remember_me, "")
            self.messages.pop(sock)
            return ["signup", "success", username] # [2] -> username
        else:
            # the username is already exists
            self.messages.pop(sock)
            return ["signup", "error"]

    def handle_database_queries(self, msg, sock):
        '''
        Handles database queries received from a client.
        '''
        if msg[1] == "check remember me status":
            # check if the user has remember me on or off
            self.messages.pop(sock)
            return self.check_remember_me(msg[2])
        
        elif msg[1] == "change remember me":
            self.change_remember_me(msg[2], msg[3], sock)
            self.messages.pop(sock)
            return ["changed remember me"]
        
        elif msg[1] == "get last score mean":
            # get last score and mean (sort numbers game)
            return self.get_last_score_mean(msg[2], sock)
        
    def handle_sorting_numbers(self, msg, sock):
        '''
        Handles sorting numbers game related messages received from a client.
        '''
        if msg[2] == "start":
            return self.start_sorting_game(sock)
        
        elif msg[2] == "check sorted numbers":
            return self.check_sorted_numbers(msg[3], sock)

        elif msg[2] == "set score":
            return self.set_score_sorting_game(msg[3], msg[4], sock)
            
    def handle_associations_game(self, msg, sock):
        '''
        Handles association game related messages received from a client.
        '''
        if msg[2] == "join":
            # join the chat if there is space (max: 5 players)
            return self.join_associations_game(msg[3], sock)
        
        elif msg[2] == "leave":
            # leave the chat
            return self.leave_associations_game(sock)
        
        elif msg[2] == "sending temp message":
            # send a temporary message in order to pass the sock.recv() function (which is blocking) in the server.py
            self.messages.pop(sock)
            return ["game", "chat", "temp message"]

        elif msg[2] == "cancel":
            # cancel the request to join the chat
            return self.cancel_associations_game(msg[3], sock)

        elif msg[2] == "send message":
            # send message in the chat
            return self.msg_associations_game(msg[3], msg[4], sock)

        elif msg[2] == "change subject":
            # change the subject in the chat every 60 seconds
            return self.change_subject(sock)

# -------------------------------------------Database Queries-----------------------------
    def check_remember_me(self, username):
        '''
        The function checks if the user has remember me on or off.
        Return: [True] if the user has remember me on, [False] if the user has remember me off.
        '''
        return [bool(self.database.check_remember_me(username))]

    def change_remember_me(self, rem_me_status, username, sock):
        '''
        A function to change the remember me status for a user.
        '''
        if rem_me_status:
            # set remember me on
            self.database.update_other_users_mac_address(self.clients_names[sock][0])
            self.database.remember_me_on(self.clients_names[sock][0], username)
        else:
            # set remember me off
            self.database.remember_me_off(username)

    def get_last_score_mean(self, username, sock):
        '''
        Gets the last score and mean for a given username.
        '''
        encryption_key = self.encryption.encryption_keys[sock]
        if self.scores.check_user_exists(username):
            # if the user exists
            score = self.scores.get_last_score(username)
            encrypted_score = self.encryption.encrypt_data(str(score).encode(), encryption_key)
            mean = self.scores.get_mean(username)
            encrypted_mean = self.encryption.encrypt_data(str(mean).encode(), encryption_key)
            self.messages.pop(sock)
            return [str(encrypted_score), str(encrypted_mean)]
        # if the user doesn't exist, send encrypted [0, 0]
        encrypted_score = self.encryption.encrypt_data(str(0).encode(), encryption_key)
        self.messages.pop(sock)
        return [str(encrypted_score), str(encrypted_score)]

# -------------------------------------------Sorting Game-----------------------------    
    def start_sorting_game(self, sock):
        '''
        generate random numbers and send them to the client
        '''
        numbers = self.sorting_numbers.generate_numbers()
        self.messages.pop(sock)
        return ["game", "sorting numbers", numbers]

    def check_sorted_numbers(self, numbers, sock):
        '''
        checks if the sorted numbers are correct
        Parameters:
            numbers (list): A list of integers representing the sorted numbers.
            sock (socket): The socket object representing the client connection.
        '''
        if self.sorting_numbers.check_sorted_numbers(numbers):
            # if correct, send success message
            self.messages.pop(sock)
            return ["game", "sorting numbers", "success"]
        self.messages.pop(sock)
        # if not correct, send fail message
        return ["game", "sorting numbers", "fail"]
    
    def set_score_sorting_game(self, username, elapsed_time, sock):
        '''
        sets the score in the database (scores.db) and sends it to the client
        '''
        score = int(((config["max_sorting_time"]-elapsed_time)/30)**2)
        if self.scores.check_user_exists(username):
            last_mean = self.scores.get_mean(username)
            new_mean = int((last_mean*config["score_coefficient"]) + (score*(1-config["score_coefficient"])))
            encrypted_score = self.encryption.encrypt_data(str(score).encode(), self.encryption.encryption_keys[sock])
            self.scores.insert_score(username, str(score), str(new_mean))
        else:
            new_mean = score
            encrypted_score = self.encryption.encrypt_data(str(score).encode(), self.encryption.encryption_keys[sock])
            self.scores.insert_score(username, str(score), str(score))
        self.messages.pop(sock)
        return ["game", "sorting numbers", "successfully set score", str(encrypted_score)]

# -------------------------------------------Associations Game-----------------------------
    def join_associations_game(self, username, sock):
        '''
        Joins the associations game chat. 
        If there is space, adds the user to the chat with their username and a score of 0.
        Updates the chat players list and flags accordingly.
        If the user is the only one in the chat, selects a random association and sends a joining message.
        If there are other users, increments the waiting count and sends a waiting message.
        '''
        if len(self.chat_players) == config["max_chat_players"]:
            # if there is no space, send error message
            self.wfc.append(username)
            self.messages.pop(sock)
            return ["game", "chat", "full chat"]
        else:
            # if there is space, join the chat
            self.chat_players[sock] = [username, 0] # updating player list that currently in the chat
            self.wfc = []
            self.chat_players_flags = len(self.chat_players)
            self.messages.pop(sock)
            if self.chat_players_flags == 1: # checks if this user is the only user that is in the chat
                index = random.randint(0, len(self.associations.keys())-1) # picks an index between 0 to num of the keys in the associations.json file
                while index == self.curr_asso_index:
                    # if the chosen index is the last index, it will choose another index untill it will be a new index
                    index = random.randint(0, len(self.associations.keys())-1) # picks an index between 0 to num of the keys in the associations.json file
                self.curr_asso_index = index
                # send joining message
                return ["game", "chat", "joining", list(self.associations.keys())[index]]
            self.waiting_for_next_round += 1
            # if there is space and the user is not the only user, send joining message of waiting for next round
            return ["game", "chat", "waiting for round"]

    def cancel_associations_game(self, username, sock):
        '''
        Cancels the joining request to the associations game for a given user.
        '''
        if username in self.wfc:
            self.wfc.remove(username) # removes the client from the waiting list
        if sock in self.chat_players:
            self.chat_players.pop(sock)
            self.chat_players_flags = len(self.chat_players)
        self.messages.pop(sock)
        return ["game", "chat", "cancel"]

    def msg_associations_game(self, username, msg, sock):
        '''
        Handles the message received in the associations game.
        '''
        if sock not in self.sent_clients:
            self.sent_clients.append(sock)
        if msg.lower() in self.used_answers:
            # if the message is already used, send error message
            self.messages.pop(sock)
            return ["game", "chat", "already used"]
        
        if msg.lower() in self.associations[list(self.associations.keys())[self.curr_asso_index]]:
            # if the message is correct, send success message
            self.chat_messages[sock] = str(username + ": " + msg)
            self.used_answers.append(msg.lower())
            self.chat_players[sock][1] += 1
            self.broadcast_message()
            self.messages.pop(sock)
            return ["game", "chat", "sent"]
        # if the message is not correct, send error message
        self.messages.pop(sock)
        return ["game", "chat", "wrong"]

    def leave_associations_game(self, sock):
        '''
        Handles leaving the associations game for the given sock (user).
        '''
        if len(self.wfc) != 0:
            # if there are waiting clients, send the first one to join the chat
            self.chat_players[sock] = [self.wfc[0], 0]
            for sock2 in self.clients_names:
                if self.clients_names[sock2][1] == self.wfc[0]:
                    sock2.send(self.message.encode_json(["game", "chat", "joining"]))
        score = self.chat_players[sock][1]
        self.chat_players.pop(sock)
        self.chat_players_flags = len(self.chat_players)
        if sock in self.not_sent_msg_clients:
            self.not_sent_msg_clients.pop(sock)
        self.messages.pop(sock)
        return ["game", "chat", "kicking client", score]
    
    def change_subject(self, sock):
        '''
        Changes the subject of the associations game to a new random association.
        '''
        self.sent_clients = []
        # waiting for all the players that are in the chat and then changing the subject
        self.chat_players_flags -= self.waiting_for_next_round
        if self.chat_players_flags > 1:
            self.chat_players_flags -= 1
            self.messages.pop(sock)
            return None
        else:
            self.chat_players_flags = len(self.chat_players)
            index = random.randint(0, len(self.associations.keys())-1) # picks an index between 0 to num of the keys in the associations.json file
            while index == self.curr_asso_index:
                # if the chosen index is the last index, it will choose another index untill it will be a new index
                index = random.randint(0, len(self.associations.keys())-1) # picks an index between 0 to num of the keys in the associations.json file
            self.curr_asso_index = index
            for s_player in self.chat_players.keys():
                if s_player != sock: # sending the message to each player in the game except the player who sent the message
                    s_player.send(self.message.encode_json(["game", "chat", "new round", list(self.associations.keys())[index]]))
            self.messages.pop(sock)
            self.waiting_for_next_round = 0
            self.used_answers = []
            return ["game", "chat", "new round", list(self.associations.keys())[index]]

#-------------------------------------------General Functions--------------------------
    def broadcast_message(self):
        '''
        The function executes when a player sends a message in the chat
        The function sends the message to each player in the chat (if he corrects) except the player who sent the message
        '''
        messages_to_remove = []
        for sender_socket in self.chat_messages:
            for chat_member_socket in self.chat_players:
                if sender_socket is chat_member_socket: # not sending the message to the player who sent the message
                    pass
                else:
                    chat_member_socket.send(self.message.encode_json(self.chat_messages[sender_socket]))
            messages_to_remove.append(sender_socket)
        
        for sender_socket in messages_to_remove:
            self.chat_messages.pop(sender_socket, None)

    def get_sock_by_username(self, username):
        '''
        The function returns the socket of the given username.
        '''
        for socket in self.clients_names:
            if self.clients_names[socket][1] == username:
                return socket

if __name__ == "__main__":
    server = Server(config["ip"], config["port"])
    server.start()
    