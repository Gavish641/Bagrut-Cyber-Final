# tkinter for the GUI
from tkinter import *
from tkinter import messagebox, scrolledtext, Checkbutton
# using my own built class "MultiThreadedClient" in order to create the client
from client import MultiThreadedClient
# haslib class for hashing the password
import hashlib
# time class & datatime for the timer in the games
import time
from datetime import datetime
# for random success message for the associations game
import random
import json
import os

# Get the directory where the current script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the client_config.json file
config_path = os.path.join(script_dir, '..', 'config.json')

# Open and read the config file
with open(config_path, 'r') as file:
    config = json.load(file)
    print(config)

# some consts, like colors...
BG_COLOR = "#212121"
EXIT_BG_COLOR = "#009e8c"
BG_COLOR_TEXT = '#d1d9eb'

class GUI:
    def __init__(self, client):
        '''
        this function initialaizes the GUI features (__init__)
        '''
        self.client = client
        self.dis_rem_me = False # disconnected_from_remembered_me
        self.used_windows = {}
        self.start_time = 0

    def first_screen(self):
        '''
        This function shows the first screen of the GUI.
        the screen contains:
        - Exit Button
        - Login Button
        - Sign Up Button
        - Some Text (like the name of the application and some guidelines)
        '''
        window = Tk()
        window.attributes('-fullscreen', True)
        window.title("Gavish's Project")
        window['background'] = BG_COLOR 

        self.used_windows["first_window"] = window

        frame_login = Frame(window, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1200, height=1010 , anchor="center")
        # laptop: width=900, height=700
        
        # Title & Subtitle
        title_name = Label(window, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.1, anchor="center")
        title_name = Label(window, text="In order to continue, please login/sign up.", font=("Goudy old style", 35, "bold"), fg="black", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.25, anchor="center")

        # Exit Button
        exit_button = Button(window, text="Exit", bd=0, font=("Goudy old style", 25), bg=EXIT_BG_COLOR, fg="white", width=8, height=1, command=lambda: self.exit(window))
        exit_button.place(relx=0.5, rely=0.9, anchor="center")

        # Login & Sign Up Buttons
        login_button = Button(window, text="Login", bd=0, font=("Goudy old style", 25), bg="#6162FF", fg="white", width=10, command=self.login_window)
        login_button.place(relx=0.347, rely=0.5)
        signup_button = Button(window, text="Sign Up", bd=0, font=("Goudy old style", 25), bg="#6162FF", fg="white", width=10, command=self.signup_window)
        signup_button.place(relx=0.56, rely=0.5)

        window.after(500, self.check_remember_me)

        window.mainloop()
    
    def check_remember_me(self):
        '''
        This function checks if the client is saved as 'remember me'.

        if the client does save as 'remember me', the server will send the client a message (["remember me", "*username*"]).
        this function checks if the server has sent this message.
        if the server has sent the message, the function will send the client to the main_screen
        '''
        if self.client.messages != [] and self.client.messages[0] == "remember me" and not self.dis_rem_me:
            self.client.username = self.client.messages[1]
            self.client.messages = []
            self.main_screen()
        
    def login_window(self):
        '''
        Initializes the login window of the GUI.
        The function handle the login process.
        '''
        login_frame = Toplevel()
        login_frame.attributes('-fullscreen', True)
        login_frame.title("login")
        login_frame['background'] = BG_COLOR

        self.used_windows["registration"] = login_frame

        frame_login = Frame(login_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1200, height=1010 , anchor="center")

        # Back & Exit Buttons
        back_button = Button(login_frame, text="Back", bd=0, font=("Goudy old style", 20), bg="grey", fg="white", width=8, height=1, command=lambda: self.back(login_frame))
        back_button.place(relx=0.72, rely=0.25)
        exit_button = Button(login_frame, text="Exit", bd=0, font=("Goudy old style", 25), bg=EXIT_BG_COLOR, fg="white", width=8, height=1, command=lambda: self.exit(login_frame))
        exit_button.place(relx=0.5, rely=0.9, anchor="center")

        # Title & Subtitle
        title_name = Label(login_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.1, anchor="center")
        title = Label(login_frame, text="Login", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.2, anchor="center")
        subtitle = Label(login_frame, text="Welcome back!", font=("Goudy old style", 25, "bold"), fg="#1d1d1d", bg=BG_COLOR_TEXT)
        subtitle.place(relx=0.25, rely=0.25)

        # Username
        lbl_user = Label(login_frame, text="Username", font=("Goudy old style", 20, "bold"), fg="grey", bg=BG_COLOR_TEXT)
        lbl_user.place(relx=0.46, rely=0.45, anchor="center")
        entry_login_username = Entry(login_frame, font=("Goudy old style", 20), bg="#E7E6E6")
        entry_login_username.place(relx=0.43, rely=0.47)

        # Password
        lbl_password = Label(login_frame, text="Password", font=("Goudy old style", 20, "bold"), fg="grey", bg=BG_COLOR_TEXT)
        lbl_password.place(relx=0.46, rely=0.55, anchor="center")
        entry_login_password = Entry(login_frame, font=("Goudy old style", 20), bg="#E7E6E6", show="*")
        entry_login_password.place(relx=0.43, rely=0.57)

        # Remember Me
        var_remember_me = BooleanVar()
        remember_me = Checkbutton(login_frame, text="Remember Me", font=("Goudy old style", 20), bg=BG_COLOR_TEXT, variable=var_remember_me)
        remember_me.place(relx=0.45, rely=0.65)
        # , font=("Ariel", 15), bg="white"

        # Submit Button
        submit = Button(login_frame, text="Login", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=lambda: self.login(entry_login_username, entry_login_password, var_remember_me))
        submit.place(relx=0.44, rely=0.7)

        def send_on_enter(event):
            submit.invoke()
        login_frame.bind('<Return>', send_on_enter) # The Submit button will be activated by pressing enter

    def login(self, entry_username, entry_password, var_remember_me):
        '''
        The function gets the enteredusername, password and the parameter of remember me and sends them to the server to login.
        The password is encrypted before sending it to the server.
        '''
        remember_me = var_remember_me.get()
        entered_username = entry_username.get()
        entered_password = entry_password.get()   
        bytes_password = entered_password.encode('utf-8')
        hashed_password = hashlib.sha256(bytes_password).digest()
        encrypted_hashed_password = self.client.encryption.encrypt_data(hashed_password)
        self.client.messages = []
        self.client.send_message(["login", entered_username, str(encrypted_hashed_password), remember_me])
        while self.client.messages == []:
            pass # waiting till the client receives data after his signup request
        if self.client.messages[1] == "success":
            while self.client.username == "":
                pass # waiting till the client receives data from the server after his signup request
            self.client.messages = []
            self.main_screen()
        else:
            self.used_windows["first_window"].iconify() # keeps the login screen
            if self.client.messages[2] == "no user exists":
                messagebox.showwarning("Login Failed!", "Could not find username: " +  entered_username)
            elif self.client.messages[2] == "user already logged in":
                messagebox.showwarning("Login Failed!", "This user is already logged in")
            else:
                messagebox.showwarning("Login Failed!", "The password does not match")
            self.client.messages = []

    def signup_window(self):
        '''
        Initializes the sign up window of the GUI.
        The function handle the sign up process.
        '''
        sign_up_frame = Toplevel()
        sign_up_frame.attributes('-fullscreen', True)
        sign_up_frame.title("sign up")
        sign_up_frame['background'] = BG_COLOR

        self.used_windows["registration"] = sign_up_frame

        frame_login = Frame(sign_up_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1200, height=1010 , anchor="center")

        # Back & Exit Buttons
        back_button = Button(sign_up_frame, text="Back", bd=0, font=("Goudy old style", 20), bg="grey", fg="white", width=8, height=1, command=lambda: self.back(sign_up_frame))
        back_button.place(relx=0.72, rely=0.25)
        exit_button = Button(sign_up_frame, text="Exit", bd=0, font=("Goudy old style", 25), bg=EXIT_BG_COLOR, fg="white", width=8, height=1, command=lambda: self.exit(sign_up_frame))
        exit_button.place(relx=0.5, rely=0.9, anchor="center")

        # Title & Subtitle
        title_name = Label(sign_up_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.1, anchor="center")
        title = Label(sign_up_frame, text="Sign Up", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.2, anchor="center")
        subtitle = Label(sign_up_frame, text="Welcome!", font=("Goudy old style", 25, "bold"), fg="#1d1d1d", bg=BG_COLOR_TEXT)
        subtitle.place(relx=0.25, rely=0.25)

        # Username
        lbl_user = Label(sign_up_frame, text="Username", font=("Goudy old style", 20, "bold"), fg="grey", bg=BG_COLOR_TEXT)
        lbl_user.place(relx=0.46, rely=0.45, anchor="center")
        entry_login_username = Entry(sign_up_frame, font=("Goudy old style", 20), bg="#E7E6E6")
        entry_login_username.place(relx=0.43, rely=0.47)

        # Password
        lbl_password = Label(sign_up_frame, text="Password", font=("Goudy old style", 20, "bold"), fg="grey", bg=BG_COLOR_TEXT)
        lbl_password.place(relx=0.46, rely=0.55, anchor="center")
        entry_login_password = Entry(sign_up_frame, font=("Goudy old style", 20), bg="#E7E6E6", show="*")
        entry_login_password.place(relx=0.43, rely=0.57)

        # Remember Me
        var_remember_me = BooleanVar()
        remember_me = Checkbutton(sign_up_frame, text="Remember Me", font=("Goudy old style", 20), bg=BG_COLOR_TEXT, variable=var_remember_me)
        remember_me.place(relx=0.45, rely=0.65)

        # Submit Button
        submit = Button(sign_up_frame, text="Sign Up", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=lambda: self.sign_up(entry_login_username, entry_login_password, var_remember_me))
        submit.place(relx=0.44, rely=0.7)

        def send_on_enter(event):
            submit.invoke()

        sign_up_frame.bind('<Return>', send_on_enter)

    def sign_up(self, entry_username, entry_password, var_remember_me):
        '''
        The function gets the entered username, password and the parameter of remember me and sends them to the server to sign up.
        There is a check if the password has at least 8 characters.
        The password is encrypted before sending it to the server.
        '''
        entered_username = entry_username.get()
        entered_password = entry_password.get()
        remember_me = var_remember_me.get()
        if len(entered_username) == 0:
            # the username cannot be empty
            self.used_windows["first_window"].iconify() # keeps the signup screen
            messagebox.showwarning("Sign Up Failed!", "Please enter a username")
        elif len(entered_username) > 20:
            # the username must be less than 20 characters
            self.used_windows["first_window"].iconify() # keeps the signup screen
            messagebox.showwarning("Sign Up Failed!", "Your username has to be less than 20 characters")
        else:
            if len(entered_password) < 8:
                # the password must be longer than 7 characters and must include special characters
                self.used_windows["first_window"].iconify() # keeps the signup screen
                messagebox.showwarning("Sign Up Failed!", "Your password has to be longer than 7 characters")
            else:
                bytes_password = entered_password.encode('utf-8')
                hashed_password = hashlib.sha256(bytes_password).digest()
                encrypted_hashed_password = self.client.encryption.encrypt_data(hashed_password)
                self.client.messages = []
                self.client.send_message(["signup", entered_username, str(encrypted_hashed_password), remember_me])
                while self.client.messages == []:
                    pass # waiting till the client receives data after his signup request
                if self.client.messages[1] == "success":
                    while self.client.username == "":
                        pass # waiting till the client receives data after his signup request
                    self.client.messages = []
                    self.main_screen()
                else:
                    self.used_windows["first_window"].iconify() # keeps the signup screen
                    messagebox.showwarning("Sign Up Failed!", "This username is already exists")
                    self.client.messages = []

    def main_screen(self):
        '''
        Creates the main screen GUI for the LuminaMentia application.
        This function initializes the main screen GUI for the LuminaMentia application. 
        The GUI includes buttons for: 
        - exiting the application
        - disconnecting from the account
        - accessing settings
        - playing the Sorting Numbers game
        - playing the association game
        - viewing the user's score
        - accessing the guidelines
        '''
        main_frame = Tk()
        main_frame['background'] = BG_COLOR
        main_frame.attributes('-fullscreen', True)
        main_frame.title("LuminaMentia Main")

        if "registration" in self.used_windows:
            self.used_windows["registration"].destroy()
        if "first_window" in self.used_windows:
            self.used_windows["first_window"].destroy()

        frame_login = Frame(main_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        # Exit Button
        exit_button = Button(main_frame, text="Exit", bd=0, font=("Goudy old style", 25), bg=EXIT_BG_COLOR, fg="white", width=8, height=1, command=lambda: self.exit(main_frame))
        exit_button.place(relx=0.5, rely=0.9, anchor="center")

        # Title & Username
        title_name = Label(main_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")

        title = Label(main_frame, text="Main", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.21, anchor="center")

        username = Label(main_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")
        games_text = Label(main_frame, text="Games:", font=("Impact", 28, "bold"), fg="black", bg=BG_COLOR_TEXT)
        games_text.place(relx=0.5, rely=0.43, anchor="center")

        # Disconnect button
        back_button = Button(main_frame, text="Disconnect", bd=0, font=("Ariel", 15), bg="grey", fg="white", width=9, height=0, command=lambda: self.disconnect(main_frame))
        back_button.place(relx=0.73, rely=0.12)

        # Settings
        sorting_numbers_button = Button(main_frame, text="Settings", bd=0, font=("Goudy old style", 17), bg="grey", fg="white", width=15, command=self.settings)
        sorting_numbers_button.place(relx=0.2, rely=0.12, anchor="center")

        # Sorting Numbers Game
        sorting_numbers_button = Button(main_frame, text="Sort Numbers", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=self.sorting_numbers)
        sorting_numbers_button.place(relx=0.5, rely=0.5, anchor="center")

        # Chat
        chat_button = Button(main_frame, text="Associations Game", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=self.associations)
        chat_button.place(relx=0.5, rely=0.6, anchor="center")

        # Score
        chat_button = Button(main_frame, text="Score", bd=0, font=("Goudy old style", 17), bg="#009e8c", fg="white", width=15, command=self.score)
        chat_button.place(relx=0.8, rely=0.5, anchor="center")

        # Guide Screen
        guide_button = Button(main_frame, text="Help", bd=0, font=("Goudy old style", 17), bg="#009e8c", fg="white", width=15, command=self.help_screen)
        guide_button.place(relx=0.2, rely=0.5, anchor="center")

# --------------------------------------------Guidelines-----------------
    def help_screen(self):
        """
        This function displays the LuminaMentia guidelines screen.
        It sets up the guidelines for the LuminaMentia application (games, score, settings).
        """
        guidelines_frame = Tk()
        guidelines_frame['background'] = BG_COLOR
        guidelines_frame.attributes('-fullscreen', True)
        guidelines_frame.title("LuminaMentia Guidelines")

        self.used_windows["game"] = guidelines_frame

        white_frame = Frame(guidelines_frame, bg=BG_COLOR_TEXT)
        white_frame.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        title = Label(guidelines_frame, text="Help", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.21, anchor="center")

        # Title & Username
        title_name = Label(guidelines_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(guidelines_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")

        # Sort Numbers Guidelines
        sort_numbers_guidelines = Label(guidelines_frame, text="Sort Numbers:", font=("Goudy old style", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        sort_numbers_guidelines.place(relx=0.7, rely=0.3, anchor="center")
        sort_numbers_explain = Label(guidelines_frame, text="Sort the given five numbers from the lowest to the highest.", font=("Goudy old style", 17, "bold"), justify="left", fg="black", bg=BG_COLOR_TEXT)
        sort_numbers_explain.place(relx=0.7, rely=0.35, anchor="center")

        # Associations Game Guidelines
        associations_guidelines = Label(guidelines_frame, text="Associations Game: ", font=("Goudy old style", 25, "bold"), anchor="e", fg="black", bg=BG_COLOR_TEXT)
        associations_guidelines.place(relx=0.7, rely=0.55, anchor="center")
        associations_explain = Label(guidelines_frame, text="State as many members (associations) as you can of the given group (subject).\nEach participant states a new member of the given group.\nWhen time is up, a new subject will be given.\nFor example:\nGroup:\"Fruits\" Members: \"Strawberry\", \"Cranberry\", \"Blueberry\", \"Peach\".", font=("Goudy old style", 17, "bold"), justify="left", fg="black", bg=BG_COLOR_TEXT)
        associations_explain.place(relx=0.71, rely=0.65, anchor="center")

        # Settings Guidelines
        settings_guidelines = Label(guidelines_frame, text="Settings:", font=("Goudy old style", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        settings_guidelines.place(relx=0.3, rely=0.3, anchor="center")
        settings_explain = Label(guidelines_frame, text="Click the \"Settings\" button to change the \"Remember me\" setting.", font=("Goudy old style", 17, "bold"), justify="left", fg="black", bg=BG_COLOR_TEXT)
        settings_explain.place(relx=0.3, rely=0.35, anchor="center")

        # Score Guidelines
        score_guidelines = Label(guidelines_frame, text="Score:", font=("Goudy old style", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        score_guidelines.place(relx=0.3, rely=0.55, anchor="center")
        score_explain = Label(guidelines_frame, text="Click the \"Score\" button to view your current score, mean score and feedback.", font=("Goudy old style", 17, "bold"), justify="left", fg="black", bg=BG_COLOR_TEXT)
        score_explain.place(relx=0.3, rely=0.6, anchor="center")

        # Back
        back_button = Button(guidelines_frame, text="Back", bd=0, font=("Goudy old style", 15), bg="grey", fg="white", width=8, height=1, command=lambda: self.back(guidelines_frame))
        back_button.place(relx=0.17, rely=0.095)

# --------------------------------------------Settings----------------
    def settings(self):
        '''
        This function displays the LuminaMentia settings screen.
        In the settings screen, the user can change the remember me setting.
        '''
        settings_frame = Tk()
        settings_frame['background'] = BG_COLOR
        settings_frame.attributes('-fullscreen', True)
        settings_frame.title("LuminaMentia Settings")

        self.used_windows["game"] = settings_frame

        white_frame = Frame(settings_frame, bg=BG_COLOR_TEXT)
        white_frame.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        title = Label(settings_frame, text="Settings", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.21, anchor="center")

        # Title & Username
        title_name = Label(settings_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(settings_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")

        # Change Remember Me
        remember_me_status = str(self.check_remember_me_on())
        title_name = Label(settings_frame, text="Remember Me: " + remember_me_status, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.5, anchor="center")
        chat_button = Button(settings_frame, text="Click To Change", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=lambda: self.change_remember_me(self.check_remember_me_on(), title_name))
        chat_button.place(relx=0.5, rely=0.55, anchor="center")

        # Back
        back_button = Button(settings_frame, text="Back", bd=0, font=("Goudy old style", 15), bg="grey", fg="white", width=8, height=1, command=lambda: self.back(settings_frame))
        back_button.place(relx=0.17, rely=0.095)

    def check_remember_me_on(self):
        '''
        This function checks if the user has remember me on or off.
        The function sends a request to the server and waits for a response.
        Return: True if the user has remember me on, False if the user has remember me off.
        '''
        self.client.messages = []
        self.client.send_message(["database", "check remember me status", self.client.username])
        while self.client.messages == []:
            pass
        return self.client.messages[0]

    def change_remember_me(self, remember_me_status, title_name):
        self.client.send_message(["database", "change remember me", not remember_me_status, self.client.username])
        title_name.config(text="Remember Me: " + str(bool(not bool(remember_me_status))))

    def score(self):
        '''
        This function displays the LuminaMentia Score screen.
        In the score screen, the user can view their last score, mean and a verbal feedback on his medical condition.
        '''
        score_frame = Tk()
        score_frame['background'] = BG_COLOR
        score_frame.attributes('-fullscreen', True)
        score_frame.title("LuminaMentia Score")

        self.used_windows["game"] = score_frame

        white_frame = Frame(score_frame, bg=BG_COLOR_TEXT)
        white_frame.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        title = Label(score_frame, text="Score Status", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.21, anchor="center")

        # Title & Username
        title_name = Label(score_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(score_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")

        # Back
        back_button = Button(score_frame, text="Back", bd=0, font=("Goudy old style", 15), bg="grey", fg="white", width=8, height=1, command=lambda: self.back(score_frame))
        back_button.place(relx=0.17, rely=0.095)

        last_score_title = Label(score_frame, text="Last Score:", font=("Impact", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        last_score_title.place(relx=0.4, rely=0.5, anchor="center")
        
        last_score_text = Label(score_frame, text=0, font=("Impact", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        last_score_text.place(relx=0.4, rely=0.6, anchor="center")

        mean_title = Label(score_frame, text="Mean:", font=("Impact", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        mean_title.place(relx=0.6, rely=0.5, anchor="center")
        
        mean_title_text = Label(score_frame, text=0, font=("Impact", 25, "bold"), fg="black", bg=BG_COLOR_TEXT)
        mean_title_text.place(relx=0.6, rely=0.6, anchor="center")

        status_rectangle = Canvas(score_frame, width=600, height=50, bg="white", )
        status_rectangle.place(relx=0.5, rely=0.8, anchor="center")
        rectangle_id = status_rectangle.create_rectangle(2, 2, 601, 51, fill="white", outline="black")
        text_id = status_rectangle.create_text(301, 25, text="Initial", fill="black", font=('Impact', 20, 'bold'))  # Center text in the rectangle

        score_frame.after(1, self.get_last_score_mean(last_score_text, mean_title_text, status_rectangle, rectangle_id, text_id))
    
    def get_last_score_mean(self, last_score_text, mean_title_text, status_rectangle, rectangle_id, text_id):
        self.client.messages = []
        self.client.send_message(["database", "get last score mean", self.client.username])
        while self.client.messages == []:
            pass
        last_encrypted_score = eval(self.client.messages[0])
        last_decrypted_score = self.client.encryption.decrypt_data(last_encrypted_score)
        mean_encrypted_details = eval(self.client.messages[1])
        last_decrypted_mean = self.client.encryption.decrypt_data(mean_encrypted_details)
        if int(last_decrypted_score) - int(last_decrypted_mean) > config["low_diffrence"]: 
            # if the score is greater than the mean by more than 5
            status_rectangle.itemconfig(rectangle_id, fill="green", outline="black")
            status_rectangle.itemconfig(text_id, text="Great !", fill="white")
        elif int(last_decrypted_mean) - int(last_decrypted_score) > config["low_diffrence"] and int(last_decrypted_mean) - int(last_decrypted_score) < config["high_diffrence"]:
            # if the mean is greater than the score by more than 5 but less than 10
            status_rectangle.itemconfig(rectangle_id, fill="yellow", outline="black")
            status_rectangle.itemconfig(text_id, text="Retrograde", fill="black")
        elif int(last_decrypted_mean) - int(last_decrypted_score) > config["high_diffrence"]:
            status_rectangle.itemconfig(rectangle_id, fill="red", outline="black")
            status_rectangle.itemconfig(text_id, text="Bad", fill="black")
        else:
            status_rectangle.itemconfig(rectangle_id, fill="white", outline="black")
            status_rectangle.itemconfig(text_id, text="Stable", fill="black")
        last_score_text.config(text=last_decrypted_score)
        mean_title_text.config(text=last_decrypted_mean)
        self.client.messages = []

# --------------------------------------------Soring Game------------------
    def sorting_numbers(self):
        """
        Create a window to display the sorting numbers game GUI, including labels, buttons, and user input fields.
        Given 5 numbers, the user needs to sort the given numbers from lowest to highest.
        """
        sorting_numbers_frame = Tk()
        sorting_numbers_frame['background'] = BG_COLOR
        sorting_numbers_frame.attributes('-fullscreen', True)
        sorting_numbers_frame.title("LuminaMentia Sorting Numbers")

        self.used_windows["game"] = sorting_numbers_frame

        frame_login = Frame(sorting_numbers_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        # Title & Username
        title_name = Label(sorting_numbers_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(sorting_numbers_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")

        self.start_time = time.time()
        self.update_timer()
        self.client.messages = []
        self.client.send_message(["game", "sorting numbers", "start"])
        while self.client.messages == []:
            pass

        numbers_to_sort = self.client.messages[2]
        task_label = Label(sorting_numbers_frame, text=f"Sort the numbers: {numbers_to_sort}", font=("Ariel", 30, "bold"), fg="black", bg=BG_COLOR_TEXT)
        task_label.place(relx=0.5, rely=0.40, anchor="center")
        entry_numbers = Entry(sorting_numbers_frame, font=("Goudy old style", 20), bg="#E7E6E6")
        entry_numbers.place(relx=0.5, rely=0.45, anchor="center")
        entry_numbers.focus_force()

        # Check sorting button
        sort_button = Button(sorting_numbers_frame, text="Check Sorting", bd=0, font=("Goudy old style", 20), bg="#6162FF", fg="white", width=15, command=lambda: self.check_sorting(entry_numbers))
        sort_button.place(relx=0.44, rely=0.5)

        def send_on_enter(event):
            sort_button.invoke()

        sorting_numbers_frame.bind('<Return>', send_on_enter)

        sorting_numbers_frame.after(1000, self.update_timer)
    
    def update_timer(self):
        '''
        Performs the update of the timer display in the game window.
        If the timer is running and has not reached the limit, updates the elapsed time display by subtracting 1000 milliseconds (1 sec).
        If the elapsed time reaches the limit (5 minutes), shows a message indicating the end of the game.
        After each second, updates the timer display by calling the update_timer method recursively.
        '''
        if self.start_time is not None:
            elapsed_time = int(time.time() - self.start_time)
            timer_label = Label(self.used_windows["game"], text=f"Time: {datetime.utcfromtimestamp(elapsed_time).strftime('%M:%S')}", font=("Ariel", 25), fg="black", bg=BG_COLOR_TEXT)
            timer_label.place(relx=0.2, rely=0.2)

            if elapsed_time >= config["max_sorting_time"]:  # 5 minutes (300 seconds)
                self.start_time = None  # stops the timer
                self.client.send_message(["game", "sorting numbers", "set score", self.client.username, elapsed_time])
                while self.client.messages == []:
                    pass
                messagebox.showinfo("Time's Up!", "You took too long! Game Over. \n Your score: " + str(0))
                self.used_windows["game"].destroy()  # destroy the sorting game frame after clicking ok on the messagebox
                self.used_windows.pop("game")

            else:
                # Call the update_timer method again after 1000 milliseconds
                self.used_windows["game"].after(1000, self.update_timer)

    def check_sorting(self, entry_numbers):
        '''
        The function sends the entered numbers to the server to check if they are sorted correctly.
        If the numbers are not sorted correctly, it shows an error message.
        If the numbers are sorted correctly, it shows a success message with the player's score and destroys the sorting game frame.
        '''
        if entry_numbers.get() == "" or not entry_numbers.get().isdigit():
            messagebox.showerror("Error", "Please enter a number!")
        else:
            self.client.messages = []
            self.client.send_message(["game", "sorting numbers", "check sorted numbers", entry_numbers.get(), self.client.username])
            while self.client.messages == []:
                pass
            if self.client.messages[2] == "success":
                self.used_windows["game"].deiconify()            
                elapsed_time = int(time.time() - self.start_time)
                self.start_time = None # stops the timer
                self.client.messages = []
                self.client.send_message(["game", "sorting numbers", "set score", self.client.username, elapsed_time])
                while self.client.messages == []:
                    pass
                encrypted_score = eval(self.client.messages[3])
                decrypted_score = self.client.encryption.decrypt_data(encrypted_score)
                messagebox.showinfo("Congratulations", "You sorted the numbers correctly! \n Your Grade: " + (str(int(decrypted_score))))
                self.used_windows["game"].destroy()  # destroy the sorting game frame after clicking ok on the messagebox
                self.used_windows.pop("game")
                
                # add a function that set the score into the database
                
            else:
                self.client.messages = []
                self.used_windows["game"].deiconify()
                messagebox.showerror("Incorrect Sorting", "Try again! The numbers are not sorted correctly.")


# -------------------------------------------Multi Player Game-------------
    def associations(self):
        '''
        The function sends a request to the server to join the associations game.
        A function to handle different chat scenarios based on the messages received from the server.
        It manages joining the game, waiting for the chat to start, and sending temporary messages in the chat.
        '''
        self.client.messages = []
        self.client.send_message(["game", "chat", "join", self.client.username])
        while self.client.messages == []:
            pass
        if self.client.messages[2] == "full chat":
            self.client.messages = []
            self.waiting_for_chat()

        elif self.client.messages[2] == "waiting for round":
            self.waiting_for_new_round()

        elif self.client.messages[2] == "joining":
            subject = self.client.messages[3]
            self.client.connect_to_chat()
            self.client.send_message(["game", "chat", "sending temp message"])
            while self.client.messages == []:
                pass
            self.client.messages = []
            self.create_chat(subject)
        
    def waiting_for_chat(self):
        '''
        A waiting screen for player to leave the game because the game is full (5 players).
        '''
        wfc_frame = Tk()
        wfc_frame['background'] = BG_COLOR
        wfc_frame.attributes('-fullscreen', True)
        wfc_frame.title("LuminaMentia Associations")

        self.used_windows["game"] = wfc_frame

        frame_login = Frame(wfc_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        # Title & Username
        title_name = Label(wfc_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(wfc_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.8, rely=0.1)

        title_name = Label(wfc_frame, text="Waiting For Another Player...", font=("Impact", 35, "bold"), fg="black", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.5, anchor="center")

        cancel_button = Button(wfc_frame, text="Cancel", bd=0, font=("Goudy old style", 15), bg="#6162FF", fg="white", width=15, command=self.cancel_chat)
        cancel_button.place(relx=0.5, rely=0.7, anchor="center")


        wfc_frame.after(1000, self.check_player)

    def waiting_for_new_round(self):
        '''
        A waiting screen for new round to start.
        '''
        wfn_frame = Tk()
        wfn_frame['background'] = BG_COLOR
        wfn_frame.attributes('-fullscreen', True)
        wfn_frame.title("LuminaMentia Associations")

        self.used_windows["game"] = wfn_frame

        frame_login = Frame(wfn_frame, bg=BG_COLOR_TEXT)
        frame_login.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        # Title & Username
        title_name = Label(wfn_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(wfn_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.8, rely=0.1)

        title_name = Label(wfn_frame, text="You Will Enter To The Game In The Next Round (max waiting time: 60 secs)...", font=("Impact", 30, "bold"), fg="black", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.5, anchor="center")

        title = Label(wfn_frame, text="Waiting For A New Round", font=("Impact", 40, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        title.place(relx=0.5, rely=0.21, anchor="center")

        cancel_button = Button(wfn_frame, text="Cancel", bd=0, font=("Goudy old style", 25), bg="#6162FF", fg="white", width=15, command=self.cancel_chat)
        cancel_button.place(relx=0.5, rely=0.7, anchor="center")
        self.client.messages = []
        wfn_frame.after(1000, self.check_round_started)

    def check_round_started(self):
        '''
        The function checks if a new round has started.
        '''
        if self.client.messages != []:
            if self.client.messages[2] == "new round":
                subject = self.client.messages[3]
                self.client.messages = []
                self.used_windows["game"].destroy()
                self.used_windows.pop("game")
                self.client.connect_to_chat()
                self.client.send_message(["game", "chat", "sending temp message"])
                while self.client.messages == []:
                    pass
                self.client.messages = []
                self.create_chat(subject)
        else:
            self.used_windows["game"].after(1000, self.check_round_started)

    def cancel_chat(self):
        '''
        The function cancels the request to join the game (in the waiting_for_chat() function).
        '''
        self.client.messages = []
        self.client.send_message(["game", "chat", "cancel", self.client.username])
        while self.client.messages == []:
            pass
        self.used_windows["game"].destroy()
        self.used_windows.pop("game")

    def check_player(self):
        '''
        The function checks recursively if a player has left the game.
        '''
        if self.client.found_player:
            self.waiting_for_new_round()
        else:
            self.used_windows["game"].after(1000, self.check_player)

    def create_chat(self, subject):
        '''
        The function creates the associations game chat GUI.
        It sets up the chat and displays the subject of the game.
        '''
        self.client.found_player = False

        chat_frame = Tk()
        chat_frame.attributes('-fullscreen', True)
        chat_frame['background'] = BG_COLOR
        chat_frame.title("Game Chat")
        frame_chat = Frame(chat_frame, bg=BG_COLOR_TEXT)
        frame_chat.place(relx=0.5, rely=0.5, width=1600, height=1000 , anchor="center")

        self.used_windows["game"] = chat_frame
        self.start_chat_time = time.time()

        # Title & Username
        title_name = Label(chat_frame, text="LuminaMentia", font=("Impact", 80, "bold"), fg="#009e8c", bg=BG_COLOR_TEXT)
        title_name.place(relx=0.5, rely=0.12, anchor="center")
        username = Label(chat_frame, text="Hello " + self.client.username, font=("Goudy old style", 20, "bold"), fg="black", bg=BG_COLOR_TEXT)
        username.place(relx=0.75, rely=0.1, anchor="center")

        text_area = scrolledtext.ScrolledText(chat_frame, wrap=WORD, width=100, height=20, state="disabled", font=("Goudy old style", 15))      
        text_area.place(relx=0.5, rely=0.5, anchor="center")

        subject_text = Label(chat_frame, text=subject, font=("Impact", 30, "bold"), fg="#6162FF", bg=BG_COLOR_TEXT)
        subject_text.place(relx=0.5, rely=0.24, anchor="center")

        self.update_chat_timer(subject_text, text_area, 60)

        message_entry = Entry(chat_frame, width=40, font=("Goudy old style", 20))
        message_entry.place(relx=0.5, rely=0.85, anchor="center")
        message_entry.focus_force()

        send_button = Button(chat_frame, text="Send", font=("Goudy old style", 13), bg="#6162FF", fg="white", command=lambda: self.send_message(message_entry, text_area))
        send_button.place(relx=0.65, rely=0.83)


        def send_on_enter(event):
            send_button.invoke()

        chat_frame.bind('<Return>', send_on_enter) # pressing enter will send the message

        leave_button = Button(chat_frame, text="Leave", bd=0, font=("Goudy old style", 20), bg=EXIT_BG_COLOR, fg="white", width=15, command=self.leave_chat)
        leave_button.place(relx=0.5, rely=0.9, anchor="center")

        chat_frame.after(1000, lambda: self.update_chat_messages(text_area))
    
    def update_chat_timer(self, subject_text, text_area, remaining_time=60):
        '''
        The function updates the timer on the associations game window.
        if the timer reaches 0, the round will end the server will send a new subject for the next round.
        '''
        if remaining_time > 0:
            timer_label = Label(self.used_windows["game"], text=f"Time: {datetime.utcfromtimestamp(remaining_time).strftime('%M:%S')}", font=("Arial", 15), fg="black", bg=BG_COLOR_TEXT)
            timer_label.place(relx=0.2, rely=0.16)
            self.used_windows["game"].after(1000, self.update_chat_timer, subject_text, text_area, remaining_time - 1)
        
        else:
            self.client.chat_messages = []
            self.client.new_subject = ""
            self.client.send_message(["game", "chat", "change subject"])
            while self.client.new_subject == "":
                pass
            timer_label = Label(self.used_windows["game"], text=f"Time: {datetime.utcfromtimestamp(remaining_time).strftime('%M:%S')}", font=("Arial", 15), fg="black", bg=BG_COLOR_TEXT)
            timer_label.place(relx=0.2, rely=0.16)
            if self.client.new_subject == "kicking client":
                messagebox.showinfo("Your got kicked !", "You got " + str(self.client.chat_messages[0][3]) + " correct answers!")
                self.client.leave_chat()
                self.client.chat_messages = []
                self.client.send_message(["game", "chat", "sending temp message"])
                while self.client.messages == []:
                    pass
                self.used_windows["game"].destroy()
                self.used_windows.pop("game")
                self.client.chat_messages = []

            else:
                text_area.config(state="normal") # Enable text editing
                text_area.insert(END, "Server: New Subject - " + self.client.new_subject + "\n", "new_subject") # Insert text 
                text_area.tag_config("new_subject", foreground="blue") # Set text color
                text_area.see(END) # Scroll to the end
                text_area.config(state="disable") # Disable text editing

                subject_text.config(text=self.client.new_subject)
                self.client.new_subject = ""
                self.used_windows["game"].after(1000, self.update_chat_timer, subject_text, text_area, 60)

    def update_chat_messages(self, text_area):
        '''
        Updates the chat messages in the given text area by iterating through the chat messages stored in the client object.
        The function handle the cases: "temp message", "kicking client", "new round" or "sent".
        '''
        if self.client.chat_messages != []:
            for msg in self.client.chat_messages:
                if msg[2] and (msg[2] == "temp message" or msg[2] == "kicking client" or msg[2] == "new round" or msg[2] == "sent"):
                    self.client.chat_messages.remove(msg)
                else:
                    text_area.config(state="normal")
                    text_area.insert(END, msg + "\n")
                    text_area.see(END)
                    text_area.config(state="disable")
                    self.client.chat_messages.remove(msg)
        self.used_windows["game"].after(1000, lambda: self.update_chat_messages(text_area))

    def send_message(self, message_entry, text_area):
        '''
        The function sends the entered message to the server.
        The function also handles the case of "already used" or a correct answer for the messages.
        '''
        message = message_entry.get()
        if len(message) > 0:
            message_entry.delete(0, 'end') # empty the text entry
            self.client.send_message(["game", "chat", "send message", self.client.username, message])
            text_area.config(state="normal")
            text_area.insert(END, str(self.client.username + ": " + message + "\n"))
            text_area.see(END)
            text_area.config(state="disable")
            while self.client.chat_messages == []:
                pass
            if self.client.chat_messages[0][2] == "already used":
                text_area.config(state="normal")
                text_area.insert(END, str("Server" + ": " + "It Already Used !" + "\n"), "already_used_color")
                text_area.tag_config("already_used_color", foreground="red")
                text_area.see(END)
                text_area.config(state="disable")
            elif self.client.chat_messages[0][2] == "sent":
                text_area.config(state="normal")
                index = random.randint(0, len(config["SUCCESS_MESSAGES"]) - 1)
                success_msg = config["SUCCESS_MESSAGES"][index]
                text_area.insert(END, str("Server" + ": " + success_msg + "\n"), "worked_color")
                text_area.tag_config("worked_color", foreground="green")
                text_area.see(END)
                text_area.config(state="disable")
            if len(self.client.chat_messages) > 1:
                # Remove the first list
                self.client.chat_messages = self.client.chat_messages[1:]
            else:
                self.client.chat_messages = []
    
    def leave_chat(self):
        '''
        The function handles leaveing the chat.
        The function sends a message to the server.
        The server sends a message to the client with the number of his correct answers.
        '''
        self.client.chat_messages = []
        self.client.send_message(["game", "chat", "leave", self.client.username])
        while self.client.chat_messages == []:
            pass
        messagebox.showinfo("Exiting Chat", "You got " + str(self.client.chat_messages[0][3]) + " correct answers!")
        self.client.leave_chat()
        self.client.send_message(["game", "chat", "sending temp message"])
        while self.client.chat_messages == []:
            pass
        self.client.messages = []
        self.used_windows["game"].destroy()
        self.used_windows.pop("game")
        self.client.chat_messages = []

# -------------------------------------------General GUI Functions---------
    def exit(self, window):
        '''
        The function handles the exit of the program.
        '''
        if window.master:
            window.master.destroy()
        else:
            window.destroy()
        self.client.disconnect()

    def back(self, window):
        '''
        The function closes the currect window and opens the previous one.
        '''
        self.used_windows["registration"] = None
        window.destroy()
        if window.master and isinstance(window.master, Tk):
            window.master.deiconify() # keeps the first screen

    def disconnect(self, window):
        '''
        The function disconnects the client from the account and calling the first screen for registration.
        '''
        window.destroy()
        if "registration" in self.used_windows:
            self.used_windows["registration"] = None  
        self.client.username = ""
        self.dis_rem_me = True
        self.first_screen()
        

if __name__ == '__main__':
    client = MultiThreadedClient(config["ip"], config["port"]) # creates a new client
    client.client_thread.start() # starts the client
    app = GUI(client) # creates a new GUI
    app.first_screen() # calls the first screen of the GUI