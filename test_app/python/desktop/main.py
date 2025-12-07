import customtkinter
import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "http://localhost:8000")

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Login App")
        self.geometry("500x400")
        self.token = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.show_login()

    def show_login(self):
        self.clear_frames()
        self.login_frame = LoginFrame(self)
        self.login_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def show_profile(self):
        self.clear_frames()
        self.profile_frame = ProfileFrame(self)
        self.profile_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")

    def clear_frames(self):
        for widget in self.winfo_children():
            widget.destroy()

    def login_success(self, token):
        self.token = token
        self.show_profile()

    def logout(self):
        self.token = None
        self.show_login()

class LoginFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        
        self.grid_columnconfigure(0, weight=1)

        self.label = customtkinter.CTkLabel(self, text="Login", font=("Arial", 24))
        self.label.grid(row=0, column=0, padx=20, pady=20)

        self.username_entry = customtkinter.CTkEntry(self, placeholder_text="Username")
        self.username_entry.grid(row=1, column=0, padx=20, pady=10)

        self.password_entry = customtkinter.CTkEntry(self, placeholder_text="Password", show="*")
        self.password_entry.grid(row=2, column=0, padx=20, pady=10)

        self.login_button = customtkinter.CTkButton(self, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, padx=20, pady=20)

        self.status_label = customtkinter.CTkLabel(self, text="")
        self.status_label.grid(row=4, column=0, padx=20, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            response = requests.post(f"{API_URL}/token", data={"username": username, "password": password})
            if response.status_code == 200:
                token = response.json().get("access_token")
                self.status_label.configure(text="Login Successful!", text_color="green")
                self.master.login_success(token)
            else:
                self.status_label.configure(text="Login Failed", text_color="red")
        except requests.exceptions.ConnectionError:
             self.status_label.configure(text="Connection Error", text_color="red")

class ProfileFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        
        self.label = customtkinter.CTkLabel(self, text="Profile", font=("Arial", 24))
        self.label.grid(row=0, column=0, padx=20, pady=20)

        self.username_label = customtkinter.CTkLabel(self, text="Username: Loading...")
        self.username_label.grid(row=1, column=0, padx=20, pady=5)

        self.fullname_entry = customtkinter.CTkEntry(self, placeholder_text="Full Name")
        self.fullname_entry.grid(row=2, column=0, padx=20, pady=10)

        self.email_entry = customtkinter.CTkEntry(self, placeholder_text="Email")
        self.email_entry.grid(row=3, column=0, padx=20, pady=10)

        self.save_button = customtkinter.CTkButton(self, text="Save Changes", command=self.save_profile)
        self.save_button.grid(row=4, column=0, padx=20, pady=20)

        self.logout_button = customtkinter.CTkButton(self, text="Logout", command=self.master.logout, fg_color="red")
        self.logout_button.grid(row=5, column=0, padx=20, pady=10)

        self.status_label = customtkinter.CTkLabel(self, text="")
        self.status_label.grid(row=6, column=0, padx=20, pady=10)

        self.load_profile()

    def load_profile(self):
        headers = {"Authorization": f"Bearer {self.master.token}"}
        try:
            response = requests.get(f"{API_URL}/users/me", headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.username_label.configure(text=f"Username: {data.get('username')}")
                if data.get('full_name'):
                    self.fullname_entry.insert(0, data.get('full_name'))
                if data.get('email'):
                    self.email_entry.insert(0, data.get('email'))
            else:
                self.status_label.configure(text="Failed to load profile", text_color="red")
        except requests.exceptions.ConnectionError:
            self.status_label.configure(text="Connection Error", text_color="red")

    def save_profile(self):
        headers = {"Authorization": f"Bearer {self.master.token}"}
        data = {
            "full_name": self.fullname_entry.get(),
            "email": self.email_entry.get()
        }
        try:
            response = requests.put(f"{API_URL}/users/me", json=data, headers=headers)
            if response.status_code == 200:
                self.status_label.configure(text="Profile Saved!", text_color="green")
            else:
                self.status_label.configure(text="Failed to save", text_color="red")
        except requests.exceptions.ConnectionError:
            self.status_label.configure(text="Connection Error", text_color="red")

if __name__ == "__main__":
    app = App()
    app.mainloop()
