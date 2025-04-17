
import os
import logging
import hashlib
import platform
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import time

# Configure logging
try:
    logging.basicConfig(
        filename=f"syscall_logs_{datetime.now().strftime('%Y%m%d')}.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - [%(username)s] - %(message)s"
    )
except Exception as e:
    print(f"Warning: Could not setup file logging: {e}")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - [%(username)s] - %(message)s"
    )

# Platform-specific commands
ALLOWED_COMMANDS = {
    "windows": {
        "whoami": "whoami",
        "date": "date /t",
        "time": "time /t",
        "dir": "dir",
        "read_file": "type",
        "hash_file": None
    },
    "unix": {
        "whoami": "whoami",
        "date": "date",
        "pwd": "/bin/pwd",
        "ls": "ls -l",
        "read_file": "cat",
        "hash_file": None
    }
}

# User database
USERS = {
    "admin": hashlib.sha256("Admin@123".encode()).hexdigest(),
    "user": hashlib.sha256("User@123".encode()).hexdigest()
}

class SecureSyscallInterface:
    def __init__(self):
        self.username = "unknown"
        self.platform = "windows" if platform.system() == "Windows" else "unix"
        self.commands = ALLOWED_COMMANDS[self.platform]
        self.last_hash = None
        self.last_file = None

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            # Normalize the file path
            file_path = os.path.normpath(file_path)
            logging.info(f"Attempting to hash file: {file_path}", extra={"username": self.username})

            if not os.path.exists(file_path):
                logging.error(f"File not found: {file_path}", extra={"username": self.username})
                return "Error: File not found"
            if not os.path.isfile(file_path):
                logging.error(f"Path is not a file: {file_path}", extra={"username": self.username})
                return "Error: Path is not a file"

            # Log file size for debugging
            file_size = os.path.getsize(file_path)
            logging.info(f"File size: {file_size} bytes", extra={"username": self.username})

            # Calculate hash
            sha256_hash = hashlib.sha256()
            total_bytes = 0
            with open(file_path, "rb") as f:
                while True:
                    byte_block = f.read(4096)
                    if not byte_block:
                        break
                    total_bytes += len(byte_block)
                    sha256_hash.update(byte_block)
            logging.info(f"Total bytes read: {total_bytes}", extra={"username": self.username})

            hash_result = sha256_hash.hexdigest()
            logging.info(f"Hash calculated: {hash_result}", extra={"username": self.username})

            # Compare with the last hash
            result = hash_result
            if self.last_hash is not None and self.last_file != file_path:
                if hash_result == self.last_hash:
                    result += f"\nNote: This file has the same content as the previously hashed file ({self.last_file})."
                else:
                    result += f"\nNote: This file has different content than the previously hashed file ({self.last_file})."
            
            self.last_hash = hash_result
            self.last_file = file_path
            return result
        except Exception as e:
            logging.error(f"Hash calculation failed for {file_path}: {str(e)}", extra={"username": self.username})
            return f"Error: {str(e)}"

    def _execute_system_call(self, command, arg=None):
        if command == "hash_file":
            if not arg:
                return "Error: Please provide a file path"
            return self._calculate_file_hash(arg)
            
        try:
            base_cmd = next((k for k, v in self.commands.items() if k == command), None)
            if not base_cmd:
                return "Command not allowed"
            
            cmd = self.commands[base_cmd]
            if arg and base_cmd == "read_file":
                arg = os.path.normpath(arg)
                cmd = f'{cmd} "{arg}"' if self.platform == "windows" else f"{cmd} {arg}"
            logging.info(f"Executing system command: {cmd}", extra={"username": self.username})
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                error_msg = f"Error: {result.stderr or 'Command failed with no output'}"
                logging.error(f"Command execution failed: {cmd} - {error_msg}", extra={"username": self.username})
                return error_msg
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {command}", extra={"username": self.username})
            return "Error: Command timed out"
        except Exception as e:
            logging.error(f"Command failed: {str(e)}", extra={"username": self.username})
            return f"Error: {str(e)}"

    def execute_command(self, command, arg=None):
        logging.info(f"Executing command: {command} {arg if arg else ''}", extra={"username": self.username})
        result = self._execute_system_call(command, arg)
        logging.info(f"Command result: {result[:100]}...", extra={"username": self.username})
        return result

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure System Call Interface")
        self.root.geometry("700x500")
        self.root.resizable(False, False)
        self.root.configure(bg="#e0e0e0")
        self.interface = SecureSyscallInterface()
        self.last_activity = time.time()
        self.timeout = 300  # 5 minutes

        # Login frame
        self.login_frame = tk.Frame(self.root, bg="#e0e0e0", bd=2, relief="groove")
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(self.login_frame, text="Secure System Call Interface", font=("Arial", 16, "bold"), bg="#e0e0e0").pack(pady=10)
        tk.Label(self.login_frame, text="Username:", bg="#e0e0e0").pack()
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12))
        self.username_entry.pack(pady=5)
        
        tk.Label(self.login_frame, text="Password:", bg="#e0e0e0").pack()
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)
        
        tk.Button(self.login_frame, text="Login", command=self.authenticate, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

        # Main frame
        self.main_frame = tk.Frame(self.root, bg="#e0e0e0")
        
        # Top bar
        top_frame = tk.Frame(self.main_frame, bg="#4CAF50", pady=5)
        top_frame.pack(fill="x")
        self.user_label = tk.Label(top_frame, text="User: unknown", font=("Arial", 12), bg="#4CAF50", fg="white")
        self.user_label.pack(side="left", padx=5)
        tk.Label(top_frame, text=f"Platform: {self.interface.platform}", font=("Arial", 12), bg="#4CAF50", fg="white").pack(side="right", padx=5)

        # Command section
        cmd_frame = tk.LabelFrame(self.main_frame, text="Execute Command", font=("Arial", 10, "bold"), bg="#e0e0e0", pady=10)
        cmd_frame.pack(fill="x", pady=5)
        self.command_var = tk.StringVar()
        self.command_dropdown = ttk.Combobox(cmd_frame, textvariable=self.command_var, 
                                            values=list(self.interface.commands.keys()), state="readonly", width=15)
        self.command_dropdown.pack(side="left", padx=10)
        
        self.arg_entry = tk.Entry(cmd_frame, width=40, font=("Arial", 10))
        self.arg_entry.pack(side="left", padx=5)
        self.arg_entry.insert(0, "Optional argument (e.g., full file path)")
        self.arg_entry.bind("<FocusIn>", lambda e: self.arg_entry.delete(0, tk.END) if "Optional" in self.arg_entry.get() else None)

        tk.Button(cmd_frame, text="Browse", command=self.browse_file, bg="#FFC107", fg="black", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(cmd_frame, text="Run", command=self.run_command, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)

        # Result and history
        result_frame = tk.LabelFrame(self.main_frame, text="Output", font=("Arial", 10, "bold"), bg="#e0e0e0", pady=5)
        result_frame.pack(fill="both", expand=True, pady=5)
        self.result_text = tk.Text(result_frame, height=12, width=80, bg="#ffffff", font=("Courier", 10), relief="flat")
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Buttons
        tk.Button(self.main_frame, text="Show History", command=self.show_history, bg="#FF9800", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5, pady=5)
        tk.Button(self.main_frame, text="Logout", command=self.logout, bg="#F44336", fg="white", font=("Arial", 10, "bold")).pack(side="right", padx=5, pady=5)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.main_frame, textvariable=self.status_var, bg="#B0BEC5", font=("Arial", 9), relief="sunken").pack(fill="x", pady=5)

        # Auto-logout check
        self.root.after(1000, self.check_timeout)

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a File",
            filetypes=(("All files", "*.*"), ("Text files", "*.txt"))
        )
        if file_path:
            self.arg_entry.delete(0, tk.END)
            self.arg_entry.insert(0, file_path)
            self.status_var.set(f"Selected file: {os.path.basename(file_path)}")
        self.last_activity = time.time()

    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()

        if username in USERS and USERS[username] == hashed_pass:
            self.interface.username = username
            self.user_label.config(text=f"User: {username}")
            logging.info(f"Authentication successful", extra={"username": self.interface.username})
            self.login_frame.place_forget()
            self.main_frame.pack(fill="both", expand=True)
            self.result_text.insert(tk.END, "Welcome! Select a command to begin.\n")
            self.result_text.insert(tk.END, "Use 'hash_file' to calculate a file's SHA-256 hash.\n")
            self.result_text.insert(tk.END, "Click 'Browse' to select a file easily.\n")
            self.status_var.set(f"Logged in as {username}")
            self.last_activity = time.time()
        else:
            logging.warning(f"Failed authentication attempt", extra={"username": username})
            messagebox.showerror("Login Failed", "Invalid username or password")

    def run_command(self):
        command = self.command_var.get()
        arg = self.arg_entry.get().strip() if self.arg_entry.get() != "Optional argument (e.g., full file path)" else None
        if not command:
            messagebox.showwarning("No Command", "Please select a command")
            return
        
        self.last_activity = time.time()
        result = self.interface.execute_command(command, arg)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Command: {command} {arg if arg else ''}\nResult: {result}\n")
        self.status_var.set(f"Executed {command} at {datetime.now().strftime('%H:%M:%S')}")

    def show_history(self):
        self.result_text.delete(1.0, tk.END)
        try:
            with open(f"syscall_logs_{datetime.now().strftime('%Y%m%d')}.log", "r") as log_file:
                self.result_text.insert(tk.END, log_file.read())
            self.status_var.set("Showing session history")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error loading history: {e}\n")
        self.last_activity = time.time()

    def logout(self):
        logging.info(f"User logged out", extra={"username": self.interface.username})
        self.main_frame.pack_forget()
        self.login_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.result_text.delete(1.0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.interface.username = "unknown"
        self.user_label.config(text="User: unknown")
        self.status_var.set("Logged out")

    def check_timeout(self):
        if self.interface.username != "unknown" and (time.time() - self.last_activity) > self.timeout:
            self.logout()
            messagebox.showinfo("Session Expired", "Logged out due to inactivity")
        self.root.after(1000, self.check_timeout)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = App(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {e}")
