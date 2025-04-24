#Imports: Standard Python modules for networking (socket, ssl), threading, file operations, and GUI.
import socket
import ssl
import threading
import os
import tkinter as tk
from tkinter import filedialog, simpledialog, scrolledtext, messagebox


#EMOJIS: List of emojis for quick insertion into chat messages.
EMOJIS = ['😀', '😂', '👍', '😭', '🔥', '🙏', '🥰', '🎉', '💯']

class ChatClient:
    def __init__(self, master):             # master: The main Tkinter window.
        self.master = master
        self.master.title("🔐 SSL Chat Room Client")
        self.master.geometry("600x500")
        self.master.configure(bg="#f0f0f0")

        self.username = simpledialog.askstring("Username", "Enter your name:") #Username prompt: Asks user for a name. If empty, shows a warning and exits.

        if not self.username:
            messagebox.showwarning("Username Required", "Username cannot be empty.")
            master.destroy()
            return
        

#Chat area: A scrollable text box for messages (read-only).

        self.chat_area = scrolledtext.ScrolledText(master, state='disabled', wrap=tk.WORD, bg="white", fg="#333")
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        input_frame = tk.Frame(master, bg="#f0f0f0") #Input frame: Contains the text entry for typing messages and buttons for sending messages/files.
        input_frame.pack(pady=10, fill=tk.X)

        self.entry_field = tk.Entry(input_frame)
        self.entry_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 5), ipady=4)
        self.entry_field.bind("<Return>", lambda e: self.send_message())

        tk.Button(input_frame, text="Send", command=self.send_message, bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Send File", command=self.send_file, bg="#2196F3", fg="white").pack(side=tk.LEFT)

        emoji_frame = tk.Frame(master, bg="#f0f0f0")  #Emoji frame: Buttons for each emoji, clicking inserts emoji into the entry field
        emoji_frame.pack(fill=tk.X)
        for emoji in EMOJIS:
            btn = tk.Button(emoji_frame, text=emoji, command=lambda e=emoji: self.insert_emoji(e), font=("Arial", 12), width=3)
            btn.pack(side=tk.LEFT, padx=2)

        os.makedirs("ReceivedFiles", exist_ok=True)  #ReceivedFiles directory: Ensures a folder exists for saving incoming files.
        self.setup_ssl_connection()   #SSL connection: Calls setup_ssl_connection() to connect to the server securely.

    def insert_emoji(self, emoji):
        self.entry_field.insert(tk.END, emoji)

    def setup_ssl_connection(self):   #SSl connection setup
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = context.wrap_socket(raw_sock, server_hostname="localhost") #Socket: Creates a socket and wraps it with SSL.

        try:
            self.sock.connect(("127.0.0.1", 5555))   #here we change the ip to servers ip so that clients can join - different systems
            username_data = self.username.encode("utf-8")
            self.sock.sendall(f"USR|{len(username_data):04d}".encode("utf-8") + username_data)
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.print_message("🟢 Connected to server")
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.master.destroy()

    def print_message(self, msg):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, msg + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def receive_messages(self):
        while True:
            try:
                header = self.sock.recv(4).decode("utf-8")  #Message protocol: Reads a 4-character header to determine message type:
                if header == 'MSG|':                        #'MSG|': Normal chat message. For messages: Reads length, then the message, and displays it.
                    msg_len = int(self.sock.recv(4).decode("utf-8"))
                    msg = self.sock.recv(msg_len).decode("utf-8")
                    self.print_message(f"💬 {msg}")
                elif header == 'FIL|':                      #'FIL|': File transfer. For files: Reads filename and file size, then receives the file in chunks and saves it.
                    filename_len = int(self.sock.recv(4).decode())
                    filename = self.sock.recv(filename_len).decode()
                    filesize = int(self.sock.recv(10).decode())
                    file_data = b''
                    while len(file_data) < filesize:
                        chunk = self.sock.recv(min(4096, filesize - len(file_data)))
                        if not chunk:
                            break
                        file_data += chunk
                    filepath = os.path.join("ReceivedFiles", filename)
                    with open(filepath, 'wb') as f:
                        f.write(file_data)
                    self.print_message(f"📁 File received: {filepath}")
            except Exception as e:
                self.print_message(f"🔴 Disconnected. Error: {e}")
                break

    def send_message(self):
        msg = self.entry_field.get()
        if not msg:
            return
        self.entry_field.delete(0, tk.END)
        full_msg = f"{self.username}: {msg}"
        encoded_msg = full_msg.encode("utf-8")
        try:
            self.sock.sendall(f"MSG|{len(encoded_msg):04d}".encode("utf-8") + encoded_msg) #Gets text from entry field, formats it with username, encodes, and sends to server.
            self.print_message(f"🧑 You: {msg}")                #Displays the sent message in the chat area.
        except:
            self.print_message("❌ Failed to send message.")       #Handles errors (e.g., if not connected).

    def send_file(self):
        filepath = filedialog.askopenfilename()     # Opens a file dialog for the user to pick a file.
        if not filepath:
            return
        filename = os.path.basename(filepath)   #Sends file info (name, size) 

        filesize = os.path.getsize(filepath)
        try:
            self.sock.sendall(f"FIL|{len(filename):04d}".encode())
            self.sock.sendall(filename.encode())
            self.sock.sendall(f"{filesize:010d}".encode())
            with open(filepath, 'rb') as f:             #sends files in chunks to the server.
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            self.print_message(f"📤 File sent: {filename}") #Shows a confirmation or error in the chat area.
        except:
            self.print_message("❌ Failed to send file.")

if __name__ == "__main__":      #Starts the GUI: Creates the main window, initializes the chat client, and starts the Tkinter event loop
    root = tk.Tk()
    ChatClient(root)
    root.mainloop()
