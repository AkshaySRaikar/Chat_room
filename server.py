"""
#1
import socket
import threading

clients = []
usernames = {}  # Map client socket to username

def broadcast(message, sender_socket=None):
    for client in clients:
        try:
            client.sendall(message)
        except:
            client.close()
            if client in clients:
                clients.remove(client)
                if client in usernames:
                    del usernames[client]

def handle_client(client_socket, addr):
    print(f"[+] Client {addr} connected.")

    try:
        # Wait for client to send username
        header = client_socket.recv(4).decode('utf-8')
        if header == 'USR|':
            username = client_socket.recv(1024).decode('utf-8')
            usernames[client_socket] = username
            print(f"[+] Username set: {username}")
        else:
            print("[!] Invalid connection - No username sent")
            client_socket.close()
            return
    except:
        print("[!] Failed to receive username.")
        client_socket.close()
        return

    while True:
        try:
            header = client_socket.recv(4).decode('utf-8')
            if not header:
                break

            if header == 'MSG|':
                msg_len = int(client_socket.recv(4).decode('utf-8'))
                msg = client_socket.recv(msg_len).decode('utf-8')
                print(f"[MSG from {usernames.get(client_socket)}]: {msg}")
                broadcast(f"MSG|{len(msg.encode('utf-8')):04d}".encode('utf-8') + msg.encode('utf-8'), client_socket)

            elif header == 'FIL|':
                filename_len = int(client_socket.recv(4).decode('utf-8'))
                filename = client_socket.recv(filename_len).decode('utf-8')
                filesize = int(client_socket.recv(10).decode('utf-8'))
                file_data = b''
                while len(file_data) < filesize:
                    file_data += client_socket.recv(min(4096, filesize - len(file_data)))

                print(f"[FILE from {usernames.get(client_socket)}]: {filename} ({filesize} bytes)")
                for client in clients:
                    try:
                        client.sendall(f"FIL|{filename_len:04d}".encode('utf-8'))
                        client.sendall(filename.encode('utf-8'))
                        client.sendall(f"{filesize:010d}".encode('utf-8'))
                        client.sendall(file_data)
                    except:
                        client.close()
                        if client in clients:
                            clients.remove(client)
                            usernames.pop(client, None)

        except:
            print(f"[-] Client {addr} disconnected.")
            if client_socket in clients:
                clients.remove(client_socket)
            usernames.pop(client_socket, None)
            client_socket.close()
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))
    server.listen(5)
    print("[*] Server started on port 5555")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()


"""
'''
#2
import socket
import threading
import os

clients = []

def broadcast(message, sender_socket=None):
    for client in clients:
        try:
            client.sendall(message)
        except:
            client.close()
            if client in clients:
                clients.remove(client)

def handle_client(client_socket, addr):
    print(f"[+] Client {addr} connected.")
    while True:
        try:
            header = client_socket.recv(4).decode('utf-8')
            if not header:
                break

            if header == 'MSG|':
                msg_len = int(client_socket.recv(4).decode('utf-8'))
                msg = client_socket.recv(msg_len).decode('utf-8')
                print(f"[MSG from {addr}]: {msg}")
                broadcast(f"MSG|{msg_len:04d}".encode('utf-8') + msg.encode('utf-8'))

            elif header == 'FIL|':
                filename_len = int(client_socket.recv(4).decode('utf-8'))
                filename = client_socket.recv(filename_len).decode('utf-8')
                filesize = int(client_socket.recv(10).decode('utf-8'))
                file_data = b''
                while len(file_data) < filesize:
                    file_data += client_socket.recv(min(4096, filesize - len(file_data)))

                print(f"[FILE from {addr}]: {filename} ({filesize} bytes)")
                for client in clients:
                    try:
                        client.sendall(f"FIL|{filename_len:04d}".encode('utf-8'))
                        client.sendall(filename.encode('utf-8'))
                        client.sendall(f"{filesize:010d}".encode('utf-8'))
                        client.sendall(file_data)
                    except:
                        client.close()
                        if client in clients:
                            clients.remove(client)

        except:
            print(f"[-] Client {addr} disconnected.")
            if client_socket in clients:
                clients.remove(client_socket)
            client_socket.close()
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 5555))  # bind to all interfaces
    server.listen(5)
    print("[*] Server started on port 5555")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
'''

'''
#same as final but here the text is not saved for the next one its saved as log file
import socket
import ssl
import threading

clients = []

def handle_client(conn, addr, username):
    print(f"[+] {username} connected from {addr}")
    while True:
        try:
            header = conn.recv(4).decode("utf-8")
            if not header:
                break
            if header == 'MSG|':
                msg_len = int(conn.recv(4).decode("utf-8"))
                msg = conn.recv(msg_len).decode("utf-8")
                broadcast(f"MSG|{len(msg.encode('utf-8')):04d}".encode("utf-8") + msg.encode("utf-8"), conn)
            elif header == 'FIL|':
                filename_len = int(conn.recv(4).decode())
                filename = conn.recv(filename_len).decode()
                filesize = int(conn.recv(10).decode())
                file_data = b''
                while len(file_data) < filesize:
                    file_data += conn.recv(min(4096, filesize - len(file_data)))
                for client in clients:
                    if client != conn:
                        try:
                            client.sendall(f"FIL|{len(filename):04d}".encode())
                            client.sendall(filename.encode())
                            client.sendall(f"{filesize:010d}".encode())
                            client.sendall(file_data)
                        except:
                            pass
        except:
            break
    print(f"[-] {username} disconnected")
    clients.remove(conn)
    conn.close()

def broadcast(msg, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.sendall(msg)
            except:
                pass

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(('0.0.0.0', 5555))
        server_sock.listen(5)
        print("[*] Server listening on port 5555")

        while True:
            client_sock, addr = server_sock.accept()
            conn = context.wrap_socket(client_sock, server_side=True)
            header = conn.recv(4).decode("utf-8")
            if header == 'USR|':
                username_len = int(conn.recv(4).decode("utf-8"))
                username = conn.recv(username_len).decode("utf-8")
                clients.append(conn)
                threading.Thread(target=handle_client, args=(conn, addr, username), daemon=True).start()

if __name__ == "__main__":
    start_server()

'''

import socket
import ssl
import threading
import os
import time
#Imports: Similar to the client but adds time for logging timestamps.

clients = []
#clients: Tracks all connected client sockets.


def handle_client(conn, addr, username):
    print(f"[+] {username} connected from {addr}")
    while True:
        try:
            header = conn.recv(4).decode("utf-8")       #Header detection: Checks for MSG| (text) or FIL| (file) headers.
            if not header:
                break
            if header == 'MSG|':
                msg_len = int(conn.recv(4).decode("utf-8"))
                msg = conn.recv(msg_len).decode("utf-8")

              
                log_message(username, msg)
                
#Text: Logs messages with log_message() and broadcasts to other clients.

                broadcast(f"MSG|{len(msg.encode('utf-8')):04d}".encode("utf-8") + msg.encode("utf-8"), conn)
            elif header == 'FIL|':
                filename_len = int(conn.recv(4).decode())
                filename = conn.recv(filename_len).decode()
                filesize = int(conn.recv(10).decode())
                file_data = b''

                
                while len(file_data) < filesize:
                    file_data += conn.recv(min(4096, filesize - len(file_data)))

#Files: Receives file data and sends it to all other clients.
               
                for client in clients:
                    if client != conn:
                        try:
                            client.sendall(f"FIL|{len(filename):04d}".encode())
                            client.sendall(filename.encode())
                            client.sendall(f"{filesize:010d}".encode())
                            client.sendall(file_data)
                        except:
                            pass
        except:
            break
    print(f"[-] {username} disconnected")
    clients.remove(conn)
    conn.close()

#Sends messages/files to all clients except the sender: Prevents echo.
def broadcast(msg, sender_conn):
    for client in clients:
        if client != sender_conn:
            try:
                client.sendall(msg)
            except:
                pass

#logging(basically to have chat history)
def log_message(username, msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    log_entry = f"[{timestamp}] {username}: {msg}\n"
    
    
    with open("chat_log.txt", "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    
    print(f"[CHAT LOG] {log_entry.strip()}")

#SSL setup: Uses cert.pem and key.pem for encryption (you’d generate these with tools like OpenSSL).
#Binds to all interfaces: 0.0.0.0 allows connections from any network.
def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(('0.0.0.0', 5555))
        server_sock.listen(5)
        print("[*] Server listening on port 5555")

        while True:
            client_sock, addr = server_sock.accept()
            conn = context.wrap_socket(client_sock, server_side=True)   #Wraps the socket in SSL.
            header = conn.recv(4).decode("utf-8")
            if header == 'USR|':                                        #Reads the username sent by the client (USR| header).
                username_len = int(conn.recv(4).decode("utf-8"))
                username = conn.recv(username_len).decode("utf-8")
                clients.append(conn)
                threading.Thread(target=handle_client, args=(conn, addr, username), daemon=True).start()

if __name__ == "__main__":
    start_server()


