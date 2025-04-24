#Imports: Similar to the client but adds time for logging timestamps.
import socket
import ssl
import threading
import os
import time

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


