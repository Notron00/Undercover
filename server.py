import socket
import threading
import sys
import re

from modules import makeup

makeup.wipe()

from modules.crypto import (
    generate_rsa_keys,
    public_key_to_bytes,
    load_public_key,
    rsa_decrypt,
    aes_decrypt,
    aes_encrypt
)

from modules.protocol import (
    send_packet,
    recv_packet
)

makeup.dancinnn()

HOST = "0.0.0.0"  # bind on all interfaces of the machine running the server

try:
    PORT = int(sys.argv[1])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number")
    exit()


clients = {}
lock = threading.Lock()


# RSA key pair for this server instance
private_key, public_key = generate_rsa_keys()
public_key_bytes = public_key_to_bytes(public_key)


def broadcast(message, exclude=None):
    """
    Sends message to everyone in the chat room.
    The client list is copied under the lock, then the lock is released
    before the (potentially slow) network sends, so one slow client
    cannot block the whole server.
    """
    with lock:
        targets = [
            (client, data["aes"])
            for client, data in clients.items()
            if client != exclude
        ]

    for client, aes in targets:
        try:
            encrypted = aes_encrypt(aes, message)
            send_packet(client, encrypted)
        except Exception:
            pass


def handle_client(conn, addr):
    print(f"[+] Connection: {addr}")

    username = "Unknown"

    try:
        # Send the RSA public key
        send_packet(conn, public_key_bytes)

        # Receive the AES session key from the client (RSA-encrypted)
        encrypted_aes = recv_packet(conn)
        aes_key = rsa_decrypt(private_key, encrypted_aes)

        # Username registration loop
        while True:
            encrypted_name = recv_packet(conn)
            username = aes_decrypt(aes_key, encrypted_name)
            username = re.sub(r"\s+", " ", username.strip())

            if not username:
                send_packet(conn, aes_encrypt(aes_key, "USERNAME_INVALID"))
                print("[***] Rejected! Empty username")
                continue

            with lock:
                normalized_username = username.casefold()

                username_taken = any(
                    re.sub(r"\s+", " ", client_data["username"].strip()).casefold()
                    == normalized_username
                    for client_data in clients.values()
                )

                if username_taken:
                    send_packet(conn, aes_encrypt(aes_key, "USERNAME_TAKEN"))
                    print("[***] Rejected! Username already taken")
                    continue

                clients[conn] = {
                    "username": username,
                    "aes": aes_key
                }
                break

        send_packet(conn, aes_encrypt(aes_key, "USERNAME_OK"))

        print(f"[+] {username} joined")
        broadcast(f"[SERVER] {username} joined chat.", conn)

        # Main message loop
        while True:
            data = recv_packet(conn)
            message = aes_decrypt(aes_key, data)
            print(f"{username}: {message}")
            broadcast(f"{username}: {message}", conn)

    except Exception as e:
        print("[!] Client error:", e)

    finally:
        with lock:
            if conn in clients:
                username = clients[conn]["username"]
                del clients[conn]
            else:
                username = "Unknown"

        try:
            conn.close()
        except Exception:
            pass

        if username != "Unknown":
            broadcast(f"[SERVER] {username} left chat.")

        print(f"[-] {username} disconnected...")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    print(f"{makeup.TextColor['cyan']}\n[SERVER] Listening {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )
        thread.start()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print(makeup.TextColor["cyan"], "\n[**] Server shutting down...")
        
