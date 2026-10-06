import socket
import threading
import sys
import re
import os

from modules import makeup

makeup.wipe()

from modules.crypto import (
    generate_rsa_keys,
    public_key_to_bytes,
    load_public_key,
    rsa_decrypt,
    aes_decrypt,
    aes_encrypt,
    save_private_key,
    load_private_key,
    public_key_fingerprint,
    hash_password,
    verify_password
)

from modules.protocol import (
    send_packet,
    recv_packet
)

makeup.dancinnn()

HOST = "0.0.0.0"

try:
    PORT = int(sys.argv[1])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number")
    exit()


clients = {}
# rooms[name] = {"owner": username, "pass_hash": bytes or None}
rooms = {}
lock = threading.Lock()


# RSA key pair, persisted to disk.
KEY_PATH = "server_key.pem"

if os.path.exists(KEY_PATH):
    private_key, public_key = load_private_key(KEY_PATH)
else:
    private_key, public_key = generate_rsa_keys()
    save_private_key(private_key, KEY_PATH)

public_key_bytes = public_key_to_bytes(public_key)

FINGERPRINT = public_key_fingerprint(public_key)
print(f"{makeup.TextColor['cyan']}[SERVER] Public key fingerprint:")
print(f"{makeup.TextColor['cyan']}  {FINGERPRINT}")


def send_to(conn, message):
    """Send a one-off system message to a single client (with its own send seq)."""
    try:
        with lock:
            if conn not in clients:
                return
            aes = clients[conn]["aes"]
            seq = clients[conn]["send_seq"]
            clients[conn]["send_seq"] = seq + 1
        encrypted = aes_encrypt(aes, message, seq)
        send_packet(conn, encrypted)
    except Exception:
        pass


def broadcast(message, room, exclude=None):
    """Send message only to clients in the given room."""
    with lock:
        targets = [
            (client, data["aes"])
            for client, data in clients.items()
            if client != exclude and data["room"] == room
        ]

    for client, aes in targets:
        try:
            with lock:
                if client not in clients:
                    continue
                seq = clients[client]["send_seq"]
                clients[client]["send_seq"] = seq + 1
            encrypted = aes_encrypt(aes, message, seq)
            send_packet(client, encrypted)
        except Exception:
            pass


def do_join(conn, username, args):
    """Handle /join <room> [password]."""
    parts = args.split(" ", 1)
    new_room = parts[0].strip()
    password = parts[1].strip() if len(parts) > 1 else None

    if not new_room:
        send_to(conn, "[SERVER] Usage: /join <room> [password]")
        return

    with lock:
        old_room = clients[conn]["room"]
        room_info = rooms.get(new_room)

        if room_info is None:
            # Room doesn't exist: create it, caller becomes owner.
            rooms[new_room] = {"owner": username, "pass_hash": None}
            created = True
        else:
            created = False
            pass_hash = room_info["pass_hash"]
            if pass_hash is not None:
                # Room is password-protected.
                if password is None or not verify_password(password, pass_hash):
                    send_to(conn, f"[SERVER] Wrong or missing password for '{new_room}'")
                    return

        clients[conn]["room"] = new_room

    broadcast(f"[SERVER] {username} left the room.", old_room, conn)
    if created:
        send_to(conn, f"[SERVER] Room '{new_room}' created. You are the owner.")
    broadcast(f"[SERVER] {username} joined {new_room}.", new_room, conn)
    send_to(conn, f"[SERVER] You are now in '{new_room}'.")
    print(f"[*] {username}: {old_room} -> {new_room}")


def do_setpass(conn, username, args):
    """Handle /setpass <password> — only the owner of the current room."""
    password = args.strip()
    if not password:
        send_to(conn, "[SERVER] Usage: /setpass <password>")
        return

    with lock:
        room = clients[conn]["room"]
        room_info = rooms.get(room)
        if room_info is None or room_info["owner"] != username:
            send_to(conn, "[SERVER] Only the room owner can set a password.")
            return
        room_info["pass_hash"] = hash_password(password)

    send_to(conn, f"[SERVER] Password set for '{room}'.")
    print(f"[*] {username} set a password for room '{room}'")


def do_delpass(conn, username, args):
    """Handle /delpass — owner removes the room password."""
    with lock:
        room = clients[conn]["room"]
        room_info = rooms.get(room)
        if room_info is None or room_info["owner"] != username:
            send_to(conn, "[SERVER] Only the room owner can remove the password.")
            return
        room_info["pass_hash"] = None

    send_to(conn, f"[SERVER] Password removed for '{room}'.")
    print(f"[*] {username} removed the password for room '{room}'")


def handle_client(conn, addr):
    print(f"[+] Connection: {addr}")

    username = "Unknown"

    try:
        send_packet(conn, public_key_bytes)

        encrypted_aes = recv_packet(conn)
        aes_key = rsa_decrypt(private_key, encrypted_aes)

        # Username registration loop
        while True:
            encrypted_name = recv_packet(conn)
            _, username = aes_decrypt(aes_key, encrypted_name)
            username = re.sub(r"\s+", " ", username.strip())

            if not username:
                send_packet(conn, aes_encrypt(aes_key, "USERNAME_INVALID"))
                print("[***] Rejected! Empty username")
                continue

            with lock:
                normalized_username = username.casefold()
                username_taken = any(
                    re.sub(r"\s+", " ", cd["username"].strip()).casefold()
                    == normalized_username
                    for cd in clients.values()
                )

                if username_taken:
                    send_packet(conn, aes_encrypt(aes_key, "USERNAME_TAKEN"))
                    print("[***] Rejected! Username already taken")
                    continue

                clients[conn] = {
                    "username": username,
                    "aes": aes_key,
                    "send_seq": 0,
                    "expected_seq": 0,
                    "room": "lobby"
                }
                # Ensure the lobby exists (ownerless default room).
                if "lobby" not in rooms:
                    rooms["lobby"] = {"owner": None, "pass_hash": None}
                break

        send_packet(conn, aes_encrypt(aes_key, "USERNAME_OK"))

        print(f"[+] {username} joined")
        broadcast(f"[SERVER] {username} joined lobby.", "lobby", conn)

        # Main message loop
        while True:
            data = recv_packet(conn)
            seq, message = aes_decrypt(aes_key, data)

            with lock:
                expected = clients[conn]["expected_seq"]
                if seq < expected:
                    print(f"[!] Replay/old message from {username} (seq {seq} < {expected}), dropped")
                    continue
                clients[conn]["expected_seq"] = seq + 1

            # Commands
            if message.startswith("/join "):
                do_join(conn, username, message[len("/join "):])
                continue
            if message.startswith("/setpass "):
                do_setpass(conn, username, message[len("/setpass "):])
                continue
            if message.strip() == "/delpass":
                do_delpass(conn, username, "")
                continue

            # Normal message
            with lock:
                room = clients[conn]["room"]
            print(f"[{room}] {username}: {message}")
            broadcast(f"{username}: {message}", room, conn)

    except Exception as e:
        print("[!] Client error:", e)

    finally:
        left_room = "lobby"
        with lock:
            if conn in clients:
                username = clients[conn]["username"]
                left_room = clients[conn]["room"]
                del clients[conn]
            else:
                username = "Unknown"

        try:
            conn.close()
        except Exception:
            pass

        if username != "Unknown":
            broadcast(f"[SERVER] {username} left chat.", left_room)

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