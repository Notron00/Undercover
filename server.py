import socket
import threading
import sys
import re
import os
import json
import time

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

from modules.ratelimit import is_locked, record_failure, reset_failures

makeup.dancinnn()

HOST = "0.0.0.0"
MAX_PASSWORD_ATTEMPTS = 3
MAX_CONNECTIONS = 100
HANDSHAKE_TIMEOUT = 30
USERS_PATH = "users.json"

try:
    PORT = int(sys.argv[1])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number")
    exit()


# Rate limiting state (dicts live here; the logic lives in modules/ratelimit.py).
ip_failures = {}
account_failures = {}

connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

clients = {}
rooms = {}
users = {}            # username (casefold) -> bcrypt hash (str)
lock = threading.Lock()
users_lock = threading.Lock()


def load_users():
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_users():
    with users_lock:
        with open(USERS_PATH, "w") as f:
            json.dump(users, f, indent=2)


users = load_users()


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


# ---------- Messaging helpers ----------

def send_enc(conn, aes_key, seq, message):
    """Send one encrypted message during the pre-registration handshake."""
    send_packet(conn, aes_encrypt(aes_key, message, seq))


def send_to(conn, message):
    """Send a one-off system message to a single already-registered client."""
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
            rooms[new_room] = {"owner": username, "pass_hash": None}
            created = True
        else:
            created = False
            pass_hash = room_info["pass_hash"]
            if pass_hash is not None:
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


def do_delpass(conn, username, args):
    with lock:
        room = clients[conn]["room"]
        room_info = rooms.get(room)
        if room_info is None or room_info["owner"] != username:
            send_to(conn, "[SERVER] Only the room owner can remove the password.")
            return
        room_info["pass_hash"] = None
    send_to(conn, f"[SERVER] Password removed for '{room}'.")


def do_msg(conn, username, args):
    parts = args.split(" ", 1)
    if len(parts) < 2 or not parts[0].strip() or not parts[1].strip():
        send_to(conn, "[SERVER] Usage: /msg <user> <message>")
        return
    target_name = parts[0].strip()
    text = parts[1].strip()
    with lock:
        target_conn = None
        for c, data in clients.items():
            if data["username"].casefold() == target_name.casefold():
                target_conn = c
                real_name = data["username"]
                break
    if target_conn is None:
        send_to(conn, f"[SERVER] User '{target_name}' not found or offline.")
        return
    if target_conn == conn:
        send_to(conn, "[SERVER] You can't private-message yourself.")
        return
    send_to(target_conn, f"[PM from {username}] {text}")
    send_to(conn, f"[PM to {real_name}] {text}")
    print(f"[PM] {username} -> {real_name}: {text}")


def authenticate(conn, aes_key, ip):
    """
    Handshake that establishes an authenticated username.
    Returns (username, next_seq) on success, or (None, _) on failure.
    """
    send_seq = 0

    while True:
        _, username = aes_decrypt(aes_key, recv_packet(conn))
        username = re.sub(r"\s+", " ", username.strip())

        if not username:
            send_enc(conn, aes_key, send_seq, "USERNAME_INVALID")
            send_seq += 1
            continue

        key = username.casefold()

        with lock:
            online = any(d["username"].casefold() == key for d in clients.values())
        if online:
            send_enc(conn, aes_key, send_seq, "ONLINE")
            send_seq += 1
            continue

        with users_lock:
            registered = key in users

        if registered:
            # Account-level lockout (defeats distributed brute-force).
            if is_locked(account_failures, key):
                send_enc(conn, aes_key, send_seq, "AUTH_LOCKED")
                send_seq += 1
                return None, send_seq

            send_enc(conn, aes_key, send_seq, "LOGIN")
            send_seq += 1
            for _ in range(MAX_PASSWORD_ATTEMPTS):
                _, password = aes_decrypt(aes_key, recv_packet(conn))
                with users_lock:
                    stored = users.get(key)
                if stored and verify_password(password, stored.encode("utf-8")):
                    send_enc(conn, aes_key, send_seq, "AUTH_OK")
                    send_seq += 1
                    reset_failures(account_failures, key)
                    reset_failures(ip_failures, ip)
                    return username, send_seq
                record_failure(account_failures, key)
                record_failure(ip_failures, ip)
                send_enc(conn, aes_key, send_seq, "AUTH_FAIL")
                send_seq += 1
            send_enc(conn, aes_key, send_seq, "AUTH_LOCKED")
            send_seq += 1
            return None, send_seq
        else:
            # REGISTER flow
            send_enc(conn, aes_key, send_seq, "REGISTER")
            send_seq += 1
            _, password = aes_decrypt(aes_key, recv_packet(conn))
            if not password.strip():
                send_enc(conn, aes_key, send_seq, "AUTH_FAIL")
                send_seq += 1
                continue
            with users_lock:
                users[key] = hash_password(password).decode("utf-8")
            save_users()
            send_enc(conn, aes_key, send_seq, "AUTH_OK")
            send_seq += 1
            return username, send_seq


def handle_client(conn, addr):
    ip = addr[0]
    print(f"[+] Connection: {addr}")
    username = "Unknown"

    # Reject connections from an IP that is currently rate-limited.
    if is_locked(ip_failures, ip):
        print(f"[!] Rejected connection from rate-limited IP {ip}")
        try:
            conn.close()
        except Exception:
            pass
        return

    # Cap concurrent connections (anti flood DoS).
    if not connection_slots.acquire(blocking=False):
        print(f"[!] Connection limit reached, rejecting {ip}")
        try:
            conn.close()
        except Exception:
            pass
        return

    # Drop connections that don't complete the handshake in time (anti slowloris).
    conn.settimeout(HANDSHAKE_TIMEOUT)

    try:
        send_packet(conn, public_key_bytes)
        encrypted_aes = recv_packet(conn)
        aes_key = rsa_decrypt(private_key, encrypted_aes)

        username, send_seq = authenticate(conn, aes_key, ip)
        if username is None:
            print("[***] Authentication failed, closing connection")
            return

        # Handshake done — remove the timeout so idle chatting isn't dropped.
        conn.settimeout(None)

        with lock:
            clients[conn] = {
                "username": username,
                "aes": aes_key,
                "send_seq": send_seq,
                "expected_seq": 0,
                "room": "lobby"
            }
            if "lobby" not in rooms:
                rooms["lobby"] = {"owner": None, "pass_hash": None}

        print(f"[+] {username} authenticated and joined")
        broadcast(f"[SERVER] {username} joined lobby.", "lobby", conn)

        while True:
            data = recv_packet(conn)
            seq, message = aes_decrypt(aes_key, data)

            with lock:
                expected = clients[conn]["expected_seq"]
                if seq < expected:
                    print(f"[!] Replay/old message from {username} (seq {seq} < {expected}), dropped")
                    continue
                clients[conn]["expected_seq"] = seq + 1

            if message.startswith("/join "):
                do_join(conn, username, message[len("/join "):])
                continue
            if message.startswith("/setpass "):
                do_setpass(conn, username, message[len("/setpass "):])
                continue
            if message.strip() == "/delpass":
                do_delpass(conn, username, "")
                continue
            if message.startswith("/msg "):
                do_msg(conn, username, message[len("/msg "):])
                continue

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
        connection_slots.release()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"{makeup.TextColor['cyan']}\n[SERVER] Listening {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print(makeup.TextColor["cyan"], "\n[**] Server shutting down...")