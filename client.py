import socket
import threading
import sys
import os
import json
import getpass

from modules import makeup
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from modules.crypto import (
    load_public_key,
    rsa_encrypt,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    fingerprint_from_bytes
)

from modules.protocol import (
    send_packet,
    recv_packet
)

session = PromptSession()

makeup.wipe()
makeup.dancinnn()

try:
    SERVER_IP = sys.argv[1]
except IndexError:
    print(makeup.TextColor["red"], "[!] IP can't be empty")
    exit()

try:
    SERVER_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number")
    exit()

try:
    EXPECTED_FINGERPRINT = sys.argv[3]
except IndexError:
    EXPECTED_FINGERPRINT = None


aes_key = None
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))


# Receive and verify the server's RSA public key
server_public_bytes = recv_packet(sock)
actual_fingerprint = fingerprint_from_bytes(server_public_bytes)

KNOWN_HOSTS_PATH = os.path.expanduser("~/.undercover_known_hosts")
host_id = f"{SERVER_IP}:{SERVER_PORT}"


def load_known_hosts():
    try:
        with open(KNOWN_HOSTS_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_known_hosts(hosts):
    with open(KNOWN_HOSTS_PATH, "w") as f:
        json.dump(hosts, f, indent=2)


if EXPECTED_FINGERPRINT is not None:
    if actual_fingerprint != EXPECTED_FINGERPRINT:
        print(makeup.TextColor["red"], "[!] SERVER FINGERPRINT MISMATCH — possible MITM attack!")
        print(makeup.TextColor["red"], f"    expected: {EXPECTED_FINGERPRINT}")
        print(makeup.TextColor["red"], f"    got:      {actual_fingerprint}")
        sock.close()
        exit()
    print(makeup.TextColor["cyan"], "[+] Server fingerprint verified (pinned).")
else:
    known_hosts = load_known_hosts()
    saved = known_hosts.get(host_id)
    if saved is None:
        print(makeup.TextColor["cyan"], f"[?] Unknown server {host_id}")
        print(makeup.TextColor["cyan"], f"    Fingerprint: {actual_fingerprint}")
        answer = input("    Trust this server and remember it? (yes/no): ").strip().lower()
        if answer not in ("yes", "y"):
            print(makeup.TextColor["red"], "[!] Connection aborted by user.")
            sock.close()
            exit()
        known_hosts[host_id] = actual_fingerprint
        save_known_hosts(known_hosts)
        print(makeup.TextColor["cyan"], "[+] Server remembered.")
    elif saved != actual_fingerprint:
        print(makeup.TextColor["red"], "[!] WARNING: SERVER KEY CHANGED — possible MITM attack!")
        print(makeup.TextColor["red"], f"    previously trusted: {saved}")
        print(makeup.TextColor["red"], f"    now received:       {actual_fingerprint}")
        sock.close()
        exit()
    else:
        print(makeup.TextColor["cyan"], "[+] Server fingerprint verified (known host).")

server_public_key = load_public_key(server_public_bytes)


# Exchange AES session key
aes_key = generate_aes_key()
encrypted_aes = rsa_encrypt(server_public_key, aes_key)
send_packet(sock, encrypted_aes)


# Sequence counters
send_seq = 0
expected_seq = 0


def send_enc(text):
    """Send one encrypted message during the handshake and bump the counter."""
    global send_seq
    send_packet(sock, aes_encrypt(aes_key, text, send_seq))
    send_seq += 1


def recv_enc():
    """Receive and decrypt one handshake message (sequence ignored here)."""
    _, msg = aes_decrypt(aes_key, recv_packet(sock))
    return msg


# Authentication handshake
username = None
while True:
    username = input("[?] Username: ").strip()
    send_enc(username)
    status = recv_enc()

    if status == "USERNAME_INVALID":
        print(makeup.TextColor["red"], "[!] Username can't be empty")
        continue
    if status == "ONLINE":
        print(makeup.TextColor["red"], "[!] That user is already online. Pick another name.")
        continue

    if status == "REGISTER":
        print(makeup.TextColor["cyan"], "[*] New user — set a password")
        pw = getpass.getpass("    New password: ")
        send_enc(pw)
        result = recv_enc()
        if result == "AUTH_OK":
            print(makeup.TextColor["cyan"], "[+] Registered and logged in.")
            break
        else:
            print(makeup.TextColor["red"], "[!] Registration failed, try again.")
            continue

    if status == "LOGIN":
        print(makeup.TextColor["cyan"], "[*] Existing user — enter your password")
        authed = False
        while True:
            pw = getpass.getpass("    Password: ")
            send_enc(pw)
            result = recv_enc()
            if result == "AUTH_OK":
                print(makeup.TextColor["cyan"], "[+] Logged in.")
                authed = True
                break
            elif result == "AUTH_FAIL":
                print(makeup.TextColor["red"], "[!] Wrong password, try again.")
                continue
            elif result == "AUTH_LOCKED":
                print(makeup.TextColor["red"], "[!] Too many attempts. Connection closed.")
                sock.close()
                exit()
        if authed:
            break


print("[+] Connected securely.")
print("[+] AES-encrypted chat started.")


def receive():
    global expected_seq
    while True:
        try:
            data = recv_packet(sock)
            seq, message = aes_decrypt(aes_key, data)
            if seq < expected_seq:
                continue
            expected_seq = seq + 1
            with patch_stdout():
                print(message)
        except Exception:
            print(makeup.TextColor["red"], "[!] Server-side problem occurred")
            sock.close()
            break


def send():
    global send_seq
    while True:
        try:
            message = session.prompt(f"{username}~$ ")
            if "/quit" in message or "/exit" in message:
                sock.close()
                print(makeup.TextColor["cyan"], "[**] Disconnected from the chat")
                break
            encrypted = aes_encrypt(aes_key, message, send_seq)
            send_seq += 1
            send_packet(sock, encrypted)
        except Exception:
            print(makeup.TextColor["red"], "[!] An error occurred while sending message.")
            sock.close()
            break


threading.Thread(target=receive, daemon=True).start()

try:
    send()
except KeyboardInterrupt:
    print(makeup.TextColor["cyan"], "\n[**] Disconnected from the chat")
    try:
        sock.close()
    except Exception:
        pass