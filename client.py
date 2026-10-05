import socket
import threading
import sys
import os
import json

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

session = PromptSession()  # keeps terminal input from breaking during async output

makeup.wipe()
makeup.dancinnn()

try:
    SERVER_IP = sys.argv[1]
except IndexError:
    print(makeup.TextColor["red"], "[!] IP can't be empty | Usage: python client.py IP PORT")
    exit()

try:
    SERVER_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number | Usage: python client.py IP PORT")
    exit()

# Optional: strict pinning if fingerprint is passed as an argument.
# If omitted, TOFU (trust-on-first-use) is used instead.
try:
    EXPECTED_FINGERPRINT = sys.argv[3]
except IndexError:
    EXPECTED_FINGERPRINT = None


aes_key = None
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))


# Receive the server's RSA public key
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
    # Strict pinning mode: fingerprint supplied on the command line.
    if actual_fingerprint != EXPECTED_FINGERPRINT:
        print(makeup.TextColor["red"], "[!] SERVER FINGERPRINT MISMATCH — possible MITM attack!")
        print(makeup.TextColor["red"], f"    expected: {EXPECTED_FINGERPRINT}")
        print(makeup.TextColor["red"], f"    got:      {actual_fingerprint}")
        sock.close()
        exit()
    print(makeup.TextColor["cyan"], "[+] Server fingerprint verified (pinned).")
else:
    # TOFU mode: trust on first use, warn if a known host's key changed.
    known_hosts = load_known_hosts()
    saved = known_hosts.get(host_id)

    if saved is None:
        # First time seeing this server.
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
        # Known host, but the key changed — possible MITM Bruh.
        print(makeup.TextColor["red"], "[!] WARNING: SERVER KEY CHANGED — possible MITM attack!")
        print(makeup.TextColor["red"], f"    previously trusted: {saved}")
        print(makeup.TextColor["red"], f"    now received:       {actual_fingerprint}")
        print(makeup.TextColor["red"], "    If you know the server legitimately changed its key,")
        print(makeup.TextColor["red"], f"    remove the entry for {host_id} from {KNOWN_HOSTS_PATH}")
        sock.close()
        exit()
    else:
        print(makeup.TextColor["cyan"], "[+] Server fingerprint verified (known host).")

server_public_key = load_public_key(server_public_bytes)


# Generate an AES session key and send it, encrypted with the server's RSA key
aes_key = generate_aes_key()
encrypted_aes = rsa_encrypt(server_public_key, aes_key)
send_packet(sock, encrypted_aes)


# Username registration loop
while True:
    username = input("[?] Username: ")

    encrypted_username = aes_encrypt(aes_key, username)
    send_packet(sock, encrypted_username)

    response = recv_packet(sock)
    response = aes_decrypt(aes_key, response)

    if response == "USERNAME_TAKEN":
        print("[!] Username already taken")
        continue
    else:
        break


print("[+] Connected securely.")
print("[+] AES-encrypted chat started (AES session key exchanged via RSA).") 


def receive():
    while True:
        try:
            data = recv_packet(sock)
            message = aes_decrypt(aes_key, data)
            with patch_stdout():
                print(message)
        except Exception:
            print(makeup.TextColor["red"], "[!] Server-side problem occurred")
            sock.close()
            break


def send(): # Send function that sends the message in text w/ emcrypted data. (I'll harden that/these with pgp after)
    while True:
        try:
            message = session.prompt(f"{username}~$ ")

            if "/quit" in message or "/exit" in message:
                sock.close()
                print(makeup.TextColor["cyan"], "[**] Disconnected from the chat")
                break

            encrypted = aes_encrypt(aes_key, message)
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
