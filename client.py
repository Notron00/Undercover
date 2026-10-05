import socket
import threading
import sys

from modules import makeup
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

from modules.crypto import (
    load_public_key,
    rsa_encrypt,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt
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
    print(makeup.TextColor["red"], "[!] IP can't be empty")
    exit()

try:
    SERVER_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    print(makeup.TextColor["red"], "[!] PORT must be a valid number")
    exit()


aes_key = None
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))


# Receive the server's RSA public key
server_public_bytes = recv_packet(sock)
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


def send():
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