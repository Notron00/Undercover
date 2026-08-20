import socket
import threading
import sys
from modules import makeup
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

session = PromptSession() # this "promptSession" will debug the text so it will not be broken on ur terminal

makeup.wipe()

makeup.dancinnn()


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

try:
    SERVER_IP = sys.argv[1]
except:
    print(makeup.TextColor["red"],"[!] IP can't be NONE")
    exit()
try:
    SERVER_PORT = int(sys.argv[2]) # Port has to be an integer typeof data
except:
    print(makeup.TextColor["red"],"[!] PORT can't be NONE")
    exit()

if SERVER_IP is None or SERVER_PORT is None:
    print("[!!] Cmon man give me an solid ip/port to connect lol xD")
    exit()



aes_key = None
sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)


sock.connect(
    (SERVER_IP, SERVER_PORT)
)


# RSA PUBLIC KEY BUILD

server_public_bytes = recv_packet(sock)

server_public_key = load_public_key(
    server_public_bytes
)


# AES KEY BUILD

aes_key = generate_aes_key()


# ecrypt the AES key w RSA
encrypted_aes = rsa_encrypt(
    server_public_key,
    aes_key
)


send_packet(
    sock,
    encrypted_aes
)



while 1:
    username = input("[?] Username: ")
    # send the encrypted username data

    encrypted_username = aes_encrypt(
        aes_key,
        username
    )


    send_packet(
        sock,
        encrypted_username
    )


    response = recv_packet(sock)
    response = aes_decrypt(
        aes_key,
        response
    )

    if response == "USERNAME_TAKEN":
        print("[!] Username already taken")
        continue
    else:
        break




print("[+] Connected securely.")
print("[+] AES supported w RSA encrypted chat started.")



def receive():

    while True:

        try:

            data = recv_packet(sock)


            message = aes_decrypt(
                aes_key,
                data
            )

            with patch_stdout():
                print(message)

        except Exception as e:
            session.prompt(makeup.TextColor["red"],"[!] Server side proble Occured o_O")
            sock.close()
            break



def send():

    while True:

        try:

            message = session.prompt(f"{username}~$ ")


            if "/quit" in message or  "/exit" in message:
                sock.close()
                print(makeup.TextColor["cyan"],"[**] Disconnected from the IRC chat x_x")
                break


            encrypted = aes_encrypt(
                aes_key,
                message
            )


            send_packet(
                sock,
                encrypted
            )


        except Exception as e:
            print(makeup. TextColor["red"],"[!] An Error Occured while sending message.")
            sock.close()
            break



threading.Thread(
    target=receive,
    daemon=True
).start()


send()