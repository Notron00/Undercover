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

HOST = "0.0.0.0" # Server binds itself (machine that runs the script)
PORT = None
try:
    PORT = int(sys.argv[1])
except:
    print(makeup.TextColor["red"],"[!!] An Error Occured")
    if PORT is None:
        print("[***] give me a port god dammit >:(")
    exit()


clients = {}
lock = threading.Lock()


# RSA KEY BUILD
private_key, public_key = generate_rsa_keys()

public_key_bytes = public_key_to_bytes(public_key)


def broadcast(message, exclude=None):
    """
    sends message to everyone in the chat room
    """

    with lock:

        for client in clients:

            if client != exclude:

                try:
                    encrypted = aes_encrypt(
                        clients[client]["aes"],
                        message
                    )

                    send_packet(
                        client,
                        encrypted
                    )

                except:
                    pass



def handle_client(conn, addr):

    print(f"[+] Connection: {addr}")

    username = "Unknown"

    try:

        # send the RSA pub key

        send_packet(
            conn,
            public_key_bytes
        )

        # Recieved AES key from the client

        encrypted_aes = recv_packet(conn)


        aes_key = rsa_decrypt(
            private_key,
            encrypted_aes
        )


        # Receive the Encrypted username data that comes from the client 

        while True:

            encrypted_name = recv_packet(conn)

            username = aes_decrypt(
                aes_key,
                encrypted_name
            )

            username = re.sub(
                r"\s+",
                " ",
                username.strip()
            )

            if not username:

                send_packet(
                    conn,
                    aes_encrypt(
                        aes_key,
                        "USERNAME_INVALID"
                    )
                )

                print("[***] Rejected! Empty username")

                continue

            with lock:

                normalized_username = username.casefold()

                username_taken = any(
                    re.sub(
                        r"\s+",
                        " ",
                        client_data["username"].strip()
                    ).casefold() == normalized_username
                    for client_data in clients.values()
                )

                if username_taken:

                    send_packet(
                        conn,
                        aes_encrypt(
                            aes_key,
                            "USERNAME_TAKEN"
                        )
                    )

                    print("[***] Rejected! Username already taken")

                    continue

                clients[conn] = {
                    "username": username,
                    "aes": aes_key
                }

                break


        send_packet(
            conn,
            aes_encrypt(
                aes_key,
                "USERNAME_OK"
            )
        )


        print(
            f"[+] {username} joined"
        )


        broadcast(
            f"[SERVER] {username} joined chat.",
            conn
        )


        while True:


            data = recv_packet(conn)


            message = aes_decrypt(
                aes_key,
                data
            )


            print(
                f"{username}: {message}"
            )


            broadcast(
                f"{username}: {message}",
                conn
            )



    except Exception as e:

        print(
            "[!] Client error:",
            e
        )


    finally:


        with lock:

            if conn in clients:

                username = clients[conn]["username"]

                del clients[conn]

            else:

                username = "Unknown"



        try:
            conn.close()
        except:
            pass


        if username != "Unknown":

            broadcast(
                f"[SERVER] {username} left chat."
            )


        print(
            f"[-] {username} disconnected..."
        )




def start_server():


    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )


    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )


    server.bind(
        (HOST, PORT)
    )


    server.listen()


    print(
        f"{makeup.TextColor["cyan"]}\n[SERVER] Listening {HOST}:{PORT}"
    )


    while True:


        conn, addr = server.accept()
        


        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )


        thread.start()



if __name__ == "__main__":

    start_server()