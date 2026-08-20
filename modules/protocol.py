import socket
import struct


def recvall(sock: socket.socket, length: int) -> bytes:
    """
    length kadar veri gelene kadar bekler.
    """

    data = b""

    while len(data) < length:
        packet = sock.recv(length - len(data))

        if not packet:
            raise ConnectionError("Connection closed.")

        data += packet

    return data


def send_packet(sock: socket.socket, data: bytes):
    """
    sends 4 bytes long data
    """

    header = struct.pack(">I", len(data))

    sock.sendall(header)
    sock.sendall(data)


def recv_packet(sock: socket.socket) -> bytes:
    """
    reads the lenght of the data first and then reads the whole packet

    """

    header = recvall(sock, 4)

    length = struct.unpack(">I", header)[0]

    return recvall(sock, length)