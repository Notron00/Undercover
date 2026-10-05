import socket
import struct

# Maximum allowed packet size (1 MB). Prevents a malicious peer from announcing
# a huge length and forcing the other side to allocate/wait for unbounded data
# (memory-exhaustion / DoS). Adjust if the protocol ever needs larger messages.
MAX_PACKET_SIZE = 1024 * 1024


def recvall(sock: socket.socket, length: int) -> bytes:
    """
    Reads exactly `length` bytes from the socket, blocking until they arrive.
    Uses a bytearray to avoid O(n^2) copying on repeated concatenation.
    """
    data = bytearray()

    while len(data) < length:
        packet = sock.recv(length - len(data))

        if not packet:
            raise ConnectionError("Connection closed.")

        data.extend(packet)

    return bytes(data)


def send_packet(sock: socket.socket, data: bytes):
    """
    Sends a packet: a 4-byte big-endian length header followed by the data.
    """
    if len(data) > MAX_PACKET_SIZE:
        raise ValueError(f"Packet too large to send: {len(data)} > {MAX_PACKET_SIZE}")

    header = struct.pack(">I", len(data))
    sock.sendall(header)
    sock.sendall(data)


def recv_packet(sock: socket.socket) -> bytes:
    """
    Reads the 4-byte length header first, then reads the full packet.
    Rejects oversized packets before allocating memory for them.
    """
    header = recvall(sock, 4)
    length = struct.unpack(">I", header)[0]

    if length > MAX_PACKET_SIZE:
        raise ValueError(f"Packet too large: {length} > {MAX_PACKET_SIZE}")

    return recvall(sock, length)