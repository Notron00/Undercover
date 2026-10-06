import os
import sys
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.protocol import send_packet, recv_packet, MAX_PACKET_SIZE


def _socket_pair():
    """Creates a connected local socket pair for testing send/recv."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))  # port 0 = let OS pick a free port
    server.listen(1)
    port = server.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn, _ = server.accept()
    server.close()
    return client, conn


def test_packet_roundtrip():
    a, b = _socket_pair()
    try:
        send_packet(a, b"hello world")
        assert recv_packet(b) == b"hello world"
    finally:
        a.close()
        b.close()


def test_empty_packet():
    a, b = _socket_pair()
    try:
        send_packet(a, b"")
        assert recv_packet(b) == b""
    finally:
        a.close()
        b.close()


def test_binary_data_roundtrip():
    a, b = _socket_pair()
    try:
        payload = bytes(range(256)) * 10  # arbitrary binary
        send_packet(a, payload)
        assert recv_packet(b) == payload
    finally:
        a.close()
        b.close()


def test_send_rejects_oversized_packet():
    a, b = _socket_pair()
    try:
        too_big = b"x" * (MAX_PACKET_SIZE + 1)
        with pytest.raises(ValueError):
            send_packet(a, too_big)
    finally:
        a.close()
        b.close()


def test_recv_rejects_oversized_header():
    """A malicious peer announcing a huge length must be rejected (DoS protection)."""
    import struct
    a, b = _socket_pair()
    try:
        # Craft a header claiming a size larger than MAX_PACKET_SIZE,
        # bypassing send_packet's own guard.
        fake_header = struct.pack(">I", MAX_PACKET_SIZE + 1)
        a.sendall(fake_header)
        with pytest.raises(ValueError):
            recv_packet(b)
    finally:
        a.close()
        b.close()