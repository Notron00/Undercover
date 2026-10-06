# Undercover
![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-yellow)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

> 🇬🇧 English | [🇹🇷 Türkçe](README.tr.md)

> Educational encrypted TCP chat application written in Python.

Undercover is a client-server TCP chat application developed to explore network programming, socket communication, cryptography, and secure communication protocols.

The project uses RSA to securely exchange an AES session key between the client and server. After the key exchange, chat communication is encrypted using AES-256-GCM.

## Contents

- [Features](#features)
- [Security Features](#security-features)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Installation](#installation)
- [Usage](#running-the-server)
- [Commands](#commands)
- [Security Considerations](#security-considerations)


## Features

- TCP client-server architecture
- Multi-client support
- Thread-based client handling
- RSA public/private key pair
- RSA-encrypted AES session key exchange
- AES-256-GCM encrypted chat messages
- Custom packet protocol
- Username management
- Duplicate username protection
- Linux development environment
- Modular project structure

## Security Features

- **Hybrid encryption**: RSA-2048 (OAEP) for session key exchange, AES-256-GCM for messages
- **Authenticated encryption**: AES-GCM provides both confidentiality and integrity
- **MITM protection**: TOFU-based server key pinning (SSH-style). The client verifies the server's public key fingerprint on first connection and warns if a known server's key ever changes. A fingerprint can also be pinned explicitly via argument.
- **DoS hardening**: packet size limits reject oversized messages before allocating memory
- **Thread-safe broadcasting**: the client list is copied under a lock, then released before network sends, so one slow client cannot block the server

## Architecture

```text
                     TCP CONNECTION
Client  ──────────────────────────────────►  Server
  │                                             │
  │          RSA Public Key                     │
  │ ◄────────────────────────────────────────── │
  │                                             │
  │          AES Session Key                    │
  │ ───────────── RSA Encrypted ─────────────►  │
  │                                             │
  │          AES Encrypted Messages             │
  │ ◄────────────────────────────────────────►  │
  │                                             │
```

## Cryptographic Design

Undercover uses a hybrid encryption approach.

### 1. RSA

The server generates an RSA-2048 key pair and persists it to disk (`server_key.pem`) so its fingerprint stays stable across restarts.

The server sends its public key to the client. The client verifies the key's SHA-256 fingerprint (see MITM protection) before trusting it.

The client generates a random AES session key and encrypts it using the server's RSA public key (OAEP padding).

The server decrypts the AES key using its RSA private key.

### 2. AES-256-GCM

After the key exchange, the client and server use the AES session key for chat communication.

AES-256-GCM is used, providing both confidentiality and integrity (authenticated encryption). A fresh 12-byte nonce is generated for every message. This avoids using RSA to encrypt every individual message.

## Project Structure

```text
Undercover/
│
├── client.py
├── server.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── modules/
    ├── __init__.py
    ├── crypto.py
    ├── protocol.py
    └── makeup.py
```

### `client.py`

Handles server connection, RSA public key reception and fingerprint verification, AES session key generation and encryption, username registration, message encryption/decryption, and user input.

### `server.py`

Handles the TCP server, client connections, RSA key generation/persistence, AES session key decryption, username management, message broadcasting, and client threads.

### `modules/crypto.py`

Contains cryptographic functions: RSA/AES operations, key persistence, and public key fingerprinting.

### `modules/protocol.py`

Contains the custom packet protocol (length-prefixed framing) with size limits to prevent memory-exhaustion DoS.

### `modules/makeup.py`

Contains terminal UI, colors, and banner functions.

## Installation

Clone the repository:

```bash
git clone https://github.com/Notron00/Undercover.git
cd Undercover
```

Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the Server

Start the server with a port:

```bash
python server.py 5555
```

On first run the server generates and saves an RSA key pair, then prints its public key fingerprint:

```text
[SERVER] Public key fingerprint:
  <64-character hex fingerprint>
[SERVER] Listening 0.0.0.0:5555
```

## Running the Client

Connect using:

```bash
python client.py 127.0.0.1 5555
```

On first connection the client shows the server's fingerprint and asks you to trust it (trust-on-first-use). It remembers trusted servers in `~/.undercover_known_hosts` and warns if a server's key later changes.

To pin a known fingerprint explicitly (strict mode), pass it as a third argument:

```bash
python client.py 127.0.0.1 5555 <fingerprint>
```

Replace `127.0.0.1` with the server's IP address when connecting from another machine.

You can run server on vds/routed Port
**TOR HiddenService supported**

### Commands

- `/join <room> [password]` — join or create a room (creator becomes owner)
- `/setpass <password>` — owner sets a room password
- `/delpass` — owner removes the room password
- `/quit` or `/exit` — disconnect
- `/msg <user> <message>` — send a private message

## Security Considerations

This project is primarily an educational implementation for learning network security and cryptography.

While it includes MITM protection, DoS hardening, and authenticated encryption, it should not be considered a fully production-ready secure messaging application without further review.

**Password hashing**: room passwords are stored as bcrypt hashes (salted), never in plaintext



## Learning Goals

The project was developed to practice:

- Python network programming
- TCP sockets
- Client-server architecture
- Multithreading
- Symmetric cryptography
- Asymmetric cryptography
- Hybrid encryption
- Network protocols
- Key pinning and fingerprint verification
- Linux development
- Git and GitHub

## Implemented Security Improvements

- [✓] AES-256-GCM authenticated encryption
- [✓] MITM protection via TOFU key pinning (SSH-style)
- [✓] Packet size limits (DoS hardening)
- [✓] Thread-safe broadcasting (no lock contention)
- [✓] Persistent server key with fingerprint verification
- [✓] Replay protection [DoS Hardening]
- [✓] bcrypt password hashing for protected rooms
- [✓] Chat rooms
- [✓] User authentication
- [✓] Private messaging
- [✓] Server_key.pem file is now owner only (0600 rule)


## Future Improvements
- [ ] E2EE (End-to-End Encryption) 
- [ ] Windows compatibility

