# Undercover

> Educational encrypted TCP chat application written in Python.

Undercover is a client-server TCP chat application developed to explore network programming, socket communication, cryptography, and secure communication protocols.

The project uses RSA to securely exchange an AES session key between the client and server. After the key exchange, chat communication is encrypted using AES.

## Features

- TCP client-server architecture
- Multi-client support
- Thread-based client handling
- RSA public/private key pair
- RSA-encrypted AES session key exchange
- AES-encrypted chat messages
- Custom packet protocol
- Username management
- Duplicate username protection
- Linux development environment
- Modular project structure

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

The server generates an RSA key pair:

```text
Private Key
Public Key
```

The server sends its public key to the client.

The client generates a random AES session key and encrypts it using the server's RSA public key.

```text
AES Session Key
      │
      ▼
RSA Public Key
      │
      ▼
Encrypted AES Key
      │
      ▼
     Server
```

The server decrypts the AES key using its RSA private key.

### 2. AES

After the key exchange, the client and server use the AES session key for chat communication.

This avoids using RSA to encrypt every individual message.

```text
Client Message
      │
      ▼
 AES Encryption
      │
      ▼
Encrypted Packet
      │
      ▼
     TCP
      │
      ▼
   Server
      │
      ▼
 AES Decryption
      │
      ▼
Original Message
```

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

Handles:

- Server connection
- RSA public key reception
- AES session key generation
- AES key encryption
- Username registration
- Message encryption/decryption
- User input

### `server.py`

Handles:

- TCP server
- Client connections
- RSA key generation
- AES session key decryption
- Username management
- Message broadcasting
- Client threads

### `modules/crypto.py`

Contains cryptographic functions used by the client and server.

### `modules/protocol.py`

Contains the custom packet sending and receiving functions.

### `modules/makeup.py`

Contains terminal UI, colors, and banner functions.

## Installation

Clone the repository:

```bash
git clone https://github.com/Notron00/Undercover.git
cd Undercover-
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Server

Start the server with a port:

```bash
python server.py 5555
```

Example:

```text
[SERVER] Listening 0.0.0.0:5555
```

## Running the Client

Connect using:

```bash
python client.py 127.0.0.1 5555
```

Replace `127.0.0.1` with the server's IP address when connecting from another machine.

## Security Considerations

This project is primarily an educational implementation for learning network security and cryptography.

It should not currently be considered a production-ready secure messaging application.

Areas that can be improved include:

- Authenticated encryption
- Stronger protocol authentication
- Replay attack protection
- Key lifecycle management
- User authentication
- Rate limiting
- Better error handling
- Security logging
- Automated security testing
- Formal protocol specification

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
- Linux development
- Git and GitHub

## Future Improvements

- [ ] AES-GCM authenticated encryption
- [ ] Replay protection
- [ ] User authentication
- [ ] Private messaging
- [ ] Chat rooms
- [ ] Rate limiting
- [ ] Security logging
- [ ] Automated tests
- [ ] Protocol documentation
- [ ] Improved exception handling

## Disclaimer

Undercover is an educational project developed for learning purposes.

The project should not be used to protect sensitive or production communications without further security review and testing.
