from collections.abc import Sequence
import os
import hashlib
import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------- RSA ---------------- #

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(data):
    return serialization.load_pem_public_key(data)

# ---------------- PASSWORD HASHING ---------------- #

def hash_password(password: str) -> bytes:
    """Hashes a password with bcrypt (salt is generated and embedded automatically)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    """Checks a password against a stored bcrypt hash. Returns True if it matches."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except (ValueError, TypeError):
        return False

def rsa_encrypt(public_key, data: bytes):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ---------------- AES ---------------- #

def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(key: bytes, plaintext: str, sequence: int = 0):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    payload = sequence.to_bytes(8, "big") + plaintext.encode("utf-8")
    ciphertext = aes.encrypt(nonce, payload, None)
    return nonce + ciphertext


def aes_decrypt(key: bytes, data: bytes):
    aes = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    payload = aes.decrypt(nonce, ciphertext, None)
    sequence = int.from_bytes(payload[:8], "big")
    plaintext = payload[8:].decode("utf-8")
    return sequence, plaintext

def save_private_key(private_key, path: str):
    """Writes the RSA private key to disk in PEM format with owner-only permissions."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(pem)
    os.chmod(path, 0o600)

def load_private_key(path: str):
    """Loads an RSA private key from a PEM file. Returns (private_key, public_key)."""
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key, private_key.public_key()


def public_key_fingerprint(public_key) -> str:
    """Returns the SHA-256 fingerprint (hex) of a public key's DER encoding."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def fingerprint_from_bytes(public_key_bytes: bytes) -> str:
    """Computes the fingerprint from raw PEM public key bytes (as received over the network)."""
    public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key_fingerprint(public_key)


