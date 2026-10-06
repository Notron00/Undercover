import os
import sys

# Allow importing the modules package from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from modules.crypto import (
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    generate_rsa_keys,
    public_key_to_bytes,
    load_public_key,
    rsa_encrypt,
    rsa_decrypt,
    public_key_fingerprint,
    fingerprint_from_bytes,
    hash_password,
    verify_password,
)


# ---------- AES ----------

def test_aes_roundtrip():
    key = generate_aes_key()
    seq, msg = aes_decrypt(key, aes_encrypt(key, "hello world", 5))
    assert msg == "hello world"
    assert seq == 5


def test_aes_wrong_key_fails():
    key1 = generate_aes_key()
    key2 = generate_aes_key()
    data = aes_encrypt(key1, "secret", 0)
    with pytest.raises(Exception):
        aes_decrypt(key2, data)


def test_aes_tamper_detected():
    key = generate_aes_key()
    data = bytearray(aes_encrypt(key, "secret", 0))
    data[-1] ^= 0x01  # flip one bit in the ciphertext
    with pytest.raises(Exception):
        aes_decrypt(key, bytes(data))


def test_aes_sequence_preserved():
    key = generate_aes_key()
    for n in (0, 1, 42, 999999):
        seq, _ = aes_decrypt(key, aes_encrypt(key, "x", n))
        assert seq == n


# ---------- RSA ----------

def test_rsa_roundtrip():
    priv, pub = generate_rsa_keys()
    aes_key = generate_aes_key()
    recovered = rsa_decrypt(priv, rsa_encrypt(pub, aes_key))
    assert recovered == aes_key


def test_public_key_serialization():
    _, pub = generate_rsa_keys()
    pub_bytes = public_key_to_bytes(pub)
    loaded = load_public_key(pub_bytes)
    assert public_key_fingerprint(pub) == public_key_fingerprint(loaded)


# ---------- Fingerprint ----------

def test_fingerprint_stable_and_matches():
    _, pub = generate_rsa_keys()
    pub_bytes = public_key_to_bytes(pub)
    fp1 = public_key_fingerprint(pub)
    fp2 = fingerprint_from_bytes(pub_bytes)
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex


def test_different_keys_different_fingerprints():
    _, pub1 = generate_rsa_keys()
    _, pub2 = generate_rsa_keys()
    assert public_key_fingerprint(pub1) != public_key_fingerprint(pub2)


# ---------- Password hashing ----------

def test_password_hash_and_verify():
    hashed = hash_password("hunter2")
    assert verify_password("hunter2", hashed)
    assert not verify_password("wrong", hashed)


def test_password_hash_is_salted():
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2
    assert verify_password("same", h1)
    assert verify_password("same", h2)