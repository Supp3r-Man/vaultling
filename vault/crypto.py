"""Envelope encryption built only on `cryptography` (AES-256-GCM). No custom primitives.

Each secret version gets its own random 256-bit data key (DEK). The DEK encrypts the value once;
the master key then wraps the DEK. Both operations bind the ciphertext to the secret's name and
version through GCM's associated data (AAD), so a record copied to another name or version fails
to decrypt instead of silently returning the wrong secret.

Blob format: 12-byte random nonce || ciphertext || 16-byte GCM tag.
Nonce safety: a DEK encrypts exactly one message, so its nonce can never repeat; the master key
wraps one DEK per secret version with random 96-bit nonces, far below the birthday bound.
"""
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
KEYCHECK_PLAINTEXT = b"vaultling-keycheck"


class DecryptError(Exception):
    """Wrong key, tampered data, or ciphertext presented under the wrong name/version."""


def new_key():
    return AESGCM.generate_key(bit_length=256)


def aad(kind, name, version):
    """Unambiguous AAD: a JSON array, so ('a/1', 2) can never collide with ('a', '1/2')."""
    return json.dumps(["vaultling/v1", kind, name, version], separators=(",", ":")).encode("utf-8")


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_BYTES:
        raise ValueError("keys must be exactly 32 bytes")


def encrypt(key, plaintext, associated_data):
    _check_key(key)
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(bytes(key)).encrypt(nonce, plaintext, associated_data)


def decrypt(key, blob, associated_data):
    _check_key(key)
    if len(blob) < NONCE_BYTES + TAG_BYTES:
        raise DecryptError("ciphertext is too short")
    try:
        return AESGCM(bytes(key)).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], associated_data)
    except InvalidTag:
        raise DecryptError("authentication failed (wrong key, tampering, or wrong name/version)") from None


def encrypt_secret(master_key, name, version, plaintext):
    """Return (ciphertext, wrapped_data_key) for one secret version."""
    dek = new_key()
    ciphertext = encrypt(dek, plaintext, aad("secret", name, version))
    wrapped = encrypt(master_key, dek, aad("dek", name, version))
    return ciphertext, wrapped


def decrypt_secret(master_key, name, version, ciphertext, wrapped_dek):
    dek = decrypt(master_key, wrapped_dek, aad("dek", name, version))
    return decrypt(dek, ciphertext, aad("secret", name, version))


def rewrap_dek(old_master, new_master, name, version, wrapped_dek):
    """Move a data key under a new master key. The secret's ciphertext is not touched."""
    dek = decrypt(old_master, wrapped_dek, aad("dek", name, version))
    return encrypt(new_master, dek, aad("dek", name, version))


def make_keycheck(master_key, master_version):
    """Small known-plaintext blob so a wrong reconstructed master key is detected at unseal."""
    return encrypt(master_key, KEYCHECK_PLAINTEXT, aad("keycheck", "-", master_version))


def check_keycheck(master_key, blob, master_version):
    try:
        return decrypt(master_key, blob, aad("keycheck", "-", master_version)) == KEYCHECK_PLAINTEXT
    except DecryptError:
        return False
