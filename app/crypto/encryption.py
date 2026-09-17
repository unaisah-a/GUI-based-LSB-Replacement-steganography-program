"""AES-256-GCM helpers for the confidential custom-payload demonstration."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_BYTES = 12
KEY_BYTES = 32


def generate_encryption_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encode_key(key: bytes) -> str:
    _validate_key(key)
    return base64.urlsafe_b64encode(key).decode("ascii")


def decode_key(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("encoded key must be text")
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise ValueError("encryption key is not valid URL-safe base64") from exc
    _validate_key(key)
    return key


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("AES-256-GCM key must contain exactly 32 bytes")


def encrypt_message(
    message: bytes, key: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    _validate_key(key)
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, message, associated_data)


def decrypt_message(
    ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes
) -> bytes:
    _validate_key(key)
    if len(nonce) != NONCE_BYTES:
        raise ValueError("AES-GCM nonce must contain exactly 12 bytes")
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
