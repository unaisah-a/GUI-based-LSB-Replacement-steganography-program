"""RSA-PSS signing primitives."""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


SIGNATURE_DOMAIN = b"INF2005-ACW1-SIGNED-PAYLOAD\x00"
SIG_HEADER_SIZE = 4
RSA_SIG_SIZE = 256  # Compatibility constant for the default 2048-bit key.


def sign_bytes(data: bytes, private_key) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return private_key.sign(
        SIGNATURE_DOMAIN + data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_bytes(data: bytes, signature: bytes, public_key) -> bool:
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        return False
    try:
        public_key.verify(
            signature,
            SIGNATURE_DOMAIN + data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_payload_block(raw_payload_block: bytes, private_key) -> bytes:
    """Compatibility framing: block + four-byte signature length + signature."""
    signature = sign_bytes(raw_payload_block, private_key)
    return raw_payload_block + struct.pack(">I", len(signature)) + signature


def verify_signature(full_extracted_bytes: bytes, public_key) -> tuple[bytes, bool]:
    """Verify compatibility framing without assuming a fixed RSA key size."""
    if len(full_extracted_bytes) < SIG_HEADER_SIZE:
        return b"", False
    expected_size = (public_key.key_size + 7) // 8
    if len(full_extracted_bytes) < SIG_HEADER_SIZE + expected_size:
        return b"", False
    header_at = len(full_extracted_bytes) - expected_size - SIG_HEADER_SIZE
    raw = full_extracted_bytes[:header_at]
    length = struct.unpack(">I", full_extracted_bytes[header_at : header_at + 4])[0]
    signature = full_extracted_bytes[header_at + 4 :]
    return raw, length == len(signature) and verify_bytes(raw, signature, public_key)
