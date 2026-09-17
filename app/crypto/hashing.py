"""Hash helpers used by payload construction and verification."""

from __future__ import annotations

import hashlib
import hmac


def compute_raw_sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data* as 32 raw bytes."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).digest()


def compute_sha256(data: bytes) -> str:
    """Return the SHA-256 digest of *data* as lower-case hexadecimal."""
    return compute_raw_sha256(data).hex()


def compute_media_hash(media_bytes: bytes) -> str:
    """Compatibility alias for callers that hash a byte representation."""
    return compute_sha256(media_bytes)


def hashes_match(expected_hex: str, data: bytes) -> bool:
    """Compare a supplied hexadecimal SHA-256 value in constant time."""
    if not isinstance(expected_hex, str):
        return False
    return hmac.compare_digest(expected_hex.lower(), compute_sha256(data))
