"""SHA-256 hashing helpers for the payload and verification layers.

Two forms of the same digest are offered because callers need both: the hex
string goes into the JSON verification record, and the raw bytes are used for
constant-time comparison.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = [
    "SHA256_DIGEST_BYTES",
    "SHA256_HEX_LENGTH",
    "compute_media_hash",
    "compute_raw_sha256",
    "hashes_equal",
]

#: A SHA-256 digest is 32 bytes, which is 64 hexadecimal characters.
SHA256_DIGEST_BYTES = 32
SHA256_HEX_LENGTH = SHA256_DIGEST_BYTES * 2


def compute_media_hash(media_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of *media_bytes*.

    Used for the ``message_hash`` field of the verification record, which records
    the digest of the **plaintext** message even when the message is carried
    encrypted (see :mod:`app.crypto.envelope`).
    """
    if not isinstance(media_bytes, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"media_bytes must be a bytes-like object, got {type(media_bytes).__name__}"
        )
    return hashlib.sha256(media_bytes).hexdigest()


def compute_raw_sha256(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"data must be a bytes-like object, got {type(data).__name__}"
        )
    return hashlib.sha256(data).digest()


def hashes_equal(left: str | bytes, right: str | bytes) -> bool:
    """Compare two digests without leaking timing information.

    Accepts hex strings or raw bytes, but both arguments must use the same form.
    A digest comparison is not a secret-key operation, so this is defence in
    depth rather than a strict necessity; it costs nothing to do it properly.
    """
    if isinstance(left, str) != isinstance(right, str):
        raise TypeError("both digests must be hex strings or both must be bytes")
    if isinstance(left, str):
        return hmac.compare_digest(left.lower(), right.lower())
    return hmac.compare_digest(left, right)
