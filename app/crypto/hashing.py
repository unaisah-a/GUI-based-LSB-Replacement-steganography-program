"""SHA-256, the one place the application computes it.

The verification record carries the digest of the plaintext message, the manifest
carries the digest of the stego file, and the media comparison reports whether two
files are byte-identical. All of them use these functions.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Final

__all__ = [
    "SHA256_HEX_LENGTH",
    "file_sha256",
    "hashes_equal",
    "sha256_hex",
]

#: A SHA-256 digest is 32 bytes, which is 64 hexadecimal characters.
SHA256_HEX_LENGTH: Final[int] = 64


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be a bytes-like object, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: str | os.PathLike[str], *, chunk_bytes: int = 1 << 20) -> str:
    """Return the SHA-256 hex digest of the file at *path*, read in chunks.

    Chunked so a large video does not have to be held in memory at once.
    """
    digest = hashlib.sha256()
    with open(os.fspath(path), "rb") as handle:
        while chunk := handle.read(chunk_bytes):
            digest.update(chunk)
    return digest.hexdigest()


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
