import hashlib
from cryptography.hazmat.primitives import hashes

def compute_media_hash(media_bytes: bytes) -> str:
    "Computes a SHA-256 hex digest for original media integrity verification (FR9)."
    digest = hashes.Hash(hashes.SHA256())
    digest.update(media_bytes)
    return digest.finalize().hex()

def compute_raw_sha256(data: bytes) -> bytes:
    "Returns raw SHA-256 bytes for internal cryptographic checks."
    return hashlib.sha256(data).digest()