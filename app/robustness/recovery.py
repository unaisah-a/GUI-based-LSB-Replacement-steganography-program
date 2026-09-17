"""Encrypted sidecar-assisted restoration of an exact original file."""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"SMIR"
VERSION = 1
HEADER = struct.Struct(">4sB12s32s32sQ")
MAX_ORIGINAL_BYTES = 256 * 1024 * 1024
DOMAIN = b"INF2005-RECOVERY-SIDECAR-V1\x00"


@dataclass(frozen=True)
class RecoveryResult:
    output_path: str
    original_sha256: str
    protected_sha256: str
    restored_bytes: int


def _read_limited(path: str | os.PathLike[str], limit: int) -> bytes:
    source = Path(path)
    size = source.stat().st_size
    if size > limit:
        raise ValueError(f"{source.name} exceeds the {limit:,}-byte safety limit")
    return source.read_bytes()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def create_recovery_sidecar(
    original_path: str | os.PathLike[str],
    protected_path: str | os.PathLike[str],
    sidecar_path: str | os.PathLike[str],
    key: bytes,
) -> RecoveryResult:
    """Encrypt an exact original file and bind it to one protected output."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("recovery key must contain exactly 32 bytes")
    original = _read_limited(original_path, MAX_ORIGINAL_BYTES)
    protected = _read_limited(protected_path, MAX_ORIGINAL_BYTES)
    original_hash = hashlib.sha256(original).digest()
    protected_hash = hashlib.sha256(protected).digest()
    nonce = os.urandom(12)
    length = len(original)
    associated_data = (
        DOMAIN + protected_hash + original_hash + length.to_bytes(8, "big")
    )
    ciphertext = AESGCM(key).encrypt(nonce, original, associated_data)
    sidecar = HEADER.pack(
        MAGIC,
        VERSION,
        nonce,
        protected_hash,
        original_hash,
        length,
    ) + ciphertext
    _atomic_write(Path(sidecar_path), sidecar)
    return RecoveryResult(
        str(sidecar_path),
        original_hash.hex(),
        protected_hash.hex(),
        length,
    )


def restore_original(
    protected_path: str | os.PathLike[str],
    sidecar_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    key: bytes,
) -> RecoveryResult:
    """Restore and validate the byte-for-byte original from its sidecar."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("recovery key must contain exactly 32 bytes")
    sidecar = _read_limited(sidecar_path, MAX_ORIGINAL_BYTES + HEADER.size + 16)
    if len(sidecar) < HEADER.size + 16:
        raise ValueError("recovery sidecar is truncated")
    magic, version, nonce, protected_hash, original_hash, length = HEADER.unpack_from(
        sidecar
    )
    if magic != MAGIC or version != VERSION:
        raise ValueError("recovery sidecar format is unsupported")
    if length > MAX_ORIGINAL_BYTES:
        raise ValueError("recovery sidecar declares an unsafe original length")
    protected = _read_limited(protected_path, MAX_ORIGINAL_BYTES)
    current_protected_hash = hashlib.sha256(protected).digest()
    if current_protected_hash != protected_hash:
        raise ValueError("recovery sidecar is bound to a different protected file")
    associated_data = (
        DOMAIN + protected_hash + original_hash + length.to_bytes(8, "big")
    )
    try:
        original = AESGCM(key).decrypt(
            nonce, sidecar[HEADER.size :], associated_data
        )
    except InvalidTag as exc:
        raise ValueError("recovery sidecar authentication failed") from exc
    if len(original) != length or hashlib.sha256(original).digest() != original_hash:
        raise ValueError("restored original failed its length or hash check")
    destination = Path(output_path)
    if destination.resolve() == Path(protected_path).resolve():
        raise ValueError("restored output must not overwrite the protected file")
    _atomic_write(destination, original)
    return RecoveryResult(
        str(destination),
        original_hash.hex(),
        protected_hash.hex(),
        len(original),
    )
