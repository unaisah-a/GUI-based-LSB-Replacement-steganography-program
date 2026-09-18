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
    sidecar_bytes: int
    storage_overhead_bytes: int


@dataclass(frozen=True)
class RecoveryInspection:
    sidecar_path: str
    original_sha256: str
    protected_sha256: str
    original_bytes: int
    sidecar_bytes: int
    storage_overhead_bytes: int


def _inspect_bytes(sidecar: bytes, sidecar_path: Path) -> RecoveryInspection:
    if len(sidecar) < HEADER.size + 16:
        raise ValueError("recovery sidecar is truncated")
    magic, version, _nonce, protected_hash, original_hash, length = HEADER.unpack_from(
        sidecar
    )
    if magic != MAGIC or version != VERSION:
        raise ValueError("recovery sidecar format is unsupported")
    if length > MAX_ORIGINAL_BYTES:
        raise ValueError("recovery sidecar declares an unsafe original length")
    expected = HEADER.size + length + 16
    if len(sidecar) != expected:
        raise ValueError(
            f"recovery sidecar length is invalid: expected {expected} bytes, "
            f"received {len(sidecar)}"
        )
    return RecoveryInspection(
        str(sidecar_path),
        original_hash.hex(),
        protected_hash.hex(),
        length,
        len(sidecar),
        len(sidecar) - length,
    )


def inspect_recovery_sidecar(
    sidecar_path: str | os.PathLike[str],
) -> RecoveryInspection:
    """Validate bounded sidecar framing and report its encrypted-backup overhead."""
    source = Path(sidecar_path).resolve()
    sidecar = _read_limited(source, MAX_ORIGINAL_BYTES + HEADER.size + 16)
    return _inspect_bytes(sidecar, source)


def _read_limited(path: str | os.PathLike[str], limit: int) -> bytes:
    source = Path(path)
    size = source.stat().st_size
    if size > limit:
        raise ValueError(f"{source.name} exceeds the {limit:,}-byte safety limit")
    return source.read_bytes()


def _paths_alias(first: Path, second: Path) -> bool:
    first = first.resolve()
    second = second.resolve()
    if first == second:
        return True
    if first.exists() and second.exists():
        try:
            return os.path.samefile(first, second)
        except OSError:
            return False
    return False


def _validate_output(path: Path, inputs: tuple[Path, ...], overwrite: bool) -> None:
    if not isinstance(overwrite, bool):
        raise TypeError("overwrite must be a boolean")
    if any(_paths_alias(path, source) for source in inputs):
        raise ValueError("recovery output must differ from every input file")
    if not path.parent.is_dir():
        raise FileNotFoundError("recovery output directory does not exist")
    if path.is_dir():
        raise IsADirectoryError(f"recovery output is a directory: {path.name}")
    if path.exists() and not overwrite:
        raise FileExistsError(f"recovery output already exists: {path.name}")


def _atomic_write(path: Path, data: bytes, *, overwrite: bool) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and not overwrite:
            raise FileExistsError(f"recovery output already exists: {path.name}")
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
    *,
    overwrite: bool = False,
) -> RecoveryResult:
    """Encrypt an exact original file and bind it to one protected output."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("recovery key must contain exactly 32 bytes")
    original_source = Path(original_path).resolve()
    protected_source = Path(protected_path).resolve()
    destination = Path(sidecar_path).resolve()
    if _paths_alias(original_source, protected_source):
        raise ValueError("original and protected paths must be different")
    _validate_output(destination, (original_source, protected_source), overwrite)
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
    _atomic_write(destination, sidecar, overwrite=overwrite)
    return RecoveryResult(
        str(destination),
        original_hash.hex(),
        protected_hash.hex(),
        length,
        len(sidecar),
        len(sidecar) - length,
    )


def restore_original(
    protected_path: str | os.PathLike[str],
    sidecar_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    key: bytes,
    *,
    overwrite: bool = False,
) -> RecoveryResult:
    """Restore and validate the byte-for-byte original from its sidecar."""
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("recovery key must contain exactly 32 bytes")
    protected_source = Path(protected_path).resolve()
    sidecar_source = Path(sidecar_path).resolve()
    destination = Path(output_path).resolve()
    if _paths_alias(protected_source, sidecar_source):
        raise ValueError("protected and recovery sidecar paths must be different")
    _validate_output(destination, (protected_source, sidecar_source), overwrite)
    sidecar = _read_limited(sidecar_path, MAX_ORIGINAL_BYTES + HEADER.size + 16)
    inspection = _inspect_bytes(sidecar, sidecar_source)
    _magic, _version, nonce, protected_hash, original_hash, length = HEADER.unpack_from(
        sidecar
    )
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
    _atomic_write(destination, original, overwrite=overwrite)
    return RecoveryResult(
        str(destination),
        original_hash.hex(),
        protected_hash.hex(),
        len(original),
        inspection.sidecar_bytes,
        inspection.storage_overhead_bytes,
    )
