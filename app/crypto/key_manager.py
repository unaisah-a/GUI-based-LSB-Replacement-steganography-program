"""RSA key generation, storage and fingerprint helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keys(key_size: int = 2048):
    """Generate an RSA private/public key pair suitable for RSA-PSS."""
    if key_size < 2048:
        raise ValueError("key_size must be at least 2048 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as stream:
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


def save_private_key_to_pem(
    key, filepath: str | os.PathLike[str], password: str | None
) -> None:
    """Save a private key, encrypted when a non-empty password is supplied."""
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    _atomic_write(Path(filepath), pem)


def save_public_key_to_pem(key, filepath: str | os.PathLike[str]) -> None:
    """Save a public key in SubjectPublicKeyInfo PEM format."""
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _atomic_write(Path(filepath), pem)


def save_key_to_pem(key, filepath: str, is_private: bool = True) -> None:
    """Compatibility wrapper used by the original project modules."""
    if is_private:
        save_private_key_to_pem(key, filepath, password=None)
    else:
        save_public_key_to_pem(key, filepath)


def load_private_key_from_pem(
    filepath: str | os.PathLike[str], password: str | None = None
):
    with open(filepath, "rb") as stream:
        data = stream.read()
    encoded_password = password.encode("utf-8") if password else None
    return serialization.load_pem_private_key(data, password=encoded_password)


def load_public_key_from_pem(filepath: str | os.PathLike[str]):
    with open(filepath, "rb") as stream:
        return serialization.load_pem_public_key(stream.read())


def public_key_fingerprint(public_key) -> str:
    """Return a stable SHA-256 fingerprint for trust confirmation."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()
