"""RSA key generation, storage and loading.

Formats on disk are the conventional ones: unencrypted PKCS#8 PEM for private
keys, SubjectPublicKeyInfo PEM for public keys.

About the unencrypted private key
---------------------------------
:func:`ensure_demo_keys` writes a private key with no passphrase, so the
demonstration and the automated tests can sign without prompting. That is the
wrong arrangement for anything real, and the application says so rather than
leaving it implied: :data:`app.utils.constants.DEMO_KEY_NOTICE` is displayed
beside the key controls in the GUI and repeated in ``docs/limitations.md``. The
repository's ``.gitignore`` excludes ``keys/demo_private/`` and ``*.pem`` while
re-including ``keys/public/*.pem``, so the public key can be shared for the
receiver side of the A-to-B demonstration and the private key cannot be committed.

:func:`save_private_key` accepts a passphrase for callers that want a protected
key; only the demo helper opts out.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto.errors import KeyMaterialError
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = [
    "DemoKeyPair",
    "generate_key_pair",
    "load_private_key",
    "load_public_key",
    "save_private_key",
    "save_public_key",
    "ensure_demo_keys",
    "demo_key_paths",
]

_log = get_logger(__name__)


def generate_key_pair(
    key_size: int = constants.RSA_KEY_SIZE_DEFAULT,
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA key pair.

    Defaults to 3072 bits. Sizes below :data:`RSA_MIN_KEY_SIZE` are refused
    rather than generated and then rejected later at signing time.
    """
    if isinstance(key_size, bool) or not isinstance(key_size, int):
        raise KeyMaterialError(
            f"key_size must be an integer, got {type(key_size).__name__}"
        )
    if key_size < constants.RSA_MIN_KEY_SIZE:
        raise KeyMaterialError(
            f"key_size must be at least {constants.RSA_MIN_KEY_SIZE} bits, "
            f"got {key_size}"
        )
    private_key = rsa.generate_private_key(
        public_exponent=constants.RSA_PUBLIC_EXPONENT, key_size=key_size
    )
    return private_key, private_key.public_key()


def save_private_key(
    key: Any,
    path: str | os.PathLike[str],
    *,
    passphrase: bytes | None = None,
    overwrite: bool = False,
) -> str:
    """Write *key* as a PKCS#8 PEM file and return the path.

    Written atomically, so an interrupted write cannot leave a truncated PEM that
    would later fail to load with a confusing error.
    """
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError(
            f"an RSA private key is required, got {type(key).__name__}"
        )
    if passphrase is not None and not isinstance(passphrase, (bytes, bytearray)):
        raise KeyMaterialError(
            f"passphrase must be bytes or None, got {type(passphrase).__name__}"
        )

    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(bytes(passphrase))
    else:
        encryption = serialization.NoEncryption()

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    target = os.fspath(path)
    file_utils.ensure_directory(os.path.dirname(os.path.abspath(target)))
    return file_utils.write_bytes_atomic(target, pem, overwrite=overwrite)


def save_public_key(
    key: Any, path: str | os.PathLike[str], *, overwrite: bool = False
) -> str:
    """Write *key* as a SubjectPublicKeyInfo PEM file and return the path.

    Accepts a private key for convenience and stores its public half, because
    handing a private key to a function named "save public key" is a common slip
    and silently writing the private key would be a serious one.
    """
    if isinstance(key, rsa.RSAPrivateKey):
        key = key.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyMaterialError(
            f"an RSA public key is required, got {type(key).__name__}"
        )

    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    target = os.fspath(path)
    file_utils.ensure_directory(os.path.dirname(os.path.abspath(target)))
    return file_utils.write_bytes_atomic(target, pem, overwrite=overwrite)


def _read_pem(path: str | os.PathLike[str]) -> bytes:
    target = os.fspath(path)
    try:
        with open(target, "rb") as handle:
            return handle.read()
    except FileNotFoundError as exc:
        raise KeyMaterialError(
            f"key file not found: {file_utils.display_name(target)}"
        ) from exc
    except IsADirectoryError as exc:
        raise KeyMaterialError(
            f"key path is a directory, not a file: "
            f"{file_utils.display_name(target)}"
        ) from exc
    except PermissionError as exc:
        raise KeyMaterialError(
            f"read access denied for key file: {file_utils.display_name(target)}"
        ) from exc
    except OSError as exc:
        raise KeyMaterialError(
            f"key file could not be read: {file_utils.display_name(target)} "
            f"({exc.strerror or type(exc).__name__})"
        ) from exc


def load_private_key(
    path: str | os.PathLike[str], *, passphrase: bytes | None = None
) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM file."""
    name = file_utils.display_name(path)
    try:
        key = serialization.load_pem_private_key(
            _read_pem(path), password=bytes(passphrase) if passphrase else None
        )
    except (ValueError, TypeError) as exc:
        raise KeyMaterialError(
            f"{name} could not be loaded as a private key: it may not be PEM, may "
            f"be corrupt, or may require a passphrase"
        ) from exc

    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError(
            f"{name} holds a {type(key).__name__}, but an RSA private key is "
            f"required"
        )
    if key.key_size < constants.RSA_MIN_KEY_SIZE:
        raise KeyMaterialError(
            f"{name} is a {key.key_size}-bit key, below the "
            f"{constants.RSA_MIN_KEY_SIZE}-bit minimum this application accepts"
        )
    return key


def load_public_key(path: str | os.PathLike[str]) -> rsa.RSAPublicKey:
    """Load an RSA public key from a PEM file.

    A private-key PEM is refused rather than quietly reduced to its public half:
    selecting the wrong file in the verify tab should be reported, since the
    receiver in the A-to-B demonstration is supposed to hold only a public key.
    """
    name = file_utils.display_name(path)
    pem = _read_pem(path)
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        if b"PRIVATE KEY" in pem:
            raise KeyMaterialError(
                f"{name} is a private key file; verification requires the public "
                f"key"
            ) from exc
        raise KeyMaterialError(
            f"{name} could not be loaded as a public key: it may not be PEM or may "
            f"be corrupt"
        ) from exc

    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyMaterialError(
            f"{name} holds a {type(key).__name__}, but an RSA public key is required"
        )
    return key


# --------------------------------------------------------------------------- #
# Demo key pair
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DemoKeyPair:
    """Where the demo key pair lives, and whether this call created it."""

    private_key_path: str
    public_key_path: str
    created: bool
    key_size: int
    notice: str = constants.DEMO_KEY_NOTICE


def demo_key_paths(root: str | os.PathLike[str] | None = None) -> tuple[str, str]:
    """Return the (private, public) demo key paths under *root*.

    *root* defaults to the repository root, derived from this file's location
    rather than the working directory, so the GUI finds the same keys whichever
    directory it was launched from.
    """
    base = Path(root) if root is not None else Path(__file__).resolve().parents[2]
    private_path = base / constants.DEMO_PRIVATE_KEY_DIR / constants.DEMO_PRIVATE_KEY_NAME
    public_path = base / constants.PUBLIC_KEY_DIR / constants.DEMO_PUBLIC_KEY_NAME
    return str(private_path), str(public_path)


def ensure_demo_keys(
    root: str | os.PathLike[str] | None = None,
    *,
    key_size: int = constants.RSA_KEY_SIZE_DEFAULT,
    regenerate: bool = False,
) -> DemoKeyPair:
    """Return the demo key pair, generating it if it is not already present.

    Idempotent: an existing pair is loaded and validated rather than replaced, so
    a stego file protected earlier in a session still verifies later in it. Pass
    ``regenerate=True`` to deliberately replace the pair, which is what the
    "wrong key" negative case uses.
    """
    private_path, public_path = demo_key_paths(root)

    if not regenerate and os.path.exists(private_path) and os.path.exists(public_path):
        existing = load_private_key(private_path)
        load_public_key(public_path)
        return DemoKeyPair(
            private_key_path=private_path,
            public_key_path=public_path,
            created=False,
            key_size=existing.key_size,
        )

    _log.info("generating a %d-bit demo RSA key pair", key_size)
    private_key, public_key = generate_key_pair(key_size)
    save_private_key(private_key, private_path, overwrite=True)
    save_public_key(public_key, public_path, overwrite=True)

    return DemoKeyPair(
        private_key_path=private_path,
        public_key_path=public_path,
        created=True,
        key_size=private_key.key_size,
    )
