"""Authenticated encryption of the message, with a passphrase-derived key.

Scheme
------
The message is encrypted with AES-256-GCM. The key comes from a passphrase
through scrypt. The stored blob is::

    nonce (12 bytes) || ciphertext || GCM tag (16 bytes)

The nonce and the scrypt salt are not secrets and travel with the file: the nonce
inside this blob, the salt in the signed verification record and in the companion
manifest. The passphrase is a secret and appears in none of those places; it is
shared out of band, exactly like the start-location secret.

Why encrypt-then-sign
---------------------
The envelope signature is computed over the ciphertext, so verification happens
before decryption. Two practical consequences:

* A file signed with the wrong key is reported as an invalid signature and the
  cipher is never invoked, so a key mix-up cannot surface as a decryption crash.
* Once the signature verifies, the ciphertext is known to be exactly what the
  sender produced. A GCM tag failure after that points at the passphrase rather
  than at the file.

The record's ``message_hash`` is the digest of the **plaintext**, which keeps the
baseline message-integrity check intact: verify the signature, decrypt, hash the
recovered plaintext, compare with the signed digest.

Why a hidden start location is not this
---------------------------------------
Concealing where a payload begins is not encryption; it provides no
confidentiality against anyone who searches the medium. This module is what
provides confidentiality, and it is deliberately separate from start-location
derivation so that neither can be mistaken for the other.

GCM tag failures are deliberately ambiguous
-------------------------------------------
A tag that does not validate means the key is wrong or the ciphertext was
modified, and the algorithm cannot say which. :class:`EncryptionError` messages
therefore state both possibilities rather than asserting one.
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.crypto.envelope import EncryptionParameters
from app.crypto.errors import EncryptionError
from app.utils import constants

__all__ = [
    "MIN_SCRYPT_N",
    "OVERHEAD_BYTES",
    "decrypt_message",
    "derive_key",
    "encrypt_message",
    "generate_salt",
    "new_parameters",
]

#: Bytes the blob adds to the plaintext: the nonce prefix plus the GCM tag.
OVERHEAD_BYTES: Final[int] = constants.GCM_NONCE_BYTES + constants.GCM_TAG_BYTES

#: Lowest scrypt cost this module will accept. Well below the production default
#: of 2**15, because the test suite derives keys hundreds of times and the
#: production cost would dominate its runtime. The floor still exists so that a
#: nonsensical value such as 2 is refused rather than silently used.
#:
#: Accepting a low cost from a record is not a weakness here: the cost parameters
#: live inside the signed verification record, so changing them requires breaking
#: the signature first.
MIN_SCRYPT_N: Final[int] = 1 << 10


def generate_salt() -> bytes:
    """Return a fresh random scrypt salt."""
    return os.urandom(constants.SCRYPT_SALT_BYTES)


def new_parameters(
    *,
    salt: bytes | None = None,
    n: int = constants.SCRYPT_N,
    r: int = constants.SCRYPT_R,
    p: int = constants.SCRYPT_P,
) -> EncryptionParameters:
    """Build the non-secret parameter set recorded alongside a ciphertext."""
    salt_bytes = salt if salt is not None else generate_salt()
    _validate_salt(salt_bytes)
    _validate_cost(n, r, p)
    return EncryptionParameters(
        cipher=constants.CIPHER_AES_256_GCM,
        kdf=constants.KDF_SCRYPT,
        salt_hex=bytes(salt_bytes).hex(),
        n=n,
        r=r,
        p=p,
    )


def _validate_salt(salt: object) -> bytes:
    if not isinstance(salt, (bytes, bytearray, memoryview)):
        raise EncryptionError(
            f"salt must be bytes-like, got {type(salt).__name__}"
        )
    value = bytes(salt)
    if len(value) < 8:
        raise EncryptionError(
            f"salt must be at least 8 bytes, got {len(value)}"
        )
    return value


def _validate_cost(n: object, r: object, p: object) -> tuple[int, int, int]:
    for name, value in (("n", n), ("r", r), ("p", p)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise EncryptionError(
                f"scrypt parameter {name} must be an integer, got "
                f"{type(value).__name__}"
            )
        if value <= 0:
            raise EncryptionError(
                f"scrypt parameter {name} must be positive, got {value}"
            )
    # scrypt requires n to be a power of two greater than 1; passing anything
    # else raises from deep inside the library with a much less helpful message.
    if n & (n - 1) != 0:
        raise EncryptionError(
            f"scrypt parameter n must be a power of two, got {n}"
        )
    if n < MIN_SCRYPT_N:
        raise EncryptionError(
            f"scrypt parameter n must be at least {MIN_SCRYPT_N}, got {n}"
        )
    return int(n), int(r), int(p)


def _validate_passphrase(passphrase: object) -> bytes:
    if isinstance(passphrase, str):
        if not passphrase:
            raise EncryptionError("passphrase must not be empty")
        return passphrase.encode("utf-8")
    if isinstance(passphrase, (bytes, bytearray)):
        if not passphrase:
            raise EncryptionError("passphrase must not be empty")
        return bytes(passphrase)
    raise EncryptionError(
        f"passphrase must be str or bytes, got {type(passphrase).__name__}"
    )


def derive_key(
    passphrase: str | bytes,
    salt: bytes,
    *,
    n: int = constants.SCRYPT_N,
    r: int = constants.SCRYPT_R,
    p: int = constants.SCRYPT_P,
) -> bytes:
    """Derive a 32-byte AES-256 key from *passphrase* and *salt* using scrypt."""
    secret = _validate_passphrase(passphrase)
    salt_bytes = _validate_salt(salt)
    cost_n, cost_r, cost_p = _validate_cost(n, r, p)

    try:
        kdf = Scrypt(
            salt=salt_bytes,
            length=constants.AES_KEY_BYTES,
            n=cost_n,
            r=cost_r,
            p=cost_p,
        )
        return kdf.derive(secret)
    except Exception as exc:  # pragma: no cover - library-level failure
        raise EncryptionError(f"key derivation failed: {exc}") from exc


def _derive_from_parameters(
    passphrase: str | bytes, parameters: EncryptionParameters
) -> bytes:
    if not isinstance(parameters, EncryptionParameters):
        raise EncryptionError(
            f"parameters must be EncryptionParameters, got "
            f"{type(parameters).__name__}"
        )
    if parameters.cipher != constants.CIPHER_AES_256_GCM:
        raise EncryptionError(
            f"unsupported cipher {parameters.cipher!r}; this build implements "
            f"{constants.CIPHER_AES_256_GCM}"
        )
    if parameters.kdf != constants.KDF_SCRYPT:
        raise EncryptionError(
            f"unsupported key derivation function {parameters.kdf!r}; this build "
            f"implements {constants.KDF_SCRYPT}"
        )
    try:
        salt = bytes.fromhex(parameters.salt_hex)
    except ValueError as exc:
        raise EncryptionError("recorded salt is not valid hexadecimal") from exc

    return derive_key(
        passphrase, salt, n=parameters.n, r=parameters.r, p=parameters.p
    )


def encrypt_message(
    plaintext: bytes,
    passphrase: str | bytes,
    *,
    parameters: EncryptionParameters | None = None,
    salt: bytes | None = None,
    n: int = constants.SCRYPT_N,
    r: int = constants.SCRYPT_R,
    p: int = constants.SCRYPT_P,
) -> tuple[bytes, EncryptionParameters]:
    """Encrypt *plaintext*, returning the blob and the parameters to record.

    The returned blob is ``nonce || ciphertext || tag``. A fresh random nonce is
    generated per call, so encrypting the same plaintext twice with the same
    passphrase produces different blobs — which is required, because reusing a
    nonce with the same key destroys GCM's security.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise EncryptionError(
            f"plaintext must be bytes-like, got {type(plaintext).__name__}"
        )

    resolved = (
        parameters
        if parameters is not None
        else new_parameters(salt=salt, n=n, r=r, p=p)
    )
    key = _derive_from_parameters(passphrase, resolved)
    nonce = os.urandom(constants.GCM_NONCE_BYTES)

    try:
        sealed = AESGCM(key).encrypt(nonce, bytes(plaintext), None)
    except Exception as exc:  # pragma: no cover - library-level failure
        raise EncryptionError(f"encryption failed: {exc}") from exc

    return nonce + sealed, resolved


def decrypt_message(
    blob: bytes, passphrase: str | bytes, parameters: EncryptionParameters
) -> bytes:
    """Decrypt a ``nonce || ciphertext || tag`` blob.

    :raises EncryptionError: the blob is too short to contain a nonce and tag, or
        the GCM tag does not validate. A tag failure means a wrong passphrase or
        modified ciphertext, and this cannot tell which; the message says so.
    """
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise EncryptionError(f"blob must be bytes-like, got {type(blob).__name__}")
    payload = bytes(blob)

    if len(payload) < OVERHEAD_BYTES:
        raise EncryptionError(
            f"encrypted message is {len(payload)} bytes, shorter than the "
            f"{OVERHEAD_BYTES}-byte minimum for a {constants.GCM_NONCE_BYTES}-byte "
            f"nonce and a {constants.GCM_TAG_BYTES}-byte authentication tag"
        )

    key = _derive_from_parameters(passphrase, parameters)
    nonce = payload[: constants.GCM_NONCE_BYTES]
    sealed = payload[constants.GCM_NONCE_BYTES :]

    try:
        return AESGCM(key).decrypt(nonce, sealed, None)
    except InvalidTag as exc:
        raise EncryptionError(
            "the message could not be decrypted: the authentication tag did not "
            "validate. This is consistent with an incorrect passphrase or with "
            "modified ciphertext, and does not distinguish between them"
        ) from exc
    except Exception as exc:  # pragma: no cover - library-level failure
        raise EncryptionError(f"decryption failed: {exc}") from exc
