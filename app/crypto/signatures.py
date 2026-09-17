"""RSA-PSS signing and verification over the payload envelope.

What gets signed
----------------
The signature covers :func:`app.crypto.envelope.signing_input`, which is the
whole envelope except its trailing signature length and signature: the magic, the
version, the flags byte, both section length fields, the canonical verification
record and the message section. Both signing and verification obtain those bytes
from that one function, so the two sides cannot drift apart.

Because the message section holds ciphertext when encryption is enabled, this is
an encrypt-then-sign construction. Verification therefore runs before decryption,
and a file signed with the wrong key is rejected without the cipher ever being
invoked.

Failure is a result, not an exception
-------------------------------------
:func:`verify_signed_region` and :func:`verify_envelope_signature` return
``False`` for a signature that does not verify. That is an expected outcome of the
verification workflow and the caller maps it to a ``SIGNATURE_INVALID`` verdict.
:class:`~app.crypto.errors.SignatureError` and
:class:`~app.crypto.errors.KeyMaterialError` are reserved for operations that
cannot be carried out at all, such as an unusable key object.

Two notes on the previous implementation, because both were real defects rather
than style choices:

* The signature block used to be located by counting backwards from the end of
  the buffer (``len(data) - 260``). Any trailing byte shifted the split, and the
  declared length field was never cross-checked against it. Parsing now walks
  forward from the declared lengths, in :mod:`app.crypto.envelope`.
* The signature size was hard-coded to 256 bytes, which silently restricted the
  whole application to 2048-bit keys even though key generation accepted a size
  parameter. Nothing here assumes a modulus size.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.crypto import envelope as envelope_module
from app.crypto.errors import KeyMaterialError, SignatureError
from app.utils import constants

__all__ = [
    "PSS_PADDING",
    "SIGNATURE_HASH",
    "sign_signed_region",
    "sign_envelope",
    "verify_signed_region",
    "verify_envelope_signature",
    "signature_size_bytes",
]

#: SHA-256 throughout: for the message digest inside PSS and for the MGF1 mask
#: generation function. ``MAX_LENGTH`` salt is the library's recommended default
#: and makes each signature non-deterministic, so signing the same envelope twice
#: produces two different but equally valid signatures.
SIGNATURE_HASH = hashes.SHA256
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
)


def _require_private_key(key: Any) -> rsa.RSAPrivateKey:
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError(
            f"an RSA private key is required for signing, got "
            f"{type(key).__name__}"
        )
    if key.key_size < constants.RSA_MIN_KEY_SIZE:
        raise KeyMaterialError(
            f"the signing key is {key.key_size} bits, below the "
            f"{constants.RSA_MIN_KEY_SIZE}-bit minimum this application accepts"
        )
    return key


def _require_public_key(key: Any) -> rsa.RSAPublicKey:
    if isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError(
            "a public key is required for verification, but a private key was "
            "supplied; pass key.public_key()"
        )
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyMaterialError(
            f"an RSA public key is required for verification, got "
            f"{type(key).__name__}"
        )
    return key


def signature_size_bytes(key: Any) -> int:
    """Return the signature length an RSA key of this size produces.

    Used to compute the expected envelope length before the signature exists,
    which the manifest needs to record. Accepts a private or public key.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return (key.key_size + 7) // 8
    raise KeyMaterialError(
        f"an RSA key is required, got {type(key).__name__}"
    )


def sign_signed_region(signed_region: bytes, private_key: Any) -> bytes:
    """Sign the exact bytes of *signed_region* with RSA-PSS over SHA-256."""
    key = _require_private_key(private_key)
    if not isinstance(signed_region, (bytes, bytearray, memoryview)):
        raise SignatureError(
            f"signed_region must be bytes-like, got {type(signed_region).__name__}"
        )
    try:
        return key.sign(bytes(signed_region), PSS_PADDING, SIGNATURE_HASH())
    except (UnsupportedAlgorithm, ValueError) as exc:
        raise SignatureError(f"signing failed: {exc}") from exc


def sign_envelope(
    record: bytes, message: bytes, private_key: Any, flags: int = 0
) -> bytes:
    """Build a complete, signed envelope.

    Composes the two halves in the only correct order: derive the signed region
    from *record*, *message* and *flags*, sign exactly those bytes, then assemble
    the envelope around them.
    """
    signed_region = envelope_module.signing_input(record, message, flags)
    signature = sign_signed_region(signed_region, private_key)
    return envelope_module.build_envelope(record, message, signature, flags)


def verify_signed_region(
    signed_region: bytes, signature: bytes, public_key: Any
) -> bool:
    """Return whether *signature* is valid for *signed_region* under *public_key*.

    Returns ``False`` rather than raising for any signature that does not verify,
    including a wrong key, modified bytes and a malformed signature, because all
    of those are verification outcomes rather than operational faults.
    """
    key = _require_public_key(public_key)
    if not isinstance(signed_region, (bytes, bytearray, memoryview)):
        raise SignatureError(
            f"signed_region must be bytes-like, got {type(signed_region).__name__}"
        )
    if not isinstance(signature, (bytes, bytearray, memoryview)):
        raise SignatureError(
            f"signature must be bytes-like, got {type(signature).__name__}"
        )
    try:
        key.verify(
            bytes(signature), bytes(signed_region), PSS_PADDING, SIGNATURE_HASH()
        )
    except InvalidSignature:
        return False
    except ValueError:
        # A signature of the wrong length for the modulus, for example. Still a
        # failed verification rather than a fault in this code.
        return False
    return True


def verify_envelope_signature(
    parsed: envelope_module.ParsedEnvelope, public_key: Any
) -> bool:
    """Return whether a parsed envelope's signature verifies under *public_key*."""
    if not isinstance(parsed, envelope_module.ParsedEnvelope):
        raise SignatureError(
            f"parsed must be a ParsedEnvelope, got {type(parsed).__name__}"
        )
    return verify_signed_region(parsed.signed_region, parsed.signature, public_key)
