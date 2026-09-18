"""Exception hierarchy for the cryptography layer.

Mirrors :mod:`app.stego.errors`: one base type so a caller can catch the whole
layer with a single handler, and named subclasses so it can catch one category.

The important distinction to hold on to is that **a verification failure is not
an exception**. A signature that does not verify, a message hash that does not
match, or a manifest that disagrees with the signed record are all expected
outcomes of the verification workflow, and they are reported as verdicts by
:mod:`app.verification.verifier`. The exceptions here are for input that is
malformed or operations that cannot be carried out at all: an envelope that is
not an envelope, a key file that will not load, a record missing a required
field.
"""

from __future__ import annotations

from app.errors import AppError

__all__ = [
    "CryptoError",
    "EnvelopeError",
    "RecordError",
    "SignatureError",
    "KeyMaterialError",
    "EncryptionError",
    "StartLocationError",
    "ManifestError",
]

class CryptoError(AppError):
    """Common base type for every error raised by the cryptography layer."""


class EnvelopeError(CryptoError):
    """A byte sequence that cannot be read as a payload envelope.

    Covers a missing or wrong magic, an unsupported version, unknown flag bits, a
    declared section length that exceeds the buffer or the allowed maximum, and
    trailing bytes after the final section.

    A wrong magic is the single most useful case: it is what distinguishes "there
    is no payload here" from "there is a payload and something about it is
    wrong". It still does not identify *why* the bytes are not an envelope, since
    a wrong LSB depth, a wrong start location, an absent payload and sample
    corruption all produce bytes that fail this check identically.
    """


class RecordError(CryptoError):
    """A verification record that is not well formed.

    Covers invalid UTF-8, invalid JSON, a non-object top level, a missing or
    wrongly typed required field, and values that cannot survive canonical
    re-serialisation.
    """


class SignatureError(CryptoError):
    """A signing operation that could not be carried out.

    Raised when the key is unusable or the input is malformed. **Not** raised
    when a signature simply fails to verify: that is a verdict, and
    :func:`app.crypto.signatures.verify_envelope_signature` returns ``False``
    for it.
    """


class KeyMaterialError(CryptoError):
    """Key material that cannot be loaded, or that fails a policy check.

    Covers an unreadable or absent PEM file, a PEM that is not an RSA key, a
    private key where a public key was expected, and a modulus below the minimum
    accepted size.
    """


class EncryptionError(CryptoError):
    """An encryption or decryption operation that could not be completed.

    Includes an AES-GCM authentication tag that does not validate, which in
    practice means either a wrong passphrase or modified ciphertext. Those two
    causes are indistinguishable by design, and the message must not claim to
    know which applies.
    """


class StartLocationError(CryptoError):
    """A start location that cannot be derived or is out of range.

    Covers an empty secret, a medium with no embeddable samples, and a payload
    that does not fit at any start location.
    """


class ManifestError(CryptoError):
    """A companion manifest that is absent, malformed, or carries unusable values.

    Manifest content is untrusted until the signature over the verification
    record has been checked, so this is raised during the *validation* of a
    manifest, before any of its values are used to drive extraction.
    """
