"""Composition of the protected payload, and recovery of the message from it.

This module is the cryptography layer's front door. It is what the planning reference's
shared interface calls ``create_payload``: everything the sender side needs, in
one call, producing the opaque bytes the steganography layer embeds.

It deliberately touches no media. Given a message it returns an envelope and the
facts about it; deciding where in a cover object those bytes go, and putting them
there, belongs to the steganography layer. That split is what lets the protect
workflow run in a fixed order without circular dependencies::

    prepare_payload(...)          ->  envelope bytes, so envelope_length is known
    measure capacity              ->  total_samples known
    resolve_start_location(...)   ->  needs envelope_length and total_samples
    embed(...)                    ->  writes the stego object
    write_manifest(...)           ->  publishes the non-secret parameters

Order of operations inside prepare_payload
------------------------------------------
1. Hash the **plaintext** message. This digest goes in the record, so the
   baseline integrity check is always against the message the user actually sent,
   whether or not it travels encrypted.
2. Encrypt the message, if a passphrase was supplied.
3. Build the verification record over the plaintext digest and every extraction
   parameter.
4. Sign the record together with the (possibly encrypted) message and the framing.

Step 4 after step 2 is the encrypt-then-sign ordering: the signature covers the
ciphertext, so a receiver verifies before decrypting and a wrong signing key can
never surface as a decryption failure.

What this module does not do
----------------------------
It does not decide verdicts. :func:`recover_message` returns the plaintext and
whether its digest matched; mapping that onto ``AUTHENTIC`` or ``TAMPERED`` is
:mod:`app.verification.verifier`'s job.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from app.crypto import encryption as encryption_module
from app.crypto import envelope as envelope_module
from app.crypto import signatures
from app.crypto.envelope import (
    EncryptionParameters,
    ErrorCorrectionParameters,
    VerificationRecord,
)
from app.crypto.errors import RecordError
from app.crypto.hashing import compute_media_hash, hashes_equal
from app.utils import constants

__all__ = [
    "PreparedPayload",
    "RecoveredMessage",
    "generate_nonce_hex",
    "prepare_payload",
    "recover_message",
]


def generate_nonce_hex() -> str:
    """Return a fresh random nonce as a hexadecimal string.

    Not a secret: the receiver needs it to reproduce a derived start location, and
    it is published in the manifest. Its purpose is to make each protected file
    distinct so that reusing one secret across files does not reuse one location.
    """
    return os.urandom(constants.RECORD_NONCE_BYTES).hex()


@dataclass(frozen=True)
class PreparedPayload:
    """The signed envelope, and everything a caller needs to place and describe it."""

    envelope: bytes
    record: VerificationRecord
    #: Length of :attr:`envelope`, which is the payload the stego layer carries.
    #: Needed to derive a start location and to publish in the manifest.
    envelope_length: int
    #: Length of the plaintext message, as recorded in the signed record.
    message_length: int
    #: Length of the message section actually embedded. Larger than
    #: :attr:`message_length` when encrypted, by the nonce and tag overhead.
    stored_message_length: int
    encrypted: bool
    flags: int

    @property
    def start_method(self) -> str:
        return self.record.start_method

    @property
    def lsb_depth(self) -> int:
        return self.record.lsb_depth


def prepare_payload(
    message: bytes,
    private_key: Any,
    *,
    media_id: str,
    media_type: str,
    lsb_depth: int,
    start_method: str = constants.START_METHOD_HMAC,
    start_location: int | None = None,
    passphrase: str | bytes | None = None,
    ecc: ErrorCorrectionParameters | None = None,
    metadata: Mapping[str, Any] | None = None,
    nonce_hex: str | None = None,
    timestamp: str | None = None,
    encryption_parameters: EncryptionParameters | None = None,
    scrypt_n: int = constants.SCRYPT_N,
    scrypt_r: int = constants.SCRYPT_R,
    scrypt_p: int = constants.SCRYPT_P,
) -> PreparedPayload:
    """Build and sign the payload envelope for *message*.

    :param start_location: required for the manual start method and rejected for
        the keyed one, where the location is derived after this call because it
        depends on the envelope length this call produces.
    :param passphrase: when supplied, the message is encrypted with AES-256-GCM
        under a scrypt-derived key. Never stored anywhere.
    :param ecc: recorded so a receiver knows an error-correcting code was applied.
        Applying it is :mod:`app.robustness`' job, after this call.
    """
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise RecordError(
            f"message must be bytes-like, got {type(message).__name__}"
        )
    plaintext = bytes(message)

    if start_method not in constants.START_METHODS:
        raise RecordError(
            f"start_method must be one of {constants.START_METHODS}, got "
            f"{start_method!r}"
        )
    if start_method == constants.START_METHOD_MANUAL:
        if start_location is None:
            raise RecordError(
                f"the {constants.START_METHOD_MANUAL!r} start method requires "
                f"start_location, which is signed into the record"
            )
    elif start_location is not None:
        # Accepting it would imply it gets signed, and it cannot be: the derived
        # location depends on the envelope length, which depends on the record
        # that would contain it.
        raise RecordError(
            f"start_location must not be supplied for the "
            f"{constants.START_METHOD_HMAC!r} start method; the location is "
            f"derived from the envelope length after the payload is built"
        )

    # 1. The digest is always of the plaintext, encrypted or not.
    message_hash = compute_media_hash(plaintext)

    # 2. Encrypt, if asked.
    stored_message = plaintext
    recorded_encryption: EncryptionParameters | None = None
    if passphrase is not None:
        stored_message, recorded_encryption = encryption_module.encrypt_message(
            plaintext,
            passphrase,
            parameters=encryption_parameters,
            n=scrypt_n,
            r=scrypt_r,
            p=scrypt_p,
        )
    elif encryption_parameters is not None:
        raise RecordError(
            "encryption_parameters were supplied without a passphrase; the message "
            "cannot be encrypted without one"
        )

    # 3. Build the record over the plaintext digest and the parameters.
    record = VerificationRecord(
        media_id=media_id,
        media_type=media_type,
        timestamp=timestamp if timestamp is not None else envelope_module.utc_timestamp(),
        nonce_hex=nonce_hex if nonce_hex is not None else generate_nonce_hex(),
        message_hash=message_hash,
        message_length=len(plaintext),
        lsb_depth=lsb_depth,
        start_method=start_method,
        start_location=start_location,
        encryption=recorded_encryption,
        ecc=ecc,
        metadata=dict(metadata) if metadata else {},
    )
    # Round-trip the record through its own validation so a bad argument is
    # reported here rather than surfacing as a puzzling failure on the receiver.
    record_bytes = record.to_bytes()
    VerificationRecord.from_bytes(record_bytes)

    # 4. Sign the record, the stored message and the framing together.
    envelope = signatures.sign_envelope(
        record_bytes, stored_message, private_key, record.flags
    )

    return PreparedPayload(
        envelope=envelope,
        record=record,
        envelope_length=len(envelope),
        message_length=len(plaintext),
        stored_message_length=len(stored_message),
        encrypted=recorded_encryption is not None,
        flags=record.flags,
    )


@dataclass(frozen=True)
class RecoveredMessage:
    """The outcome of opening a verified envelope."""

    message: bytes
    #: Whether the recovered plaintext's digest matched the signed record.
    hash_matches: bool
    was_encrypted: bool


def recover_message(
    parsed: envelope_module.ParsedEnvelope,
    record: VerificationRecord,
    *,
    passphrase: str | bytes | None = None,
) -> RecoveredMessage:
    """Recover the plaintext message from a **signature-verified** envelope.

    Decrypts when the record says the message is encrypted, then recomputes the
    plaintext digest and compares it with the signed value.

    Call this only after :func:`app.crypto.signatures.verify_envelope_signature`
    has returned ``True``. Decrypting first would mean a wrong signing key could
    surface as a cipher failure instead of a signature failure, which is exactly
    the confusion the encrypt-then-sign ordering exists to prevent.

    :raises EncryptionError: the record says the message is encrypted and either
        no passphrase was given or the authentication tag did not validate.
    """
    if not isinstance(parsed, envelope_module.ParsedEnvelope):
        raise RecordError(
            f"parsed must be a ParsedEnvelope, got {type(parsed).__name__}"
        )
    if not isinstance(record, VerificationRecord):
        raise RecordError(
            f"record must be a VerificationRecord, got {type(record).__name__}"
        )

    if record.encryption is not None:
        if passphrase is None:
            from app.crypto.errors import EncryptionError

            raise EncryptionError(
                "the message is encrypted and no passphrase was supplied; the "
                "passphrase is shared separately from the file and its manifest"
            )
        plaintext = encryption_module.decrypt_message(
            parsed.message, passphrase, record.encryption
        )
        was_encrypted = True
    else:
        plaintext = parsed.message
        was_encrypted = False

    return RecoveredMessage(
        message=plaintext,
        hash_matches=(
            len(plaintext) == record.message_length
            and hashes_equal(compute_media_hash(plaintext), record.message_hash)
        ),
        was_encrypted=was_encrypted,
    )
