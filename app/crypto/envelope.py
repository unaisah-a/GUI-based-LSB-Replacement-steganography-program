"""The versioned payload envelope, and the verification record it carries.

Where the envelope sits
-----------------------
The envelope is the **payload** that the steganography layer embeds. It is not
part of the stego framing. Both the image and the audio layer write a bare 4-byte
big-endian length header followed by opaque bytes, and those opaque bytes are an
envelope::

    stego framing (per medium)   [4-byte length][ ................. ]
    envelope (shared)                           [magic|ver|flags|...]

Keeping the magic and version here rather than in the stego layers preserves the
image specification's rule that the encoded stream carries no format-version,
type or marker byte (Requirement 4.5), while still giving image, audio and video
one shared, versioned, self-describing format. It also means the "is there a
payload here at all?" check is identical for every medium, which the audio layer
previously provided for itself with a private ``b"INF2005"`` marker and the image
layer did not provide at all.

Byte layout
-----------
::

    offset  size  field
    0       8     magic          b"INF2005E"
    8       1     version        1
    9       1     flags          bit 0 encrypted, bit 1 error-corrected
    10      4     record_len     big-endian uint32
    14      R     record         canonical JSON, UTF-8
    14+R    4     message_len    big-endian uint32
    18+R    M     message        plaintext, or AES-256-GCM nonce||ciphertext||tag
    18+R+M  4     signature_len  big-endian uint32
    22+R+M  S     signature      RSA-PSS over bytes [0, 18+R+M)

The signature covers the magic, version, flags, both length fields and both
section bodies. Two consequences worth stating:

* The framing is authenticated, not just the record. An attacker cannot change
  the declared record length, flip the encrypted flag, or swap the message for a
  different one of the same length without invalidating the signature.
* Because the signature is computed over everything that precedes it, the total
  envelope length is fully determined by the signed bytes plus the signature
  size. A receiver can therefore recompute the expected envelope length and
  compare it with the length recorded in the companion manifest, which is how a
  manifest-level length claim gets authenticated without being inside the
  signature.

Encrypt-then-sign
-----------------
When encryption is enabled, the ``message`` section holds ciphertext and the
signature is computed over that ciphertext. Verification therefore happens
*before* decryption: a file signed with the wrong key is rejected as an invalid
signature and never reaches the cipher. The record's ``message_hash`` is the
digest of the **plaintext**, so the baseline message-integrity check of the
project's security design is preserved: verify the signature, decrypt, hash the
recovered plaintext, compare with the signed digest.

Trust boundary
--------------
:func:`parse_envelope` performs *structural* validation only. It decodes the
record's JSON so a caller can inspect it, but it draws no conclusion from the
contents, because at parse time nothing has been authenticated yet. Turning that
dictionary into a :class:`VerificationRecord` and acting on its values is a
separate step that belongs after the signature check. The verifier is written in
that order.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final, Mapping

from app.crypto.errors import EnvelopeError, RecordError
from app.utils import constants

__all__ = [
    "MAGIC_SIZE",
    "VERSION_SIZE",
    "FLAGS_SIZE",
    "LENGTH_SIZE",
    "HEADER_SIZE",
    "MIN_ENVELOPE_SIZE",
    "SUPPORTED_VERSIONS",
    "KNOWN_FLAGS",
    "EncryptionParameters",
    "ErrorCorrectionParameters",
    "VerificationRecord",
    "ParsedEnvelope",
    "canonical_json",
    "build_envelope",
    "envelope_length_for",
    "parse_envelope",
    "signing_input",
    "utc_timestamp",
]

MAGIC_SIZE: Final[int] = len(constants.ENVELOPE_MAGIC)
VERSION_SIZE: Final[int] = 1
FLAGS_SIZE: Final[int] = 1
LENGTH_SIZE: Final[int] = constants.ENVELOPE_LENGTH_FIELD_BYTES

HEADER_SIZE: Final[int] = MAGIC_SIZE + VERSION_SIZE + FLAGS_SIZE

#: Smallest possible envelope: full header plus three empty sections.
MIN_ENVELOPE_SIZE: Final[int] = HEADER_SIZE + 3 * LENGTH_SIZE

SUPPORTED_VERSIONS: Final[tuple[int, ...]] = (constants.ENVELOPE_VERSION,)

KNOWN_FLAGS: Final[int] = (
    constants.ENVELOPE_FLAG_ENCRYPTED | constants.ENVELOPE_FLAG_ECC
)

_MAX_SECTION: Final[int] = constants.MAX_ENVELOPE_SECTION_BYTES
_UINT32_MAX: Final[int] = 0xFFFF_FFFF


# --------------------------------------------------------------------------- #
# Canonical serialisation
# --------------------------------------------------------------------------- #


def _reject_unstable_values(value: Any, path: str = "record") -> None:
    """Refuse values whose JSON text is not reproducible byte for byte.

    Floats are rejected outright. A signature is computed over exact bytes, so a
    value that can serialise as ``0.1`` on one machine and ``0.1000000001`` on
    another would produce a record that fails to verify against itself. Every
    numeric field the record actually needs is an integer, so nothing is lost.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return
    if isinstance(value, float):
        raise RecordError(
            f"{path} contains a floating-point value ({value!r}); the record must "
            f"survive canonical re-serialisation byte for byte, so only integers, "
            f"strings, booleans, null, objects and arrays are permitted"
        )
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecordError(
                    f"{path} contains a non-string object key ({key!r}); JSON "
                    f"object keys must be strings for the canonical form to be "
                    f"well defined"
                )
            _reject_unstable_values(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_unstable_values(item, f"{path}[{index}]")
        return
    raise RecordError(
        f"{path} contains an unsupported value of type {type(value).__name__}"
    )


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Serialise *payload* to the exact bytes that get signed.

    Canonical means three things, and all three matter:

    * ``sort_keys=True`` — key order becomes a property of the content rather
      than of the insertion order of whichever dictionary happened to build it.
      Without this, re-serialising a parsed record can produce different bytes
      and break signature verification.
    * ``separators=(",", ":")`` — no incidental whitespace.
    * ``ensure_ascii=True`` — output is pure ASCII, so no Unicode normalisation
      or encoding choice can alter the byte sequence.

    ``allow_nan=False`` additionally rejects ``NaN`` and infinities, which are
    not valid JSON and would not round-trip.
    """
    if not isinstance(payload, Mapping):
        raise RecordError(
            f"record must be a JSON object, got {type(payload).__name__}"
        )
    _reject_unstable_values(dict(payload))
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def utc_timestamp() -> str:
    """Return the current time as an ISO 8601 string with an explicit offset.

    Second resolution: sub-second digits add nothing here and make the recorded
    value harder to read in the demo.
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# --------------------------------------------------------------------------- #
# Record sub-structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EncryptionParameters:
    """Non-secret parameters needed to reconstruct the message key.

    The salt is not a secret and must travel with the file; the passphrase is a
    secret and never appears here, in the record, or in the manifest.
    """

    cipher: str
    kdf: str
    salt_hex: str
    n: int
    r: int
    p: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "cipher": self.cipher,
            "kdf": self.kdf,
            "salt": self.salt_hex,
            "n": self.n,
            "r": self.r,
            "p": self.p,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EncryptionParameters":
        cipher = _require(data, "cipher", str, "record.encryption")
        kdf = _require(data, "kdf", str, "record.encryption")
        salt = _require(data, "salt", str, "record.encryption")
        if cipher != constants.CIPHER_AES_256_GCM:
            raise RecordError(
                f"record.encryption.cipher must be "
                f"{constants.CIPHER_AES_256_GCM!r}, got {cipher!r}"
            )
        if kdf != constants.KDF_SCRYPT:
            raise RecordError(
                f"record.encryption.kdf must be {constants.KDF_SCRYPT!r}, got {kdf!r}"
            )
        _require_hex(salt, "record.encryption.salt")
        return cls(
            cipher=cipher,
            kdf=kdf,
            salt_hex=salt,
            n=_require_positive(data, "n", "record.encryption"),
            r=_require_positive(data, "r", "record.encryption"),
            p=_require_positive(data, "p", "record.encryption"),
        )


@dataclass(frozen=True)
class ErrorCorrectionParameters:
    """Which error-correcting code was applied to the envelope before embedding."""

    scheme: str
    factor: int

    def as_dict(self) -> dict[str, Any]:
        return {"scheme": self.scheme, "factor": self.factor}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ErrorCorrectionParameters":
        scheme = _require(data, "scheme", str, "record.ecc")
        if scheme not in constants.ECC_SCHEMES:
            raise RecordError(
                f"record.ecc.scheme must be one of {constants.ECC_SCHEMES}, "
                f"got {scheme!r}"
            )
        factor = _require_positive(data, "factor", "record.ecc")
        if scheme == constants.ECC_REPETITION and factor % 2 == 0:
            raise RecordError(
                f"record.ecc.factor must be odd for the "
                f"{constants.ECC_REPETITION} scheme so a majority vote cannot "
                f"tie, got {factor}"
            )
        return cls(scheme=scheme, factor=factor)


# --------------------------------------------------------------------------- #
# Field validation helpers
# --------------------------------------------------------------------------- #


def _require(data: Mapping[str, Any], key: str, kind: type, where: str) -> Any:
    if key not in data:
        raise RecordError(f"{where} is missing the required field {key!r}")
    value = data[key]
    # bool is a subclass of int, so an explicit guard is needed wherever an
    # integer is expected; True silently meaning 1 hides a caller mistake.
    if kind is int and isinstance(value, bool):
        raise RecordError(f"{where}.{key} must be an integer, got a boolean")
    if not isinstance(value, kind):
        raise RecordError(
            f"{where}.{key} must be {kind.__name__}, got {type(value).__name__}"
        )
    return value


def _require_positive(data: Mapping[str, Any], key: str, where: str) -> int:
    value = _require(data, key, int, where)
    if value <= 0:
        raise RecordError(f"{where}.{key} must be a positive integer, got {value}")
    return value


def _require_hex(value: str, where: str, *, expected_length: int | None = None) -> str:
    if expected_length is not None and len(value) != expected_length:
        raise RecordError(
            f"{where} must be {expected_length} hexadecimal characters, "
            f"got {len(value)}"
        )
    if not value or len(value) % 2 != 0:
        raise RecordError(
            f"{where} must be a non-empty even-length hexadecimal string, "
            f"got {len(value)} characters"
        )
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise RecordError(f"{where} is not valid hexadecimal") from exc
    return value


# --------------------------------------------------------------------------- #
# Verification record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VerificationRecord:
    """The signed statement about a protected message.

    ``start_location`` is deliberately nullable, and the reason is worth
    recording because it looks like an omission.

    In ``manual`` mode the user chooses the start location outright, so it can be
    signed. In ``hmac_prf`` mode the location is derived from, among other
    things, the envelope length — and the envelope length depends on the length
    of this record, which would depend on the location. That is circular, so the
    derived location is not stored. Nothing is lost: the derivation inputs
    (``media_id``, ``nonce``, ``media_type``, ``lsb_depth``) are all signed
    fields, the envelope length is implied by the signed bytes, and the only
    other input is the secret, which is shared out of band. A receiver that
    reproduces the derivation from authenticated inputs arrives at an
    authenticated location.
    """

    media_id: str
    media_type: str
    timestamp: str
    nonce_hex: str
    message_hash: str
    message_length: int
    lsb_depth: int
    start_method: str
    start_location: int | None = None
    encryption: EncryptionParameters | None = None
    ecc: ErrorCorrectionParameters | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = constants.ENVELOPE_VERSION

    def __post_init__(self) -> None:
        # Copy the caller's mapping. Without this the record aliases a dictionary
        # the caller still holds, so mutating it after the record was signed would
        # change what `as_dict` reports while the signature covers the original
        # bytes — a record that disagrees with its own signature for no visible
        # reason. `object.__setattr__` is required because the dataclass is frozen.
        object.__setattr__(self, "metadata", dict(self.metadata))

    # -- serialisation ---------------------------------------------------- #

    def as_dict(self) -> dict[str, Any]:
        """Return the plain dictionary that :func:`canonical_json` serialises."""
        return {
            "v": self.version,
            "media_id": self.media_id,
            "media_type": self.media_type,
            "timestamp": self.timestamp,
            "nonce": self.nonce_hex,
            "message_hash": self.message_hash,
            "message_length": self.message_length,
            "lsb_depth": self.lsb_depth,
            "start_method": self.start_method,
            "start_location": self.start_location,
            "encryption": self.encryption.as_dict() if self.encryption else None,
            "ecc": self.ecc.as_dict() if self.ecc else None,
            "metadata": dict(self.metadata),
        }

    def to_bytes(self) -> bytes:
        """Return the canonical bytes of this record."""
        return canonical_json(self.as_dict())

    @property
    def encrypted(self) -> bool:
        return self.encryption is not None

    @property
    def flags(self) -> int:
        """The envelope flag byte implied by this record."""
        value = 0
        if self.encryption is not None:
            value |= constants.ENVELOPE_FLAG_ENCRYPTED
        if self.ecc is not None and self.ecc.scheme != constants.ECC_NONE:
            value |= constants.ENVELOPE_FLAG_ECC
        return value

    # -- parsing ---------------------------------------------------------- #

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationRecord":
        """Validate *data* and build a record.

        Call this only after the envelope signature has verified. Before that the
        contents are attacker-controlled, and this method's job is to reject
        malformed input, not to make untrusted input safe to act on.
        """
        if not isinstance(data, Mapping):
            raise RecordError(
                f"record must be a JSON object, got {type(data).__name__}"
            )

        version = _require(data, "v", int, "record")
        if version not in SUPPORTED_VERSIONS:
            raise RecordError(
                f"record version {version} is not supported; this build "
                f"understands {SUPPORTED_VERSIONS}"
            )

        media_type = _require(data, "media_type", str, "record")
        if media_type not in constants.MEDIA_TYPES:
            raise RecordError(
                f"record.media_type must be one of {constants.MEDIA_TYPES}, "
                f"got {media_type!r}"
            )

        start_method = _require(data, "start_method", str, "record")
        if start_method not in constants.START_METHODS:
            raise RecordError(
                f"record.start_method must be one of {constants.START_METHODS}, "
                f"got {start_method!r}"
            )

        lsb_depth = _require(data, "lsb_depth", int, "record")
        if not constants.MIN_LSB_DEPTH <= lsb_depth <= constants.MAX_LSB_DEPTH:
            raise RecordError(
                f"record.lsb_depth must be from {constants.MIN_LSB_DEPTH} to "
                f"{constants.MAX_LSB_DEPTH} inclusive, got {lsb_depth}"
            )

        message_length = _require(data, "message_length", int, "record")
        if message_length < 0:
            raise RecordError(
                f"record.message_length must not be negative, got {message_length}"
            )

        if "start_location" not in data:
            raise RecordError("record is missing the required field 'start_location'")
        start_location = data["start_location"]
        if start_location is not None:
            if isinstance(start_location, bool) or not isinstance(start_location, int):
                raise RecordError(
                    f"record.start_location must be an integer or null, got "
                    f"{type(start_location).__name__}"
                )
            if start_location < 0:
                raise RecordError(
                    f"record.start_location must not be negative, got {start_location}"
                )

        encryption_data = data.get("encryption")
        if encryption_data is not None and not isinstance(encryption_data, Mapping):
            raise RecordError(
                f"record.encryption must be an object or null, got "
                f"{type(encryption_data).__name__}"
            )
        ecc_data = data.get("ecc")
        if ecc_data is not None and not isinstance(ecc_data, Mapping):
            raise RecordError(
                f"record.ecc must be an object or null, got {type(ecc_data).__name__}"
            )
        metadata = data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise RecordError(
                f"record.metadata must be an object, got {type(metadata).__name__}"
            )

        return cls(
            media_id=_require(data, "media_id", str, "record"),
            media_type=media_type,
            timestamp=_require(data, "timestamp", str, "record"),
            nonce_hex=_require_hex(
                _require(data, "nonce", str, "record"), "record.nonce"
            ),
            message_hash=_require_hex(
                _require(data, "message_hash", str, "record"),
                "record.message_hash",
                expected_length=64,
            ),
            message_length=message_length,
            lsb_depth=lsb_depth,
            start_method=start_method,
            start_location=start_location,
            encryption=(
                EncryptionParameters.from_dict(encryption_data)
                if encryption_data is not None
                else None
            ),
            ecc=(
                ErrorCorrectionParameters.from_dict(ecc_data)
                if ecc_data is not None
                else None
            ),
            metadata=dict(metadata),
            version=version,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VerificationRecord":
        """Decode and validate a record from its serialised bytes."""
        return cls.from_dict(decode_record(data))


def decode_record(data: bytes) -> dict[str, Any]:
    """Decode record bytes to a dictionary without interpreting the contents."""
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordError("record is not valid UTF-8") from exc
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecordError(f"record is not valid JSON: {exc.msg}") from exc
    if not isinstance(decoded, dict):
        raise RecordError(
            f"record must be a JSON object, got {type(decoded).__name__}"
        )
    return decoded


# --------------------------------------------------------------------------- #
# Envelope construction
# --------------------------------------------------------------------------- #


def _check_section(name: str, data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise EnvelopeError(
            f"{name} must be bytes-like, got {type(data).__name__}"
        )
    payload = bytes(data)
    if len(payload) > _MAX_SECTION:
        raise EnvelopeError(
            f"{name} is {len(payload)} bytes, which exceeds the {_MAX_SECTION}-byte "
            f"maximum this build accepts"
        )
    return payload


def _check_flags(flags: int) -> int:
    if isinstance(flags, bool) or not isinstance(flags, int):
        raise EnvelopeError(f"flags must be an integer, got {type(flags).__name__}")
    if not 0 <= flags <= 0xFF:
        raise EnvelopeError(f"flags must fit in one byte, got {flags}")
    unknown = flags & ~KNOWN_FLAGS
    if unknown:
        raise EnvelopeError(
            f"flags byte sets unknown bits 0b{unknown:08b}; this build understands "
            f"0b{KNOWN_FLAGS:08b}"
        )
    return flags


def signing_input(record: bytes, message: bytes, flags: int = 0) -> bytes:
    """Return the exact bytes a signature must be computed over.

    This is the whole envelope except the trailing signature length and
    signature, so the magic, version, flags and both length fields are all
    covered. Exposed as its own function so that signing and verification cannot
    drift apart: both call this.
    """
    record_bytes = _check_section("record", record)
    message_bytes = _check_section("message", message)
    flag_byte = _check_flags(flags)

    return b"".join(
        (
            constants.ENVELOPE_MAGIC,
            bytes((constants.ENVELOPE_VERSION, flag_byte)),
            len(record_bytes).to_bytes(LENGTH_SIZE, "big"),
            record_bytes,
            len(message_bytes).to_bytes(LENGTH_SIZE, "big"),
            message_bytes,
        )
    )


def build_envelope(
    record: bytes, message: bytes, signature: bytes, flags: int = 0
) -> bytes:
    """Assemble a complete envelope.

    *signature* must be the signature over :func:`signing_input` called with the
    same *record*, *message* and *flags*. This function does not verify that, as
    it has no key; :func:`app.crypto.signatures.sign_envelope` composes the two
    steps correctly.
    """
    signed = signing_input(record, message, flags)
    signature_bytes = _check_section("signature", signature)
    return signed + len(signature_bytes).to_bytes(LENGTH_SIZE, "big") + signature_bytes


def envelope_length_for(
    record_length: int, message_length: int, signature_length: int
) -> int:
    """Return the total envelope length for the given section lengths.

    Used to record the expected length in the companion manifest, and by the
    verifier to recompute that length from the parsed envelope and compare.
    """
    for name, value in (
        ("record_length", record_length),
        ("message_length", message_length),
        ("signature_length", signature_length),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EnvelopeError(f"{name} must be a non-negative integer, got {value!r}")
    return (
        HEADER_SIZE
        + 3 * LENGTH_SIZE
        + record_length
        + message_length
        + signature_length
    )


# --------------------------------------------------------------------------- #
# Envelope parsing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ParsedEnvelope:
    """The structural contents of an envelope.

    Nothing here is authenticated. ``record`` is the decoded JSON dictionary,
    provided so a caller can inspect the claim; it becomes trustworthy only once
    ``signed_region`` has been checked against ``signature`` with a trusted
    public key.
    """

    version: int
    flags: int
    record_bytes: bytes
    record: dict[str, Any]
    message: bytes
    signature: bytes
    #: The byte range the signature is computed over.
    signed_region: bytes
    total_length: int

    @property
    def encrypted_flag(self) -> bool:
        return bool(self.flags & constants.ENVELOPE_FLAG_ENCRYPTED)

    @property
    def ecc_flag(self) -> bool:
        return bool(self.flags & constants.ENVELOPE_FLAG_ECC)


def _read_section(data: bytes, offset: int, name: str) -> tuple[bytes, int]:
    """Read one length-prefixed section starting at *offset*.

    The declared length is bounds-checked against both the configured maximum and
    the actual remaining buffer *before* any slice is taken, so a corrupt or
    hostile length field cannot drive a large allocation.
    """
    end_of_length = offset + LENGTH_SIZE
    if end_of_length > len(data):
        raise EnvelopeError(
            f"envelope is truncated: the {name} length field needs {LENGTH_SIZE} "
            f"bytes at offset {offset}, but the payload is only {len(data)} bytes"
        )
    declared = int.from_bytes(data[offset:end_of_length], "big")
    if declared > _MAX_SECTION:
        raise EnvelopeError(
            f"envelope declares a {name} of {declared} bytes, which exceeds the "
            f"{_MAX_SECTION}-byte maximum this build accepts"
        )
    end_of_body = end_of_length + declared
    if end_of_body > len(data):
        raise EnvelopeError(
            f"envelope is truncated: it declares a {declared}-byte {name} at "
            f"offset {end_of_length}, but only {len(data) - end_of_length} bytes "
            f"remain"
        )
    return data[end_of_length:end_of_body], end_of_body


def parse_envelope(data: bytes) -> ParsedEnvelope:
    """Parse *data* as an envelope, validating structure only.

    :raises EnvelopeError: the bytes are not a well-formed envelope of a
        supported version.
    :raises RecordError: the framing is valid but the record is not decodable
        JSON.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise EnvelopeError(
            f"envelope must be bytes-like, got {type(data).__name__}"
        )
    payload = bytes(data)

    if len(payload) < MIN_ENVELOPE_SIZE:
        raise EnvelopeError(
            f"no payload envelope found: {len(payload)} bytes is shorter than the "
            f"{MIN_ENVELOPE_SIZE}-byte minimum envelope"
        )

    if payload[:MAGIC_SIZE] != constants.ENVELOPE_MAGIC:
        # The single most informative failure: these bytes are not an envelope.
        # It still does not say why, because a wrong depth, a wrong start
        # location, an absent payload and corruption all land here identically.
        raise EnvelopeError(
            "no payload envelope found: the extracted bytes do not begin with the "
            "envelope marker. This is consistent with an absent payload, an "
            "incorrect LSB depth, an incorrect start location or secret, or "
            "modified media, and does not distinguish between them"
        )

    version = payload[MAGIC_SIZE]
    if version not in SUPPORTED_VERSIONS:
        raise EnvelopeError(
            f"envelope version {version} is not supported; this build understands "
            f"{SUPPORTED_VERSIONS}"
        )

    flags = _check_flags(payload[MAGIC_SIZE + VERSION_SIZE])

    offset = HEADER_SIZE
    record_bytes, offset = _read_section(payload, offset, "record")
    message, offset = _read_section(payload, offset, "message")
    signed_region = payload[:offset]
    signature, offset = _read_section(payload, offset, "signature")

    if offset != len(payload):
        raise EnvelopeError(
            f"envelope has {len(payload) - offset} trailing bytes after the "
            f"signature; the declared section lengths must account for the whole "
            f"payload"
        )

    return ParsedEnvelope(
        version=version,
        flags=flags,
        record_bytes=record_bytes,
        record=decode_record(record_bytes),
        message=message,
        signature=signature,
        signed_region=signed_region,
        total_length=len(payload),
    )
