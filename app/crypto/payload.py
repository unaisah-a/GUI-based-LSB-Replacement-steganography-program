"""Versioned payload envelope shared by image, audio and video carriers."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto.encryption import decrypt_message, encrypt_message
from app.crypto.hashing import compute_sha256, hashes_match
from app.crypto.key_manager import public_key_fingerprint
from app.crypto.signatures import sign_bytes, verify_bytes


MAGIC = b"SMIV"
FORMAT_VERSION = 1
FLAG_ENCRYPTED = 0x01
HEADER = struct.Struct(">4sBBIII")
MAX_RECORD_BYTES = 1_048_576
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
MAX_STORED_MESSAGE_BYTES = MAX_MESSAGE_BYTES + 16
MAX_SIGNATURE_BYTES = 16_384
MIN_SIGNATURE_BYTES = 256
MIN_ENVELOPE_BYTES = HEADER.size + 1 + MIN_SIGNATURE_BYTES
MAX_ENVELOPE_BYTES = (
    HEADER.size + MAX_RECORD_BYTES + MAX_STORED_MESSAGE_BYTES + MAX_SIGNATURE_BYTES
)
MAX_MEDIA_ID_BYTES = 1_024
MAX_NONCE_BYTES = 256
MAX_CONTENT_TYPE_BYTES = 256
PAYLOAD_DOMAIN = b"INF2005-ACW1-PAYLOAD-V1\x00"


class PayloadFormatError(ValueError):
    """The extracted payload is malformed or uses an unsupported format."""


@dataclass(frozen=True)
class ParsedEnvelope:
    record: dict[str, Any]
    record_bytes: bytes
    stored_message: bytes
    signature: bytes
    encrypted: bool
    serialized_length: int


@dataclass(frozen=True)
class BuiltEnvelope:
    data: bytes
    record: dict[str, Any]
    plaintext_message: bytes
    stored_message: bytes
    encrypted: bool


def _require_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PayloadFormatError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise PayloadFormatError(f"{field} is outside the supported range")
    return value


def _require_text(value: object, field: str, *, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise PayloadFormatError(f"{field} must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PayloadFormatError(f"{field} is not valid Unicode text") from exc
    if len(encoded) > maximum_bytes:
        raise PayloadFormatError(f"{field} exceeds the supported size")
    return value


def _require_ascii(value: object, field: str, *, maximum_bytes: int) -> str:
    text = _require_text(value, field, maximum_bytes=maximum_bytes)
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PayloadFormatError(f"{field} must contain ASCII text") from exc
    return text


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PayloadFormatError(f"signed record contains duplicate field {key!r}")
        value[key] = item
    return value


def _validate_json_value(value: object, field: str, depth: int = 0) -> None:
    if depth > 32:
        raise PayloadFormatError(f"{field} exceeds the maximum nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PayloadFormatError(f"{field} contains invalid Unicode text") from exc
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise PayloadFormatError(f"{field} contains a non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, field, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PayloadFormatError(f"{field} object keys must be text")
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise PayloadFormatError(
                    f"{field} contains an invalid Unicode object key"
                ) from exc
            _validate_json_value(item, field, depth + 1)
        return
    raise PayloadFormatError(f"{field} contains a value that JSON cannot represent")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise PayloadFormatError(f"{field} is not valid URL-safe base64") from exc
    if _b64(decoded) != value:
        raise PayloadFormatError(f"{field} is not canonical URL-safe base64")
    return decoded


def _validate_record(record: object, *, encrypted: bool, total_length: int) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise PayloadFormatError("signed record must be a JSON object")
    required = {
        "content_type",
        "encryption",
        "extraction",
        "media_id",
        "message_hash",
        "metadata",
        "nonce",
        "public_key_fingerprint",
        "record_version",
        "timestamp",
    }
    missing = required - set(record)
    unknown = set(record) - required
    if missing:
        raise PayloadFormatError(
            "signed record is missing required fields: " + ", ".join(sorted(missing))
        )
    if unknown:
        raise PayloadFormatError(
            "signed record contains unsupported fields: " + ", ".join(sorted(unknown))
        )

    _require_int(
        record["record_version"],
        "record_version",
        minimum=0,
        maximum=255,
    )
    if record["record_version"] != FORMAT_VERSION:
        raise PayloadFormatError(
            f"record version {record['record_version']} is unsupported"
        )
    _require_text(
        record["media_id"], "media_id", maximum_bytes=MAX_MEDIA_ID_BYTES
    )
    _require_ascii(record["nonce"], "nonce", maximum_bytes=MAX_NONCE_BYTES)
    _require_text(
        record["content_type"],
        "content_type",
        maximum_bytes=MAX_CONTENT_TYPE_BYTES,
    )
    timestamp = _require_text(record["timestamp"], "timestamp", maximum_bytes=128)
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)
    except (ValueError, OverflowError) as exc:
        raise PayloadFormatError("timestamp must be ISO-8601 text") from exc
    if parsed_timestamp.tzinfo is None:
        raise PayloadFormatError("timestamp must include a timezone")

    for field in ("message_hash", "public_key_fingerprint"):
        digest = record[field]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise PayloadFormatError(f"{field} must be 64 lower-case hex digits")

    metadata = record["metadata"]
    if not isinstance(metadata, dict):
        raise PayloadFormatError("metadata must be a JSON object")
    _validate_json_value(metadata, "metadata")

    extraction = record["extraction"]
    if not isinstance(extraction, dict):
        raise PayloadFormatError("extraction must be a JSON object")
    extraction_required = {
        "lsb_count",
        "media_type",
        "payload_length",
        "robustness",
        "start_method",
    }
    start_method = extraction.get("start_method")
    if start_method == "manual":
        extraction_required.add("start_location")
    missing = extraction_required - set(extraction)
    unknown = set(extraction) - extraction_required
    if missing:
        raise PayloadFormatError(
            "signed extraction settings are missing fields: "
            + ", ".join(sorted(missing))
        )
    if unknown:
        raise PayloadFormatError(
            "signed extraction settings contain unsupported fields: "
            + ", ".join(sorted(unknown))
        )
    media_type = extraction["media_type"]
    if not isinstance(media_type, str) or media_type not in {"image", "audio", "video"}:
        raise PayloadFormatError("signed media_type is unsupported")
    _require_int(extraction["lsb_count"], "signed lsb_count", minimum=1, maximum=8)
    if not isinstance(start_method, str) or start_method not in {"manual", "hmac-sha256"}:
        raise PayloadFormatError("signed start_method is unsupported")
    if start_method == "manual":
        _require_int(
            extraction["start_location"],
            "signed start_location",
            minimum=0,
            maximum=(1 << 63) - 1,
        )
    robustness = extraction["robustness"]
    if not isinstance(robustness, str) or robustness not in {"none", "repetition-3"}:
        raise PayloadFormatError("signed robustness mode is unsupported")
    payload_length = _require_int(
        extraction["payload_length"],
        "signed payload_length",
        minimum=MIN_ENVELOPE_BYTES,
        maximum=MAX_ENVELOPE_BYTES,
    )
    if payload_length != total_length:
        raise PayloadFormatError(
            "signed payload_length does not match the serialized envelope length"
        )

    encryption = record["encryption"]
    if not isinstance(encryption, dict):
        raise PayloadFormatError("encryption must be a JSON object")
    expected_algorithm = "AES-256-GCM" if encrypted else "none"
    if encryption.get("algorithm") != expected_algorithm:
        raise PayloadFormatError(
            "envelope encryption flag disagrees with signed encryption metadata"
        )
    expected_fields = {"algorithm", "nonce"} if encrypted else {"algorithm"}
    if set(encryption) != expected_fields:
        raise PayloadFormatError("signed encryption metadata has invalid fields")
    if encrypted:
        nonce = encryption["nonce"]
        if not isinstance(nonce, str) or len(_unb64(nonce, "encryption nonce")) != 12:
            raise PayloadFormatError("encryption nonce must decode to exactly 12 bytes")
    return record


def encryption_associated_data(media_id: str, record_nonce: str) -> bytes:
    return PAYLOAD_DOMAIN + media_id.encode("utf-8") + b"\x00" + record_nonce.encode("ascii")


def signature_input(record_bytes: bytes, stored_message: bytes) -> bytes:
    return PAYLOAD_DOMAIN + struct.pack(">I", len(record_bytes)) + record_bytes + stored_message


def build_envelope(
    message: bytes,
    *,
    media_id: str,
    media_type: str,
    lsb_count: int,
    start_method: str,
    private_key,
    content_type: str = "text/plain; charset=utf-8",
    metadata: dict[str, Any] | None = None,
    encryption_key: bytes | None = None,
    manual_start_location: int | None = None,
    robustness: str = "none",
    timestamp: str | None = None,
    record_nonce: str | None = None,
) -> BuiltEnvelope:
    """Create, optionally encrypt, and sign a complete payload envelope."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError(f"message exceeds the {MAX_MESSAGE_BYTES}-byte safety limit")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("private_key must be an RSA private key")
    if private_key.key_size < 2048 or (private_key.key_size + 7) // 8 > MAX_SIGNATURE_BYTES:
        raise ValueError("RSA private key size is outside the supported range")
    try:
        _require_text(media_id, "media_id", maximum_bytes=MAX_MEDIA_ID_BYTES)
        _require_text(
            content_type, "content_type", maximum_bytes=MAX_CONTENT_TYPE_BYTES
        )
    except PayloadFormatError as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(media_type, str) or media_type not in {"image", "audio", "video"}:
        raise ValueError("media_type must be image, audio, or video")
    if isinstance(lsb_count, bool) or not isinstance(lsb_count, int) or not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be an integer from 1 to 8")
    if start_method not in {"manual", "hmac-sha256"}:
        raise ValueError("start_method must be manual or hmac-sha256")
    if start_method == "manual" and (
        isinstance(manual_start_location, bool)
        or not isinstance(manual_start_location, int)
        or manual_start_location < 0
    ):
        raise ValueError("manual start mode requires a non-negative start location")
    if start_method == "hmac-sha256" and manual_start_location is not None:
        raise ValueError("derived start mode must not include a manual start location")
    if not isinstance(robustness, str) or robustness not in {"none", "repetition-3"}:
        raise ValueError("robustness must be none or repetition-3")
    if metadata is not None and not isinstance(metadata, dict):
        raise TypeError("metadata must be a dictionary")
    try:
        _validate_json_value(metadata or {}, "metadata")
    except PayloadFormatError as exc:
        raise ValueError(str(exc)) from exc

    record_nonce = (
        secrets.token_urlsafe(16) if record_nonce is None else record_nonce
    )
    timestamp = (
        datetime.now(timezone.utc).isoformat(timespec="seconds")
        if timestamp is None
        else timestamp
    )
    try:
        _require_ascii(record_nonce, "nonce", maximum_bytes=MAX_NONCE_BYTES)
    except PayloadFormatError as exc:
        raise ValueError(str(exc)) from exc
    aad = encryption_associated_data(media_id, record_nonce)
    encrypted = encryption_key is not None
    if encrypted:
        aes_nonce, stored_message = encrypt_message(message, encryption_key, aad)
        encryption_record: dict[str, Any] = {
            "algorithm": "AES-256-GCM",
            "nonce": _b64(aes_nonce),
        }
    else:
        stored_message = message
        encryption_record = {"algorithm": "none"}

    public_key = private_key.public_key()
    extraction: dict[str, Any] = {
        "lsb_count": lsb_count,
        "media_type": media_type,
        "payload_length": 0,
        "robustness": robustness,
        "start_method": start_method,
    }
    if start_method == "manual":
        extraction["start_location"] = manual_start_location

    record: dict[str, Any] = {
        "content_type": content_type,
        "encryption": encryption_record,
        "extraction": extraction,
        "media_id": media_id,
        "message_hash": compute_sha256(message),
        "metadata": {} if metadata is None else metadata,
        "nonce": record_nonce,
        "public_key_fingerprint": public_key_fingerprint(public_key),
        "record_version": FORMAT_VERSION,
        "timestamp": timestamp,
    }

    signature_size = (private_key.key_size + 7) // 8
    for _ in range(8):
        record_bytes = _canonical_json(record)
        if len(record_bytes) > MAX_RECORD_BYTES:
            raise ValueError("signed record exceeds the supported size")
        total_length = HEADER.size + len(record_bytes) + len(stored_message) + signature_size
        if total_length > MAX_ENVELOPE_BYTES:
            raise ValueError("payload envelope exceeds the supported size")
        if extraction["payload_length"] == total_length:
            break
        extraction["payload_length"] = total_length
    else:  # pragma: no cover - decimal length reaches a fixed point immediately.
        raise RuntimeError("payload length did not stabilise")

    record_bytes = _canonical_json(record)
    try:
        _validate_record(record, encrypted=encrypted, total_length=total_length)
    except PayloadFormatError as exc:
        raise ValueError(f"invalid signed record: {exc}") from exc
    signature = sign_bytes(signature_input(record_bytes, stored_message), private_key)
    flags = FLAG_ENCRYPTED if encrypted else 0
    header = HEADER.pack(
        MAGIC,
        FORMAT_VERSION,
        flags,
        len(record_bytes),
        len(stored_message),
        len(signature),
    )
    data = header + record_bytes + stored_message + signature
    if len(data) != extraction["payload_length"]:
        raise RuntimeError("payload length changed after signing")
    # Keep builder and parser limits/schema in lockstep.
    parse_envelope(data)
    return BuiltEnvelope(data, record, message, stored_message, encrypted)


def parse_envelope(data: bytes) -> ParsedEnvelope:
    """Parse an envelope with strict length checks before slicing its fields."""
    if not isinstance(data, bytes):
        raise TypeError("payload envelope must be bytes")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise PayloadFormatError("payload envelope exceeds the supported size")
    if len(data) < HEADER.size:
        raise PayloadFormatError("payload envelope is shorter than its header")
    magic, version, flags, record_len, message_len, signature_len = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise PayloadFormatError("payload magic is invalid")
    if version != FORMAT_VERSION:
        raise PayloadFormatError(f"payload format version {version} is unsupported")
    if flags & ~FLAG_ENCRYPTED:
        raise PayloadFormatError("payload flags contain unsupported values")
    if record_len == 0 or record_len > MAX_RECORD_BYTES:
        raise PayloadFormatError("payload record length exceeds the safety limit")
    if message_len > MAX_STORED_MESSAGE_BYTES:
        raise PayloadFormatError("stored message length exceeds the safety limit")
    if not MIN_SIGNATURE_BYTES <= signature_len <= MAX_SIGNATURE_BYTES:
        raise PayloadFormatError("signature length exceeds the safety limit")
    encrypted = bool(flags & FLAG_ENCRYPTED)
    if encrypted and message_len < 16:
        raise PayloadFormatError("encrypted message is shorter than its authentication tag")
    total = HEADER.size + record_len + message_len + signature_len
    if total != len(data):
        raise PayloadFormatError(
            f"payload length fields describe {total} bytes but {len(data)} were extracted"
        )
    cursor = HEADER.size
    record_bytes = data[cursor : cursor + record_len]
    cursor += record_len
    stored_message = data[cursor : cursor + message_len]
    cursor += message_len
    signature = data[cursor : cursor + signature_len]
    try:
        record = json.loads(
            record_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PayloadFormatError(
                    f"signed record contains invalid JSON constant {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PayloadFormatError("signed record is not valid UTF-8 JSON") from exc
    record = _validate_record(record, encrypted=encrypted, total_length=total)
    if _canonical_json(record) != record_bytes:
        raise PayloadFormatError("signed record is not in canonical JSON form")
    return ParsedEnvelope(
        record=record,
        record_bytes=record_bytes,
        stored_message=stored_message,
        signature=signature,
        encrypted=encrypted,
        serialized_length=total,
    )


def verify_envelope_signature(envelope: ParsedEnvelope, public_key) -> bool:
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    expected_signature_length = (public_key.key_size + 7) // 8
    if len(envelope.signature) != expected_signature_length:
        return False
    return verify_bytes(
        signature_input(envelope.record_bytes, envelope.stored_message),
        envelope.signature,
        public_key,
    )


def recover_message(envelope: ParsedEnvelope, encryption_key: bytes | None = None) -> bytes:
    record = envelope.record
    if envelope.encrypted:
        if encryption_key is None:
            raise ValueError("an encryption key is required for this payload")
        encryption = record.get("encryption")
        if not isinstance(encryption, dict) or encryption.get("algorithm") != "AES-256-GCM":
            raise PayloadFormatError("encrypted payload has invalid encryption metadata")
        nonce = _unb64(encryption["nonce"], "encryption nonce")
        media_id = record["media_id"]
        record_nonce = record["nonce"]
        return decrypt_message(
            envelope.stored_message,
            encryption_key,
            nonce,
            encryption_associated_data(media_id, record_nonce),
        )
    return envelope.stored_message


def message_hash_is_valid(envelope: ParsedEnvelope, message: bytes) -> bool:
    return hashes_match(envelope.record["message_hash"], message)


# Compatibility helpers retained for teammates that used the initial JSON block.
def build_payload_block(
    media_bytes: bytes, media_id: str, metadata: dict | None = None
) -> bytes:
    record = {
        "hash": compute_sha256(media_bytes),
        "id": media_id,
        "meta": metadata or {},
        "nonce": secrets.token_hex(8),
        "ts": int(datetime.now(timezone.utc).timestamp()),
    }
    encoded = _canonical_json(record)
    return struct.pack(">I", len(encoded)) + encoded


def parse_payload_block(raw_payload_block: bytes) -> dict:
    if len(raw_payload_block) < 4:
        raise PayloadFormatError("payload block is shorter than its length header")
    length = struct.unpack(">I", raw_payload_block[:4])[0]
    if length > MAX_RECORD_BYTES or len(raw_payload_block) != length + 4:
        raise PayloadFormatError("payload block length is invalid")
    try:
        value = json.loads(raw_payload_block[4:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadFormatError("payload block is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PayloadFormatError("payload block must contain a JSON object")
    return value
