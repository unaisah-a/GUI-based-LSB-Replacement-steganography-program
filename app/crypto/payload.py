"""Versioned payload envelope shared by image, audio and video carriers."""

from __future__ import annotations

import base64
import json
import os
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

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
MAX_SIGNATURE_BYTES = 16_384
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
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise PayloadFormatError(f"{field} is not valid URL-safe base64") from exc


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
    if not media_id or not isinstance(media_id, str):
        raise ValueError("media_id must be non-empty text")
    if media_type not in {"image", "audio", "video"}:
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

    record_nonce = record_nonce or secrets.token_urlsafe(16)
    timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
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
        "metadata": metadata or {},
        "nonce": record_nonce,
        "public_key_fingerprint": public_key_fingerprint(public_key),
        "record_version": FORMAT_VERSION,
        "timestamp": timestamp,
    }

    signature_size = (private_key.key_size + 7) // 8
    for _ in range(8):
        record_bytes = _canonical_json(record)
        total_length = HEADER.size + len(record_bytes) + len(stored_message) + signature_size
        if extraction["payload_length"] == total_length:
            break
        extraction["payload_length"] = total_length
    else:  # pragma: no cover - decimal length reaches a fixed point immediately.
        raise RuntimeError("payload length did not stabilise")

    record_bytes = _canonical_json(record)
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
    return BuiltEnvelope(data, record, message, stored_message, encrypted)


def parse_envelope(data: bytes) -> ParsedEnvelope:
    """Parse an envelope with strict length checks before slicing its fields."""
    if not isinstance(data, bytes):
        raise TypeError("payload envelope must be bytes")
    if len(data) < HEADER.size:
        raise PayloadFormatError("payload envelope is shorter than its header")
    magic, version, flags, record_len, message_len, signature_len = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise PayloadFormatError("payload magic is invalid")
    if version != FORMAT_VERSION:
        raise PayloadFormatError(f"payload format version {version} is unsupported")
    if flags & ~FLAG_ENCRYPTED:
        raise PayloadFormatError("payload flags contain unsupported values")
    if record_len > MAX_RECORD_BYTES:
        raise PayloadFormatError("payload record length exceeds the safety limit")
    if message_len > MAX_MESSAGE_BYTES + 16:
        raise PayloadFormatError("stored message length exceeds the safety limit")
    if signature_len > MAX_SIGNATURE_BYTES:
        raise PayloadFormatError("signature length exceeds the safety limit")
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
        record = json.loads(record_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadFormatError("signed record is not valid UTF-8 JSON") from exc
    if not isinstance(record, dict):
        raise PayloadFormatError("signed record must be a JSON object")
    return ParsedEnvelope(
        record=record,
        record_bytes=record_bytes,
        stored_message=stored_message,
        signature=signature,
        encrypted=bool(flags & FLAG_ENCRYPTED),
        serialized_length=total,
    )


def verify_envelope_signature(envelope: ParsedEnvelope, public_key) -> bool:
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
        nonce = _unb64(str(encryption.get("nonce", "")), "encryption nonce")
        media_id = str(record.get("media_id", ""))
        record_nonce = str(record.get("nonce", ""))
        return decrypt_message(
            envelope.stored_message,
            encryption_key,
            nonce,
            encryption_associated_data(media_id, record_nonce),
        )
    return envelope.stored_message


def message_hash_is_valid(envelope: ParsedEnvelope, message: bytes) -> bool:
    return hashes_match(str(envelope.record.get("message_hash", "")), message)


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
