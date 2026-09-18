"""Companion manifest for extraction parameters that cannot be hidden-only."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.crypto.payload import (
    FORMAT_VERSION,
    MAX_ENVELOPE_BYTES,
    MIN_ENVELOPE_BYTES,
)


MANIFEST_VERSION = 1
PAYLOAD_FORMAT_VERSION = FORMAT_VERSION
MAX_MANIFEST_BYTES = 1_048_576
MAX_MEDIA_ID_BYTES = 1_024
MAX_NONCE_BYTES = 256
MAX_CARRIER_PAYLOAD_BYTES = MAX_ENVELOPE_BYTES * 3


class ManifestError(ValueError):
    """A manifest is missing, malformed, or contains unsafe values."""


def _require_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ManifestError(f"{field} is outside the supported range")
    return value


def _require_text(value: object, field: str, *, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{field} must be non-empty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ManifestError(f"{field} is not valid Unicode text") from exc
    if len(encoded) > maximum_bytes:
        raise ManifestError(f"{field} exceeds the supported size")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ManifestError(f"manifest contains duplicate field {key!r}")
        value[key] = item
    return value


@dataclass(frozen=True)
class Manifest:
    media_type: str
    media_id: str
    nonce: str
    lsb_count: int
    start_method: str
    payload_length: int
    public_key_fingerprint: str
    robustness: str = "none"
    start_location: int | None = None
    carrier_payload_length: int | None = None
    manifest_version: int = MANIFEST_VERSION
    payload_format: int = PAYLOAD_FORMAT_VERSION
    video_frame_index: int | None = None

    def validate(self) -> "Manifest":
        _require_int(
            self.manifest_version,
            "manifest_version",
            minimum=0,
            maximum=(1 << 31) - 1,
        )
        if self.manifest_version != MANIFEST_VERSION:
            raise ManifestError(
                f"manifest version {self.manifest_version} is unsupported"
            )
        _require_int(
            self.payload_format,
            "payload_format",
            minimum=0,
            maximum=(1 << 31) - 1,
        )
        if self.payload_format != PAYLOAD_FORMAT_VERSION:
            raise ManifestError(
                f"payload format {self.payload_format} is unsupported"
            )
        if not isinstance(self.media_type, str) or self.media_type not in {
            "image",
            "audio",
            "video",
        }:
            raise ManifestError("media_type must be image, audio, or video")
        _require_text(
            self.media_id, "media_id", maximum_bytes=MAX_MEDIA_ID_BYTES
        )
        nonce = _require_text(self.nonce, "nonce", maximum_bytes=MAX_NONCE_BYTES)
        try:
            nonce.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ManifestError("nonce must contain ASCII text") from exc
        _require_int(self.lsb_count, "lsb_count", minimum=1, maximum=8)
        if not isinstance(self.start_method, str) or self.start_method not in {
            "manual",
            "hmac-sha256",
        }:
            raise ManifestError("start_method must be manual or hmac-sha256")
        if self.start_method == "manual":
            if (
                isinstance(self.start_location, bool)
                or not isinstance(self.start_location, int)
                or self.start_location < 0
            ):
                raise ManifestError(
                    "manual start mode requires a non-negative start_location"
                )
        elif self.start_location is not None:
            raise ManifestError(
                "a derived start location must not be disclosed in the manifest"
            )
        _require_int(
            self.payload_length,
            "payload_length",
            minimum=MIN_ENVELOPE_BYTES,
            maximum=MAX_ENVELOPE_BYTES,
        )
        if self.carrier_payload_length is not None:
            _require_int(
                self.carrier_payload_length,
                "carrier_payload_length",
                minimum=1,
                maximum=MAX_CARRIER_PAYLOAD_BYTES,
            )
        fingerprint = self.public_key_fingerprint
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise ManifestError("public_key_fingerprint must be 64 lower-case hex digits")
        if not isinstance(self.robustness, str) or self.robustness not in {
            "none",
            "repetition-3",
        }:
            raise ManifestError("robustness mode is unsupported")
        if self.media_type == "video":
            _require_int(
                self.video_frame_index,
                "video_frame_index",
                minimum=0,
                maximum=(1 << 31) - 1,
            )
        elif self.video_frame_index is not None:
            raise ManifestError("video_frame_index is only valid for video media")
        if self.robustness == "none" and self.carrier_payload_length not in {
            None,
            self.payload_length,
        }:
            raise ManifestError(
                "carrier_payload_length must equal payload_length without robustness"
            )
        if self.robustness == "repetition-3" and (
            self.carrier_payload_length != self.payload_length * 3
        ):
            raise ManifestError(
                "repetition-3 carrier_payload_length must be three times payload_length"
            )
        return self

    @property
    def embedded_payload_length(self) -> int:
        return self.carrier_payload_length or self.payload_length

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if value["start_location"] is None:
            del value["start_location"]
        if value["video_frame_index"] is None:
            del value["video_frame_index"]
        return value

    def to_json(self) -> str:
        self.validate()
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Manifest":
        if not isinstance(value, dict):
            raise ManifestError("manifest root must be a JSON object")
        if any(not isinstance(key, str) for key in value):
            raise ManifestError("manifest field names must be text")
        allowed = {
            "manifest_version",
            "payload_format",
            "media_type",
            "media_id",
            "nonce",
            "lsb_count",
            "start_method",
            "start_location",
            "payload_length",
            "carrier_payload_length",
            "public_key_fingerprint",
            "robustness",
            "video_frame_index",
        }
        required = allowed - {
            "start_location",
            "carrier_payload_length",
            "video_frame_index",
        }
        if value.get("media_type") == "video":
            required.add("video_frame_index")
        missing = required - set(value)
        if missing:
            raise ManifestError(
                "manifest is missing required fields: " + ", ".join(sorted(missing))
            )
        unknown = set(value) - allowed
        if unknown:
            raise ManifestError(
                "manifest contains unsupported fields: " + ", ".join(sorted(unknown))
            )
        try:
            manifest = cls(**value)
        except TypeError as exc:
            raise ManifestError(f"manifest fields are incomplete: {exc}") from exc
        return manifest.validate()


def save_manifest(manifest: Manifest, path: str | os.PathLike[str]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = manifest.to_json().encode("utf-8")
    handle, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(destination.parent)
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def load_manifest(path: str | os.PathLike[str]) -> Manifest:
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise ManifestError("manifest file could not be read") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest exceeds the 1 MiB safety limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ManifestError(f"manifest contains invalid JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError("manifest is not valid UTF-8 JSON") from exc
    return Manifest.from_dict(value)
