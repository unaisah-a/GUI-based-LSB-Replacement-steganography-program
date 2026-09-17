"""Companion manifest for extraction parameters that cannot be hidden-only."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


MANIFEST_VERSION = 1
PAYLOAD_FORMAT_VERSION = 1


class ManifestError(ValueError):
    """A manifest is missing, malformed, or contains unsafe values."""


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

    def validate(self) -> "Manifest":
        if self.manifest_version != MANIFEST_VERSION:
            raise ManifestError(
                f"manifest version {self.manifest_version} is unsupported"
            )
        if self.payload_format != PAYLOAD_FORMAT_VERSION:
            raise ManifestError(
                f"payload format {self.payload_format} is unsupported"
            )
        if self.media_type not in {"image", "audio", "video"}:
            raise ManifestError("media_type must be image, audio, or video")
        if not self.media_id or not self.nonce:
            raise ManifestError("media_id and nonce must not be empty")
        if isinstance(self.lsb_count, bool) or not 1 <= self.lsb_count <= 8:
            raise ManifestError("lsb_count must be an integer from 1 to 8")
        if self.start_method not in {"manual", "hmac-sha256"}:
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
        if (
            isinstance(self.payload_length, bool)
            or not isinstance(self.payload_length, int)
            or self.payload_length <= 0
            or self.payload_length > 64 * 1024 * 1024
        ):
            raise ManifestError("payload_length is outside the supported range")
        if self.carrier_payload_length is not None and (
            isinstance(self.carrier_payload_length, bool)
            or not isinstance(self.carrier_payload_length, int)
            or self.carrier_payload_length <= 0
            or self.carrier_payload_length > 192 * 1024 * 1024
        ):
            raise ManifestError("carrier_payload_length is outside the supported range")
        fingerprint = self.public_key_fingerprint
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise ManifestError("public_key_fingerprint must be 64 lower-case hex digits")
        if self.robustness not in {"none", "repetition-3"}:
            raise ManifestError("robustness mode is unsupported")
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
        }
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
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ManifestError("manifest file could not be read") from exc
    if len(raw) > 1_048_576:
        raise ManifestError("manifest exceeds the 1 MiB safety limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest is not valid UTF-8 JSON") from exc
    return Manifest.from_dict(value)
