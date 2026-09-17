"""Keyed, reproducible payload start-location derivation."""

from __future__ import annotations

import hashlib
import hmac


def _secret_bytes(secret: str | bytes) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or not secret:
        raise ValueError("start-location secret must not be empty")
    return secret


def derive_start_location(
    secret: str | bytes,
    *,
    total_samples: int,
    required_samples: int,
    media_type: str,
    media_id: str,
    nonce: str,
    lsb_count: int,
) -> int:
    """Map HMAC-SHA256 into every start position where the payload fits."""
    key = _secret_bytes(secret)
    if total_samples <= 0:
        raise ValueError("total_samples must be positive")
    if required_samples <= 0:
        raise ValueError("required_samples must be positive")
    if required_samples > total_samples:
        raise ValueError(
            f"payload needs {required_samples} samples but only {total_samples} are available"
        )
    if media_type not in {"image", "audio", "video"}:
        raise ValueError("media_type must be image, audio, or video")
    if not media_id or not nonce:
        raise ValueError("media_id and nonce must not be empty")
    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be between 1 and 8")

    message = (
        f"INF2005|start-v1|{media_type}|{media_id}|{nonce}|"
        f"{total_samples}|{required_samples}|{lsb_count}"
    ).encode("utf-8")
    value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
    highest_start = total_samples - required_samples
    return value % (highest_start + 1)


def calculate_start_location(
    passcode: str, cover_capacity: int, payload_len: int
) -> int:
    """Compatibility helper with corrected exact-fit handling."""
    if cover_capacity <= 0 or payload_len <= 0:
        raise ValueError("cover_capacity and payload_len must be positive")
    if payload_len > cover_capacity:
        raise ValueError(
            f"payload capacity check failed: payload ({payload_len}) exceeds "
            f"capacity ({cover_capacity})"
        )
    key = _secret_bytes(passcode)
    message = f"INF2005|legacy|{cover_capacity}|{payload_len}".encode("utf-8")
    value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
    return value % (cover_capacity - payload_len + 1)


def calculate_audio_start_location(
    passcode: str,
    total_samples: int,
    sample_rate: int,
    channels: int,
    lsb_count: int,
) -> int:
    """Legacy audio API retained for direct audio-layer callers."""
    if sample_rate <= 0 or channels <= 0:
        raise ValueError("sample_rate and channels must be positive")
    if total_samples <= 0:
        raise ValueError("total_samples must be positive")
    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be between 1 and 8")
    key = _secret_bytes(passcode)
    message = (
        f"INF2005|audio-legacy|{total_samples}|{sample_rate}|"
        f"{channels}|{lsb_count}"
    ).encode("utf-8")
    value = int.from_bytes(hmac.new(key, message, hashlib.sha256).digest(), "big")
    return value % max(1, total_samples // 4)
