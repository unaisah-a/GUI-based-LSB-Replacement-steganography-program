"""Simple repetition coding used as the project's robustness innovation."""

from __future__ import annotations

import numpy as np


def encode_repetition3(data: bytes) -> bytes:
    """Store each byte three times consecutively."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data:
        return b""
    values = np.frombuffer(data, dtype=np.uint8)
    return np.repeat(values, 3).tobytes()


def decode_repetition3(data: bytes, expected_length: int) -> bytes:
    """Recover each byte using bitwise majority voting across three copies."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if expected_length < 0:
        raise ValueError("expected_length must not be negative")
    expected_encoded = expected_length * 3
    if len(data) != expected_encoded:
        raise ValueError(
            f"repetition-3 data should contain {expected_encoded} bytes, "
            f"received {len(data)}"
        )
    if not data:
        return b""
    values = np.frombuffer(data, dtype=np.uint8).reshape(-1, 3)
    majority = (
        (values[:, 0] & values[:, 1])
        | (values[:, 0] & values[:, 2])
        | (values[:, 1] & values[:, 2])
    )
    return majority.astype(np.uint8, copy=False).tobytes()
