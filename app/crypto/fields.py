"""Field checks for the untrusted JSON objects the crypto layer parses.

The verification record and the companion manifest are both JSON objects that arrive
from outside and must be checked field by field before any value is used. Each
function here takes the exception type to raise, so the record reports a
:class:`~app.crypto.errors.RecordError` and the manifest a
:class:`~app.crypto.errors.ManifestError` from the same checks.

*where* names the object in messages (``"record"``, ``"record.encryption"``,
``"manifest"``), so a failure reads as ``record.lsb_depth must be int, got str``.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    "require",
    "require_bounded_int",
    "require_hex",
    "require_positive",
]


def require(
    data: Mapping[str, Any],
    key: str,
    kind: type,
    where: str,
    *,
    error: type[Exception],
) -> Any:
    """Return ``data[key]``, which must be present and of type *kind*."""
    if key not in data:
        raise error(f"{where} is missing the required field {key!r}")
    value = data[key]
    # bool is a subclass of int, so an explicit guard is needed wherever an
    # integer is expected; True silently meaning 1 hides a caller mistake.
    if kind is int and isinstance(value, bool):
        raise error(f"{where}.{key} must be an integer, got a boolean")
    if not isinstance(value, kind):
        raise error(f"{where}.{key} must be {kind.__name__}, got {type(value).__name__}")
    return value


def require_positive(
    data: Mapping[str, Any], key: str, where: str, *, error: type[Exception]
) -> int:
    """Return ``data[key]``, which must be a positive integer."""
    value = require(data, key, int, where, error=error)
    if value <= 0:
        raise error(f"{where}.{key} must be a positive integer, got {value}")
    return value


def require_bounded_int(
    data: Mapping[str, Any],
    key: str,
    where: str,
    *,
    minimum: int,
    maximum: int,
    error: type[Exception],
) -> int:
    """Return ``data[key]``, which must be an integer from *minimum* to *maximum*."""
    value = require(data, key, int, where, error=error)
    if not minimum <= value <= maximum:
        raise error(
            f"{where}.{key} must be from {minimum} to {maximum} inclusive, got {value}"
        )
    return value


def require_hex(
    value: str,
    name: str,
    *,
    error: type[Exception],
    expected_length: int | None = None,
) -> str:
    """Return *value*, which must be a non-empty, even-length hexadecimal string."""
    if expected_length is not None and len(value) != expected_length:
        raise error(
            f"{name} must be {expected_length} hexadecimal characters, "
            f"got {len(value)}"
        )
    if not value or len(value) % 2 != 0:
        raise error(
            f"{name} must be a non-empty even-length hexadecimal string, "
            f"got {len(value)} characters"
        )
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise error(f"{name} is not valid hexadecimal") from exc
    return value
