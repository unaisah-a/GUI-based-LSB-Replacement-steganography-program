"""Keyed derivation of the payload start location.

Scheme
------
::

    seed  = HMAC-SHA256(
                key = secret,
                msg = "INF2005-START|v1|{media_type}|{media_id}|{nonce}"
                      "|{total_samples}|{lsb_depth}|{envelope_length}"
            )
    start = int(seed) mod (highest_valid_start_location + 1)

The result is a **sample index** in the same domain both stego layers use: an
index into the flattened stream of embeddable samples, which for an image means a
per-channel byte index with alpha excluded, and for audio means an interleaved
scalar sample index. The range is bounded by the highest index at which the whole
payload still fits, so a derived location always leaves room and never wraps.

Why every input is in the message
---------------------------------
All of ``media_id``, ``media_type``, ``nonce``, ``total_samples``, ``lsb_depth``
and ``envelope_length`` are included so that two files protected with the same
secret land in different places, and so that changing any extraction parameter
changes the location rather than silently producing a location that still
"works". The domain string and scheme version provide domain separation, so a
future scheme cannot produce colliding locations.

What replaced what, and why
---------------------------
This module previously held two incompatible derivations, both of which had to go:

* ``calculate_start_location`` reduced modulo ``cover_capacity - payload_len``,
  which made the location depend on the payload length. The extractor cannot know
  the payload length before locating the payload, so the value was not
  reproducible by a receiver. Its units were bytes, while both stego layers index
  samples.
* ``calculate_audio_start_location`` fixed the reproducibility problem by
  excluding the payload length, but confined the result to the first quarter of
  the file for no stated reason, applied only to audio, and lived behind a
  ``try/except ImportError`` inside the audio stego layer — putting key-derived
  behaviour inside a layer that is supposed to carry opaque bytes.

The circularity that broke the first version is resolved by the companion
manifest rather than by dropping an input: the manifest publishes
``envelope_length``, so a receiver knows it before extraction. It is not a secret,
and it is implied by the signed bytes, so a receiver can recompute it from the
parsed envelope and compare.

What this does and does not provide
-----------------------------------
A keyed start location conceals *where* a payload begins. It is not encryption
and provides no confidentiality: an attacker who is willing to search every
offset and depth will find the payload. Confidentiality comes from
:mod:`app.crypto.encryption`. See
:data:`app.utils.constants.START_LOCATION_NOTICE`, which the GUI displays beside
the start-mode control.

The secret is shared out of band and never appears in the manifest, the
verification record or the stego file.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

from app.crypto.errors import StartLocationError
from app.utils import constants

__all__ = [
    "DERIVATION_MESSAGE_TEMPLATE",
    "derive_start_location",
    "highest_valid_start_location",
    "required_sample_count",
    "resolve_start_location",
    "validate_manual_start_location",
]

#: Shown in the documentation and asserted by the tests, so the message layout is
#: a stated part of the scheme rather than an implementation detail.
DERIVATION_MESSAGE_TEMPLATE: Final[str] = (
    "{domain}|v{version}|{media_type}|{media_id}|{nonce}"
    "|{total_samples}|{lsb_depth}|{envelope_length}"
)


def _validate_secret(secret: object) -> bytes:
    if isinstance(secret, str):
        if not secret:
            raise StartLocationError(
                "the start-location secret must not be empty; either supply one or "
                f"use the {constants.START_METHOD_MANUAL!r} start method"
            )
        return secret.encode("utf-8")
    if isinstance(secret, (bytes, bytearray)):
        if not secret:
            raise StartLocationError(
                "the start-location secret must not be empty; either supply one or "
                f"use the {constants.START_METHOD_MANUAL!r} start method"
            )
        return bytes(secret)
    raise StartLocationError(
        f"the start-location secret must be str or bytes, got "
        f"{type(secret).__name__}"
    )


def _validate_count(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StartLocationError(
            f"{name} must be an integer, got {type(value).__name__}"
        )
    if value < minimum:
        raise StartLocationError(f"{name} must be at least {minimum}, got {value}")
    return value


def _validate_depth(lsb_depth: object) -> int:
    if isinstance(lsb_depth, bool) or not isinstance(lsb_depth, int):
        raise StartLocationError(
            f"lsb_depth must be an integer, got {type(lsb_depth).__name__}"
        )
    if not constants.MIN_LSB_DEPTH <= lsb_depth <= constants.MAX_LSB_DEPTH:
        raise StartLocationError(
            f"lsb_depth must be from {constants.MIN_LSB_DEPTH} to "
            f"{constants.MAX_LSB_DEPTH} inclusive, got {lsb_depth}"
        )
    return lsb_depth


def required_sample_count(envelope_length: int, lsb_depth: int) -> int:
    """Return how many consecutive samples an envelope occupies.

    The stego layer prepends its own 4-byte length header to the envelope, so the
    encoded stream is ``envelope_length + 4`` bytes and the sample count is that
    bit count divided by the depth, rounded up.

    The arithmetic is restated here rather than imported from
    :mod:`app.stego.capacity` so that the cryptography layer does not depend on
    the steganography layer. ``tests/test_start_location.py`` asserts that this
    agrees with ``capacity.required_position_count``, so the two cannot drift.
    """
    length = _validate_count(envelope_length, "envelope_length")
    depth = _validate_depth(lsb_depth)
    encoded_bits = (length + constants.LENGTH_HEADER_BYTES) * 8
    return -(-encoded_bits // depth)


def highest_valid_start_location(
    total_samples: int, envelope_length: int, lsb_depth: int
) -> int:
    """Return the largest start location at which the envelope still fits.

    A negative result means no start location fits, which callers should treat as
    insufficient capacity rather than clamping to zero.
    """
    total = _validate_count(total_samples, "total_samples")
    return total - required_sample_count(envelope_length, lsb_depth)


def derive_start_location(
    secret: str | bytes,
    *,
    media_id: str,
    media_type: str,
    nonce_hex: str,
    total_samples: int,
    lsb_depth: int,
    envelope_length: int,
) -> int:
    """Derive a reproducible start location from a shared secret.

    Every argument except *secret* is a non-secret value the receiver already
    holds: the manifest carries ``media_id``, ``media_type``, ``nonce``,
    ``lsb_depth`` and ``envelope_length``, and ``total_samples`` comes from the
    medium itself.

    :raises StartLocationError: the secret is empty or the wrong type, an argument
        is out of range, or the envelope does not fit at any start location.
    """
    key = _validate_secret(secret)
    depth = _validate_depth(lsb_depth)
    total = _validate_count(total_samples, "total_samples", minimum=1)
    length = _validate_count(envelope_length, "envelope_length")

    if not isinstance(media_id, str) or not media_id:
        raise StartLocationError("media_id must be a non-empty string")
    if media_type not in constants.MEDIA_TYPES:
        raise StartLocationError(
            f"media_type must be one of {constants.MEDIA_TYPES}, got {media_type!r}"
        )
    if not isinstance(nonce_hex, str) or not nonce_hex:
        raise StartLocationError("nonce_hex must be a non-empty hexadecimal string")

    highest = highest_valid_start_location(total, length, depth)
    if highest < 0:
        needed = required_sample_count(length, depth)
        raise StartLocationError(
            f"the payload does not fit at any start location: a {length}-byte "
            f"envelope needs {needed} samples at depth {depth}, but the medium has "
            f"only {total}"
        )

    message = DERIVATION_MESSAGE_TEMPLATE.format(
        domain=constants.START_LOCATION_DOMAIN,
        version=constants.START_LOCATION_SCHEME_VERSION,
        media_type=media_type,
        media_id=media_id,
        nonce=nonce_hex,
        total_samples=total,
        lsb_depth=depth,
        envelope_length=length,
    ).encode("utf-8")

    digest = hmac.new(key, message, hashlib.sha256).digest()
    # `highest` is inclusive, so the modulus is one larger. Without the +1 the
    # last valid sample position could never be selected.
    return int.from_bytes(digest, "big") % (highest + 1)


def validate_manual_start_location(
    start_location: int,
    *,
    total_samples: int,
    lsb_depth: int,
    envelope_length: int,
) -> int:
    """Check a user-chosen start location and return it.

    :raises StartLocationError: the value is not an integer, is negative, lies
        beyond the medium, or leaves too little room for the envelope.
    """
    value = _validate_count(start_location, "start_location")
    total = _validate_count(total_samples, "total_samples", minimum=1)
    highest = highest_valid_start_location(total, envelope_length, lsb_depth)

    if highest < 0:
        needed = required_sample_count(envelope_length, lsb_depth)
        raise StartLocationError(
            f"the payload does not fit at any start location: a "
            f"{envelope_length}-byte envelope needs {needed} samples at depth "
            f"{lsb_depth}, but the medium has only {total}"
        )
    if value >= total:
        raise StartLocationError(
            f"start_location {value} lies beyond the medium, which has "
            f"{total} embeddable samples (valid indices are 0 to {total - 1})"
        )
    if value > highest:
        needed = required_sample_count(envelope_length, lsb_depth)
        raise StartLocationError(
            f"start_location {value} leaves too little room: a "
            f"{envelope_length}-byte envelope needs {needed} samples at depth "
            f"{lsb_depth}, so the highest usable start location is {highest}"
        )
    return value


def resolve_start_location(
    start_method: str,
    *,
    total_samples: int,
    lsb_depth: int,
    envelope_length: int,
    secret: str | bytes | None = None,
    manual_start_location: int | None = None,
    media_id: str | None = None,
    media_type: str | None = None,
    nonce_hex: str | None = None,
) -> int:
    """Resolve a start location for either mode.

    One entry point so the sender and receiver sides cannot disagree about how a
    mode is interpreted. Which arguments are required depends on the mode, and a
    missing one is reported by name rather than defaulting to zero, because a
    silent fallback to sample 0 would be both a security regression and very hard
    to notice.
    """
    if start_method == constants.START_METHOD_MANUAL:
        if manual_start_location is None:
            raise StartLocationError(
                f"the {constants.START_METHOD_MANUAL!r} start method requires "
                f"manual_start_location"
            )
        return validate_manual_start_location(
            manual_start_location,
            total_samples=total_samples,
            lsb_depth=lsb_depth,
            envelope_length=envelope_length,
        )

    if start_method == constants.START_METHOD_HMAC:
        missing = [
            name
            for name, value in (
                ("secret", secret),
                ("media_id", media_id),
                ("media_type", media_type),
                ("nonce_hex", nonce_hex),
            )
            if value is None
        ]
        if missing:
            raise StartLocationError(
                f"the {constants.START_METHOD_HMAC!r} start method requires "
                f"{', '.join(missing)}"
            )
        return derive_start_location(
            secret,
            media_id=media_id,
            media_type=media_type,
            nonce_hex=nonce_hex,
            total_samples=total_samples,
            lsb_depth=lsb_depth,
            envelope_length=envelope_length,
        )

    raise StartLocationError(
        f"start_method must be one of {constants.START_METHODS}, got "
        f"{start_method!r}"
    )
