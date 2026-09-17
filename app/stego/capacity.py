"""Media-independent capacity arithmetic (Requirements 5 and 7).

Requirement 5.6 requires the arithmetic to take a plain sample count rather than
a file path or a sample array, so that the audio layer can pass
``frame_count * channel_count`` and reuse this module unchanged.
:func:`image_capacity_report` is a thin image-specific wrapper that derives the
sample count and additionally reports the embeddable channel count asked for by
Requirement 5.4.

Three quantities are deliberately kept distinct, because conflating them is the
easiest way to produce an off-by-four bug:

``available_capacity_bytes``
    The maximum **Encoded_Stream** length, which includes the 4-byte length
    header (Requirement 5.2).
``max_payload_length``
    The largest **payload** that fits, which is the above minus 4, floored at 0
    (Requirement 5.7).
``required_position_count``
    The number of consecutive samples an encoded stream occupies at a given
    depth (Requirement 7.3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.stego.bit_utils import validate_lsb_depth
from app.stego.errors import ValidationError

__all__ = [
    "LENGTH_HEADER_BYTES",
    "MAX_PAYLOAD_LENGTH",
    "CapacityReport",
    "embeddable_channel_count",
    "capacity_report",
    "image_capacity_report",
    "available_capacity_bytes",
    "required_position_count",
    "highest_valid_start_location",
]

#: Requirement 4.1: the length header is a fixed 4-byte big-endian integer.
LENGTH_HEADER_BYTES: Final[int] = 4

#: Requirement 4.3: the largest payload length a 4-byte header can represent.
MAX_PAYLOAD_LENGTH: Final[int] = 0xFFFF_FFFF


@dataclass(frozen=True)
class CapacityReport:
    """Capacity measurement for one (sample count, depth, start location) triple.

    Requirement 5.4 fixes the reported fields. Every field is a plain Python
    ``int``, ``bool``, ``float`` or ``None`` so that the GUI layer can render the
    report without importing anything from this layer.
    """

    total_embeddable_samples: int
    lsb_count: int
    start_location: int
    available_samples: int
    available_capacity_bytes: int
    max_payload_length: int
    payload_fits: bool
    length_header_bytes: int = LENGTH_HEADER_BYTES
    embeddable_channel_count: int | None = None
    #: Present only when the caller supplied a payload length.
    payload_length: int | None = None
    required_encoded_length: int | None = None
    required_position_count: int | None = None
    #: ``None`` when the available capacity is below the 4-byte header, which
    #: Requirement 5.8 reports as "not applicable" rather than as an error.
    capacity_used_percent: float | None = None
    #: Requirement 7.4. ``None`` when no payload length was supplied.
    highest_valid_start_location: int | None = None
    #: Requirement 7.7. ``True`` when no start location can hold the payload.
    start_location_range_empty: bool = False


def _validate_count(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"{name} must be a non-negative integer, got type {type(value).__name__}"
        )
    if value < 0:
        raise ValidationError(f"{name} must be a non-negative integer, got {value}")
    return value


def embeddable_channel_count(channel_count: int) -> int:
    """Return how many of *channel_count* channels can carry payload bits.

    Requirement 5.1 and 2.2: alpha-channel samples are excluded, so an RGBA
    image reports 3 just like its RGB equivalent.
    """
    count = _validate_count(channel_count, "channel_count")
    if count == 1:
        return 1
    if count == 3:
        return 3
    if count == 4:
        return 3  # RGBA: red, green and blue only.
    raise ValidationError(
        f"channel_count must be 1, 3 or 4, got {count}"
    )


def available_capacity_bytes(
    total_embeddable_samples: int, lsb_count: int, start_location: int = 0
) -> int:
    """Return the maximum encoded-stream length in bytes.

    Requirement 5.2 and 5.3. Rounds down to whole bytes, so the reported value
    is always achievable.
    """
    total = _validate_count(total_embeddable_samples, "total_embeddable_samples")
    depth = validate_lsb_depth(lsb_count)
    start = _validate_count(start_location, "start_location")
    available_samples = max(0, total - start)
    return (available_samples * depth) // 8


def required_position_count(encoded_length: int, lsb_count: int) -> int:
    """Return how many consecutive samples an encoded stream occupies.

    Requirement 7.3: the ceiling of the encoded bit count divided by the depth.
    """
    length = _validate_count(encoded_length, "encoded_length")
    depth = validate_lsb_depth(lsb_count)
    return -(-(length * 8) // depth)


def highest_valid_start_location(
    total_embeddable_samples: int, encoded_length: int, lsb_count: int
) -> int:
    """Return the largest start location that still fits *encoded_length*.

    Requirement 7.4. A negative result means no start location fits; callers
    should treat that as the empty range of Requirement 7.7 rather than clamping
    it to 0. :func:`capacity_report` surfaces this as
    ``start_location_range_empty``.
    """
    total = _validate_count(total_embeddable_samples, "total_embeddable_samples")
    needed = required_position_count(encoded_length, lsb_count)
    return total - needed


def capacity_report(
    total_embeddable_samples: int,
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
    *,
    embeddable_channels: int | None = None,
) -> CapacityReport:
    """Measure capacity for a sample count, depth and start location.

    Media-independent as required by Requirement 5.6: the audio layer passes
    ``frame_count * channel_count`` as *total_embeddable_samples*.

    Requirement 5.8 makes an insufficient capacity a measurement result, not an
    error, so this function does not raise when nothing fits. Requirement 7.7
    does the same for an empty start-location range. Enforcement is the caller's
    job; see :func:`app.stego.image_stego.embed_image`.
    """
    total = _validate_count(total_embeddable_samples, "total_embeddable_samples")
    depth = validate_lsb_depth(lsb_count)
    start = _validate_count(start_location, "start_location")

    available_samples = max(0, total - start)
    capacity = (available_samples * depth) // 8
    max_payload = max(0, capacity - LENGTH_HEADER_BYTES)

    required_encoded: int | None = None
    required_positions: int | None = None
    used_percent: float | None = None
    highest_start: int | None = None
    range_empty = False

    if payload_length is not None:
        payload = _validate_count(payload_length, "payload_length")
        required_encoded = payload + LENGTH_HEADER_BYTES
        required_positions = required_position_count(required_encoded, depth)
        highest_start = total - required_positions
        range_empty = highest_start < 0
        # Requirement 5.9: report the percentage only when the header itself
        # fits, and do not cap it at 100 so that an oversized payload is visibly
        # oversized.
        if capacity >= LENGTH_HEADER_BYTES and capacity > 0:
            used_percent = round(required_encoded / capacity * 100, 1)

    return CapacityReport(
        total_embeddable_samples=total,
        lsb_count=depth,
        start_location=start,
        available_samples=available_samples,
        available_capacity_bytes=capacity,
        max_payload_length=max_payload,
        # An earlier version computed this as ``max_payload > 0``, ignoring
        # payload_length entirely, so a payload far larger than the cover was
        # still reported as fitting. Embedding was never unsafe, because
        # embed_image enforces capacity itself, but a GUI pre-flight check
        # reading this field would have been wrong.
        #
        # The comparison is against the *encoded* length, so a zero-length
        # payload still requires room for the 4-byte header. With no payload
        # length supplied the report describes the medium rather than a specific
        # embedding, and the question degrades to whether the header alone fits.
        payload_fits=(
            capacity >= LENGTH_HEADER_BYTES
            if payload_length is None
            else capacity >= required_encoded
        ),
        embeddable_channel_count=embeddable_channels,
        payload_length=payload_length,
        required_encoded_length=required_encoded,
        required_position_count=required_positions,
        capacity_used_percent=used_percent,
        highest_valid_start_location=highest_start,
        start_location_range_empty=range_empty,
    )


def image_capacity_report(
    height: int,
    width: int,
    channel_count: int,
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
) -> CapacityReport:
    """Measure capacity for a decoded image shape.

    Requirement 5.1: the sample count is
    ``width * height * embeddable_channel_count``, where the embeddable channel
    count excludes alpha.
    """
    rows = _validate_count(height, "height")
    columns = _validate_count(width, "width")
    channels = embeddable_channel_count(channel_count)
    return capacity_report(
        rows * columns * channels,
        lsb_count,
        start_location,
        payload_length,
        embeddable_channels=channels,
    )
