"""The LSB replacement algorithm, independent of any medium.

Image, audio and video all embed the same encoded stream the same way; they differ
only in where their flat sample stream comes from and how wide a sample is. This
module holds everything they share, so each medium only has to supply its samples:

* the encoded stream is a 4-byte big-endian payload length followed by the payload;
* its bits are written most-significant-bit first into the ``depth`` lowest bits of
  consecutive samples from ``start``, never wrapping;
* extraction reads the header first and bounds-checks the decoded length against the
  available capacity *before* sizing any payload buffer, then reads the payload bits
  from bit 32 of the same continuous stream, with no realignment to a sample
  boundary.

The header is unauthenticated, and a wrong depth, a wrong start location, an absent
payload and corrupted samples all produce indistinguishable streams, so the
extraction errors never claim which one occurred. A mismatched read can also decode a
plausible length and return wrong bytes with no error at all. Nothing returned here
is verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Final

import numpy as np
import numpy.typing as npt

from app.stego.bit_utils import (
    bits_to_bytes,
    bytes_to_bits,
    groups_needed,
    pack_bits_to_groups,
    read_low_bits,
    unpack_groups_to_bits,
    write_low_bits,
)
from app.stego.capacity import MAX_PAYLOAD_LENGTH
from app.stego.errors import CapacityError, ExtractionError, ValidationError
from app.utils import constants

__all__ = [
    "LENGTH_HEADER_BITS",
    "MAX_PAYLOAD_LENGTH",
    "EncodedStream",
    "embed_stream",
    "encode_stream",
    "extract_stream",
    "validate_payload",
    "validate_start_location",
]

#: The length header occupies the first 32 bits of the continuous bit stream.
LENGTH_HEADER_BITS: Final[int] = constants.LENGTH_HEADER_BYTES * 8


#: Returns the samples in ``[begin, end)`` of a medium's flat stream.
RangeReader = Callable[[int, int], npt.NDArray[np.unsignedinteger]]


def validate_payload(payload: object) -> bytes:
    """Return *payload* as ``bytes``, or raise :class:`ValidationError`."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ValidationError(
            f"payload must be bytes or bytearray, got type {type(payload).__name__}"
        )
    data = bytes(payload)
    if len(data) > MAX_PAYLOAD_LENGTH:
        raise ValidationError(
            f"payload length {len(data)} exceeds the maximum representable length "
            f"of {MAX_PAYLOAD_LENGTH} bytes for a "
            f"{constants.LENGTH_HEADER_BYTES}-byte length header"
        )
    return data


def validate_start_location(
    start_location: object, total_samples: int, medium: str
) -> int:
    """Return *start_location* as an ``int`` index into *total_samples*.

    ``numpy`` integers are accepted, because a start location may come out of
    numpy arithmetic. ``bool`` is refused even though it is an ``int`` subclass,
    because ``True`` silently meaning index 1 would hide a caller mistake. The type
    check comes before the range check.
    """
    if isinstance(start_location, bool) or not isinstance(
        start_location, (int, np.integer)
    ):
        raise ValidationError(
            f"start_location must be an integer, got type "
            f"{type(start_location).__name__}"
        )
    value = int(start_location)
    if total_samples == 0:
        raise CapacityError(f"the {medium} has no embeddable samples")
    if not 0 <= value < total_samples:
        raise ValidationError(
            f"start_location must be an integer from 0 to {total_samples - 1} "
            f"inclusive, got {value}"
        )
    return value


@dataclass(frozen=True)
class EncodedStream:
    """An encoded stream, split into the per-sample values to write."""

    payload_length: int
    #: Header plus payload, in bytes.
    encoded_length: int
    #: One ``depth``-bit value per sample, the last one zero-padded.
    groups: npt.NDArray[np.uint16]

    @property
    def samples_needed(self) -> int:
        return int(self.groups.size)


def encode_stream(
    payload: bytes, depth: int, total_samples: int, start: int
) -> EncodedStream:
    """Encode *payload* and confirm it fits from *start*.

    :raises CapacityError: the encoded stream needs more samples than remain after
        *start*. Raised before anything is written.
    """
    encoded = len(payload).to_bytes(constants.LENGTH_HEADER_BYTES, "big") + payload
    bits = bytes_to_bits(encoded)
    needed = groups_needed(int(bits.size), depth)

    available = total_samples - start
    if needed > available:
        capacity = (available * depth) // 8
        raise CapacityError(
            f"payload does not fit: the encoded stream needs {len(encoded)} bytes "
            f"({needed} samples) at depth {depth} from start location {start}, but "
            f"only {capacity} bytes ({available} samples) are available; the largest "
            f"payload that fits is "
            f"{max(0, capacity - constants.LENGTH_HEADER_BYTES)} bytes"
        )
    return EncodedStream(
        payload_length=len(payload),
        encoded_length=len(encoded),
        groups=pack_bits_to_groups(bits, depth),
    )


def embed_stream(
    flat: npt.NDArray[np.unsignedinteger],
    payload: bytes,
    depth: int,
    start: int,
    width: int,
) -> tuple[npt.NDArray[np.unsignedinteger], EncodedStream]:
    """Return a copy of *flat* with *payload* embedded from *start*, and the stream.

    For media held in memory as one flat array. *flat* is not modified.
    """
    stream = encode_stream(payload, depth, int(flat.size), start)
    end = start + stream.samples_needed
    stego = flat.copy()
    stego[start:end] = write_low_bits(flat[start:end], stream.groups, depth, width)
    return stego, stream


def extract_stream(
    read_range: RangeReader,
    total_samples: int,
    depth: int,
    start: int,
    width: int,
    medium: str,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Read an encoded stream starting at *start* and return its payload.

    *read_range* supplies samples on demand, so a medium that streams its samples,
    such as video, never has to hold more than the region being read.

    :param manifest_payload_length: when supplied, the decoded header must agree with
        it. The header still decides how many bytes are read; this is a cross-check.
    :raises ExtractionError: the decoded length is inconsistent with the capacity,
        the stream is truncated, or the manifest length disagrees.
    """
    available = total_samples - start
    header_groups = groups_needed(LENGTH_HEADER_BITS, depth)
    if available < header_groups:
        raise ExtractionError(
            f"bit stream is truncated: reading a {LENGTH_HEADER_BITS}-bit length "
            f"header at depth {depth} needs {header_groups} samples from start "
            f"location {start}, but only {available} are available"
        )

    header_bits = unpack_groups_to_bits(
        read_low_bits(read_range(start, start + header_groups), depth, width), depth
    )
    payload_length = int.from_bytes(
        bits_to_bytes(header_bits[:LENGTH_HEADER_BITS]), "big"
    )

    # Bounds-check before allocating anything, so a corrupt or crafted header cannot
    # request a multi-gigabyte buffer.
    max_payload = max(0, (available * depth) // 8 - constants.LENGTH_HEADER_BYTES)
    if payload_length > max_payload:
        raise ExtractionError(
            f"decoded payload length {payload_length} is inconsistent with the "
            f"{medium} capacity: at depth {depth} from start location {start} the "
            f"{medium} can hold at most {max_payload} payload bytes"
        )

    if manifest_payload_length is not None and payload_length != manifest_payload_length:
        raise ExtractionError(
            f"decoded payload length {payload_length} disagrees with the manifest "
            f"payload length {manifest_payload_length}"
        )

    if payload_length == 0:
        return b""

    total_bits = LENGTH_HEADER_BITS + payload_length * 8
    needed_groups = groups_needed(total_bits, depth)
    if needed_groups > available:
        raise ExtractionError(
            f"bit stream is truncated: a {payload_length}-byte payload needs "
            f"{needed_groups} samples at depth {depth} from start location {start}, "
            f"but only {available} are available"
        )

    stream_bits = unpack_groups_to_bits(
        read_low_bits(read_range(start, start + needed_groups), depth, width), depth
    )
    # Payload bits follow the header with no realignment; trailing padding bits
    # beyond the payload are discarded.
    return bits_to_bytes(stream_bits[LENGTH_HEADER_BITS:total_bits])
