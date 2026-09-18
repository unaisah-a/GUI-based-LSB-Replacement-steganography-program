"""Media-independent bit manipulation helpers (Requirement 13).

This module is shared with the audio layer. It accepts and returns only
integers, integer arrays and byte sequences, and performs no file access and no
media decoding (Requirement 13.6).

Two conventions are fixed here and relied on by every caller:

* **Bit order is most-significant-bit first.** A byte ``0b1000_0000`` becomes
  the bit sequence ``[1, 0, 0, 0, 0, 0, 0, 0]`` (Requirement 13.1, 13.2).
* **Bit sequences are ``uint8`` arrays whose every element is 0 or 1**, not
  bit-packed integers (Requirement 13.8). The unpacked form costs 8x the memory
  of the packed form but makes the group arithmetic in :func:`pack_bits_to_groups`
  a single reshape, which is what keeps the 36-million-element budget of
  Requirement 13.8 reachable.

Every operation is expressed as a whole-array numpy operation. A Python loop
over samples cannot meet the Requirement 13.8 budget: at roughly 10^7 loop
iterations per second, a 36-million-element sequence would take on the order of
tens of seconds against a 5-second limit, whereas the vectorised form runs in
the tens of milliseconds.
"""

from __future__ import annotations

from typing import Final

import numpy as np
import numpy.typing as npt

from app.stego.errors import ValidationError
from app.utils import constants

__all__ = [
    "MIN_LSB_DEPTH",
    "MAX_LSB_DEPTH",
    "SUPPORTED_SAMPLE_WIDTHS",
    "MAX_CONVERTIBLE_BYTES",
    "validate_lsb_depth",
    "validate_sample_width",
    "bytes_to_bits",
    "bits_to_bytes",
    "pack_bits_to_groups",
    "unpack_groups_to_bits",
    "write_low_bits",
    "read_low_bits",
    "groups_needed",
]

#: Requirement 13.4 and 14.3: LSB depth is an integer from 1 to 8 inclusive.
MIN_LSB_DEPTH: Final[int] = constants.MIN_LSB_DEPTH
MAX_LSB_DEPTH: Final[int] = constants.MAX_LSB_DEPTH

#: Requirement 13.4: 8-bit image and video samples and 16-bit PCM audio samples.
SUPPORTED_SAMPLE_WIDTHS: Final[tuple[int, ...]] = (
    constants.IMAGE_SAMPLE_WIDTH_BITS,
    constants.AUDIO_SAMPLE_WIDTH_BITS,
)

#: Requirement 13.1 and 13.3: conversion is specified for up to 64 MiB.
MAX_CONVERTIBLE_BYTES: Final[int] = 67_108_864

_WIDTH_TO_DTYPE: Final[dict[int, np.dtype]] = {
    8: np.dtype(np.uint8),
    16: np.dtype(np.uint16),
}

BitArray = npt.NDArray[np.uint8]


def validate_lsb_depth(lsb_count: object) -> int:
    """Return *lsb_count* as an ``int``, or raise :class:`ValidationError`.

    Requirement 13.10 and 14.3. ``bool`` is rejected even though it is a
    subclass of ``int``, because ``True`` silently meaning depth 1 hides a
    caller mistake.
    """
    if isinstance(lsb_count, bool) or not isinstance(lsb_count, (int, np.integer)):
        raise ValidationError(
            f"lsb_count must be an integer from {MIN_LSB_DEPTH} to {MAX_LSB_DEPTH} "
            f"inclusive, got type {type(lsb_count).__name__}"
        )
    value = int(lsb_count)
    if not MIN_LSB_DEPTH <= value <= MAX_LSB_DEPTH:
        raise ValidationError(
            f"lsb_count must be an integer from {MIN_LSB_DEPTH} to {MAX_LSB_DEPTH} "
            f"inclusive, got {value}"
        )
    return value


def validate_sample_width(sample_width: object) -> int:
    """Return *sample_width* as an ``int``, or raise :class:`ValidationError`.

    Requirement 13.10.
    """
    if isinstance(sample_width, bool) or not isinstance(
        sample_width, (int, np.integer)
    ):
        raise ValidationError(
            f"sample_width must be one of {SUPPORTED_SAMPLE_WIDTHS} bits, "
            f"got type {type(sample_width).__name__}"
        )
    value = int(sample_width)
    if value not in SUPPORTED_SAMPLE_WIDTHS:
        raise ValidationError(
            f"sample_width must be one of {SUPPORTED_SAMPLE_WIDTHS} bits, got {value}"
        )
    return value


def bytes_to_bits(data: bytes | bytearray | memoryview) -> BitArray:
    """Convert *data* to a most-significant-bit-first bit array.

    Requirement 13.1. Returns exactly ``8 * len(data)`` elements, each 0 or 1.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValidationError(
            "data must be bytes, bytearray or memoryview, "
            f"got type {type(data).__name__}"
        )
    length = len(bytes(data)) if isinstance(data, memoryview) else len(data)
    if length > MAX_CONVERTIBLE_BYTES:
        raise ValidationError(
            f"data must be at most {MAX_CONVERTIBLE_BYTES} bytes, got {length} bytes"
        )
    if length == 0:
        return np.zeros(0, dtype=np.uint8)
    # np.unpackbits is most-significant-bit first, matching Requirement 13.1.
    return np.unpackbits(np.frombuffer(bytes(data), dtype=np.uint8))


def bits_to_bytes(bits: npt.ArrayLike) -> bytes:
    """Convert a most-significant-bit-first bit array back to bytes.

    Requirement 13.2. Requirement 13.9 makes a length that is not a multiple of
    8 a validation error rather than something this function pads, because
    padding is the calling layer's decision.
    """
    array = np.ascontiguousarray(bits, dtype=np.uint8)
    if array.ndim != 1:
        raise ValidationError(
            f"bits must be a one-dimensional sequence, got {array.ndim} dimensions"
        )
    count = int(array.size)
    if count % 8 != 0:
        nearest = (count // 8) * 8
        raise ValidationError(
            f"bit count must be an exact multiple of 8, got {count}; "
            f"nearest multiples of 8 are {nearest} and {nearest + 8}"
        )
    if count == 0:
        return b""
    return np.packbits(array).tobytes()


def groups_needed(bit_count: int, lsb_count: int) -> int:
    """Return the number of samples an unpadded *bit_count* occupies.

    Requirement 2.7: the group count is the bit count divided by the LSB depth,
    rounded up.
    """
    return -(-int(bit_count) // int(lsb_count))


def pack_bits_to_groups(
    bits: npt.ArrayLike, lsb_count: int
) -> npt.NDArray[np.uint16]:
    """Pack a bit array into ``lsb_count``-wide unsigned group values.

    Requirement 2.4-2.6. Bits are consumed most-significant-bit first, so the
    first bit of each group lands in bit position ``lsb_count - 1`` of the group
    value. A trailing partial group is padded with zero bits (Requirement 2.6).

    The returned dtype is ``uint16`` so that a depth-8 group value of up to 255
    and the intermediate weighted sum both fit without overflow.
    """
    depth = validate_lsb_depth(lsb_count)
    array = np.ascontiguousarray(bits, dtype=np.uint8)
    if array.ndim != 1:
        raise ValidationError(
            f"bits must be a one-dimensional sequence, got {array.ndim} dimensions"
        )
    count = int(array.size)
    if count == 0:
        return np.zeros(0, dtype=np.uint16)

    group_count = groups_needed(count, depth)
    padded_length = group_count * depth
    if padded_length == count:
        padded = array
    else:
        padded = np.zeros(padded_length, dtype=np.uint8)
        padded[:count] = array

    # One reshape plus one matrix-vector product; no Python-level iteration.
    weights = (1 << np.arange(depth - 1, -1, -1, dtype=np.uint32)).astype(np.uint32)
    grouped = padded.reshape(group_count, depth).astype(np.uint32, copy=False)
    return grouped.dot(weights).astype(np.uint16)


def unpack_groups_to_bits(
    groups: npt.ArrayLike, lsb_count: int
) -> BitArray:
    """Expand ``lsb_count``-wide group values back into a bit array.

    Inverse of :func:`pack_bits_to_groups`. Requirement 3.2: bits come out in
    descending bit-position order, which reproduces the most-significant-bit
    first ordering used when writing.
    """
    depth = validate_lsb_depth(lsb_count)
    array = np.ascontiguousarray(groups)
    if array.ndim != 1:
        raise ValidationError(
            f"groups must be a one-dimensional sequence, got {array.ndim} dimensions"
        )
    if array.size == 0:
        return np.zeros(0, dtype=np.uint8)

    shifts = np.arange(depth - 1, -1, -1, dtype=np.uint32)
    widened = array.astype(np.uint32, copy=False)[:, None]
    return ((widened >> shifts) & np.uint32(1)).astype(np.uint8).reshape(-1)


def write_low_bits(
    samples: npt.ArrayLike,
    values: npt.ArrayLike,
    lsb_count: int,
    sample_width: int = 8,
) -> npt.NDArray[np.unsignedinteger]:
    """Replace the ``lsb_count`` lowest-order bits of *samples* with *values*.

    Requirement 13.4 and 13.5. Bit positions at or above ``lsb_count`` are
    preserved exactly, which is the cover-preservation guarantee of
    Requirement 2.8. Returns a new array; *samples* is not modified.
    """
    depth = validate_lsb_depth(lsb_count)
    width = validate_sample_width(sample_width)
    dtype = _WIDTH_TO_DTYPE[width]

    cover = np.ascontiguousarray(samples, dtype=dtype)
    data = np.ascontiguousarray(values, dtype=dtype)
    if cover.shape != data.shape:
        raise ValidationError(
            f"samples and values must have the same shape, "
            f"got {cover.shape} and {data.shape}"
        )

    payload_mask = dtype.type((1 << depth) - 1)
    # Complement within the sample width, so that depth 8 on an 8-bit sample
    # clears every bit and depth 8 on a 16-bit sample clears only the low byte.
    keep_mask = dtype.type(((1 << width) - 1) ^ ((1 << depth) - 1))
    return ((cover & keep_mask) | (data & payload_mask)).astype(dtype, copy=False)


def read_low_bits(
    samples: npt.ArrayLike, lsb_count: int, sample_width: int = 8
) -> npt.NDArray[np.unsignedinteger]:
    """Return the ``lsb_count`` lowest-order bits of each sample.

    Requirement 13.4. Returns a new array; *samples* is not modified.
    """
    depth = validate_lsb_depth(lsb_count)
    width = validate_sample_width(sample_width)
    dtype = _WIDTH_TO_DTYPE[width]

    array = np.ascontiguousarray(samples, dtype=dtype)
    payload_mask = dtype.type((1 << depth) - 1)
    return (array & payload_mask).astype(dtype, copy=False)
