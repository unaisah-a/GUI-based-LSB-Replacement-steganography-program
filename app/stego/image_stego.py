"""LSB replacement embedding and extraction for PNG and BMP cover objects.

Implements Requirements 2, 3, 4, 6, 7 and 14 of the image-steganography-analysis
specification, using :mod:`app.stego.bit_utils` for every bit operation
(Requirement 13.7) and :mod:`app.stego.capacity` for every capacity figure.

The public interface matches the team's agreed signatures::

    embed_image(input_path, output_path, payload, lsb_count, start_location)
    extract_image(input_path, lsb_count, start_location) -> bytes

Extra arguments are keyword-only with defaults, so the agreed positional form
keeps working.

Security boundary
-----------------
This module carries opaque bytes. It performs no hashing, signing, signature
verification or encryption, and returns no verdict. Three consequences are worth
stating plainly, because they are easy to overstate elsewhere:

* The 4-byte length header is **unauthenticated** (Requirement 4.4). A modified
  header is indistinguishable here from an unmodified one. Detecting that is the
  verification layer's job.
* A non-zero start location **conceals** the payload position. It is not
  encryption and provides neither confidentiality nor authenticity
  (Requirement 7.8). Deriving a start location from a secret key belongs to the
  cryptography layer.
* An extraction failure does **not** identify its cause (Requirement 3.9). A
  wrong depth, a wrong start location, an absent payload and sample corruption
  produce indistinguishable bit streams. Worse, a mismatched read can decode a
  length that happens to fit and return plausible-but-wrong bytes with no error
  at all (Requirement 3.10). Never treat a returned byte sequence as verified.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

import numpy as np
import numpy.typing as npt

from app.stego import image_io, paths
from app.stego.bit_utils import (
    bits_to_bytes,
    bytes_to_bits,
    groups_needed,
    pack_bits_to_groups,
    read_low_bits,
    unpack_groups_to_bits,
    validate_lsb_depth,
    write_low_bits,
)
from app.stego.capacity import (
    LENGTH_HEADER_BYTES,
    MAX_PAYLOAD_LENGTH,
    CapacityReport,
    embeddable_channel_count,
    image_capacity_report,
)
from app.stego.errors import (
    CapacityError,
    ExtractionError,
    FileError,
    ValidationError,
    safe_path,
)
from app.stego.image_io import ImageDescriptor

__all__ = [
    "IMAGE_SAMPLE_WIDTH_BITS",
    "LENGTH_HEADER_BITS",
    "EmbedResult",
    "embed_image",
    "extract_image",
    "measure_capacity",
    "embeddable_stream",
]

#: Image samples are 8 bits wide (Requirement 1.1).
IMAGE_SAMPLE_WIDTH_BITS: Final[int] = 8

#: The length header occupies the first 32 bits of the continuous bit stream.
LENGTH_HEADER_BITS: Final[int] = LENGTH_HEADER_BYTES * 8


@dataclass(frozen=True)
class EmbedResult:
    """What an embedding produced.

    Returned so the GUI can report capacity use without recomputing it. The
    agreed interface does not specify a return value, so callers may ignore this.
    """

    output_path: str
    container_format: str
    descriptor: ImageDescriptor
    capacity: CapacityReport
    lsb_count: int
    start_location: int
    payload_length: int
    encoded_length: int
    samples_written: int


# --------------------------------------------------------------------------- #
# Byte stream construction
# --------------------------------------------------------------------------- #


def embeddable_stream(array: npt.NDArray[np.uint8]) -> tuple[npt.NDArray[np.uint8], int]:
    """Return a flat view of the embeddable samples, and the channel count used.

    Requirement 2.1 and 2.2. Traversal_Order is row-major over pixels and, within
    a pixel, red then green then blue. Alpha is excluded, so an RGBA cover has
    the same embeddable sample count as its RGB equivalent.

    ``array[:, :, :n]`` followed by a C-order ``reshape(-1)`` produces exactly
    that ordering: the last axis varies fastest, then columns, then rows. The
    slice is contiguous for 1- and 3-channel arrays but not for a 4-channel one,
    so the reshape may copy; callers must not rely on the result aliasing
    *array*.

    The flat index ``i`` maps back to the full array as::

        row     = i // (width * n)
        column  = (i // n) % width
        channel = i % n
    """
    channels = array.shape[2]
    usable = embeddable_channel_count(channels)
    return array[:, :, :usable].reshape(-1), usable


def measure_capacity(
    input_path: str | os.PathLike[str],
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
) -> tuple[CapacityReport, ImageDescriptor]:
    """Measure the capacity of an image file without embedding anything.

    Requirement 5. Raises only for an unreadable or unsupported file and for an
    invalid depth; an insufficient capacity is reported in the result rather than
    raised (Requirement 5.8).
    """
    depth = validate_lsb_depth(lsb_count)
    descriptor = image_io.describe_only(input_path)
    report = image_capacity_report(
        descriptor.height,
        descriptor.width,
        descriptor.channel_count,
        depth,
        start_location,
        payload_length,
    )
    return report, descriptor


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #


# The filesystem checks are shared with the audio and video layers, so that all
# three reject an in-place write, an occupied output path and an unreadable input
# identically. Aliased rather than called through the module so the existing call
# sites and their tests are unchanged.
_assert_readable = paths.assert_readable
_assert_distinct_paths = paths.assert_distinct_paths


def _validate_payload(payload: object) -> bytes:
    """Requirement 14.4 (type) and Requirement 4.3 (representable length)."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ValidationError(
            f"payload must be bytes or bytearray, got type {type(payload).__name__}"
        )
    data = bytes(payload)
    if len(data) > MAX_PAYLOAD_LENGTH:
        raise ValidationError(
            f"payload length {len(data)} exceeds the maximum representable length "
            f"of {MAX_PAYLOAD_LENGTH} bytes for a "
            f"{LENGTH_HEADER_BYTES}-byte length header"
        )
    return data


def _validate_start_location(start_location: object, total_samples: int) -> int:
    """Requirement 7.1, 7.2 and 7.6.

    The type check precedes the range check, and ``bool`` is rejected even though
    it is an ``int`` subclass, because ``True`` silently meaning index 1 hides a
    caller mistake.
    """
    if isinstance(start_location, bool) or not isinstance(
        start_location, (int, np.integer)
    ):
        raise ValidationError(
            f"start_location must be an integer, got type {type(start_location).__name__}"
        )
    value = int(start_location)
    if total_samples == 0:
        raise CapacityError("image has no embeddable samples")
    if not 0 <= value < total_samples:
        raise ValidationError(
            f"start_location must be an integer from 0 to {total_samples - 1} "
            f"inclusive, got {value}"
        )
    return value


# --------------------------------------------------------------------------- #
# Embedding
# --------------------------------------------------------------------------- #


def embed_image(
    input_path: str,
    output_path: str,
    payload: bytes,
    lsb_count: int,
    start_location: int,
    *,
    overwrite: bool = False,
) -> EmbedResult:
    """Embed *payload* into the cover image at *input_path*.

    The encoded stream is a 4-byte big-endian payload length followed by the
    payload bytes (Requirement 4.1). Its bits are written most-significant-bit
    first into the ``lsb_count`` lowest-order bits of consecutive embeddable
    samples, starting at *start_location* and never wrapping (Requirement 2).

    Validation runs in the order fixed by Requirement 14.6 — input existence,
    input readability, output writability, payload type, LSB depth, start
    location, then capacity — and only the first failure is reported. Nothing is
    written until every check has passed (Requirement 6.1).

    :param overwrite: Requirement 6.6 makes an occupied output path an error
        unless this is ``True``. Keyword-only, so the agreed positional signature
        is unchanged.
    :raises FileError: missing or unreadable input, unwritable or occupied output.
    :raises DecodeError: unsupported or corrupt cover format.
    :raises ValidationError: bad payload type, depth, start location, or an
        output path equal to the input path.
    :raises CapacityError: the payload does not fit from *start_location*.
    """
    # Requirement 14.6 ordering.
    _assert_readable(input_path)
    _assert_distinct_paths(input_path, output_path)
    image_io.check_output_writable(output_path, overwrite)
    data = _validate_payload(payload)
    depth = validate_lsb_depth(lsb_count)

    array, descriptor = image_io.load_image(input_path)
    flat, usable_channels = embeddable_stream(array)
    total_samples = int(flat.size)
    start = _validate_start_location(start_location, total_samples)

    encoded = len(data).to_bytes(LENGTH_HEADER_BYTES, "big") + data
    bits = bytes_to_bits(encoded)
    group_count = groups_needed(int(bits.size), depth)

    report = image_capacity_report(
        descriptor.height,
        descriptor.width,
        descriptor.channel_count,
        depth,
        start,
        len(data),
    )

    # Requirement 6.1 and 7.3: enforce before touching a single sample.
    available = total_samples - start
    if group_count > available:
        raise CapacityError(
            f"payload does not fit: the encoded stream needs {len(encoded)} bytes "
            f"({group_count} samples) at depth {depth} from start location {start}, "
            f"but only {report.available_capacity_bytes} bytes ({available} samples) "
            f"are available; the largest payload that fits is "
            f"{report.max_payload_length} bytes"
        )

    groups = pack_bits_to_groups(bits, depth)
    stego_flat = flat.copy()
    stego_flat[start : start + group_count] = write_low_bits(
        flat[start : start + group_count],
        groups,
        depth,
        IMAGE_SAMPLE_WIDTH_BITS,
    )

    stego = array.copy()
    stego[:, :, :usable_channels] = stego_flat.reshape(
        array.shape[0], array.shape[1], usable_channels
    )

    # Requirement 1.3: the container comes from the detected cover format.
    image_io.save_image(
        stego, output_path, descriptor.container_format, overwrite=overwrite
    )

    return EmbedResult(
        output_path=os.fspath(output_path),
        container_format=descriptor.container_format,
        descriptor=descriptor,
        capacity=report,
        lsb_count=depth,
        start_location=start,
        payload_length=len(data),
        encoded_length=len(encoded),
        samples_written=group_count,
    )


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def _decode_length_header(header_bits: npt.NDArray[np.uint8]) -> int:
    """Decode the 32-bit big-endian length from the head of the bit stream."""
    return int.from_bytes(bits_to_bytes(header_bits[:LENGTH_HEADER_BITS]), "big")


def extract_image(
    input_path: str,
    lsb_count: int,
    start_location: int,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Extract an embedded payload from the stego image at *input_path*.

    Reads the ``lsb_count`` lowest-order bits of each embeddable sample from
    *start_location* onward into one continuous bit stream, decodes the 32-bit
    length header from its first 32 bits, then reads the payload bits **starting
    at bit 32 of that same stream**. There is deliberately no realignment to a
    sample boundary, which matters whenever the depth does not divide 32.

    Worked example at ``lsb_count=3``: 32 header bits occupy
    ``ceil(32 / 3) = 11`` samples, which supply 33 bits. Bit 32 — the first
    payload bit — is therefore the *last* of the three bits taken from sample 10,
    not the first bit of sample 11. Realigning to sample 11 would drop one bit
    and corrupt every payload byte. The same applies at depths 5, 6 and 7.

    The read happens in two stages. Only the samples needed for the header are
    read first, and the decoded length is bounds-checked against the available
    capacity *before* any payload buffer is sized (Requirements 3.6 and 4.6).
    Without that check, a crafted or corrupt header could request a multi-gigabyte
    allocation.

    :param manifest_payload_length: Requirement 4.7. When supplied, the decoded
        header must agree with it. The header still determines how many bytes are
        read; the manifest value is a cross-check, not an override.
    :raises ExtractionError: the decoded length is inconsistent with the image
        capacity, the bit stream is truncated, or the manifest length disagrees.
        Per Requirement 3.9 the message never asserts which cause applies.
    """
    _assert_readable(input_path)
    depth = validate_lsb_depth(lsb_count)

    array, descriptor = image_io.load_image(input_path)
    flat, _ = embeddable_stream(array)
    total_samples = int(flat.size)
    start = _validate_start_location(start_location, total_samples)

    available = total_samples - start
    header_groups = groups_needed(LENGTH_HEADER_BITS, depth)
    if available < header_groups:
        raise ExtractionError(
            f"bit stream is truncated: reading a {LENGTH_HEADER_BITS}-bit length "
            f"header at depth {depth} needs {header_groups} samples from start "
            f"location {start}, but only {available} are available"
        )

    header_bits = unpack_groups_to_bits(
        read_low_bits(
            flat[start : start + header_groups], depth, IMAGE_SAMPLE_WIDTH_BITS
        ),
        depth,
    )
    payload_length = _decode_length_header(header_bits)

    # Requirement 3.6 and 4.6: bound-check before allocating anything.
    available_capacity = (available * depth) // 8
    max_payload = max(0, available_capacity - LENGTH_HEADER_BYTES)
    if payload_length > max_payload:
        raise ExtractionError(
            f"decoded payload length {payload_length} is inconsistent with the image "
            f"capacity: at depth {depth} from start location {start} the image can "
            f"hold at most {max_payload} payload bytes"
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
        read_low_bits(
            flat[start : start + needed_groups], depth, IMAGE_SAMPLE_WIDTH_BITS
        ),
        depth,
    )
    # Continuous stream: payload bits follow the header with no realignment, and
    # trailing padding bits beyond the payload are discarded (Requirement 3.3).
    payload_bits = stream_bits[LENGTH_HEADER_BITS:total_bits]
    return bits_to_bytes(payload_bits)
