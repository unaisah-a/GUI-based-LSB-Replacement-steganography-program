"""LSB replacement embedding and extraction for PNG and BMP cover objects.

Implements Requirements 2, 3, 4, 6, 7 and 14 of the image-steganography-analysis
specification (``docs/image_layer_requirements.md``). The algorithm itself is shared
with the other media and lives in :mod:`app.stego.lsb_core`; this module supplies the
image's flat sample stream and writes the result back as the cover's own format.

    embed_image(input_path, output_path, payload, lsb_count, start_location)
    extract_image(input_path, lsb_count, start_location) -> bytes

Extra arguments are keyword-only with defaults, so the agreed positional form keeps
working.

This module carries opaque bytes and returns no verdict. The 4-byte length header is
unauthenticated (Requirement 4.4), a non-zero start location conceals the payload
position but is not encryption (Requirement 7.8), and an extraction failure does not
identify its cause (Requirement 3.9). A mismatched read can even return plausible but
wrong bytes with no error (Requirement 3.10). Never treat a returned byte sequence as
verified.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from app.stego import image_io, lsb_core, paths
from app.stego.bit_utils import validate_lsb_depth
from app.stego.capacity import (
    CapacityReport,
    embeddable_channel_count,
    image_capacity_report,
)
from app.stego.image_io import ImageDescriptor
from app.utils import constants

__all__ = [
    "EmbedResult",
    "embed_image",
    "extract_image",
    "measure_capacity",
    "embeddable_stream",
]

_WIDTH = constants.IMAGE_SAMPLE_WIDTH_BITS


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

    Validation runs in the order fixed by Requirement 14.6 — input existence,
    input readability, output writability, payload type, LSB depth, start
    location, then capacity — and only the first failure is reported. Nothing is
    written until every check has passed (Requirement 6.1).

    :param overwrite: Requirement 6.6 makes an occupied output path an error
        unless this is ``True``.
    :raises FileError: missing or unreadable input, unwritable or occupied output.
    :raises DecodeError: unsupported or corrupt cover format.
    :raises ValidationError: bad payload type, depth, start location, or an
        output path equal to the input path.
    :raises CapacityError: the payload does not fit from *start_location*.
    """
    paths.assert_readable(input_path)
    paths.assert_distinct_paths(input_path, output_path)
    paths.check_output_writable(output_path, overwrite)
    data = lsb_core.validate_payload(payload)
    depth = validate_lsb_depth(lsb_count)

    array, descriptor = image_io.load_image(input_path)
    flat, usable_channels = embeddable_stream(array)
    start = lsb_core.validate_start_location(start_location, int(flat.size), "image")

    stego_flat, stream = lsb_core.embed_stream(flat, data, depth, start, _WIDTH)
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
        capacity=image_capacity_report(
            descriptor.height,
            descriptor.width,
            descriptor.channel_count,
            depth,
            start,
            len(data),
        ),
        lsb_count=depth,
        start_location=start,
        payload_length=len(data),
        encoded_length=stream.encoded_length,
        samples_written=stream.samples_needed,
    )


def extract_image(
    input_path: str,
    lsb_count: int,
    start_location: int,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Extract an embedded payload from the stego image at *input_path*.

    Reads the payload bits **starting at bit 32 of the same continuous stream** as
    the header, with no realignment to a sample boundary. At ``lsb_count=3`` the 32
    header bits occupy ``ceil(32 / 3) = 11`` samples, which supply 33 bits, so the
    first payload bit is the *last* bit taken from sample 10. Realigning to sample 11
    would drop that bit and corrupt every payload byte.

    :param manifest_payload_length: Requirement 4.7. When supplied, the decoded
        header must agree with it; it is a cross-check, not an override.
    :raises ExtractionError: the decoded length is inconsistent with the image
        capacity, the bit stream is truncated, or the manifest length disagrees.
        Per Requirement 3.9 the message never asserts which cause applies.
    """
    paths.assert_readable(input_path)
    depth = validate_lsb_depth(lsb_count)

    array, _ = image_io.load_image(input_path)
    flat, _ = embeddable_stream(array)
    total = int(flat.size)
    start = lsb_core.validate_start_location(start_location, total, "image")

    return lsb_core.extract_stream(
        lambda begin, end: flat[begin:end],
        total,
        depth,
        start,
        _WIDTH,
        "image",
        manifest_payload_length=manifest_payload_length,
    )
