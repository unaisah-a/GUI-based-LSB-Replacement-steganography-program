"""LSB replacement embedding and extraction for 16-bit PCM WAV cover objects.

The audio counterpart of :mod:`app.stego.image_stego`, with the same encoded-stream
format, validation order, error hierarchy and public signature::

    embed_audio(input_path, output_path, payload, lsb_count, start_location)
    extract_audio(input_path, lsb_count, start_location) -> bytes

PCM samples are signed, so the sample array is *reinterpreted* with
``view(np.uint16)`` rather than cast: LSB replacement must operate on the
two's-complement bit pattern, and a cast would change the numbers. See
``docs/architecture.md`` section 3.

This module carries opaque bytes and returns no verdict. The length header is
unauthenticated, and a mismatched depth or start location can decode a plausible
length and return wrong bytes with no error. Never treat a returned byte sequence as
verified.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

import numpy as np
import numpy.typing as npt
import soundfile as sf

from app.stego import lsb_core, paths
from app.stego.bit_utils import validate_lsb_depth
from app.stego.capacity import CapacityReport, capacity_report
from app.stego.errors import DecodeError
from app.utils import constants, file_utils
from app.utils.file_utils import display_name

__all__ = [
    "SUPPORTED_FORMAT",
    "SUPPORTED_SUBTYPE",
    "AudioDescriptor",
    "AudioEmbedResult",
    "embed_audio",
    "extract_audio",
    "measure_capacity",
    "embeddable_stream",
    "read_audio",
    "write_audio",
]

SUPPORTED_FORMAT: Final[str] = "WAV"
SUPPORTED_SUBTYPE: Final[str] = "PCM_16"

_WIDTH = constants.AUDIO_SAMPLE_WIDTH_BITS


@dataclass(frozen=True)
class AudioDescriptor:
    """What can be said about a WAV file once decoded."""

    file_name: str
    container_format: str
    subtype: str
    sample_rate: int
    channel_count: int
    frame_count: int
    #: Scalar samples across all channels: ``frame_count * channel_count``. This
    #: is the domain a start location indexes.
    total_samples: int
    duration_seconds: float


@dataclass(frozen=True)
class AudioEmbedResult:
    """What an embedding produced.

    Mirrors :class:`app.stego.image_stego.EmbedResult` field for field where the
    two media have the same concept, so a caller can render either without
    branching.
    """

    output_path: str
    container_format: str
    descriptor: AudioDescriptor
    capacity: CapacityReport
    lsb_count: int
    start_location: int
    payload_length: int
    encoded_length: int
    samples_written: int


# --------------------------------------------------------------------------- #
# Reading and writing
# --------------------------------------------------------------------------- #


def _describe(path: str | os.PathLike[str], info: "sf._SoundFileInfo") -> AudioDescriptor:
    channels = int(info.channels)
    frames = int(info.frames)
    return AudioDescriptor(
        file_name=display_name(path),
        container_format=info.format,
        subtype=info.subtype,
        sample_rate=int(info.samplerate),
        channel_count=channels,
        frame_count=frames,
        total_samples=frames * channels,
        duration_seconds=(frames / info.samplerate) if info.samplerate else 0.0,
    )


def describe_only(path: str | os.PathLike[str]) -> AudioDescriptor:
    """Describe a WAV file without decoding its samples.

    Used for capacity queries, where reading a multi-megabyte sample array only to
    count it would be wasteful.
    """
    paths.assert_readable(path)
    name = display_name(path)
    try:
        info = sf.info(os.fspath(path))
    except Exception as exc:
        raise DecodeError(
            f"{name} could not be read as an audio file; supported covers are "
            f"16-bit PCM WAV ({SUPPORTED_SUBTYPE})"
        ) from exc

    if info.format != SUPPORTED_FORMAT:
        raise DecodeError(
            f"{name} was detected as {info.format}, but only {SUPPORTED_FORMAT} is "
            f"supported as an audio cover object"
        )
    if info.subtype != SUPPORTED_SUBTYPE:
        raise DecodeError(
            f"{name} is a {info.subtype} WAV file, but only {SUPPORTED_SUBTYPE} "
            f"(16-bit PCM) is supported; other subtypes either apply lossy "
            f"compression or use a sample width this layer does not handle"
        )
    if info.frames == 0:
        raise DecodeError(f"{name} contains no audio samples")

    return _describe(path, info)


def read_audio(
    path: str | os.PathLike[str],
) -> tuple[npt.NDArray[np.int16], AudioDescriptor]:
    """Decode a 16-bit PCM WAV file into an int16 sample array and a descriptor.

    The array has shape ``(frames,)`` for mono and ``(frames, channels)``
    otherwise, matching what ``soundfile`` produces with ``always_2d=False``.
    """
    descriptor = describe_only(path)
    try:
        samples, _ = sf.read(os.fspath(path), dtype="int16", always_2d=False)
    except Exception as exc:
        raise DecodeError(
            f"{descriptor.file_name} could not be decoded as "
            f"{SUPPORTED_SUBTYPE} audio"
        ) from exc

    array = np.ascontiguousarray(samples, dtype=np.int16)
    if array.size != descriptor.total_samples:
        raise DecodeError(
            f"{descriptor.file_name} declares {descriptor.frame_count} frames of "
            f"{descriptor.channel_count} channels but decoded to {array.size} samples"
        )
    return array, descriptor


def write_audio(
    samples: npt.NDArray[np.int16],
    path: str | os.PathLike[str],
    sample_rate: int,
    *,
    overwrite: bool = False,
) -> None:
    """Write *samples* as a 16-bit PCM WAV file, atomically.

    The file is built under a temporary name in the destination directory and then
    moved into place, so an interrupted write cannot leave a truncated WAV that a
    receiver would later try to verify. The container and subtype are passed
    explicitly rather than inferred from the extension, both because the temporary
    name is not a plain ``.wav`` and because inferring the format from a path is exactly the
    mistake the image layer avoids.
    """
    array = np.ascontiguousarray(samples, dtype=np.int16)
    paths.check_output_writable(path, overwrite)

    with file_utils.atomic_output(path) as temporary:
        sf.write(
            temporary,
            array,
            int(sample_rate),
            format=SUPPORTED_FORMAT,
            subtype=SUPPORTED_SUBTYPE,
        )


# --------------------------------------------------------------------------- #
# Sample stream
# --------------------------------------------------------------------------- #


def embeddable_stream(
    samples: npt.NDArray[np.int16],
) -> tuple[npt.NDArray[np.uint16], int]:
    """Return a flat unsigned view of the embeddable samples, and the channel count.

    Traversal order is the interleaved scalar order the file already stores:
    ``L0, R0, L1, R1, ...`` for stereo. Every channel carries payload bits; unlike
    an image's alpha channel there is nothing to exclude.

    The returned array is ``uint16``, obtained by **reinterpreting** the int16 bit
    pattern rather than converting it, so the shared bit helpers can operate on it.
    See the module docstring for why a view and not a cast.
    """
    flat = np.ascontiguousarray(samples, dtype=np.int16).reshape(-1)
    channels = 1 if samples.ndim == 1 else int(samples.shape[1])
    return flat.view(np.uint16), channels


def _restore_shape(
    flat: npt.NDArray[np.uint16], original: npt.NDArray[np.int16]
) -> npt.NDArray[np.int16]:
    """Reinterpret a flat unsigned array back to the original signed shape."""
    return np.ascontiguousarray(flat, dtype=np.uint16).view(np.int16).reshape(
        original.shape
    )


def measure_capacity(
    path: str | os.PathLike[str],
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
) -> tuple[CapacityReport, AudioDescriptor]:
    """Measure the capacity of a WAV file without embedding anything.

    An insufficient capacity is reported in the result rather than raised, so a
    GUI can display it while the user is still adjusting settings.
    """
    depth = validate_lsb_depth(lsb_count)
    descriptor = describe_only(path)
    report = capacity_report(
        descriptor.total_samples,
        depth,
        start_location,
        payload_length,
        embeddable_channels=descriptor.channel_count,
    )
    return report, descriptor


def embed_audio(
    input_path: str,
    output_path: str,
    payload: bytes,
    lsb_count: int,
    start_location: int,
    *,
    overwrite: bool = False,
) -> AudioEmbedResult:
    """Embed *payload* into the WAV cover at *input_path*.

    Validation runs in a fixed order — input existence, input readability, output
    path distinct from input, output writability, payload type, LSB depth, start
    location, capacity — and nothing is written until every check has passed.

    :raises FileError: missing or unreadable input, unwritable or occupied output.
    :raises DecodeError: not a 16-bit PCM WAV file.
    :raises ValidationError: bad payload type, depth, start location, or an output
        path equal to the input path.
    :raises CapacityError: the payload does not fit from *start_location*.
    """
    paths.assert_readable(input_path)
    paths.assert_distinct_paths(input_path, output_path)
    paths.check_output_writable(output_path, overwrite)
    data = lsb_core.validate_payload(payload)
    depth = validate_lsb_depth(lsb_count)

    samples, descriptor = read_audio(input_path)
    flat, channels = embeddable_stream(samples)
    total = int(flat.size)
    start = lsb_core.validate_start_location(start_location, total, "audio file")

    stego_flat, stream = lsb_core.embed_stream(flat, data, depth, start, _WIDTH)
    write_audio(
        _restore_shape(stego_flat, samples),
        output_path,
        descriptor.sample_rate,
        overwrite=overwrite,
    )

    return AudioEmbedResult(
        output_path=os.fspath(output_path),
        container_format=descriptor.container_format,
        descriptor=descriptor,
        capacity=capacity_report(
            total, depth, start, len(data), embeddable_channels=channels
        ),
        lsb_count=depth,
        start_location=start,
        payload_length=len(data),
        encoded_length=stream.encoded_length,
        samples_written=stream.samples_needed,
    )


def extract_audio(
    input_path: str,
    lsb_count: int,
    start_location: int,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Extract an embedded payload from the stego WAV at *input_path*.

    :param manifest_payload_length: when supplied, the decoded header must agree
        with it; it is a cross-check, not an override.
    :raises ExtractionError: the decoded length is inconsistent with the file's
        capacity, the bit stream is truncated, or the manifest length disagrees.
        The message never asserts which cause applies, because they are
        indistinguishable.
    """
    paths.assert_readable(input_path)
    depth = validate_lsb_depth(lsb_count)

    samples, _ = read_audio(input_path)
    flat, _ = embeddable_stream(samples)
    total = int(flat.size)
    start = lsb_core.validate_start_location(start_location, total, "audio file")

    return lsb_core.extract_stream(
        lambda begin, end: flat[begin:end],
        total,
        depth,
        start,
        _WIDTH,
        "audio file",
        manifest_payload_length=manifest_payload_length,
    )
