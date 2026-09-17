"""LSB replacement embedding and extraction for video cover objects.

The third medium, built on the same primitives as :mod:`app.stego.image_stego` and
:mod:`app.stego.audio_stego`, with the same public signature shape::

    embed_video(input_path, output_path, payload, lsb_count, start_location)
    extract_video(input_path, lsb_count, start_location) -> bytes

One flat sample domain, not a frame-selection scheme
----------------------------------------------------
The obvious design for video is to pick a set of "carrier frames" and embed inside
them, keyed by something the receiver also knows. That was rejected, because it
would have needed the stego layer to know about keys and nonces — exactly the
boundary the image and audio layers keep — and it would have added new fields to
the manifest for something the existing machinery already does.

Instead a clip is treated as one continuous sample domain: every pixel of every
frame, in decode order, then row-major within each frame, then across the three
colour channels. That single change makes video fall out of the existing design
with no new concepts at all:

* ``total_samples`` is ``frame_count * height * width * 3``,
* ``start_location`` indexes that domain exactly as it indexes an image's pixels,
* the existing keyed derivation in :mod:`app.crypto.start_location` therefore
  already scatters the payload to an unpredictable frame *and* offset within it,
* and a payload longer than one frame simply runs on into the next.

So "which frames carry the payload" is decided by the same secret that decides
where in an image the payload starts, and no separate mechanism was needed.

Losslessness is the whole problem
---------------------------------
LSB replacement survives only if every pixel is preserved bit for bit, and almost
every video codec in common use is lossy. Output is therefore always **FFV1 in a
Matroska container**, regardless of what the cover was: FFV1 is mathematically
lossless and is present in the FFmpeg build that ships with ``opencv-python``, so
no external binary is required.

The cover's own codec does not have to be lossless — its frames are decoded to
pixels either way — but two container-level properties do have to survive, and
they are checked rather than assumed:

*Frame count.* The sample domain is measured in frames, so the sender and the
receiver must count the same number. Containers routinely report a frame count
that differs from what actually decodes, so :func:`embed_video` counts the frames
it really reads and refuses to continue if the container lied.

*The written file.* A codec that quietly re-quantised the pixels would produce a
file that looks fine and verifies as ``PAYLOAD_MISSING`` later, with nothing to
point at. Rather than trust the codec, :func:`embed_video` reads its own output
back and confirms the payload extracts identically before the file is moved into
place. That costs an extra decode pass; silent corruption of a demonstration
artefact costs more.

Memory
------
Frames are streamed one at a time in both directions, so a clip is never fully
resident. A ten-second 1080p clip is around 1.8 GB of raw samples, which is why
holding the whole decoded array — the simplest implementation — was not an option.

Security boundary
-----------------
As with the other two media, this module carries opaque bytes. No hashing,
signing, verification or encryption, no key material, and no verdict. The 4-byte
length header is unauthenticated, and an extraction failure does not identify its
cause. Never treat a returned byte sequence as verified.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Any, Final, Iterator

import numpy as np
import numpy.typing as npt

from app.stego import paths
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
    capacity_report,
)
from app.stego.errors import (
    CapacityError,
    DecodeError,
    ExtractionError,
    ValidationError,
    safe_path,
)
from app.utils import constants, media_utils

__all__ = [
    "LENGTH_HEADER_BITS",
    "OUTPUT_CODEC",
    "OUTPUT_CONTAINER",
    "VIDEO_CHANNEL_COUNT",
    "VIDEO_SAMPLE_WIDTH_BITS",
    "VideoDescriptor",
    "VideoEmbedResult",
    "describe_only",
    "embed_video",
    "extract_video",
    "iterate_frames",
    "measure_capacity",
    "read_sample_range",
    "write_frames",
]

#: Decoded frames are 8-bit BGR, as they are for an image.
VIDEO_SAMPLE_WIDTH_BITS: Final[int] = 8

#: OpenCV always hands back three colour channels, even for a greyscale source, so
#: the sample count per frame is fixed rather than codec-dependent.
VIDEO_CHANNEL_COUNT: Final[int] = 3

LENGTH_HEADER_BITS: Final[int] = LENGTH_HEADER_BYTES * 8

#: FFV1 is lossless and available in the FFmpeg build bundled with
#: ``opencv-python``, so no external encoder has to be installed.
OUTPUT_CODEC: Final[str] = "FFV1"
OUTPUT_CONTAINER: Final[str] = constants.CONTAINER_MKV

#: Used when a container reports no frame rate at all. The value has no effect on
#: the payload; it only stops the output from having a nonsensical rate.
FALLBACK_FRAME_RATE: Final[float] = 25.0


# --------------------------------------------------------------------------- #
# Descriptors
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VideoDescriptor:
    """What can be said about a video file once its container is read."""

    file_name: str
    container_format: str
    codec: str
    width: int
    height: int
    frame_count: int
    frame_rate: float
    channel_count: int
    #: Scalar samples across the whole clip:
    #: ``frame_count * height * width * channel_count``. This is the domain a
    #: start location indexes.
    total_samples: int
    duration_seconds: float

    @property
    def samples_per_frame(self) -> int:
        return self.height * self.width * self.channel_count

    @property
    def resolution(self) -> str:
        return f"{self.width}x{self.height}"


@dataclass(frozen=True)
class VideoEmbedResult:
    """What an embedding produced.

    Field for field the same as :class:`app.stego.audio_stego.AudioEmbedResult`
    where the concepts coincide, so :mod:`app.stego.media` needs no special case.
    """

    output_path: str
    container_format: str
    descriptor: VideoDescriptor
    capacity: CapacityReport
    lsb_count: int
    start_location: int
    payload_length: int
    encoded_length: int
    samples_written: int
    #: How many frames the payload actually touched. Reported because it is the
    #: figure that makes the flat-domain design concrete for a reader.
    frames_touched: int
    first_frame_touched: int
    last_frame_touched: int


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


def describe_only(path: str | os.PathLike[str]) -> VideoDescriptor:
    """Describe a video file without decoding every frame.

    Reads container-level properties only, so a capacity query on a large clip
    does not have to decode it.

    :raises DecodeError: the file cannot be opened as video, or reports no
        decodable frames.
    """
    paths.assert_readable(path)
    try:
        properties = media_utils.read_video_properties(path)
    except media_utils.VideoInspectionError as exc:
        raise DecodeError(str(exc)) from exc

    from app.utils import file_utils

    try:
        container = file_utils.detect_container(path)
    except file_utils.UnsupportedMediaError as exc:
        raise DecodeError(str(exc)) from exc

    frame_rate = (
        properties.frame_rate if properties.frame_rate > 0 else FALLBACK_FRAME_RATE
    )
    samples = (
        properties.frame_count
        * properties.height
        * properties.width
        * VIDEO_CHANNEL_COUNT
    )
    return VideoDescriptor(
        file_name=safe_path(path),
        container_format=container,
        codec=properties.codec,
        width=properties.width,
        height=properties.height,
        frame_count=properties.frame_count,
        frame_rate=frame_rate,
        channel_count=VIDEO_CHANNEL_COUNT,
        total_samples=samples,
        duration_seconds=properties.duration_seconds,
    )


def iterate_frames(
    path: str | os.PathLike[str], descriptor: VideoDescriptor | None = None
) -> Iterator[npt.NDArray[np.uint8]]:
    """Yield each decoded frame of *path* in order, as a writable ``uint8`` array.

    Frames are yielded one at a time rather than collected, which is what keeps a
    long clip from having to be fully resident. When *descriptor* is supplied each
    frame's shape is checked against it, because a mid-clip resolution change would
    silently shift every subsequent sample index.

    :raises DecodeError: the clip cannot be opened, or a frame's shape disagrees
        with the descriptor.
    """
    import cv2

    target = os.fspath(path)
    name = safe_path(path)

    capture = cv2.VideoCapture(target)
    try:
        if not capture.isOpened():
            raise DecodeError(f"{name} could not be opened as a video file")
        index = 0
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            array = np.ascontiguousarray(frame, dtype=np.uint8)
            if descriptor is not None:
                expected = (descriptor.height, descriptor.width, VIDEO_CHANNEL_COUNT)
                if array.shape != expected:
                    raise DecodeError(
                        f"{name} frame {index} decoded to shape {array.shape} but the "
                        f"container declares {expected}; a clip whose frame size "
                        f"changes partway through cannot be used as a cover object"
                    )
            yield array
            index += 1
    finally:
        capture.release()


def read_sample_range(
    path: str | os.PathLike[str],
    descriptor: VideoDescriptor,
    begin: int,
    end: int,
) -> npt.NDArray[np.uint8]:
    """Return the flat samples of *path* in ``[begin, end)``.

    Streams frames and copies only the part of each that falls inside the range, so
    reading a payload out of a long clip costs one decode pass and a buffer the
    size of the payload region rather than the size of the clip.

    :raises ExtractionError: the clip ran out of frames before the range was
        filled, which is what a truncated or re-encoded file looks like here.
    """
    if begin < 0 or end < begin:
        raise ValidationError(
            f"sample range must satisfy 0 <= begin <= end, got [{begin}, {end})"
        )
    if end == begin:
        return np.empty(0, dtype=np.uint8)

    per_frame = descriptor.samples_per_frame
    collected = np.empty(end - begin, dtype=np.uint8)
    filled = 0

    for index, frame in enumerate(iterate_frames(path, descriptor)):
        base = index * per_frame
        if base >= end:
            break
        low = max(begin, base)
        high = min(end, base + per_frame)
        if low < high:
            collected[low - begin : high - begin] = frame.reshape(-1)[
                low - base : high - base
            ]
            filled += high - low

    if filled != end - begin:
        raise ExtractionError(
            f"bit stream is truncated: samples {begin} to {end} were requested from "
            f"{descriptor.file_name} but only {filled} of {end - begin} could be "
            f"decoded; the clip is shorter than its container declares"
        )
    return collected


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def _open_writer(target: str, descriptor: VideoDescriptor, codec: str) -> Any:
    import cv2

    writer = cv2.VideoWriter(
        target,
        cv2.VideoWriter_fourcc(*codec),
        float(descriptor.frame_rate),
        (descriptor.width, descriptor.height),
    )
    if not writer.isOpened():
        writer.release()
        raise DecodeError(
            f"the installed OpenCV build could not open a {codec} encoder for "
            f"{descriptor.width}x{descriptor.height} video. {OUTPUT_CODEC} in a "
            f"{OUTPUT_CONTAINER} container is the only lossless output this "
            f"application writes, and LSB data cannot survive a lossy codec"
        )
    return writer


def write_frames(
    frames: Iterator[npt.NDArray[np.uint8]],
    path: str | os.PathLike[str],
    descriptor: VideoDescriptor,
    *,
    overwrite: bool = False,
    codec: str = OUTPUT_CODEC,
) -> int:
    """Write *frames* to *path* as a lossless clip, atomically. Returns the count.

    Built under a temporary name in the destination directory and moved into place,
    so an interrupted write cannot leave a truncated clip that a receiver would
    later try to verify. The temporary name keeps a ``.mkv`` suffix because OpenCV
    selects the container from the path's extension.
    """
    paths.check_output_writable(path, overwrite)

    target = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(target)) or "."
    handle, temporary = tempfile.mkstemp(
        prefix=".partial-", suffix=constants.CONTAINER_EXTENSIONS[OUTPUT_CONTAINER],
        dir=directory,
    )
    os.close(handle)

    try:
        writer = _open_writer(temporary, descriptor, codec)
        written = 0
        try:
            for frame in frames:
                writer.write(frame)
                written += 1
        finally:
            writer.release()

        if written == 0:
            raise DecodeError(
                f"no frames were written for {safe_path(target)}; the cover clip "
                f"decoded to nothing"
            )
        os.replace(temporary, target)
        return written
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# Capacity
# --------------------------------------------------------------------------- #


def measure_capacity(
    path: str | os.PathLike[str],
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
) -> tuple[CapacityReport, VideoDescriptor]:
    """Measure the capacity of a video file without embedding anything.

    An insufficient capacity is reported in the result rather than raised, so a GUI
    can display it while the user is still adjusting settings.
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


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def _validate_payload(payload: object) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise ValidationError(
            f"payload must be bytes or bytearray, got type {type(payload).__name__}"
        )
    data = bytes(payload)
    if len(data) > MAX_PAYLOAD_LENGTH:
        raise ValidationError(
            f"payload is {len(data)} bytes, which cannot be represented in the "
            f"{LENGTH_HEADER_BYTES}-byte length header (maximum "
            f"{MAX_PAYLOAD_LENGTH})"
        )
    return data


def _validate_start_location(start_location: object, total_samples: int) -> int:
    """Same rules as the other two media: integers only, ``bool`` refused."""
    if isinstance(start_location, bool) or not isinstance(
        start_location, (int, np.integer)
    ):
        raise ValidationError(
            f"start_location must be an integer, got type "
            f"{type(start_location).__name__}"
        )
    value = int(start_location)
    if total_samples == 0:
        raise CapacityError("video file has no embeddable samples")
    if not 0 <= value < total_samples:
        raise ValidationError(
            f"start_location must be an integer from 0 to {total_samples - 1} "
            f"inclusive, got {value}"
        )
    return value


# --------------------------------------------------------------------------- #
# Embedding
# --------------------------------------------------------------------------- #


def _embedding_frames(
    input_path: str,
    descriptor: VideoDescriptor,
    groups: npt.NDArray[np.uint16],
    depth: int,
    start: int,
    counters: dict[str, int],
) -> Iterator[npt.NDArray[np.uint8]]:
    """Yield every frame of the cover, with the payload written into the region.

    A generator rather than a list so that :func:`write_frames` consumes frames as
    they are decoded and the clip is never fully resident. *counters* is filled in
    as a side effect, because a generator cannot return values to its consumer.
    """
    per_frame = descriptor.samples_per_frame
    end = start + int(groups.size)
    decoded = 0
    touched = 0
    first = -1
    last = -1

    for index, frame in enumerate(iterate_frames(input_path, descriptor)):
        decoded += 1
        base = index * per_frame
        low = max(start, base)
        high = min(end, base + per_frame)
        if low < high:
            flat = frame.reshape(-1)
            flat[low - base : high - base] = write_low_bits(
                flat[low - base : high - base],
                groups[low - start : high - start],
                depth,
                VIDEO_SAMPLE_WIDTH_BITS,
            )
            touched += 1
            if first < 0:
                first = index
            last = index
        yield frame

    counters["frames_decoded"] = decoded
    counters["frames_touched"] = touched
    counters["first_frame_touched"] = first
    counters["last_frame_touched"] = last


def embed_video(
    input_path: str,
    output_path: str,
    payload: bytes,
    lsb_count: int,
    start_location: int,
    *,
    overwrite: bool = False,
    verify_round_trip: bool = True,
) -> VideoEmbedResult:
    """Embed *payload* into the video cover at *input_path*.

    The encoded stream is a 4-byte big-endian payload length followed by the
    payload bytes, written most-significant-bit first into the ``lsb_count``
    lowest-order bits of consecutive samples of the flat frame domain from
    *start_location*, crossing frame boundaries where it has to and never wrapping.

    The output is always ``FFV1`` in a ``.mkv`` container, whatever the cover was,
    because nothing lossy can carry LSB data.

    :param verify_round_trip: read the written file back and confirm the payload
        extracts identically before the file is moved into place. On by default:
        a codec that silently re-quantised would otherwise produce an artefact that
        only fails much later, at verification, with nothing to point at. Set
        ``False`` only when the extra decode pass is genuinely too expensive.
    :raises FileError: missing or unreadable input, unwritable or occupied output.
    :raises DecodeError: not a decodable video file, or the container's frame count
        disagrees with what actually decodes, or the round-trip check failed.
    :raises ValidationError: bad payload type, depth, start location, or an output
        path equal to the input path.
    :raises CapacityError: the payload does not fit from *start_location*.
    """
    paths.assert_readable(input_path)
    paths.assert_distinct_paths(input_path, output_path)
    paths.check_output_writable(output_path, overwrite)
    data = _validate_payload(payload)
    depth = validate_lsb_depth(lsb_count)

    descriptor = describe_only(input_path)
    total_samples = descriptor.total_samples
    start = _validate_start_location(start_location, total_samples)

    encoded = len(data).to_bytes(LENGTH_HEADER_BYTES, "big") + data
    bits = bytes_to_bits(encoded)
    group_count = groups_needed(int(bits.size), depth)

    report = capacity_report(
        total_samples,
        depth,
        start,
        len(data),
        embeddable_channels=descriptor.channel_count,
    )

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
    counters: dict[str, int] = {}
    written_frames = write_frames(
        _embedding_frames(
            os.fspath(input_path), descriptor, groups, depth, start, counters
        ),
        output_path,
        descriptor,
        overwrite=overwrite,
    )

    # The sample domain is measured in frames, so a container that over- or
    # under-reports its frame count would make the sender and the receiver measure
    # different domains and derive different start locations — silently. Checked
    # rather than trusted.
    decoded = counters.get("frames_decoded", 0)
    if decoded != descriptor.frame_count:
        _discard(output_path)
        raise DecodeError(
            f"{descriptor.file_name} declares {descriptor.frame_count} frames but "
            f"{decoded} actually decoded. The sample domain is measured in frames, "
            f"so a receiver would measure a different domain and look in the wrong "
            f"place. Re-encode the cover losslessly "
            f"({OUTPUT_CODEC} in {OUTPUT_CONTAINER}) and try again"
        )

    if verify_round_trip:
        _assert_round_trip(
            output_path, depth, start, encoded, written_frames, descriptor
        )

    return VideoEmbedResult(
        output_path=os.fspath(output_path),
        container_format=OUTPUT_CONTAINER,
        descriptor=descriptor,
        capacity=report,
        lsb_count=depth,
        start_location=start,
        payload_length=len(data),
        encoded_length=len(encoded),
        samples_written=group_count,
        frames_touched=counters.get("frames_touched", 0),
        first_frame_touched=counters.get("first_frame_touched", -1),
        last_frame_touched=counters.get("last_frame_touched", -1),
    )


def _discard(path: str | os.PathLike[str]) -> None:
    """Remove a written output that turned out to be unusable."""
    try:
        os.unlink(os.fspath(path))
    except OSError:
        pass


def _assert_round_trip(
    output_path: str | os.PathLike[str],
    depth: int,
    start: int,
    encoded: bytes,
    written_frames: int,
    cover: VideoDescriptor,
) -> None:
    """Confirm the written clip gives the payload back byte for byte.

    Everything this checks is something a codec or container can get wrong without
    raising: quantising the pixels, dropping a frame, or reporting a frame count
    that no longer matches. Each of those would produce a file that verifies as
    ``PAYLOAD_MISSING`` later with no way to tell why, so the failure is moved
    here, where it can name the cause.
    """
    try:
        written = describe_only(output_path)
    except DecodeError as exc:
        _discard(output_path)
        raise DecodeError(
            f"the clip that was written could not be read back: {exc}"
        ) from exc

    if written.frame_count != written_frames:
        _discard(output_path)
        raise DecodeError(
            f"the clip that was written reports {written.frame_count} frames but "
            f"{written_frames} were encoded, so a receiver would measure a "
            f"different sample domain"
        )
    if (written.width, written.height) != (cover.width, cover.height):
        _discard(output_path)
        raise DecodeError(
            f"the clip that was written is {written.resolution} but the cover was "
            f"{cover.resolution}; the encoder changed the frame size"
        )

    try:
        recovered = extract_video(
            os.fspath(output_path), depth, start, manifest_payload_length=None
        )
    except (DecodeError, ExtractionError) as exc:
        _discard(output_path)
        raise DecodeError(
            f"the payload could not be read back out of the clip that was just "
            f"written: {exc}. The encoder did not preserve the pixels exactly"
        ) from exc

    expected = encoded[LENGTH_HEADER_BYTES:]
    if recovered != expected:
        _discard(output_path)
        differing = sum(1 for a, b in zip(recovered, expected) if a != b)
        raise DecodeError(
            f"the payload read back out of the clip that was just written differs "
            f"from what was embedded ({len(recovered)} of {len(expected)} bytes "
            f"recovered, {differing} of the overlapping bytes wrong). The "
            f"{OUTPUT_CODEC} encoder did not preserve the pixels exactly, so LSB "
            f"data cannot survive in this build"
        )


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def extract_video(
    input_path: str,
    lsb_count: int,
    start_location: int,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Extract an embedded payload from the stego clip at *input_path*.

    Reads in two stages, as the other two media do: only the samples needed for the
    32-bit length header first, then a bounds check on the decoded length *before*
    any payload buffer is sized, so a corrupt or crafted header cannot request a
    huge allocation.

    Each stage is one decode pass, so extraction decodes the clip twice. Seeking to
    the second range instead would be faster but is not reliable across containers,
    and a wrong seek here would be indistinguishable from a missing payload.

    :param manifest_payload_length: when supplied, the decoded header must agree
        with it. The header still determines how many bytes are read; the manifest
        value is a cross-check, not an override.
    :raises ExtractionError: the decoded length is inconsistent with the clip's
        capacity, the stream is truncated, or the manifest length disagrees. The
        message never asserts which cause applies, because they are
        indistinguishable.
    """
    paths.assert_readable(input_path)
    depth = validate_lsb_depth(lsb_count)

    descriptor = describe_only(input_path)
    total_samples = descriptor.total_samples
    start = _validate_start_location(start_location, total_samples)

    available = total_samples - start
    header_groups = groups_needed(LENGTH_HEADER_BITS, depth)
    if available < header_groups:
        raise ExtractionError(
            f"bit stream is truncated: reading a {LENGTH_HEADER_BITS}-bit length "
            f"header at depth {depth} needs {header_groups} samples from start "
            f"location {start}, but only {available} are available"
        )

    header_samples = read_sample_range(
        input_path, descriptor, start, start + header_groups
    )
    header_bits = unpack_groups_to_bits(
        read_low_bits(header_samples, depth, VIDEO_SAMPLE_WIDTH_BITS), depth
    )
    payload_length = int.from_bytes(
        bits_to_bytes(header_bits[:LENGTH_HEADER_BITS]), "big"
    )

    available_capacity = (available * depth) // 8
    max_payload = max(0, available_capacity - LENGTH_HEADER_BYTES)
    if payload_length > max_payload:
        raise ExtractionError(
            f"decoded payload length {payload_length} is inconsistent with the "
            f"video capacity: at depth {depth} from start location {start} the clip "
            f"can hold at most {max_payload} payload bytes"
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

    stream_samples = read_sample_range(
        input_path, descriptor, start, start + needed_groups
    )
    stream_bits = unpack_groups_to_bits(
        read_low_bits(stream_samples, depth, VIDEO_SAMPLE_WIDTH_BITS), depth
    )
    # Continuous stream: payload bits follow the header with no realignment, and
    # trailing padding bits beyond the payload are discarded.
    return bits_to_bytes(stream_bits[LENGTH_HEADER_BITS:total_bits])
