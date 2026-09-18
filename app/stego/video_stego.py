"""LSB replacement embedding and extraction for video cover objects.

Same public signature shape as the image and audio layers::

    embed_video(input_path, output_path, payload, lsb_count, start_location)
    extract_video(input_path, lsb_count, start_location) -> bytes

A clip is one flat sample domain: every channel value of every frame, in decode
order, then row-major within a frame, then across the three colour channels. A start
location indexes that domain exactly as it indexes an image, so the keyed
start-location derivation already places the payload at an unpredictable frame and
offset, and a payload longer than one frame runs on into the next.

Output is always FFV1 in Matroska, because only a lossless codec preserves LSB data.
Frames are streamed one at a time in both directions. :func:`embed_video` counts the
frames it actually decodes rather than trusting the container, and reads its own
output back to confirm the payload survives before moving the file into place. The
reasoning behind each of these is in ``docs/architecture.md`` section 3.

This module carries opaque bytes and returns no verdict. Never treat a returned byte
sequence as verified.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final, Iterator

import numpy as np
import numpy.typing as npt

from app.stego import lsb_core, paths
from app.stego.bit_utils import validate_lsb_depth, write_low_bits
from app.stego.capacity import CapacityReport, capacity_report
from app.stego.errors import DecodeError, ExtractionError, ValidationError
from app.utils import constants, file_utils, media_utils
from app.utils.file_utils import display_name

__all__ = [
    "OUTPUT_CODEC",
    "OUTPUT_CONTAINER",
    "VIDEO_CHANNEL_COUNT",
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

#: OpenCV always hands back three colour channels, even for a greyscale source, so
#: the sample count per frame is fixed rather than codec-dependent.
VIDEO_CHANNEL_COUNT: Final[int] = 3

_WIDTH = constants.VIDEO_SAMPLE_WIDTH_BITS

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
        file_name=display_name(path),
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
    name = display_name(path)

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

    suffix = constants.CONTAINER_EXTENSIONS[OUTPUT_CONTAINER]
    with file_utils.atomic_output(path, suffix=suffix) as temporary:
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
                f"no frames were written for {display_name(path)}; the cover clip "
                f"decoded to nothing"
            )
    return written


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
                _WIDTH,
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
    data = lsb_core.validate_payload(payload)
    depth = validate_lsb_depth(lsb_count)

    descriptor = describe_only(input_path)
    total_samples = descriptor.total_samples
    start = lsb_core.validate_start_location(
        start_location, total_samples, "video file"
    )
    stream = lsb_core.encode_stream(data, depth, total_samples, start)

    counters: dict[str, int] = {}
    written_frames = write_frames(
        _embedding_frames(
            os.fspath(input_path), descriptor, stream.groups, depth, start, counters
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
            output_path, depth, start, data, written_frames, descriptor
        )

    return VideoEmbedResult(
        output_path=os.fspath(output_path),
        container_format=OUTPUT_CONTAINER,
        descriptor=descriptor,
        capacity=capacity_report(
            total_samples,
            depth,
            start,
            len(data),
            embeddable_channels=descriptor.channel_count,
        ),
        lsb_count=depth,
        start_location=start,
        payload_length=len(data),
        encoded_length=stream.encoded_length,
        samples_written=stream.samples_needed,
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
    expected: bytes,
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
    start = lsb_core.validate_start_location(
        start_location, total_samples, "video file"
    )

    return lsb_core.extract_stream(
        lambda begin, end: read_sample_range(input_path, descriptor, begin, end),
        total_samples,
        depth,
        start,
        _WIDTH,
        "video file",
        manifest_payload_length=manifest_payload_length,
    )
