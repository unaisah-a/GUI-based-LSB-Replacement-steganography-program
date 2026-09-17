"""One interface over every steganography medium.

Callers above this line — the verifier, the attack simulator, the GUI — should not
branch on media type. They hand a path to :func:`measure`, :func:`embed` or
:func:`extract` and get back the same shapes regardless of whether the cover is a
PNG, a WAV or a video. Dispatch happens here, once, based on the file's *content*
rather than its extension.

What this facade normalises
---------------------------
Each medium's own module keeps its natural result types, because each has genuine
extras worth reporting — an image has pixel dimensions, audio has a sample rate.
This module maps the parts they share onto :class:`UnifiedCapacity` and
:class:`UnifiedEmbedResult`, and keeps the medium-specific descriptor available on
those results for a caller that wants it.

The underlying layers were made uniform in their own right rather than papered
over here: both now take the same positional arguments, use the same encoded
stream, index the same flattened sample domain, and raise from the same error
hierarchy. This module is therefore thin, which is the point — a thick adapter
would have been a sign the layers still disagreed.

Video
-----
Video needed no special case here, which was the test of the design. Because
:mod:`app.stego.video_stego` treats a clip as one flat sample domain — every pixel
of every frame in decode order — its measure, embed and extract functions have the
same shapes as the other two, and registering it was a three-line change to
:data:`_HANDLERS`.

The one thing callers should know is that video embedding always *re-encodes*: the
output is FFV1 in a Matroska container whatever the cover was, because no lossy
codec can carry LSB data. So unlike an image or a WAV, a stego clip is not a
byte-level near-copy of its cover, and comparing the two file sizes is not
meaningful.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Final

from app.stego import audio_stego, image_stego, video_stego
from app.stego.capacity import CapacityReport
from app.stego.errors import DecodeError
from app.utils import constants, file_utils

__all__ = [
    "SUPPORTED_MEDIA_TYPES",
    "UnifiedCapacity",
    "UnifiedEmbedResult",
    "describe",
    "detect_media_type",
    "embed",
    "extract",
    "measure",
    "supports",
]


# --------------------------------------------------------------------------- #
# Unified results
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class UnifiedCapacity:
    """A capacity measurement, in terms every medium shares."""

    media_type: str
    container_format: str
    report: CapacityReport
    #: The medium's own descriptor: an ``ImageDescriptor`` or an
    #: ``AudioDescriptor``. Available for callers that want the extras.
    descriptor: Any

    @property
    def total_samples(self) -> int:
        """Embeddable samples in the whole medium.

        This is the domain a start location indexes, and the value
        :func:`app.crypto.start_location.derive_start_location` needs.
        """
        return self.report.total_embeddable_samples

    @property
    def available_capacity_bytes(self) -> int:
        return self.report.available_capacity_bytes

    @property
    def max_payload_length(self) -> int:
        return self.report.max_payload_length

    @property
    def payload_fits(self) -> bool:
        return self.report.payload_fits


@dataclass(frozen=True)
class UnifiedEmbedResult:
    """The outcome of an embedding, in terms every medium shares."""

    media_type: str
    container_format: str
    output_path: str
    report: CapacityReport
    lsb_count: int
    start_location: int
    payload_length: int
    encoded_length: int
    samples_written: int
    descriptor: Any

    @property
    def total_samples(self) -> int:
        return self.report.total_embeddable_samples


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Handler:
    """How to drive one medium."""

    measure: Callable[..., tuple[CapacityReport, Any]]
    embed: Callable[..., Any]
    extract: Callable[..., bytes]


_HANDLERS: Final[dict[str, _Handler]] = {
    constants.MEDIA_IMAGE: _Handler(
        measure=image_stego.measure_capacity,
        embed=image_stego.embed_image,
        extract=image_stego.extract_image,
    ),
    constants.MEDIA_AUDIO: _Handler(
        measure=audio_stego.measure_capacity,
        embed=audio_stego.embed_audio,
        extract=audio_stego.extract_audio,
    ),
    constants.MEDIA_VIDEO: _Handler(
        measure=video_stego.measure_capacity,
        embed=video_stego.embed_video,
        extract=video_stego.extract_video,
    ),
}

SUPPORTED_MEDIA_TYPES: Final[tuple[str, ...]] = tuple(_HANDLERS)


def supports(media_type: str) -> bool:
    """Return whether this build can carry a payload in *media_type*."""
    return media_type in _HANDLERS


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #


def detect_media_type(path: str | os.PathLike[str]) -> str:
    """Return the media type of *path*, detected from its content.

    Raises :class:`~app.stego.errors.DecodeError` rather than
    :class:`~app.utils.file_utils.UnsupportedMediaError`, so that a caller working
    with this layer can catch one error family. The original message, which names
    the detected format, is preserved.
    """
    try:
        return file_utils.detect_media_type(path)
    except file_utils.UnsupportedMediaError as exc:
        raise DecodeError(str(exc)) from exc


def describe(path: str | os.PathLike[str]) -> file_utils.MediaDescription:
    """Describe *path* without decoding its samples."""
    try:
        return file_utils.describe_file(path)
    except file_utils.UnsupportedMediaError as exc:
        raise DecodeError(str(exc)) from exc


def _handler_for(path: str | os.PathLike[str]) -> tuple[str, _Handler]:
    media_type = detect_media_type(path)
    handler = _HANDLERS.get(media_type)
    if handler is None:
        raise DecodeError(
            f"{file_utils.display_name(path)} is {media_type} media, which this "
            f"build cannot carry a payload in; supported media types are "
            f"{SUPPORTED_MEDIA_TYPES}"
        )
    return media_type, handler


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #


def measure(
    path: str | os.PathLike[str],
    lsb_count: int,
    start_location: int = 0,
    payload_length: int | None = None,
) -> UnifiedCapacity:
    """Measure the capacity of *path* without embedding anything.

    An insufficient capacity is reported in the result rather than raised, so the
    GUI can display it while the user is still adjusting settings.
    """
    media_type, handler = _handler_for(path)
    report, descriptor = handler.measure(
        path, lsb_count, start_location, payload_length
    )
    return UnifiedCapacity(
        media_type=media_type,
        container_format=descriptor.container_format,
        report=report,
        descriptor=descriptor,
    )


def embed(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    payload: bytes,
    lsb_count: int,
    start_location: int,
    *,
    overwrite: bool = False,
) -> UnifiedEmbedResult:
    """Embed *payload* into the cover at *input_path*, whatever medium it is.

    The positional arguments are the team's agreed shared interface, so this call
    reads the same as a direct call to either underlying layer.
    """
    media_type, handler = _handler_for(input_path)
    result = handler.embed(
        os.fspath(input_path),
        os.fspath(output_path),
        payload,
        lsb_count,
        start_location,
        overwrite=overwrite,
    )
    return UnifiedEmbedResult(
        media_type=media_type,
        container_format=result.container_format,
        output_path=result.output_path,
        report=result.capacity,
        lsb_count=result.lsb_count,
        start_location=result.start_location,
        payload_length=result.payload_length,
        encoded_length=result.encoded_length,
        samples_written=result.samples_written,
        descriptor=result.descriptor,
    )


def extract(
    input_path: str | os.PathLike[str],
    lsb_count: int,
    start_location: int,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    """Extract an embedded payload from *input_path*, whatever medium it is.

    The returned bytes are **not** verified. A mismatched depth or start location
    can decode a plausible length and return wrong bytes with no error at all;
    establishing that a payload is genuine is
    :mod:`app.verification.verifier`'s job.
    """
    _, handler = _handler_for(input_path)
    return handler.extract(
        os.fspath(input_path),
        lsb_count,
        start_location,
        manifest_payload_length=manifest_payload_length,
    )
