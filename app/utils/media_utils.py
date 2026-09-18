"""Media property inspection that the steganography layers do not already provide.

The image and audio layers each return a rich descriptor of their own
(``ImageDescriptor``, ``AudioDescriptor``), so nothing here duplicates those.
What is missing is video: no other module can report a clip's resolution, frame
rate, frame count or codec, and both the media comparison table and the video
steganography layer need those figures.

OpenCV is imported lazily rather than at module import time. It is a large native
extension, and importing it costs a noticeable fraction of a second; the image and
audio paths never need it, and neither does the test suite for those paths.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from app.utils import file_utils

__all__ = [
    "VideoProperties",
    "fourcc_to_codec",
    "read_video_properties",
]


class VideoInspectionError(Exception):
    """A video file that cannot be opened or described."""


@dataclass(frozen=True)
class VideoProperties:
    """What can be read from a video container without decoding every frame."""

    file_name: str
    width: int
    height: int
    frame_count: int
    frame_rate: float
    codec: str
    duration_seconds: float

    @property
    def resolution(self) -> str:
        return f"{self.width}x{self.height}"


def fourcc_to_codec(fourcc: int) -> str:
    """Convert OpenCV's numeric FourCC to its four-character name.

    OpenCV reports the codec as a 32-bit integer holding four ASCII characters,
    little end first. A container that reports nothing yields 0, which becomes an
    empty string rather than four NUL characters.
    """
    if not fourcc:
        return "unknown"
    characters = [chr((int(fourcc) >> shift) & 0xFF) for shift in (0, 8, 16, 24)]
    name = "".join(characters).strip("\x00 ")
    return name or "unknown"


def read_video_properties(path: str | os.PathLike[str]) -> VideoProperties:
    """Read the container-level properties of the video at *path*.

    :raises VideoInspectionError: the file cannot be opened as video, or reports a
        zero frame count, which means OpenCV could not decode the stream even
        though it opened the container.
    """
    import cv2  # imported lazily; see the module docstring

    target = os.fspath(path)
    name = file_utils.display_name(target)

    if not os.path.isfile(target):
        raise VideoInspectionError(f"video file not found: {name}")

    capture = cv2.VideoCapture(target)
    try:
        if not capture.isOpened():
            raise VideoInspectionError(
                f"{name} could not be opened as a video file. The container may be "
                f"unsupported by the installed OpenCV build"
            )

        width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT))
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_rate = float(capture.get(cv2.CAP_PROP_FPS))
        codec = fourcc_to_codec(int(capture.get(cv2.CAP_PROP_FOURCC)))
    finally:
        capture.release()

    if width <= 0 or height <= 0 or frame_count <= 0:
        raise VideoInspectionError(
            f"{name} opened but reported no decodable frames "
            f"({width}x{height}, {frame_count} frames). The codec may not be "
            f"supported by the installed OpenCV build"
        )

    return VideoProperties(
        file_name=name,
        width=width,
        height=height,
        frame_count=frame_count,
        frame_rate=frame_rate,
        codec=codec,
        duration_seconds=(frame_count / frame_rate) if frame_rate > 0 else 0.0,
    )
