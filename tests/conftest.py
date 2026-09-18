"""Shared fixtures, strategies and helpers for the image steganography tests.

Requirement 15 fixes the generation bounds: images from 1x1 to 64x64, channel
counts of 1, 3 or 4, and payloads of 0 to 256 bytes. Those bounds keep the
property suite inside the 120-second budget of Requirement 15.10; a single
megapixel example would consume most of it on its own.

The central design choice here is :func:`embedding_case`. A naive strategy would
draw a payload length and a start location independently and then discard the
combinations that do not fit, but Hypothesis raises a ``filter_too_much`` health
check when most draws are rejected, and the vast majority of independent draws do
not fit. This strategy instead **derives** each value from the ones already
drawn: the depth fixes a minimum image size, the image size fixes the payload
bound, and the payload length fixes the start-location bound. Nothing is ever
filtered, so every generated example is valid by construction.
"""

from __future__ import annotations

import math
import os
import tempfile
from dataclasses import dataclass

import numpy as np
import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st

# Qt must run without a display for the GUI tests to work on a build machine or over
# a remote session. Set before anything imports PySide6, because the platform plugin
# is chosen when the first QApplication is created and cannot be changed afterwards.
# `setdefault` so a developer can override it to watch the widgets appear.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from app.stego import image_io
from app.stego.capacity import LENGTH_HEADER_BYTES, embeddable_channel_count
from app.utils import logging_utils


@pytest.fixture(autouse=True, scope="session")
def _keep_test_logs_out_of_the_repository(tmp_path_factory):
    """Point any file logging a test sets up at a temporary directory.

    Only ``main()`` configures logging, so an ordinary test writes no log file at all.
    This covers the tests that configure it deliberately: none of them may append to
    ``evidence/logs/``, which is submission evidence, not a test artefact.
    """
    patch = pytest.MonkeyPatch()
    log_directory = tmp_path_factory.mktemp("logs")
    patch.setattr(logging_utils, "log_directory", lambda: log_directory)
    yield
    patch.undo()

# Requirement 15.10: at most 100 examples per property, no per-example deadline,
# and the whole property suite finishes within 120 seconds. The deadline is
# disabled rather than raised because PNG encoding time varies with content and a
# per-example limit would make the suite flaky on a loaded machine.
settings.register_profile(
    "image-stego",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "fast",
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "image-stego"))

MAX_DIMENSION = 64
MAX_PAYLOAD_BYTES = 256
CHANNEL_COUNTS = (1, 3, 4)


# --------------------------------------------------------------------------- #
# Cover generation
# --------------------------------------------------------------------------- #

#: Patterns rather than pure noise, because noise hides the ordering bugs that
#: structured content exposes: a transposed traversal order still round-trips on
#: noise but visibly corrupts a gradient.
PATTERNS = ("noise", "gradient", "flat", "stripes", "extremes")


def make_cover(
    height: int, width: int, channels: int, pattern: str = "noise", seed: int = 0
) -> np.ndarray:
    """Build a deterministic cover array of the requested shape and pattern."""
    rng = np.random.default_rng(seed)
    if pattern == "noise":
        base = rng.integers(0, 256, (height, width, channels), dtype=np.uint8)
    elif pattern == "gradient":
        row = np.linspace(0, 255, width, dtype=np.uint8)
        plane = np.tile(row, (height, 1))
        base = np.stack([plane] * channels, axis=2)
    elif pattern == "flat":
        value = int(rng.integers(0, 256))
        base = np.full((height, width, channels), value, dtype=np.uint8)
    elif pattern == "stripes":
        column = (np.arange(width) % 2 * 255).astype(np.uint8)
        plane = np.tile(column, (height, 1))
        base = np.stack([plane] * channels, axis=2)
    elif pattern == "extremes":
        # 0 and 255 exercise the clamping edges of every bit operation.
        base = rng.choice(
            np.array([0, 255], dtype=np.uint8), size=(height, width, channels)
        ).astype(np.uint8)
    else:  # pragma: no cover - guarded by the strategy
        raise ValueError(f"unknown pattern {pattern!r}")
    return np.ascontiguousarray(base, dtype=np.uint8)


def container_for(channels: int, preferred: str) -> str:
    """Return a container that can actually store *channels* channels.

    Grayscale BMP is excluded by design: the BMP format stores 8-bit grayscale as
    an indexed-colour palette image, which Requirement 1.6 requires this layer to
    reject on load, so writing one would produce a file it could not read back.
    """
    if channels == 1:
        return image_io.PNG
    return preferred


def write_cover(directory: str, array: np.ndarray, container: str, name: str) -> str:
    """Write *array* into *directory* and return the path."""
    suffix = ".png" if container == image_io.PNG else ".bmp"
    path = os.path.join(directory, f"{name}{suffix}")
    with open(path, "wb") as handle:
        handle.write(image_io.encode_image(array, container))
    return path


# --------------------------------------------------------------------------- #
# Embedding cases
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class EmbeddingCase:
    """A generated embedding scenario that is valid by construction."""

    height: int
    width: int
    channels: int
    container: str
    pattern: str
    seed: int
    lsb_count: int
    start_location: int
    payload: bytes

    @property
    def embeddable_channels(self) -> int:
        return embeddable_channel_count(self.channels)

    @property
    def total_samples(self) -> int:
        return self.height * self.width * self.embeddable_channels

    @property
    def encoded_length(self) -> int:
        return len(self.payload) + LENGTH_HEADER_BYTES

    @property
    def samples_needed(self) -> int:
        return math.ceil(self.encoded_length * 8 / self.lsb_count)

    def cover(self) -> np.ndarray:
        return make_cover(
            self.height, self.width, self.channels, self.pattern, self.seed
        )

    def write_cover(self, directory: str, name: str = "cover") -> str:
        return write_cover(directory, self.cover(), self.container, name)


def _minimum_height(width: int, embeddable_channels: int, lsb_count: int) -> int:
    """Smallest height whose sample count can hold a bare 4-byte length header.

    Derived rather than filtered. The header needs ``ceil(32 / lsb_count)``
    samples, which is at most 32, so this never exceeds 32 and therefore never
    exceeds the 64-pixel bound.
    """
    header_samples = math.ceil(LENGTH_HEADER_BYTES * 8 / lsb_count)
    return max(1, math.ceil(header_samples / (width * embeddable_channels)))


@st.composite
def embedding_case(
    draw,
    *,
    containers: tuple[str, ...] = (image_io.PNG, image_io.BMP),
    max_payload: int = MAX_PAYLOAD_BYTES,
) -> EmbeddingCase:
    """Generate an embedding scenario whose payload always fits.

    Each value is derived from the previous draws, so no example is ever
    filtered out.
    """
    channels = draw(st.sampled_from(CHANNEL_COUNTS))
    lsb_count = draw(st.integers(min_value=1, max_value=8))
    width = draw(st.integers(min_value=1, max_value=MAX_DIMENSION))

    embeddable = embeddable_channel_count(channels)
    lowest_height = _minimum_height(width, embeddable, lsb_count)
    height = draw(st.integers(min_value=lowest_height, max_value=MAX_DIMENSION))

    total_samples = height * width * embeddable
    capacity = (total_samples * lsb_count) // 8
    payload_ceiling = min(max_payload, max(0, capacity - LENGTH_HEADER_BYTES))
    payload_length = draw(st.integers(min_value=0, max_value=payload_ceiling))
    payload = draw(
        st.binary(min_size=payload_length, max_size=payload_length)
    )

    samples_needed = math.ceil((payload_length + LENGTH_HEADER_BYTES) * 8 / lsb_count)
    highest_start = total_samples - samples_needed
    start_location = draw(st.integers(min_value=0, max_value=max(0, highest_start)))

    return EmbeddingCase(
        height=height,
        width=width,
        channels=channels,
        container=container_for(channels, draw(st.sampled_from(containers))),
        pattern=draw(st.sampled_from(PATTERNS)),
        seed=draw(st.integers(min_value=0, max_value=2**32 - 1)),
        lsb_count=lsb_count,
        start_location=start_location,
        payload=payload,
    )


@st.composite
def image_pair(draw) -> tuple[np.ndarray, np.ndarray]:
    """Generate two arrays of identical shape, sometimes identical in content."""
    channels = draw(st.sampled_from(CHANNEL_COUNTS))
    height = draw(st.integers(min_value=1, max_value=MAX_DIMENSION))
    width = draw(st.integers(min_value=1, max_value=MAX_DIMENSION))
    pattern = draw(st.sampled_from(PATTERNS))
    first = make_cover(
        height, width, channels, pattern, draw(st.integers(0, 2**32 - 1))
    )
    if draw(st.booleans()):
        return first, first.copy()
    second = make_cover(
        height, width, channels, pattern, draw(st.integers(0, 2**32 - 1))
    )
    return first, second


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture()
def workspace(tmp_path):
    """A per-test directory (Requirement 15.11: nothing survives the session)."""
    return str(tmp_path)


class ScratchDirectory:
    """Context manager giving each Hypothesis example its own clean directory.

    A single per-test directory would accumulate up to 100 generated images, so
    each example gets and releases its own.
    """

    def __enter__(self) -> str:
        self._handle = tempfile.TemporaryDirectory(prefix="stego-test-")
        return self._handle.name

    def __exit__(self, *exc_info) -> None:
        self._handle.cleanup()


@pytest.fixture()
def scratch():
    return ScratchDirectory


# --------------------------------------------------------------------------- #
# Audio cover generation
# --------------------------------------------------------------------------- #
#
# The audio layer works on 16-bit PCM WAV. These helpers mirror the image
# helpers above: deterministic content, written into a caller-supplied temporary
# directory, never into the repository. `samples/audio/` holds committed demo
# media and must not be read by tests, because a test that depends on the
# process working directory fails as soon as pytest is invoked from elsewhere.

AUDIO_SAMPLE_RATE = 44_100
AUDIO_SUBTYPE = "PCM_16"
PCM16_PEAK = 32_767

AUDIO_PATTERNS = ("tone", "noise", "silence", "extremes", "ramp")


def make_audio(
    frame_count: int,
    channels: int = 1,
    pattern: str = "tone",
    seed: int = 0,
) -> np.ndarray:
    """Build a deterministic int16 sample array.

    Returns shape ``(frame_count,)`` for mono and ``(frame_count, channels)``
    otherwise, matching what ``soundfile.read(always_2d=False)`` produces.
    """
    rng = np.random.default_rng(seed)
    if pattern == "tone":
        time = np.arange(frame_count, dtype=np.float64) / AUDIO_SAMPLE_RATE
        mono = np.rint(0.5 * PCM16_PEAK * np.sin(2 * np.pi * 440.0 * time))
    elif pattern == "noise":
        mono = rng.integers(-PCM16_PEAK, PCM16_PEAK + 1, frame_count)
    elif pattern == "silence":
        mono = np.zeros(frame_count)
    elif pattern == "extremes":
        # -32768 and 32767 exercise the sign boundary of int16 arithmetic, which
        # is where a naive bit mask written for unsigned samples goes wrong.
        mono = rng.choice(np.array([-32768, 32767]), size=frame_count)
    elif pattern == "ramp":
        mono = np.linspace(-PCM16_PEAK, PCM16_PEAK, frame_count)
    else:  # pragma: no cover - guarded by the strategy
        raise ValueError(f"unknown audio pattern {pattern!r}")

    mono = np.clip(mono, -32768, 32767).astype(np.int16)
    if channels == 1:
        return mono
    # Offset each channel so a channel-ordering bug cannot hide behind identical
    # channels, while staying inside the int16 range.
    stacked = np.stack(
        [np.clip(mono.astype(np.int32) // (index + 1), -32768, 32767) for index in range(channels)],
        axis=1,
    )
    return stacked.astype(np.int16)


def write_audio_file(
    directory: str,
    samples: np.ndarray,
    name: str = "cover",
    sample_rate: int = AUDIO_SAMPLE_RATE,
) -> str:
    """Write *samples* as a 16-bit PCM WAV inside *directory* and return the path."""
    import soundfile as sf

    path = os.path.join(directory, f"{name}.wav")
    sf.write(path, np.asarray(samples, dtype=np.int16), sample_rate, subtype=AUDIO_SUBTYPE)
    return path


@pytest.fixture()
def wav_factory(tmp_path):
    """Return a callable writing deterministic WAV covers into this test's directory."""

    def _make(
        frame_count: int = 4_096,
        channels: int = 1,
        pattern: str = "tone",
        seed: int = 0,
        name: str = "cover",
        sample_rate: int = AUDIO_SAMPLE_RATE,
    ) -> str:
        samples = make_audio(frame_count, channels, pattern, seed)
        return write_audio_file(str(tmp_path), samples, name, sample_rate)

    return _make


# --------------------------------------------------------------------------- #
# Video cover generation
# --------------------------------------------------------------------------- #
#
# Real clips, not header stubs: the video layer's correctness is entirely about
# whether a codec preserves pixels, and a fake file cannot test that. They are
# small on purpose — 32x24 for eight frames is 18 432 samples, enough to hold a
# few hundred payload bytes at depth 1 and still encode in a few milliseconds.
#
# Frames are generated per-index so that a frame-ordering bug cannot hide behind
# identical frames, which is the video equivalent of the per-channel offset in
# make_audio.

VIDEO_WIDTH = 32
VIDEO_HEIGHT = 24
VIDEO_FRAME_COUNT = 8
VIDEO_FRAME_RATE = 10.0

VIDEO_PATTERNS = ("noise", "gradient", "flat", "extremes")


def make_video_frames(
    frame_count: int = VIDEO_FRAME_COUNT,
    height: int = VIDEO_HEIGHT,
    width: int = VIDEO_WIDTH,
    pattern: str = "noise",
    seed: int = 0,
) -> list[np.ndarray]:
    """Build a deterministic list of 8-bit BGR frames."""
    frames = []
    for index in range(frame_count):
        # A distinct seed per frame, so frame N's content depends on N.
        frames.append(make_cover(height, width, 3, pattern, seed + index * 101))
    return frames


def write_video_file(
    directory: str,
    frames: list[np.ndarray],
    name: str = "cover",
    frame_rate: float = VIDEO_FRAME_RATE,
) -> str:
    """Write *frames* as a lossless FFV1 Matroska clip and return the path.

    FFV1 rather than anything else because it is the only lossless codec the
    application writes, and because a cover that is already FFV1 keeps the test
    focused on the embedding rather than on transcoding.
    """
    import cv2

    path = os.path.join(directory, f"{name}.mkv")
    height, width = frames[0].shape[:2]
    writer = cv2.VideoWriter(
        path, cv2.VideoWriter_fourcc(*"FFV1"), float(frame_rate), (width, height)
    )
    if not writer.isOpened():  # pragma: no cover - environment guard
        raise RuntimeError(
            "the installed OpenCV build cannot write FFV1; the video tests need a "
            "lossless encoder"
        )
    try:
        for frame in frames:
            writer.write(np.ascontiguousarray(frame, dtype=np.uint8))
    finally:
        writer.release()
    return path


@pytest.fixture()
def video_factory(tmp_path):
    """Return a callable writing deterministic lossless clips into this test's dir."""

    def _make(
        frame_count: int = VIDEO_FRAME_COUNT,
        height: int = VIDEO_HEIGHT,
        width: int = VIDEO_WIDTH,
        pattern: str = "noise",
        seed: int = 0,
        name: str = "cover",
        frame_rate: float = VIDEO_FRAME_RATE,
    ) -> str:
        frames = make_video_frames(frame_count, height, width, pattern, seed)
        return write_video_file(str(tmp_path), frames, name, frame_rate)

    return _make
