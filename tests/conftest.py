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

from app.stego import image_io
from app.stego.capacity import LENGTH_HEADER_BYTES, embeddable_channel_count

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
