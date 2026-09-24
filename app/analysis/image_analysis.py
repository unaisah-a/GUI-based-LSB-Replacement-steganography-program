"""Image quality comparison without detection or visualisation features.

Overall MSE/PSNR exclude alpha; labelled per-channel metrics include alpha.
Inputs are never mutated and this module imports no GUI toolkit.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Final

import numpy as np
import numpy.typing as npt

from app.stego.capacity import embeddable_channel_count
from app.stego.errors import ComparisonError, ValidationError
from app.stego.image_io import load_image

PEAK_SAMPLE_VALUE: Final[int] = 255


_CHANNEL_LABELS: Final[dict[int, tuple[str, ...]]] = {
    1: ("gray",),
    3: ("red", "green", "blue"),
    4: ("red", "green", "blue", "alpha"),
}


@dataclass(frozen=True)
class ChannelMetric:
    """Per-channel quality metrics (Requirement 8.1, 8.6)."""

    index: int
    label: str
    mse: float
    psnr_db: float
    psnr_unbounded: bool
    is_alpha: bool


@dataclass(frozen=True)
class QualityComparison:
    """Result of :func:`compare_quality` (Requirement 8)."""

    overall_mse: float
    overall_psnr_db: float
    #: Requirement 8.5: lets a caller render the infinite case without parsing text.
    overall_psnr_unbounded: bool
    channels: tuple[ChannelMetric, ...]
    pixel_identical: bool
    max_absolute_difference: int
    differing_samples: int
    total_samples: int
    differing_proportion: float
    height: int
    width: int
    channel_count: int
    height_equal: bool
    width_equal: bool
    dimensions_equal: bool
    channel_count_equal: bool
    alpha_excluded_from_overall: bool
    file_size_a: int | None = None
    file_size_b: int | None = None
    file_size_equal: bool | None = None
    #: Requirement 8.11: no cryptographic digest is produced by this layer.
    digest_note: str = (
        "No cryptographic digest is computed here. Sample-level equality is "
        "reported by pixel_identical and differing_samples; file digests are "
        "produced by the cryptography layer."
    )


def _as_array(image: object, argument: str = "image") -> npt.NDArray[np.uint8]:
    """Accept a file path or a decoded array (Requirement 12.6).

    Grayscale input is normalised to a 3-dimensional ``(height, width, 1)`` array
    so that downstream channel indexing is uniform. The caller's array is never
    modified.
    """
    if isinstance(image, (str, os.PathLike)):
        array, _ = load_image(image)
        return array

    if not isinstance(image, np.ndarray):
        raise ValidationError(
            f"{argument} must be a file path or a numpy array, "
            f"got type {type(image).__name__}"
        )
    if image.dtype != np.uint8:
        raise ValidationError(
            f"{argument} must have dtype uint8, got {image.dtype}"
        )
    if image.ndim == 2:
        view = image[:, :, np.newaxis]
    elif image.ndim == 3:
        view = image
    else:
        raise ValidationError(
            f"{argument} must have 2 or 3 dimensions, got {image.ndim}"
        )
    if view.shape[2] not in _CHANNEL_LABELS:
        raise ValidationError(
            f"{argument} must have 1, 3 or 4 channels, got {view.shape[2]}"
        )
    return view


def _labels(channel_count: int) -> tuple[str, ...]:
    return _CHANNEL_LABELS[channel_count]


def _colour_channel_count(channel_count: int) -> int:
    """Channels excluding alpha, matching the embedding definition."""
    return embeddable_channel_count(channel_count)


def _file_size(path: object) -> int | None:
    if isinstance(path, (str, os.PathLike)) and os.path.isfile(os.fspath(path)):
        return os.path.getsize(os.fspath(path))
    return None


def _require_same_shape(
    first: npt.NDArray[np.uint8], second: npt.NDArray[np.uint8]
) -> None:
    """Requirement 8.4: a shape mismatch is a comparison error."""
    if first.shape != second.shape:
        raise ComparisonError(
            f"images must have identical dimensions and channel count to be "
            f"compared, got height x width x channels of "
            f"{first.shape[0]}x{first.shape[1]}x{first.shape[2]} and "
            f"{second.shape[0]}x{second.shape[1]}x{second.shape[2]}"
        )


def _psnr_from_mse(mse: float) -> tuple[float, bool]:
    """Return (PSNR in dB, unbounded flag).

    Requirement 8.5 and 8.6: MSE of exactly 0 means the images are identical and
    PSNR is unbounded, reported as positive infinity plus a boolean flag.
    """
    if mse <= 0.0:
        return math.inf, True
    return 10.0 * math.log10((PEAK_SAMPLE_VALUE**2) / mse), False


def compare_quality(
    image_a: object,
    image_b: object,
    *,
    path_a: object = None,
    path_b: object = None,
) -> QualityComparison:
    """Compare two images and report MSE, PSNR and equality facts.

    Requirement 8. Both arguments may be file paths or decoded arrays; when they
    are paths, the file sizes are reported too (Requirement 8.10).

    The squared differences are accumulated in ``int64`` after widening from
    ``uint8``. That widening is not cosmetic: subtracting two ``uint8`` arrays
    wraps around, so a cover sample of 3 and a stego sample of 5 would otherwise
    yield a difference of 254 rather than 2, and squaring even a correct
    ``uint8`` difference overflows above 15.

    Overall MSE and PSNR exclude alpha (Requirement 8.9); the alpha channel's own
    metrics appear in ``channels`` labelled as alpha.
    """
    first = _as_array(image_a, "image_a")
    second = _as_array(image_b, "image_b")

    size_a = _file_size(path_a if path_a is not None else image_a)
    size_b = _file_size(path_b if path_b is not None else image_b)

    # Requirement 8.3: report the shape facts before the mismatch check, so the
    # error message can name both shapes.
    _require_same_shape(first, second)

    height, width, channel_count = first.shape
    labels = _labels(channel_count)
    colour_channels = _colour_channel_count(channel_count)
    has_alpha = channel_count == 4

    wide_a = first.astype(np.int64, copy=False)
    wide_b = second.astype(np.int64, copy=False)
    delta = wide_a - wide_b
    squared = delta * delta
    absolute = np.abs(delta)

    channel_metrics: list[ChannelMetric] = []
    for index in range(channel_count):
        channel_mse = float(squared[:, :, index].mean())
        psnr_db, unbounded = _psnr_from_mse(channel_mse)
        channel_metrics.append(
            ChannelMetric(
                index=index,
                label=labels[index],
                mse=channel_mse,
                psnr_db=psnr_db,
                psnr_unbounded=unbounded,
                is_alpha=has_alpha and index == 3,
            )
        )

    overall_mse = float(squared[:, :, :colour_channels].mean())
    overall_psnr, overall_unbounded = _psnr_from_mse(overall_mse)

    differing = np.not_equal(first, second)
    total_samples = int(first.size)
    differing_samples = int(differing.sum())

    return QualityComparison(
        overall_mse=overall_mse,
        overall_psnr_db=overall_psnr,
        overall_psnr_unbounded=overall_unbounded,
        channels=tuple(channel_metrics),
        pixel_identical=differing_samples == 0,
        max_absolute_difference=int(absolute.max()) if total_samples else 0,
        differing_samples=differing_samples,
        total_samples=total_samples,
        differing_proportion=(
            differing_samples / total_samples if total_samples else 0.0
        ),
        height=height,
        width=width,
        channel_count=channel_count,
        height_equal=True,
        width_equal=True,
        dimensions_equal=True,
        channel_count_equal=True,
        alpha_excluded_from_overall=has_alpha,
        file_size_a=size_a,
        file_size_b=size_b,
        file_size_equal=(None if size_a is None or size_b is None else size_a == size_b),
    )
