"""Image quality comparison, bit-plane views, difference imaging and steganalysis.

Implements Requirements 8 to 12 of the image-steganography-analysis
specification.

This module returns data, never rendered output. It imports no GUI toolkit and
no plotting library, creates no window and opens no display surface
(Requirement 12.2), so the same functions serve the GUI's Steganalysis tab, the
test suite and any script. Every returned array is freshly allocated and shares
no memory with a caller-supplied array, and no function mutates its inputs
(Requirement 12.4).

On what the steganalysis indicators mean
----------------------------------------
Every indicator here is a descriptive statistic. None of them establishes that
an image does or does not contain embedded data, and this module deliberately
returns no verdict and no confidence percentage (Requirement 11.6, 11.7). Natural
images routinely produce "suspicious" values, and a small or low-entropy payload
routinely produces unremarkable ones. A threshold flag, where a caller supplies a
threshold, records a comparison the caller asked for; it is not a detection.

The two chi-square indicators report a **goodness-of-fit p-value**, as in the
Westfeld-Pfitzmann attack, with the raw statistic kept in ``details``. LSB
replacement drives the counts toward the even split the test models, which makes
the statistic *smaller* and the p-value *larger*. A p-value near 1 is therefore
what embedding looks like, and a threshold on these indicators flags
``value >= threshold``. The p-value is the probability of counts at least this far
from an even split if they were even; it is not the probability that the image
contains data.

Alpha channel handling is deliberately asymmetric, matching the specification:

* Steganalysis indicators and histograms cover colour channels only, because
  those are the channels embedding touches.
* Difference images and bit-plane extraction include alpha, because they describe
  what changed in a file rather than what can carry payload bits, and an
  unexpected alpha change is worth seeing.
* Overall MSE and PSNR exclude alpha, but the alpha channel's own MSE and PSNR
  are reported as labelled per-channel values.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Final, Sequence

import numpy as np
import numpy.typing as npt
from scipy.stats import chi2

from app.stego.capacity import embeddable_channel_count
from app.stego.errors import ComparisonError, ValidationError
from app.stego.image_io import load_image

__all__ = [
    "INDICATOR_DISCLAIMER",
    "MIN_ANALYSED_SAMPLES",
    "MIN_INCLUDED_BIN_PAIRS",
    "MIN_EXPECTED_BIN_COUNT",
    "Region",
    "ChannelMetric",
    "QualityComparison",
    "DifferenceResult",
    "BitPlaneResult",
    "IndicatorResult",
    "HistogramComparison",
    "compare_quality",
    "extract_bit_plane",
    "extract_all_bit_planes",
    "difference_image",
    "lsb_distribution",
    "bit0_uniformity",
    "pair_of_values_chi_square",
    "pair_of_values_neighbour",
    "histogram_compare",
]

#: Requirement 11.6: attached to every steganalysis result.
INDICATOR_DISCLAIMER: Final[str] = (
    "This value is a statistical indicator only. It does not establish the "
    "presence or absence of embedded data."
)

#: Requirement 11.10 thresholds for reporting an insufficient-sample status.
MIN_ANALYSED_SAMPLES: Final[int] = 256
MIN_INCLUDED_BIN_PAIRS: Final[int] = 2

#: Requirement 11.9: bin pairs whose expected count falls below this are excluded
#: from the chi-square statistic, the conventional guard for the approximation.
MIN_EXPECTED_BIN_COUNT: Final[int] = 5

#: Requirement 8.1: PSNR uses a peak sample value of 255 for 8-bit samples.
PEAK_SAMPLE_VALUE: Final[int] = 255

_CHANNEL_LABELS: Final[dict[int, tuple[str, ...]]] = {
    1: ("gray",),
    3: ("red", "green", "blue"),
    4: ("red", "green", "blue", "alpha"),
}

ImageInput = "str | os.PathLike[str] | npt.NDArray[np.uint8]"


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Region:
    """A rectangular region of interest (Requirement 11.11)."""

    left: int
    top: int
    width: int
    height: int

    def as_dict(self) -> dict[str, int]:
        return {
            "left": self.left,
            "top": self.top,
            "width": self.width,
            "height": self.height,
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


@dataclass(frozen=True)
class DifferenceResult:
    """Result of :func:`difference_image` (Requirement 10)."""

    difference: npt.NDArray[np.uint8]
    changed_pixel_map: npt.NDArray[np.bool_]
    mode: str
    max_absolute_difference: int
    scale_factor: float
    changed_pixels: int
    differing_samples: int
    total_samples: int
    differing_proportion: float
    includes_alpha: bool


@dataclass(frozen=True)
class BitPlaneResult:
    """One extracted bit plane (Requirement 9)."""

    plane: npt.NDArray[np.uint8]
    channel_index: int
    channel_label: str
    bit_position: int
    scaled: bool


@dataclass(frozen=True)
class IndicatorResult:
    """One steganalysis indicator (Requirement 11.5 to 11.8, 11.10).

    ``value`` is ``None`` exactly when ``insufficient_sample`` is ``True``, in
    which case no threshold flag is produced either.
    """

    indicator: str
    scope: str
    channel_index: int | None
    value: float | None
    insufficient_sample: bool
    analysed_sample_count: int
    region: dict[str, int] | None
    degrees_of_freedom: int | None = None
    threshold: float | None = None
    threshold_exceeded: bool | None = None
    threshold_direction: str | None = None
    details: dict[str, float] = field(default_factory=dict)
    disclaimer: str = INDICATOR_DISCLAIMER


@dataclass(frozen=True)
class HistogramComparison:
    """Result of :func:`histogram_compare` (Requirement 11.3)."""

    channel_indices: tuple[int, ...]
    channel_labels: tuple[str, ...]
    histograms_a: npt.NDArray[np.int64]
    histograms_b: npt.NDArray[np.int64]
    difference_counts: npt.NDArray[np.int64]
    difference_proportions: npt.NDArray[np.float64]
    analysed_sample_count_a: int
    analysed_sample_count_b: int
    region: dict[str, int] | None
    disclaimer: str = INDICATOR_DISCLAIMER


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #


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


def _coerce_region(region: object) -> Region | None:
    if region is None:
        return None
    if isinstance(region, Region):
        return region
    if isinstance(region, Sequence) and len(region) == 4:
        left, top, width, height = region
        return Region(int(left), int(top), int(width), int(height))
    raise ValidationError(
        "region must be a Region or a (left, top, width, height) sequence, "
        f"got type {type(region).__name__}"
    )


def _apply_region(
    array: npt.NDArray[np.uint8], region: Region | None
) -> npt.NDArray[np.uint8]:
    """Restrict *array* to *region*, validating the bounds (Requirement 11.11)."""
    if region is None:
        return array
    height, width = array.shape[:2]
    if region.width < 1 or region.height < 1:
        raise ValidationError(
            f"region width and height must be at least 1, got "
            f"{region.width}x{region.height}"
        )
    if region.left < 0 or region.top < 0:
        raise ValidationError(
            f"region left and top must be non-negative, got "
            f"left={region.left}, top={region.top}"
        )
    if region.left + region.width > width or region.top + region.height > height:
        raise ValidationError(
            f"region ({region.left}, {region.top}, {region.width}, {region.height}) "
            f"does not fit inside an image of {width}x{height}"
        )
    return array[
        region.top : region.top + region.height,
        region.left : region.left + region.width,
    ]


def _require_same_shape(
    first: npt.NDArray[np.uint8], second: npt.NDArray[np.uint8]
) -> None:
    """Requirement 8.4 and 10.9: a shape mismatch is a comparison error."""
    if first.shape != second.shape:
        raise ComparisonError(
            f"images must have identical dimensions and channel count to be "
            f"compared, got height x width x channels of "
            f"{first.shape[0]}x{first.shape[1]}x{first.shape[2]} and "
            f"{second.shape[0]}x{second.shape[1]}x{second.shape[2]}"
        )


# --------------------------------------------------------------------------- #
# Requirement 8: quality comparison
# --------------------------------------------------------------------------- #


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


# --------------------------------------------------------------------------- #
# Requirement 9: bit-plane visualisation
# --------------------------------------------------------------------------- #


def extract_bit_plane(
    image: object, bit_position: int, channel: int = 0, *, scaled: bool = True
) -> BitPlaneResult:
    """Extract bit plane *bit_position* of *channel*.

    Requirement 9. ``scaled=True`` maps bit 0 to sample value 0 and bit 1 to 255
    so the plane is directly viewable; ``scaled=False`` returns values restricted
    to 0 and 1 for numeric work.

    The alpha channel is a valid channel here (Requirement 9.6), even though
    embedding never touches it.
    """
    array = _as_array(image)
    channel_count = array.shape[2]

    if isinstance(bit_position, bool) or not isinstance(
        bit_position, (int, np.integer)
    ):
        raise ValidationError(
            f"bit_position must be an integer from 0 to 7 inclusive, "
            f"got type {type(bit_position).__name__}"
        )
    position = int(bit_position)
    if not 0 <= position <= 7:
        raise ValidationError(
            f"bit_position must be an integer from 0 to 7 inclusive, got {position}"
        )

    if isinstance(channel, bool) or not isinstance(channel, (int, np.integer)):
        raise ValidationError(
            f"channel must be an integer from 0 to {channel_count - 1} inclusive, "
            f"got type {type(channel).__name__}"
        )
    channel_index = int(channel)
    if not 0 <= channel_index < channel_count:
        raise ValidationError(
            f"channel must be an integer from 0 to {channel_count - 1} inclusive, "
            f"got {channel_index}"
        )

    bits = (array[:, :, channel_index] >> np.uint8(position)) & np.uint8(1)
    plane = (bits * np.uint8(255)) if scaled else bits
    return BitPlaneResult(
        plane=np.ascontiguousarray(plane, dtype=np.uint8),
        channel_index=channel_index,
        channel_label=_labels(channel_count)[channel_index],
        bit_position=position,
        scaled=scaled,
    )


def extract_all_bit_planes(
    image: object, *, scaled: bool = True
) -> tuple[BitPlaneResult, ...]:
    """Extract every bit plane of every channel.

    Requirement 9.7: ordered by ascending channel index then ascending bit
    position, giving ``channel_count * 8`` planes.
    """
    array = _as_array(image)
    return tuple(
        extract_bit_plane(array, position, channel, scaled=scaled)
        for channel in range(array.shape[2])
        for position in range(8)
    )


# --------------------------------------------------------------------------- #
# Requirement 10: difference imaging
# --------------------------------------------------------------------------- #


def difference_image(
    image_a: object,
    image_b: object,
    *,
    amplify: bool = False,
    binary_mask: bool = False,
) -> DifferenceResult:
    """Compute the per-sample absolute difference between two images.

    Requirement 10. Alpha samples are included (Requirement 10.6).

    ``amplify`` scales the largest observed difference to 255, which is what makes
    a 1-bit LSB change visible at all; a raw LSB difference of 1 is
    indistinguishable from black on screen. ``binary_mask`` instead maps any
    non-zero difference to 255. The two modes are mutually exclusive
    (Requirement 10.5).

    Inputs are widened out of ``uint8`` before subtraction. Without that,
    ``np.uint8(3) - np.uint8(5)`` wraps to 254 instead of yielding 2, which would
    silently invert the meaning of every difference image.
    """
    if amplify and binary_mask:
        raise ValidationError(
            "amplify and binary_mask are mutually exclusive; request one mode at a time"
        )

    first = _as_array(image_a, "image_a")
    second = _as_array(image_b, "image_b")
    _require_same_shape(first, second)

    delta = np.abs(first.astype(np.int16, copy=False) - second.astype(np.int16, copy=False))
    maximum = int(delta.max()) if delta.size else 0

    if binary_mask:
        mode = "binary"
        scale = 1.0
        difference = np.where(delta > 0, np.uint8(255), np.uint8(0)).astype(np.uint8)
    elif amplify:
        mode = "amplified"
        if maximum == 0:
            # Requirement 10.3: no division when there is nothing to scale.
            scale = 1.0
            difference = np.zeros(first.shape, dtype=np.uint8)
        else:
            scale = 255.0 / maximum
            difference = np.rint(delta * scale).clip(0, 255).astype(np.uint8)
    else:
        mode = "raw"
        scale = 1.0
        difference = delta.astype(np.uint8)

    differing = delta > 0
    changed_pixel_map = differing.any(axis=2)
    total_samples = int(first.size)
    differing_samples = int(differing.sum())

    return DifferenceResult(
        difference=np.ascontiguousarray(difference, dtype=np.uint8),
        changed_pixel_map=np.ascontiguousarray(changed_pixel_map, dtype=bool),
        mode=mode,
        max_absolute_difference=maximum,
        scale_factor=scale,
        changed_pixels=int(changed_pixel_map.sum()),
        differing_samples=differing_samples,
        total_samples=total_samples,
        differing_proportion=(
            differing_samples / total_samples if total_samples else 0.0
        ),
        includes_alpha=first.shape[2] == 4,
    )


# --------------------------------------------------------------------------- #
# Requirement 11: steganalysis indicators
# --------------------------------------------------------------------------- #


#: Every indicator here moves *up* under LSB replacement: the chi-square p-values
#: rise as pair counts are equalised, and the neighbour proportion rises as more
#: adjacent samples differ only in bit 0. So every threshold flags values at or
#: above it. Stated once, and recorded on each result, so it is never implicit.
THRESHOLD_DIRECTION: Final[str] = "value >= threshold"


def _threshold_fields(
    value: float | None, threshold: float | None
) -> tuple[float | None, bool | None, str | None]:
    """Requirement 11.8: flag a threshold crossing and record the direction."""
    if threshold is None or value is None:
        return (None if threshold is None else float(threshold)), None, None
    return float(threshold), bool(value >= threshold), THRESHOLD_DIRECTION


def chi_square_p_value(statistic: float, degrees_of_freedom: int) -> float:
    """Return the upper-tail probability of *statistic* on *degrees_of_freedom*."""
    return float(chi2.sf(statistic, degrees_of_freedom))


def lsb_distribution(
    image: object, *, region: object = None
) -> tuple[IndicatorResult, ...]:
    """Report how many analysed samples have bit 0 set.

    Requirement 11.1. Returns one result per colour channel plus an overall
    result. Alpha samples are excluded, and no reference cover is needed.

    Note on a specification tension: Requirement 11.1 unconditionally requires
    the counts and proportions to be returned, while Requirement 11.10 suppresses
    numeric values for channels with fewer than 256 analysed samples. This
    function follows Requirement 11.1 and always reports the counts, because a
    raw count is meaningful at any sample size, while still setting
    ``insufficient_sample`` so a caller can see that the proportion is not
    statistically informative. The suppression rule of Requirement 11.10 is
    applied strictly to the three statistical indicators below.
    """
    array = _as_array(image)
    bounds = _coerce_region(region)
    windowed = _apply_region(array, bounds)
    colour_channels = _colour_channel_count(array.shape[2])
    labels = _labels(array.shape[2])
    region_dict = bounds.as_dict() if bounds else None

    results: list[IndicatorResult] = []
    total_analysed = 0
    total_ones = 0

    for index in range(colour_channels):
        samples = windowed[:, :, index]
        analysed = int(samples.size)
        ones = int((samples & np.uint8(1)).sum())
        total_analysed += analysed
        total_ones += ones
        proportion = ones / analysed if analysed else 0.0
        results.append(
            IndicatorResult(
                indicator="lsb_distribution",
                scope=f"channel:{index}:{labels[index]}",
                channel_index=index,
                value=proportion,
                insufficient_sample=analysed < MIN_ANALYSED_SAMPLES,
                analysed_sample_count=analysed,
                region=region_dict,
                details={"ones_count": float(ones), "zeros_count": float(analysed - ones)},
            )
        )

    overall_proportion = total_ones / total_analysed if total_analysed else 0.0
    results.append(
        IndicatorResult(
            indicator="lsb_distribution",
            scope="overall",
            channel_index=None,
            value=overall_proportion,
            insufficient_sample=total_analysed < MIN_ANALYSED_SAMPLES,
            analysed_sample_count=total_analysed,
            region=region_dict,
            details={
                "ones_count": float(total_ones),
                "zeros_count": float(total_analysed - total_ones),
            },
        )
    )
    return tuple(results)


def bit0_uniformity(
    image: object, *, region: object = None, threshold: float | None = None
) -> tuple[IndicatorResult, ...]:
    """Chi-square test of bit-0 values against an even split, as a p-value.

    Requirement 11.2. One degree of freedom; the statistic is in
    ``details["statistic"]``. This is a different indicator from
    :func:`pair_of_values_chi_square`: it asks only whether zeros and ones are
    balanced, which many unmodified natural images already satisfy, so a high
    p-value here is weak evidence of anything.
    """
    array = _as_array(image)
    bounds = _coerce_region(region)
    windowed = _apply_region(array, bounds)
    colour_channels = _colour_channel_count(array.shape[2])
    labels = _labels(array.shape[2])
    region_dict = bounds.as_dict() if bounds else None

    results: list[IndicatorResult] = []
    for index in range(colour_channels):
        samples = windowed[:, :, index]
        analysed = int(samples.size)
        ones = int((samples & np.uint8(1)).sum())
        zeros = analysed - ones

        if analysed < MIN_ANALYSED_SAMPLES:
            results.append(
                IndicatorResult(
                    indicator="bit0_uniformity_chi_square",
                    scope=f"channel:{index}:{labels[index]}",
                    channel_index=index,
                    value=None,
                    insufficient_sample=True,
                    analysed_sample_count=analysed,
                    region=region_dict,
                    degrees_of_freedom=1,
                    details={
                        "minimum_analysed_samples": float(MIN_ANALYSED_SAMPLES),
                    },
                )
            )
            continue

        expected = analysed / 2.0
        statistic = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
        p_value = chi_square_p_value(statistic, 1)
        limit, exceeded, direction = _threshold_fields(p_value, threshold)
        results.append(
            IndicatorResult(
                indicator="bit0_uniformity_chi_square",
                scope=f"channel:{index}:{labels[index]}",
                channel_index=index,
                value=p_value,
                insufficient_sample=False,
                analysed_sample_count=analysed,
                region=region_dict,
                degrees_of_freedom=1,
                threshold=limit,
                threshold_exceeded=exceeded,
                threshold_direction=direction,
                details={
                    "statistic": float(statistic),
                    "ones_count": float(ones),
                    "zeros_count": float(zeros),
                },
            )
        )
    return tuple(results)


def pair_of_values_chi_square(
    image: object, *, region: object = None, threshold: float | None = None
) -> tuple[IndicatorResult, ...]:
    """Pair-of-values chi-square over histogram bin pairs (2k, 2k+1), as a p-value.

    Requirement 11.9. The statistic is in ``details["statistic"]``. LSB replacement
    moves samples between the two members of a ``(2k, 2k+1)`` pair without moving
    them out of the pair, so it drives the two bin counts of each pair toward each
    other while leaving the pair total unchanged. The expected count is therefore the
    mean of the pair.

    This is the Westfeld-Pfitzmann statistic, ``sum((n_2k - mean_k)**2 / mean_k)``,
    which takes one bin per pair. Summing both bins would double every term, and a
    fully embedded image would then give a p-value spread uniformly over 0 to 1
    rather than near 1, which is the behaviour the attack relies on.

    Bin pairs whose expected count falls below 5 are excluded, the conventional
    guard for the chi-square approximation, and the degrees of freedom are the
    number of included pairs minus 1. No reference cover is required, which is
    the point: a real analyst does not have the original.
    """
    array = _as_array(image)
    bounds = _coerce_region(region)
    windowed = _apply_region(array, bounds)
    colour_channels = _colour_channel_count(array.shape[2])
    labels = _labels(array.shape[2])
    region_dict = bounds.as_dict() if bounds else None

    results: list[IndicatorResult] = []
    for index in range(colour_channels):
        samples = windowed[:, :, index]
        analysed = int(samples.size)
        histogram = np.bincount(samples.reshape(-1), minlength=256).astype(np.float64)

        even = histogram[0::2]
        odd = histogram[1::2]
        expected = (even + odd) / 2.0
        included = expected >= MIN_EXPECTED_BIN_COUNT
        included_pairs = int(included.sum())
        excluded_pairs = int(expected.size - included_pairs)

        if analysed < MIN_ANALYSED_SAMPLES or included_pairs < MIN_INCLUDED_BIN_PAIRS:
            results.append(
                IndicatorResult(
                    indicator="pair_of_values_chi_square",
                    scope=f"channel:{index}:{labels[index]}",
                    channel_index=index,
                    value=None,
                    insufficient_sample=True,
                    analysed_sample_count=analysed,
                    region=region_dict,
                    degrees_of_freedom=None,
                    details={
                        "included_bin_pairs": float(included_pairs),
                        "excluded_bin_pairs": float(excluded_pairs),
                        "minimum_analysed_samples": float(MIN_ANALYSED_SAMPLES),
                        "minimum_included_bin_pairs": float(MIN_INCLUDED_BIN_PAIRS),
                    },
                )
            )
            continue

        used_even = even[included]
        used_expected = expected[included]
        # One bin per pair: the odd bin's deviation mirrors the even bin's exactly.
        statistic = float((((used_even - used_expected) ** 2) / used_expected).sum())
        degrees_of_freedom = included_pairs - 1
        p_value = chi_square_p_value(statistic, degrees_of_freedom)
        limit, exceeded, direction = _threshold_fields(p_value, threshold)
        results.append(
            IndicatorResult(
                indicator="pair_of_values_chi_square",
                scope=f"channel:{index}:{labels[index]}",
                channel_index=index,
                value=p_value,
                insufficient_sample=False,
                analysed_sample_count=analysed,
                region=region_dict,
                degrees_of_freedom=degrees_of_freedom,
                threshold=limit,
                threshold_exceeded=exceeded,
                threshold_direction=direction,
                details={
                    "statistic": statistic,
                    "included_bin_pairs": float(included_pairs),
                    "excluded_bin_pairs": float(excluded_pairs),
                },
            )
        )
    return tuple(results)


def pair_of_values_neighbour(
    image: object, *, region: object = None, threshold: float | None = None
) -> tuple[IndicatorResult, ...]:
    """Proportion of horizontally adjacent sample pairs differing only in bit 0.

    Requirement 11.4. A pair is two samples of the same colour channel at
    horizontally adjacent pixels in the same row; pairs never span a row boundary,
    so each channel contributes ``(width - 1) * height`` pairs. This pairing is
    over neighbouring pixels and is distinct from the histogram bin pairing used
    by :func:`pair_of_values_chi_square`.
    """
    array = _as_array(image)
    bounds = _coerce_region(region)
    windowed = _apply_region(array, bounds)
    colour_channels = _colour_channel_count(array.shape[2])
    labels = _labels(array.shape[2])
    region_dict = bounds.as_dict() if bounds else None
    height, width = windowed.shape[:2]

    results: list[IndicatorResult] = []
    for index in range(colour_channels):
        samples = windowed[:, :, index]
        analysed = int(samples.size)
        examined = max(0, width - 1) * height

        if (
            examined == 0
            or analysed < MIN_ANALYSED_SAMPLES
        ):
            results.append(
                IndicatorResult(
                    indicator="pair_of_values_neighbour",
                    scope=f"channel:{index}:{labels[index]}",
                    channel_index=index,
                    value=None,
                    insufficient_sample=True,
                    analysed_sample_count=analysed,
                    region=region_dict,
                    details={
                        "examined_pair_count": float(examined),
                        "minimum_analysed_samples": float(MIN_ANALYSED_SAMPLES),
                    },
                )
            )
            continue

        left = samples[:, :-1].astype(np.uint8, copy=False)
        right = samples[:, 1:].astype(np.uint8, copy=False)
        matches = int(((left ^ right) == np.uint8(1)).sum())
        proportion = matches / examined
        limit, exceeded, direction = _threshold_fields(proportion, threshold)
        results.append(
            IndicatorResult(
                indicator="pair_of_values_neighbour",
                scope=f"channel:{index}:{labels[index]}",
                channel_index=index,
                value=float(proportion),
                insufficient_sample=False,
                analysed_sample_count=analysed,
                region=region_dict,
                threshold=limit,
                threshold_exceeded=exceeded,
                threshold_direction=direction,
                details={
                    "examined_pair_count": float(examined),
                    "matching_pair_count": float(matches),
                },
            )
        )
    return tuple(results)


def histogram_compare(
    image_a: object, image_b: object, *, region: object = None
) -> HistogramComparison:
    """Compare the per-channel sample histograms of two images.

    Requirement 11.3. Covers the colour channel indices present in both images,
    reporting each 256-bin histogram, the bin-wise count difference, and the
    bin-wise difference as proportions of each image's analysed sample count so
    that images of different sizes remain comparable.
    """
    first = _as_array(image_a, "image_a")
    second = _as_array(image_b, "image_b")
    bounds = _coerce_region(region)
    window_a = _apply_region(first, bounds)
    window_b = _apply_region(second, bounds)

    shared = min(
        _colour_channel_count(first.shape[2]), _colour_channel_count(second.shape[2])
    )
    labels_a = _labels(first.shape[2])

    histograms_a = np.zeros((shared, 256), dtype=np.int64)
    histograms_b = np.zeros((shared, 256), dtype=np.int64)
    for index in range(shared):
        histograms_a[index] = np.bincount(
            window_a[:, :, index].reshape(-1), minlength=256
        )
        histograms_b[index] = np.bincount(
            window_b[:, :, index].reshape(-1), minlength=256
        )

    count_a = int(window_a[:, :, :shared].size)
    count_b = int(window_b[:, :, :shared].size)
    per_channel_a = count_a / shared if shared else 0
    per_channel_b = count_b / shared if shared else 0

    proportions_a = (
        histograms_a / per_channel_a
        if per_channel_a
        else np.zeros_like(histograms_a, dtype=np.float64)
    )
    proportions_b = (
        histograms_b / per_channel_b
        if per_channel_b
        else np.zeros_like(histograms_b, dtype=np.float64)
    )

    return HistogramComparison(
        channel_indices=tuple(range(shared)),
        channel_labels=tuple(labels_a[:shared]),
        histograms_a=histograms_a,
        histograms_b=histograms_b,
        difference_counts=histograms_a - histograms_b,
        difference_proportions=(proportions_a - proportions_b).astype(np.float64),
        analysed_sample_count_a=count_a,
        analysed_sample_count_b=count_b,
        region=bounds.as_dict() if bounds else None,
    )
