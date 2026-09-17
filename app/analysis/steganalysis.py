"""One steganalysis interface over image and audio media.

:mod:`app.analysis.image_analysis` already implements a full set of image indicators.
Audio had none, so the three that transfer meaningfully to a sample stream are
implemented here, and both are presented through one :class:`AnalysisReport` so the
interface does not have to branch on media type.

What these numbers are
----------------------
Descriptive statistics. Not detectors. None of them establishes that a file does or
does not contain embedded data, and this module returns no verdict, no confidence and
no probability. Natural media routinely produces values that look suspicious, and a
short or low-entropy payload routinely produces values that look ordinary.

Every indicator therefore carries
:data:`app.analysis.image_analysis.INDICATOR_DISCLAIMER`, and
:attr:`Indicator.insufficient_sample` marks the cases where there was not enough data
for the number to mean anything at all. A threshold comparison, where a caller asks
for one, records the comparison the caller requested; it is not a detection.

Why the audio indicators are the ones they are
----------------------------------------------
LSB replacement in a sample stream has the same statistical signature as in a pixel
stream: it pushes the proportion of set low bits toward one half, and it moves samples
between the two members of a ``(2k, 2k+1)`` value pair without moving them out of that
pair. The bit-0 balance test and the neighbour-pair test both carry over directly. The
histogram pair test does not transfer as cleanly, because 16-bit audio spreads
65,536 values thinly enough that most pair counts fall below the threshold where the
chi-square approximation holds, so it is reported as an insufficient sample rather
than as a number that would look precise and mean nothing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.analysis import image_analysis
from app.analysis.image_analysis import (
    INDICATOR_DISCLAIMER,
    MIN_ANALYSED_SAMPLES,
    BitPlaneResult,
    DifferenceResult,
    HistogramComparison,
    IndicatorResult,
    Region,
)
from app.analysis.quality_metrics import QualityReport
from app.stego import audio_stego, media
from app.stego.errors import ComparisonError
from app.utils import constants

__all__ = [
    "INDICATOR_DISCLAIMER",
    "AnalysisReport",
    "Indicator",
    "analyse",
    "audio_indicators",
]


@dataclass(frozen=True)
class Indicator:
    """One statistical indicator, in terms shared by every medium."""

    name: str
    scope: str
    #: ``None`` when there was too little data for the value to mean anything.
    value: float | None
    insufficient_sample: bool
    analysed_sample_count: int
    #: What the number is measuring, in words, for display beside it.
    explanation: str
    details: dict[str, float] = field(default_factory=dict)
    threshold: float | None = None
    threshold_exceeded: bool | None = None
    disclaimer: str = INDICATOR_DISCLAIMER

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", dict(self.details))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope,
            "value": self.value,
            "insufficient_sample": self.insufficient_sample,
            "analysed_sample_count": self.analysed_sample_count,
            "explanation": self.explanation,
            "threshold": self.threshold,
            "threshold_exceeded": self.threshold_exceeded,
            "details": dict(self.details),
            "disclaimer": self.disclaimer,
        }


#: Plain-language explanations, keyed by indicator name. Shown beside each value so a
#: reader knows what it measures without consulting the source.
_EXPLANATIONS: dict[str, str] = {
    "lsb_distribution": (
        "The proportion of analysed samples whose lowest bit is 1. Replacement pushes "
        "this toward 0.5, but plenty of unmodified media sits near 0.5 already."
    ),
    "bit0_uniformity_chi_square": (
        "How far the balance of zero and one low bits departs from an even split, on "
        "one degree of freedom. A low value means balanced, which many natural files "
        "already are."
    ),
    "pair_of_values_chi_square": (
        "Compares the counts within each pair of adjacent sample values. Replacement "
        "moves samples between the two members of a pair without moving them out of "
        "it, driving the two counts together."
    ),
    "pair_of_values_neighbour": (
        "The proportion of adjacent same-channel sample pairs that differ only in "
        "their lowest bit."
    ),
}


def _explain(name: str) -> str:
    return _EXPLANATIONS.get(name, "")


def _from_image_indicator(result: IndicatorResult) -> Indicator:
    return Indicator(
        name=result.indicator,
        scope=result.scope,
        value=result.value,
        insufficient_sample=result.insufficient_sample,
        analysed_sample_count=result.analysed_sample_count,
        explanation=_explain(result.indicator),
        details=dict(result.details),
        threshold=getattr(result, "threshold", None),
        threshold_exceeded=getattr(result, "threshold_exceeded", None),
    )


@dataclass(frozen=True)
class AnalysisReport:
    """Everything the steganalysis view can show about a file."""

    media_type: str
    path: str
    indicators: tuple[Indicator, ...]
    #: Image only. Empty for audio, which has no spatial planes to show.
    bit_planes: tuple[BitPlaneResult, ...] = ()
    #: Present only when a reference file was supplied.
    difference: DifferenceResult | None = None
    histograms: HistogramComparison | None = None
    quality: QualityReport | None = None
    #: Audio only: the per-sample difference from the reference, for a waveform view.
    sample_difference: np.ndarray | None = None
    disclaimer: str = INDICATOR_DISCLAIMER

    @property
    def has_reference(self) -> bool:
        return self.quality is not None

    def as_dict(self) -> dict[str, Any]:
        """A JSON-friendly summary. Arrays are described, not serialised."""
        return {
            "media_type": self.media_type,
            "file": os.path.basename(self.path),
            "has_reference": self.has_reference,
            "indicators": [indicator.as_dict() for indicator in self.indicators],
            "bit_plane_count": len(self.bit_planes),
            "quality": None if self.quality is None else self.quality.as_dict(),
            "disclaimer": self.disclaimer,
        }


# --------------------------------------------------------------------------- #
# Audio indicators
# --------------------------------------------------------------------------- #


def audio_indicators(
    path: str | os.PathLike[str], *, threshold: float | None = None
) -> tuple[Indicator, ...]:
    """Compute the three transferable indicators for a WAV file.

    Operates on the interleaved scalar sample stream, which is the same domain the
    audio stego layer embeds into, so the samples analysed are exactly the samples
    that can carry payload bits.
    """
    samples, descriptor = audio_stego.read_audio(path)
    flat = np.ascontiguousarray(samples, dtype=np.int16).reshape(-1)
    analysed = int(flat.size)

    # Reinterpret rather than cast, for the same reason the stego layer does: the low
    # bits of a two's-complement value are what embedding writes.
    unsigned = flat.view(np.uint16)
    low_bits = (unsigned & np.uint16(1)).astype(np.int64)
    ones = int(low_bits.sum())
    zeros = analysed - ones
    insufficient = analysed < MIN_ANALYSED_SAMPLES

    indicators: list[Indicator] = [
        Indicator(
            name="lsb_distribution",
            scope="overall",
            value=(ones / analysed) if analysed else 0.0,
            insufficient_sample=insufficient,
            analysed_sample_count=analysed,
            explanation=_explain("lsb_distribution"),
            details={"ones_count": float(ones), "zeros_count": float(zeros)},
        )
    ]

    if insufficient:
        indicators.append(
            Indicator(
                name="bit0_uniformity_chi_square",
                scope="overall",
                value=None,
                insufficient_sample=True,
                analysed_sample_count=analysed,
                explanation=_explain("bit0_uniformity_chi_square"),
                details={"minimum_analysed_samples": float(MIN_ANALYSED_SAMPLES)},
            )
        )
    else:
        expected = analysed / 2.0
        statistic = ((zeros - expected) ** 2 + (ones - expected) ** 2) / expected
        indicators.append(
            Indicator(
                name="bit0_uniformity_chi_square",
                scope="overall",
                value=float(statistic),
                insufficient_sample=False,
                analysed_sample_count=analysed,
                explanation=_explain("bit0_uniformity_chi_square"),
                details={"degrees_of_freedom": 1.0},
                threshold=threshold,
                threshold_exceeded=(
                    None if threshold is None else bool(statistic > threshold)
                ),
            )
        )

    # Neighbour pairs, per channel, never spanning a channel boundary: for stereo the
    # flat stream interleaves channels, so consecutive scalar samples belong to
    # different channels and comparing them would be meaningless.
    channels = descriptor.channel_count
    examined = 0
    matches = 0
    for channel in range(channels):
        channel_samples = unsigned[channel::channels]
        if channel_samples.size < 2:
            continue
        left = channel_samples[:-1]
        right = channel_samples[1:]
        matches += int(((left ^ right) == np.uint16(1)).sum())
        examined += int(left.size)

    if examined == 0 or insufficient:
        indicators.append(
            Indicator(
                name="pair_of_values_neighbour",
                scope="overall",
                value=None,
                insufficient_sample=True,
                analysed_sample_count=analysed,
                explanation=_explain("pair_of_values_neighbour"),
                details={"examined_pair_count": float(examined)},
            )
        )
    else:
        proportion = matches / examined
        indicators.append(
            Indicator(
                name="pair_of_values_neighbour",
                scope="overall",
                value=float(proportion),
                insufficient_sample=False,
                analysed_sample_count=analysed,
                explanation=_explain("pair_of_values_neighbour"),
                details={
                    "examined_pair_count": float(examined),
                    "matching_pair_count": float(matches),
                    "channels": float(channels),
                },
                threshold=threshold,
                threshold_exceeded=(
                    None if threshold is None else bool(proportion > threshold)
                ),
            )
        )

    # Stated rather than computed: see the module docstring on why the histogram pair
    # test does not transfer to 16-bit audio.
    indicators.append(
        Indicator(
            name="pair_of_values_chi_square",
            scope="overall",
            value=None,
            insufficient_sample=True,
            analysed_sample_count=analysed,
            explanation=(
                _explain("pair_of_values_chi_square")
                + " Not reported for 16-bit audio: with 65,536 possible values, most "
                "pair counts fall below the level at which the chi-square "
                "approximation is valid."
            ),
            details={"value_range": 65_536.0},
        )
    )

    return tuple(indicators)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


def _image_report(
    path: str,
    reference: str | None,
    region: Region | None,
    threshold: float | None,
    scaled_planes: bool,
) -> AnalysisReport:
    indicators: list[Indicator] = []
    for function in (
        image_analysis.lsb_distribution,
        image_analysis.bit0_uniformity,
        image_analysis.pair_of_values_chi_square,
        image_analysis.pair_of_values_neighbour,
    ):
        if function is image_analysis.lsb_distribution:
            results = function(path, region=region)
        else:
            results = function(path, region=region, threshold=threshold)
        indicators.extend(_from_image_indicator(result) for result in results)

    difference = None
    histograms = None
    quality = None
    if reference is not None:
        from app.analysis import quality_metrics

        # Amplified: a one-bit change is indistinguishable from black otherwise, which
        # is precisely the change a viewer is trying to see.
        difference = image_analysis.difference_image(reference, path, amplify=True)
        histograms = image_analysis.histogram_compare(reference, path, region=region)
        quality = quality_metrics.compare_quality(reference, path)

    return AnalysisReport(
        media_type=constants.MEDIA_IMAGE,
        path=path,
        indicators=tuple(indicators),
        bit_planes=image_analysis.extract_all_bit_planes(path, scaled=scaled_planes),
        difference=difference,
        histograms=histograms,
        quality=quality,
    )


def _audio_report(
    path: str, reference: str | None, threshold: float | None
) -> AnalysisReport:
    quality = None
    sample_difference = None

    if reference is not None:
        from app.analysis import quality_metrics

        quality = quality_metrics.compare_quality(reference, path)

        original, _ = audio_stego.read_audio(reference)
        stego, _ = audio_stego.read_audio(path)
        if original.shape == stego.shape:
            sample_difference = (
                stego.astype(np.int32).reshape(-1)
                - original.astype(np.int32).reshape(-1)
            )

    return AnalysisReport(
        media_type=constants.MEDIA_AUDIO,
        path=path,
        indicators=audio_indicators(path, threshold=threshold),
        quality=quality,
        sample_difference=sample_difference,
    )


def analyse(
    path: str | os.PathLike[str],
    *,
    reference: str | os.PathLike[str] | None = None,
    region: Region | None = None,
    threshold: float | None = None,
    scaled_planes: bool = True,
) -> AnalysisReport:
    """Analyse *path*, optionally against the original *reference*.

    A reference is not required. That is deliberate and it is the realistic case: an
    analyst examining a suspicious file does not have the original. Supplying one adds
    the difference image, the histogram comparison and the distortion metrics, none of
    which can be computed without it.

    :raises app.stego.errors.ComparisonError: the reference is a different medium, or
        analysis is not implemented for this medium.
    :raises app.stego.errors.DecodeError: the file is not a supported medium.
    """
    target = os.fspath(path)
    media_type = media.detect_media_type(target)

    reference_path = None
    if reference is not None:
        reference_path = os.fspath(reference)
        reference_type = media.detect_media_type(reference_path)
        if reference_type != media_type:
            raise ComparisonError(
                f"cannot compare {media_type} media with {reference_type} media"
            )

    if media_type == constants.MEDIA_IMAGE:
        return _image_report(
            target, reference_path, region, threshold, scaled_planes
        )
    if media_type == constants.MEDIA_AUDIO:
        return _audio_report(target, reference_path, threshold)

    # Video is carried and attacked, but not analysed here, and that is a scope
    # decision rather than an oversight. The indicators are per-sample statistics over
    # one homogeneous stream; a clip is hundreds of separate images, only a handful of
    # which carry anything, so a clip-wide figure would be dominated by the untouched
    # frames and a per-frame figure would be hundreds of numbers with no summary that
    # means anything. The Video tab shows the per-frame difference instead, which is
    # the question a viewer actually has.
    raise ComparisonError(
        f"steganalysis is not implemented for {media_type} media. For a clip, use "
        f"the Video tab to compare individual frames against the cover: a clip-wide "
        f"statistic would be dominated by the frames that carry no payload"
    )
