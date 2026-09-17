"""One quality report for every medium.

:mod:`app.analysis.image_analysis` and :mod:`app.analysis.audio_analysis` were
written independently and report in different shapes: the image module returns a
frozen ``QualityComparison`` dataclass with per-channel detail, the audio module
returns a flat dictionary with different key names. Both are worth keeping as they
are — each reports things the other has no concept of — so this module maps the
figures they have in common onto one :class:`QualityReport`.

What "in common" means here
---------------------------
MSE and PSNR are defined the same way for every medium, given a peak sample value:
255 for 8-bit image and video channels, 32767 for 16-bit PCM. SNR is meaningful for
audio and is reported as ``None`` for the other two rather than invented. The bound
for a given LSB depth, ``2**depth - 1``, is the same for all three and is checked
against the observed maximum difference, which is a cheap way to catch an
embedding that wrote more than it claimed.

Video has no module of its own to delegate to, so :func:`_video_report` does the
arithmetic here, accumulating frame by frame rather than over a decoded array. It
also reports a per-frame worst case, because a clip-wide average is misleading for
video in a way it is not for the other two media: the payload occupies a few frames
out of hundreds, so averaging over the untouched ones makes any embedding look
negligible.

This module returns data and no rendered output, so it imports no GUI toolkit and
no plotting library.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Any

from app.analysis import audio_analysis, image_analysis
from app.stego import media
from app.utils import constants

__all__ = [
    "ChannelQuality",
    "QualityReport",
    "compare_quality",
    "distortion_bound",
]


def distortion_bound(lsb_depth: int) -> int:
    """Return the largest per-sample change that replacing *lsb_depth* bits can cause.

    Replacing the low ``n`` bits can move a sample by at most ``2**n - 1``, whatever
    the medium. An observed difference above this means more was written than the
    depth accounts for.
    """
    if isinstance(lsb_depth, bool) or not isinstance(lsb_depth, int):
        raise TypeError(f"lsb_depth must be an integer, got {type(lsb_depth).__name__}")
    if not constants.MIN_LSB_DEPTH <= lsb_depth <= constants.MAX_LSB_DEPTH:
        raise ValueError(
            f"lsb_depth must be from {constants.MIN_LSB_DEPTH} to "
            f"{constants.MAX_LSB_DEPTH} inclusive, got {lsb_depth}"
        )
    return (1 << lsb_depth) - 1


@dataclass(frozen=True)
class ChannelQuality:
    """Per-channel figures. Image media only; audio reports whole-signal figures."""

    label: str
    mse: float
    psnr_db: float
    psnr_unbounded: bool


@dataclass(frozen=True)
class QualityReport:
    """Distortion between an original and a modified file, in shared terms."""

    media_type: str
    mse: float
    psnr_db: float
    #: ``True`` when the two files are identical, so PSNR is infinite. Lets a
    #: caller render that case without parsing the number.
    psnr_unbounded: bool
    max_absolute_difference: float
    changed_samples: int
    total_samples: int
    identical: bool
    #: Audio only. ``None`` for images, where it has no accepted definition.
    snr_db: float | None = None
    channels: tuple[ChannelQuality, ...] = ()
    #: Set when a depth was supplied: whether the observed maximum difference is
    #: within ``2**depth - 1``.
    within_distortion_bound: bool | None = None
    expected_distortion_bound: int | None = None
    #: Figures specific to one medium, kept rather than discarded.
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra", dict(self.extra))

    @property
    def changed_proportion(self) -> float:
        return self.changed_samples / self.total_samples if self.total_samples else 0.0

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly summary for the GUI and the evidence log."""
        return {
            "media_type": self.media_type,
            "mse": self.mse,
            "psnr_db": None if self.psnr_unbounded else self.psnr_db,
            "psnr_unbounded": self.psnr_unbounded,
            "snr_db": self.snr_db,
            "max_absolute_difference": self.max_absolute_difference,
            "changed_samples": self.changed_samples,
            "total_samples": self.total_samples,
            "changed_proportion": self.changed_proportion,
            "identical": self.identical,
            "within_distortion_bound": self.within_distortion_bound,
            "expected_distortion_bound": self.expected_distortion_bound,
            "channels": [
                {
                    "label": channel.label,
                    "mse": channel.mse,
                    "psnr_db": None if channel.psnr_unbounded else channel.psnr_db,
                }
                for channel in self.channels
            ],
            "extra": dict(self.extra),
        }


def _image_report(
    original_path: str, stego_path: str, lsb_depth: int | None
) -> QualityReport:
    comparison = image_analysis.compare_quality(original_path, stego_path)
    bound = None if lsb_depth is None else distortion_bound(lsb_depth)

    return QualityReport(
        media_type=constants.MEDIA_IMAGE,
        mse=comparison.overall_mse,
        psnr_db=comparison.overall_psnr_db,
        psnr_unbounded=comparison.overall_psnr_unbounded,
        max_absolute_difference=float(comparison.max_absolute_difference),
        changed_samples=comparison.differing_samples,
        total_samples=comparison.total_samples,
        identical=comparison.pixel_identical,
        snr_db=None,
        channels=tuple(
            ChannelQuality(
                label=channel.label,
                mse=channel.mse,
                psnr_db=channel.psnr_db,
                psnr_unbounded=channel.psnr_unbounded,
            )
            for channel in comparison.channels
        ),
        within_distortion_bound=(
            None if bound is None else comparison.max_absolute_difference <= bound
        ),
        expected_distortion_bound=bound,
        extra={
            "height": comparison.height,
            "width": comparison.width,
            "channel_count": comparison.channel_count,
            "dimensions_equal": comparison.dimensions_equal,
            "channel_count_equal": comparison.channel_count_equal,
        },
    )


def _audio_report(
    original_path: str, stego_path: str, lsb_depth: int | None
) -> QualityReport:
    from app.stego.errors import ComparisonError

    try:
        report = audio_analysis.calculate_quality_report(
            original_path, stego_path, lsb_count=lsb_depth
        )
    except ValueError as exc:
        # audio_analysis predates the shared error hierarchy and raises bare
        # ValueError when the two files differ in sample rate, channel count or
        # length. Translated here so a caller of this facade sees the same
        # ComparisonError it would get for a pair of mismatched images, rather
        # than having to catch two unrelated exception types.
        raise ComparisonError(
            f"the two audio files cannot be compared: {exc}"
        ) from exc
    bound = None if lsb_depth is None else distortion_bound(lsb_depth)
    psnr = report["psnr_db"]
    unbounded = math.isinf(psnr)

    return QualityReport(
        media_type=constants.MEDIA_AUDIO,
        mse=report["mse"],
        psnr_db=psnr,
        psnr_unbounded=unbounded,
        max_absolute_difference=report["max_absolute_difference"],
        changed_samples=report["changed_samples"],
        total_samples=report["total_scalar_samples"],
        identical=report["changed_samples"] == 0,
        snr_db=report["snr_db"],
        within_distortion_bound=(
            None
            if bound is None
            else report["max_absolute_difference"] <= bound
        ),
        expected_distortion_bound=bound,
        extra={
            "sample_rate": report["sample_rate"],
            "channels": report["channels"],
            "total_frames": report["total_frames"],
            "duration_seconds": report["duration_seconds"],
            "rmse": report["rmse"],
            "mae": report["mae"],
            "changed_percentage": report["changed_percentage"],
        },
    )


def _video_report(
    original_path: str, stego_path: str, lsb_depth: int | None
) -> QualityReport:
    """Compare two clips frame by frame.

    Unlike the other two media there is no existing module to delegate to, so the
    arithmetic is here. It is accumulated frame by frame rather than over a decoded
    array, because a clip large enough to be interesting does not fit in memory
    twice.

    A *per-frame* worst case is reported alongside the whole-clip figures, because a
    clip-wide average hides the thing a viewer would actually notice: the payload
    occupies a handful of frames, so those few are distorted while the rest are
    untouched, and an average over hundreds of clean frames makes any embedding look
    negligible.
    """
    import numpy as np

    from app.stego import video_stego
    from app.stego.errors import ComparisonError

    cover = video_stego.describe_only(original_path)
    stego = video_stego.describe_only(stego_path)

    if (cover.width, cover.height) != (stego.width, stego.height):
        raise ComparisonError(
            f"the two clips cannot be compared: {cover.resolution} against "
            f"{stego.resolution}"
        )
    if cover.frame_count != stego.frame_count:
        raise ComparisonError(
            f"the two clips cannot be compared: {cover.frame_count} frames against "
            f"{stego.frame_count}"
        )

    peak = 255.0
    squared_error = 0
    changed = 0
    largest = 0
    counted = 0
    frames_changed = 0
    worst_index = -1
    worst_mse = 0.0

    pairs = zip(
        video_stego.iterate_frames(original_path, cover),
        video_stego.iterate_frames(stego_path, stego),
    )
    for index, (left, right) in enumerate(pairs):
        a = left.reshape(-1).astype(np.int32)
        b = right.reshape(-1).astype(np.int32)
        difference = np.abs(a - b)

        frame_error = int(np.sum(difference.astype(np.int64) ** 2))
        frame_changed = int(np.count_nonzero(difference))

        squared_error += frame_error
        changed += frame_changed
        counted += int(difference.size)
        largest = max(largest, int(difference.max(initial=0)))

        if frame_changed:
            frames_changed += 1
            frame_mse = frame_error / difference.size
            if frame_mse > worst_mse:
                worst_mse = frame_mse
                worst_index = index

    if counted == 0:  # pragma: no cover - describe_only rejects empty clips
        raise ComparisonError("neither clip decoded to any frames")

    mse = squared_error / counted
    unbounded = mse == 0.0
    psnr = math.inf if unbounded else 10.0 * math.log10(peak * peak / mse)
    worst_psnr = (
        None if worst_mse <= 0 else 10.0 * math.log10(peak * peak / worst_mse)
    )
    bound = None if lsb_depth is None else distortion_bound(lsb_depth)

    return QualityReport(
        media_type=constants.MEDIA_VIDEO,
        mse=mse,
        psnr_db=psnr,
        psnr_unbounded=unbounded,
        max_absolute_difference=float(largest),
        changed_samples=changed,
        total_samples=counted,
        identical=changed == 0,
        snr_db=None,
        within_distortion_bound=(None if bound is None else largest <= bound),
        expected_distortion_bound=bound,
        extra={
            "width": cover.width,
            "height": cover.height,
            "frame_count": cover.frame_count,
            "frame_rate": cover.frame_rate,
            "cover_codec": cover.codec,
            "stego_codec": stego.codec,
            "frames_changed": frames_changed,
            "worst_frame_index": worst_index,
            "worst_frame_mse": worst_mse,
            "worst_frame_psnr_db": worst_psnr,
        },
    )


def compare_quality(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    *,
    lsb_depth: int | None = None,
) -> QualityReport:
    """Compare two files of the same medium and report the distortion.

    The medium is detected from *original_path*'s content. Supplying *lsb_depth*
    additionally checks the observed maximum difference against the theoretical
    bound for that depth.

    :raises app.stego.errors.DecodeError: the medium is unsupported, or the two
        files are of different media types.
    """
    original = os.fspath(original_path)
    stego = os.fspath(stego_path)

    media_type = media.detect_media_type(original)
    stego_media_type = media.detect_media_type(stego)
    if media_type != stego_media_type:
        from app.stego.errors import ComparisonError

        raise ComparisonError(
            f"cannot compare {media_type} media with {stego_media_type} media"
        )

    if media_type == constants.MEDIA_IMAGE:
        return _image_report(original, stego, lsb_depth)
    if media_type == constants.MEDIA_AUDIO:
        return _audio_report(original, stego, lsb_depth)
    if media_type == constants.MEDIA_VIDEO:
        return _video_report(original, stego, lsb_depth)

    from app.stego.errors import ComparisonError

    raise ComparisonError(
        f"quality comparison is not implemented for {media_type} media"
    )
