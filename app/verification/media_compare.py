"""Side-by-side property comparison of an original and a stego object.

Produces the table from the project plan: one row per property, with the original
value, the stego value, and whether they match.

    Original                 Stego
    Size       8.42 MB       8.42 MB       ok
    Duration   12.04 s       12.04 s       ok
    ...

Three points about how equality is reported, because each is easy to get wrong in
a way that misleads:

* **A differing SHA-256 is expected, not a fault.** Embedding changes the cover, so
  the digests of a cover and its stego object must differ. The row is reported as
  unequal and :attr:`MediaComparison.notes` explains why, rather than the row being
  hidden to make the table look clean.
* **Structural equality and content equality are separate.** Width, duration and
  sample rate should all match; sample values should not. The
  :attr:`MediaComparison.structure_identical` flag covers only the properties that
  ought to be unchanged, so a caller can assert on it meaningfully.
* **PNG file size may or may not match.** PNG is compressed, so changing low-order
  bits changes how well the data deflates. WAV and BMP store samples at fixed
  positions and normally do preserve size. The row states what happened and makes
  no promise either way.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from app.analysis import quality_metrics
from app.analysis.quality_metrics import QualityReport
from app.stego import audio_stego, image_io, media
from app.stego.errors import ComparisonError
from app.utils import constants, file_utils, media_utils

__all__ = [
    "ComparisonRow",
    "MediaComparison",
    "compare",
    "compare_audio",
    "compare_image",
    "compare_video",
]


@dataclass(frozen=True)
class ComparisonRow:
    """One property, as it stands in each file."""

    label: str
    original: str
    stego: str
    equal: bool
    #: ``False`` for rows that are not expected to match, such as the digest. Those
    #: are excluded from :attr:`MediaComparison.structure_identical`.
    structural: bool = True
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "original": self.original,
            "stego": self.stego,
            "equal": self.equal,
            "structural": self.structural,
            "note": self.note,
        }


@dataclass(frozen=True)
class MediaComparison:
    """The full comparison of two files."""

    media_type: str
    original_path: str
    stego_path: str
    rows: tuple[ComparisonRow, ...]
    quality: QualityReport | None = None
    notes: tuple[str, ...] = ()

    @property
    def structure_identical(self) -> bool:
        """Whether every property that ought to be unchanged is unchanged.

        Excludes rows marked non-structural, such as the digest and the file size,
        which legitimately differ.
        """
        return all(row.equal for row in self.rows if row.structural)

    @property
    def differing_rows(self) -> tuple[ComparisonRow, ...]:
        return tuple(row for row in self.rows if not row.equal)

    def as_dict(self) -> dict[str, Any]:
        return {
            "media_type": self.media_type,
            "original": file_utils.display_name(self.original_path),
            "stego": file_utils.display_name(self.stego_path),
            "structure_identical": self.structure_identical,
            "rows": [row.as_dict() for row in self.rows],
            "quality": None if self.quality is None else self.quality.as_dict(),
            "notes": list(self.notes),
        }

    def as_text(self) -> str:
        """Render the table as fixed-width text, for logs and the evidence folder."""
        label_width = max((len(row.label) for row in self.rows), default=8)
        original_width = max((len(row.original) for row in self.rows), default=8)
        stego_width = max((len(row.stego) for row in self.rows), default=8)

        lines = [
            f"{'':<{label_width}}  {'Original':<{original_width}}  "
            f"{'Stego':<{stego_width}}"
        ]
        for row in self.rows:
            marker = "ok" if row.equal else "differs"
            lines.append(
                f"{row.label:<{label_width}}  {row.original:<{original_width}}  "
                f"{row.stego:<{stego_width}}  {marker}"
            )
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #


def _row(
    label: str,
    original: Any,
    stego: Any,
    *,
    structural: bool = True,
    note: str | None = None,
) -> ComparisonRow:
    return ComparisonRow(
        label=label,
        original=str(original),
        stego=str(stego),
        equal=original == stego,
        structural=structural,
        note=note,
    )


_SIZE_NOTE = (
    "A differing size is not a fault. PNG is compressed, so changing low-order "
    "bits changes how well the data deflates. WAV and BMP store samples at fixed "
    "positions and normally do preserve size."
)

_DIGEST_NOTE = (
    "The digests are expected to differ: embedding changes the cover. Whole-file "
    "equality is not what verification establishes."
)


def _common_rows(original_path: str, stego_path: str) -> list[ComparisonRow]:
    original_size = os.path.getsize(original_path)
    stego_size = os.path.getsize(stego_path)

    return [
        ComparisonRow(
            label="File size",
            original=f"{file_utils.human_size(original_size)} ({original_size} B)",
            stego=f"{file_utils.human_size(stego_size)} ({stego_size} B)",
            equal=original_size == stego_size,
            structural=False,
            note=_SIZE_NOTE,
        ),
        ComparisonRow(
            label="SHA-256",
            original=file_utils.file_sha256(original_path)[:16] + "...",
            stego=file_utils.file_sha256(stego_path)[:16] + "...",
            equal=file_utils.file_sha256(original_path)
            == file_utils.file_sha256(stego_path),
            structural=False,
            note=_DIGEST_NOTE,
        ),
    ]


def _quality_or_none(
    original_path: str, stego_path: str, lsb_depth: int | None
) -> QualityReport | None:
    try:
        return quality_metrics.compare_quality(
            original_path, stego_path, lsb_depth=lsb_depth
        )
    except ComparisonError:
        # Different dimensions or channel counts: the properties table still has
        # something useful to say, so report it without the metrics rather than
        # failing the whole comparison.
        return None


# --------------------------------------------------------------------------- #
# Per-medium comparisons
# --------------------------------------------------------------------------- #


def compare_image(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    *,
    lsb_depth: int | None = None,
) -> MediaComparison:
    """Compare two image files."""
    original = os.fspath(original_path)
    stego = os.fspath(stego_path)

    first = image_io.describe_only(original)
    second = image_io.describe_only(stego)
    quality = _quality_or_none(original, stego, lsb_depth)

    rows = [
        _row("Container", first.container_format, second.container_format),
        _row("Width", first.width, second.width),
        _row("Height", first.height, second.height),
        _row("Channels", first.channel_count, second.channel_count),
        *_common_rows(original, stego),
    ]

    if quality is not None:
        rows.append(
            ComparisonRow(
                label="Pixels identical",
                original="-",
                stego="yes" if quality.identical else "no",
                equal=quality.identical,
                structural=False,
                note=(
                    "Pixel data is expected to differ after embedding; identical "
                    "pixels would mean nothing was written."
                ),
            )
        )

    notes = [_SIZE_NOTE, _DIGEST_NOTE]
    return MediaComparison(
        media_type=constants.MEDIA_IMAGE,
        original_path=original,
        stego_path=stego,
        rows=tuple(rows),
        quality=quality,
        notes=tuple(notes),
    )


def compare_audio(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    *,
    lsb_depth: int | None = None,
) -> MediaComparison:
    """Compare two audio files."""
    original = os.fspath(original_path)
    stego = os.fspath(stego_path)

    first = audio_stego.describe_only(original)
    second = audio_stego.describe_only(stego)
    quality = _quality_or_none(original, stego, lsb_depth)

    rows = [
        _row("Container", first.container_format, second.container_format),
        _row("Subtype", first.subtype, second.subtype),
        _row("Sample rate", f"{first.sample_rate} Hz", f"{second.sample_rate} Hz"),
        _row("Channels", first.channel_count, second.channel_count),
        _row("Frames", first.frame_count, second.frame_count),
        _row(
            "Duration",
            f"{first.duration_seconds:.3f} s",
            f"{second.duration_seconds:.3f} s",
        ),
        _row("Scalar samples", first.total_samples, second.total_samples),
        *_common_rows(original, stego),
    ]

    if quality is not None:
        rows.append(
            ComparisonRow(
                label="Samples changed",
                original="-",
                stego=(
                    f"{quality.changed_samples} of {quality.total_samples} "
                    f"({quality.changed_proportion * 100:.3f}%)"
                ),
                equal=quality.identical,
                structural=False,
                note=(
                    "Sample values are expected to differ after embedding."
                ),
            )
        )

    return MediaComparison(
        media_type=constants.MEDIA_AUDIO,
        original_path=original,
        stego_path=stego,
        rows=tuple(rows),
        quality=quality,
        notes=(_SIZE_NOTE, _DIGEST_NOTE),
    )


def compare_video(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    *,
    lsb_depth: int | None = None,
) -> MediaComparison:
    """Compare two video files.

    Container-level properties, plus frame-by-frame distortion when the two clips
    have the same shape. Both matter and neither substitutes for the other: the
    container tells you whether the codec changed, and the distortion tells you what
    the embedding did to the pixels.

    The size row is the least meaningful one for video, and the notes say so. A stego
    clip is always re-encoded as FFV1, so its size reflects the codec change far more
    than the payload.
    """
    original = os.fspath(original_path)
    stego = os.fspath(stego_path)

    try:
        first = media_utils.read_video_properties(original)
        second = media_utils.read_video_properties(stego)
    except media_utils.VideoInspectionError as exc:
        # Translated so a caller of this module catches one error family, exactly as
        # the audio branch translates audio_analysis's bare ValueError.
        raise ComparisonError(f"the two clips cannot be compared: {exc}") from exc

    rows = [
        _row("Resolution", first.resolution, second.resolution),
        _row("Frame rate", f"{first.frame_rate:.3f} fps", f"{second.frame_rate:.3f} fps"),
        _row("Frames", first.frame_count, second.frame_count),
        _row(
            "Duration",
            f"{first.duration_seconds:.3f} s",
            f"{second.duration_seconds:.3f} s",
        ),
        _row("Codec", first.codec, second.codec),
        *_common_rows(original, stego),
    ]

    quality = None
    notes = [
        _SIZE_NOTE,
        _DIGEST_NOTE,
        "Lossy re-encoding destroys an LSB payload, so a stego video must stay "
        "in a lossless codec for the payload to survive.",
    ]

    comparable = (
        (first.width, first.height, first.frame_count)
        == (second.width, second.height, second.frame_count)
    )
    if comparable:
        quality = quality_metrics.compare_quality(
            original, stego, lsb_depth=lsb_depth
        )
        notes.append(
            "The distortion figures are averaged over the whole clip. A payload "
            "occupies only a few frames, so the whole-clip average understates what "
            "happened to those frames; the worst-frame figure is the one to read."
        )
    else:
        notes.append(
            f"Frame-by-frame distortion was not computed: the clips differ in shape "
            f"({first.resolution} at {first.frame_count} frames against "
            f"{second.resolution} at {second.frame_count}). That difference is "
            f"itself the finding."
        )

    return MediaComparison(
        media_type=constants.MEDIA_VIDEO,
        original_path=original,
        stego_path=stego,
        rows=tuple(rows),
        quality=quality,
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


def compare(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    *,
    lsb_depth: int | None = None,
) -> MediaComparison:
    """Compare two files of the same medium, detected from their content.

    :raises app.stego.errors.ComparisonError: the two files are of different media
        types, which cannot be meaningfully compared.
    :raises app.stego.errors.DecodeError: either file is not a supported medium.
    """
    original = os.fspath(original_path)
    stego = os.fspath(stego_path)

    original_type = media.detect_media_type(original)
    stego_type = media.detect_media_type(stego)
    if original_type != stego_type:
        raise ComparisonError(
            f"cannot compare {file_utils.display_name(original)} "
            f"({original_type}) with {file_utils.display_name(stego)} "
            f"({stego_type}): they are different media types"
        )

    if original_type == constants.MEDIA_IMAGE:
        return compare_image(original, stego, lsb_depth=lsb_depth)
    if original_type == constants.MEDIA_AUDIO:
        return compare_audio(original, stego, lsb_depth=lsb_depth)
    return compare_video(original, stego, lsb_depth=lsb_depth)
