"""Attacks against an image cover object.

The interesting pair here is :func:`modify_pixels_inside_payload` and
:func:`modify_pixels_outside_payload`. They make the same kind of change in two
different places and produce opposite verdicts, which is the clearest way to show
what baseline verification does and does not cover:

* inside the payload region -> the signature no longer verifies
* outside the payload region -> the payload is untouched, so verification succeeds

The second is a genuine limitation of the scheme, not a bug, and the test suite
asserts it rather than avoiding it. The GUI states it through
:data:`app.utils.constants.AUTHENTIC_SCOPE_NOTICE`.
"""

from __future__ import annotations

import os

import numpy as np

from app.attacks.base import (
    AttackError,
    AttackOutcome,
    inside_payload_expected,
    payload_tail,
)
from app.stego import image_io, image_stego
from app.utils import constants, file_utils
from app.verification import verdicts

__all__ = [
    "blank_region",
    "invert_samples",
    "modify_pixels_inside_payload",
    "modify_pixels_outside_payload",
    "recompress_as_lossy",
]


def _load(path: str) -> tuple[np.ndarray, object]:
    try:
        return image_io.load_image(os.fspath(path))
    except Exception as exc:
        raise AttackError(
            f"{file_utils.display_name(path)} could not be read as an image: {exc}"
        ) from exc


def _save(array: np.ndarray, descriptor, output_path: str, overwrite: bool) -> str:
    target = os.fspath(output_path)
    image_io.save_image(array, target, descriptor.container_format, overwrite=overwrite)
    return target


def invert_samples(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    first: int,
    end: int,
    *,
    overwrite: bool = False,
) -> str:
    """Invert the embeddable samples ``[first, end)`` and write the result."""
    array, descriptor = _load(os.fspath(stego_path))
    flat, channels = image_stego.embeddable_stream(array)

    if first >= flat.size:
        raise AttackError(
            f"sample {first} lies beyond the image's {flat.size} embeddable samples"
        )

    modified = flat.copy()
    modified[first : min(end, flat.size)] ^= 0xFF

    stego = array.copy()
    stego[:, :, :channels] = modified.reshape(
        array.shape[0], array.shape[1], channels
    )
    return _save(stego, descriptor, output_path, overwrite)


def modify_pixels_inside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 64,
    overwrite: bool = False,
    ecc: object = None,
) -> AttackOutcome:
    """Invert the last samples of the payload region, where the signature lies.

    See :func:`app.attacks.base.payload_tail` for why the end of the region is the
    target rather than its start.
    """
    first, end = payload_tail(start_location, samples_written, sample_count)
    written = invert_samples(stego_path, output_path, first, end, overwrite=overwrite)

    return AttackOutcome(
        name="modify pixels inside the payload",
        output_path=written,
        description=(
            f"Inverted {end - first} samples, {first} to {end - 1}, at the end of the "
            f"payload region. They carry the signature, so the length header and the "
            f"framing still read and the damage reaches the signature check."
        ),
        expected_verdicts=inside_payload_expected(ecc),
        target="media",
        details={
            "samples_modified": end - first,
            "first_sample": first,
            "start_location": start_location,
        },
    )



def modify_pixels_outside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 64,
    overwrite: bool = False,
) -> AttackOutcome:
    """Invert samples outside the payload region.

    Verification still succeeds. That is the honest limitation of authenticating a
    signed message rather than the whole file, and it is demonstrated rather than
    hidden.
    """
    array, descriptor = _load(os.fspath(stego_path))
    flat, channels = image_stego.embeddable_stream(array)

    payload_end = start_location + samples_written
    remaining = flat.size - payload_end
    if remaining < 1:
        raise AttackError(
            "the payload occupies the image to its end, so there is no region "
            "outside it to modify; use a larger cover or a greater LSB depth"
        )

    begin = payload_end
    end = min(flat.size, begin + max(1, min(sample_count, remaining)))
    modified = flat.copy()
    modified[begin:end] ^= 0xFF

    stego = array.copy()
    stego[:, :, :channels] = modified.reshape(
        array.shape[0], array.shape[1], channels
    )
    written = _save(stego, descriptor, output_path, overwrite)

    return AttackOutcome(
        name="modify pixels outside the payload",
        output_path=written,
        description=(
            f"Inverted {end - begin} samples starting at sample {begin}, which is "
            f"past the end of the payload region. Verification is expected to "
            f"succeed: it authenticates the signed message, not the whole file."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_AUTHENTIC}),
        target="media",
        details={
            "samples_modified": end - begin,
            "payload_end": payload_end,
            "limitation": constants.AUTHENTIC_SCOPE_NOTICE,
        },
    )


def blank_region(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    left: int = 0,
    top: int = 0,
    width: int = 16,
    height: int = 16,
    overwrite: bool = False,
) -> AttackOutcome:
    """Set a rectangular region of the image to black.

    A visible, obviously destructive edit, of the kind a real image editor would
    make. Whether it breaks verification depends on whether the rectangle overlaps
    the payload region.
    """
    array, descriptor = _load(os.fspath(stego_path))
    rows, columns = array.shape[0], array.shape[1]

    if left < 0 or top < 0 or width <= 0 or height <= 0:
        raise AttackError("the region offsets must be non-negative and its size positive")
    if left >= columns or top >= rows:
        raise AttackError(
            f"the region starts outside the {columns}x{rows} image"
        )

    right = min(columns, left + width)
    bottom = min(rows, top + height)

    stego = array.copy()
    stego[top:bottom, left:right, :] = 0
    written = _save(stego, descriptor, output_path, overwrite)

    return AttackOutcome(
        name="blank a region",
        output_path=written,
        description=(
            f"Set the {right - left}x{bottom - top} region at ({left}, {top}) to "
            f"black, as an image editor would."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_AUTHENTIC,
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "left": left,
            "top": top,
            "width": right - left,
            "height": bottom - top,
            "note": (
                "The outcome depends on whether the region overlaps the payload."
            ),
        },
    )


def recompress_as_lossy(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    quality: int = 85,
    overwrite: bool = False,
) -> AttackOutcome:
    """Re-encode the stego image as JPEG, destroying the payload.

    The output is deliberately unreadable by this application: the verifier refuses
    lossy input by design. The point of the attack is to show that a payload cannot
    survive lossy recompression, which is why the supported formats are PNG and BMP.
    """
    from PIL import Image

    array, _ = _load(os.fspath(stego_path))
    target = os.fspath(output_path)
    if os.path.exists(target) and not overwrite:
        raise AttackError(
            f"attack output path is already occupied: "
            f"{file_utils.display_name(target)}"
        )

    if array.shape[2] == 1:
        image = Image.fromarray(array[:, :, 0], mode="L")
    else:
        image = Image.fromarray(array[:, :, :3], mode="RGB")
    image.save(target, format="JPEG", quality=quality)

    return AttackOutcome(
        name="re-encode as lossy JPEG",
        output_path=target,
        description=(
            f"Re-encoded the stego image as JPEG at quality {quality}. Lossy "
            f"compression does not preserve low-order bits, so the payload is "
            f"destroyed and the file is no longer a supported cover object."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_CANNOT_VERIFY}),
        target="media",
        details={
            "quality": quality,
            "note": (
                "The verifier refuses lossy input, so this is reported as an "
                "unreadable cover rather than as a missing payload."
            ),
        },
    )
