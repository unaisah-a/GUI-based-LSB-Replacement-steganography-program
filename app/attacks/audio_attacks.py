"""Attacks against an audio cover object.

Mirrors :mod:`app.attacks.image_attacks`, including the inside/outside pair that
demonstrates the scope of what verification establishes.

Two attacks here are specific to audio and worth having, because they are what
would actually happen to a WAV in transit rather than under deliberate attack:

* :func:`scale_amplitude` changes every sample slightly, as a volume adjustment
  would. It destroys the payload completely, which is the honest answer to "is this
  robust to processing?".
* :func:`resample` changes the sample rate. Same outcome, for the same reason.

Neither is survivable by LSB embedding, and the tests assert that rather than
implying some resilience the scheme does not have.
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
from app.stego import audio_stego
from app.utils import constants, file_utils
from app.verification import verdicts

__all__ = [
    "corrupt_samples_inside_payload",
    "corrupt_samples_outside_payload",
    "invert_samples",
    "resample",
    "scale_amplitude",
    "truncate_audio",
]


def _load(path: str) -> tuple[np.ndarray, audio_stego.AudioDescriptor]:
    try:
        return audio_stego.read_audio(os.fspath(path))
    except Exception as exc:
        raise AttackError(
            f"{file_utils.display_name(path)} could not be read as audio: {exc}"
        ) from exc


def _save(
    samples: np.ndarray,
    descriptor: audio_stego.AudioDescriptor,
    output_path: str,
    overwrite: bool,
    *,
    sample_rate: int | None = None,
) -> str:
    target = os.fspath(output_path)
    audio_stego.write_audio(
        samples,
        target,
        sample_rate if sample_rate is not None else descriptor.sample_rate,
        overwrite=overwrite,
    )
    return target


def invert_samples(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    first: int,
    end: int,
    *,
    overwrite: bool = False,
) -> str:
    """Invert the low byte of samples ``[first, end)`` and write the result."""
    samples, descriptor = _load(os.fspath(stego_path))
    flat, _ = audio_stego.embeddable_stream(samples)

    if first >= flat.size:
        raise AttackError(f"sample {first} lies beyond the file's {flat.size} samples")

    modified = flat.copy()
    # Invert only the low byte, so the change is audible-scale rather than a
    # full-scale sample inversion that would sound like a click.
    modified[first : min(end, flat.size)] ^= np.uint16(0x00FF)

    return _save(
        modified.view(np.int16).reshape(samples.shape),
        descriptor,
        output_path,
        overwrite,
    )


def corrupt_samples_inside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 64,
    overwrite: bool = False,
    ecc: object = None,
) -> AttackOutcome:
    """Invert the low byte of the last samples of the payload region.

    See :func:`app.attacks.base.payload_tail` for why the end of the region is the
    target rather than its start.
    """
    first, end = payload_tail(start_location, samples_written, sample_count)
    written = invert_samples(stego_path, output_path, first, end, overwrite=overwrite)

    return AttackOutcome(
        name="corrupt samples inside the payload",
        output_path=written,
        description=(
            f"Inverted the low byte of {end - first} samples, {first} to {end - 1}, "
            f"at the end of the payload region. They carry the signature, so the "
            f"length header and the framing still read and the damage reaches the "
            f"signature check."
        ),
        expected_verdicts=inside_payload_expected(ecc),
        target="media",
        details={
            "samples_modified": end - first,
            "first_sample": first,
            "start_location": start_location,
        },
    )


def corrupt_samples_outside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 64,
    overwrite: bool = False,
) -> AttackOutcome:
    """Invert the low bits of samples outside the payload region.

    Verification still succeeds, for the same reason as the image equivalent.
    """
    samples, descriptor = _load(os.fspath(stego_path))
    flat, _ = audio_stego.embeddable_stream(samples)

    payload_end = start_location + samples_written
    remaining = flat.size - payload_end
    if remaining < 1:
        raise AttackError(
            "the payload occupies the file to its end, so there is no region "
            "outside it to modify; use a longer cover or a greater LSB depth"
        )

    begin = payload_end
    end = min(flat.size, begin + max(1, min(sample_count, remaining)))
    modified = flat.copy()
    modified[begin:end] ^= np.uint16(0x00FF)

    written = _save(
        modified.view(np.int16).reshape(samples.shape),
        descriptor,
        output_path,
        overwrite,
    )

    return AttackOutcome(
        name="corrupt samples outside the payload",
        output_path=written,
        description=(
            f"Inverted the low byte of {end - begin} samples starting at sample "
            f"{begin}, past the end of the payload region. Verification is expected "
            f"to succeed: it authenticates the signed message, not the whole file."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_AUTHENTIC}),
        target="media",
        details={
            "samples_modified": end - begin,
            "payload_end": payload_end,
            "limitation": constants.AUTHENTIC_SCOPE_NOTICE,
        },
    )


def scale_amplitude(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    factor: float = 0.9,
    overwrite: bool = False,
) -> AttackOutcome:
    """Scale every sample, as a volume adjustment would.

    Destroys the payload completely: scaling changes low-order bits everywhere. LSB
    embedding is not robust to this, and the demonstration should say so.
    """
    if factor <= 0:
        raise AttackError(f"factor must be positive, got {factor}")

    samples, descriptor = _load(os.fspath(stego_path))
    scaled = np.clip(
        np.rint(samples.astype(np.float64) * factor), -32768, 32767
    ).astype(np.int16)
    written = _save(scaled, descriptor, output_path, overwrite)

    changed = int(np.count_nonzero(scaled != samples))
    return AttackOutcome(
        name="scale amplitude",
        output_path=written,
        description=(
            f"Multiplied every sample by {factor}, changing {changed} of "
            f"{samples.size} samples. A volume adjustment destroys an LSB payload."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "factor": factor,
            "samples_changed": changed,
            "total_samples": int(samples.size),
        },
    )


def resample(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    target_rate: int = 22_050,
    overwrite: bool = False,
) -> AttackOutcome:
    """Resample to a different rate, destroying the payload.

    Implemented by nearest-neighbour selection rather than a proper filter. That is
    deliberate: the point is to show that the sample positions change, not to
    produce good-sounding audio, and a filter would only make the destruction more
    thorough.
    """
    if target_rate <= 0:
        raise AttackError(f"target_rate must be positive, got {target_rate}")

    samples, descriptor = _load(os.fspath(stego_path))
    ratio = target_rate / descriptor.sample_rate
    new_frame_count = max(1, int(descriptor.frame_count * ratio))
    indices = np.clip(
        np.rint(np.arange(new_frame_count) / ratio).astype(np.int64),
        0,
        descriptor.frame_count - 1,
    )
    resampled = samples[indices]

    written = _save(
        resampled, descriptor, output_path, overwrite, sample_rate=target_rate
    )

    return AttackOutcome(
        name="resample",
        output_path=written,
        description=(
            f"Resampled from {descriptor.sample_rate} Hz to {target_rate} Hz, "
            f"changing the frame count from {descriptor.frame_count} to "
            f"{new_frame_count}. Sample positions move, so the payload is destroyed."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "original_rate": descriptor.sample_rate,
            "target_rate": target_rate,
            "original_frames": descriptor.frame_count,
            "new_frames": new_frame_count,
        },
    )


def truncate_audio(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    keep_fraction: float = 0.5,
    overwrite: bool = False,
) -> AttackOutcome:
    """Cut the recording short."""
    if not 0 < keep_fraction < 1:
        raise AttackError(
            f"keep_fraction must be between 0 and 1 exclusive, got {keep_fraction}"
        )

    samples, descriptor = _load(os.fspath(stego_path))
    keep_frames = max(1, int(descriptor.frame_count * keep_fraction))
    written = _save(samples[:keep_frames], descriptor, output_path, overwrite)

    return AttackOutcome(
        name="truncate audio",
        output_path=written,
        description=(
            f"Kept the first {keep_frames} of {descriptor.frame_count} frames. "
            f"Whether the payload survives depends on whether it lay within the "
            f"retained portion."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_AUTHENTIC,
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_WRONG_START_LOCATION,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "original_frames": descriptor.frame_count,
            "kept_frames": keep_frames,
            "note": (
                "A derived start location depends on the total sample count, so "
                "truncation also moves where the receiver looks."
            ),
        },
    )
