"""Attacks against a video cover object.

Video repeats the image layer's inside/outside pair, because the lesson is the same
and worth showing on a third medium. What it adds are two attacks that have no
image equivalent, and both are the ones a real clip is most likely to meet:

:func:`recompress_lossy`
    Every ordinary thing done to a video — uploading it, sending it through a chat
    app, editing it in anything — re-encodes it with a lossy codec. This is
    therefore not an exotic attack but the *default* fate of a clip, and it
    destroys the payload completely.

:func:`drop_frames`
    Cutting frames out shifts the flat sample domain and changes the frame count,
    so the receiver both measures a different domain and derives a different start
    location. The payload is still physically present in the surviving frames and
    is nonetheless unfindable, which shows what the keyed derivation is doing.

Which lossy codec
-----------------
H.264 would be the natural choice and is what these clips would meet in the wild,
but ``opencv-python`` ships without the OpenH264 library on many installations,
including this one, so requesting it produces an encoder that fails to open. Rather
than depend on that, :func:`recompress_lossy` tries a short list of lossy codecs
and uses the first the installed build can actually open. Motion JPEG is the usual
winner. It is lossy for the same reason H.264 is — block DCT with quantisation —
so the demonstration is unaffected, and the codec actually used is reported in the
outcome rather than assumed.
"""

from __future__ import annotations

import os
import tempfile
from typing import Final, Iterator

import numpy as np

from app.attacks.base import AttackError, AttackOutcome
from app.stego import video_stego
from app.stego.errors import StegoError
from app.utils import constants, file_utils
from app.verification import verdicts

__all__ = [
    "LOSSY_CODEC_CANDIDATES",
    "corrupt_samples_inside_payload",
    "corrupt_samples_outside_payload",
    "drop_frames",
    "recompress_lossy",
]

#: Tried in order; the first the installed OpenCV build can open is used. Each
#: entry is a FourCC and the container extension it needs.
LOSSY_CODEC_CANDIDATES: Final[tuple[tuple[str, str], ...]] = (
    ("avc1", ".mp4"),  # H.264, if OpenH264 happens to be installed
    ("mp4v", ".mp4"),  # MPEG-4 Part 2
    ("MJPG", ".avi"),  # Motion JPEG; almost always available
    ("XVID", ".avi"),
)


def _describe(path: str) -> video_stego.VideoDescriptor:
    try:
        return video_stego.describe_only(path)
    except StegoError as exc:
        raise AttackError(
            f"{file_utils.display_name(path)} could not be read as a video file: "
            f"{exc}"
        ) from exc


def _write(
    frames: Iterator[np.ndarray],
    output_path: str,
    descriptor: video_stego.VideoDescriptor,
    overwrite: bool,
) -> str:
    """Write modified frames back out losslessly, so only the attack changed them."""
    try:
        video_stego.write_frames(
            frames, output_path, descriptor, overwrite=overwrite
        )
    except StegoError as exc:
        raise AttackError(f"the attacked clip could not be written: {exc}") from exc
    return os.fspath(output_path)


def _corrupt_range(
    stego_path: str,
    output_path: str,
    descriptor: video_stego.VideoDescriptor,
    begin: int,
    end: int,
    overwrite: bool,
) -> str:
    """Invert every sample in the flat range ``[begin, end)`` and re-encode."""
    per_frame = descriptor.samples_per_frame

    def modified() -> Iterator[np.ndarray]:
        for index, frame in enumerate(
            video_stego.iterate_frames(stego_path, descriptor)
        ):
            base = index * per_frame
            low = max(begin, base)
            high = min(end, base + per_frame)
            if low < high:
                flat = frame.reshape(-1)
                flat[low - base : high - base] ^= 0xFF
            yield frame

    return _write(modified(), output_path, descriptor, overwrite)


def corrupt_samples_inside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 256,
    overwrite: bool = False,
) -> AttackOutcome:
    """Invert samples inside the region carrying the payload."""
    source = os.fspath(stego_path)
    descriptor = _describe(source)

    if start_location >= descriptor.total_samples:
        raise AttackError(
            f"start location {start_location} lies beyond the clip's "
            f"{descriptor.total_samples} samples"
        )

    end = min(
        descriptor.total_samples,
        start_location + max(1, min(sample_count, samples_written)),
    )
    written = _corrupt_range(
        source, os.fspath(output_path), descriptor, start_location, end, overwrite
    )

    first_frame = start_location // descriptor.samples_per_frame
    last_frame = (end - 1) // descriptor.samples_per_frame

    return AttackOutcome(
        name="corrupt samples inside the payload",
        output_path=written,
        description=(
            f"Inverted {end - start_location} samples from sample "
            f"{start_location}, inside the payload region, spanning frames "
            f"{first_frame} to {last_frame}."
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
            "samples_modified": end - start_location,
            "start_location": start_location,
            "first_frame": first_frame,
            "last_frame": last_frame,
        },
    )


def corrupt_samples_outside_payload(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    start_location: int,
    samples_written: int,
    *,
    sample_count: int = 256,
    overwrite: bool = False,
) -> AttackOutcome:
    """Invert samples past the payload region.

    Verification still succeeds, exactly as with an image. Repeated on video
    because a viewer's intuition that "the video has visibly changed, so it must
    fail" is strongest here, and it is wrong: what was authenticated is the signed
    message, not the clip.
    """
    source = os.fspath(stego_path)
    descriptor = _describe(source)

    payload_end = start_location + samples_written
    remaining = descriptor.total_samples - payload_end
    if remaining < 1:
        raise AttackError(
            "the payload occupies the clip to its end, so there is no region "
            "outside it to modify; use a longer clip or a greater LSB depth"
        )

    end = min(
        descriptor.total_samples, payload_end + max(1, min(sample_count, remaining))
    )
    written = _corrupt_range(
        source, os.fspath(output_path), descriptor, payload_end, end, overwrite
    )

    return AttackOutcome(
        name="corrupt samples outside the payload",
        output_path=written,
        description=(
            f"Inverted {end - payload_end} samples from sample {payload_end}, past "
            f"the end of the payload region. Verification is expected to succeed: "
            f"it authenticates the signed message, not the whole clip."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_AUTHENTIC}),
        target="media",
        details={
            "samples_modified": end - payload_end,
            "payload_end": payload_end,
            "limitation": constants.AUTHENTIC_SCOPE_NOTICE,
        },
    )


def drop_frames(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    drop_first: int = 1,
    overwrite: bool = False,
) -> AttackOutcome:
    """Remove frames from the start of the clip, as a trim would.

    Two things break at once, and both are worth naming. The frame count changes,
    so the receiver measures a smaller sample domain and the keyed derivation lands
    somewhere else entirely. And every surviving sample has shifted backwards by a
    whole frame's worth of positions, so even the right start location would now
    point at the wrong bits.

    The payload bytes are still in the file. They are simply no longer findable,
    which is the clearest demonstration of what the derivation contributes.
    """
    source = os.fspath(stego_path)
    descriptor = _describe(source)

    if drop_first < 1:
        raise AttackError(f"drop_first must be at least 1, got {drop_first}")
    if drop_first >= descriptor.frame_count:
        raise AttackError(
            f"dropping {drop_first} frames would empty a {descriptor.frame_count}"
            f"-frame clip; drop fewer"
        )

    def survivors() -> Iterator[np.ndarray]:
        for index, frame in enumerate(
            video_stego.iterate_frames(source, descriptor)
        ):
            if index >= drop_first:
                yield frame

    written = _write(survivors(), os.fspath(output_path), descriptor, overwrite)

    return AttackOutcome(
        name="drop frames",
        output_path=written,
        description=(
            f"Removed the first {drop_first} of {descriptor.frame_count} frames. "
            f"The payload bytes are still in the file, but the clip now has a "
            f"different sample domain and every position has shifted, so the "
            f"receiver cannot find them."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_WRONG_START_LOCATION,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "frames_dropped": drop_first,
            "frames_before": descriptor.frame_count,
            "frames_after": descriptor.frame_count - drop_first,
            "samples_shifted_by": drop_first * descriptor.samples_per_frame,
        },
    )


def _open_lossy_writer(
    descriptor: video_stego.VideoDescriptor, directory: str
) -> tuple[object, str, str]:
    """Return an opened lossy writer, the file it writes to, and its codec name.

    Tries the candidates in order because codec availability is a property of the
    installed FFmpeg build, not of this application, and hardcoding one would make
    the attack fail on a machine that is otherwise fine. See the module docstring.
    """
    import cv2

    attempted: list[str] = []
    for codec, extension in LOSSY_CODEC_CANDIDATES:
        handle, temporary = tempfile.mkstemp(
            prefix=".lossy-", suffix=extension, dir=directory
        )
        os.close(handle)
        writer = cv2.VideoWriter(
            temporary,
            cv2.VideoWriter_fourcc(*codec),
            float(descriptor.frame_rate),
            (descriptor.width, descriptor.height),
        )
        if writer.isOpened():
            return writer, temporary, codec
        writer.release()
        try:
            os.unlink(temporary)
        except OSError:
            pass
        attempted.append(codec)

    raise AttackError(
        f"the installed OpenCV build could not open any lossy encoder; tried "
        f"{', '.join(attempted)}. This attack needs one to demonstrate that lossy "
        f"re-encoding destroys the payload"
    )


def recompress_lossy(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> AttackOutcome:
    """Re-encode the clip with a lossy codec, destroying the payload.

    The single most important video attack, because it is what happens to a clip
    by accident. Nothing about the pixels is preserved at bit level, so the payload
    is gone whether or not anyone was attacking.

    The result is written under *output_path*'s directory with whatever extension
    the chosen codec's container needs, so the returned path may not be exactly the
    one requested. That is reported rather than hidden.
    """
    source = os.fspath(stego_path)
    descriptor = _describe(source)

    target = os.fspath(output_path)
    directory = os.path.dirname(os.path.abspath(target)) or "."
    if not os.path.isdir(directory):
        raise AttackError(
            f"attack output directory does not exist for "
            f"{file_utils.display_name(target)}"
        )

    writer, temporary, codec = _open_lossy_writer(descriptor, directory)
    extension = os.path.splitext(temporary)[1]
    final = os.path.splitext(target)[0] + extension

    if os.path.exists(final) and not overwrite:
        writer.release()
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise AttackError(
            f"attack output path is already occupied: "
            f"{file_utils.display_name(final)}"
        )

    written = 0
    try:
        for frame in video_stego.iterate_frames(source, descriptor):
            writer.write(frame)
            written += 1
    finally:
        writer.release()

    if written == 0:  # pragma: no cover - guarded by describe_only
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise AttackError(f"no frames could be decoded from {descriptor.file_name}")

    os.replace(temporary, final)

    return AttackOutcome(
        name="re-encode with a lossy codec",
        output_path=final,
        description=(
            f"Re-encoded all {written} frames with the {codec} codec. Lossy "
            f"compression does not preserve low-order bits, so the payload is "
            f"destroyed. This is what an upload, a share or an edit does to a clip "
            f"by default, not only what a deliberate attacker does."
        ),
        expected_verdicts=frozenset(
            {
                verdicts.VERDICT_PAYLOAD_MISSING,
                verdicts.VERDICT_SIGNATURE_INVALID,
                verdicts.VERDICT_WRONG_START_LOCATION,
                verdicts.VERDICT_CANNOT_VERIFY,
            }
        ),
        target="media",
        details={
            "codec": codec,
            "frames": written,
            "container": extension.lstrip("."),
            "note": (
                "The codec is chosen from those the installed OpenCV build can "
                "open, so it may differ between machines. All the candidates are "
                "lossy in the same way."
            ),
        },
    )
