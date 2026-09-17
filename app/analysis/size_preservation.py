"""Can a stego file be made exactly the same size as its cover?

The project plan asks this to be *investigated* and the answer *recorded*, not
assumed, and explicitly warns against claiming it works in general unless testing
shows it does. This module runs the experiment and reports what happened, including
the failures.

Why the answer differs by container
-----------------------------------
The distinction that matters is whether the container stores samples at a fixed
position and width, or compresses them.

``WAV`` and ``BMP`` store samples literally, so replacing low-order bits changes
byte *values* and not byte *counts*. Size preservation is not something to achieve
here; it is unavoidable, and the experiment's job is to confirm it rather than to
work for it.

``PNG`` runs the pixel data through DEFLATE. Altering low bits makes the data more
or less compressible, so the compressed stream changes length in a direction nobody
controls. Two things follow, and both are demonstrated below rather than argued:

* the size usually **grows**, because LSB replacement pushes low bits toward random
  and random data does not compress, and
* when it happens to shrink, the difference *can* be made up exactly, because PNG
  allows arbitrary ancillary chunks.

``video`` is a re-encode from end to end, so the output size has essentially no
relationship to the input's. Nothing here tries to preserve it, and the report says
so plainly instead of producing a meaningless number.

The PNG strategy, and its honest limits
---------------------------------------
:func:`preserve_png_size` does two things in order:

1. **Re-encode at every DEFLATE level, 0 to 9.** Different levels give different
   lengths, so one of them may already hit the target exactly. This costs nothing
   but time and changes no pixel.
2. **Pad with an ancillary chunk.** If the smallest candidate is still under the
   target, the shortfall is filled with a ``teXt`` chunk sized to close the gap
   exactly. Ancillary chunks are skippable by specification, so the result is a
   valid PNG that decodes to identical pixels.

The limit is stated rather than hidden: **if every candidate encoding is already
larger than the cover, the size cannot be matched.** Bytes cannot be removed from a
PNG without changing its pixels, and that is the common case at higher LSB depths.
So this is reported as a per-file outcome, never as a guarantee.

A padding chunk also has a cost worth naming: it is an unusual feature in an
otherwise plain PNG, so a file padded this way is arguably *more* conspicuous to an
analyst than one that is merely the wrong size. :attr:`SizeResult.notes` says so.
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Final

from app.stego import image_io
from app.stego.errors import DecodeError, ValidationError
from app.utils import constants, file_utils

__all__ = [
    "DEFLATE_LEVELS",
    "MIN_PNG_CHUNK_OVERHEAD",
    "PADDING_CHUNK_TYPE",
    "SizeResult",
    "encode_png_at_level",
    "pad_png_to_size",
    "preserve_png_size",
    "size_outcome",
]

#: Every DEFLATE level Pillow will accept. Level 0 stores without compressing, which
#: is the largest and is included because it is occasionally the only one that fits a
#: target when the cover itself was stored uncompressed.
DEFLATE_LEVELS: Final[tuple[int, ...]] = tuple(range(10))

#: A PNG chunk costs 4 bytes of length, 4 of type and 4 of CRC even when its payload
#: is empty, so a shortfall smaller than this cannot be padded away.
MIN_PNG_CHUNK_OVERHEAD: Final[int] = 12

#: Lower-case first letter means ancillary (skippable); lower-case second means
#: private, so this cannot collide with a registered chunk type. Both are what the
#: PNG specification's naming rules require of a chunk a decoder may ignore.
PADDING_CHUNK_TYPE: Final[bytes] = b"stPd"


@dataclass(frozen=True)
class SizeResult:
    """What happened when one file's size was compared, or matched, to its cover."""

    media_type: str
    container_format: str
    cover_path: str
    stego_path: str
    cover_size: int
    stego_size: int
    #: The size after any padding was applied. Equals *stego_size* when nothing was
    #: attempted.
    final_size: int
    #: Whether the final file is exactly the cover's size.
    exact: bool
    #: Whether preservation was *attempted*, as opposed to happening for free.
    attempted: bool
    #: ``True`` when the container makes preservation automatic.
    inherent: bool
    strategy: str
    #: ``False`` when the question does not apply to this container at all, which is
    #: the case for video. Kept separate from ``exact`` so that a coincidental match
    #: cannot be counted as a success: two re-encoded clips can land on the same
    #: length by chance, and reporting that as size preservation would be wrong.
    applicable: bool = True
    #: Whether the pixels or samples still decode identically to the stego file's.
    content_unchanged: bool | None = None
    notes: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", dict(self.details))
        object.__setattr__(self, "notes", tuple(self.notes))

    @property
    def difference(self) -> int:
        """Final size minus cover size. Negative means the stego file is smaller."""
        return self.final_size - self.cover_size

    @property
    def growth_proportion(self) -> float:
        return self.difference / self.cover_size if self.cover_size else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "media_type": self.media_type,
            "container": self.container_format,
            "cover": file_utils.display_name(self.cover_path),
            "stego": file_utils.display_name(self.stego_path),
            "cover_size": self.cover_size,
            "stego_size": self.stego_size,
            "final_size": self.final_size,
            "difference": self.difference,
            "growth_proportion": self.growth_proportion,
            "exact": self.exact,
            "attempted": self.attempted,
            "inherent": self.inherent,
            "applicable": self.applicable,
            "strategy": self.strategy,
            "content_unchanged": self.content_unchanged,
            "notes": list(self.notes),
            "details": dict(self.details),
        }

    def summary(self) -> str:
        if not self.applicable:
            return (
                f"{self.container_format}: the question does not apply — "
                f"{self.strategy}"
            )
        if self.exact and self.inherent:
            return (
                f"{self.container_format}: exact at {self.final_size:,} bytes, "
                f"inherent to the container"
            )
        if self.exact:
            return (
                f"{self.container_format}: matched exactly at {self.final_size:,} "
                f"bytes by {self.strategy}"
            )
        return (
            f"{self.container_format}: not matched — {self.stego_size:,} bytes "
            f"against a {self.cover_size:,}-byte cover "
            f"({self.difference:+,}, {self.growth_proportion * 100:+.2f}%)"
        )


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #


def encode_png_at_level(array, level: int) -> bytes:
    """Encode *array* as a PNG at DEFLATE *level*.

    Separate from :func:`app.stego.image_io.encode_image`, which deliberately fixes
    the level so its output is deterministic. Varying it is the whole point here, and
    the pixel data is identical at every level, so this changes size and nothing else.
    """
    import io

    from PIL import Image

    if level not in DEFLATE_LEVELS:
        raise ValidationError(
            f"DEFLATE level must be one of {DEFLATE_LEVELS}, got {level}"
        )

    channels = array.shape[2]
    if channels == 1:
        image = Image.fromarray(array[:, :, 0], mode="L")
    elif channels == 3:
        image = Image.fromarray(array, mode="RGB")
    else:
        image = Image.fromarray(array, mode="RGBA")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False, compress_level=level)
    return buffer.getvalue()


def _split_png_chunks(raw: bytes) -> list[tuple[bytes, bytes]]:
    """Split a PNG into (type, payload) pairs, so a chunk can be inserted.

    :raises DecodeError: the bytes are not a well-formed PNG chunk stream.
    """
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise DecodeError("not a PNG: the signature is missing")

    chunks: list[tuple[bytes, bytes]] = []
    offset = 8
    while offset < len(raw):
        if offset + 8 > len(raw):
            raise DecodeError("truncated PNG: a chunk header runs past the end")
        (length,) = struct.unpack(">I", raw[offset : offset + 4])
        kind = raw[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        if payload_end + 4 > len(raw):
            raise DecodeError(f"truncated PNG: chunk {kind!r} runs past the end")
        chunks.append((kind, raw[payload_start:payload_end]))
        offset = payload_end + 4
        if kind == b"IEND":
            break
    return chunks


def _build_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFF_FFFF)
    )


def pad_png_to_size(raw: bytes, target_size: int) -> bytes:
    """Return *raw* grown to exactly *target_size* bytes with an ancillary chunk.

    The chunk is inserted immediately before ``IEND``, which is where any trailing
    ancillary chunk belongs. Its type is ancillary and private, so a conforming
    decoder skips it and the decoded pixels are unchanged.

    :raises ValidationError: the target is smaller than *raw*, or the shortfall is
        too small to hold a chunk at all. Both are real limits: a PNG cannot be made
        smaller without changing its pixels, and a chunk costs 12 bytes even empty.
    """
    shortfall = target_size - len(raw)
    if shortfall == 0:
        return raw
    if shortfall < 0:
        raise ValidationError(
            f"cannot pad to {target_size:,} bytes: the file is already "
            f"{len(raw):,} bytes. A PNG cannot be shortened without changing its "
            f"pixels"
        )
    if shortfall < MIN_PNG_CHUNK_OVERHEAD:
        raise ValidationError(
            f"cannot pad by {shortfall} bytes: a PNG chunk costs "
            f"{MIN_PNG_CHUNK_OVERHEAD} bytes even with an empty payload"
        )

    chunks = _split_png_chunks(raw)
    padding = _build_chunk(
        PADDING_CHUNK_TYPE, b"\x00" * (shortfall - MIN_PNG_CHUNK_OVERHEAD)
    )

    rebuilt = bytearray(b"\x89PNG\r\n\x1a\n")
    for kind, payload in chunks:
        if kind == b"IEND":
            rebuilt += padding
        rebuilt += _build_chunk(kind, payload)

    if len(rebuilt) != target_size:  # pragma: no cover - arithmetic guard
        raise ValidationError(
            f"padding produced {len(rebuilt):,} bytes rather than the requested "
            f"{target_size:,}"
        )
    return bytes(rebuilt)


def preserve_png_size(
    cover_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> SizeResult:
    """Try to write a copy of the stego PNG that is exactly the cover's size.

    Re-encodes at every DEFLATE level looking for an exact hit, then pads the
    smallest under-sized candidate. Reports failure as a result rather than raising,
    because "this file could not be matched" is the finding, not an error.

    The pixels are always preserved: every candidate is an encoding of the *same*
    array, and padding adds a skippable chunk. That is verified rather than asserted
    — the written file is decoded and compared.
    """
    cover = os.fspath(cover_path)
    stego = os.fspath(stego_path)
    target = os.fspath(output_path)

    cover_size = os.path.getsize(cover)
    stego_size = os.path.getsize(stego)
    array, descriptor = image_io.load_image(stego)

    if descriptor.container_format != constants.CONTAINER_PNG:
        raise ValidationError(
            f"this experiment applies to PNG; "
            f"{file_utils.display_name(stego)} is {descriptor.container_format}"
        )

    # Step 1: every level, looking for an exact hit and remembering the smallest.
    by_level = {level: encode_png_at_level(array, level) for level in DEFLATE_LEVELS}
    sizes = {level: len(data) for level, data in by_level.items()}

    exact_level = next(
        (level for level in DEFLATE_LEVELS if sizes[level] == cover_size), None
    )
    smallest_level = min(DEFLATE_LEVELS, key=lambda level: sizes[level])

    notes: list[str] = []
    if exact_level is not None:
        chosen = by_level[exact_level]
        strategy = f"re-encoding at DEFLATE level {exact_level}"
        notes.append(
            "No padding was needed: one of the ten DEFLATE levels happened to "
            "produce exactly the cover's length."
        )
        padded_bytes = 0
    elif sizes[smallest_level] <= cover_size:
        shortfall = cover_size - sizes[smallest_level]
        if shortfall and shortfall < MIN_PNG_CHUNK_OVERHEAD:
            # Honest dead end: too close to pad, too far to match.
            chosen = by_level[smallest_level]
            strategy = "not matched: the shortfall is smaller than a PNG chunk"
            notes.append(
                f"The closest encoding is {shortfall} bytes short, but the smallest "
                f"possible chunk is {MIN_PNG_CHUNK_OVERHEAD} bytes, so the gap "
                f"cannot be closed exactly."
            )
            padded_bytes = 0
        else:
            chosen = pad_png_to_size(by_level[smallest_level], cover_size)
            strategy = (
                f"DEFLATE level {smallest_level} plus a {shortfall}-byte "
                f"{PADDING_CHUNK_TYPE.decode()} padding chunk"
            )
            padded_bytes = shortfall
            notes.append(
                "The padding chunk is ancillary and private, so a conforming decoder "
                "skips it and the pixels are unchanged. It is also an unusual feature "
                "in an otherwise plain PNG, which makes the file arguably more "
                "conspicuous to an analyst than a size mismatch would."
            )
    else:
        chosen = by_level[smallest_level]
        strategy = "not matched: every encoding is larger than the cover"
        padded_bytes = 0
        notes.append(
            f"LSB replacement pushed the low-order bits toward random, and random "
            f"data does not compress. The smallest of the ten encodings is still "
            f"{sizes[smallest_level] - cover_size:,} bytes over. Bytes cannot be "
            f"removed from a PNG without changing its pixels, so this file cannot be "
            f"matched. This is the usual outcome at higher LSB depths."
        )

    file_utils.write_bytes_atomic(target, chosen, overwrite=overwrite)

    # The claim "the pixels are unchanged" is checked, not asserted.
    rewritten, _ = image_io.load_image(target)
    content_unchanged = bool(
        rewritten.shape == array.shape and (rewritten == array).all()
    )

    final_size = len(chosen)
    return SizeResult(
        media_type=constants.MEDIA_IMAGE,
        container_format=constants.CONTAINER_PNG,
        cover_path=cover,
        stego_path=stego,
        cover_size=cover_size,
        stego_size=stego_size,
        final_size=final_size,
        exact=final_size == cover_size,
        attempted=True,
        inherent=False,
        strategy=strategy,
        content_unchanged=content_unchanged,
        notes=tuple(notes),
        details={
            "sizes_by_deflate_level": dict(sizes),
            "exact_level": exact_level,
            "smallest_level": smallest_level,
            "padded_bytes": padded_bytes,
            "output": file_utils.display_name(target),
        },
    )


# --------------------------------------------------------------------------- #
# The containers where nothing has to be done
# --------------------------------------------------------------------------- #


def size_outcome(
    cover_path: str | os.PathLike[str], stego_path: str | os.PathLike[str]
) -> SizeResult:
    """Report the size relationship for any medium, without attempting to change it.

    For WAV and BMP this is the whole experiment: the sizes are expected to match
    already, and a mismatch would mean something is wrong with the writer rather than
    with the format. For PNG it is the *baseline* that
    :func:`preserve_png_size` is measured against. For video it records that the
    question does not apply.
    """
    from app.stego import media

    cover = os.fspath(cover_path)
    stego = os.fspath(stego_path)

    cover_size = os.path.getsize(cover)
    stego_size = os.path.getsize(stego)
    media_type = media.detect_media_type(stego)
    container = file_utils.describe_file(stego).container_format

    inherent = container in (constants.CONTAINER_WAV, constants.CONTAINER_BMP)
    notes: list[str] = []

    if inherent:
        strategy = "none needed: samples are stored at fixed positions and widths"
        notes.append(
            "Replacing low-order bits changes byte values, not byte counts, so the "
            "size is preserved without doing anything. A mismatch here would point "
            "at the writer, not at the format."
        )
    elif container == constants.CONTAINER_PNG:
        strategy = "baseline, before any attempt"
        notes.append(
            "PNG compresses its pixel data, so the size moves in whichever "
            "direction DEFLATE happens to take it. See preserve_png_size for the "
            "attempt to match it."
        )
    else:
        strategy = "not applicable: the output is a full re-encode"
        notes.append(
            "A protected clip is re-encoded as FFV1 from the decoded frames, so its "
            "size bears no relation to the cover's — the cover may not even have "
            "been in a lossless codec. Comparing the two sizes measures the codec "
            "change, not the embedding."
        )
        if stego_size == cover_size:
            # Two independently encoded FFV1 streams can land on the same length. It
            # would be wrong to record that as size preservation.
            notes.append(
                "The two sizes happen to be equal here. That is a coincidence of two "
                "separate FFV1 encodings, not preservation, and it is not something "
                "to rely on."
            )

    return SizeResult(
        media_type=media_type,
        container_format=container,
        cover_path=cover,
        stego_path=stego,
        cover_size=cover_size,
        stego_size=stego_size,
        final_size=stego_size,
        exact=stego_size == cover_size,
        attempted=False,
        inherent=inherent,
        applicable=media_type != constants.MEDIA_VIDEO,
        strategy=strategy,
        notes=tuple(notes),
    )
