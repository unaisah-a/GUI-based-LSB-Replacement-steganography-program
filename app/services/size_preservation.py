"""Measured file-size preservation helpers for supported lossless formats."""

from __future__ import annotations

import os
import struct
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IEND = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
PADDING_TYPE = b"stEg"


@dataclass(frozen=True)
class SizePreservationResult:
    output_path: str
    original_size: int
    initial_stego_size: int
    final_size: int
    exact: bool
    method: str


def pad_png_to_size(
    png_path: str | os.PathLike[str],
    target_size: int,
    output_path: str | os.PathLike[str] | None = None,
) -> SizePreservationResult:
    """Add a private ancillary PNG chunk when legal padding can reach a target."""
    source = Path(png_path)
    raw = source.read_bytes()
    initial_size = len(raw)
    if not raw.startswith(PNG_SIGNATURE) or not raw.endswith(IEND):
        raise ValueError("input is not a canonical PNG ending in IEND")
    if target_size < initial_size:
        raise ValueError(
            f"PNG is already {initial_size - target_size} bytes larger than the target"
        )
    difference = target_size - initial_size
    if difference == 0:
        padded = raw
        method = "already-exact"
    elif difference < 12:
        raise ValueError(
            "PNG padding needs at least 12 bytes for a legal ancillary chunk"
        )
    else:
        data = bytes(difference - 12)
        crc = zlib.crc32(PADDING_TYPE + data) & 0xFFFFFFFF
        chunk = (
            struct.pack(">I", len(data))
            + PADDING_TYPE
            + data
            + struct.pack(">I", crc)
        )
        padded = raw[:-len(IEND)] + chunk + IEND
        method = "private-ancillary-padding"
    destination = Path(output_path) if output_path else source
    if not destination.parent.is_dir():
        raise FileNotFoundError("PNG output directory does not exist")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(padded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return SizePreservationResult(
        str(destination),
        target_size,
        initial_size,
        len(padded),
        len(padded) == target_size,
        method,
    )


def compare_file_sizes(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    original_size = Path(original_path).stat().st_size
    stego_size = Path(stego_path).stat().st_size
    return SizePreservationResult(
        str(stego_path),
        original_size,
        stego_size,
        stego_size,
        original_size == stego_size,
        "replacement-only" if original_size == stego_size else "not-preserved",
    )
