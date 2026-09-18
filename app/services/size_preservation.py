"""Bounded file-size and container-layout preservation experiments."""

from __future__ import annotations

import json
import os
import struct
import tempfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from app.stego import image_io
from app.stego.audio_stego import read_audio


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IEND = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"
PADDING_TYPE = b"stEg"
MAX_PNG_TARGET_SIZE = 256 * 1024 * 1024
MAX_PNG_PADDING_SIZE = 64 * 1024 * 1024
MAX_LAYOUT_FILE_SIZE = 512 * 1024 * 1024
PNG_COMPRESSION_LEVELS = tuple(range(10))


@dataclass(frozen=True)
class SizePreservationResult:
    output_path: str
    original_size: int
    initial_stego_size: int
    final_size: int
    exact: bool
    method: str
    failure_reason: str | None = None
    attempts: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


def _atomic_write(path: Path, data: bytes, *, overwrite: bool) -> None:
    destination = path.resolve()
    if not destination.parent.is_dir():
        raise FileNotFoundError("size-preservation output directory does not exist")
    if destination.is_dir():
        raise IsADirectoryError(f"output path is a directory: {destination.name}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {destination.name}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _validate_png_target(target_size: int, initial_size: int) -> int:
    if isinstance(target_size, bool) or not isinstance(target_size, int):
        raise TypeError("PNG target size must be an integer")
    if target_size < initial_size:
        raise ValueError(
            f"PNG is already {initial_size - target_size} bytes larger than the target"
        )
    if target_size > MAX_PNG_TARGET_SIZE:
        raise ValueError(
            f"PNG target exceeds the {MAX_PNG_TARGET_SIZE:,}-byte safety limit"
        )
    difference = target_size - initial_size
    if difference > MAX_PNG_PADDING_SIZE:
        raise ValueError(
            f"PNG padding exceeds the {MAX_PNG_PADDING_SIZE:,}-byte safety limit"
        )
    return difference


def _padded_png(raw: bytes, target_size: int) -> tuple[bytes, str]:
    initial_size = len(raw)
    if not raw.startswith(PNG_SIGNATURE) or not raw.endswith(IEND):
        raise ValueError("input is not a canonical PNG ending in IEND")
    difference = _validate_png_target(target_size, initial_size)
    if difference == 0:
        return raw, "already-exact"
    if difference < 12:
        raise ValueError(
            "PNG padding gap is below the 12-byte legal ancillary-chunk minimum"
        )
    data = bytes(difference - 12)
    crc = zlib.crc32(PADDING_TYPE + data) & 0xFFFFFFFF
    chunk = (
        struct.pack(">I", len(data))
        + PADDING_TYPE
        + data
        + struct.pack(">I", crc)
    )
    return raw[: -len(IEND)] + chunk + IEND, "private-ancillary-padding"


def pad_png_to_size(
    png_path: str | os.PathLike[str],
    target_size: int,
    output_path: str | os.PathLike[str] | None = None,
    *,
    overwrite: bool = False,
) -> SizePreservationResult:
    """Add one bounded private ancillary chunk when legal padding reaches a target."""
    source = Path(png_path)
    initial_size = source.stat().st_size
    _validate_png_target(target_size, initial_size)
    raw = source.read_bytes()
    padded, method = _padded_png(raw, target_size)
    destination = Path(output_path) if output_path else source
    in_place = destination.resolve() == source.resolve()
    if not in_place and destination.exists():
        try:
            aliases_source = os.path.samefile(source, destination)
        except OSError:
            aliases_source = False
        if aliases_source:
            raise ValueError("PNG output must not alias the input file")
    _atomic_write(destination, padded, overwrite=in_place or overwrite)
    return SizePreservationResult(
        str(destination),
        target_size,
        len(raw),
        len(padded),
        len(padded) == target_size,
        method,
    )


def preserve_png_size(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    """Try bounded lossless PNG encodings, then legal padding, for an exact target."""
    original = Path(original_path)
    stego = Path(stego_path)
    target = original.stat().st_size
    initial = stego.stat().st_size
    if target > MAX_PNG_TARGET_SIZE:
        raise ValueError(
            f"PNG target exceeds the {MAX_PNG_TARGET_SIZE:,}-byte safety limit"
        )
    pixels, descriptor = image_io.load_image(stego)
    if descriptor.container_format != image_io.PNG:
        raise ValueError("PNG preservation requires a PNG stego file")
    if initial == target:
        return SizePreservationResult(
            str(stego), target, initial, initial, True, "already-exact", attempts=0
        )

    candidates: list[tuple[int, bytes]] = []
    small_gaps: list[int] = []
    bounded_out_gaps: list[int] = []
    for level in PNG_COMPRESSION_LEVELS:
        encoded = image_io.encode_png(pixels, compress_level=level)
        difference = target - len(encoded)
        if difference == 0:
            candidates.append((level, encoded))
        elif 0 < difference < 12:
            small_gaps.append(difference)
        elif 12 <= difference <= MAX_PNG_PADDING_SIZE:
            candidates.append((level, encoded))
        elif difference > MAX_PNG_PADDING_SIZE:
            bounded_out_gaps.append(difference)

    if candidates:
        level, encoded = max(candidates, key=lambda item: len(item[1]))
        final, padding_method = _padded_png(encoded, target)
        _atomic_write(stego, final, overwrite=True)
        method = f"png-compression-{level}"
        if padding_method == "private-ancillary-padding":
            method += "+private-ancillary-padding"
        return SizePreservationResult(
            str(stego), target, initial, len(final), True, method, attempts=10
        )

    if small_gaps:
        reason = (
            "all fitting compression candidates left an illegal padding gap below 12 bytes"
        )
    elif bounded_out_gaps:
        reason = "required PNG padding exceeds the configured safety limit"
    else:
        reason = "every bounded lossless compression candidate exceeded the target size"
    return SizePreservationResult(
        str(stego),
        target,
        initial,
        initial,
        initial == target,
        "unavailable: png-size",
        reason,
        10,
    )


def _bmp_layout(raw: bytes) -> tuple[int, int, int, int, bool, int]:
    if len(raw) < 54 or raw[:2] != b"BM":
        raise ValueError("BMP layout preservation requires a BMP file")
    declared_size = struct.unpack_from("<I", raw, 2)[0]
    pixel_offset = struct.unpack_from("<I", raw, 10)[0]
    width, height_raw = struct.unpack_from("<ii", raw, 18)
    bit_count = struct.unpack_from("<H", raw, 28)[0]
    compression = struct.unpack_from("<I", raw, 30)[0]
    if declared_size != len(raw):
        raise ValueError("unsupported BMP layout: declared file size is not exact")
    if width <= 0 or height_raw == 0 or bit_count not in {24, 32}:
        raise ValueError("unsupported BMP layout for sample-preserving replacement")
    if compression not in {0, 3}:
        raise ValueError("unsupported BMP compression for layout preservation")
    height = abs(height_raw)
    channels = bit_count // 8
    stride = ((bit_count * width + 31) // 32) * 4
    if pixel_offset + stride * height > len(raw):
        raise ValueError("unsupported BMP layout: pixel region is truncated")
    return width, height, channels, stride, height_raw > 0, pixel_offset


def preserve_bmp_layout(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    """Replace only BMP colour sample bytes in the original container layout."""
    original = Path(original_path)
    stego = Path(stego_path)
    if original.stat().st_size > MAX_LAYOUT_FILE_SIZE:
        raise ValueError("BMP layout exceeds the configured safety limit")
    raw = original.read_bytes()
    width, height, channels, stride, bottom_up, offset = _bmp_layout(raw)
    original_pixels, original_descriptor = image_io.load_image(original)
    protected_pixels, protected_descriptor = image_io.load_image(stego)
    if original_descriptor.container_format != image_io.BMP:
        raise ValueError("BMP layout preservation requires a BMP cover")
    if protected_descriptor.container_format != image_io.BMP:
        raise ValueError("BMP layout preservation requires a BMP stego file")
    expected_shape = (height, width, channels)
    if original_pixels.shape != expected_shape or protected_pixels.shape != expected_shape:
        raise ValueError("BMP sample shape changed during embedding")

    stored = protected_pixels[::-1] if bottom_up else protected_pixels
    ordered = stored[:, :, ::-1] if channels == 3 else stored[:, :, [2, 1, 0, 3]]
    output = bytearray(raw)
    initial = stego.stat().st_size
    row_bytes = width * channels
    for row_index in range(height):
        start = offset + row_index * stride
        output[start : start + row_bytes] = ordered[row_index].tobytes()
    _atomic_write(stego, bytes(output), overwrite=True)
    return SizePreservationResult(
        str(stego), len(raw), initial, len(output), True, "bmp-layout-preserved"
    )


def _wav_layout(raw: bytes) -> tuple[int, int, int, int, int]:
    if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise ValueError("WAV layout preservation requires a RIFF/WAVE file")
    if struct.unpack_from("<I", raw, 4)[0] + 8 != len(raw):
        raise ValueError("unsupported WAV layout: RIFF size is not exact")
    cursor = 12
    fmt: tuple[int, int, int, int] | None = None
    data_region: tuple[int, int] | None = None
    while cursor < len(raw):
        if cursor + 8 > len(raw):
            raise ValueError("unsupported WAV layout: truncated chunk header")
        kind = raw[cursor : cursor + 4]
        size = struct.unpack_from("<I", raw, cursor + 4)[0]
        start = cursor + 8
        end = start + size
        padded_end = end + (size & 1)
        if end > len(raw) or padded_end > len(raw):
            raise ValueError("unsupported WAV layout: truncated chunk")
        if kind == b"fmt ":
            if fmt is not None or size < 16:
                raise ValueError("unsupported WAV layout: invalid fmt chunk")
            audio_format, channels, sample_rate, _byte_rate, block_align, bits = (
                struct.unpack_from("<HHIIHH", raw, start)
            )
            if audio_format != 1 or bits != 16 or block_align != channels * 2:
                raise ValueError("unsupported WAV layout: expected integer PCM-16")
            fmt = channels, sample_rate, block_align, bits
        elif kind == b"data":
            if data_region is not None:
                raise ValueError("unsupported WAV layout: multiple data chunks")
            data_region = start, size
        cursor = padded_end
    if cursor != len(raw) or fmt is None or data_region is None:
        raise ValueError("unsupported WAV layout: required chunks are missing")
    channels, sample_rate, block_align, _bits = fmt
    data_start, data_size = data_region
    if data_size % block_align:
        raise ValueError("unsupported WAV layout: data is not frame-aligned")
    return data_start, data_size, channels, sample_rate, block_align


def preserve_wav_layout(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    """Replace only PCM sample bytes in the original RIFF/WAV container layout."""
    original = Path(original_path)
    stego = Path(stego_path)
    if original.stat().st_size > MAX_LAYOUT_FILE_SIZE:
        raise ValueError("WAV layout exceeds the configured safety limit")
    raw = original.read_bytes()
    data_start, data_size, channels, sample_rate, _block_align = _wav_layout(raw)
    samples, protected_rate = read_audio(stego)
    protected_channels = 1 if samples.ndim == 1 else int(samples.shape[1])
    sample_bytes = np.asarray(samples, dtype="<i2").tobytes()
    if protected_rate != sample_rate or protected_channels != channels:
        raise ValueError("WAV properties changed during embedding")
    if len(sample_bytes) != data_size:
        raise ValueError("WAV sample-data length changed during embedding")
    output = bytearray(raw)
    output[data_start : data_start + data_size] = sample_bytes
    initial = stego.stat().st_size
    _atomic_write(stego, bytes(output), overwrite=True)
    return SizePreservationResult(
        str(stego), len(raw), initial, len(output), True, "wav-layout-preserved"
    )


def preserve_protected_size(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    """Apply the supported, content-detected preservation strategy."""
    with Path(original_path).open("rb") as stream:
        signature = stream.read(12)
    if signature.startswith(PNG_SIGNATURE):
        return preserve_png_size(original_path, stego_path)
    if signature.startswith(b"BM"):
        return preserve_bmp_layout(original_path, stego_path)
    if signature[:4] == b"RIFF" and signature[8:12] == b"WAVE":
        return preserve_wav_layout(original_path, stego_path)
    raise ValueError("size preservation supports PNG, BMP, and RIFF/WAVE only")


def compare_file_sizes(
    original_path: str | os.PathLike[str],
    stego_path: str | os.PathLike[str],
) -> SizePreservationResult:
    original_size = Path(original_path).stat().st_size
    stego_size = Path(stego_path).stat().st_size
    exact = original_size == stego_size
    return SizePreservationResult(
        str(stego_path),
        original_size,
        stego_size,
        stego_size,
        exact,
        "comparison-only",
        None if exact else "file sizes differ; no preservation strategy was applied",
    )


def export_size_preservation_result(
    result: SizePreservationResult,
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(result, SizePreservationResult):
        raise TypeError("result must be a SizePreservationResult")
    encoded = (json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    _atomic_write(Path(output_path), encoded, overwrite=overwrite)
