"""Lossless PNG and BMP loading, format detection and atomic saving.

Requirement 1 (loading and saving) and Requirement 6.5-6.8 (atomic writes).

Format detection reads the file content, never the path extension
(Requirement 1.1, 1.2). PNG headers are validated by parsing IHDR and BMP
headers by parsing the DIB header, because Pillow's ``mode`` attribute alone
loses the distinctions Requirements 1.5-1.7 depend on: a palette BMP and a
grayscale BMP both open as an 8-bit image, and a 16-bit PNG opens as ``I;16``
only on some builds.

BMP is decoded and encoded by this module rather than by Pillow. Two measured
Pillow behaviours forced that decision:

* Saving an RGBA image as BMP writes a 32-bit BI_RGB bitmap that Pillow itself
  reads back as 3-channel RGB, discarding alpha. That breaks the round-trip
  guarantee of Requirement 1.4 and the channel-count preservation of
  Requirement 1.9, and contradicts Requirement 1.12, which requires an
  uncompressed 32-bit BMP to decode as a 4-channel image.
* Saving a grayscale image as BMP writes an 8-bit palette bitmap, which
  Requirement 1.6 requires this layer to reject. Grayscale BMP is therefore not
  a supported cover format; grayscale PNG is.

PNG is handled by Pillow, which writes exactly IHDR, IDAT and IEND for an image
built from an array, satisfying the "no ancillary metadata" rule of
Requirement 1.11.
"""

from __future__ import annotations

import os
import struct
import tempfile
import time
from dataclasses import dataclass
from typing import Final

import numpy as np
import numpy.typing as npt
from PIL import Image, UnidentifiedImageError

from app.stego import paths
from app.stego.errors import DecodeError, FileError, ValidationError, safe_path

__all__ = [
    "PNG",
    "BMP",
    "SUPPORTED_CONTAINERS",
    "MIN_DIMENSION",
    "MAX_DIMENSION",
    "SUPPORTED_CHANNEL_COUNTS",
    "ImageDescriptor",
    "load_image",
    "save_image",
    "encode_image",
    "check_output_writable",
    "describe_only",
]

PNG: Final[str] = "PNG"
BMP: Final[str] = "BMP"
SUPPORTED_CONTAINERS: Final[tuple[str, ...]] = (PNG, BMP)

#: Requirement 1.1 bounds the accepted pixel dimensions.
MIN_DIMENSION: Final[int] = 1
MAX_DIMENSION: Final[int] = 30_000

#: Requirement 1.1: grayscale, RGB and RGBA only.
SUPPORTED_CHANNEL_COUNTS: Final[tuple[int, ...]] = (1, 3, 4)

_PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"
_BMP_SIGNATURE: Final[bytes] = b"BM"

# PNG colour types from the specification.
_PNG_GRAY: Final[int] = 0
_PNG_RGB: Final[int] = 2
_PNG_PALETTE: Final[int] = 3
_PNG_GRAY_ALPHA: Final[int] = 4
_PNG_RGBA: Final[int] = 6
_PNG_COLOUR_TYPE_CHANNELS: Final[dict[int, int]] = {
    _PNG_GRAY: 1,
    _PNG_RGB: 3,
    _PNG_RGBA: 4,
}

# BMP compression values.
_BI_RGB: Final[int] = 0
_BI_RLE8: Final[int] = 1
_BI_RLE4: Final[int] = 2
_BI_BITFIELDS: Final[int] = 3
_BI_JPEG: Final[int] = 4
_BI_PNG: Final[int] = 5

_BITMAPCOREHEADER: Final[int] = 12
_BITMAPINFOHEADER: Final[int] = 40
_BITMAPV4HEADER: Final[int] = 108
_BITMAPV5HEADER: Final[int] = 124

# Standard 32-bit BGRA channel masks. Requirement 1.12 covers V4 and V5 headers,
# which carry explicit masks; anything other than the standard layout is
# rejected rather than guessed at.
_STANDARD_MASKS: Final[tuple[int, int, int, int]] = (
    0x00FF0000,  # red
    0x0000FF00,  # green
    0x000000FF,  # blue
    0xFF000000,  # alpha
)

#: Lossy container signatures, reported by name for Requirement 1.5.
_LOSSY_SIGNATURES: Final[tuple[tuple[bytes, str], ...]] = (
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x00\x00\x00\x0cjP  ", "JPEG 2000"),
    (b"\xff\x4f\xff\x51", "JPEG 2000 codestream"),
    (b"RIFF", "WebP or RIFF container"),
    (b"GIF8", "GIF"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
)


@dataclass(frozen=True)
class ImageDescriptor:
    """Non-pixel facts about a decoded cover or stego object.

    ``container_format`` is detected from content and ``extension_format`` from
    the path, so Requirement 1.2 can report both when they disagree.
    """

    file_name: str
    container_format: str
    extension_format: str | None
    height: int
    width: int
    channel_count: int
    sample_width_bits: int
    interlaced: bool
    file_size_bytes: int
    #: BMP only: the DIB header size, and whether rows were stored bottom-up.
    bmp_header_size: int | None = None
    bmp_bottom_up: bool | None = None

    @property
    def shape(self) -> tuple[int, int, int]:
        return (self.height, self.width, self.channel_count)


def _extension_format(path: str | os.PathLike[str]) -> str | None:
    suffix = os.path.splitext(os.fspath(path))[1].lower()
    if suffix == ".png":
        return PNG
    if suffix == ".bmp":
        return BMP
    return None


def _read_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read a file, mapping filesystem faults to :class:`FileError`.

    Requirement 14.1 and 14.8 distinguish a missing path from denied read
    access while using the same error type, and Requirement 14.9 keeps the
    directory portion out of the message.
    """
    name = safe_path(path)
    text = os.fspath(path)
    if not os.path.exists(text):
        raise FileError(f"input file not found: {name}")
    if os.path.isdir(text):
        raise FileError(f"input path is a directory, not a file: {name}")
    try:
        with open(text, "rb") as handle:
            return handle.read()
    except PermissionError as exc:
        raise FileError(f"read access denied for input file: {name}") from exc
    except OSError as exc:
        raise FileError(
            f"input file could not be read: {name} ({exc.strerror or type(exc).__name__})"
        ) from exc


def _sniff_container(raw: bytes, name: str) -> str:
    """Identify the container from magic bytes (Requirement 1.1, 1.5)."""
    if raw.startswith(_PNG_SIGNATURE):
        return PNG
    if raw.startswith(_BMP_SIGNATURE):
        return BMP
    for signature, label in _LOSSY_SIGNATURES:
        if raw.startswith(signature) or (
            label.startswith("JPEG 2000") and raw[4:8] == b"jP  "
        ):
            raise DecodeError(
                f"{name} is {label}, which applies lossy compression or is "
                f"unsupported; supported formats are {PNG} and {BMP}"
            )
    raise DecodeError(
        f"{name} could not be identified as {PNG} or {BMP} from its content; "
        f"supported formats are {PNG} and {BMP}"
    )


def _check_dimensions(width: int, height: int, name: str) -> None:
    if not (MIN_DIMENSION <= width <= MAX_DIMENSION) or not (
        MIN_DIMENSION <= height <= MAX_DIMENSION
    ):
        raise DecodeError(
            f"{name} has pixel dimensions {width}x{height}, outside the supported "
            f"range {MIN_DIMENSION}x{MIN_DIMENSION} to {MAX_DIMENSION}x{MAX_DIMENSION}"
        )


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #


def _inspect_png(raw: bytes, name: str) -> tuple[int, int, int, int, bool]:
    """Parse IHDR, returning (height, width, channels, sample_bits, interlaced).

    Parsing IHDR directly rather than trusting Pillow's ``mode`` is what makes
    the distinct rejections of Requirements 1.6 and 1.7 possible.
    """
    if len(raw) < 33 or raw[12:16] != b"IHDR":
        raise DecodeError(f"{name} is not a valid {PNG} file: IHDR chunk is missing")
    width, height = struct.unpack(">II", raw[16:24])
    sample_bits = raw[24]
    colour_type = raw[25]
    interlace = raw[28]

    _check_dimensions(width, height, name)

    if colour_type == _PNG_PALETTE:
        raise DecodeError(
            f"{name} is a palette (indexed-colour) {PNG} image, which is "
            f"unsupported because palette indices are not colour samples; "
            f"convert it to 8-bit-per-channel RGB before embedding"
        )
    if colour_type == _PNG_GRAY_ALPHA:
        raise DecodeError(
            f"{name} is a grayscale-with-alpha {PNG} image (2 channels), which is "
            f"unsupported; supported channel counts are {SUPPORTED_CHANNEL_COUNTS}"
        )
    if colour_type not in _PNG_COLOUR_TYPE_CHANNELS:
        raise DecodeError(
            f"{name} declares {PNG} colour type {colour_type}, which is unsupported; "
            f"supported colour types are 0 (grayscale), 2 (RGB) and 6 (RGBA)"
        )
    if sample_bits != 8:
        raise DecodeError(
            f"{name} has a sample width of {sample_bits} bits per channel; "
            f"the supported sample width is 8 bits per channel"
        )

    return height, width, _PNG_COLOUR_TYPE_CHANNELS[colour_type], 8, interlace == 1


def _decode_png(raw: bytes, name: str, channels: int) -> npt.NDArray[np.uint8]:
    """Decode PNG pixel data with Pillow.

    Requirement 1.10: an interlaced PNG decodes to the same array as its
    non-interlaced equivalent, which Pillow handles transparently.
    """
    import io

    try:
        with Image.open(io.BytesIO(raw)) as image:
            image.load()
            array = np.array(image)
    except UnidentifiedImageError as exc:
        raise DecodeError(f"{name} could not be decoded as {PNG}") from exc
    except OSError as exc:
        raise DecodeError(f"{name} could not be decoded as {PNG}: {exc}") from exc

    if array.dtype != np.uint8:
        raise DecodeError(
            f"{name} decoded to sample type {array.dtype}; "
            f"the supported sample width is 8 bits per channel"
        )
    if array.ndim == 2:
        array = array[:, :, np.newaxis]
    if array.shape[2] != channels:
        raise DecodeError(
            f"{name} declares {channels} channels in its header but decoded to "
            f"{array.shape[2]} channels"
        )
    return np.ascontiguousarray(array, dtype=np.uint8)


def _encode_png(array: npt.NDArray[np.uint8]) -> bytes:
    """Encode an array as a non-interlaced PNG with no ancillary metadata.

    Requirement 1.3 (lossless compression) and 1.11 (required records only).
    Building the image from the array rather than copying a source image is what
    guarantees no ancillary chunks are carried over.
    """
    import io

    channels = array.shape[2]
    if channels == 1:
        image = Image.fromarray(array[:, :, 0], mode="L")
    elif channels == 3:
        image = Image.fromarray(array, mode="RGB")
    else:
        image = Image.fromarray(array, mode="RGBA")

    buffer = io.BytesIO()
    # optimize=False keeps output deterministic across Pillow builds; the pixel
    # data is lossless either way (Requirement 2.11 determinism).
    image.save(buffer, format="PNG", optimize=False, compress_level=6)
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# BMP
# --------------------------------------------------------------------------- #


def _bmp_row_stride(width: int, bit_count: int) -> int:
    """BMP rows are padded to a 4-byte boundary."""
    return ((bit_count * width + 31) // 32) * 4


def _inspect_bmp(raw: bytes, name: str) -> tuple[int, int, int, int, bool, int, int]:
    """Parse the BMP file and DIB headers.

    Returns (height, width, channels, sample_bits, bottom_up, header_size,
    pixel_offset).
    """
    if len(raw) < 18:
        raise DecodeError(f"{name} is too short to be a valid {BMP} file")
    pixel_offset = struct.unpack("<I", raw[10:14])[0]
    header_size = struct.unpack("<I", raw[14:18])[0]

    if header_size == _BITMAPCOREHEADER:
        raise DecodeError(
            f"{name} uses a BITMAPCOREHEADER {BMP} variant, which is unsupported; "
            f"supported variants are BITMAPINFOHEADER, BITMAPV4HEADER and "
            f"BITMAPV5HEADER"
        )
    if header_size < _BITMAPINFOHEADER or len(raw) < 14 + header_size:
        raise DecodeError(
            f"{name} declares an unsupported {BMP} DIB header size of {header_size} bytes"
        )

    width, height_raw = struct.unpack("<ii", raw[18:26])
    bit_count = struct.unpack("<H", raw[28:30])[0]
    compression = struct.unpack("<I", raw[30:34])[0]

    bottom_up = height_raw > 0
    height = abs(height_raw)
    _check_dimensions(width, height, name)

    if compression in (_BI_RLE8, _BI_RLE4):
        variant = "RLE8" if compression == _BI_RLE8 else "RLE4"
        raise DecodeError(
            f"{name} is an {variant}-compressed indexed-colour {BMP} image, which is "
            f"unsupported because palette indices are not colour samples; convert it "
            f"to 8-bit-per-channel RGB before embedding"
        )
    if compression in (_BI_JPEG, _BI_PNG):
        embedded = "JPEG" if compression == _BI_JPEG else "PNG"
        raise DecodeError(
            f"{name} is a {BMP} container wrapping an embedded {embedded} stream, "
            f"which is unsupported"
        )
    if compression not in (_BI_RGB, _BI_BITFIELDS):
        raise DecodeError(
            f"{name} declares {BMP} compression value {compression}, which is "
            f"unsupported; supported values are BI_RGB and BI_BITFIELDS"
        )

    if bit_count in (1, 4, 8):
        raise DecodeError(
            f"{name} is a {bit_count}-bit indexed-colour (palette) {BMP} image, which "
            f"is unsupported because palette indices are not colour samples; convert "
            f"it to 8-bit-per-channel RGB before embedding"
        )
    if bit_count == 16:
        raise DecodeError(
            f"{name} is a packed 16-bit {BMP} image, whose channels are 5 or 6 bits "
            f"wide; the supported sample width is 8 bits per channel"
        )
    if bit_count not in (24, 32):
        raise DecodeError(
            f"{name} declares {bit_count} bits per pixel, which is unsupported; "
            f"supported {BMP} layouts are 24-bit RGB and 32-bit RGBA"
        )

    if compression == _BI_BITFIELDS:
        _check_bmp_masks(raw, header_size, bit_count, name)

    channels = 3 if bit_count == 24 else 4
    return height, width, channels, 8, bottom_up, header_size, pixel_offset


def _check_bmp_masks(raw: bytes, header_size: int, bit_count: int, name: str) -> None:
    """Reject BI_BITFIELDS bitmaps that do not use the standard BGRA masks."""
    if header_size >= _BITMAPV4HEADER:
        red, green, blue, alpha = struct.unpack("<IIII", raw[54:70])
    else:
        # BITMAPINFOHEADER with BI_BITFIELDS stores three masks after the header
        # and has no alpha mask.
        if len(raw) < 14 + header_size + 12:
            raise DecodeError(f"{name} declares BI_BITFIELDS but omits the channel masks")
        red, green, blue = struct.unpack("<III", raw[14 + header_size : 14 + header_size + 12])
        alpha = 0xFF000000 if bit_count == 32 else 0

    expected_red, expected_green, expected_blue, expected_alpha = _STANDARD_MASKS
    if bit_count == 24:
        expected_alpha = 0
    if (red, green, blue) != (expected_red, expected_green, expected_blue) or (
        bit_count == 32 and alpha not in (expected_alpha, 0)
    ):
        raise DecodeError(
            f"{name} uses non-standard {BMP} channel masks "
            f"(red=0x{red:08X}, green=0x{green:08X}, blue=0x{blue:08X}, "
            f"alpha=0x{alpha:08X}); only the standard 8-bit BGRA layout is supported"
        )


def _decode_bmp(
    raw: bytes,
    name: str,
    height: int,
    width: int,
    channels: int,
    bottom_up: bool,
    pixel_offset: int,
) -> npt.NDArray[np.uint8]:
    """Decode uncompressed 24-bit or 32-bit BMP pixel data.

    Requirement 1.12: rows are returned top-down regardless of stored order, so
    that Traversal_Order does not depend on the BMP row convention.
    """
    bit_count = channels * 8
    stride = _bmp_row_stride(width, bit_count)
    needed = pixel_offset + stride * height
    if len(raw) < needed:
        raise DecodeError(
            f"{name} is truncated: {BMP} pixel data needs {needed} bytes but the "
            f"file holds {len(raw)}"
        )

    block = np.frombuffer(raw, dtype=np.uint8, count=stride * height, offset=pixel_offset)
    rows = block.reshape(height, stride)
    # Drop the row padding, then reinterpret as pixels.
    pixels = rows[:, : width * channels].reshape(height, width, channels)
    if bottom_up:
        pixels = pixels[::-1]
    # BMP stores BGR(A); convert to RGB(A).
    if channels == 3:
        pixels = pixels[:, :, ::-1]
    else:
        pixels = pixels[:, :, [2, 1, 0, 3]]
    return np.ascontiguousarray(pixels, dtype=np.uint8)


def _encode_bmp(array: npt.NDArray[np.uint8]) -> bytes:
    """Encode an array as an uncompressed BMP.

    3-channel arrays become 24-bit BI_RGB with a BITMAPINFOHEADER. 4-channel
    arrays become 32-bit BI_BITFIELDS with a BITMAPV4HEADER carrying an explicit
    alpha mask, which is what makes the alpha round-trip of Requirement 1.4
    hold. Rows are written bottom-up, the conventional BMP order.
    """
    height, width, channels = array.shape
    bit_count = channels * 8
    stride = _bmp_row_stride(width, bit_count)
    pixel_bytes = stride * height

    if channels == 3:
        header_size = _BITMAPINFOHEADER
        compression = _BI_RGB
        ordered = array[:, :, ::-1]  # RGB -> BGR
    else:
        header_size = _BITMAPV4HEADER
        compression = _BI_BITFIELDS
        ordered = array[:, :, [2, 1, 0, 3]]  # RGBA -> BGRA

    pixel_offset = 14 + header_size
    file_size = pixel_offset + pixel_bytes

    rows = np.zeros((height, stride), dtype=np.uint8)
    rows[:, : width * channels] = ordered[::-1].reshape(height, width * channels)

    file_header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, pixel_offset)
    info = struct.pack(
        "<IiiHHIIiiII",
        header_size,
        width,
        height,  # positive: bottom-up
        1,  # planes
        bit_count,
        compression,
        pixel_bytes,
        0,  # horizontal resolution
        0,  # vertical resolution
        0,  # palette entries used
        0,  # important palette entries
    )
    if header_size == _BITMAPV4HEADER:
        red, green, blue, alpha = _STANDARD_MASKS
        info += struct.pack("<IIII", red, green, blue, alpha)
        info += struct.pack("<I", 0x73524742)  # LCS_sRGB colour space
        info += b"\x00" * 36  # CIEXYZTRIPLE endpoints
        info += struct.pack("<III", 0, 0, 0)  # gamma red, green, blue

    return file_header + info + bytes(rows)


# --------------------------------------------------------------------------- #
# Public interface
# --------------------------------------------------------------------------- #


def _inspect(
    raw: bytes, path: str | os.PathLike[str]
) -> tuple[ImageDescriptor, int, bool]:
    """Detect and validate the container, returning a descriptor."""
    name = safe_path(path)
    container = _sniff_container(raw, name)

    if container == PNG:
        height, width, channels, bits, interlaced = _inspect_png(raw, name)
        header_size: int | None = None
        bottom_up: bool | None = None
        pixel_offset = 0
    else:
        (
            height,
            width,
            channels,
            bits,
            bottom_up_flag,
            header_size,
            pixel_offset,
        ) = _inspect_bmp(raw, name)
        interlaced = False
        bottom_up = bottom_up_flag

    if channels not in SUPPORTED_CHANNEL_COUNTS:
        raise DecodeError(
            f"{name} decoded to {channels} channels; supported channel counts are "
            f"{SUPPORTED_CHANNEL_COUNTS}"
        )

    descriptor = ImageDescriptor(
        file_name=name,
        container_format=container,
        extension_format=_extension_format(path),
        height=height,
        width=width,
        channel_count=channels,
        sample_width_bits=bits,
        interlaced=interlaced,
        file_size_bytes=len(raw),
        bmp_header_size=header_size,
        bmp_bottom_up=bottom_up,
    )
    return descriptor, pixel_offset, bool(descriptor.bmp_bottom_up)


def describe_only(path: str | os.PathLike[str]) -> ImageDescriptor:
    """Validate and describe an image without decoding its pixel data."""
    raw = _read_bytes(path)
    descriptor, _, _ = _inspect(raw, path)
    return descriptor


def load_image(
    path: str | os.PathLike[str],
) -> tuple[npt.NDArray[np.uint8], ImageDescriptor]:
    """Load a PNG or BMP cover object.

    Returns a ``(height, width, channel_count)`` ``uint8`` array and a
    descriptor. Grayscale images return a 1-channel array rather than a
    2-dimensional one, so that downstream indexing is uniform.

    Raises :class:`FileError` for filesystem faults and :class:`DecodeError` for
    unsupported content (Requirements 1.5-1.7, 14.1, 14.2, 14.8).
    """
    raw = _read_bytes(path)
    descriptor, pixel_offset, bottom_up = _inspect(raw, path)

    if descriptor.container_format == PNG:
        array = _decode_png(raw, descriptor.file_name, descriptor.channel_count)
    else:
        array = _decode_bmp(
            raw,
            descriptor.file_name,
            descriptor.height,
            descriptor.width,
            descriptor.channel_count,
            bottom_up,
            pixel_offset,
        )

    if array.shape[:2] != (descriptor.height, descriptor.width):
        raise DecodeError(
            f"{descriptor.file_name} declares {descriptor.width}x{descriptor.height} "
            f"but decoded to {array.shape[1]}x{array.shape[0]}"
        )
    return array, descriptor


def encode_image(array: npt.NDArray[np.uint8], container_format: str) -> bytes:
    """Encode *array* in *container_format*.

    Requirement 1.3: the container comes from the detected cover format, never
    from the output path extension.
    """
    if array.dtype != np.uint8:
        raise ValidationError(
            f"sample array must have dtype uint8, got {array.dtype}"
        )
    if array.ndim != 3 or array.shape[2] not in SUPPORTED_CHANNEL_COUNTS:
        raise ValidationError(
            f"sample array must have shape (height, width, channels) with channels in "
            f"{SUPPORTED_CHANNEL_COUNTS}, got shape {array.shape}"
        )
    if container_format == PNG:
        return _encode_png(array)
    if container_format == BMP:
        if array.shape[2] == 1:
            raise ValidationError(
                f"grayscale output cannot be written as {BMP}, because {BMP} stores "
                f"8-bit grayscale as an indexed-colour palette image that this layer "
                f"rejects on load; use {PNG} for grayscale covers"
            )
        return _encode_bmp(array)
    raise ValidationError(
        f"container_format must be one of {SUPPORTED_CONTAINERS}, got {container_format!r}"
    )


def check_output_writable(path: str | os.PathLike[str], overwrite: bool) -> None:
    """Validate the output location before any sample is modified.

    Requirement 14.5 (directory must exist and be writable) and Requirement 6.6
    (an occupied output path is an error unless overwrite is enabled).

    Kept as a name in this module because :func:`save_image` and
    :func:`app.stego.image_stego.embed_image` both call it, but the implementation
    now lives in :mod:`app.stego.paths` so that the audio and video layers apply
    exactly the same checks.
    """
    paths.check_output_writable(path, overwrite)


def save_image(
    array: npt.NDArray[np.uint8],
    path: str | os.PathLike[str],
    container_format: str,
    *,
    overwrite: bool = False,
    replace_attempts: int = 3,
    replace_delay_seconds: float = 0.1,
) -> None:
    """Write *array* to *path* atomically.

    Requirement 6.5-6.8. The encoded bytes go to a temporary file in the same
    directory, then a single :func:`os.replace` makes them visible, so a
    concurrent reader sees either the previous content or the complete stego
    object and never a partial one.

    On Windows :func:`os.replace` fails with ``PermissionError`` while another
    process holds the destination open, which is common when an image viewer is
    showing the previous output. Requirement 6.8 therefore asks for 3 attempts
    spaced at least 100 ms apart before giving up. The temporary file is removed
    on every failure path (Requirement 6.7).
    """
    check_output_writable(path, overwrite)
    payload = encode_image(array, container_format)

    text = os.fspath(path)
    name = safe_path(path)
    directory = os.path.dirname(os.path.abspath(text))
    handle, temporary = tempfile.mkstemp(
        prefix=".stego-", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

        last_error: OSError | None = None
        for attempt in range(replace_attempts):
            try:
                os.replace(temporary, text)
                return
            except PermissionError as exc:
                last_error = exc
                if attempt < replace_attempts - 1:
                    time.sleep(replace_delay_seconds)
        raise FileError(
            f"output path could not be replaced after {replace_attempts} attempts: "
            f"{name}; another process may be holding it open"
        ) from last_error
    finally:
        if os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass
