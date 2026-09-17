"""Filesystem and media-identification helpers.

Two design rules apply throughout:

* **Format detection reads content, never the extension.** A PNG saved as
  ``photo.bmp`` is a PNG, and the application must treat it as one. The
  extension is only ever used to *suggest* an output name.
* **Writes are atomic.** Every write goes to a temporary file in the destination
  directory and is then moved into place with :func:`os.replace`, so an
  interrupted run cannot leave a half-written stego file or manifest that would
  later be verified and reported as tampered.

This module imports only :mod:`app.utils.constants` from within the application,
so it sits below the stego, crypto and verification layers and can be used by
all of them.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Final

from app.utils import constants

__all__ = [
    "MediaDescription",
    "UnsupportedMediaError",
    "describe_file",
    "detect_container",
    "detect_media_type",
    "display_name",
    "ensure_directory",
    "file_sha256",
    "human_size",
    "manifest_path_for",
    "read_json",
    "sha256_of_bytes",
    "suggest_output_path",
    "unique_path",
    "write_bytes_atomic",
    "write_json_atomic",
    "write_text_atomic",
]


class UnsupportedMediaError(Exception):
    """A file whose content is not a container this application can carry data in.

    Carries the detected format name when detection succeeded but the format is
    unsupported, which lets callers say "this is a JPEG, and JPEG is lossy"
    rather than the much less useful "unrecognised file".
    """

    def __init__(self, message: str, *, detected: str | None = None) -> None:
        super().__init__(message)
        self.detected = detected


# --------------------------------------------------------------------------- #
# Content sniffing
# --------------------------------------------------------------------------- #

#: Bytes read from the head of a file for format detection. 32 is enough for
#: every signature checked below, including the MP4 ``ftyp`` box at offset 4 and
#: the WAVE form type at offset 8.
_SNIFF_BYTES: Final[int] = 32

_PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"
_BMP_SIGNATURE: Final[bytes] = b"BM"
_RIFF_SIGNATURE: Final[bytes] = b"RIFF"
_EBML_SIGNATURE: Final[bytes] = b"\x1a\x45\xdf\xa3"
_JPEG_SIGNATURE: Final[bytes] = b"\xff\xd8\xff"
_GIF_SIGNATURES: Final[tuple[bytes, ...]] = (b"GIF87a", b"GIF89a")
_FLAC_SIGNATURE: Final[bytes] = b"fLaC"
_OGG_SIGNATURE: Final[bytes] = b"OggS"
_ID3_SIGNATURE: Final[bytes] = b"ID3"

#: Which media type each detected container belongs to.
_CONTAINER_MEDIA_TYPE: Final[dict[str, str]] = {
    constants.CONTAINER_PNG: constants.MEDIA_IMAGE,
    constants.CONTAINER_BMP: constants.MEDIA_IMAGE,
    constants.CONTAINER_WAV: constants.MEDIA_AUDIO,
    constants.CONTAINER_MKV: constants.MEDIA_VIDEO,
    "AVI": constants.MEDIA_VIDEO,
}


def _sniff(path: str | os.PathLike[str]) -> bytes:
    text = os.fspath(path)
    if os.path.isdir(text):
        raise UnsupportedMediaError(
            f"{display_name(text)} is a directory, not a media file"
        )
    try:
        with open(text, "rb") as handle:
            return handle.read(_SNIFF_BYTES)
    except FileNotFoundError as exc:
        raise UnsupportedMediaError(f"file not found: {display_name(text)}") from exc
    except PermissionError as exc:
        raise UnsupportedMediaError(
            f"read access denied: {display_name(text)}"
        ) from exc
    except OSError as exc:
        raise UnsupportedMediaError(
            f"could not read {display_name(text)} "
            f"({exc.strerror or type(exc).__name__})"
        ) from exc


def _identify(head: bytes) -> str | None:
    """Return a format name for *head*, or ``None`` if nothing matches.

    Recognises unsupported formats too, so the caller can explain *why* a file
    is rejected. Ordering matters only for RIFF, whose form type at offset 8
    distinguishes WAV from AVI.
    """
    if head.startswith(_PNG_SIGNATURE):
        return constants.CONTAINER_PNG
    if head.startswith(_BMP_SIGNATURE):
        return constants.CONTAINER_BMP
    if head.startswith(_RIFF_SIGNATURE) and len(head) >= 12:
        form = head[8:12]
        if form == b"WAVE":
            return constants.CONTAINER_WAV
        if form == b"AVI ":
            return "AVI"
        return None
    if head.startswith(_EBML_SIGNATURE):
        # Matroska and WebM share the EBML header. WebM is only ever VP8/VP9,
        # which is lossy, but the codec check belongs to the video layer; at this
        # level both are "MKV-family container".
        return constants.CONTAINER_MKV
    if head.startswith(_JPEG_SIGNATURE):
        return "JPEG"
    if any(head.startswith(signature) for signature in _GIF_SIGNATURES):
        return "GIF"
    if head.startswith(_FLAC_SIGNATURE):
        return "FLAC"
    if head.startswith(_OGG_SIGNATURE):
        return "OGG"
    if head.startswith(_ID3_SIGNATURE) or head[:2] in (b"\xff\xfb", b"\xff\xf3"):
        return "MP3"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"jp2 ", b"jpx "):
            return "JPEG2000"
        return "MP4"
    if len(head) >= 12 and head[:4] == b"\x00\x00\x00\x0c" and head[4:8] == b"jP  ":
        return "JPEG2000"
    return None


def detect_container(path: str | os.PathLike[str]) -> str:
    """Return the container format detected from the *content* of *path*.

    :raises UnsupportedMediaError: the file is unreadable, or its content is not
        a container this application can carry a payload in. The message names
        the detected format when one was recognised.
    """
    head = _sniff(path)
    detected = _identify(head)
    name = display_name(path)

    if detected is None:
        raise UnsupportedMediaError(
            f"{name} is not a recognised media container; supported covers are "
            f"PNG, BMP, WAV (16-bit PCM) and lossless MKV",
            detected=None,
        )
    if detected not in _CONTAINER_MEDIA_TYPE:
        reason = (
            "that format applies lossy compression, which destroys LSB payloads"
            if detected in constants.LOSSY_FORMAT_NAMES
            else "that format is not supported as a cover object"
        )
        raise UnsupportedMediaError(
            f"{name} was detected as {detected}: {reason}. Supported covers are "
            f"PNG, BMP, WAV (16-bit PCM) and lossless MKV",
            detected=detected,
        )
    return detected


def detect_media_type(path: str | os.PathLike[str]) -> str:
    """Return ``"image"``, ``"audio"`` or ``"video"`` for the content of *path*."""
    return _CONTAINER_MEDIA_TYPE[detect_container(path)]


@dataclass(frozen=True)
class MediaDescription:
    """What can be said about a file without decoding it."""

    path: str
    name: str
    media_type: str
    container_format: str
    size_bytes: int
    size_human: str
    extension: str
    #: ``True`` when the extension disagrees with the detected content. Not an
    #: error: detection wins, but the GUI should say so, because a cover named
    #: ``.bmp`` that is really a PNG will produce a PNG stego object.
    extension_mismatch: bool


def describe_file(path: str | os.PathLike[str]) -> MediaDescription:
    """Describe *path* using content detection and filesystem metadata only."""
    text = os.fspath(path)
    container = detect_container(text)
    size = os.path.getsize(text)
    extension = os.path.splitext(text)[1].lower()
    expected = constants.CONTAINER_EXTENSIONS.get(container)
    # AVI has no entry in CONTAINER_EXTENSIONS because it is readable but never
    # written; treat any recognised video extension as consistent.
    if container == "AVI":
        mismatch = extension not in (".avi",)
    else:
        mismatch = bool(expected) and extension != expected

    return MediaDescription(
        path=text,
        name=display_name(text),
        media_type=_CONTAINER_MEDIA_TYPE[container],
        container_format=container,
        size_bytes=size,
        size_human=human_size(size),
        extension=extension,
        extension_mismatch=mismatch,
    )


# --------------------------------------------------------------------------- #
# Presentation
# --------------------------------------------------------------------------- #


def display_name(path: str | os.PathLike[str]) -> str:
    """Return only the file name component of *path*.

    Error messages and the GUI use this so a user's directory layout does not
    appear in output that may be screenshotted for submission evidence.
    """
    text = os.fspath(path) if hasattr(path, "__fspath__") else str(path)
    name = os.path.basename(text.rstrip("\\/"))
    return name or text


_SIZE_UNITS: Final[tuple[str, ...]] = ("B", "kB", "MB", "GB", "TB")


def human_size(size_bytes: int) -> str:
    """Format a byte count for display, e.g. ``4.21 MB``.

    Uses decimal units (1 kB = 1000 B) to match what file managers report, so a
    figure shown here agrees with what a user sees in Explorer.
    """
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool):
        raise TypeError(
            f"size_bytes must be an integer, got {type(size_bytes).__name__}"
        )
    if size_bytes < 0:
        raise ValueError(f"size_bytes must not be negative, got {size_bytes}")
    if size_bytes < 1000:
        return f"{size_bytes} B"

    value = float(size_bytes)
    for unit in _SIZE_UNITS[1:]:
        value /= 1000.0
        if value < 1000.0:
            return f"{value:.2f} {unit}"
    return f"{value:.2f} {_SIZE_UNITS[-1]}"


# --------------------------------------------------------------------------- #
# Digests
# --------------------------------------------------------------------------- #


def sha256_of_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: str | os.PathLike[str], *, chunk_bytes: int = 1 << 20) -> str:
    """Return the SHA-256 hex digest of the file at *path*, read in chunks.

    Chunked so a large video does not have to be held in memory at once.
    """
    digest = hashlib.sha256()
    with open(os.fspath(path), "rb") as handle:
        while True:
            chunk = handle.read(chunk_bytes)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def ensure_directory(path: str | os.PathLike[str]) -> str:
    """Create the directory at *path* if absent and return it."""
    text = os.fspath(path)
    os.makedirs(text, exist_ok=True)
    return text


def manifest_path_for(stego_path: str | os.PathLike[str]) -> str:
    """Return the companion manifest path for a stego file.

    ``cover_stego.png`` becomes ``cover_stego.png.manifest.json``. The full
    original name is kept, extension included, so a manifest cannot be silently
    paired with a different file that happens to share a stem.
    """
    return os.fspath(stego_path) + constants.MANIFEST_SUFFIX


def suggest_output_path(
    input_path: str | os.PathLike[str],
    *,
    suffix: str = "_stego",
    directory: str | os.PathLike[str] | None = None,
    extension: str | None = None,
) -> str:
    """Suggest an output path beside *input_path* (or inside *directory*)."""
    text = os.fspath(input_path)
    parent = os.fspath(directory) if directory is not None else os.path.dirname(
        os.path.abspath(text)
    )
    stem, original_extension = os.path.splitext(os.path.basename(text))
    return os.path.join(parent, f"{stem}{suffix}{extension or original_extension}")


def unique_path(path: str | os.PathLike[str]) -> str:
    """Return *path*, or the first ``name (n).ext`` variant that does not exist.

    Used for GUI-suggested output names so a second run does not silently
    propose a path that the embed call will then refuse as occupied.
    """
    text = os.fspath(path)
    if not os.path.exists(text):
        return text
    stem, extension = os.path.splitext(text)
    counter = 2
    while True:
        candidate = f"{stem} ({counter}){extension}"
        if not os.path.exists(candidate):
            return candidate
        counter += 1


# --------------------------------------------------------------------------- #
# Atomic writes
# --------------------------------------------------------------------------- #


def _atomic_write(
    path: str | os.PathLike[str], data: bytes, *, overwrite: bool
) -> str:
    text = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(text)) or "."

    if not os.path.isdir(directory):
        raise FileNotFoundError(f"output directory does not exist for {display_name(text)}")
    if os.path.isdir(text):
        raise IsADirectoryError(f"output path is a directory: {display_name(text)}")
    if os.path.exists(text) and not overwrite:
        raise FileExistsError(
            f"output path is already occupied: {display_name(text)}; "
            f"pass overwrite=True to replace it"
        )

    handle, temporary = tempfile.mkstemp(
        prefix=".partial-", suffix=os.path.basename(text), dir=directory
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, text)
    except BaseException:
        # Leave no partial file behind on any failure path, including
        # KeyboardInterrupt.
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return text


def write_bytes_atomic(
    path: str | os.PathLike[str], data: bytes, *, overwrite: bool = False
) -> str:
    """Write *data* to *path* atomically and return the path."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    return _atomic_write(path, bytes(data), overwrite=overwrite)


def write_text_atomic(
    path: str | os.PathLike[str], text: str, *, overwrite: bool = False
) -> str:
    """Write *text* to *path* atomically as UTF-8 and return the path."""
    return _atomic_write(path, text.encode("utf-8"), overwrite=overwrite)


def write_json_atomic(
    path: str | os.PathLike[str], payload: Any, *, overwrite: bool = False
) -> str:
    """Write *payload* to *path* atomically as human-readable UTF-8 JSON.

    Indented and key-sorted because the manifest is meant to be opened, read and
    even hand-edited during the demo. This is *not* the canonical form used for
    signing; that lives in :mod:`app.crypto.envelope` and is deliberately
    separate, so pretty-printing here can never change what was signed.
    """
    encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    return _atomic_write(path, (encoded + "\n").encode("utf-8"), overwrite=overwrite)


def read_json(path: str | os.PathLike[str]) -> Any:
    """Read UTF-8 JSON from *path*."""
    with open(os.fspath(path), "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))
