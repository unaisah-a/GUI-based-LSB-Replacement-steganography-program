"""Describe, label and name a payload that is a file rather than typed text.

The stego and crypto layers carry arbitrary bytes. What they cannot do on their own
is tell the receiver *what* those bytes were, so a recovered PNG would arrive as an
anonymous blob. The sender therefore records the original file name and a type hint
in the verification record's ``metadata`` mapping, which is signed with everything
else, and the receiver uses them to propose a sensible name when saving.

Two rules keep this safe on the receiving side:

* The *preview* decision is made by sniffing the recovered bytes, never by trusting
  the type hint. A file that claims to be an image but is not one is shown as hex.
* The recorded name is reduced to a bare, harmless file name before it is offered as
  a default. A signature proves who sent a name, not that the name is benign, so
  ``..\\..\\startup\\run.bat`` becomes ``run.bat`` and still needs the user to click
  Save.

Nothing here imports Qt, so the rules are tested without a window.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "KIND_AUDIO",
    "KIND_BINARY",
    "KIND_IMAGE",
    "KIND_TEXT",
    "MAX_PAYLOAD_FILE_BYTES",
    "METADATA_CONTENT_TYPE",
    "METADATA_FILENAME",
    "PAYLOAD_FILE_FILTER",
    "PayloadType",
    "detect_payload_type",
    "metadata_for_file",
    "safe_filename",
    "suggested_filename",
]

KIND_TEXT: Final[str] = "text"
KIND_IMAGE: Final[str] = "image"
KIND_AUDIO: Final[str] = "audio"
KIND_BINARY: Final[str] = "binary"

#: Keys used in the signed record's ``metadata`` mapping.
METADATA_FILENAME: Final[str] = "filename"
METADATA_CONTENT_TYPE: Final[str] = "content_type"

#: Larger files are refused before they are read. Far beyond what any cover here can
#: carry, so it only stops an accidental multi-gigabyte selection from being loaded.
MAX_PAYLOAD_FILE_BYTES: Final[int] = 64 * 1024 * 1024

PAYLOAD_FILE_FILTER: Final[str] = (
    "Supported payloads (*.txt *.png *.bmp *.jpg *.jpeg *.wav *.mp3);;"
    "Text files (*.txt);;"
    "Images (*.png *.bmp *.jpg *.jpeg);;"
    "Audio (*.wav *.mp3);;"
    "All files (*)"
)

_FALLBACK_STEM: Final[str] = "recovered_payload"
_MAX_NAME_LENGTH: Final[int] = 120
# Characters Windows forbids in a file name, plus control characters.
_UNSAFE_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED_WINDOWS_NAMES: Final[frozenset[str]] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{n}" for n in range(1, 10)}
    | {f"LPT{n}" for n in range(1, 10)}
)


@dataclass(frozen=True)
class PayloadType:
    """What a payload's bytes appear to be."""

    kind: str
    content_type: str
    extension: str
    label: str

    @property
    def previewable(self) -> bool:
        """Whether :class:`~app.gui.widgets.media_preview.MediaPreview` can show it."""
        return self.kind in (KIND_IMAGE, KIND_AUDIO)


_TEXT = PayloadType(KIND_TEXT, "text/plain", ".txt", "UTF-8 text")
_BINARY = PayloadType(KIND_BINARY, "application/octet-stream", ".bin", "binary data")


def _is_mp3(data: bytes) -> bool:
    if data.startswith(b"ID3"):
        return True
    # An MPEG audio frame sync: eleven set bits, then a valid version and layer III.
    return len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE6) == 0xE2


def detect_payload_type(data: bytes) -> PayloadType:
    """Identify *data* from its content alone."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return PayloadType(KIND_IMAGE, "image/png", ".png", "PNG image")
    if data.startswith(b"\xff\xd8\xff"):
        return PayloadType(KIND_IMAGE, "image/jpeg", ".jpg", "JPEG image")
    if data.startswith(b"BM") and len(data) >= 26:
        return PayloadType(KIND_IMAGE, "image/bmp", ".bmp", "BMP image")
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return PayloadType(KIND_AUDIO, "audio/wav", ".wav", "WAV audio")
    if _is_mp3(data):
        return PayloadType(KIND_AUDIO, "audio/mpeg", ".mp3", "MP3 audio")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return _BINARY
    return _TEXT


def safe_filename(name: object) -> str | None:
    """Reduce *name* to a bare, harmless file name, or ``None`` if nothing is left.

    Directory parts are dropped whichever separator they use, characters Windows
    rejects are replaced, leading dots are removed so the result is never hidden or
    relative, and reserved device names are refused.
    """
    if not isinstance(name, str):
        return None
    base = re.split(r"[\\/]", name)[-1]
    base = _UNSAFE_CHARACTERS.sub("_", base).strip().lstrip(".").rstrip(". ")
    if not base:
        return None
    stem, extension = os.path.splitext(base)
    if stem.upper() in _RESERVED_WINDOWS_NAMES:
        return None
    if len(base) > _MAX_NAME_LENGTH:
        base = stem[: _MAX_NAME_LENGTH - len(extension)] + extension
    return base


def metadata_for_file(path: str | os.PathLike[str], data: bytes) -> dict[str, str]:
    """The metadata a sender records for a file payload."""
    name = safe_filename(os.path.basename(os.fspath(path))) or _FALLBACK_STEM
    return {
        METADATA_FILENAME: name,
        METADATA_CONTENT_TYPE: detect_payload_type(data).content_type,
    }


def suggested_filename(metadata: Mapping[str, Any] | None, data: bytes) -> str:
    """A default name for saving recovered *data*.

    The recorded file name when there is a usable one, otherwise a fixed stem with
    the extension the content was detected as.
    """
    recorded = safe_filename((metadata or {}).get(METADATA_FILENAME))
    if recorded is not None:
        return recorded
    return _FALLBACK_STEM + detect_payload_type(data).extension
