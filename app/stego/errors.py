"""Exception hierarchy for the image steganography layer.

Requirement 14.7 asks for exactly five distinct exception types, each a direct
subclass of a single common base type, so that a caller can catch one named
category or the whole layer with a single handler.

Image, audio and video all raise from this hierarchy, and :class:`StegoError`
derives from :class:`app.errors.AppError`, which caps every message at 500
characters (Requirement 14.9).

Requirement 14.9 also requires every message to name the failed check and report
the offending value, and to exclude the directory portion of any filesystem path.
Use :func:`app.utils.file_utils.display_name` when a path appears in a message.
"""

from __future__ import annotations

from app.errors import AppError

__all__ = [
    "StegoError",
    "FileError",
    "DecodeError",
    "ValidationError",
    "CapacityError",
    "ExtractionError",
    "ComparisonError",
]


class StegoError(AppError):
    """Common base type for every error raised by the steganography layer.

    Requirement 14.7. Catching this catches every category below.
    """


class FileError(StegoError):
    """A filesystem fault.

    Covers a missing input path, denied read access to an existing input path,
    and an absent or non-writable output directory (Requirement 14.1, 14.5,
    14.8).
    """


class DecodeError(StegoError):
    """A readable file that cannot be decoded as a supported cover object.

    Covers lossy formats, palette images, unsupported sample widths and
    unsupported channel layouts (Requirement 1.5-1.7, Requirement 14.2).
    """


class ValidationError(StegoError):
    """An argument that fails a type or range check.

    Covers payload type, LSB depth, start location, bit-sequence length, sample
    width, output path equal to input path, and mutually exclusive
    difference-image modes (Requirement 2.15, 7.2, 7.6, 9.4, 9.5, 10.5, 13.9,
    13.10, 14.3, 14.4).
    """


class CapacityError(StegoError):
    """The payload does not fit from the requested start location.

    Requirement 6.2, 6.4, 7.3.
    """


class ExtractionError(StegoError):
    """The embedded bit stream cannot be read as a payload.

    Covers a decoded length header inconsistent with the image capacity, a
    truncated bit stream, and a manifest payload length that disagrees with the
    decoded header (Requirement 3.6, 3.7, 4.6, 4.7).

    Requirement 3.9 applies to every instance of this class: an incorrect LSB
    depth, an incorrect start location, an absent payload and sample corruption
    produce indistinguishable bit streams, so the message never asserts which
    of those occurred.
    """


class ComparisonError(ValidationError):
    """Two images that cannot be compared because their shapes differ.

    Requirement 8.4, 10.9. Modelled as a :class:`ValidationError` subclass
    because a shape mismatch is an argument fault, which keeps the count of
    direct :class:`StegoError` subclasses at the five required by
    Requirement 14.7.
    """
