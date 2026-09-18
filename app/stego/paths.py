"""Filesystem validation shared by every steganography medium.

Image, audio and video all call these, so every medium refuses an in-place write,
an occupied output path and an unreadable input in exactly the same way.

Every function raises from the :mod:`app.stego.errors` hierarchy, and messages
name only the file, never its directory (Requirement 14.9), because they are
surfaced in the GUI and may appear in submission screenshots.
"""

from __future__ import annotations

import os

from app.stego.errors import FileError, ValidationError
from app.utils.file_utils import display_name

__all__ = [
    "assert_distinct_paths",
    "assert_readable",
    "check_output_writable",
]


def assert_readable(path: str | os.PathLike[str]) -> None:
    """Check that *path* exists and can be read, without decoding it.

    Requirement 14.6 orders this before any check on the output path, so that a
    missing input is reported before anything about the destination.
    """
    text = os.fspath(path)
    name = display_name(path)

    if not os.path.exists(text):
        raise FileError(f"input file not found: {name}")
    if os.path.isdir(text):
        raise FileError(f"input path is a directory, not a file: {name}")
    try:
        with open(text, "rb") as handle:
            handle.read(1)
    except PermissionError as exc:
        raise FileError(f"read access denied for input file: {name}") from exc
    except OSError as exc:
        raise FileError(
            f"input file could not be read: {name} "
            f"({exc.strerror or type(exc).__name__})"
        ) from exc


def assert_distinct_paths(
    input_path: str | os.PathLike[str], output_path: str | os.PathLike[str]
) -> None:
    """Reject an output path that resolves to the input file (Requirement 2.15).

    Embedding in place would destroy the cover object, and the cover must be left
    byte-for-byte unchanged (Requirement 2.12). ``realpath`` catches the common
    case; ``samefile`` additionally catches hard links and junctions, and is only
    reachable when the target already exists.
    """
    source = os.fspath(input_path)
    target = os.fspath(output_path)

    same = os.path.realpath(source) == os.path.realpath(target)
    if not same and os.path.exists(target):
        try:
            same = os.path.samefile(source, target)
        except OSError:
            same = False
    if same:
        raise ValidationError(
            f"output path must differ from the input path, both resolve to "
            f"{display_name(source)}"
        )


def check_output_writable(path: str | os.PathLike[str], overwrite: bool) -> None:
    """Validate the output location before any sample is modified.

    Requirement 14.5 (the directory must exist and be writable) and
    Requirement 6.6 (an occupied output path is an error unless *overwrite* is
    set).
    """
    text = os.fspath(path)
    name = display_name(path)
    directory = os.path.dirname(os.path.abspath(text))

    if not os.path.isdir(directory):
        raise FileError(f"output directory does not exist for {name}")
    if not os.access(directory, os.W_OK):
        raise FileError(f"output directory is not writable for {name}")
    if os.path.isdir(text):
        raise FileError(f"output path is a directory, not a file: {name}")
    if os.path.exists(text) and not overwrite:
        raise FileError(
            f"output path is already occupied: {name}; pass overwrite=True to "
            f"replace it"
        )
