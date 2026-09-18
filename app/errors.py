"""The one base class for every error this application raises on purpose.

Each layer keeps its own family — :class:`app.stego.errors.StegoError`,
:class:`app.crypto.errors.CryptoError` and the rest — so a caller can still catch
exactly one category. Every family derives from :class:`AppError`, so the interface
can tell an expected, user-readable failure from a programming error with a single
``except AppError``.

This module imports nothing from the application, so any layer can use it.
"""

from __future__ import annotations

from typing import Final

__all__ = ["MAX_MESSAGE_LENGTH", "AppError"]

#: Messages are shown in the interface and may appear in screenshots, so they are
#: capped: a corrupt field must not be able to produce a megabyte of text in a label.
MAX_MESSAGE_LENGTH: Final[int] = 500


class AppError(Exception):
    """An expected failure, with a message written to be shown to a user."""

    def __init__(self, message: str) -> None:
        if len(message) > MAX_MESSAGE_LENGTH:
            message = message[: MAX_MESSAGE_LENGTH - 3] + "..."
        super().__init__(message)
