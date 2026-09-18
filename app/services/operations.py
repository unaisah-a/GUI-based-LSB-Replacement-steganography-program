"""Cooperative progress and cancellation for application service operations."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Callable


class OperationCancelled(RuntimeError):
    """Raised at a safe checkpoint when the user cancels an operation."""


class CancellationToken:
    """Thread-safe cancellation request shared by a GUI worker and a service."""

    def __init__(self) -> None:
        self._requested = Event()

    @property
    def requested(self) -> bool:
        return self._requested.is_set()

    def cancel(self) -> None:
        self._requested.set()

    def checkpoint(self) -> None:
        if self.requested:
            raise OperationCancelled("Operation cancelled.")


@dataclass(frozen=True)
class OperationControl:
    """Optional runtime hooks kept out of persistent workflow data."""

    cancellation: CancellationToken
    progress: Callable[[str], None] | None = None

    def checkpoint(self, message: str | None = None) -> None:
        self.cancellation.checkpoint()
        if message is not None and self.progress is not None:
            self.progress(message)

