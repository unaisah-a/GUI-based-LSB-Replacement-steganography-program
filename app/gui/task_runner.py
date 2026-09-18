"""Reusable QThread runner for GUI operations."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal

from app.services.operations import CancellationToken, OperationCancelled


class _TaskThread(QThread):
    succeeded = Signal(object)
    failed = Signal(object)
    cancelled = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        operation: Callable[[CancellationToken, Callable[[str], None]], Any],
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self.operation = operation
        self.token = CancellationToken()

    def run(self) -> None:
        try:
            self.token.checkpoint()
            result = self.operation(self.token, self.progress.emit)
        except OperationCancelled as exc:
            self.cancelled.emit(str(exc))
        except Exception as exc:  # Errors are rendered by the owning tab.
            self.failed.emit(exc)
        else:
            self.succeeded.emit(result)


class TaskRunner(QObject):
    """Own one background task and deliver its outcome on the GUI thread."""

    started = Signal()
    progress = Signal(str)
    succeeded = Signal(object)
    failed = Signal(object)
    cancelled = Signal(str)
    finished = Signal()

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._thread: _TaskThread | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def start(
        self,
        operation: Callable[[CancellationToken, Callable[[str], None]], Any],
    ) -> None:
        if self.busy:
            raise RuntimeError("an operation is already running")
        thread = _TaskThread(operation, self)
        thread.progress.connect(self.progress.emit)
        thread.succeeded.connect(self.succeeded.emit)
        thread.failed.connect(self.failed.emit)
        thread.cancelled.connect(self.cancelled.emit)
        thread.finished.connect(self._task_finished)
        self._thread = thread
        thread.start()
        self.started.emit()

    def cancel(self) -> None:
        if self._thread is not None:
            self._thread.token.cancel()

    def _task_finished(self) -> None:
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.deleteLater()
        self.finished.emit()

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Request cancellation and wait briefly during application shutdown."""
        thread = self._thread
        if thread is None:
            return
        self.cancel()
        thread.wait(timeout_ms)
