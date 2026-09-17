"""Running backend work off the user interface thread.

Every operation the tabs trigger can take long enough to freeze the window if it
runs inline. Embedding into a large PNG, deriving a key with scrypt at the
production cost, computing bit planes over millions of samples, and anything to do
with video are all in that category. Qt repaints only from the main thread, so a
long call there produces a window that stops responding, which during a live
demonstration looks like a crash.

So all of it goes through :class:`BackgroundRunner`. Tabs hand over a plain
callable and receive the result back on the main thread through a signal.

Why ``QRunnable`` and a pool
----------------------------
The alternative is a ``QThread`` per operation, which means managing a thread
object's lifetime alongside the widget that started it — a common source of "QThread
destroyed while still running" warnings when a user closes a tab mid-operation. A
pool owns the threads, the runnable is disposable, and the widget only has to keep
the signal connection alive.

Exceptions are values here
--------------------------
An exception raised inside a worker cannot propagate to the caller: there is no
caller left on that stack. :class:`Worker` therefore catches everything and emits
:attr:`WorkerSignals.failed` with a message and the exception. A tab connects that
to something that shows the message, so a backend error becomes a visible label
rather than a traceback printed to a console nobody is watching.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from app.utils.logging_utils import get_logger

__all__ = [
    "BackgroundRunner",
    "Worker",
    "WorkerSignals",
    "describe_exception",
]

_log = get_logger(__name__)


def describe_exception(error: BaseException) -> str:
    """Return a message suitable for showing a user.

    The application's own error types already carry messages written to be read, so
    those are used as they are. Anything else gets its type name prefixed, because a
    bare ``KeyError: 'nonce'`` on its own tells a user nothing about what failed.
    """
    from app.crypto.errors import CryptoError
    from app.stego.errors import StegoError
    from app.utils.file_utils import UnsupportedMediaError

    if isinstance(error, (StegoError, CryptoError, UnsupportedMediaError)):
        return str(error)

    message = str(error).strip()
    if not message:
        return f"{type(error).__name__} (no further detail available)"
    return f"{type(error).__name__}: {message}"


class WorkerSignals(QObject):
    """Signals a worker emits.

    Kept on a separate ``QObject`` because ``QRunnable`` is not one and so cannot
    carry signals itself.
    """

    #: The callable returned normally. Carries whatever it returned.
    succeeded = Signal(object)
    #: The callable raised. Carries (message, traceback text).
    failed = Signal(str, str)
    #: Always emitted last, whichever of the above fired. For re-enabling controls.
    finished = Signal()


class Worker(QRunnable):
    """Runs one callable on a pool thread and reports the outcome by signal."""

    def __init__(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._function = function
        self._args = args
        self._kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:  # pragma: no cover - exercised through BackgroundRunner
        try:
            result = self._function(*self._args, **self._kwargs)
        except BaseException as error:  # noqa: BLE001 - see the module docstring
            detail = traceback.format_exc()
            _log.exception("background task failed: %s", self._function)
            self.signals.failed.emit(describe_exception(error), detail)
        else:
            self.signals.succeeded.emit(result)
        finally:
            self.signals.finished.emit()


class BackgroundRunner:
    """Submits callables to a thread pool and wires up their callbacks.

    One instance per tab. Holding a reference to each live worker matters: without
    it Python can collect the worker, and with it the ``WorkerSignals`` object the
    connections live on, so a completed operation would silently deliver nothing.
    """

    def __init__(self, max_thread_count: int | None = None) -> None:
        self._pool = QThreadPool()
        if max_thread_count is not None:
            self._pool.setMaxThreadCount(max_thread_count)
        self._active: list[Worker] = []

    @property
    def pool(self) -> QThreadPool:
        return self._pool

    @property
    def active_count(self) -> int:
        return len(self._active)

    def submit(
        self,
        function: Callable[..., Any],
        *args: Any,
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[str, str], None] | None = None,
        on_finished: Callable[[], None] | None = None,
        **kwargs: Any,
    ) -> Worker:
        """Run *function* on a pool thread and return the worker.

        The returned worker is mostly useful for tests, which call ``run()`` on it
        directly to get deterministic, synchronous behaviour.
        """
        worker = Worker(function, *args, **kwargs)

        if on_success is not None:
            worker.signals.succeeded.connect(on_success)
        if on_error is not None:
            worker.signals.failed.connect(on_error)
        if on_finished is not None:
            worker.signals.finished.connect(on_finished)

        self._active.append(worker)
        worker.signals.finished.connect(lambda: self._release(worker))

        self._pool.start(worker)
        return worker

    def _release(self, worker: Worker) -> None:
        try:
            self._active.remove(worker)
        except ValueError:  # pragma: no cover - already released
            pass

    def wait(self, timeout_milliseconds: int = 30_000) -> bool:
        """Block until every submitted task has finished.

        Used when closing the window, so a half-finished write is not abandoned, and
        by tests that need to synchronise.
        """
        return self._pool.waitForDone(timeout_milliseconds)
