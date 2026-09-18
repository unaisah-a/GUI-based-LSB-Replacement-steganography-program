"""Application logging.

Log records go to ``evidence/logs/`` because the assignment expects logs as
submission evidence, and to stderr so a developer running from a terminal sees
them immediately.

Only the application entry point configures logging, by calling
:func:`configure_logging` from ``main()``. Modules call :func:`get_logger`, which
never configures anything, so importing any part of ``app`` creates no directory
and opens no file. Until ``main()`` runs, records follow Python's defaults, which
is what lets pytest capture them in tests.

The log file rotates at :data:`MAX_LOG_BYTES`, keeping :data:`LOG_BACKUP_COUNT`
old files, so a long-lived checkout cannot grow it without bound.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
from pathlib import Path
from typing import Final

from app.utils import constants

__all__ = [
    "DEFAULT_LOG_FILE_NAME",
    "LOG_DIRECTORY_NAME",
    "get_logger",
    "configure_logging",
    "log_directory",
    "reset_logging",
]

LOGGER_NAME: Final[str] = "inf2005"
LOG_DIRECTORY_NAME: Final[str] = os.path.join("evidence", "logs")
DEFAULT_LOG_FILE_NAME: Final[str] = "application.log"
MAX_LOG_BYTES: Final[int] = 1_000_000
LOG_BACKUP_COUNT: Final[int] = 3

_FORMAT: Final[str] = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"

#: Guards the one-time handler installation. The GUI runs work on QThreads, so
#: two threads can reach the first logging call at the same time; without this a
#: handler could be attached twice and every record would appear twice.
_lock = threading.Lock()
_configured = False


def repository_root() -> Path:
    """Return the repository root, derived from this file's location.

    ``app/utils/logging_utils.py`` is three levels below the root. Deriving the
    root from ``__file__`` rather than the working directory means logs land in
    the same place no matter where the process was started from, which is the
    same mistake that made the old audio quality "test" fail on collection.
    """
    return Path(__file__).resolve().parents[2]


def log_directory() -> Path:
    """Return the directory log files are written to."""
    return repository_root() / LOG_DIRECTORY_NAME


def configure_logging(
    *,
    level: int = logging.INFO,
    file_name: str = DEFAULT_LOG_FILE_NAME,
    to_file: bool = True,
    to_stderr: bool = True,
) -> logging.Logger:
    """Install handlers on the application logger once and return it.

    Called by ``main()``. Repeat calls are no-ops. Use :func:`reset_logging` in a
    test that needs to reconfigure.
    """
    global _configured

    logger = logging.getLogger(LOGGER_NAME)
    with _lock:
        if _configured:
            return logger

        logger.setLevel(level)
        # Records are handled here and must not also reach the root logger, which
        # pytest and other tooling install their own handlers on.
        logger.propagate = False
        formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)

        if to_stderr:
            stream_handler = logging.StreamHandler(sys.stderr)
            stream_handler.setFormatter(formatter)
            logger.addHandler(stream_handler)

        if to_file:
            try:
                directory = log_directory()
                directory.mkdir(parents=True, exist_ok=True)
                file_handler = logging.handlers.RotatingFileHandler(
                    directory / file_name,
                    maxBytes=MAX_LOG_BYTES,
                    backupCount=LOG_BACKUP_COUNT,
                    encoding="utf-8",
                )
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except OSError:
                # A read-only checkout or a locked file must not stop the
                # application from running; stderr logging still works. Reported
                # through the logger itself rather than swallowed silently.
                logger.warning(
                    "file logging disabled: %s is not writable", log_directory()
                )

        if not logger.handlers:
            logger.addHandler(logging.NullHandler())

        _configured = True

    logger.debug(
        "%s %s logging initialised", constants.APP_SHORT_NAME, constants.APP_VERSION
    )
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child of the application logger. Never configures logging.

    ``get_logger(__name__)`` in ``app.stego.image_stego`` yields
    ``inf2005.app.stego.image_stego``, so log output identifies its source module.
    """
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(LOGGER_NAME).getChild(name)


def reset_logging() -> None:
    """Remove installed handlers so the next call reconfigures. For tests."""
    global _configured

    logger = logging.getLogger(LOGGER_NAME)
    with _lock:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover - handler already closed
                pass
        _configured = False
