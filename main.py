"""Entry point for the media integrity and steganography tool.

    python main.py

Everything of substance lives under ``app/``. This module only starts Qt, applies
the stylesheet, shows the window and hands control to the event loop, so that the
application's behaviour is testable without going through here.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.utils import constants
from app.utils.logging_utils import configure_logging, get_logger

STYLESHEET_PATH = Path(__file__).resolve().parent / "assets" / "styles" / "app.qss"


def load_stylesheet() -> str:
    """Return the application stylesheet, or an empty string if it is absent.

    A missing stylesheet is not worth refusing to start over: the window is fully
    usable unstyled, and failing here would turn a cosmetic problem into a fatal one.
    """
    try:
        return STYLESHEET_PATH.read_text(encoding="utf-8")
    except OSError:
        return ""


def main(argv: list[str] | None = None) -> int:
    """Start the application and return its exit code."""
    from PySide6.QtWidgets import QApplication

    from app.gui.main_window import MainWindow

    configure_logging()
    log = get_logger(__name__)
    log.info("starting %s %s", constants.APP_NAME, constants.APP_VERSION)

    application = QApplication(argv if argv is not None else sys.argv)
    application.setApplicationName(constants.APP_NAME)
    application.setApplicationVersion(constants.APP_VERSION)
    application.setOrganizationName(constants.APP_SHORT_NAME)

    stylesheet = load_stylesheet()
    if stylesheet:
        application.setStyleSheet(stylesheet)
    else:
        log.warning("stylesheet not found at %s; using default styling", STYLESHEET_PATH)

    window = MainWindow()
    window.show()

    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
