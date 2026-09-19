"""Application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from app.gui.main_window import MainWindow


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv if argv is None else argv)
    smoke_test = "--smoke-test" in arguments
    arguments = [argument for argument in arguments if argument != "--smoke-test"]
    application = QApplication(arguments)
    application.setApplicationName("Steganographic Media Integrity Lab")
    application.setOrganizationName("INF2005")
    window = MainWindow()
    window.show()
    if smoke_test:
        QTimer.singleShot(500, application.quit)
    exit_code = application.exec()
    if smoke_test and exit_code == 0:
        print("Application startup smoke check passed.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
