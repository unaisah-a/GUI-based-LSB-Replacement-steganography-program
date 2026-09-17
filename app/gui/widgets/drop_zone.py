"""Reusable drag-and-drop target for local files."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout


class DropZone(QFrame):
    file_dropped = Signal(str)

    def __init__(self, prompt: str = "Drop a media file here", parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("dropZone")
        self.setMinimumHeight(82)
        layout = QVBoxLayout(self)
        label = QLabel(prompt)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)

    def dragEnterEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        path = Path(event.mimeData().urls()[0].toLocalFile())
        if path.is_file():
            self.file_dropped.emit(str(path))
            event.acceptProposedAction()
        else:
            event.ignore()
