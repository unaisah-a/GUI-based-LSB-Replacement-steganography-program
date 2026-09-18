"""A drag-and-drop target with a file picker fallback.

Drag-and-drop is a stated requirement, but on its own it is not enough: a file
picker is needed for anyone driving the application by keyboard, and it is also how
the demonstration will usually select files. Both routes emit the same signal, so a
tab handles one path in one place.

What this widget validates, and what it does not
------------------------------------------------
It checks that a drop carries exactly one local file and, if the caller restricted
the media types, that the file's *content* is one of them. That check is the same
content sniff the backend uses, so the immediate feedback and the eventual result
agree.

It does not decide whether the file is usable. A PNG with dimensions the stego layer
rejects, or a WAV with the wrong sample width, passes this widget and is reported
properly by the layer that actually knows. Duplicating that judgement here would
mean two places to keep in step.
"""

from __future__ import annotations

import os
from typing import Iterable

from PySide6.QtCore import QMimeData, Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDragLeaveEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.utils import constants, file_utils

__all__ = ["DropZone", "file_dialog_filter"]


def file_dialog_filter(media_types: Iterable[str] | None = None) -> str:
    """Build a Qt file-dialog filter string for the given media types.

    Extensions here only shape what the dialog shows. Detection is by content, so a
    mislabelled file selected through "All files" is still handled correctly.
    """
    selected = tuple(media_types) if media_types else constants.MEDIA_TYPES
    groups: list[str] = []
    every: list[str] = []

    for media_type in selected:
        extensions = constants.OPEN_FILE_EXTENSIONS.get(media_type, ())
        if not extensions:
            continue
        patterns = " ".join(f"*{extension}" for extension in extensions)
        groups.append(f"{media_type.capitalize()} files ({patterns})")
        every.extend(f"*{extension}" for extension in extensions)

    if len(groups) > 1:
        groups.insert(0, f"Supported media ({' '.join(every)})")
    groups.append("All files (*)")
    return ";;".join(groups)


class DropZone(QFrame):
    """A bordered panel that accepts a dropped file or opens a file picker."""

    #: Emitted with an absolute path when a file is accepted by either route.
    fileSelected = Signal(str)
    #: Emitted with a reason when a drop is refused, so a tab can show it.
    selectionRejected = Signal(str)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        media_types: Iterable[str] | None = None,
        prompt: str = "Drag an image, audio or video file here",
        button_text: str = "Select File",
    ) -> None:
        super().__init__(parent)
        self._media_types = tuple(media_types) if media_types else None
        self._prompt = prompt
        self._selected_path: str | None = None

        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setMinimumHeight(110)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._prompt_label = QLabel(prompt, self)
        self._prompt_label.setObjectName("dropZonePrompt")
        self._prompt_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._prompt_label.setWordWrap(True)
        layout.addWidget(self._prompt_label)

        self._detail_label = QLabel("", self)
        self._detail_label.setObjectName("dropZoneDetail")
        self._detail_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._detail_label.setWordWrap(True)
        layout.addWidget(self._detail_label)

        button_row = QHBoxLayout()
        button_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._browse_button = QPushButton(button_text, self)
        self._browse_button.setObjectName("dropZoneBrowse")
        self._browse_button.clicked.connect(self.open_file_dialog)
        button_row.addWidget(self._browse_button)

        self._clear_button = QPushButton("Clear", self)
        self._clear_button.setObjectName("dropZoneClear")
        self._clear_button.clicked.connect(self.clear)
        self._clear_button.setEnabled(False)
        button_row.addWidget(self._clear_button)
        layout.addLayout(button_row)

    # -- state ------------------------------------------------------------- #

    @property
    def selected_path(self) -> str | None:
        return self._selected_path

    def clear(self) -> None:
        """Forget the current selection and restore the prompt."""
        self._selected_path = None
        self._prompt_label.setText(self._prompt)
        self._detail_label.setText("")
        self._clear_button.setEnabled(False)
        self.setProperty("state", "")
        self._restyle()

    # -- selection --------------------------------------------------------- #

    def open_file_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a media file",
            "",
            file_dialog_filter(self._media_types),
        )
        if path:
            self.accept_path(path)

    def accept_path(self, path: str) -> bool:
        """Validate and accept *path*, emitting the appropriate signal.

        Returns whether the path was accepted, which is what the tests assert on.
        """
        reason = self._rejection_reason(path)
        if reason is not None:
            self._detail_label.setText(reason)
            self.setProperty("state", "rejected")
            self._restyle()
            self.selectionRejected.emit(reason)
            return False

        self._selected_path = os.path.abspath(path)
        self._prompt_label.setText(file_utils.display_name(path))

        try:
            description = file_utils.describe_file(self._selected_path)
            self._detail_label.setText(
                f"{description.media_type} / {description.container_format} - "
                f"{description.size_human}"
            )
        except file_utils.UnsupportedMediaError:  # pragma: no cover - guarded above
            self._detail_label.setText("")

        self._clear_button.setEnabled(True)
        self.setProperty("state", "accepted")
        self._restyle()
        self.fileSelected.emit(self._selected_path)
        return True

    def _rejection_reason(self, path: str) -> str | None:
        if not os.path.isfile(path):
            return f"{file_utils.display_name(path)} is not a file"
        try:
            media_type = file_utils.detect_media_type(path)
        except file_utils.UnsupportedMediaError as exc:
            return str(exc)
        if self._media_types and media_type not in self._media_types:
            wanted = " or ".join(self._media_types)
            return (
                f"{file_utils.display_name(path)} is {media_type} media, but this "
                f"panel accepts {wanted}"
            )
        return None

    def _restyle(self) -> None:
        # Qt does not re-evaluate a stylesheet when a dynamic property changes, so
        # the style has to be reapplied explicitly for the border colour to update.
        self.style().unpolish(self)
        self.style().polish(self)

    # -- drag and drop ----------------------------------------------------- #

    @staticmethod
    def _single_local_file(mime: QMimeData) -> str | None:
        if not mime.hasUrls():
            return None
        urls = [url for url in mime.urls() if url.isLocalFile()]
        if len(urls) != 1:
            return None
        return urls[0].toLocalFile()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        path = self._single_local_file(event.mimeData())
        if path is None:
            event.ignore()
            return
        event.acceptProposedAction()
        self.setProperty("state", "hover")
        self._restyle()

    def dragLeaveEvent(self, event: QDragLeaveEvent) -> None:
        self.setProperty("state", "")
        self._restyle()
        event.accept()

    def dropEvent(self, event: QDropEvent) -> None:
        path = self._single_local_file(event.mimeData())
        if path is None:
            self.selectionRejected.emit("drop exactly one local file")
            event.ignore()
            return
        event.acceptProposedAction()
        self.accept_path(path)
