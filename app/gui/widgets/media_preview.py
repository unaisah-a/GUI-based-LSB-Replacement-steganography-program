"""Image preview and WAV playback widget."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap
from PySide6.QtMultimedia import QAudioOutput, QMediaPlayer
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)


class MediaPreview(QGroupBox):
    def __init__(self, title: str, parent=None):
        super().__init__(title, parent)
        self._path: str | None = None
        self._image = QLabel("No media selected")
        self._image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._image.setMinimumHeight(190)
        self._image.setWordWrap(True)
        self._play = QPushButton("Play")
        self._pause = QPushButton("Pause")
        self._play.setEnabled(False)
        self._pause.setEnabled(False)
        self._audio = QAudioOutput(self)
        self._player = QMediaPlayer(self)
        self._player.setAudioOutput(self._audio)
        self._play.clicked.connect(self._player.play)
        self._pause.clicked.connect(self._player.pause)
        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self._play)
        buttons.addWidget(self._pause)
        buttons.addStretch()
        layout = QVBoxLayout(self)
        layout.addWidget(self._image, 1)
        layout.addLayout(buttons)

    def clear(self, message: str = "No media selected") -> None:
        self._path = None
        self._player.stop()
        self._player.setSource(QUrl())
        self._image.setPixmap(QPixmap())
        self._image.setText(message)
        self._play.setEnabled(False)
        self._pause.setEnabled(False)

    def set_file(self, path: str) -> None:
        self._path = path
        suffix = Path(path).suffix.lower()
        if suffix in {".png", ".bmp"}:
            pixmap = QPixmap(path)
            if pixmap.isNull():
                self._image.setText("Image preview unavailable")
            else:
                self._image.setPixmap(
                    pixmap.scaled(
                        480,
                        280,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
            self._player.stop()
            self._play.setEnabled(False)
            self._pause.setEnabled(False)
        elif suffix in {".wav", ".mkv", ".mp4", ".mov", ".avi"}:
            self._image.setPixmap(QPixmap())
            media_label = "PCM WAV" if suffix == ".wav" else "Video"
            self._image.setText(f"{media_label}\n{Path(path).name}")
            self._player.setSource(QUrl.fromLocalFile(str(Path(path).resolve())))
            self._play.setEnabled(True)
            self._pause.setEnabled(True)
        else:
            self._image.setPixmap(QPixmap())
            self._image.setText(Path(path).name)
            self._play.setEnabled(False)
            self._pause.setEnabled(False)
