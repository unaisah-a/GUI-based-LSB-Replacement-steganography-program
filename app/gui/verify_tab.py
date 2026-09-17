"""Receiver-side extraction and verification tab."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.crypto.encryption import decode_key
from app.crypto.key_manager import load_public_key_from_pem
from app.gui.widgets import DropZone, MediaPreview, ResultPanel
from app.verification.verifier import verify_media


class VerifyTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.media_path = QLineEdit()
        self.manifest_path = QLineEdit()
        self.public_key_path = QLineEdit()
        self.start_secret = QLineEdit()
        self.start_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.encryption_key = QLineEdit()
        self.encryption_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.preview = MediaPreview("Received protected media")
        self.results = ResultPanel()

        root = QVBoxLayout(self)
        drop = DropZone("Party B: drop the downloaded protected media here")
        drop.file_dropped.connect(self._set_media)
        root.addWidget(drop)
        files = QGroupBox("Verification inputs")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Protected media", self.media_path, self._browse_media)
        self._picker(grid, 1, "Companion manifest", self.manifest_path, self._browse_manifest)
        self._picker(grid, 2, "Trusted public key", self.public_key_path, self._browse_key)
        grid.addWidget(QLabel("Start secret"), 3, 0)
        grid.addWidget(self.start_secret, 3, 1, 1, 2)
        grid.addWidget(QLabel("Encryption key (if used)"), 4, 0)
        grid.addWidget(self.encryption_key, 4, 1, 1, 2)
        root.addWidget(files)
        button = QPushButton("Extract and verify")
        button.setObjectName("primaryButton")
        button.clicked.connect(self._verify)
        root.addWidget(button)
        root.addWidget(self.preview)
        root.addWidget(self.results, 1)

    @staticmethod
    def _picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _set_media(self, path: str):
        self.media_path.setText(path)
        self.preview.set_file(path)

    def _browse_media(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Protected media", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self._set_media(path)

    def _browse_manifest(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Companion manifest", "", "JSON manifest (*.json)"
        )
        if path:
            self.manifest_path.setText(path)

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Trusted public key", "", "PEM keys (*.pem)"
        )
        if path:
            self.public_key_path.setText(path)

    def _verify(self):
        try:
            public_key = load_public_key_from_pem(self.public_key_path.text().strip())
            key_text = self.encryption_key.text().strip()
            result = verify_media(
                self.media_path.text().strip(),
                self.manifest_path.text().strip(),
                public_key,
                start_secret=self.start_secret.text() or None,
                encryption_key=decode_key(key_text) if key_text else None,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Verification failed", str(exc))
            return
        self.results.set_result(result)
