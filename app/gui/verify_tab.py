"""Receiver-side extraction and verification tab."""

from __future__ import annotations

import tempfile
from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.crypto.encryption import decode_key
from app.crypto.key_manager import load_public_key_from_pem, public_key_fingerprint
from app.gui.task_runner import TaskRunner
from app.gui.recovery_panel import RecoveryPanel
from app.gui.widgets import DropZone, MediaPreview, ResultPanel
from app.services.output_files import save_recovered_payload
from app.verification.verdicts import VerificationResult
from app.verification.verifier import verify_media


_PREVIEW_SUFFIXES = {
    "image/png": ".png",
    "image/bmp": ".bmp",
    "audio/wav": ".wav",
    "audio/x-wav": ".wav",
}


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
        self.key_fingerprint = QLabel("Trusted-key fingerprint: choose a public key.")
        self.key_fingerprint.setWordWrap(True)
        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        self.preview = MediaPreview("Received protected media")
        self.recovered_preview = MediaPreview("Trusted recovered payload preview")
        self.results = ResultPanel()
        self.recovery_panel = RecoveryPanel()
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.runner = TaskRunner(self)
        self._verified_result: VerificationResult | None = None
        self._preview_directory: tempfile.TemporaryDirectory[str] | None = None

        root = QVBoxLayout(self)
        drop = DropZone("Party B: drop the downloaded protected media here")
        drop.file_dropped.connect(self._set_media)
        root.addWidget(drop)
        files = QGroupBox("Verification inputs")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Protected media", self.media_path, self._browse_media)
        self._picker(grid, 1, "Companion manifest", self.manifest_path, self._browse_manifest)
        self._picker(grid, 2, "Trusted public key", self.public_key_path, self._browse_key)
        grid.addWidget(self.key_fingerprint, 3, 0, 1, 3)
        grid.addWidget(QLabel("Start secret"), 4, 0)
        grid.addWidget(self.start_secret, 4, 1, 1, 2)
        grid.addWidget(QLabel("Encryption key (if used)"), 5, 0)
        grid.addWidget(self.encryption_key, 5, 1, 1, 2)
        root.addWidget(files)
        self.inputs_group = files
        actions = QHBoxLayout()
        self.verify_button = QPushButton("Extract and verify")
        self.verify_button.setObjectName("primaryButton")
        self.verify_button.clicked.connect(self._verify)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        self.save_button = QPushButton("Save trusted recovered payload…")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._save_recovered)
        actions.addWidget(self.verify_button)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.save_button)
        root.addLayout(actions)
        root.addWidget(self.progress)
        root.addWidget(self.status)
        previews = QHBoxLayout()
        previews.addWidget(self.preview)
        previews.addWidget(self.recovered_preview)
        root.addLayout(previews)
        root.addWidget(self.results, 1)
        root.addWidget(self.recovery_panel)

        for editor in (
            self.media_path,
            self.manifest_path,
            self.public_key_path,
            self.start_secret,
            self.encryption_key,
        ):
            editor.textChanged.connect(self._inputs_changed)
        self.public_key_path.editingFinished.connect(self._update_key_fingerprint)
        self.media_path.textChanged.connect(self.recovery_panel.set_protected_path)
        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.progress.connect(self.status.setText)
        self.runner.succeeded.connect(self._verification_succeeded)
        self.runner.failed.connect(self._verification_failed)
        self.runner.cancelled.connect(self._verification_cancelled)
        self.runner.finished.connect(lambda: self._set_busy(False))

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
            self, "Protected media", "", "Supported media (*.png *.bmp *.wav *.mkv)"
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
            self._update_key_fingerprint()

    def _update_key_fingerprint(self):
        path = self.public_key_path.text().strip()
        if not path:
            self.key_fingerprint.setText("Trusted-key fingerprint: choose a public key.")
            return
        try:
            key = load_public_key_from_pem(path)
            fingerprint = public_key_fingerprint(key)
        except Exception as exc:
            self.key_fingerprint.setText(f"Trusted-key fingerprint unavailable: {exc}")
            return
        grouped = ":".join(fingerprint[index : index + 4] for index in range(0, len(fingerprint), 4))
        self.key_fingerprint.setText(f"Trusted-key fingerprint (SHA-256): {grouped}")

    def _inputs_changed(self):
        if self.runner.busy:
            return
        self._clear_recovered()
        self.results.clear()
        self.status.setText("Inputs changed; run verification again.")

    def _verify(self):
        if self.runner.busy:
            return
        media_path = self.media_path.text().strip()
        manifest_path = self.manifest_path.text().strip()
        public_key_path = self.public_key_path.text().strip()
        start_secret = self.start_secret.text() or None
        key_text = self.encryption_key.text().strip()
        self._clear_recovered()
        self.results.clear()
        self.status.setText("Starting verification…")

        def operation(token, progress):
            token.checkpoint()
            progress("Loading the trusted public key…")
            public_key = load_public_key_from_pem(public_key_path)
            encryption_key = decode_key(key_text) if key_text else None
            token.checkpoint()
            progress("Extracting and verifying the signed payload…")
            result = verify_media(
                media_path,
                manifest_path,
                public_key,
                start_secret=start_secret,
                encryption_key=encryption_key,
            )
            token.checkpoint()
            return result

        self.runner.start(operation)

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.status.setText("Cancellation requested; waiting for a safe checkpoint…")

    def _set_busy(self, busy: bool):
        self.verify_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        self.inputs_group.setEnabled(not busy)

    def _verification_failed(self, exc: Exception):
        self._clear_recovered()
        self.results.clear()
        QMessageBox.critical(self, "Verification failed", str(exc))
        self.status.setText(f"Verification failed: {exc}")

    def _verification_cancelled(self, message: str):
        self._clear_recovered()
        self.results.clear()
        self.status.setText(message)

    def _verification_succeeded(self, result: VerificationResult):
        self.results.set_result(result)
        self.status.setText(result.summary)
        if not result.authentic or result.message is None:
            self._verified_result = None
            self.save_button.setEnabled(False)
            self.recovered_preview.clear("No trusted payload available")
            return
        self._verified_result = result
        self.save_button.setEnabled(True)
        self._show_recovered_preview(result)

    def _show_recovered_preview(self, result: VerificationResult):
        suffix = _PREVIEW_SUFFIXES.get((result.content_type or "").split(";", 1)[0].lower())
        if suffix is None or result.message is None:
            self.recovered_preview.clear("Trusted payload is available to save.")
            return
        self._discard_preview_directory()
        self._preview_directory = tempfile.TemporaryDirectory(prefix="smiv-preview-")
        preview_path = Path(self._preview_directory.name) / f"recovered{suffix}"
        preview_path.write_bytes(result.message)
        self.recovered_preview.set_file(str(preview_path))

    def _suggested_payload_name(self) -> str:
        result = self._verified_result
        if result is not None and isinstance(result.record, dict):
            metadata = result.record.get("metadata")
            if isinstance(metadata, dict):
                candidate = metadata.get("payload_filename")
                if isinstance(candidate, str) and candidate:
                    return Path(candidate).name
        content_type = "" if result is None else (result.content_type or "")
        return "recovered-payload" + _PREVIEW_SUFFIXES.get(content_type.split(";", 1)[0], ".bin")

    def _save_recovered(self):
        result = self._verified_result
        if result is None or not result.authentic or result.message is None:
            QMessageBox.warning(self, "Nothing to save", "Verify an authentic payload first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save trusted recovered payload", self._suggested_payload_name()
        )
        if not path:
            return
        overwrite = Path(path).exists()
        if overwrite and QMessageBox.question(
            self, "Replace recovered file?", "The selected file exists. Replace it?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            save_recovered_payload(path, result.message, overwrite=overwrite)
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.status.setText(f"Trusted recovered payload saved to {Path(path).name}.")

    def _discard_preview_directory(self):
        self.recovered_preview.clear()
        if self._preview_directory is not None:
            self._preview_directory.cleanup()
            self._preview_directory = None

    def _clear_recovered(self):
        self._verified_result = None
        self.save_button.setEnabled(False)
        self._discard_preview_directory()

    def shutdown(self) -> None:
        self.runner.shutdown()
        self.recovery_panel.shutdown()
        self.preview.clear()
        self._discard_preview_directory()
