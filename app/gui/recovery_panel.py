"""Receiver-side encrypted recovery-sidecar restoration panel."""

from __future__ import annotations

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
)

from app.crypto.encryption import decode_key
from app.gui.task_runner import TaskRunner
from app.robustness.recovery import inspect_recovery_sidecar
from app.services.operations import OperationControl
from app.services.recovery import restore_recovery_bundle


class RecoveryPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("Restore exact original from encrypted sidecar", parent)
        self.protected_path = QLineEdit()
        self.protected_path.setReadOnly(True)
        self.sidecar_path = QLineEdit()
        self.output_path = QLineEdit()
        self.recovery_key = QLineEdit()
        self.recovery_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.description = QLabel(
            "The sidecar is an encrypted backup of the complete original file, bound "
            "to this protected media. It is not reversible LSB embedding or free capacity."
        )
        self.description.setWordWrap(True)
        self.storage = QLabel("Choose a sidecar to inspect its storage overhead.")
        self.storage.setWordWrap(True)
        self.status = QLabel("Ready to restore after selecting all recovery inputs.")
        self.status.setWordWrap(True)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.runner = TaskRunner(self)

        layout = QVBoxLayout(self)
        layout.addWidget(self.description)
        grid = QGridLayout()
        grid.addWidget(QLabel("Protected media selected above"), 0, 0)
        grid.addWidget(self.protected_path, 0, 1, 1, 2)
        self._picker(grid, 1, "Encrypted sidecar", self.sidecar_path, self._browse_sidecar)
        self._picker(grid, 2, "Restored original output", self.output_path, self._browse_output)
        grid.addWidget(QLabel("Separate recovery key"), 3, 0)
        grid.addWidget(self.recovery_key, 3, 1, 1, 2)
        layout.addLayout(grid)
        layout.addWidget(self.storage)
        actions = QHBoxLayout()
        self.restore_button = QPushButton("Restore and verify original")
        self.restore_button.clicked.connect(self._restore)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        actions.addWidget(self.restore_button)
        actions.addWidget(self.cancel_button)
        layout.addLayout(actions)
        layout.addWidget(self.progress)
        layout.addWidget(self.status)

        self.sidecar_path.editingFinished.connect(self._inspect_sidecar)
        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.progress.connect(self.status.setText)
        self.runner.succeeded.connect(self._restoration_succeeded)
        self.runner.failed.connect(self._restoration_failed)
        self.runner.cancelled.connect(self._restoration_cancelled)
        self.runner.finished.connect(lambda: self._set_busy(False))

    @staticmethod
    def _picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def set_protected_path(self, path: str) -> None:
        if not self.runner.busy:
            self.protected_path.setText(path)

    def _browse_sidecar(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Encrypted recovery sidecar", "", "Recovery sidecars (*.smir);;All files (*)"
        )
        if path:
            self.sidecar_path.setText(path)
            protected = Path(self.protected_path.text())
            suffix = protected.suffix if protected.suffix else ".bin"
            self.output_path.setText(
                str(protected.with_name(f"{protected.stem}_restored{suffix}"))
            )
            self._inspect_sidecar()

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Restore exact original", self.output_path.text(), "All files (*)"
        )
        if path:
            self.output_path.setText(path)

    def _inspect_sidecar(self):
        path = self.sidecar_path.text().strip()
        if not path:
            self.storage.setText("Choose a sidecar to inspect its storage overhead.")
            return
        try:
            inspection = inspect_recovery_sidecar(path)
        except Exception as exc:
            self.storage.setText(f"Sidecar inspection failed: {exc}")
            return
        percent = (
            inspection.sidecar_bytes / inspection.original_bytes * 100
            if inspection.original_bytes
            else 0.0
        )
        self.storage.setText(
            f"Encrypted backup: {inspection.sidecar_bytes:,} bytes for an original "
            f"{inspection.original_bytes:,}-byte file ({percent:.1f}% of original; "
            f"format/authentication overhead {inspection.storage_overhead_bytes:,} bytes)."
        )

    def _restore(self):
        if self.runner.busy:
            return
        try:
            protected = self.protected_path.text().strip()
            sidecar = self.sidecar_path.text().strip()
            output = self.output_path.text().strip()
            if not protected or not sidecar or not output:
                raise ValueError("choose protected media, sidecar, and restoration output")
            key = decode_key(self.recovery_key.text().strip())
            overwrite = Path(output).exists()
            if overwrite and QMessageBox.question(
                self,
                "Replace restored output?",
                "The selected restoration output exists. Replace it only after the "
                "sidecar and protected file authenticate?",
            ) != QMessageBox.StandardButton.Yes:
                self.status.setText("Restoration cancelled; existing output was retained.")
                return
        except Exception as exc:
            self._restoration_failed(exc)
            return
        self.status.setText("Starting sidecar restoration…")
        self.runner.start(
            lambda token, progress: restore_recovery_bundle(
                protected,
                sidecar,
                output,
                key,
                overwrite=overwrite,
                operation=OperationControl(token, progress),
            )
        )

    def _restoration_succeeded(self, result):
        recovery = result.recovery
        self.status.setText(
            f"Restored {recovery.restored_bytes:,} bytes to "
            f"{Path(recovery.output_path).name}; SHA-256 {recovery.original_sha256}."
        )

    def _restoration_failed(self, exc: Exception):
        QMessageBox.critical(self, "Restoration failed", str(exc))
        self.status.setText(f"Restoration failed: {exc}")

    def _restoration_cancelled(self, message: str):
        self.status.setText(message)

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.status.setText("Cancellation requested; existing outputs remain protected…")

    def _set_busy(self, busy: bool):
        self.restore_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        for editor in (self.sidecar_path, self.output_path, self.recovery_key):
            editor.setEnabled(not busy)

    def shutdown(self) -> None:
        self.runner.shutdown()
