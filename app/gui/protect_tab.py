"""Protect/sign workflow tab."""

from __future__ import annotations

import mimetypes
from dataclasses import replace
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.crypto.encryption import decode_key, encode_key, generate_encryption_key
from app.crypto.key_manager import (
    generate_rsa_keys,
    load_private_key_from_pem,
    public_key_fingerprint,
    save_private_key_to_pem,
    save_public_key_to_pem,
)
from app.crypto.payload import MAX_MESSAGE_BYTES
from app.gui.task_runner import TaskRunner
from app.gui.widgets import DropZone, FileInfoPanel, MediaPreview
from app.services.operations import OperationControl
from app.services.output_files import export_secret_bundle
from app.services.protection import (
    ProtectionOptions,
    estimate_protection_capacity,
    protect_media,
)


class ProtectTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.input_path = QLineEdit()
        self.output_path = QLineEdit()
        self.manifest_path = QLineEdit()
        self.private_key_path = QLineEdit()
        self.key_password = QLineEdit()
        self.key_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.media_id = QLineEdit("MEDIA-001")
        self.lsb_count = QSpinBox()
        self.lsb_count.setRange(1, 8)
        self.video_frame_index = QSpinBox()
        self.video_frame_index.setRange(0, 299)
        self.robustness = QComboBox()
        self.robustness.addItem("None", "none")
        self.robustness.addItem("Repetition ×3 with majority voting", "repetition-3")
        self.start_method = QComboBox()
        self.start_method.addItem("Secret-derived (HMAC-SHA256)", "hmac-sha256")
        self.start_method.addItem("Manual sample index", "manual")
        self.start_value = QLineEdit()
        self.start_value.setEchoMode(QLineEdit.EchoMode.Password)
        self.start_value.setPlaceholderText("Separate start-location secret")
        self.encrypt = QCheckBox("Encrypt message with AES-256-GCM")
        self.encryption_key = QLineEdit()
        self.encryption_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.encryption_key.setEnabled(False)
        self.preserve_size = QCheckBox("Attempt exact original file size")
        self.size_report_path = QLineEdit()
        self.create_recovery = QCheckBox(
            "Create encrypted recovery sidecar for byte-exact restoration"
        )
        self.recovery_key = QLineEdit()
        self.recovery_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.recovery_key.setEnabled(False)
        self.overwrite = QCheckBox("Replace an existing complete output bundle")
        self.payload_mode = QComboBox()
        self.payload_mode.addItem("Text message", "text")
        self.payload_mode.addItem("File bytes", "file")
        self.payload_file_path = QLineEdit()
        self.payload_file_path.setEnabled(False)
        self.message = QPlainTextEdit()
        self.message.setPlaceholderText("Enter the message or verification payload.")
        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        self.capacity = QLabel("Select a cover object to estimate capacity.")
        self.capacity.setWordWrap(True)
        self.original_preview = MediaPreview("Original")
        self.output_preview = MediaPreview("Protected output")
        self.file_info = FileInfoPanel()
        self.signer_fingerprint = QLabel("Signer fingerprint: choose a private key.")
        self.signer_fingerprint.setWordWrap(True)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.runner = TaskRunner(self)

        root = QVBoxLayout(self)
        drop = DropZone("Drop a PNG, BMP, PCM-16 WAV, or bounded video cover here")
        drop.file_dropped.connect(self._set_input)
        root.addWidget(drop)

        paths = QGroupBox("Files and signing key")
        paths_form = QGridLayout(paths)
        self._add_picker(paths_form, 0, "Cover object", self.input_path, self._browse_input)
        self._add_picker(paths_form, 1, "Protected output", self.output_path, self._browse_output)
        self._add_picker(
            paths_form, 2, "Companion manifest", self.manifest_path, self._browse_manifest
        )
        self._add_picker(
            paths_form, 3, "Private signing key", self.private_key_path, self._browse_key
        )
        self._add_picker(
            paths_form, 4, "Size experiment report", self.size_report_path, self._browse_size_report
        )
        paths_form.addWidget(QLabel("Key password"), 5, 0)
        paths_form.addWidget(self.key_password, 5, 1)
        generate_keys = QPushButton("Generate demo key pair…")
        generate_keys.clicked.connect(self._generate_keys)
        paths_form.addWidget(generate_keys, 5, 2)
        paths_form.addWidget(self.signer_fingerprint, 6, 0, 1, 3)
        root.addWidget(paths)

        settings = QGroupBox("Protection settings")
        settings_form = QFormLayout(settings)
        settings_form.addRow("Media ID", self.media_id)
        settings_form.addRow("LSB depth", self.lsb_count)
        settings_form.addRow("Video frame index", self.video_frame_index)
        settings_form.addRow("Robustness", self.robustness)
        settings_form.addRow("Start method", self.start_method)
        settings_form.addRow("Secret / index", self.start_value)
        settings_form.addRow(self.encrypt)
        key_row = QHBoxLayout()
        key_row.addWidget(self.encryption_key)
        generate_encryption = QPushButton("Generate key")
        generate_encryption.clicked.connect(self._generate_encryption_key)
        key_row.addWidget(generate_encryption)
        settings_form.addRow("Encryption key", key_row)
        settings_form.addRow(self.preserve_size)
        settings_form.addRow(self.create_recovery)
        recovery_row = QHBoxLayout()
        recovery_row.addWidget(self.recovery_key)
        generate_recovery = QPushButton("Generate key")
        generate_recovery.clicked.connect(self._generate_recovery_key)
        recovery_row.addWidget(generate_recovery)
        settings_form.addRow("Recovery key", recovery_row)
        settings_form.addRow(self.overwrite)
        settings_form.addRow("Estimated capacity", self.capacity)
        root.addWidget(settings)

        payload = QGroupBox("Payload")
        payload_form = QFormLayout(payload)
        payload_form.addRow("Payload source", self.payload_mode)
        file_row = QHBoxLayout()
        file_row.addWidget(self.payload_file_path)
        self.payload_file_button = QPushButton("Browse…")
        self.payload_file_button.setEnabled(False)
        self.payload_file_button.clicked.connect(self._browse_payload_file)
        file_row.addWidget(self.payload_file_button)
        payload_form.addRow("Payload file", file_row)
        payload_form.addRow("Text message", self.message)
        root.addWidget(payload)
        self.export_secrets_button = QPushButton("Export configured secrets…")
        self.export_secrets_button.clicked.connect(self._export_secrets)
        root.addWidget(self.export_secrets_button)
        self._input_groups = (paths, settings, payload)
        action_row = QHBoxLayout()
        self.protect_button = QPushButton("Protect and sign")
        self.protect_button.setObjectName("primaryButton")
        self.protect_button.clicked.connect(self._protect)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        action_row.addWidget(self.protect_button)
        action_row.addWidget(self.cancel_button)
        root.addLayout(action_row)
        root.addWidget(self.progress)
        root.addWidget(self.status)
        root.addWidget(self.file_info)
        previews = QHBoxLayout()
        previews.addWidget(self.original_preview)
        previews.addWidget(self.output_preview)
        root.addLayout(previews)

        self.start_method.currentIndexChanged.connect(self._start_mode_changed)
        self.encrypt.toggled.connect(self.encryption_key.setEnabled)
        self.create_recovery.toggled.connect(self.recovery_key.setEnabled)
        self.input_path.editingFinished.connect(
            lambda: self._set_input(self.input_path.text())
        )
        self.lsb_count.valueChanged.connect(self._update_capacity)
        self.video_frame_index.valueChanged.connect(self._update_capacity)
        self.message.textChanged.connect(self._update_capacity)
        self.private_key_path.textChanged.connect(self._update_capacity)
        self.key_password.textChanged.connect(self._update_capacity)
        self.media_id.textChanged.connect(self._update_capacity)
        self.robustness.currentIndexChanged.connect(self._update_capacity)
        self.start_method.currentIndexChanged.connect(self._update_capacity)
        self.start_value.textChanged.connect(self._update_capacity)
        self.encrypt.toggled.connect(self._update_capacity)
        self.encryption_key.textChanged.connect(self._update_capacity)
        self.payload_mode.currentIndexChanged.connect(self._payload_mode_changed)
        self.payload_file_path.textChanged.connect(self._update_capacity)
        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.progress.connect(self.status.setText)
        self.runner.succeeded.connect(self._protection_succeeded)
        self.runner.failed.connect(self._protection_failed)
        self.runner.cancelled.connect(self._protection_cancelled)
        self.runner.finished.connect(lambda: self._set_busy(False))

    @staticmethod
    def _add_picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select cover object",
            "",
            "Supported media (*.png *.bmp *.wav *.mkv *.mp4 *.mov *.avi)",
        )
        if path:
            self._set_input(path)

    def _set_input(self, path: str):
        if not path:
            return
        self.input_path.setText(path)
        source = Path(path)
        suffix = source.suffix.lower()
        output_suffix = ".mkv" if suffix in {".mkv", ".mp4", ".mov", ".avi"} else suffix
        self.output_path.setText(
            str(source.with_name(f"{source.stem}_protected{output_suffix}"))
        )
        self.manifest_path.setText(
            str(source.with_name(f"{source.stem}_protected.manifest.json"))
        )
        self.size_report_path.setText(
            str(source.with_name(f"{source.stem}_size-experiment.json"))
        )
        self.original_preview.set_file(path)
        self.file_info.set_file(path)
        self._update_capacity()

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Protected output",
            self.output_path.text(),
            "Media (*.png *.bmp *.wav *.mkv)",
        )
        if path:
            self.output_path.setText(path)

    def _browse_manifest(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Companion manifest",
            self.manifest_path.text(),
            "JSON manifest (*.json)",
        )
        if path:
            self.manifest_path.setText(path)

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Private signing key", "", "PEM keys (*.pem)"
        )
        if path:
            self.private_key_path.setText(path)

    def _browse_size_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Size experiment report",
            self.size_report_path.text(),
            "JSON reports (*.json)",
        )
        if path:
            self.size_report_path.setText(path)

    def _browse_payload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select payload file")
        if path:
            self.payload_file_path.setText(path)

    def _payload_mode_changed(self):
        file_mode = self.payload_mode.currentData() == "file"
        self.payload_file_path.setEnabled(file_mode)
        self.payload_file_button.setEnabled(file_mode)
        self.message.setEnabled(not file_mode)
        self._update_capacity()

    def _payload(self) -> tuple[bytes, str, dict[str, str]]:
        if self.payload_mode.currentData() == "file":
            path_text = self.payload_file_path.text().strip()
            if not path_text:
                raise ValueError("choose a payload file")
            path = Path(path_text)
            if not path.is_file():
                raise FileNotFoundError(f"payload file not found: {path.name}")
            if path.stat().st_size > MAX_MESSAGE_BYTES:
                raise ValueError(
                    f"payload file exceeds the {MAX_MESSAGE_BYTES:,}-byte safety limit"
                )
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            return path.read_bytes(), content_type, {"payload_filename": path.name}
        return (
            self.message.toPlainText().encode("utf-8"),
            "text/plain; charset=utf-8",
            {},
        )

    def _generate_keys(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save demo private key", "demo_private.pem", "PEM keys (*.pem)"
        )
        if not path:
            return
        private_path = Path(path)
        public_path = private_path.with_name(f"{private_path.stem}_public.pem")
        if (private_path.exists() or public_path.exists()) and QMessageBox.question(
            self,
            "Replace keys?",
            "One or both demo key files already exist. Replace them?",
        ) != QMessageBox.StandardButton.Yes:
            return
        private_key, public_key = generate_rsa_keys()
        save_private_key_to_pem(
            private_key, private_path, self.key_password.text() or None
        )
        save_public_key_to_pem(public_key, public_path)
        self.private_key_path.setText(str(private_path))
        self.status.setText(
            f"Generated demo keys. Give the receiver {public_path.name}; keep "
            f"{private_path.name} private."
        )
        self.signer_fingerprint.setText(
            "Signer fingerprint (SHA-256): " + public_key_fingerprint(public_key)
        )

    def _generate_encryption_key(self):
        self.encryption_key.setText(encode_key(generate_encryption_key()))
        self.encrypt.setChecked(True)

    def _generate_recovery_key(self):
        self.recovery_key.setText(encode_key(generate_encryption_key()))
        self.create_recovery.setChecked(True)

    def _export_secrets(self):
        secrets: dict[str, str] = {}
        if self.start_method.currentData() == "hmac-sha256":
            secrets["start_location_secret"] = self.start_value.text()
        if self.encrypt.isChecked():
            secrets["message_encryption_key"] = self.encryption_key.text().strip()
        if self.create_recovery.isChecked():
            secrets["recovery_sidecar_key"] = self.recovery_key.text().strip()
        if not any(secrets.values()):
            QMessageBox.information(self, "No secrets", "There are no configured secrets to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export private secrets", "private-secrets.json", "JSON (*.json)"
        )
        if not path:
            return
        destination = Path(path).resolve()
        reserved = {
            Path(value).resolve()
            for value in (
                self.input_path.text().strip(),
                self.output_path.text().strip(),
                self.manifest_path.text().strip(),
            )
            if value
        }
        if destination in reserved:
            QMessageBox.critical(
                self,
                "Secret export failed",
                "The private secret bundle must use a path separate from the cover, "
                "protected media, and public manifest.",
            )
            return
        if QMessageBox.question(
            self,
            "Export private secrets?",
            "This file contains private secrets. Keep it private and transfer it "
            "separately from the public manifest.",
        ) != QMessageBox.StandardButton.Yes:
            return
        overwrite = Path(path).exists()
        if overwrite and QMessageBox.question(
            self, "Replace secret file?", "The selected file exists. Replace it?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            export_secret_bundle(path, secrets, overwrite=overwrite)
        except Exception as exc:
            QMessageBox.critical(self, "Secret export failed", str(exc))
            return
        self.status.setText(
            f"Private secrets exported to {Path(path).name}; keep this file separate "
            "from the public manifest."
        )

    def _start_mode_changed(self):
        manual = self.start_method.currentData() == "manual"
        self.start_value.setEchoMode(
            QLineEdit.EchoMode.Normal if manual else QLineEdit.EchoMode.Password
        )
        self.start_value.setPlaceholderText(
            "Non-negative eligible-sample index"
            if manual
            else "Separate start-location secret"
        )

    def _payload_options(
        self,
        content_type: str = "text/plain; charset=utf-8",
        payload_metadata: dict[str, str] | None = None,
    ) -> ProtectionOptions:
        method = self.start_method.currentData()
        if method == "manual":
            start_location = int(self.start_value.text())
            start_secret = None
        else:
            start_location = None
            start_secret = self.start_value.text()
        encryption_key = (
            decode_key(self.encryption_key.text().strip())
            if self.encrypt.isChecked()
            else None
        )
        return ProtectionOptions(
            media_id=self.media_id.text().strip(),
            lsb_count=self.lsb_count.value(),
            start_method=method,
            start_secret=start_secret,
            start_location=start_location,
            encryption_key=encryption_key,
            robustness=self.robustness.currentData(),
            content_type=content_type,
            metadata={"application": "INF2005 ACW1", **(payload_metadata or {})},
            video_frame_index=self.video_frame_index.value(),
            overwrite=self.overwrite.isChecked(),
        )

    def _update_capacity(self):
        path = self.input_path.text().strip()
        if not path or not Path(path).is_file():
            self.capacity.setText("Select a cover object to estimate capacity.")
            return
        try:
            key_path = self.private_key_path.text().strip()
            if not key_path:
                self.capacity.setText(
                    "Choose a private signing key for an exact signed-envelope estimate."
                )
                return
            private_key = load_private_key_from_pem(
                key_path, self.key_password.text() or None
            )
            self.signer_fingerprint.setText(
                "Signer fingerprint (SHA-256): "
                + public_key_fingerprint(private_key.public_key())
            )
            payload, content_type, payload_metadata = self._payload()
            estimate = estimate_protection_capacity(
                path,
                payload,
                private_key,
                self._payload_options(content_type, payload_metadata),
            )
            carrier = estimate.carrier
            outcome = "fits" if estimate.fits else "does not fit"
            self.capacity.setText(
                f"Exact signed envelope: {estimate.envelope_length:,} bytes; stored "
                f"payload: {estimate.embedded_payload_length:,} bytes; carrier framing: "
                f"{carrier.carrier_header_bytes} bytes. Requires "
                f"{carrier.required_samples:,} of {carrier.available_samples:,} available "
                f"samples from index {carrier.start_location:,}: {outcome}."
            )
        except Exception as exc:
            self.capacity.setText(str(exc))

    def _protect(self):
        if self.runner.busy:
            return
        try:
            private_key = load_private_key_from_pem(
                self.private_key_path.text().strip(),
                self.key_password.text() or None,
            )
            payload, content_type, payload_metadata = self._payload()
            options = self._payload_options(content_type, payload_metadata)
            recovery_key = (
                decode_key(self.recovery_key.text().strip())
                if self.create_recovery.isChecked()
                else None
            )
            options = replace(
                options,
                preserve_size=self.preserve_size.isChecked(),
                size_report_path=(
                    self.size_report_path.text().strip()
                    if self.preserve_size.isChecked()
                    and self.size_report_path.text().strip()
                    else None
                ),
                recovery_key=recovery_key,
            )
            input_path = self.input_path.text().strip()
            output_path = self.output_path.text().strip()
            manifest_path = self.manifest_path.text().strip()
        except Exception as exc:
            self._protection_failed(exc)
            return
        self.output_preview.clear("Protection is running…")
        self.status.setText("Starting protection…")
        self.runner.start(
            lambda token, progress: protect_media(
                input_path,
                output_path,
                manifest_path,
                payload,
                private_key,
                replace(
                    options,
                    operation=OperationControl(token, progress),
                ),
            )
        )

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.status.setText("Cancellation requested; waiting for a safe checkpoint…")

    def _set_busy(self, busy: bool):
        self.protect_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        self.export_secrets_button.setEnabled(not busy)
        for group in self._input_groups:
            group.setEnabled(not busy)

    def _protection_failed(self, exc: Exception):
        self.output_preview.clear()
        QMessageBox.critical(self, "Protection failed", str(exc))
        self.status.setText(f"Protection failed: {exc}")

    def _protection_cancelled(self, message: str):
        self.output_preview.clear()
        self.status.setText(message)

    def _protection_succeeded(self, result):
        notes = []
        if result.size_preservation is not None:
            size_note = (
                f"size preservation: {result.size_preservation.method}; "
                f"{result.size_preservation.original_size:,} -> "
                f"{result.size_preservation.final_size:,} bytes"
            )
            if result.size_preservation.failure_reason:
                size_note += f" ({result.size_preservation.failure_reason})"
            notes.append(size_note)
        if result.size_report_path is not None:
            notes.append(f"size report: {Path(result.size_report_path).name}")
        if result.recovery is not None:
            notes.append(
                f"encrypted recovery backup: {Path(result.recovery.output_path).name}; "
                f"{result.recovery.sidecar_bytes:,} bytes "
                f"({result.recovery.storage_overhead_bytes:,} bytes format/authentication "
                "overhead; stores the complete original file)"
            )
        self.output_preview.set_file(result.output_path)
        suffix = " " + "; ".join(notes) + "." if notes else ""
        self.status.setText(
            f"Protected {result.media_type} created. Embedded "
            f"{result.embedded_payload_length:,} "
            f"bytes from sample {result.start_location:,}. Manifest saved beside it."
            f"{suffix}"
        )

    def shutdown(self) -> None:
        self.runner.shutdown()
        self.original_preview.clear()
        self.output_preview.clear()
