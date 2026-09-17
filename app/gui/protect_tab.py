"""Protect/sign workflow tab."""

from __future__ import annotations

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
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.crypto.encryption import decode_key, encode_key, generate_encryption_key
from app.crypto.key_manager import (
    generate_rsa_keys,
    load_private_key_from_pem,
    save_private_key_to_pem,
    save_public_key_to_pem,
)
from app.gui.widgets import DropZone, FileInfoPanel, MediaPreview
from app.services.media import inspect_carrier
from app.services.protection import ProtectionOptions, protect_media
from app.services.size_preservation import compare_file_sizes, pad_png_to_size
from app.robustness.recovery import create_recovery_sidecar


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
        self.create_recovery = QCheckBox(
            "Create encrypted recovery sidecar for byte-exact restoration"
        )
        self.recovery_key = QLineEdit()
        self.recovery_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.recovery_key.setEnabled(False)
        self.message = QPlainTextEdit()
        self.message.setPlaceholderText("Enter the message or verification payload.")
        self.status = QLabel("Ready.")
        self.status.setWordWrap(True)
        self.capacity = QLabel("Select a cover object to estimate capacity.")
        self.capacity.setWordWrap(True)
        self.original_preview = MediaPreview("Original")
        self.output_preview = MediaPreview("Protected output")
        self.file_info = FileInfoPanel()

        root = QVBoxLayout(self)
        drop = DropZone("Drop a PNG, BMP, or PCM-16 WAV cover object here")
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
        paths_form.addWidget(QLabel("Key password"), 4, 0)
        paths_form.addWidget(self.key_password, 4, 1)
        generate_keys = QPushButton("Generate demo key pair…")
        generate_keys.clicked.connect(self._generate_keys)
        paths_form.addWidget(generate_keys, 4, 2)
        root.addWidget(paths)

        settings = QGroupBox("Protection settings")
        settings_form = QFormLayout(settings)
        settings_form.addRow("Media ID", self.media_id)
        settings_form.addRow("LSB depth", self.lsb_count)
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
        settings_form.addRow("Estimated capacity", self.capacity)
        root.addWidget(settings)

        root.addWidget(QLabel("Message"))
        root.addWidget(self.message)
        protect = QPushButton("Protect and sign")
        protect.setObjectName("primaryButton")
        protect.clicked.connect(self._protect)
        root.addWidget(protect)
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
        self.message.textChanged.connect(self._update_capacity)

    @staticmethod
    def _add_picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select cover object", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self._set_input(path)

    def _set_input(self, path: str):
        if not path:
            return
        self.input_path.setText(path)
        source = Path(path)
        suffix = source.suffix.lower()
        self.output_path.setText(str(source.with_name(f"{source.stem}_protected{suffix}")))
        self.manifest_path.setText(
            str(source.with_name(f"{source.stem}_protected.manifest.json"))
        )
        self.original_preview.set_file(path)
        self.file_info.set_file(path)
        self._update_capacity()

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Protected output", self.output_path.text(), "Media (*.png *.bmp *.wav)"
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

    def _generate_encryption_key(self):
        self.encryption_key.setText(encode_key(generate_encryption_key()))
        self.encrypt.setChecked(True)

    def _generate_recovery_key(self):
        self.recovery_key.setText(encode_key(generate_encryption_key()))
        self.create_recovery.setChecked(True)

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

    def _update_capacity(self):
        path = self.input_path.text().strip()
        if not path or not Path(path).is_file():
            return
        try:
            carrier = inspect_carrier(path)
            raw_capacity = (
                carrier.total_samples * self.lsb_count.value() // 8
                - carrier.carrier_header_bytes
            )
            message_bytes = len(self.message.toPlainText().encode("utf-8"))
            self.capacity.setText(
                f"Carrier maximum before signed-envelope overhead: "
                f"{max(0, raw_capacity):,} bytes. Message: {message_bytes:,} bytes."
            )
        except Exception as exc:
            self.capacity.setText(str(exc))

    def _protect(self):
        try:
            private_key = load_private_key_from_pem(
                self.private_key_path.text().strip(),
                self.key_password.text() or None,
            )
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
            result = protect_media(
                self.input_path.text().strip(),
                self.output_path.text().strip(),
                self.manifest_path.text().strip(),
                self.message.toPlainText().encode("utf-8"),
                private_key,
                ProtectionOptions(
                    media_id=self.media_id.text().strip(),
                    lsb_count=self.lsb_count.value(),
                    start_method=method,
                    start_secret=start_secret,
                    start_location=start_location,
                    encryption_key=encryption_key,
                    robustness=self.robustness.currentData(),
                    metadata={"application": "INF2005 ACW1"},
                ),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Protection failed", str(exc))
            self.status.setText(f"Protection failed: {exc}")
            return
        self.output_preview.set_file(result.output_path)
        notes = []
        if self.preserve_size.isChecked():
            original_size = Path(self.input_path.text().strip()).stat().st_size
            output = Path(result.output_path)
            if output.suffix.lower() == ".png":
                try:
                    size_result = pad_png_to_size(output, original_size)
                    notes.append(f"size preservation: {size_result.method}")
                except ValueError as exc:
                    notes.append(f"exact PNG size unavailable: {exc}")
            else:
                size_result = compare_file_sizes(self.input_path.text(), output)
                notes.append(
                    "file size preserved" if size_result.exact else "file size differs"
                )
        if self.create_recovery.isChecked():
            recovery_path = f"{result.output_path}.recovery.smir"
            create_recovery_sidecar(
                self.input_path.text().strip(),
                result.output_path,
                recovery_path,
                decode_key(self.recovery_key.text().strip()),
            )
            notes.append(f"recovery sidecar: {Path(recovery_path).name}")
        suffix = " " + "; ".join(notes) + "." if notes else ""
        self.status.setText(
            f"Protected {result.media_type} created. Embedded {result.payload_length:,} "
            f"bytes from sample {result.start_location:,}. Manifest saved beside it."
            f"{suffix}"
        )
