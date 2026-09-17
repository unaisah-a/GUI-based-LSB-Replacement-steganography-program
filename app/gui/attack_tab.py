"""Controlled negative-case generation tab."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.attacks import corrupt_embedded_payload, modify_outside_payload
from app.gui.widgets import MediaPreview


class AttackTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.input_path = QLineEdit()
        self.manifest_path = QLineEdit()
        self.output_path = QLineEdit()
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.attack = QComboBox()
        self.attack.addItem("Corrupt the signed embedded payload", "payload")
        self.attack.addItem("Modify media outside the payload", "outside")
        self.status = QLabel(
            "Attacks always create a separate copy. Verify the copy in the Verify tab."
        )
        self.status.setWordWrap(True)
        self.before = MediaPreview("Before attack")
        self.after = MediaPreview("After attack")

        root = QVBoxLayout(self)
        files = QGroupBox("Attack inputs")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Protected media", self.input_path, self._browse_input)
        self._picker(grid, 1, "Manifest", self.manifest_path, self._browse_manifest)
        self._picker(grid, 2, "Attack output", self.output_path, self._browse_output)
        root.addWidget(files)
        settings = QGroupBox("Controlled attack")
        form = QFormLayout(settings)
        form.addRow("Attack", self.attack)
        form.addRow("Start secret (if derived)", self.secret)
        root.addWidget(settings)
        run = QPushButton("Create attacked copy")
        run.setObjectName("primaryButton")
        run.clicked.connect(self._run)
        root.addWidget(run)
        root.addWidget(self.status)
        previews = QHBoxLayout()
        previews.addWidget(self.before)
        previews.addWidget(self.after)
        root.addLayout(previews, 1)

    @staticmethod
    def _picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Protected media", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self.input_path.setText(path)
            source = Path(path)
            self.output_path.setText(
                str(source.with_name(f"{source.stem}_attacked{source.suffix}"))
            )
            self.before.set_file(path)

    def _browse_manifest(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Manifest", "", "JSON manifest (*.json)"
        )
        if path:
            self.manifest_path.setText(path)

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Attack output", self.output_path.text(), "Media (*.png *.bmp *.wav)"
        )
        if path:
            self.output_path.setText(path)

    def _run(self):
        function = (
            corrupt_embedded_payload
            if self.attack.currentData() == "payload"
            else modify_outside_payload
        )
        try:
            result = function(
                self.input_path.text().strip(),
                self.output_path.text().strip(),
                self.manifest_path.text().strip(),
                start_secret=self.secret.text() or None,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Attack failed", str(exc))
            return
        self.after.set_file(result.output_path)
        self.status.setText(
            f"Created {Path(result.output_path).name}. {result.detail} "
            f"Changed eligible sample {result.changed_sample_index:,}."
        )
