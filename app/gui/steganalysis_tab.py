"""Before/after quality comparison and statistical indicator tab."""

from __future__ import annotations

import math

from PySide6.QtWidgets import (
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.analysis.audio_analysis import calculate_quality_report
from app.analysis.image_analysis import compare_quality, lsb_distribution
from app.services.media import inspect_carrier


class SteganalysisTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.original = QLineEdit()
        self.modified = QLineEdit()
        self.lsb_count = QSpinBox()
        self.lsb_count.setRange(1, 8)
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText("Quality metrics and indicators appear here.")

        root = QVBoxLayout(self)
        files = QGroupBox("Compare original and protected media")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Original", self.original, self._browse_original)
        self._picker(grid, 1, "Protected / modified", self.modified, self._browse_modified)
        grid.addWidget(QLabel("Embedding LSB depth"), 2, 0)
        grid.addWidget(self.lsb_count, 2, 1)
        root.addWidget(files)
        run = QPushButton("Run comparison")
        run.setObjectName("primaryButton")
        run.clicked.connect(self._compare)
        root.addWidget(run)
        note = QLabel(
            "Statistical values are indicators only; they do not prove the presence "
            "or absence of hidden data."
        )
        note.setWordWrap(True)
        root.addWidget(note)
        root.addWidget(self.report, 1)

    @staticmethod
    def _picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _browse_original(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Original media", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self.original.setText(path)

    def _browse_modified(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Modified media", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self.modified.setText(path)

    @staticmethod
    def _number(value):
        if isinstance(value, float):
            if math.isinf(value):
                return "∞"
            return f"{value:.6g}"
        return str(value)

    def _compare(self):
        try:
            first = inspect_carrier(self.original.text().strip())
            second = inspect_carrier(self.modified.text().strip())
            if first.media_type != second.media_type:
                raise ValueError("both files must be the same media type")
            if first.media_type == "image":
                quality = compare_quality(
                    self.original.text().strip(),
                    self.modified.text().strip(),
                )
                lines = [
                    "IMAGE QUALITY",
                    f"Dimensions: {quality.width} × {quality.height}",
                    f"Channels: {quality.channel_count}",
                    f"Pixel-identical: {quality.pixel_identical}",
                    f"MSE: {self._number(quality.overall_mse)}",
                    f"PSNR: {self._number(quality.overall_psnr_db)} dB",
                    f"Maximum sample difference: {quality.max_absolute_difference}",
                    f"Differing samples: {quality.differing_samples:,} / "
                    f"{quality.total_samples:,} ({quality.differing_proportion:.4%})",
                    "",
                    "PROTECTED IMAGE LSB DISTRIBUTION",
                ]
                for indicator in lsb_distribution(self.modified.text().strip()):
                    lines.append(
                        f"{indicator.scope}: ones proportion "
                        f"{self._number(indicator.value)} over "
                        f"{indicator.analysed_sample_count:,} samples"
                    )
            else:
                values = calculate_quality_report(
                    self.original.text().strip(),
                    self.modified.text().strip(),
                    self.lsb_count.value(),
                )
                lines = ["AUDIO QUALITY"] + [
                    f"{key.replace('_', ' ').title()}: {self._number(value)}"
                    for key, value in values.items()
                ]
            self.report.setPlainText("\n".join(lines))
        except Exception as exc:
            QMessageBox.critical(self, "Comparison failed", str(exc))
