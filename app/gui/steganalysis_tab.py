"""Before/after media comparison, visual analysis, and evidence export."""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
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
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.analysis.experiments import (
    AnalysisBundle,
    export_analysis_evidence,
    prepare_analysis,
)
from app.gui.task_runner import TaskRunner


class _ArrayPreview(QLabel):
    def __init__(self, text: str):
        super().__init__(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumSize(210, 180)
        self.setStyleSheet("background: #111820; color: white; padding: 4px;")

    def set_array(self, values: np.ndarray) -> None:
        array = np.ascontiguousarray(values, dtype=np.uint8)
        height, width = array.shape[:2]
        if array.ndim == 2:
            image = QImage(
                array.data,
                width,
                height,
                int(array.strides[0]),
                QImage.Format.Format_Grayscale8,
            ).copy()
        elif array.shape[2] == 3:
            image = QImage(
                array.data,
                width,
                height,
                int(array.strides[0]),
                QImage.Format.Format_RGB888,
            ).copy()
        elif array.shape[2] == 4:
            image = QImage(
                array.data,
                width,
                height,
                int(array.strides[0]),
                QImage.Format.Format_RGBA8888,
            ).copy()
        else:
            raise ValueError("preview arrays must be grayscale, RGB, or RGBA")
        self.setPixmap(
            QPixmap.fromImage(image).scaled(
                360,
                240,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.FastTransformation,
            )
        )


class _SeriesPlot(QLabel):
    _COLOURS = (
        QColor("#1769aa"),
        QColor("#d1495b"),
        QColor("#2a9d8f"),
        QColor("#7b2cbf"),
        QColor("#f4a261"),
        QColor("#59656f"),
    )

    def __init__(self, empty_text: str):
        super().__init__(empty_text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(190)
        self.setStyleSheet("background: white; border: 1px solid #d9e0e7;")

    def set_series(self, series: list[np.ndarray]) -> None:
        width, height, margin = 780, 190, 16
        canvas = QPixmap(width, height)
        canvas.fill(QColor("white"))
        painter = QPainter(canvas)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#d9e0e7"), 1))
        painter.drawRect(margin, margin, width - 2 * margin, height - 2 * margin)
        arrays = [np.asarray(values, dtype=np.float64).reshape(-1) for values in series]
        finite = [values[np.isfinite(values)] for values in arrays if values.size]
        if finite:
            low = min(float(values.min()) for values in finite if values.size)
            high = max(float(values.max()) for values in finite if values.size)
            if high == low:
                high = low + 1.0
            plot_width = width - 2 * margin
            plot_height = height - 2 * margin
            for index, values in enumerate(arrays):
                if not values.size:
                    continue
                painter.setPen(QPen(self._COLOURS[index % len(self._COLOURS)], 1.3))
                previous = None
                divisor = max(1, values.size - 1)
                for position, value in enumerate(values):
                    x = margin + int(position * plot_width / divisor)
                    y = margin + int((high - float(value)) * plot_height / (high - low))
                    if previous is not None:
                        painter.drawLine(previous[0], previous[1], x, y)
                    previous = (x, y)
        painter.end()
        self.setPixmap(canvas)


class SteganalysisTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._bundle: AnalysisBundle | None = None
        self.original = QLineEdit()
        self.modified = QLineEdit()
        self.lsb_count = QSpinBox()
        self.lsb_count.setRange(1, 8)
        self.experiment_bytes = QSpinBox()
        self.experiment_bytes.setRange(1, 1_048_576)
        self.experiment_bytes.setValue(32)
        self.experiment_bytes.setSuffix(" bytes")
        self.listening_observation = QLineEdit()
        self.listening_observation.setPlaceholderText(
            "Optional human observation and listening conditions for audio"
        )
        self.report = QPlainTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText("Quality metrics and indicators appear here.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.runner = TaskRunner(self)

        root = QVBoxLayout(self)
        files = QGroupBox("Compare original and protected media")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Original", self.original, self._browse_original)
        self._picker(grid, 1, "Protected / modified", self.modified, self._browse_modified)
        grid.addWidget(QLabel("Known embedding LSB depth"), 2, 0)
        grid.addWidget(self.lsb_count, 2, 1)
        grid.addWidget(QLabel("Controlled experiment message"), 3, 0)
        grid.addWidget(self.experiment_bytes, 3, 1)
        grid.addWidget(QLabel("Listening observation"), 4, 0)
        grid.addWidget(self.listening_observation, 4, 1, 1, 2)
        root.addWidget(files)
        self.inputs_group = files

        actions = QHBoxLayout()
        self.run_button = QPushButton("Run comparison and depth experiment")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self._compare)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        self.export_button = QPushButton("Export JSON evidence…")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export)
        actions.addWidget(self.run_button)
        actions.addWidget(self.cancel_button)
        actions.addWidget(self.export_button)
        root.addLayout(actions)
        root.addWidget(self.progress)
        note = QLabel(
            "Statistical values are indicators only; they do not prove hidden data. "
            "Depth results apply to this cover and deterministic message. Listening "
            "observations must be made and recorded by a person."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        self.views = QTabWidget()
        self.views.addTab(self.report, "Metrics and evidence")
        self.image_page = QWidget()
        image_layout = QVBoxLayout(self.image_page)
        image_row = QHBoxLayout()
        self.original_lsb = _ArrayPreview("Original red-channel LSB")
        self.modified_lsb = _ArrayPreview("Protected red-channel LSB")
        self.difference = _ArrayPreview("Amplified absolute difference")
        image_row.addWidget(self.original_lsb)
        image_row.addWidget(self.modified_lsb)
        image_row.addWidget(self.difference)
        image_layout.addLayout(image_row)
        image_layout.addWidget(
            QLabel(
                "Per-channel histograms — red: blue/red; green: green/purple; "
                "blue: orange/gray (original/modified)"
            )
        )
        self.histogram = _SeriesPlot("Histogram comparison appears after analysis")
        image_layout.addWidget(self.histogram)
        self.views.addTab(self.image_page, "Image views")

        self.audio_page = QWidget()
        audio_layout = QVBoxLayout(self.audio_page)
        audio_layout.addWidget(QLabel("Waveforms: original and modified (display downsample)"))
        self.waveforms = _SeriesPlot("Waveform comparison appears after analysis")
        audio_layout.addWidget(self.waveforms)
        audio_layout.addWidget(QLabel("Modified minus original waveform"))
        self.audio_difference = _SeriesPlot("Audio difference appears after analysis")
        audio_layout.addWidget(self.audio_difference)
        self.views.addTab(self.audio_page, "Audio views")
        root.addWidget(self.views, 1)

        for widget in (self.original, self.modified, self.listening_observation):
            widget.textChanged.connect(self._clear_results)
        self.lsb_count.valueChanged.connect(self._clear_results)
        self.experiment_bytes.valueChanged.connect(self._clear_results)
        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.succeeded.connect(self._comparison_succeeded)
        self.runner.failed.connect(self._comparison_failed)
        self.runner.cancelled.connect(self._comparison_cancelled)
        self.runner.finished.connect(lambda: self._set_busy(False))

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
        if value is None:
            return "∞"
        if isinstance(value, float):
            if math.isinf(value):
                return "∞"
            return f"{value:.6g}"
        return str(value)

    @classmethod
    def _render_report(cls, bundle: AnalysisBundle) -> str:
        evidence = bundle.evidence
        original = evidence["original"]
        modified = evidence["modified"]
        quality = evidence["quality"]
        lines = [
            f"{bundle.media_type.upper()} COMPARISON",
            f"Original: {original['name']} — {original['size_bytes']:,} bytes",
            f"SHA-256: {original['sha256']}",
            f"Properties: {original['properties']}",
            f"Modified: {modified['name']} — {modified['size_bytes']:,} bytes",
            f"SHA-256: {modified['sha256']}",
            f"Properties: {modified['properties']}",
            "",
        ]
        if bundle.media_type == "image":
            lines.extend(
                [
                    "IMAGE QUALITY",
                    f"All samples identical: {quality['all_samples_identical']}",
                    f"Colour samples identical: {quality['colour_samples_identical']}",
                    f"Colour-channel MSE: {cls._number(quality['colour_mse'])}",
                    f"Colour-channel PSNR: {cls._number(quality['colour_psnr_db'])} dB"
                    + (" (zero colour error)" if quality['colour_psnr_unbounded'] else ""),
                    "Alpha is excluded from the colour aggregate and reported below."
                    if quality["alpha_excluded_from_colour_metrics"]
                    else "No alpha channel is present.",
                    f"Maximum sample difference: {quality['max_absolute_difference']}",
                    f"Differing samples: {quality['differing_samples']:,} / "
                    f"{quality['total_samples']:,} ({quality['differing_proportion']:.4%})",
                    "Per-channel metrics:",
                ]
            )
            for channel in quality["channels"]:
                suffix = " (alpha)" if channel["is_alpha"] else ""
                lines.append(
                    f"  {channel['label']}{suffix}: MSE {cls._number(channel['mse'])}, "
                    f"PSNR {cls._number(channel['psnr_db'])} dB"
                )
            histogram = evidence["histogram"]
            lines.extend(["", "HISTOGRAM COMPARISON"])
            for index, label in enumerate(histogram["channel_labels"]):
                delta = sum(abs(value) for value in histogram["difference_counts"][index])
                lines.append(f"  {label}: total absolute bin-count difference {delta:,}")
            lines.extend(["", "STATISTICAL INDICATORS"])
            for source in ("original", "modified"):
                lines.append(source.title())
                for indicator in evidence["indicators"][source]:
                    lines.append(
                        f"  {indicator['indicator']} / {indicator['scope']}: "
                        f"{cls._number(indicator['value'])} over "
                        f"{indicator['analysed_sample_count']:,} samples"
                    )
            lines.extend(["", evidence["indicator_disclaimer"]])
        else:
            lines.append("AUDIO QUALITY")
            for key, value in quality.items():
                lines.append(f"{key.replace('_', ' ').title()}: {cls._number(value)}")
            lines.extend(["", evidence["listening_observation"]])

        lines.extend(
            [
                "",
                "CONTROLLED LSB-DEPTH EXPERIMENT",
                bundle.experiment.method,
                "Depth | message | encoded | density | MSE | PSNR/SNR | max Δ | changed",
            ]
        )
        for row in bundle.experiment.rows:
            signal = row.psnr_db if bundle.media_type == "image" else row.snr_db
            lines.append(
                f"{row.lsb_count:>5} | {row.message_bytes:>7} | {row.encoded_bytes:>7} | "
                f"{row.embedding_density:>7.3%} | {row.mse:>9.4g} | "
                f"{cls._number(signal):>8} | {row.max_absolute_difference:>5} | "
                f"{row.changed_sample_percentage:>7.3f}%"
            )
        lines.extend(["", bundle.experiment.interpretation])
        return "\n".join(lines)

    @classmethod
    def _build_report(cls, original: str, modified: str, lsb_count: int) -> str:
        """Retained helper for callers that only need a textual comparison."""
        return cls._render_report(prepare_analysis(original, modified, lsb_count, 32))

    def _compare(self):
        if self.runner.busy:
            return
        original = self.original.text().strip()
        modified = self.modified.text().strip()
        if not original or not modified:
            QMessageBox.critical(self, "Comparison failed", "choose both media files")
            return
        lsb_count = self.lsb_count.value()
        experiment_bytes = self.experiment_bytes.value()
        listening_observation = self.listening_observation.text()
        self._clear_results()

        def operation(token, progress):
            progress("Calculating comparison views and depth 1–8 evidence…")
            return prepare_analysis(
                original,
                modified,
                lsb_count,
                experiment_bytes,
                listening_observation=listening_observation,
                checkpoint=token.checkpoint,
            )

        self.runner.start(operation)

    def _comparison_succeeded(self, bundle: AnalysisBundle):
        self._bundle = bundle
        self.report.setPlainText(self._render_report(bundle))
        self.export_button.setEnabled(True)
        image = bundle.media_type == "image"
        self.views.setTabEnabled(1, image)
        self.views.setTabEnabled(2, not image)
        if image:
            self.original_lsb.set_array(bundle.image_original_lsb)
            self.modified_lsb.set_array(bundle.image_modified_lsb)
            self.difference.set_array(bundle.image_difference)
            series = []
            for original, modified in zip(
                bundle.histogram_original, bundle.histogram_modified
            ):
                series.extend((original, modified))
            self.histogram.set_series(series)
            self.views.setCurrentIndex(1)
        else:
            self.waveforms.set_series([bundle.audio_original, bundle.audio_modified])
            self.audio_difference.set_series([bundle.audio_difference])
            self.views.setCurrentIndex(2)

    def _export(self):
        if self._bundle is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export analysis evidence", "analysis-evidence.json", "JSON (*.json)"
        )
        if not path:
            return
        overwrite = False
        if Path(path).exists():
            choice = QMessageBox.question(
                self,
                "Replace evidence?",
                f"Replace {Path(path).name}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if choice != QMessageBox.StandardButton.Yes:
                return
            overwrite = True
        try:
            export_analysis_evidence(self._bundle, path, overwrite=overwrite)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Evidence exported", f"Saved {Path(path).name}.")

    def _clear_results(self):
        if self.runner.busy:
            return
        self._bundle = None
        self.report.clear()
        self.export_button.setEnabled(False)
        self.views.setCurrentIndex(0)

    def _comparison_failed(self, exc: Exception):
        self._clear_results()
        QMessageBox.critical(self, "Comparison failed", str(exc))

    def _comparison_cancelled(self, message: str):
        self._bundle = None
        self.export_button.setEnabled(False)
        self.report.setPlainText(message)

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.report.setPlainText(
            "Cancellation requested; the current file calculation may finish first."
        )

    def _set_busy(self, busy: bool):
        self.run_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        self.inputs_group.setEnabled(not busy)
        self.export_button.setEnabled(not busy and self._bundle is not None)

    def shutdown(self) -> None:
        self.runner.shutdown()
