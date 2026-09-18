"""The Steganalysis tab: look at a file's statistics and bit planes.

Renders what :func:`app.analysis.steganalysis.analyse` returns. The tab computes
nothing itself; the analysis layer holds no Qt dependency, and this holds no
statistics.

The disclaimer is not decoration
--------------------------------
Every indicator is shown with an explanation of what it measures and with
:data:`app.analysis.image_analysis.INDICATOR_DISCLAIMER`. Indicators that had too
little data report "insufficient sample" instead of a number, rather than a
precise-looking figure computed from nothing. There is no verdict, no confidence
percentage and no "probably contains data" anywhere in this tab, because the
underlying statistics do not support one.

Why the reference file is optional
----------------------------------
The realistic case is that an analyst has the suspicious file and nothing else, so
the indicators all work without a reference. Supplying the original adds the
difference image, the histogram comparison and the distortion metrics — the three
things that genuinely cannot be computed from one file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.analysis import steganalysis
from app.analysis.steganalysis import AnalysisReport
from app.gui.widgets.drop_zone import DropZone
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.workers import BackgroundRunner
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = ["SteganalysisTab", "array_to_pixmap"]

_log = get_logger(__name__)

#: Bit planes are single-channel images; a modest fixed width keeps the grid readable.
_PLANE_WIDTH = 150


def array_to_pixmap(array: np.ndarray) -> QPixmap:
    """Convert a ``uint8`` array to a pixmap.

    Handles the two shapes the analysis layer produces: a two-dimensional plane and a
    three-dimensional colour image. The array is copied, because ``QImage`` does not
    take ownership of the buffer it is handed and would otherwise reference memory
    numpy may free.
    """
    data = np.ascontiguousarray(array, dtype=np.uint8)

    if data.ndim == 2:
        height, width = data.shape
        image = QImage(
            data.tobytes(), width, height, width, QImage.Format.Format_Grayscale8
        )
    elif data.ndim == 3 and data.shape[2] == 1:
        height, width = data.shape[:2]
        image = QImage(
            data[:, :, 0].tobytes(),
            width,
            height,
            width,
            QImage.Format.Format_Grayscale8,
        )
    elif data.ndim == 3 and data.shape[2] == 3:
        height, width = data.shape[:2]
        image = QImage(
            data.tobytes(), width, height, width * 3, QImage.Format.Format_RGB888
        )
    elif data.ndim == 3 and data.shape[2] == 4:
        height, width = data.shape[:2]
        image = QImage(
            data.tobytes(), width, height, width * 4, QImage.Format.Format_RGBA8888
        )
    else:
        raise ValueError(f"cannot render an array of shape {data.shape}")

    return QPixmap.fromImage(image.copy())


@dataclass(frozen=True)
class AnalysisInputs:
    """A snapshot of the form, taken on the interface thread before work starts."""

    path: str
    reference: str | None
    scaled_planes: bool


class SteganalysisTab(QWidget):
    """Shows indicators, bit planes and, with a reference, a difference image."""

    TITLE = "Steganalysis"

    statusMessage = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("steganalysisTab")

        self._runner = BackgroundRunner()
        self._path: str | None = None
        self._report: AnalysisReport | None = None

        outer = QVBoxLayout(self)

        self.drop_zone = DropZone(
            self,
            media_types=(constants.MEDIA_IMAGE, constants.MEDIA_AUDIO),
            prompt="Drag a file to analyse here",
        )
        self.drop_zone.fileSelected.connect(self._on_file_selected)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        outer.addWidget(self.drop_zone)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._build_controls())
        splitter.addWidget(self._build_output())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        outer.addWidget(splitter, 1)

    # -- construction ------------------------------------------------------ #

    def _build_controls(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        options = QGroupBox("Options", container)
        form = QFormLayout(options)

        reference_row = QWidget(options)
        reference_layout = QHBoxLayout(reference_row)
        reference_layout.setContentsMargins(0, 0, 0, 0)
        self.reference_edit = QLineEdit(reference_row)
        self.reference_edit.setPlaceholderText("optional: the original, for comparison")
        reference_layout.addWidget(self.reference_edit, 1)
        self.reference_browse_button = QPushButton("Browse...", reference_row)
        self.reference_browse_button.clicked.connect(self._choose_reference)
        reference_layout.addWidget(self.reference_browse_button)
        form.addRow("Original:", reference_row)

        self.scaled_check = QCheckBox("Scale bit planes to black and white", options)
        self.scaled_check.setChecked(True)
        self.scaled_check.setToolTip(
            "A bit plane holds only 0 and 1. Unscaled it appears solid black, so it is "
            "mapped to 0 and 255 to be viewable."
        )
        form.addRow("", self.scaled_check)

        layout.addWidget(options)

        self.analyse_button = QPushButton("Analyse", container)
        self.analyse_button.setMinimumHeight(32)
        self.analyse_button.clicked.connect(self.analyse)
        layout.addWidget(self.analyse_button)

        self.quality_panel = FileInfoPanel(container, title="Distortion (needs the original)")
        layout.addWidget(self.quality_panel)

        self.disclaimer_label = QLabel(steganalysis.INDICATOR_DISCLAIMER, container)
        self.disclaimer_label.setObjectName("fileInfoNotice")
        self.disclaimer_label.setTextFormat(Qt.TextFormat.PlainText)
        self.disclaimer_label.setWordWrap(True)
        layout.addWidget(self.disclaimer_label)

        layout.addStretch(1)
        return container

    def _build_output(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        indicators_box = QGroupBox("Statistical indicators", container)
        indicators_layout = QVBoxLayout(indicators_box)

        self.indicator_table = QTableWidget(0, 5, indicators_box)
        self.indicator_table.setHorizontalHeaderLabels(
            ["Indicator", "Scope", "Value", "Samples", "What it measures"]
        )
        self.indicator_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        self.indicator_table.setWordWrap(True)
        self.indicator_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        indicators_layout.addWidget(self.indicator_table)
        layout.addWidget(indicators_box, 2)

        self.views_box = QGroupBox("Bit planes and difference", container)
        views_layout = QVBoxLayout(self.views_box)

        self.plane_channel_combo = QComboBox(self.views_box)
        self.plane_channel_combo.currentIndexChanged.connect(self._render_planes)
        channel_row = QHBoxLayout()
        channel_row.addWidget(QLabel("Channel:", self.views_box))
        channel_row.addWidget(self.plane_channel_combo, 1)
        views_layout.addLayout(channel_row)

        scroll = QScrollArea(self.views_box)
        scroll.setWidgetResizable(True)
        self._plane_container = QWidget(scroll)
        self._plane_grid = QGridLayout(self._plane_container)
        scroll.setWidget(self._plane_container)
        views_layout.addWidget(scroll, 1)

        self.difference_label = QLabel("", self.views_box)
        self.difference_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.difference_label.setObjectName("mediaPreviewImage")
        views_layout.addWidget(self.difference_label)

        self.difference_caption = QLabel("", self.views_box)
        self.difference_caption.setObjectName("mediaPreviewCaption")
        self.difference_caption.setTextFormat(Qt.TextFormat.PlainText)
        self.difference_caption.setWordWrap(True)
        views_layout.addWidget(self.difference_caption)

        layout.addWidget(self.views_box, 3)
        return container

    # -- state ------------------------------------------------------------- #

    @property
    def path(self) -> str | None:
        return self._path

    @property
    def report(self) -> AnalysisReport | None:
        return self._report

    # -- reactions --------------------------------------------------------- #

    def _on_file_selected(self, path: str) -> None:
        self._path = path
        self._report = None
        self._clear_output()

        # A stego file's original is usually the cover it was made from; propose it
        # when the conventional name is sitting next to it.
        if not self.reference_edit.text().strip():
            candidate = path.replace("_stego", "")
            if candidate != path and os.path.isfile(candidate):
                self.reference_edit.setText(candidate)
                self.statusMessage.emit(
                    f"Found a likely original: {file_utils.display_name(candidate)}."
                )

    def _choose_reference(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the original file", "", "All files (*)"
        )
        if path:
            self.reference_edit.setText(path)

    def _clear_output(self) -> None:
        self.indicator_table.setRowCount(0)
        self.quality_panel.clear()
        self.plane_channel_combo.clear()
        self.difference_label.clear()
        self.difference_caption.setText("")
        while self._plane_grid.count():
            item = self._plane_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    # -- the operation ----------------------------------------------------- #

    def validation_error(self) -> str | None:
        """Return why analysis cannot run, or ``None`` if it can."""
        if self._path is None:
            return "Select a file to analyse first."
        reference = self.reference_edit.text().strip()
        if reference and not os.path.isfile(reference):
            return f"{file_utils.display_name(reference)} does not exist."
        return None

    def analyse(self) -> None:
        problem = self.validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Steganalysis", problem)
            return

        self.analyse_button.setEnabled(False)
        self.statusMessage.emit("Analysing...")

        self._runner.submit(
            self._run_analysis,
            self._collect_inputs(),
            on_success=self._on_analysed,
            on_error=self._on_analysis_failed,
            on_finished=lambda: self.analyse_button.setEnabled(True),
        )

    def _collect_inputs(self) -> AnalysisInputs:
        """Read the form. Interface thread only."""
        assert self._path is not None
        return AnalysisInputs(
            path=self._path,
            reference=self.reference_edit.text().strip() or None,
            scaled_planes=self.scaled_check.isChecked(),
        )

    @staticmethod
    def _run_analysis(inputs: AnalysisInputs) -> AnalysisReport:
        """The backend call. Runs on a worker thread and reads only *inputs*."""
        return steganalysis.analyse(
            inputs.path, reference=inputs.reference, scaled_planes=inputs.scaled_planes
        )

    def _on_analysed(self, report: AnalysisReport) -> None:
        self._report = report
        self._clear_output()

        self._render_indicators(report)
        self._render_quality(report)
        self._render_channels(report)
        self._render_difference(report)

        self.statusMessage.emit(
            f"Analysed {file_utils.display_name(report.path)}: "
            f"{len(report.indicators)} indicators"
            + (", with the original for comparison" if report.has_reference else "")
            + "."
        )

    def _render_indicators(self, report: AnalysisReport) -> None:
        self.indicator_table.setRowCount(len(report.indicators))

        for row, indicator in enumerate(report.indicators):
            if indicator.insufficient_sample or indicator.value is None:
                # Deliberately not a number: there was not enough data for one.
                value_text = "insufficient sample"
            else:
                value_text = f"{indicator.value:.6f}"

            for column, text in enumerate(
                (
                    indicator.name,
                    indicator.scope,
                    value_text,
                    f"{indicator.analysed_sample_count:,}",
                    indicator.explanation,
                )
            ):
                item = QTableWidgetItem(text)
                item.setToolTip(indicator.disclaimer)
                self.indicator_table.setItem(row, column, item)

        self.indicator_table.resizeRowsToContents()

    def _render_quality(self, report: AnalysisReport) -> None:
        if report.quality is None:
            self.quality_panel.clear()
            self.quality_panel.set_notice(
                "Select the original file to see the difference image, the histogram "
                "comparison and the distortion metrics. The indicators above do not "
                "need it."
            )
            return

        quality = report.quality
        rows: list[tuple[str, object]] = [
            ("MSE", f"{quality.mse:.6f}"),
            (
                "PSNR",
                "infinite (identical)"
                if quality.psnr_unbounded
                else f"{quality.psnr_db:.2f} dB",
            ),
        ]
        if quality.snr_db is not None:
            rows.append(("SNR", f"{quality.snr_db:.2f} dB"))
        rows += [
            ("Largest change", f"{quality.max_absolute_difference:.0f}"),
            (
                "Samples changed",
                f"{quality.changed_samples:,} of {quality.total_samples:,} "
                f"({quality.changed_proportion * 100:.3f}%)",
            ),
            ("Identical", "yes" if quality.identical else "no"),
        ]
        self.quality_panel.set_rows(rows)

    def _render_channels(self, report: AnalysisReport) -> None:
        if not report.bit_planes:
            self.views_box.setTitle("Bit planes (image media only)")
            return

        self.views_box.setTitle("Bit planes and difference")
        labels: list[str] = []
        for plane in report.bit_planes:
            if plane.channel_label not in labels:
                labels.append(plane.channel_label)

        self.plane_channel_combo.blockSignals(True)
        self.plane_channel_combo.clear()
        for label in labels:
            self.plane_channel_combo.addItem(label)
        self.plane_channel_combo.blockSignals(False)

        if labels:
            self.plane_channel_combo.setCurrentIndex(0)
            self._render_planes()

    def _render_planes(self) -> None:
        while self._plane_grid.count():
            item = self._plane_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if self._report is None or not self._report.bit_planes:
            return

        wanted = self.plane_channel_combo.currentText()
        planes = [
            plane
            for plane in self._report.bit_planes
            if plane.channel_label == wanted
        ]

        for index, plane in enumerate(sorted(planes, key=lambda item: -item.bit_position)):
            cell = QWidget(self._plane_container)
            cell_layout = QVBoxLayout(cell)
            cell_layout.setContentsMargins(2, 2, 2, 2)

            image_label = QLabel(cell)
            image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            image_label.setObjectName("mediaPreviewImage")
            try:
                pixmap = array_to_pixmap(plane.plane)
            except ValueError:  # pragma: no cover - shapes are known
                continue
            image_label.setPixmap(
                pixmap.scaledToWidth(_PLANE_WIDTH, Qt.TransformationMode.FastTransformation)
                if pixmap.width() > _PLANE_WIDTH
                else pixmap
            )
            cell_layout.addWidget(image_label)

            caption = QLabel(f"bit {plane.bit_position}", cell)
            caption.setObjectName("mediaPreviewCaption")
            caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cell_layout.addWidget(caption)

            self._plane_grid.addWidget(cell, index // 4, index % 4)

    def _render_difference(self, report: AnalysisReport) -> None:
        if report.difference is None:
            self.difference_label.clear()
            if report.media_type == constants.MEDIA_AUDIO and (
                report.sample_difference is not None
            ):
                changed = int(np.count_nonzero(report.sample_difference))
                largest = int(np.abs(report.sample_difference).max(initial=0))
                self.difference_caption.setText(
                    f"Sample differences from the original: {changed:,} samples "
                    f"changed, largest change {largest}."
                )
            else:
                self.difference_caption.setText("")
            return

        try:
            pixmap = array_to_pixmap(report.difference.difference)
        except ValueError:  # pragma: no cover - shapes are known
            return

        self.difference_label.setPixmap(
            pixmap.scaledToWidth(360, Qt.TransformationMode.SmoothTransformation)
            if pixmap.width() > 360
            else pixmap
        )
        self.difference_caption.setText(
            f"Difference from the original, amplified so a one-bit change is visible "
            f"(mode: {report.difference.mode}). Without amplification a single-bit "
            f"change is indistinguishable from black."
        )

    def _on_analysis_failed(self, message: str, detail: str) -> None:
        self.statusMessage.emit(message)
        _log.error("analysis failed: %s", message)
        QMessageBox.warning(self, "Steganalysis", message)
