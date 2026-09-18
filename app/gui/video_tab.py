"""Lossless-video frame preview and measured lossy-transcode laboratory."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
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

from app.crypto.encryption import decode_key
from app.crypto.key_manager import load_public_key_from_pem
from app.gui.task_runner import TaskRunner
from app.services.video import (
    LossyVideoExperiment,
    export_lossy_video_experiment,
    run_lossy_video_experiment,
)
from app.stego.video_stego import decode_video_frame


class VideoTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._experiment: LossyVideoExperiment | None = None
        self.runner = TaskRunner(self)
        self.video_path = QLineEdit()
        self.frame_index = QSpinBox()
        self.frame_index.setRange(0, 299)
        self.frame_preview = QLabel("Choose a video and preview its selected frame.")
        self.frame_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_preview.setMinimumHeight(260)
        self.frame_preview.setStyleSheet("background: #111820; color: white;")
        self.video_info = QLabel("No video inspected.")
        self.video_info.setWordWrap(True)

        self.protected_path = QLineEdit()
        self.manifest_path = QLineEdit()
        self.public_key_path = QLineEdit()
        self.start_secret = QLineEdit()
        self.start_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.encryption_key = QLineEdit()
        self.encryption_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.lossy_output_path = QLineEdit()
        self.evidence_path = QLineEdit()
        self.crf = QSpinBox()
        self.crf.setRange(0, 51)
        self.crf.setValue(23)
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText("Measured lossy verification evidence appears here.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()

        root = QVBoxLayout(self)
        title = QLabel("Lossless FFV1/Matroska video extension")
        title.setObjectName("sectionTitle")
        root.addWidget(title)
        note = QLabel(
            "Protect embeds in one selected decoded RGB frame and writes FFV1 Matroska. "
            "The service verifies every decoded colour byte and remuxes compatible audio. "
            "Use Protect and Verify for the signed workflow; this tab previews frames and "
            "measures a separate H.264 transcode."
        )
        note.setWordWrap(True)
        root.addWidget(note)

        preview_group = QGroupBox("Selected-frame preview")
        preview_form = QFormLayout(preview_group)
        preview_form.addRow("Video", self._picker_row(self.video_path, self._browse_video))
        preview_form.addRow("Zero-based frame", self.frame_index)
        preview_button = QPushButton("Inspect and preview frame")
        preview_button.clicked.connect(self._preview)
        preview_form.addRow(preview_button)
        preview_form.addRow(self.video_info)
        preview_form.addRow(self.frame_preview)
        root.addWidget(preview_group)

        experiment_group = QGroupBox("Lossy H.264 verification experiment")
        form = QFormLayout(experiment_group)
        form.addRow("Protected FFV1 video", self._picker_row(self.protected_path, self._browse_protected))
        form.addRow("Companion manifest", self._picker_row(self.manifest_path, self._browse_manifest))
        form.addRow("Trusted public key", self._picker_row(self.public_key_path, self._browse_key))
        form.addRow("Start secret (if used)", self.start_secret)
        form.addRow("Encryption key (if used)", self.encryption_key)
        form.addRow("H.264 CRF", self.crf)
        form.addRow("Lossy output", self._picker_row(self.lossy_output_path, self._browse_lossy_output, save=True))
        form.addRow("JSON evidence", self._picker_row(self.evidence_path, self._browse_evidence, save=True))
        buttons = QHBoxLayout()
        self.run_button = QPushButton("Transcode, extract, and verify")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self._run_experiment)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        buttons.addWidget(self.run_button)
        buttons.addWidget(self.cancel_button)
        form.addRow(buttons)
        root.addWidget(experiment_group)
        root.addWidget(self.progress)
        root.addWidget(self.result, 1)
        self._groups = (preview_group, experiment_group)

        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.succeeded.connect(self._succeeded)
        self.runner.failed.connect(self._failed)
        self.runner.cancelled.connect(self.result.setPlainText)
        self.runner.finished.connect(lambda: self._set_busy(False))

    @staticmethod
    def _picker_row(editor, callback, *, save=False):
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(editor)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return row

    def _open(self, title, pattern):
        return QFileDialog.getOpenFileName(self, title, "", pattern)[0]

    def _save(self, title, suggested, pattern):
        return QFileDialog.getSaveFileName(self, title, suggested, pattern)[0]

    def _browse_video(self):
        path = self._open("Video cover", "Video (*.mkv *.mp4 *.mov *.avi)")
        if path:
            self.video_path.setText(path)

    def _browse_protected(self):
        path = self._open("Protected FFV1 video", "Matroska video (*.mkv)")
        if path:
            self.protected_path.setText(path)
            source = Path(path)
            self.lossy_output_path.setText(str(source.with_name(f"{source.stem}_lossy.mkv")))
            self.evidence_path.setText(str(source.with_name(f"{source.stem}_lossy-evidence.json")))

    def _browse_manifest(self):
        path = self._open("Companion manifest", "JSON (*.json)")
        if path:
            self.manifest_path.setText(path)

    def _browse_key(self):
        path = self._open("Trusted public key", "PEM (*.pem)")
        if path:
            self.public_key_path.setText(path)

    def _browse_lossy_output(self):
        path = self._save("Lossy experiment output", self.lossy_output_path.text(), "Matroska (*.mkv)")
        if path:
            self.lossy_output_path.setText(path)

    def _browse_evidence(self):
        path = self._save("Lossy evidence", self.evidence_path.text(), "JSON (*.json)")
        if path:
            self.evidence_path.setText(path)

    @staticmethod
    def _pixmap(frame: np.ndarray) -> QPixmap:
        array = np.ascontiguousarray(frame, dtype=np.uint8)
        height, width, _channels = array.shape
        image = QImage(
            array.data,
            width,
            height,
            int(array.strides[0]),
            QImage.Format.Format_RGB888,
        ).copy()
        return QPixmap.fromImage(image).scaled(
            720,
            420,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

    def _preview(self):
        if self.runner.busy:
            return
        path = self.video_path.text().strip()
        index = self.frame_index.value()

        def operation(token, progress):
            token.checkpoint()
            progress("Decoding selected video frame…")
            frame, info = decode_video_frame(path, index)
            token.checkpoint()
            return "preview", frame, info

        self.runner.start(operation)

    def _run_experiment(self):
        if self.runner.busy:
            return
        try:
            public_key = load_public_key_from_pem(self.public_key_path.text().strip())
            encryption_text = self.encryption_key.text().strip()
            encryption_key = decode_key(encryption_text) if encryption_text else None
            protected = self.protected_path.text().strip()
            manifest = self.manifest_path.text().strip()
            lossy = self.lossy_output_path.text().strip()
            evidence = self.evidence_path.text().strip()
            if not all((protected, manifest, lossy, evidence)):
                raise ValueError("choose protected video, manifest, lossy output, and evidence paths")
            overwrite = Path(lossy).exists() or Path(evidence).exists()
            start_secret = self.start_secret.text() or None
            crf = self.crf.value()
            if overwrite and QMessageBox.question(
                self,
                "Replace experiment files?",
                "One or more experiment outputs exist. Replace them?",
            ) != QMessageBox.StandardButton.Yes:
                return
        except Exception as exc:
            self._failed(exc)
            return

        def operation(token, progress):
            token.checkpoint()
            progress("Creating H.264 test copy and running real verification…")
            result = run_lossy_video_experiment(
                protected,
                lossy,
                manifest,
                public_key,
                start_secret=start_secret,
                encryption_key=encryption_key,
                crf=crf,
                overwrite=overwrite,
            )
            token.checkpoint()
            export_lossy_video_experiment(result, evidence, overwrite=overwrite)
            token.checkpoint()
            return "experiment", result

        self.result.clear()
        self.runner.start(operation)

    def _succeeded(self, value):
        if value[0] == "preview":
            _kind, frame, info = value
            self.frame_preview.setPixmap(self._pixmap(frame))
            self.video_info.setText(
                f"{info.width}×{info.height}, {info.frame_count} frames at "
                f"{info.frame_rate} fps, codec {info.codec_name}, "
                f"{len(info.audio_streams)} audio stream(s)."
            )
            return
        _kind, result = value
        self._experiment = result
        self.result.setPlainText(
            f"Lossy codec: {result.codec}, CRF {result.crf}\n"
            f"Selected-frame changed samples: {result.selected_frame_differing_samples:,} / "
            f"{result.selected_frame_total_samples:,}\n"
            f"Actual verification verdict: {result.verification_verdict}\n"
            f"{result.verification_summary}\n\n{result.interpretation}"
        )

    def _failed(self, exc: Exception):
        QMessageBox.critical(self, "Video operation failed", str(exc))
        self.result.setPlainText(f"Video operation failed: {exc}")

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.result.setPlainText("Cancellation requested; the current FFmpeg step may finish first.")

    def _set_busy(self, busy: bool):
        self.run_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        for group in self._groups:
            group.setEnabled(not busy)

    def shutdown(self) -> None:
        self.runner.shutdown()
