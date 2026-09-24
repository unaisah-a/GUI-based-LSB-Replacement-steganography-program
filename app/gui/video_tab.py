"""The Video tab: inspect a clip, and see which frames a payload actually occupies.

This tab deliberately does **not** duplicate Protect and Verify. Registering the
video handler in :mod:`app.stego.media` made those two tabs work on clips as they
stand, and adding a second embedding form here would have meant two places to keep
in step for no benefit.

What it does instead is the thing the other tabs cannot show. Video's sample domain
is one flat run over every pixel of every frame, so a payload lands in a specific
short span of specific frames, decided by the keyed start location. That is the
single most useful thing to be able to see about a video embedding, and it is
invisible in a side-by-side player: the affected frames look exactly like the others.

The tab previews the clip and maps the claimed payload range to frames.
Protection and verification remain in their existing tabs. A located range alone
is not authentication; manifest settings are untrusted until verification.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.crypto import manifest as manifest_module
from app.crypto import start_location as start_location_module
from app.crypto.errors import CryptoError
from app.gui.widgets.drop_zone import DropZone
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.workers import BackgroundRunner
from app.robustness import error_correction
from app.stego import video_stego
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = ["PayloadFrameSpan", "VideoTab", "frame_span_for"]

_log = get_logger(__name__)

#: Frames are shown at a fixed width so the three panels line up regardless of the
#: clip's resolution.
_FRAME_WIDTH = 240


@dataclass(frozen=True)
class PayloadFrameSpan:
    """Which frames of a clip a payload occupies, and how much of each."""

    start_location: int
    embedded_length: int
    samples_written: int
    samples_per_frame: int
    frame_count: int
    first_frame: int
    last_frame: int

    @property
    def frames_touched(self) -> int:
        return self.last_frame - self.first_frame + 1

    @property
    def proportion_of_clip(self) -> float:
        return self.frames_touched / self.frame_count if self.frame_count else 0.0

    def covers(self, frame_index: int) -> bool:
        return self.first_frame <= frame_index <= self.last_frame

    def offset_within_first_frame(self) -> int:
        return self.start_location - self.first_frame * self.samples_per_frame


def frame_span_for(
    descriptor: video_stego.VideoDescriptor,
    start_location: int,
    embedded_length: int,
    lsb_depth: int,
) -> PayloadFrameSpan:
    """Work out which frames a payload of *embedded_length* bytes occupies.

    Pure arithmetic on the flat domain, kept out of the widget so it can be tested
    without a window. The sample count is the *encoded* stream — the payload plus its
    4-byte length header — divided by the depth and rounded up, exactly as the
    embedding computes it.
    """
    from app.stego.bit_utils import groups_needed

    encoded_bits = (embedded_length + constants.LENGTH_HEADER_BYTES) * 8
    samples = groups_needed(encoded_bits, lsb_depth)
    per_frame = descriptor.samples_per_frame

    first = start_location // per_frame
    last = min(descriptor.frame_count - 1, (start_location + samples - 1) // per_frame)

    return PayloadFrameSpan(
        start_location=start_location,
        embedded_length=embedded_length,
        samples_written=samples,
        samples_per_frame=per_frame,
        frame_count=descriptor.frame_count,
        first_frame=first,
        last_frame=last,
    )


class VideoTab(QWidget):
    """Preview a clip and locate the claimed payload frame range."""

    TITLE = "Video"
    statusMessage = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._runner = BackgroundRunner()
        self._path = None
        self._descriptor = None
        self._span = None
        self._generation = 0
        layout = QVBoxLayout(self)
        self.drop_zone = DropZone(self, media_types=(constants.MEDIA_VIDEO,),
                                  prompt="Drag a video clip here")
        self.drop_zone.fileSelected.connect(self._on_clip_selected)
        self.drop_zone.selectionCleared.connect(self._clear_selection)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        layout.addWidget(self.drop_zone)
        self.notice_label = QLabel(
            "Protect and Verify support video. Protected output is video-only FFV1/MKV: "
            "source audio is omitted. Lossy conversion can destroy the hidden payload.", self
        )
        self.notice_label.setWordWrap(True)
        layout.addWidget(self.notice_label)
        self.info_panel = FileInfoPanel(self, title="Clip")
        layout.addWidget(self.info_panel)
        form = QFormLayout()
        self.manifest_edit = QLineEdit(self)
        self.manifest_edit.setPlaceholderText("Companion manifest")
        row = QHBoxLayout()
        row.addWidget(self.manifest_edit)
        self.manifest_browse_button = QPushButton("Browse...", self)
        self.manifest_browse_button.clicked.connect(self._choose_manifest)
        row.addWidget(self.manifest_browse_button)
        form.addRow("Manifest:", row)
        self.secret_edit = QLineEdit(self)
        self.secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Start secret:", self.secret_edit)
        layout.addLayout(form)
        self.locate_button = QPushButton("Locate the payload frames", self)
        self.locate_button.clicked.connect(self.locate_payload)
        layout.addWidget(self.locate_button)
        self.span_panel = FileInfoPanel(self, title="Claimed payload region")
        layout.addWidget(self.span_panel)
        from app.gui.widgets.media_preview import MediaPreview
        self.preview = MediaPreview(self, title="Video preview")
        layout.addWidget(self.preview, 1)
        self.locate_button.setEnabled(False)
        self.manifest_edit.textChanged.connect(self._clear_span)
        self.secret_edit.textChanged.connect(self._clear_span)

    @property
    def path(self):
        return self._path

    @property
    def descriptor(self):
        return self._descriptor

    @property
    def span(self):
        return self._span

    def _clear_span(self):
        self._span = None
        self.span_panel.clear()

    def _clear_selection(self):
        self._generation += 1
        self._path = None
        self._descriptor = None
        self._clear_span()
        self.info_panel.clear()
        self.preview.clear()
        self.locate_button.setEnabled(False)

    def _on_clip_selected(self, path):
        self._clear_selection()
        self._path = path
        generation = self._generation
        candidate = file_utils.manifest_path_for(path)
        self.manifest_edit.setText(candidate if os.path.isfile(candidate) else "")
        self.preview.show_file(path)
        self._runner.submit(
            video_stego.describe_only, path,
            on_success=lambda result: self._on_described(result)
            if generation == self._generation else None,
            on_error=lambda message, detail: self.statusMessage.emit(message)
            if generation == self._generation else None,
        )

    def _on_described(self, descriptor):
        self._descriptor = descriptor
        self.locate_button.setEnabled(True)
        self.info_panel.set_rows([
            ("Dimensions", f"{descriptor.width} x {descriptor.height}"),
            ("Frames", str(descriptor.frame_count)),
            ("Frame rate", str(descriptor.frame_rate)),
        ])

    def _choose_manifest(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select manifest", "", "JSON files (*.json)")
        if path:
            self.manifest_edit.setText(path)

    def locate_validation_error(self):
        if self._descriptor is None:
            return "Select a clip first."
        if not os.path.isfile(self.manifest_edit.text().strip()):
            return "Select an existing companion manifest."
        return None

    def locate_payload(self):
        self._clear_span()
        problem = self.locate_validation_error()
        if problem:
            self.statusMessage.emit(problem)
            return
        try:
            manifest = manifest_module.read_manifest(self.manifest_edit.text().strip())
            if manifest.media_type != constants.MEDIA_VIDEO:
                raise ValueError("The manifest does not describe video.")
            length = error_correction.encoded_length(manifest.envelope_length, manifest.ecc)
            start = start_location_module.resolve_start_location(
                manifest.start_method, total_samples=self._descriptor.total_samples,
                lsb_depth=manifest.lsb_depth, envelope_length=length,
                secret=self.secret_edit.text() or None,
                manual_start_location=manifest.start_location,
                media_id=manifest.media_id, media_type=manifest.media_type,
                nonce_hex=manifest.nonce_hex,
            )
            self._span = frame_span_for(self._descriptor, start, length, manifest.lsb_depth)
        except (CryptoError, ValueError) as exc:
            self.statusMessage.emit(str(exc))
            self.span_panel.set_notice(str(exc))
            return
        self.span_panel.set_rows([
            ("Frames", f"{self._span.first_frame} to {self._span.last_frame}"),
            ("Frames touched", str(self._span.frames_touched)),
            ("Start sample", str(start)), ("Embedded bytes", str(length)),
        ])
        self.span_panel.set_notice(
            "Located from untrusted manifest settings; use Verify to authenticate. "
            "Edits outside the payload can still verify successfully."
        )

    def shutdown(self):
        self._generation += 1
        self.preview.clear()
        self._runner.wait()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)
