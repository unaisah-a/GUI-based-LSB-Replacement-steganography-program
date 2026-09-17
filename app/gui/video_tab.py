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

So the tab does three things:

* reports the clip's properties and its capacity at every LSB depth, which makes the
  frames-versus-payload trade-off concrete,
* maps a payload region onto frame numbers, from the manifest and the start secret,
  and says which frames carry it,
* steps through frames one at a time, next to the same frame of a reference clip and
  the amplified difference between them, so a viewer can confirm both that the
  carrying frames changed and that the rest did not.

Decoding happens on a worker thread, because seeking a frame out of a clip is slow
enough to freeze the window if done inline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSlider,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
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
from app.stego import media, video_stego
from app.stego.errors import StegoError
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
    """Inspects a clip's capacity and shows where a payload sits inside it."""

    TITLE = "Video"

    statusMessage = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("videoTab")

        self._runner = BackgroundRunner()
        self._path: str | None = None
        self._descriptor: video_stego.VideoDescriptor | None = None
        self._span: PayloadFrameSpan | None = None
        self._frames: dict[int, np.ndarray] = {}

        outer = QVBoxLayout(self)

        self.drop_zone = DropZone(
            self,
            media_types=(constants.MEDIA_VIDEO,),
            prompt="Drag a lossless video clip here",
        )
        self.drop_zone.fileSelected.connect(self._on_clip_selected)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        outer.addWidget(self.drop_zone)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        outer.addWidget(splitter, 1)

        self._set_availability()

    # -- construction ------------------------------------------------------ #

    def _build_left(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        self.info_panel = FileInfoPanel(container, title="Clip")
        layout.addWidget(self.info_panel)

        capacity_box = QGroupBox("Capacity by LSB depth", container)
        capacity_layout = QVBoxLayout(capacity_box)
        self.capacity_table = QTableWidget(0, 3, capacity_box)
        self.capacity_table.setHorizontalHeaderLabels(
            ["Depth", "Largest payload", "Frames a full payload spans"]
        )
        self.capacity_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.capacity_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        capacity_layout.addWidget(self.capacity_table)
        layout.addWidget(capacity_box, 1)

        payload_box = QGroupBox("Locate a payload", container)
        payload_form = QFormLayout(payload_box)

        manifest_row = QWidget(payload_box)
        manifest_layout = QHBoxLayout(manifest_row)
        manifest_layout.setContentsMargins(0, 0, 0, 0)
        self.manifest_edit = QLineEdit(manifest_row)
        self.manifest_edit.setPlaceholderText("found automatically beside the clip")
        manifest_layout.addWidget(self.manifest_edit, 1)
        self.manifest_browse_button = QPushButton("Browse...", manifest_row)
        self.manifest_browse_button.clicked.connect(self._choose_manifest)
        manifest_layout.addWidget(self.manifest_browse_button)
        payload_form.addRow("Manifest:", manifest_row)

        self.secret_edit = QLineEdit(payload_box)
        self.secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_edit.setPlaceholderText("needed for a derived start location")
        payload_form.addRow("Start secret:", self.secret_edit)

        self.locate_button = QPushButton("Locate the payload frames", payload_box)
        self.locate_button.clicked.connect(self.locate_payload)
        payload_form.addRow("", self.locate_button)

        layout.addWidget(payload_box)

        self.span_panel = FileInfoPanel(container, title="Payload region")
        layout.addWidget(self.span_panel)

        return container

    def _build_right(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        reference_box = QGroupBox("Reference clip (optional)", container)
        reference_layout = QHBoxLayout(reference_box)
        self.reference_edit = QLineEdit(reference_box)
        self.reference_edit.setPlaceholderText(
            "the cover this clip was made from, to see the difference"
        )
        reference_layout.addWidget(self.reference_edit, 1)
        self.reference_browse_button = QPushButton("Browse...", reference_box)
        self.reference_browse_button.clicked.connect(self._choose_reference)
        reference_layout.addWidget(self.reference_browse_button)
        layout.addWidget(reference_box)

        frames_box = QGroupBox("Frames", container)
        frames_layout = QVBoxLayout(frames_box)

        slider_row = QHBoxLayout()
        self.frame_slider = QSlider(Qt.Orientation.Horizontal, frames_box)
        self.frame_slider.setRange(0, 0)
        self.frame_slider.valueChanged.connect(self._on_frame_changed)
        slider_row.addWidget(self.frame_slider, 1)
        self.frame_number_label = QLabel("frame 0", frames_box)
        self.frame_number_label.setMinimumWidth(90)
        slider_row.addWidget(self.frame_number_label)
        frames_layout.addLayout(slider_row)

        self.carrier_label = QLabel("", frames_box)
        self.carrier_label.setObjectName("fileInfoNotice")
        self.carrier_label.setTextFormat(Qt.TextFormat.PlainText)
        self.carrier_label.setWordWrap(True)
        frames_layout.addWidget(self.carrier_label)

        images_row = QHBoxLayout()
        self.selected_frame_label = self._frame_view(frames_box, "This clip")
        self.reference_frame_label = self._frame_view(frames_box, "Reference")
        self.difference_frame_label = self._frame_view(frames_box, "Difference")
        for view in (
            self.selected_frame_label,
            self.reference_frame_label,
            self.difference_frame_label,
        ):
            images_row.addWidget(view.parentWidget())
        frames_layout.addLayout(images_row, 1)

        self.difference_caption = QLabel("", frames_box)
        self.difference_caption.setObjectName("mediaPreviewCaption")
        self.difference_caption.setTextFormat(Qt.TextFormat.PlainText)
        self.difference_caption.setWordWrap(True)
        frames_layout.addWidget(self.difference_caption)

        self.show_frame_button = QPushButton("Show this frame", frames_box)
        self.show_frame_button.clicked.connect(self.show_selected_frame)
        frames_layout.addWidget(self.show_frame_button)

        layout.addWidget(frames_box, 1)

        self.notice_label = QLabel(
            "LSB data cannot survive a lossy codec, so protected clips are always "
            "written as FFV1 in a Matroska container. Re-encoding one for upload, or "
            "trimming frames from it, destroys the payload — see the Attack Lab.",
            container,
        )
        self.notice_label.setObjectName("fileInfoNotice")
        self.notice_label.setWordWrap(True)
        layout.addWidget(self.notice_label)

        return container

    @staticmethod
    def _frame_view(parent: QWidget, title: str) -> QLabel:
        cell = QWidget(parent)
        cell_layout = QVBoxLayout(cell)
        cell_layout.setContentsMargins(2, 2, 2, 2)

        heading = QLabel(title, cell)
        heading.setObjectName("mediaPreviewTitle")
        cell_layout.addWidget(heading)

        image = QLabel(cell)
        image.setObjectName("mediaPreviewImage")
        image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        image.setMinimumSize(120, 90)
        cell_layout.addWidget(image, 1)
        return image

    # -- state ------------------------------------------------------------- #

    @property
    def path(self) -> str | None:
        return self._path

    @property
    def descriptor(self) -> video_stego.VideoDescriptor | None:
        return self._descriptor

    @property
    def span(self) -> PayloadFrameSpan | None:
        return self._span

    def _set_availability(self) -> None:
        """Disable the controls that need a clip, until one is loaded."""
        loaded = self._descriptor is not None
        self.locate_button.setEnabled(loaded)
        self.show_frame_button.setEnabled(loaded)
        self.frame_slider.setEnabled(loaded)

    # -- selection --------------------------------------------------------- #

    def _on_clip_selected(self, path: str) -> None:
        self._path = path
        self._descriptor = None
        self._span = None
        self._frames.clear()
        self.span_panel.clear()
        self.capacity_table.setRowCount(0)
        self.carrier_label.setText("")
        self.difference_caption.setText("")
        for view in (
            self.selected_frame_label,
            self.reference_frame_label,
            self.difference_frame_label,
        ):
            view.clear()

        candidate = file_utils.manifest_path_for(path)
        if os.path.isfile(candidate) and not self.manifest_edit.text().strip():
            self.manifest_edit.setText(candidate)

        self._runner.submit(
            video_stego.describe_only,
            path,
            on_success=self._on_described,
            on_error=self._on_failed,
        )
        self.statusMessage.emit(
            f"Reading {file_utils.display_name(path)}..."
        )

    def _on_described(self, descriptor: video_stego.VideoDescriptor) -> None:
        self._descriptor = descriptor
        self._set_availability()

        self.frame_slider.setRange(0, max(0, descriptor.frame_count - 1))
        self.frame_slider.setValue(0)
        self._on_frame_changed(0)

        try:
            description = file_utils.describe_file(self._path)
            capacity = media.measure(self._path, 1)
        except (StegoError, file_utils.UnsupportedMediaError) as exc:
            self.info_panel.clear()
            self.info_panel.set_notice(str(exc))
            return

        self.info_panel.show_capacity(description, capacity, lsb_depth=1)
        self.info_panel.set_notice(
            f"The whole clip is one sample domain of "
            f"{descriptor.total_samples:,} samples, in decode order. A start "
            f"location indexes it exactly as it indexes an image's pixels, so the "
            f"payload's frames are chosen by the same secret."
        )
        self._render_capacity_table(descriptor)

        self.statusMessage.emit(
            f"{file_utils.display_name(self._path)}: {descriptor.frame_count} frames "
            f"of {descriptor.resolution}, {descriptor.codec}."
        )

    def _render_capacity_table(self, descriptor: video_stego.VideoDescriptor) -> None:
        depths = constants.LSB_DEPTHS
        self.capacity_table.setRowCount(len(depths))

        for row, depth in enumerate(depths):
            capacity_bytes = (descriptor.total_samples * depth) // 8
            largest = max(0, capacity_bytes - constants.LENGTH_HEADER_BYTES)
            # How many frames a payload filling the clip would need is just the
            # whole clip; the useful figure is how many frames one *frame's worth*
            # of capacity covers, so report the per-frame capacity instead.
            per_frame_bytes = (descriptor.samples_per_frame * depth) // 8

            for column, text in enumerate(
                (
                    str(depth),
                    f"{file_utils.human_size(largest)} ({largest:,} B)",
                    f"{per_frame_bytes:,} B per frame, so a payload spans one frame "
                    f"per {per_frame_bytes:,} bytes",
                )
            ):
                self.capacity_table.setItem(row, column, QTableWidgetItem(text))

        self.capacity_table.resizeRowsToContents()

    def _choose_manifest(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the manifest", "", "Manifest files (*.json);;All files (*)"
        )
        if path:
            self.manifest_edit.setText(path)

    def _choose_reference(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the reference clip", "", "Video files (*.mkv *.avi);;All files (*)"
        )
        if path:
            self.reference_edit.setText(path)

    # -- locating the payload ---------------------------------------------- #

    def locate_validation_error(self) -> str | None:
        """Return why the payload cannot be located, or ``None`` if it can."""
        if self._descriptor is None:
            return "Select a clip first."
        manifest_path = self.manifest_edit.text().strip()
        if not manifest_path:
            return "Select the clip's manifest. It publishes the depth and the length."
        if not os.path.isfile(manifest_path):
            return f"{file_utils.display_name(manifest_path)} does not exist."
        return None

    def locate_payload(self) -> None:
        """Resolve the start location and report which frames carry the payload."""
        problem = self.locate_validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Video", problem)
            return

        try:
            span = self._compute_span()
        except (CryptoError, StegoError) as exc:
            self._span = None
            self.span_panel.clear()
            self.span_panel.set_notice(str(exc))
            self.statusMessage.emit(str(exc))
            return

        self._span = span
        self._render_span(span)
        self._on_frame_changed(self.frame_slider.value())
        self.statusMessage.emit(
            f"The payload occupies frames {span.first_frame} to {span.last_frame} "
            f"of {span.frame_count}."
        )

    def _compute_span(self) -> PayloadFrameSpan:
        """Resolve the start location from the manifest, then map it onto frames.

        Uses exactly the derivation the verifier uses, including measuring the
        embedded length as the envelope length after any error-correcting code, so
        the frames reported here are the frames the receiver will read.
        """
        assert self._descriptor is not None  # guarded by locate_validation_error
        manifest = manifest_module.read_manifest(self.manifest_edit.text().strip())

        embedded_length = error_correction.encoded_length(
            manifest.envelope_length, manifest.ecc
        )
        secret = self.secret_edit.text() or None
        if manifest.start_method == constants.START_METHOD_HMAC and secret is None:
            from app.crypto.errors import StartLocationError

            raise StartLocationError(
                "this clip uses a derived start location, so the start secret is "
                "needed to work out which frames carry the payload"
            )

        start = start_location_module.resolve_start_location(
            manifest.start_method,
            total_samples=self._descriptor.total_samples,
            lsb_depth=manifest.lsb_depth,
            envelope_length=embedded_length,
            secret=secret,
            manual_start_location=manifest.start_location,
            media_id=manifest.media_id,
            media_type=manifest.media_type,
            nonce_hex=manifest.nonce_hex,
        )
        return frame_span_for(
            self._descriptor, start, embedded_length, manifest.lsb_depth
        )

    def _render_span(self, span: PayloadFrameSpan) -> None:
        self.span_panel.set_rows(
            [
                ("Start location", f"sample {span.start_location:,}"),
                ("Embedded length", f"{span.embedded_length:,} B"),
                ("Samples occupied", f"{span.samples_written:,}"),
                (
                    "Frames",
                    f"{span.first_frame} to {span.last_frame} "
                    f"({span.frames_touched} of {span.frame_count})",
                ),
                (
                    "Offset in the first frame",
                    f"sample {span.offset_within_first_frame():,} of "
                    f"{span.samples_per_frame:,}",
                ),
                ("Share of the clip", f"{span.proportion_of_clip * 100:.2f}%"),
            ]
        )
        self.span_panel.set_notice(
            "Every other frame is untouched, which is why verification says nothing "
            "about them. Corrupting one of those frames leaves the verdict AUTHENTIC."
        )

    # -- frames ------------------------------------------------------------ #

    def _on_frame_changed(self, index: int) -> None:
        total = 0 if self._descriptor is None else self._descriptor.frame_count
        self.frame_number_label.setText(f"frame {index} of {max(0, total - 1)}")

        if self._span is None:
            self.carrier_label.setText("")
        elif self._span.covers(index):
            self.carrier_label.setText(
                f"Frame {index} carries part of the payload."
            )
        else:
            self.carrier_label.setText(
                f"Frame {index} carries no payload. Nothing verification says "
                f"applies to it."
            )

    def show_selected_frame(self) -> None:
        """Decode the selected frame, and the reference's, off the main thread."""
        if self._descriptor is None or self._path is None:
            self.statusMessage.emit("Select a clip first.")
            return

        index = self.frame_slider.value()
        reference = self.reference_edit.text().strip() or None
        if reference and not os.path.isfile(reference):
            message = f"{file_utils.display_name(reference)} does not exist."
            self.statusMessage.emit(message)
            QMessageBox.warning(self, "Video", message)
            return

        self.show_frame_button.setEnabled(False)
        self.statusMessage.emit(f"Decoding frame {index}...")

        self._runner.submit(
            self._decode_frames,
            self._path,
            reference,
            index,
            on_success=self._on_frames_decoded,
            on_error=self._on_failed,
            on_finished=lambda: self.show_frame_button.setEnabled(True),
        )

    @staticmethod
    def _decode_frames(
        path: str, reference: str | None, index: int
    ) -> tuple[int, np.ndarray | None, np.ndarray | None]:
        """Decode one frame from each clip. Runs on a worker thread; no widgets."""

        def one(target: str) -> np.ndarray | None:
            descriptor = video_stego.describe_only(target)
            for position, frame in enumerate(
                video_stego.iterate_frames(target, descriptor)
            ):
                if position == index:
                    return frame
            return None

        selected = one(path)
        other = one(reference) if reference else None
        return index, selected, other

    def _on_frames_decoded(
        self, decoded: tuple[int, np.ndarray | None, np.ndarray | None]
    ) -> None:
        from app.gui.steganalysis_tab import array_to_pixmap

        index, selected, reference = decoded

        if selected is None:
            self.statusMessage.emit(
                f"Frame {index} could not be decoded; the clip is shorter than its "
                f"container declares."
            )
            return

        # OpenCV decodes to BGR; the pixmap helper expects RGB, so the channel order
        # is reversed for display only. The samples themselves are never reordered.
        self.selected_frame_label.setPixmap(
            array_to_pixmap(selected[:, :, ::-1]).scaledToWidth(
                _FRAME_WIDTH, Qt.TransformationMode.FastTransformation
            )
        )

        if reference is None:
            self.reference_frame_label.clear()
            self.difference_frame_label.clear()
            self.difference_caption.setText(
                "Select a reference clip to see the per-frame difference."
            )
            return

        if reference.shape != selected.shape:
            self.reference_frame_label.clear()
            self.difference_frame_label.clear()
            self.difference_caption.setText(
                f"The reference frame is {reference.shape[1]}x{reference.shape[0]} "
                f"but this one is {selected.shape[1]}x{selected.shape[0]}, so they "
                f"cannot be compared."
            )
            return

        self.reference_frame_label.setPixmap(
            array_to_pixmap(reference[:, :, ::-1]).scaledToWidth(
                _FRAME_WIDTH, Qt.TransformationMode.FastTransformation
            )
        )

        difference = np.abs(
            selected.astype(np.int16) - reference.astype(np.int16)
        ).astype(np.uint8)
        changed = int(np.count_nonzero(difference))
        largest = int(difference.max(initial=0))

        # Amplified to full range, because a one-bit change is indistinguishable
        # from black at true scale.
        amplified = (
            (difference * (255 // largest)).astype(np.uint8)
            if largest
            else difference
        )
        self.difference_frame_label.setPixmap(
            array_to_pixmap(amplified[:, :, ::-1]).scaledToWidth(
                _FRAME_WIDTH, Qt.TransformationMode.FastTransformation
            )
        )
        self.difference_caption.setText(
            f"Frame {index}: {changed:,} of {difference.size:,} samples differ, "
            f"largest change {largest}. Amplified so a one-bit change is visible."
        )
        self.statusMessage.emit(f"Frame {index}: {changed:,} samples differ.")

    def _on_failed(self, message: str, detail: str) -> None:
        self.statusMessage.emit(message)
        _log.error("video tab operation failed: %s", message)
        self.info_panel.set_notice(message)
