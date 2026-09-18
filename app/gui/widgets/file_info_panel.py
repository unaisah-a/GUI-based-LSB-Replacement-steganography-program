"""A labelled read-out of media properties and capacity figures.

Used by the Protect tab for the cover and by other tabs for whatever file they hold.
It renders values that the backend has already computed and formatted decisions
about; it does no measuring of its own, so what it shows and what an embed call will
do cannot disagree.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.stego.media import UnifiedCapacity
from app.utils import constants, file_utils

__all__ = ["FileInfoPanel"]


class FileInfoPanel(QGroupBox):
    """Shows what is known about the selected file."""

    def __init__(self, parent: QWidget | None = None, *, title: str = "Media Information") -> None:
        super().__init__(title, parent)
        self.setObjectName("fileInfoPanel")

        outer = QVBoxLayout(self)
        self._form = QFormLayout()
        self._form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow
        )
        outer.addLayout(self._form)

        self._empty_label = QLabel("No file selected.", self)
        self._empty_label.setObjectName("fileInfoEmpty")
        outer.addWidget(self._empty_label)

        self._notice_label = QLabel("", self)
        self._notice_label.setObjectName("fileInfoNotice")
        self._notice_label.setWordWrap(True)
        self._notice_label.setVisible(False)
        outer.addWidget(self._notice_label)

        outer.addStretch(1)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self._rows: dict[str, QLabel] = {}

    # -- rendering --------------------------------------------------------- #

    def clear(self) -> None:
        while self._form.rowCount():
            self._form.removeRow(0)
        self._rows.clear()
        self._empty_label.setVisible(True)
        self._notice_label.setVisible(False)

    def set_rows(self, rows: Iterable[tuple[str, Any]]) -> None:
        """Replace the displayed rows with *rows*, a sequence of label/value pairs."""
        self.clear()
        collected = list(rows)
        if not collected:
            return

        self._empty_label.setVisible(False)
        for label, value in collected:
            field = QLabel(str(value), self)
            field.setObjectName("fileInfoValue")
            field.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            field.setWordWrap(True)
            self._form.addRow(f"{label}:", field)
            self._rows[label] = field

    def set_notice(self, text: str) -> None:
        self._notice_label.setText(text)
        self._notice_label.setVisible(bool(text))

    def value_for(self, label: str) -> str | None:
        """Return the currently displayed value for *label*. For tests."""
        widget = self._rows.get(label)
        return None if widget is None else widget.text()

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(self._rows)

    # -- convenience renderers --------------------------------------------- #

    def show_description(self, description: file_utils.MediaDescription) -> None:
        """Show what is known from the file alone, without decoding it."""
        rows: list[tuple[str, Any]] = [
            ("File", description.name),
            ("Media type", description.media_type),
            ("Container", description.container_format),
            ("Size", f"{description.size_human} ({description.size_bytes} B)"),
        ]
        self.set_rows(rows)

        if description.extension_mismatch:
            # Not an error: content wins. But it changes the output container, so
            # the user should know before being surprised by the result.
            self.set_notice(
                f"The file extension is {description.extension} but the content is "
                f"{description.container_format}. The content decides, so the output "
                f"will be written as {description.container_format}."
            )

    def show_capacity(
        self,
        description: file_utils.MediaDescription,
        capacity: UnifiedCapacity,
        *,
        payload_length: int | None = None,
        lsb_depth: int | None = None,
    ) -> None:
        """Show media properties together with the capacity at the chosen settings."""
        report = capacity.report
        rows: list[tuple[str, Any]] = [
            ("File", description.name),
            ("Media type", capacity.media_type),
            ("Container", capacity.container_format),
            ("Size", f"{description.size_human} ({description.size_bytes} B)"),
        ]

        rows.extend(self._medium_rows(capacity))

        if lsb_depth is not None:
            rows.append(("LSB depth", f"{lsb_depth} of {constants.MAX_LSB_DEPTH}"))

        rows += [
            ("Embeddable samples", f"{report.total_embeddable_samples:,}"),
            (
                "Capacity",
                f"{file_utils.human_size(report.max_payload_length)} "
                f"({report.max_payload_length:,} B)",
            ),
        ]

        if payload_length is not None:
            rows.append(
                (
                    "Payload",
                    f"{file_utils.human_size(payload_length)} "
                    f"({payload_length:,} B)",
                )
            )
            if report.capacity_used_percent is not None:
                rows.append(("Capacity used", f"{report.capacity_used_percent:.1f}%"))
            rows.append(("Fits", "yes" if report.payload_fits else "no"))

        self.set_rows(rows)

    @staticmethod
    def _medium_rows(capacity: UnifiedCapacity) -> list[tuple[str, Any]]:
        """Rows that only make sense for one medium."""
        descriptor = capacity.descriptor
        rows: list[tuple[str, Any]] = []

        if capacity.media_type == constants.MEDIA_IMAGE:
            rows += [
                ("Dimensions", f"{descriptor.width} x {descriptor.height}"),
                ("Channels", descriptor.channel_count),
            ]
        elif capacity.media_type == constants.MEDIA_AUDIO:
            rows += [
                ("Sample rate", f"{descriptor.sample_rate:,} Hz"),
                ("Channels", descriptor.channel_count),
                ("Duration", f"{descriptor.duration_seconds:.3f} s"),
                ("Frames", f"{descriptor.frame_count:,}"),
            ]
        elif capacity.media_type == constants.MEDIA_VIDEO:
            rows += [
                ("Dimensions", f"{descriptor.width} x {descriptor.height}"),
                ("Frames", f"{descriptor.frame_count:,}"),
                ("Frame rate", f"{descriptor.frame_rate:.3f} fps"),
                ("Duration", f"{descriptor.duration_seconds:.3f} s"),
                ("Codec", descriptor.codec),
                ("Samples per frame", f"{descriptor.samples_per_frame:,}"),
            ]
        return rows
