"""Displays a verification verdict, and recovered content, safely.

The verdict is the point of the whole application, so it gets a prominent coloured
banner, the four agreed boolean flags, the specific reason, and any caveats that
apply.

Recovered content is inert
--------------------------
The plan is explicit that extracted content must not be executed automatically, and
this widget is where that rule is enforced. Recovered bytes are shown as plain text
in a read-only view, or as a hex dump when they are not valid UTF-8. Nothing is
passed to ``QDesktopServices``, no rich text is rendered, and no path is opened.
The bytes can be saved, but only to a path the user picks in a save dialog, and the
default name offered is the sender's recorded name reduced to a bare file name by
:func:`app.utils.payload_files.safe_filename`.

Rich text matters more than it sounds: a ``QLabel`` renders HTML by default, so a
recovered message containing markup would be interpreted rather than displayed, and
an ``<img src=...>`` would make the application fetch a URL of the sender's
choosing. Every view here is explicitly set to plain text.
"""

from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.utils import constants, file_utils, payload_files
from app.verification.verdicts import VERDICT_DESCRIPTIONS, VerificationResult

__all__ = ["ResultPanel", "hex_dump"]

#: Which style class each verdict gets, so the stylesheet decides the colours.
_VERDICT_STYLE: dict[str, str] = {
    constants.VERDICT_AUTHENTIC: "authentic",
    constants.VERDICT_TAMPERED: "failed",
    constants.VERDICT_SIGNATURE_INVALID: "failed",
    constants.VERDICT_PAYLOAD_MISSING: "unknown",
    constants.VERDICT_WRONG_START_LOCATION: "unknown",
    constants.VERDICT_CANNOT_VERIFY: "unknown",
}

_FLAG_LABELS: tuple[tuple[str, str], ...] = (
    ("payload_found", "Payload found"),
    ("signature_valid", "Signature valid"),
    ("hash_valid", "Message hash matches"),
    ("start_location_valid", "Start location usable"),
    ("manifest_consistent", "Manifest agrees with record"),
)


def hex_dump(data: bytes, *, width: int = 16, limit: int = 4096) -> str:
    """Render *data* as an offset/hex/ASCII dump.

    Truncated at *limit* bytes: a multi-megabyte recovered file would otherwise
    lock the interface while Qt laid out the text.
    """
    view = data[:limit]
    lines: list[str] = []
    for offset in range(0, len(view), width):
        chunk = view[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "." for byte in chunk
        )
        lines.append(f"{offset:08x}  {hex_part:<{width * 3 - 1}}  {ascii_part}")
    if len(data) > limit:
        lines.append(
            f"... {len(data) - limit} further bytes not shown "
            f"({len(data)} bytes total)"
        )
    return "\n".join(lines) if lines else "(empty)"


def _flag_text(value: bool | None) -> str:
    if value is None:
        # Meaningfully different from False: the workflow never got far enough to
        # establish this, so saying "no" would be a claim it did not make.
        return "not established"
    return "yes" if value else "no"


class ResultPanel(QGroupBox):
    """The verdict banner, the flags, the reason, the notes and the payload view."""

    def __init__(self, parent: QWidget | None = None, *, title: str = "Result") -> None:
        super().__init__(title, parent)
        self.setObjectName("resultPanel")

        outer = QVBoxLayout(self)

        self._verdict_label = QLabel("", self)
        self._verdict_label.setObjectName("verdictBanner")
        self._verdict_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._verdict_label.setTextFormat(Qt.TextFormat.PlainText)
        self._verdict_label.setMinimumHeight(44)
        outer.addWidget(self._verdict_label)

        self._description_label = QLabel("", self)
        self._description_label.setObjectName("verdictDescription")
        self._description_label.setTextFormat(Qt.TextFormat.PlainText)
        self._description_label.setWordWrap(True)
        outer.addWidget(self._description_label)

        self._reason_label = QLabel("", self)
        self._reason_label.setObjectName("verdictReason")
        self._reason_label.setTextFormat(Qt.TextFormat.PlainText)
        self._reason_label.setWordWrap(True)
        outer.addWidget(self._reason_label)

        self._flags_box = QGroupBox("Checks", self)
        self._flags_form = QFormLayout(self._flags_box)
        self._flags_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        outer.addWidget(self._flags_box)
        self._flag_widgets: dict[str, QLabel] = {}

        self._notes_label = QLabel("", self)
        self._notes_label.setObjectName("verdictNotes")
        self._notes_label.setTextFormat(Qt.TextFormat.PlainText)
        self._notes_label.setWordWrap(True)
        outer.addWidget(self._notes_label)

        payload_box = QGroupBox("Recovered message", self)
        payload_layout = QVBoxLayout(payload_box)

        inert_notice = QLabel(constants.EXTRACTED_CONTENT_NOTICE, payload_box)
        inert_notice.setObjectName("inertNotice")
        inert_notice.setTextFormat(Qt.TextFormat.PlainText)
        inert_notice.setWordWrap(True)
        payload_layout.addWidget(inert_notice)

        self._payload_info_label = QLabel("", payload_box)
        self._payload_info_label.setObjectName("payloadInfo")
        # The recorded file name comes from the sender, so it is never rendered.
        self._payload_info_label.setTextFormat(Qt.TextFormat.PlainText)
        self._payload_info_label.setWordWrap(True)
        payload_layout.addWidget(self._payload_info_label)

        self._payload_view = QPlainTextEdit(payload_box)
        self._payload_view.setObjectName("payloadView")
        self._payload_view.setReadOnly(True)
        self._payload_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._payload_view.setPlaceholderText("No message recovered.")
        payload_layout.addWidget(self._payload_view)

        toggle_row = QHBoxLayout()
        self._as_text_button = QPushButton("Show as text", payload_box)
        self._as_text_button.clicked.connect(lambda: self._render_payload(False))
        toggle_row.addWidget(self._as_text_button)

        self._as_hex_button = QPushButton("Show as hex", payload_box)
        self._as_hex_button.clicked.connect(lambda: self._render_payload(True))
        toggle_row.addWidget(self._as_hex_button)

        self._save_button = QPushButton("Save recovered payload...", payload_box)
        self._save_button.clicked.connect(self._choose_save_path)
        toggle_row.addWidget(self._save_button)
        toggle_row.addStretch(1)
        payload_layout.addLayout(toggle_row)

        outer.addWidget(payload_box, 1)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._message: bytes | None = None
        self._result: VerificationResult | None = None
        self.clear()

    # -- state ------------------------------------------------------------- #

    @property
    def result(self) -> VerificationResult | None:
        return self._result

    @property
    def verdict_text(self) -> str:
        return self._verdict_label.text()

    def flag_text(self, name: str) -> str | None:
        widget = self._flag_widgets.get(name)
        return None if widget is None else widget.text()

    @property
    def payload_text(self) -> str:
        return self._payload_view.toPlainText()

    @property
    def payload_info_text(self) -> str:
        return self._payload_info_label.text()

    @property
    def save_enabled(self) -> bool:
        return self._save_button.isEnabled()

    def suggested_filename(self) -> str | None:
        """The default name offered when saving, or ``None`` with nothing to save."""
        if self._message is None:
            return None
        metadata = None if self._result is None or self._result.record is None else (
            self._result.record.metadata
        )
        return payload_files.suggested_filename(metadata, self._message)

    def clear(self) -> None:
        self._result = None
        self._message = None
        self._verdict_label.setText("No verification run yet")
        self._verdict_label.setProperty("verdict", "")
        self._restyle(self._verdict_label)
        self._description_label.setText("")
        self._reason_label.setText("")
        self._notes_label.setText("")
        self._payload_view.setPlainText("")
        self._payload_info_label.setText("")
        self._set_payload_buttons(False)

        while self._flags_form.rowCount():
            self._flags_form.removeRow(0)
        self._flag_widgets.clear()

    # -- rendering --------------------------------------------------------- #

    def show_result(self, result: VerificationResult) -> None:
        """Render a verification result."""
        self.clear()
        self._result = result

        self._verdict_label.setText(result.verdict)
        self._verdict_label.setProperty(
            "verdict", _VERDICT_STYLE.get(result.verdict, "unknown")
        )
        self._restyle(self._verdict_label)

        self._description_label.setText(
            VERDICT_DESCRIPTIONS.get(result.verdict, "")
        )
        self._reason_label.setText(result.reason)

        for attribute, label in _FLAG_LABELS:
            value = getattr(result, attribute)
            widget = QLabel(_flag_text(value), self._flags_box)
            widget.setObjectName("flagValue")
            widget.setTextFormat(Qt.TextFormat.PlainText)
            widget.setProperty(
                "flag", "" if value is None else ("yes" if value else "no")
            )
            self._flags_form.addRow(f"{label}:", widget)
            self._flag_widgets[attribute] = widget

        if result.mismatched_fields:
            widget = QLabel(", ".join(result.mismatched_fields), self._flags_box)
            widget.setTextFormat(Qt.TextFormat.PlainText)
            widget.setWordWrap(True)
            self._flags_form.addRow("Fields that disagree:", widget)

        if result.start_location is not None:
            widget = QLabel(f"{result.start_location:,}", self._flags_box)
            widget.setTextFormat(Qt.TextFormat.PlainText)
            self._flags_form.addRow("Start location used:", widget)

        self.set_notes(result.notes)
        self.show_message(result.message)

    def set_notes(self, notes: Iterable[str]) -> None:
        collected = [note for note in notes if note]
        self._notes_label.setText("\n\n".join(collected))

    def show_message(self, message: bytes | None) -> None:
        """Show recovered bytes, as inert text or a hex dump."""
        self._message = message
        if message is None:
            self._payload_view.setPlainText("")
            self._payload_info_label.setText("")
            self._set_payload_buttons(False)
            return

        detected = payload_files.detect_payload_type(message)
        self._payload_info_label.setText(
            f"{len(message):,} bytes, detected as {detected.label}. "
            f"Saved by default as: {self.suggested_filename()}"
        )

        self._set_payload_buttons(True)
        # Prefer text when the bytes are valid UTF-8, since that is what a reader
        # wants; fall back to hex rather than showing replacement characters.
        self._render_payload(not self._is_text(message))

    @staticmethod
    def _is_text(message: bytes) -> bool:
        try:
            message.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    def _render_payload(self, as_hex: bool) -> None:
        if self._message is None:
            return
        if as_hex:
            self._payload_view.setPlainText(hex_dump(self._message))
            return
        try:
            decoded = self._message.decode("utf-8")
        except UnicodeDecodeError:
            self._payload_view.setPlainText(hex_dump(self._message))
            return
        # setPlainText, never setHtml: recovered content must not be interpreted.
        self._payload_view.setPlainText(decoded)

    def _set_payload_buttons(self, enabled: bool) -> None:
        self._as_text_button.setEnabled(enabled)
        self._as_hex_button.setEnabled(enabled)
        self._save_button.setEnabled(enabled)

    def _choose_save_path(self) -> None:
        suggested = self.suggested_filename()
        if suggested is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save the recovered payload as", suggested, "All files (*)"
        )
        if not path:
            return
        try:
            self.save_payload(path)
        except OSError as exc:
            QMessageBox.warning(self, "Save recovered payload", str(exc))

    def save_payload(self, path: str) -> str:
        """Write the recovered bytes to *path*, exactly as recovered.

        The save dialog has already asked about replacing an existing file, so this
        overwrites. Nothing is opened afterwards.
        """
        if self._message is None:
            raise OSError("there is no recovered payload to save")
        return file_utils.write_bytes_atomic(path, self._message, overwrite=True)

    def show_error(self, message: str) -> None:
        """Show an operational failure that is not a verdict."""
        self.clear()
        self._verdict_label.setText("Could not complete")
        self._verdict_label.setProperty("verdict", "unknown")
        self._restyle(self._verdict_label)
        self._reason_label.setText(message)

    @staticmethod
    def _restyle(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
