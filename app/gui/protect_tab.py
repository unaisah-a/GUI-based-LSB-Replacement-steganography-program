"""The Protect tab: sign a message and hide it in a cover object.

The whole sender-side workflow is one call to
:func:`app.verification.protect.protect_media`. This tab collects its arguments,
runs it off the interface thread, and reports what came back. Every handler here is
short, and none of them contains steganography or cryptography — that separation is
what the project plan asks for and it is also what makes the workflow testable
without a window.

The capacity read-out
---------------------
The depth control's purpose is to make the trade-off visible, so the read-out has to
update as the user types rather than only after an attempt fails. That needs the
*exact* payload length before anything is signed, which is possible because every
variable-width field in the verification record is either fixed-length (the nonce,
the digest, the timestamp) or already known (the media identifier, the depth, the
start method). :meth:`ProtectTab._estimated_envelope_length` builds a record with the
values in hand and measures it, so the figure shown matches what will actually be
embedded.

Why the output path is explicit
-------------------------------
The tab proposes a name beside the cover and lets it be changed, rather than writing
somewhere implicit. Combined with the stego layer refusing to overwrite and refusing
to write over its own input, it is difficult to destroy a cover object by accident.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSlider,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.analysis import quality_metrics
from app.crypto import envelope as envelope_module
from app.crypto import key_manager
from app.crypto.envelope import ErrorCorrectionParameters, VerificationRecord
from app.gui.widgets.drop_zone import DropZone
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.widgets.media_preview import MediaPreview
from app.gui.workers import BackgroundRunner
from app.robustness import error_correction
from app.stego import media
from app.stego.errors import StegoError
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger
from app.verification.protect import ProtectResult, protect_media

__all__ = ["ProtectTab"]

#: How long the key path must stop changing before the key file is read.
KEY_READ_DELAY_MS = 300

_log = get_logger(__name__)

#: Derived from the registry rather than hardcoded, so the tab never offers a medium
#: this build cannot act on and never omits one it can.
_ACCEPTED_MEDIA = tuple(
    media_type
    for media_type in (constants.MEDIA_IMAGE, constants.MEDIA_AUDIO, constants.MEDIA_VIDEO)
    if media.supports(media_type)
)


@dataclass(frozen=True)
class ProtectInputs:
    """A snapshot of the form, taken on the interface thread before work starts.

    The worker thread reads only this, never the widgets, so a value edited while
    protection is running cannot leak into the operation halfway through.
    """

    cover_path: str
    output_path: str
    key_path: str
    message: bytes
    media_id: str
    lsb_depth: int
    start_method: str
    start_secret: str | None
    manual_start_location: int | None
    passphrase: str | None
    ecc: ErrorCorrectionParameters | None
    match_cover_size: bool


def _cover_prompt() -> str:
    """Name the containers actually accepted, built from the same registry."""
    extensions = [
        name.upper().lstrip(".")
        for media_type in _ACCEPTED_MEDIA
        for name in constants.OPEN_FILE_EXTENSIONS.get(media_type, ())
    ]
    if not extensions:  # pragma: no cover - a build with no media registered
        return "No cover media types are available in this build"
    return f"Drag a {', '.join(extensions[:-1])} or {extensions[-1]} cover object here"


class ProtectTab(QWidget):
    """Collects embedding settings and runs the protect workflow."""

    TITLE = "Protect"

    #: Emitted with the result so other tabs can pick the file up.
    mediaProtected = Signal(object)
    #: Emitted with a message for the window's status bar.
    statusMessage = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("protectTab")

        self._runner = BackgroundRunner()
        self._cover_path: str | None = None
        self._cover_media_type: str = constants.MEDIA_IMAGE
        self._result: ProtectResult | None = None
        # The signature length depends on the modulus of the key actually selected,
        # so the capacity read-out cannot assume the default size. Kept up to date by
        # _read_key_size and used by _estimated_envelope_length.
        self._signature_size = constants.RSA_KEY_SIZE_DEFAULT // 8
        # Reading the key parses a PEM file, so it waits until typing pauses rather
        # than running on every keystroke.
        self._key_read_timer = QTimer(self)
        self._key_read_timer.setSingleShot(True)
        self._key_read_timer.setInterval(KEY_READ_DELAY_MS)
        self._key_read_timer.timeout.connect(self._read_key_size)

        outer = QVBoxLayout(self)

        self.drop_zone = DropZone(
            self,
            media_types=_ACCEPTED_MEDIA,
            prompt=_cover_prompt(),
        )
        self.drop_zone.fileSelected.connect(self._on_cover_selected)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        outer.addWidget(self.drop_zone)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._build_settings())
        splitter.addWidget(self._build_readout())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        outer.addWidget(splitter, 1)

        self._refresh_start_controls()
        self._refresh_encryption_controls()
        self._load_default_key()

    # -- construction ------------------------------------------------------ #

    def _build_settings(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        settings = QGroupBox("Embedding Settings", container)
        form = QFormLayout(settings)

        self.media_id_edit = QLineEdit(settings)
        self.media_id_edit.setPlaceholderText("IMG-001")
        form.addRow("Media ID:", self.media_id_edit)

        depth_row = QWidget(settings)
        depth_layout = QHBoxLayout(depth_row)
        depth_layout.setContentsMargins(0, 0, 0, 0)
        self.depth_slider = QSlider(Qt.Orientation.Horizontal, depth_row)
        self.depth_slider.setRange(constants.MIN_LSB_DEPTH, constants.MAX_LSB_DEPTH)
        self.depth_slider.setValue(1)
        self.depth_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.depth_slider.setTickInterval(1)
        self.depth_slider.setPageStep(1)
        self.depth_slider.valueChanged.connect(self._on_depth_changed)
        depth_layout.addWidget(self.depth_slider, 1)
        self.depth_label = QLabel("1", depth_row)
        self.depth_label.setMinimumWidth(18)
        depth_layout.addWidget(self.depth_label)
        form.addRow("LSB depth:", depth_row)

        self.start_mode_combo = QComboBox(settings)
        self.start_mode_combo.addItem("Derived from a secret (HMAC)", constants.START_METHOD_HMAC)
        self.start_mode_combo.addItem("Chosen manually", constants.START_METHOD_MANUAL)
        self.start_mode_combo.currentIndexChanged.connect(self._refresh_start_controls)
        form.addRow("Start mode:", self.start_mode_combo)

        self.start_secret_edit = QLineEdit(settings)
        self.start_secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.start_secret_edit.setPlaceholderText("shared with the receiver separately")
        form.addRow("Start secret:", self.start_secret_edit)

        self.start_location_spin = QSpinBox(settings)
        self.start_location_spin.setRange(0, 2_000_000_000)
        self.start_location_spin.setValue(0)
        self.start_location_spin.valueChanged.connect(self._update_readout)
        form.addRow("Start location:", self.start_location_spin)

        self.encrypt_check = QCheckBox("Encrypt the message (AES-256-GCM)", settings)
        self.encrypt_check.toggled.connect(self._refresh_encryption_controls)
        form.addRow("", self.encrypt_check)

        self.passphrase_edit = QLineEdit(settings)
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_edit.setPlaceholderText("shared with the receiver separately")
        form.addRow("Passphrase:", self.passphrase_edit)

        self.ecc_check = QCheckBox(
            f"Apply repetition coding (factor "
            f"{constants.ECC_REPETITION_DEFAULT_FACTOR})",
            settings,
        )
        self.ecc_check.setToolTip(
            f"Repeats the payload {constants.ECC_REPETITION_DEFAULT_FACTOR} times and "
            f"recovers it by majority vote, so scattered bit damage can be repaired. "
            f"It multiplies the payload size by "
            f"{constants.ECC_REPETITION_DEFAULT_FACTOR}, and it does not help against "
            f"changes that touch every sample, such as amplitude scaling or lossy "
            f"recompression."
        )
        self.ecc_check.toggled.connect(self._update_readout)
        form.addRow("", self.ecc_check)

        self.match_size_check = QCheckBox(
            "Match the cover's file size where possible", settings
        )
        self.match_size_check.setToolTip(
            "PNG only. Re-encodes at every DEFLATE level looking for one that is "
            "exactly the cover's length, and closes any remaining shortfall with an "
            "ancillary PNG chunk. It cannot always succeed: a stego PNG is usually "
            "larger than its cover, and bytes cannot be removed without changing the "
            "pixels. WAV and BMP already preserve the size; video is re-encoded, so "
            "the question does not apply. A padding chunk is also unusual in an "
            "otherwise plain PNG, which may make the file more conspicuous than a "
            "size mismatch would."
        )
        form.addRow("", self.match_size_check)

        layout.addWidget(settings)

        message_box = QGroupBox("Message", container)
        message_layout = QVBoxLayout(message_box)
        self.message_edit = QPlainTextEdit(message_box)
        self.message_edit.setPlaceholderText("Type the message to protect...")
        self.message_edit.textChanged.connect(self._update_readout)
        message_layout.addWidget(self.message_edit)

        message_buttons = QHBoxLayout()
        self.load_message_button = QPushButton("Load from file...", message_box)
        self.load_message_button.clicked.connect(self._load_message_from_file)
        message_buttons.addWidget(self.load_message_button)
        self.message_length_label = QLabel("0 bytes", message_box)
        message_buttons.addWidget(self.message_length_label)
        message_buttons.addStretch(1)
        message_layout.addLayout(message_buttons)
        layout.addWidget(message_box, 1)

        output_box = QGroupBox("Output", container)
        output_form = QFormLayout(output_box)

        output_row = QWidget(output_box)
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        self.output_edit = QLineEdit(output_row)
        self.output_edit.setPlaceholderText("chosen automatically beside the cover")
        output_layout.addWidget(self.output_edit, 1)
        self.output_browse_button = QPushButton("Browse...", output_row)
        self.output_browse_button.clicked.connect(self._choose_output_path)
        output_layout.addWidget(self.output_browse_button)
        output_form.addRow("Stego file:", output_row)

        key_row = QWidget(output_box)
        key_layout = QHBoxLayout(key_row)
        key_layout.setContentsMargins(0, 0, 0, 0)
        self.key_edit = QLineEdit(key_row)
        self.key_edit.setPlaceholderText("private key used to sign")
        self.key_edit.textChanged.connect(self._key_read_timer.start)
        key_layout.addWidget(self.key_edit, 1)
        self.key_browse_button = QPushButton("Browse...", key_row)
        self.key_browse_button.clicked.connect(self._choose_key_path)
        key_layout.addWidget(self.key_browse_button)
        output_form.addRow("Private key:", key_row)

        layout.addWidget(output_box)

        self.protect_button = QPushButton("Protect && Sign", container)
        self.protect_button.setObjectName("protectButton")
        self.protect_button.setMinimumHeight(36)
        self.protect_button.clicked.connect(self.protect)
        layout.addWidget(self.protect_button)

        return container

    def _build_readout(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        self.info_panel = FileInfoPanel(container)
        layout.addWidget(self.info_panel)

        self.quality_panel = FileInfoPanel(container, title="Quality")
        layout.addWidget(self.quality_panel)

        preview_row = QSplitter(Qt.Orientation.Horizontal, container)
        self.cover_preview = MediaPreview(preview_row, title="Cover")
        self.stego_preview = MediaPreview(preview_row, title="Stego")
        preview_row.addWidget(self.cover_preview)
        preview_row.addWidget(self.stego_preview)
        layout.addWidget(preview_row, 1)

        self.secrets_label = QLabel("", container)
        self.secrets_label.setObjectName("fileInfoNotice")
        self.secrets_label.setTextFormat(Qt.TextFormat.PlainText)
        self.secrets_label.setWordWrap(True)
        self.secrets_label.setVisible(False)
        layout.addWidget(self.secrets_label)

        return container

    # -- state ------------------------------------------------------------- #

    @property
    def cover_path(self) -> str | None:
        return self._cover_path

    @property
    def result(self) -> ProtectResult | None:
        return self._result

    @property
    def start_method(self) -> str:
        return self.start_mode_combo.currentData()

    @property
    def lsb_depth(self) -> int:
        return self.depth_slider.value()

    def message_bytes(self) -> bytes:
        return self.message_edit.toPlainText().encode("utf-8")

    def _load_default_key(self) -> None:
        """Pre-fill the demo private key path when it already exists."""
        private_path, _ = key_manager.demo_key_paths()
        if os.path.isfile(private_path):
            self.key_edit.setText(private_path)

    # -- reactions --------------------------------------------------------- #

    def _on_depth_changed(self, value: int) -> None:
        self.depth_label.setText(str(value))
        self._update_readout()

    def _refresh_start_controls(self) -> None:
        manual = self.start_method == constants.START_METHOD_MANUAL
        self.start_location_spin.setEnabled(manual)
        self.start_secret_edit.setEnabled(not manual)
        self._update_readout()

    def _refresh_encryption_controls(self) -> None:
        self.passphrase_edit.setEnabled(self.encrypt_check.isChecked())
        self._update_readout()

    def _read_key_size(self) -> None:
        """Read the selected key's size so the capacity read-out stays exact.

        A 2048-bit key produces a 256-byte signature and a 3072-bit key a 384-byte
        one. Assuming the default would make the predicted payload length wrong by
        128 bytes for anyone using a smaller key, and the read-out is meant to match
        what actually gets embedded.

        Runs once the path has stopped changing for :data:`KEY_READ_DELAY_MS`, or at
        once when the read-out needs the size and a read is still pending.
        """
        self._key_read_timer.stop()
        candidate = self.key_edit.text().strip()
        size = constants.RSA_KEY_SIZE_DEFAULT // 8

        if candidate and os.path.isfile(candidate):
            try:
                key = key_manager.load_private_key(candidate)
            except Exception:
                pass
            else:
                size = (key.key_size + 7) // 8

        if size != self._signature_size:
            self._signature_size = size
            self._update_readout()

    def _on_cover_selected(self, path: str) -> None:
        self._cover_path = path
        self._result = None
        self.stego_preview.clear()
        self.quality_panel.clear()
        self.secrets_label.setVisible(False)

        try:
            self._cover_media_type = media.detect_media_type(path)
        except StegoError:
            # The read-out below reports the same problem properly; the record
            # estimate just needs *some* media type, and all three names happen to
            # be the same length so the prediction is unaffected either way.
            self._cover_media_type = constants.MEDIA_IMAGE

        self.cover_preview.show_file(path)

        if not self.media_id_edit.text().strip():
            stem = os.path.splitext(file_utils.display_name(path))[0]
            self.media_id_edit.setText(stem.upper()[:32] or "MEDIA-001")

        # Video is always written as FFV1 in Matroska whatever the cover was, so the
        # suggested name has to change extension or it would be misleading.
        forced_extension = (
            constants.CONTAINER_EXTENSIONS[constants.CONTAINER_MKV]
            if self._cover_media_type == constants.MEDIA_VIDEO
            else None
        )
        self.output_edit.setText(
            file_utils.unique_path(
                file_utils.suggest_output_path(path, extension=forced_extension)
            )
        )
        self._update_readout()

    # -- the live capacity read-out ---------------------------------------- #

    def _representative_record(self) -> VerificationRecord:
        """A record with the values in hand, for measuring the payload length.

        Every field that varies in width is either fixed-length or already known, so
        this measures to the byte rather than estimating.
        """
        encryption = None
        if self.encrypt_check.isChecked():
            from app.crypto import encryption as encryption_module

            encryption = encryption_module.new_parameters(salt=b"\x00" * 16)

        return VerificationRecord(
            media_id=self.media_id_edit.text().strip() or "MEDIA-001",
            media_type=self._cover_media_type,
            timestamp=envelope_module.utc_timestamp(),
            nonce_hex="0" * (constants.RECORD_NONCE_BYTES * 2),
            message_hash="0" * 64,
            message_length=len(self.message_bytes()),
            lsb_depth=self.lsb_depth,
            start_method=self.start_method,
            start_location=(
                self.start_location_spin.value()
                if self.start_method == constants.START_METHOD_MANUAL
                else None
            ),
            encryption=encryption,
            ecc=self._ecc_parameters(),
        )

    def _ecc_parameters(self) -> ErrorCorrectionParameters | None:
        if not self.ecc_check.isChecked():
            return None
        return ErrorCorrectionParameters(
            constants.ECC_REPETITION, constants.ECC_REPETITION_DEFAULT_FACTOR
        )

    def _estimated_envelope_length(self) -> int:
        """The envelope's own length, before any error-correcting code."""
        if self._key_read_timer.isActive():
            self._read_key_size()
        from app.crypto.encryption import OVERHEAD_BYTES

        message_length = len(self.message_bytes())
        stored = message_length + (
            OVERHEAD_BYTES if self.encrypt_check.isChecked() else 0
        )
        return envelope_module.envelope_length_for(
            len(self._representative_record().to_bytes()),
            stored,
            self._signature_size,
        )

    def _estimated_embedded_length(self) -> int:
        """The number of bytes that will actually be written into the cover.

        Larger than the envelope when a code is applied, and it is this figure that
        capacity has to be measured against.
        """
        return error_correction.encoded_length(
            self._estimated_envelope_length(), self._ecc_parameters()
        )

    def _update_readout(self) -> None:
        message_length = len(self.message_bytes())
        self.message_length_label.setText(f"{message_length:,} bytes")

        if self._cover_path is None:
            self.info_panel.clear()
            return

        envelope_length = self._estimated_envelope_length()
        embedded_length = self._estimated_embedded_length()
        ecc = self._ecc_parameters()

        try:
            description = file_utils.describe_file(self._cover_path)
            capacity = media.measure(
                self._cover_path,
                self.lsb_depth,
                payload_length=embedded_length,
            )
        except (StegoError, file_utils.UnsupportedMediaError) as exc:
            self.info_panel.clear()
            self.info_panel.set_notice(str(exc))
            return

        self.info_panel.show_capacity(
            description,
            capacity,
            payload_length=embedded_length,
            lsb_depth=self.lsb_depth,
        )

        overhead = envelope_length - message_length
        coding = ""
        if ecc is not None:
            coding = (
                f" That is multiplied to {embedded_length:,} bytes by {ecc.scheme} "
                f"coding at factor {ecc.factor}, which is the cost of being able to "
                f"repair damage."
            )

        if capacity.report.payload_fits:
            self.info_panel.set_notice(
                f"The signed payload is {envelope_length:,} bytes: the "
                f"{message_length:,}-byte message plus {overhead:,} bytes of record "
                f"and signature.{coding}"
            )
        else:
            largest = max(
                0,
                error_correction.largest_raw_payload(
                    capacity.report.max_payload_length, ecc
                )
                - overhead,
            )
            self.info_panel.set_notice(
                f"The message does not fit at depth {self.lsb_depth}. The largest "
                f"message that fits is about {largest:,} bytes. A greater depth, a "
                f"larger cover, or turning off error correction would raise that."
            )

        if self.start_method == constants.START_METHOD_MANUAL:
            self.start_location_spin.setMaximum(
                max(0, capacity.report.total_embeddable_samples - 1)
            )

    # -- file pickers ------------------------------------------------------ #

    def _load_message_from_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load a message", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            QMessageBox.warning(self, "Load message", str(exc))
            return

        try:
            self.message_edit.setPlainText(data.decode("utf-8"))
        except UnicodeDecodeError:
            QMessageBox.warning(
                self,
                "Load message",
                f"{file_utils.display_name(path)} is not UTF-8 text. The message box "
                f"holds text; a binary payload is not supported through this control.",
            )

    def _choose_output_path(self) -> None:
        suggested = self.output_edit.text() or ""
        path, _ = QFileDialog.getSaveFileName(
            self, "Save the stego file as", suggested, "All files (*)"
        )
        if path:
            self.output_edit.setText(path)

    def _choose_key_path(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the private key", "", "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.key_edit.setText(path)

    # -- the operation ----------------------------------------------------- #

    def validation_error(self) -> str | None:
        """Return why the current settings cannot be used, or ``None`` if they can.

        Separated from :meth:`protect` so the tests can check the rules without
        going through a button press or a message box.
        """
        if self._cover_path is None:
            return "Select a cover object first."
        if not self.media_id_edit.text().strip():
            return "Enter a media ID. It identifies this file in the signed record."
        if not self.output_edit.text().strip():
            return "Choose where to write the stego file."
        if not self.key_edit.text().strip():
            return (
                "Select a private key to sign with, or generate the demo key pair "
                "from the Keys menu."
            )
        if self.start_method == constants.START_METHOD_HMAC and not (
            self.start_secret_edit.text()
        ):
            return (
                "Enter a start secret, or switch to a manually chosen start location."
            )
        if self.encrypt_check.isChecked() and not self.passphrase_edit.text():
            return "Enter a passphrase, or turn encryption off."
        return None

    def protect(self) -> None:
        """Validate, then run the protect workflow off the interface thread."""
        problem = self.validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Protect", problem)
            return

        self.protect_button.setEnabled(False)
        self.statusMessage.emit("Protecting...")

        self._runner.submit(
            self._run_protect,
            self._collect_inputs(),
            on_success=self._on_protected,
            on_error=self._on_protect_failed,
            on_finished=lambda: self.protect_button.setEnabled(True),
        )

    def _collect_inputs(self) -> ProtectInputs:
        """Read the form. Interface thread only."""
        manual = self.start_method == constants.START_METHOD_MANUAL
        return ProtectInputs(
            cover_path=self._cover_path,
            output_path=self.output_edit.text().strip(),
            key_path=self.key_edit.text().strip(),
            message=self.message_bytes(),
            media_id=self.media_id_edit.text().strip(),
            lsb_depth=self.lsb_depth,
            start_method=self.start_method,
            start_secret=None if manual else self.start_secret_edit.text(),
            manual_start_location=self.start_location_spin.value() if manual else None,
            passphrase=(
                self.passphrase_edit.text() if self.encrypt_check.isChecked() else None
            ),
            ecc=self._ecc_parameters(),
            match_cover_size=self.match_size_check.isChecked(),
        )

    @staticmethod
    def _run_protect(inputs: ProtectInputs) -> ProtectResult:
        """The backend call. Runs on a worker thread and reads only *inputs*."""
        return protect_media(
            inputs.cover_path,
            inputs.output_path,
            inputs.message,
            key_manager.load_private_key(inputs.key_path),
            media_id=inputs.media_id,
            lsb_depth=inputs.lsb_depth,
            start_method=inputs.start_method,
            start_secret=inputs.start_secret,
            manual_start_location=inputs.manual_start_location,
            passphrase=inputs.passphrase,
            ecc=inputs.ecc,
            match_cover_size=inputs.match_cover_size,
        )

    def _on_protected(self, result: ProtectResult) -> None:
        self._result = result
        self.stego_preview.show_file(result.stego_path)
        self._show_quality(result)

        if result.required_secrets:
            self.secrets_label.setText(
                "Send the stego file and its manifest together. The receiver also "
                "needs, shared separately: "
                + ", ".join(result.required_secrets)
                + "."
            )
        else:
            self.secrets_label.setText(
                "Send the stego file and its manifest together. No secret is needed "
                "for a manually chosen start location."
            )
        self.secrets_label.setVisible(True)

        message = (
            f"Protected as {file_utils.display_name(result.stego_path)} "
            f"({result.envelope_length:,}-byte payload at depth "
            f"{result.record.lsb_depth}, start location {result.start_location:,})."
        )
        self.statusMessage.emit(message)
        _log.info("%s", message)
        self.mediaProtected.emit(result)

    def _show_quality(self, result: ProtectResult) -> None:
        """Report the distortion the chosen depth produced."""
        try:
            report = quality_metrics.compare_quality(
                self._cover_path, result.stego_path, lsb_depth=result.record.lsb_depth
            )
        except Exception as exc:
            self.quality_panel.clear()
            self.quality_panel.set_notice(f"Quality metrics unavailable: {exc}")
            return

        original_size = os.path.getsize(self._cover_path)
        stego_size = os.path.getsize(result.stego_path)

        rows: list[tuple[str, object]] = [
            ("Original size", f"{file_utils.human_size(original_size)} ({original_size:,} B)"),
            ("Stego size", f"{file_utils.human_size(stego_size)} ({stego_size:,} B)"),
            ("MSE", f"{report.mse:.6f}"),
            (
                "PSNR",
                "infinite (identical)"
                if report.psnr_unbounded
                else f"{report.psnr_db:.2f} dB",
            ),
        ]
        if report.snr_db is not None:
            rows.append(("SNR", f"{report.snr_db:.2f} dB"))
        rows += [
            ("Largest sample change", f"{report.max_absolute_difference:.0f}"),
            (
                "Samples changed",
                f"{report.changed_samples:,} of {report.total_samples:,} "
                f"({report.changed_proportion * 100:.3f}%)",
            ),
        ]
        if report.expected_distortion_bound is not None:
            rows.append(
                (
                    "Within the depth bound",
                    f"{'yes' if report.within_distortion_bound else 'no'} "
                    f"(at most {report.expected_distortion_bound})",
                )
            )

        if result.size_preservation is not None:
            outcome = result.size_preservation
            rows.append(
                (
                    "Size matched",
                    "not applicable"
                    if not outcome.applicable
                    else ("yes" if outcome.exact else "no"),
                )
            )
            rows.append(("Size strategy", outcome.strategy))

        self.quality_panel.set_rows(rows)

        if result.size_preservation is not None and result.size_preservation.notes:
            # The outcome varies per file, so the reason is shown rather than left for
            # the user to infer from two numbers.
            self.quality_panel.set_notice(result.size_preservation.notes[0])
            return

        if report.media_type == constants.MEDIA_VIDEO:
            # Video is always fully re-encoded, so a size comparison says nothing
            # about the embedding and should not be read as if it did.
            worst = report.extra.get("worst_frame_psnr_db")
            frames_changed = report.extra.get("frames_changed")
            self.quality_panel.set_notice(
                f"The payload touched {frames_changed} of "
                f"{report.extra.get('frame_count')} frames"
                + (f", worst-frame PSNR {worst:.2f} dB" if worst else "")
                + ". The clip was re-encoded losslessly as FFV1, so the file size "
                  "difference reflects the codec change, not the embedding."
            )
        elif original_size != stego_size:
            self.quality_panel.set_notice(
                "The file size changed. PNG is compressed, so altering low-order bits "
                "changes how well the data deflates. WAV and BMP normally preserve size."
            )

    def _on_protect_failed(self, message: str, detail: str) -> None:
        self.statusMessage.emit(message)
        _log.error("protect failed: %s", message)
        QMessageBox.warning(self, "Protect", message)
