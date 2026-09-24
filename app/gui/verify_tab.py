"""The Verify tab: recover a message from a stego object and report a verdict.

The receiver side is one call to
:func:`app.verification.verifier.verify_media`. This tab collects its inputs, runs it
off the interface thread, and hands the result to
:class:`app.gui.widgets.result_panel.ResultPanel`.

A verdict is not an error
-------------------------
``verify_media`` returns a result for every outcome a receiver can meet, including a
missing payload and a bad signature, and raises only when something unrelated to the
file goes wrong — an unreadable public key, for instance. So the success callback
here handles all six verdicts and the failure callback is genuinely exceptional. That
is why a ``TAMPERED`` result appears in the panel rather than in a warning dialog:
detecting tampering is the application working, not failing.

Finding the manifest
--------------------
The manifest is picked up automatically from the conventional
``<stego file>.manifest.json`` beside the file, because that is where the Protect tab
writes it and it is what a receiver will normally have. It can still be chosen
explicitly, for the case where the two arrived separately or were renamed.

Previewing a recovered file
---------------------------
When the recovered bytes are an image or an audio file, they are written to a
private temporary directory and shown in a :class:`MediaPreview`, the same widget
that shows cover objects. The type is decided by sniffing the bytes, not by the
sender's type hint, and the copy is only ever rendered or played inside this
process. It is deleted when the next file or result replaces it.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import weakref
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.crypto import key_manager
from app.crypto import manifest as manifest_module
from app.gui.widgets.drop_zone import DropZone
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.widgets.media_preview import MediaPreview
from app.gui.widgets.result_panel import ResultPanel
from app.gui.workers import BackgroundRunner
from app.utils import constants, file_utils, payload_files
from app.utils.logging_utils import get_logger
from app.verification import media_compare
from app.verification.verdicts import VerificationResult
from app.verification.verifier import verify_media

__all__ = ["VerifyTab"]

_log = get_logger(__name__)


@dataclass(frozen=True)
class VerifyInputs:
    """A snapshot of the form, taken on the interface thread before work starts."""

    stego_path: str
    manifest_path: str
    key_path: str
    start_secret: str | None
    passphrase: str | None


class VerifyTab(QWidget):
    """Collects the receiver's inputs and reports a verdict."""

    TITLE = "Verify"

    statusMessage = Signal(str)
    #: Emitted with the result after each verification.
    mediaVerified = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("verifyTab")

        self._runner = BackgroundRunner()
        self._generation = 0
        self._stego_path: str | None = None
        self._original_path: str | None = None
        self._result: VerificationResult | None = None
        # Removes the temporary copy of a recovered file that is being previewed.
        # A finalizer, so the copy is also removed if the tab is simply discarded
        # or the application exits.
        self._payload_cleanup: weakref.finalize | None = None

        outer = QVBoxLayout(self)

        self.drop_zone = DropZone(
            self, prompt="Drag the received stego file here"
        )
        self.drop_zone.fileSelected.connect(self._on_stego_selected)
        self.drop_zone.selectionCleared.connect(self._clear_selection)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        outer.addWidget(self.drop_zone)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._build_inputs())
        splitter.addWidget(self._build_output())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        outer.addWidget(splitter, 1)

        self.fingerprint_label = QLabel("Select the trusted public key to see its fingerprint.", self)
        self.fingerprint_label.setWordWrap(True)
        self.fingerprint_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self.fingerprint_label)
        self._fingerprint_timer = QTimer(self)
        self._fingerprint_timer.setSingleShot(True)
        self._fingerprint_timer.setInterval(250)
        self._fingerprint_timer.timeout.connect(self._show_fingerprint)
        for field in (self.key_edit, self.manifest_edit, self.start_secret_edit, self.passphrase_edit):
            field.textChanged.connect(self._invalidate_result)
        self.key_edit.textChanged.connect(lambda: self._fingerprint_timer.start())
        self._load_default_key()

    def _invalidate_result(self):
        self._generation += 1
        self._result = None
        self.result_panel.clear()
        self._clear_payload_preview()
        self.comparison_view.clear()

    def _clear_selection(self):
        self._stego_path = None
        self._invalidate_result()
        self.preview.clear()
        self.manifest_edit.clear()
        self.manifest_panel.clear()

    def _show_fingerprint(self):
        try:
            key = key_manager.load_public_key(self.key_edit.text().strip())
            value = key_manager.public_key_fingerprint(key)
        except Exception:
            self.fingerprint_label.setText("Select a valid trusted public key.")
        else:
            self.fingerprint_label.setText(
                f"Public key SHA-256: {value}\nCompare through an independently trusted channel."
            )

    def shutdown(self):
        self._generation += 1
        self._fingerprint_timer.stop()
        self._runner.wait()
        self._clear_payload_preview()
        self.preview.clear()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)

    # -- construction ------------------------------------------------------ #

    def _build_inputs(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        inputs = QGroupBox("Receiver Inputs", container)
        form = QFormLayout(inputs)

        manifest_row = QWidget(inputs)
        manifest_layout = QHBoxLayout(manifest_row)
        manifest_layout.setContentsMargins(0, 0, 0, 0)
        self.manifest_edit = QLineEdit(manifest_row)
        self.manifest_edit.setPlaceholderText("found automatically beside the file")
        manifest_layout.addWidget(self.manifest_edit, 1)
        self.manifest_browse_button = QPushButton("Browse...", manifest_row)
        self.manifest_browse_button.clicked.connect(self._choose_manifest)
        manifest_layout.addWidget(self.manifest_browse_button)
        form.addRow("Manifest:", manifest_row)

        key_row = QWidget(inputs)
        key_layout = QHBoxLayout(key_row)
        key_layout.setContentsMargins(0, 0, 0, 0)
        self.key_edit = QLineEdit(key_row)
        self.key_edit.setPlaceholderText("the sender's public key")
        key_layout.addWidget(self.key_edit, 1)
        self.key_browse_button = QPushButton("Browse...", key_row)
        self.key_browse_button.clicked.connect(self._choose_key)
        key_layout.addWidget(self.key_browse_button)
        form.addRow("Public key:", key_row)

        self.start_secret_edit = QLineEdit(inputs)
        self.start_secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.start_secret_edit.setPlaceholderText("only for a derived start location")
        form.addRow("Start secret:", self.start_secret_edit)

        self.passphrase_edit = QLineEdit(inputs)
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_edit.setPlaceholderText("only for an encrypted message")
        form.addRow("Passphrase:", self.passphrase_edit)

        original_row = QWidget(inputs)
        original_layout = QHBoxLayout(original_row)
        original_layout.setContentsMargins(0, 0, 0, 0)
        self.original_edit = QLineEdit(original_row)
        self.original_edit.setPlaceholderText("optional, enables the comparison table")
        original_layout.addWidget(self.original_edit, 1)
        self.original_browse_button = QPushButton("Browse...", original_row)
        self.original_browse_button.clicked.connect(self._choose_original)
        original_layout.addWidget(self.original_browse_button)
        form.addRow("Original cover:", original_row)

        layout.addWidget(inputs)

        self.manifest_panel = FileInfoPanel(container, title="Manifest (unverified)")
        layout.addWidget(self.manifest_panel)

        self.verify_button = QPushButton("Verify", container)
        self.verify_button.setObjectName("verifyButton")
        self.verify_button.setMinimumHeight(36)
        self.verify_button.clicked.connect(self.verify)
        layout.addWidget(self.verify_button)

        self.preview = MediaPreview(container, title="Received file")
        layout.addWidget(self.preview, 1)

        return container

    def _build_output(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        self.result_panel = ResultPanel(container, title="Verification Result")
        layout.addWidget(self.result_panel, 3)

        self.payload_preview_box = QGroupBox("Recovered file preview", container)
        payload_preview_layout = QVBoxLayout(self.payload_preview_box)
        self.payload_preview = MediaPreview(self.payload_preview_box)
        payload_preview_layout.addWidget(self.payload_preview)
        self.payload_preview_box.setVisible(False)
        layout.addWidget(self.payload_preview_box, 2)

        comparison_box = QGroupBox("Comparison with the original", container)
        comparison_layout = QVBoxLayout(comparison_box)
        self.comparison_view = QPlainTextEdit(comparison_box)
        self.comparison_view.setObjectName("payloadView")
        self.comparison_view.setReadOnly(True)
        self.comparison_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.comparison_view.setPlaceholderText(
            "Select the original cover object to compare properties and distortion."
        )
        comparison_layout.addWidget(self.comparison_view)
        layout.addWidget(comparison_box, 2)

        return container

    # -- state ------------------------------------------------------------- #

    @property
    def stego_path(self) -> str | None:
        return self._stego_path

    @property
    def result(self) -> VerificationResult | None:
        return self._result

    @property
    def payload_preview_path(self) -> str | None:
        """The temporary copy being previewed, if any."""
        return None if self._payload_cleanup is None else self.payload_preview.path

    def _load_default_key(self) -> None:
        _, public_path = key_manager.demo_key_paths()
        if os.path.isfile(public_path):
            self.key_edit.setText(public_path)

    def use_demo_keys(self, private_path: str, public_path: str) -> None:
        """Fill in a newly generated demo public key, unless a real key is already set.

        A field holding something that is not a file, such as a name typed by
        mistake or a key that has since been deleted, is replaced too.
        """
        if not os.path.isfile(self.key_edit.text().strip()):
            self.key_edit.setText(public_path)

    # -- reactions --------------------------------------------------------- #

    def _on_stego_selected(self, path: str) -> None:
        self._invalidate_result()
        self._stego_path = path
        self._result = None
        self.result_panel.clear()
        self._clear_payload_preview()
        self.comparison_view.setPlainText("")
        self.preview.show_file(path)

        conventional = file_utils.manifest_path_for(path)
        if os.path.isfile(conventional):
            self.manifest_edit.setText(conventional)
            self.statusMessage.emit(
                f"Found the companion manifest beside "
                f"{file_utils.display_name(path)}."
            )
        else:
            self.manifest_edit.setText("")
            self.statusMessage.emit(
                f"No manifest found beside {file_utils.display_name(path)}. Select it "
                f"with Browse; it is required to locate the payload."
            )

        self._show_manifest_summary()

    def _show_manifest_summary(self) -> None:
        """Display the manifest's claims, labelled as not yet verified.

        Worth showing before verification because it is what the receiver has to work
        from, and worth labelling because at this point nothing about it is
        authenticated.
        """
        path = self.manifest_edit.text().strip()
        if not path or not os.path.isfile(path):
            self.manifest_panel.clear()
            return

        try:
            manifest = manifest_module.read_manifest(path)
        except Exception as exc:
            self.manifest_panel.clear()
            self.manifest_panel.set_notice(str(exc))
            return

        self.manifest_panel.set_rows(
            [
                ("Media ID", manifest.media_id),
                ("Media type", manifest.media_type),
                ("Container", manifest.container_format),
                ("LSB depth", manifest.lsb_depth),
                ("Start method", manifest.start_method),
                (
                    "Start location",
                    "derived from the secret"
                    if manifest.start_location is None
                    else f"{manifest.start_location:,}",
                ),
                ("Payload length", f"{manifest.envelope_length:,} B"),
                ("Message length", f"{manifest.message_length:,} B"),
                ("Encrypted", "yes" if manifest.encrypted else "no"),
            ]
        )
        self.manifest_panel.set_notice(
            "These values are the manifest's claims. Nothing here is authenticated "
            "until the signature over the verification record has been checked."
        )

        # Prompt for exactly the secrets this file needs, and no others.
        needs_secret = manifest.start_method == constants.START_METHOD_HMAC
        self.start_secret_edit.setEnabled(needs_secret)
        self.passphrase_edit.setEnabled(manifest.encrypted)

    # -- file pickers ------------------------------------------------------ #

    def _choose_manifest(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the companion manifest", "", "JSON files (*.json);;All files (*)"
        )
        if path:
            self.manifest_edit.setText(path)
            self._show_manifest_summary()

    def _choose_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the sender's public key", "", "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.key_edit.setText(path)

    def _choose_original(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the original cover object", "", "All files (*)"
        )
        if path:
            self.original_edit.setText(path)

    # -- the operation ----------------------------------------------------- #

    def validation_error(self) -> str | None:
        """Return why verification cannot be attempted, or ``None`` if it can."""
        if self._stego_path is None:
            return "Select the received stego file first."
        if not self.key_edit.text().strip():
            return (
                "Select the sender's public key. Verification cannot proceed without "
                "it."
            )
        manifest_path = self.manifest_edit.text().strip()
        if not manifest_path:
            return (
                "Select the companion manifest. It carries the parameters needed to "
                "locate the payload and is sent alongside the stego file."
            )
        if not os.path.isfile(manifest_path):
            return f"{file_utils.display_name(manifest_path)} does not exist."
        return None

    def verify(self) -> None:
        """Validate, then run verification off the interface thread."""
        problem = self.validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Verify", problem)
            return

        self.verify_button.setEnabled(False)
        self.statusMessage.emit("Verifying...")

        self._runner.submit(
            self._run_verify,
            self._collect_inputs(),
            on_success=lambda result, generation=self._generation: self._on_verified(result)
            if generation == self._generation else None,
            on_error=lambda message, detail, generation=self._generation: self._on_verify_failed(message, detail)
            if generation == self._generation else None,
            on_finished=lambda: self.verify_button.setEnabled(True),
        )

    def _collect_inputs(self) -> VerifyInputs:
        """Read the form. Interface thread only."""
        assert self._stego_path is not None
        return VerifyInputs(
            stego_path=self._stego_path,
            manifest_path=self.manifest_edit.text().strip(),
            key_path=self.key_edit.text().strip(),
            start_secret=self.start_secret_edit.text() or None,
            passphrase=self.passphrase_edit.text() or None,
        )

    @staticmethod
    def _run_verify(inputs: VerifyInputs) -> VerificationResult:
        """The backend call. Runs on a worker thread and reads only *inputs*."""
        return verify_media(
            inputs.stego_path,
            inputs.manifest_path,
            inputs.key_path,
            start_secret=inputs.start_secret,
            passphrase=inputs.passphrase,
        )

    def _on_verified(self, result: VerificationResult) -> None:
        """Every one of the six verdicts arrives here; none is an error."""
        self._result = result
        self.result_panel.show_result(result)
        self._show_payload_preview(result.message if result.verdict == constants.VERDICT_AUTHENTIC else None)
        self._show_comparison(result)

        self.statusMessage.emit(f"{result.verdict}: {result.reason}")
        _log.info(
            "verified %s: %s",
            file_utils.display_name(self._stego_path or ""),
            result.verdict,
        )
        self.mediaVerified.emit(result)

    def _clear_payload_preview(self) -> None:
        self.payload_preview.clear()
        self.payload_preview_box.setVisible(False)
        if self._payload_cleanup is not None:
            self._payload_cleanup()
            self._payload_cleanup = None

    def _show_payload_preview(self, message: bytes | None) -> None:
        """Preview a recovered image or audio file; anything else is text or hex."""
        self._clear_payload_preview()
        if message is None:
            return
        detected = payload_files.detect_payload_type(message)
        if not detected.previewable:
            return

        directory = tempfile.mkdtemp(prefix="stego-payload-")
        # ignore_errors: on Windows the media backend can hold the file a moment
        # after it is released, and a stale temporary file is harmless.
        self._payload_cleanup = weakref.finalize(self, shutil.rmtree, directory, True)
        # A fixed name with the sniffed extension: the sender's recorded name is
        # never used as a path.
        path = os.path.join(directory, "recovered_payload" + detected.extension)
        with open(path, "wb") as handle:
            handle.write(message)

        self.payload_preview_box.setVisible(True)
        self.payload_preview.show_file(
            path,
            media_type=detected.kind,
            caption=f"Recovered {detected.label}, {len(message):,} bytes",
        )

    def _show_comparison(self, result: VerificationResult) -> None:
        original = self.original_edit.text().strip()
        if not original or not os.path.isfile(original):
            self.comparison_view.setPlainText("")
            return

        depth = None if result.record is None else result.record.lsb_depth
        try:
            comparison = media_compare.compare(
                original, self._stego_path, lsb_depth=depth
            )
        except Exception as exc:
            self.comparison_view.setPlainText(f"Comparison unavailable: {exc}")
            return

        lines = [comparison.as_text(), ""]
        if comparison.structure_identical:
            lines.append(
                "Every property that should be unchanged is unchanged."
            )
        else:
            differing = ", ".join(
                row.label for row in comparison.differing_rows if row.structural
            )
            lines.append(f"Properties that differ unexpectedly: {differing}")

        if comparison.quality is not None:
            quality = comparison.quality
            lines += [
                "",
                f"MSE: {quality.mse:.6f}",
                "PSNR: "
                + (
                    "infinite (identical)"
                    if quality.psnr_unbounded
                    else f"{quality.psnr_db:.2f} dB"
                ),
            ]
            if quality.snr_db is not None:
                lines.append(f"SNR: {quality.snr_db:.2f} dB")
            lines.append(
                f"Samples changed: {quality.changed_samples:,} of "
                f"{quality.total_samples:,}"
            )

        lines += ["", *comparison.notes]
        self.comparison_view.setPlainText("\n".join(lines))

    def _on_verify_failed(self, message: str, detail: str) -> None:
        """Only genuinely exceptional failures reach here, such as an unusable key."""
        self.result_panel.show_error(message)
        self._clear_payload_preview()
        self.statusMessage.emit(message)
        _log.error("verification could not run: %s", message)
        QMessageBox.warning(self, "Verify", message)
