"""The Attack Lab tab: break a protected file and watch the verdict change.

This is where the negative cases get demonstrated. It loads a protected file, lists
the attacks that apply to it, applies the one chosen, and shows the verdict before
and after side by side.

Why the expected verdict is shown too
-------------------------------------
Each attack declares which verdicts are acceptable outcomes, and the tab displays
that alongside what actually happened. For most attacks the expected set has one
member and the pairing is a straightforward pass. For a few it has several, because
the outcome genuinely depends on where the damage lands, and showing the set makes
that honest rather than looking like vagueness.

One attack is expected to leave the verdict at ``AUTHENTIC``: modifying the cover
*outside* the payload region. That is not a failed attack, it is the scope of what
verification establishes, and the tab reports it as a match rather than hiding it.

Run all
-------
The "Run every applicable attack" button produces the whole table in one go, which is
what the demonstration and the evidence folder want. Attacks that cannot run on the
loaded file — modifying outside the payload when the payload fills the medium, for
instance — are reported as skipped with the reason, not silently dropped.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from app.attacks import registry
from app.attacks.base import Attack, AttackContext, AttackError
from app.attacks.registry import AttackRun
from app.crypto import key_manager, manifest as manifest_module
from app.gui.widgets.drop_zone import DropZone
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.workers import BackgroundRunner
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = ["AttackTab"]

_log = get_logger(__name__)

#: Manifest fields offered for the manifest-tampering attack. Two are start-location
#: derivation inputs and two are not, so both detection routes can be demonstrated.
_MANIFEST_FIELDS: tuple[tuple[str, str], ...] = (
    ("message_length", "message_length (caught by the cross-check)"),
    ("lsb_depth", "lsb_depth (breaks extraction)"),
    ("media_id", "media_id (breaks extraction)"),
    ("encrypted", "encrypted (caught by the cross-check)"),
)


@dataclass(frozen=True)
class AttackInputs:
    """A snapshot of the form, taken on the interface thread before work starts.

    The worker thread reads only this, never the widgets.
    """

    stego_path: str
    media_type: str | None
    manifest_path: str
    key_path: str
    start_secret: str | None
    passphrase: str | None
    bit_error_rate: float
    manifest_field: object


class AttackTab(QWidget):
    """Applies an attack to a protected file and re-verifies it."""

    TITLE = "Attack Lab"

    statusMessage = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("attackTab")

        self._runner = BackgroundRunner()
        self._stego_path: str | None = None
        self._media_type: str | None = None
        self._runs: list[AttackRun] = []

        outer = QVBoxLayout(self)

        self.drop_zone = DropZone(self, prompt="Drag a protected stego file here")
        self.drop_zone.fileSelected.connect(self._on_stego_selected)
        self.drop_zone.selectionRejected.connect(self.statusMessage.emit)
        outer.addWidget(self.drop_zone)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.addWidget(self._build_controls())
        splitter.addWidget(self._build_output())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        outer.addWidget(splitter, 1)

        self._load_default_key()
        self._refresh_attack_list()

    # -- construction ------------------------------------------------------ #

    def _build_controls(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        inputs = QGroupBox("Verification Inputs", container)
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

        layout.addWidget(inputs)

        attacks_box = QGroupBox("Attacks", container)
        attacks_layout = QVBoxLayout(attacks_box)

        self.attack_list = QListWidget(attacks_box)
        self.attack_list.currentItemChanged.connect(self._on_attack_changed)
        attacks_layout.addWidget(self.attack_list, 1)

        self.attack_summary = QLabel("", attacks_box)
        self.attack_summary.setObjectName("verdictDescription")
        self.attack_summary.setTextFormat(Qt.TextFormat.PlainText)
        self.attack_summary.setWordWrap(True)
        attacks_layout.addWidget(self.attack_summary)

        options_form = QFormLayout()

        self.bit_error_spin = QDoubleSpinBox(attacks_box)
        self.bit_error_spin.setDecimals(4)
        self.bit_error_spin.setRange(0.0001, 1.0)
        self.bit_error_spin.setSingleStep(0.005)
        self.bit_error_spin.setValue(0.01)
        self.bit_error_label = QLabel("Bit error rate:", attacks_box)
        options_form.addRow(self.bit_error_label, self.bit_error_spin)

        self.manifest_field_combo = QComboBox(attacks_box)
        for value, label in _MANIFEST_FIELDS:
            self.manifest_field_combo.addItem(label, value)
        self.manifest_field_label = QLabel("Manifest field:", attacks_box)
        options_form.addRow(self.manifest_field_label, self.manifest_field_combo)

        attacks_layout.addLayout(options_form)
        layout.addWidget(attacks_box, 1)

        buttons = QHBoxLayout()
        self.run_button = QPushButton("Run Attack", container)
        self.run_button.setMinimumHeight(32)
        self.run_button.clicked.connect(self.run_selected_attack)
        buttons.addWidget(self.run_button)

        self.run_all_button = QPushButton("Run every applicable attack", container)
        self.run_all_button.setMinimumHeight(32)
        self.run_all_button.clicked.connect(self.run_all_attacks)
        buttons.addWidget(self.run_all_button)
        layout.addLayout(buttons)

        return container

    def _build_output(self) -> QWidget:
        container = QWidget(self)
        layout = QVBoxLayout(container)

        self.summary_panel = FileInfoPanel(container, title="Latest Attack")
        layout.addWidget(self.summary_panel)

        log_box = QGroupBox("Attack log", container)
        log_layout = QVBoxLayout(log_box)
        self.log_view = QPlainTextEdit(log_box)
        self.log_view.setObjectName("payloadView")
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText(
            "Run an attack to see the verdict before and after."
        )
        log_layout.addWidget(self.log_view)

        log_buttons = QHBoxLayout()
        self.clear_log_button = QPushButton("Clear", log_box)
        self.clear_log_button.clicked.connect(self.clear_log)
        log_buttons.addWidget(self.clear_log_button)
        self.save_log_button = QPushButton("Save as evidence...", log_box)
        self.save_log_button.clicked.connect(self._save_log)
        log_buttons.addWidget(self.save_log_button)
        log_buttons.addStretch(1)
        log_layout.addLayout(log_buttons)

        layout.addWidget(log_box, 1)
        return container

    # -- state ------------------------------------------------------------- #

    @property
    def stego_path(self) -> str | None:
        return self._stego_path

    @property
    def runs(self) -> tuple[AttackRun, ...]:
        return tuple(self._runs)

    def selected_attack(self) -> Attack | None:
        item = self.attack_list.currentItem()
        if item is None:
            return None
        return registry.attack_by_key(item.data(Qt.ItemDataRole.UserRole))

    def _load_default_key(self) -> None:
        _, public_path = key_manager.demo_key_paths()
        if os.path.isfile(public_path):
            self.key_edit.setText(public_path)

    # -- reactions --------------------------------------------------------- #

    def _on_stego_selected(self, path: str) -> None:
        self._stego_path = path
        try:
            self._media_type = file_utils.detect_media_type(path)
        except file_utils.UnsupportedMediaError as exc:
            self._media_type = None
            self.statusMessage.emit(str(exc))

        conventional = file_utils.manifest_path_for(path)
        self.manifest_edit.setText(conventional if os.path.isfile(conventional) else "")

        self._apply_manifest_hints()
        self._refresh_attack_list()

    def _apply_manifest_hints(self) -> None:
        """Enable only the secret fields this file actually needs."""
        path = self.manifest_edit.text().strip()
        if not path or not os.path.isfile(path):
            return
        try:
            manifest = manifest_module.read_manifest(path)
        except Exception:  # noqa: BLE001 - reported when an attack is run
            return

        self.start_secret_edit.setEnabled(
            manifest.start_method == constants.START_METHOD_HMAC
        )
        self.passphrase_edit.setEnabled(manifest.encrypted)

    def _refresh_attack_list(self) -> None:
        self.attack_list.clear()
        if self._media_type is None:
            self.attack_summary.setText("Load a protected file to see its attacks.")
            return

        for attack in registry.available_attacks(self._media_type):
            item = QListWidgetItem(attack.label, self.attack_list)
            item.setData(Qt.ItemDataRole.UserRole, attack.key)
            item.setToolTip(attack.summary)

        if self.attack_list.count():
            self.attack_list.setCurrentRow(0)

    def _on_attack_changed(self) -> None:
        attack = self.selected_attack()
        if attack is None:
            self.attack_summary.setText("")
            self._show_options(None)
            return
        self.attack_summary.setText(attack.summary)
        self._show_options(attack.key)

    def _show_options(self, key: str | None) -> None:
        """Show only the options the selected attack actually uses."""
        wants_rate = key == "payload.random_bits"
        wants_field = key == "manifest.tamper"

        self.bit_error_label.setVisible(wants_rate)
        self.bit_error_spin.setVisible(wants_rate)
        self.manifest_field_label.setVisible(wants_field)
        self.manifest_field_combo.setVisible(wants_field)

    # -- file pickers ------------------------------------------------------ #

    def _choose_manifest(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the companion manifest", "", "JSON files (*.json);;All files (*)"
        )
        if path:
            self.manifest_edit.setText(path)
            self._apply_manifest_hints()

    def _choose_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select the sender's public key", "", "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.key_edit.setText(path)

    # -- running ----------------------------------------------------------- #

    def validation_error(self) -> str | None:
        """Return why an attack cannot be run, or ``None`` if one can."""
        if self._stego_path is None:
            return "Load a protected stego file first."
        manifest_path = self.manifest_edit.text().strip()
        if not manifest_path:
            return (
                "Select the companion manifest. It carries the parameters needed to "
                "locate the payload."
            )
        if not os.path.isfile(manifest_path):
            return f"{file_utils.display_name(manifest_path)} does not exist."
        if not self.key_edit.text().strip():
            return "Select the sender's public key, so the verdict can be checked."
        if self.selected_attack() is None:
            return "Choose an attack from the list."
        return None

    def _collect_inputs(self) -> AttackInputs:
        """Read the form. Interface thread only."""
        assert self._stego_path is not None
        return AttackInputs(
            stego_path=self._stego_path,
            media_type=self._media_type,
            manifest_path=self.manifest_edit.text().strip(),
            key_path=self.key_edit.text().strip(),
            start_secret=self.start_secret_edit.text() or None,
            passphrase=self.passphrase_edit.text() or None,
            bit_error_rate=self.bit_error_spin.value(),
            manifest_field=self.manifest_field_combo.currentData(),
        )

    @staticmethod
    def _options_for(attack: Attack, inputs: AttackInputs) -> dict[str, object]:
        if attack.key == "payload.random_bits":
            return {"bit_error_rate": inputs.bit_error_rate}
        if attack.key == "manifest.tamper":
            return {"field": inputs.manifest_field}
        return {}

    @staticmethod
    def _output_path_for(attack: Attack, inputs: AttackInputs) -> str:
        stem = attack.key.replace(".", "_")

        if attack.target == "manifest":
            base = inputs.manifest_path
            directory = os.path.dirname(os.path.abspath(base))
            return file_utils.unique_path(
                os.path.join(directory, f"attacked_{stem}.manifest.json")
            )

        directory = os.path.dirname(os.path.abspath(inputs.stego_path))
        extension = os.path.splitext(inputs.stego_path)[1]
        return file_utils.unique_path(
            os.path.join(directory, f"attacked_{stem}{extension}")
        )

    def _build_context(self, attack: Attack, inputs: AttackInputs) -> AttackContext:
        return registry.context_from_manifest(
            inputs.stego_path,
            inputs.manifest_path,
            self._output_path_for(attack, inputs),
            start_secret=inputs.start_secret,
            attacker_private_key=self._attacker_key_if_needed(attack),
            **self._options_for(attack, inputs),
        )

    @staticmethod
    def _attacker_key_if_needed(attack: Attack):
        """Generate a key the attacker controls, for the re-signing attack.

        An attacker with a signing key of their own is exactly the scenario that
        attack models, so the key is generated here rather than asked for. It is
        deliberately *not* the sender's key, which is the point: the result shows the
        substitution failing against a receiver who holds the genuine public key.
        """
        if attack.key != "payload.resign":
            return None
        private_key, _ = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
        return private_key

    def run_selected_attack(self) -> None:
        problem = self.validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Attack Lab", problem)
            return

        attack = self.selected_attack()
        assert attack is not None

        self._set_running(True)
        self.statusMessage.emit(f"Running: {attack.label}...")

        self._runner.submit(
            self._run_one,
            attack,
            self._collect_inputs(),
            on_success=self._on_attack_finished,
            on_error=self._on_attack_failed,
            on_finished=lambda: self._set_running(False),
        )

    def _run_one(self, attack: Attack, inputs: AttackInputs) -> AttackRun:
        """The backend call. Runs on a worker thread and reads only *inputs*."""
        return registry.run_attack(
            attack.key,
            self._build_context(attack, inputs),
            inputs.key_path,
            start_secret=inputs.start_secret,
            passphrase=inputs.passphrase,
        )

    def run_all_attacks(self) -> None:
        """Run every attack that applies, reporting any that cannot run."""
        problem = self.validation_error()
        if problem is not None:
            self.statusMessage.emit(problem)
            QMessageBox.warning(self, "Attack Lab", problem)
            return

        self._set_running(True)
        self.statusMessage.emit("Running every applicable attack...")

        self._runner.submit(
            self._run_every,
            self._collect_inputs(),
            on_success=self._on_all_finished,
            on_error=self._on_attack_failed,
            on_finished=lambda: self._set_running(False),
        )

    def _run_every(
        self, inputs: AttackInputs
    ) -> tuple[list[AttackRun], list[tuple[str, str]]]:
        """Runs on a worker thread and reads only *inputs*."""
        assert inputs.media_type is not None
        completed: list[AttackRun] = []
        skipped: list[tuple[str, str]] = []

        for attack in registry.available_attacks(inputs.media_type):
            try:
                completed.append(self._run_one(attack, inputs))
            except AttackError as exc:
                # Not every attack applies to every file: modifying outside the
                # payload needs a payload that does not fill the medium, for one.
                skipped.append((attack.label, str(exc)))

        return completed, skipped

    def _set_running(self, running: bool) -> None:
        self.run_button.setEnabled(not running)
        self.run_all_button.setEnabled(not running)

    # -- reporting --------------------------------------------------------- #

    def _on_attack_finished(self, run: AttackRun) -> None:
        self._runs.append(run)
        self._show_summary(run)
        self.append_log(self._describe(run))

        self.statusMessage.emit(
            f"{run.attack.label}: {run.before.verdict} -> {run.after.verdict}"
        )
        _log.info(
            "attack %s: %s -> %s", run.attack.key, run.before.verdict, run.after.verdict
        )

    def _on_all_finished(
        self, outcome: tuple[list[AttackRun], list[tuple[str, str]]]
    ) -> None:
        completed, skipped = outcome
        self._runs.extend(completed)

        lines = ["Ran every applicable attack.", ""]
        lines.append(f"{'Attack':<40} {'Before':<18} {'After':<18} Match")
        lines.append("-" * 88)
        for run in completed:
            lines.append(
                f"{run.attack.label:<40} {run.before.verdict:<18} "
                f"{run.after.verdict:<18} {'yes' if run.matched_expectation else 'no'}"
            )

        if skipped:
            lines += ["", "Not applicable to this file:"]
            for label, reason in skipped:
                lines.append(f"  {label}: {reason}")

        unchanged = [run for run in completed if not run.verdict_changed]
        if unchanged:
            lines += [
                "",
                "Attacks that left the verdict unchanged, and why that is correct:",
            ]
            for run in unchanged:
                lines.append(f"  {run.attack.label}: {run.outcome.description}")

        lines += ["", constants.AUTHENTIC_SCOPE_NOTICE, "", constants.AMBIGUOUS_FAILURE_NOTICE]
        self.append_log("\n".join(lines))

        if completed:
            self._show_summary(completed[-1])
        self.statusMessage.emit(
            f"Ran {len(completed)} attacks, skipped {len(skipped)}."
        )

    def _show_summary(self, run: AttackRun) -> None:
        self.summary_panel.set_rows(
            [
                ("Attack", run.attack.label),
                ("Target", run.attack.target),
                ("Verdict before", run.before.verdict),
                ("Verdict after", run.after.verdict),
                ("Changed", "yes" if run.verdict_changed else "no"),
                ("Expected", ", ".join(sorted(run.outcome.expected_verdicts))),
                ("Matched expectation", "yes" if run.matched_expectation else "no"),
                ("Output", file_utils.display_name(run.outcome.output_path)),
            ]
        )
        self.summary_panel.set_notice(run.outcome.description)

    @staticmethod
    def _describe(run: AttackRun) -> str:
        lines = [
            f"{run.attack.label} [{run.attack.key}]",
            f"  {run.outcome.description}",
            f"  wrote:    {file_utils.display_name(run.outcome.output_path)}",
            f"  before:   {run.before.verdict}",
            f"  after:    {run.after.verdict}",
            f"  expected: {', '.join(sorted(run.outcome.expected_verdicts))}",
            f"  matched:  {'yes' if run.matched_expectation else 'no'}",
            f"  reason:   {run.after.reason}",
        ]
        if not run.verdict_changed and run.after.verdict == constants.VERDICT_AUTHENTIC:
            lines.append(
                "  note:     the verdict is unchanged on purpose. "
                + constants.AUTHENTIC_SCOPE_NOTICE
            )
        return "\n".join(lines)

    def append_log(self, text: str) -> None:
        existing = self.log_view.toPlainText()
        self.log_view.setPlainText(f"{existing}\n\n{text}".strip() if existing else text)

    def clear_log(self) -> None:
        self._runs.clear()
        self.log_view.setPlainText("")
        self.summary_panel.clear()

    def _save_log(self) -> None:
        if not self.log_view.toPlainText().strip():
            self.statusMessage.emit("There is nothing in the log to save yet.")
            return

        directory = os.path.join(
            str(file_utils.ensure_directory("evidence/results")), "attack_log.txt"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Save the attack log", directory, "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            file_utils.write_text_atomic(
                path, self.log_view.toPlainText(), overwrite=True
            )
        except OSError as exc:
            QMessageBox.warning(self, "Attack Lab", str(exc))
            return
        self.statusMessage.emit(f"Saved the attack log to {file_utils.display_name(path)}.")

    def _on_attack_failed(self, message: str, detail: str) -> None:
        self.statusMessage.emit(message)
        self.append_log(f"Could not run the attack: {message}")
        _log.error("attack failed: %s", message)
        QMessageBox.warning(self, "Attack Lab", message)
