"""Controlled negative-case generation and paired verification tab."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.attacks import export_attack_evidence, run_attack_experiment
from app.crypto.encryption import decode_key
from app.crypto.key_manager import load_public_key_from_pem
from app.gui.task_runner import TaskRunner
from app.gui.widgets import MediaPreview


class AttackTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.input_path = QLineEdit()
        self.manifest_path = QLineEdit()
        self.public_key_path = QLineEdit()
        self.output_path = QLineEdit()
        self.report_path = QLineEdit()
        self.alternate_key_path = QLineEdit()
        self.substitute_manifest_path = QLineEdit()
        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.wrong_secret = QLineEdit()
        self.wrong_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.encryption_key = QLineEdit()
        self.encryption_key.setEchoMode(QLineEdit.EchoMode.Password)

        self.attack = QComboBox()
        for label, value in (
            ("Corrupt final embedded payload bit", "payload-corruption"),
            ("Corrupt signed record", "record-corruption"),
            ("Corrupt stored message", "message-corruption"),
            ("Corrupt signature", "signature-corruption"),
            ("Simulate payload truncation", "payload-truncation"),
            ("Add seeded payload noise", "seeded-noise"),
            ("Modify media outside payload", "outside-payload"),
            ("Verify with wrong public key", "wrong-public-key"),
            ("Verify with wrong start secret", "wrong-start-secret"),
            ("Substitute companion manifest", "substitution"),
            ("Replay byte-identical bundle", "replay"),
        ):
            self.attack.addItem(label, value)
        self.seed = QSpinBox()
        self.seed.setRange(0, 2_147_483_647)
        self.seed.setValue(2005)
        self.severity = QSpinBox()
        self.severity.setRange(1, 1_000_000)
        self.severity.setValue(8)
        self.fault_copies = QSpinBox()
        self.fault_copies.setRange(1, 3)

        self.status = QLabel(
            "Run a baseline and controlled outcome verification. Source media is never changed."
        )
        self.status.setWordWrap(True)
        self.baseline_status = QLabel("Baseline: not run")
        self.baseline_status.setWordWrap(True)
        self.outcome_status = QLabel("Outcome: not run")
        self.outcome_status.setWordWrap(True)
        self.boundary_status = QLabel("")
        self.boundary_status.setWordWrap(True)
        self.before = MediaPreview("Before attack")
        self.after = MediaPreview("After attack / verification input")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.runner = TaskRunner(self)

        root = QVBoxLayout(self)
        files = QGroupBox("Attack and verification inputs")
        grid = QGridLayout(files)
        self._picker(grid, 0, "Protected media", self.input_path, self._browse_input)
        self._picker(grid, 1, "Manifest", self.manifest_path, self._browse_manifest)
        self._picker(grid, 2, "Trusted public key", self.public_key_path, self._browse_key)
        self._picker(grid, 3, "Attack/replay output", self.output_path, self._browse_output)
        self._picker(grid, 4, "Evidence report", self.report_path, self._browse_report)
        root.addWidget(files)

        settings = QGroupBox("Controlled scenario")
        form = QFormLayout(settings)
        form.addRow("Scenario", self.attack)
        form.addRow("Start secret (if derived)", self.secret)
        form.addRow("Encryption key (if used)", self.encryption_key)
        form.addRow("Wrong start secret", self.wrong_secret)
        form.addRow("Alternate public key path", self.alternate_key_path)
        form.addRow("Substitute manifest path", self.substitute_manifest_path)
        form.addRow("Random seed", self.seed)
        form.addRow("Severity (bits/tail bytes)", self.severity)
        form.addRow("Repetition copies to damage", self.fault_copies)
        root.addWidget(settings)
        self._input_groups = (files, settings)

        actions = QHBoxLayout()
        self.run_button = QPushButton("Run attack experiment")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self._run)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel)
        actions.addWidget(self.run_button)
        actions.addWidget(self.cancel_button)
        root.addLayout(actions)
        root.addWidget(self.progress)
        root.addWidget(self.status)
        root.addWidget(self.baseline_status)
        root.addWidget(self.outcome_status)
        root.addWidget(self.boundary_status)
        previews = QHBoxLayout()
        previews.addWidget(self.before)
        previews.addWidget(self.after)
        root.addLayout(previews, 1)

        self.runner.started.connect(lambda: self._set_busy(True))
        self.runner.progress.connect(self.status.setText)
        self.runner.succeeded.connect(self._attack_succeeded)
        self.runner.failed.connect(self._attack_failed)
        self.runner.cancelled.connect(self._attack_cancelled)
        self.runner.finished.connect(lambda: self._set_busy(False))

    @staticmethod
    def _picker(layout, row, label, editor, callback):
        layout.addWidget(QLabel(label), row, 0)
        layout.addWidget(editor, row, 1)
        button = QPushButton("Browse…")
        button.clicked.connect(callback)
        layout.addWidget(button, row, 2)

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Protected media", "", "Supported media (*.png *.bmp *.wav)"
        )
        if path:
            self.input_path.setText(path)
            source = Path(path)
            self.output_path.setText(
                str(source.with_name(f"{source.stem}_attacked{source.suffix}"))
            )
            self.report_path.setText(
                str(source.with_name(f"{source.stem}_attack-evidence.json"))
            )
            self.before.set_file(path)

    def _browse_manifest(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Manifest", "", "JSON manifest (*.json)"
        )
        if path:
            self.manifest_path.setText(path)

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Trusted public key", "", "PEM keys (*.pem)"
        )
        if path:
            self.public_key_path.setText(path)

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Attack output", self.output_path.text(), "Media (*.png *.bmp *.wav)"
        )
        if path:
            self.output_path.setText(path)

    def _browse_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Attack evidence", self.report_path.text(), "JSON reports (*.json)"
        )
        if path:
            self.report_path.setText(path)

    def _run(self):
        if self.runner.busy:
            return
        values = {
            "input_path": self.input_path.text().strip(),
            "output_path": self.output_path.text().strip(),
            "manifest_path": self.manifest_path.text().strip(),
            "public_key_path": self.public_key_path.text().strip(),
            "alternate_key_path": self.alternate_key_path.text().strip(),
            "substitute_manifest_path": self.substitute_manifest_path.text().strip(),
            "report_path": self.report_path.text().strip(),
            "scenario": self.attack.currentData(),
            "secret": self.secret.text() or None,
            "wrong_secret": self.wrong_secret.text() or None,
            "encryption_key_text": self.encryption_key.text().strip(),
            "seed": self.seed.value(),
            "severity": self.severity.value(),
            "fault_copies": self.fault_copies.value(),
        }
        self.after.clear("Attack is running…")
        self.baseline_status.setText("Baseline: running…")
        self.outcome_status.setText("Outcome: waiting…")
        self.boundary_status.clear()
        self.runner.start(
            lambda token, progress: self._run_attack(token, progress, **values)
        )

    @staticmethod
    def _run_attack(
        token,
        progress,
        *,
        input_path,
        output_path,
        manifest_path,
        public_key_path,
        alternate_key_path,
        substitute_manifest_path,
        report_path,
        scenario,
        secret,
        wrong_secret,
        encryption_key_text,
        seed,
        severity,
        fault_copies,
    ):
        token.checkpoint()
        progress("Loading verification inputs…")
        public_key = load_public_key_from_pem(public_key_path)
        alternate_key = (
            load_public_key_from_pem(alternate_key_path)
            if alternate_key_path
            else None
        )
        encryption_key = decode_key(encryption_key_text) if encryption_key_text else None
        token.checkpoint()
        progress("Running baseline and controlled outcome verification…")
        evidence = run_attack_experiment(
            input_path,
            manifest_path,
            public_key,
            scenario,
            output_path=output_path or None,
            start_secret=secret,
            encryption_key=encryption_key,
            alternate_public_key=alternate_key,
            wrong_start_secret=wrong_secret,
            substitute_manifest_path=substitute_manifest_path or None,
            seed=seed,
            severity=severity,
            fault_copies=fault_copies,
        )
        token.checkpoint()
        if report_path:
            progress("Exporting attack evidence…")
            export_attack_evidence(evidence, report_path)
        token.checkpoint()
        return evidence

    def _attack_succeeded(self, result):
        if result.mutation is not None:
            self.after.set_file(result.mutation.output_path)
        else:
            self.after.set_file(result.outcome.media_path)
        self.baseline_status.setText(
            f"Baseline: {result.baseline.verdict} — {result.baseline.summary}"
        )
        self.outcome_status.setText(
            f"Outcome: {result.outcome.verdict} — {result.outcome.summary}"
        )
        self.boundary_status.setText(result.limitation)
        report = self.report_path.text().strip()
        report_detail = f" Evidence: {Path(report).name}." if report else ""
        self.status.setText(f"Completed {result.scenario}.{report_detail}")

    def _attack_failed(self, exc: Exception):
        self.after.clear()
        self.baseline_status.setText("Baseline: not completed")
        self.outcome_status.setText("Outcome: not completed")
        self.boundary_status.clear()
        QMessageBox.critical(self, "Attack failed", str(exc))
        self.status.setText(f"Attack failed: {exc}")

    def _attack_cancelled(self, message: str):
        self.after.clear()
        self.baseline_status.setText("Baseline: cancelled")
        self.outcome_status.setText("Outcome: cancelled")
        self.boundary_status.clear()
        self.status.setText(message)

    def _cancel(self):
        self.runner.cancel()
        self.cancel_button.setEnabled(False)
        self.status.setText("Cancellation requested; an atomic file operation may finish first…")

    def _set_busy(self, busy: bool):
        self.run_button.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.progress.setVisible(busy)
        for group in self._input_groups:
            group.setEnabled(not busy)

    def shutdown(self) -> None:
        self.runner.shutdown()
        self.before.clear()
        self.after.clear()
