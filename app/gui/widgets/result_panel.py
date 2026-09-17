"""Structured verification result display."""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGroupBox,
    QLabel,
    QPlainTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from app.verification.verdicts import CheckStatus, VerificationResult


class ResultPanel(QGroupBox):
    def __init__(self, title: str = "Verification result", parent=None):
        super().__init__(title, parent)
        self.verdict = QLabel("Not verified")
        self.verdict.setObjectName("verdictLabel")
        self.summary = QLabel("Select a protected file and its manifest.")
        self.summary.setWordWrap(True)
        self.checks = QTreeWidget()
        self.checks.setHeaderLabels(["Check", "Status", "Detail"])
        self.checks.setRootIsDecorated(False)
        self.message = QPlainTextEdit()
        self.message.setReadOnly(True)
        self.message.setPlaceholderText("Recovered text appears here.")
        self.message.setMaximumHeight(120)
        layout = QVBoxLayout(self)
        layout.addWidget(self.verdict)
        layout.addWidget(self.summary)
        layout.addWidget(self.checks)
        layout.addWidget(self.message)

    def set_result(self, result: VerificationResult) -> None:
        self.verdict.setText(result.verdict.value)
        self.summary.setText(result.summary)
        self.checks.clear()
        colours = {
            CheckStatus.PASS: QColor("#138a5b"),
            CheckStatus.FAIL: QColor("#c13b36"),
            CheckStatus.NOT_RUN: QColor("#777777"),
        }
        for check in result.checks:
            item = QTreeWidgetItem(
                [check.name, check.status.value.replace("_", " "), check.detail]
            )
            item.setForeground(1, colours[check.status])
            self.checks.addTopLevelItem(item)
        self.checks.resizeColumnToContents(0)
        self.checks.resizeColumnToContents(1)
        if result.message is None:
            self.message.clear()
        else:
            try:
                self.message.setPlainText(result.message.decode("utf-8"))
            except UnicodeDecodeError:
                self.message.setPlainText(
                    f"Binary payload recovered ({len(result.message):,} bytes)."
                )
