"""Compact carrier information panel."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFormLayout, QGroupBox, QLabel

from app.services.media import inspect_carrier


class FileInfoPanel(QGroupBox):
    def __init__(self, title: str = "Media information", parent=None):
        super().__init__(title, parent)
        self._name = QLabel("No file selected")
        self._type = QLabel("—")
        self._details = QLabel("—")
        self._details.setWordWrap(True)
        layout = QFormLayout(self)
        layout.addRow("File", self._name)
        layout.addRow("Type", self._type)
        layout.addRow("Properties", self._details)

    def set_file(self, path: str) -> None:
        source = Path(path)
        self._name.setText(source.name)
        try:
            info = inspect_carrier(source)
        except Exception as exc:
            self._type.setText("Unsupported")
            self._details.setText(str(exc))
            return
        self._type.setText(info.media_type.title())
        values = ", ".join(f"{key}: {value}" for key, value in info.description.items())
        self._details.setText(
            f"{values}, eligible samples: {info.total_samples:,}, "
            f"file size: {source.stat().st_size:,} bytes"
        )
