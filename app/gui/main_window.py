"""Main PySide6 window for the media-security laboratory."""

from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtWidgets import (
    QMainWindow,
    QScrollArea,
    QTabWidget,
    QWidget,
)

from app.gui.attack_tab import AttackTab
from app.gui.protect_tab import ProtectTab
from app.gui.steganalysis_tab import SteganalysisTab
from app.gui.verify_tab import VerifyTab
from app.gui.video_tab import VideoTab


STYLE = """
QMainWindow { background: #f4f6f8; }
QWidget { font-family: "Segoe UI"; font-size: 10pt; color: #17212b; }
QGroupBox {
    background: white; border: 1px solid #d9e0e7; border-radius: 8px;
    margin-top: 12px; padding: 12px;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; font-weight: 600; }
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox, QTreeWidget {
    background: white; border: 1px solid #c8d1dc; border-radius: 5px; padding: 6px;
}
QPushButton {
    background: #e8edf3; border: 1px solid #c8d1dc; border-radius: 5px;
    padding: 7px 12px;
}
QPushButton:hover { background: #dce5ee; }
QPushButton#primaryButton {
    background: #1769aa; color: white; border: 0; padding: 10px 16px; font-weight: 600;
}
QPushButton#primaryButton:hover { background: #12598f; }
QFrame#dropZone {
    background: #eef5fb; border: 2px dashed #74a3c7; border-radius: 9px;
}
QLabel#verdictLabel { font-size: 16pt; font-weight: 700; color: #1769aa; }
QLabel#sectionTitle { font-size: 17pt; font-weight: 700; }
QTabBar::tab { padding: 10px 18px; }
QTabBar::tab:selected { color: #1769aa; font-weight: 600; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steganographic Media Integrity Lab")
        self.setMinimumSize(QSize(980, 720))
        self.resize(1180, 900)
        self.setStyleSheet(STYLE)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.protect_tab = ProtectTab()
        self.verify_tab = VerifyTab()
        self.attack_tab = AttackTab()
        self.analysis_tab = SteganalysisTab()
        self.video_tab = VideoTab()
        self._add_tab(self.protect_tab, "Protect")
        self._add_tab(self.verify_tab, "Verify")
        self._add_tab(self.attack_tab, "Attack Lab")
        self._add_tab(self.analysis_tab, "Analysis")
        self._add_tab(self.video_tab, "Video")
        self.statusBar().showMessage(
            "Successful verification authenticates the hidden message and signed record."
        )

    def _add_tab(self, widget: QWidget, label: str) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(widget)
        self.tabs.addTab(scroll, label)

    def closeEvent(self, event) -> None:
        for tab in (
            self.protect_tab,
            self.verify_tab,
            self.attack_tab,
            self.analysis_tab,
            self.video_tab,
        ):
            shutdown = getattr(tab, "shutdown", None)
            if shutdown is not None:
                shutdown()
        super().closeEvent(event)
