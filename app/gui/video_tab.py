"""Video extension status and guidance."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class VideoTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        title = QLabel("Lossless video extension")
        title.setObjectName("sectionTitle")
        description = QLabel(
            "Video is an optional challenge and will use an FFV1 lossless Matroska "
            "workflow. The required image and audio workflows are available in the "
            "Protect and Verify tabs. Lossy H.264/H.265 transcoding can destroy LSB "
            "payloads and will be treated as a measured failure experiment."
        )
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(title)
        layout.addWidget(description)
        layout.addStretch()
