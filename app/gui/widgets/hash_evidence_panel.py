"""Shared, selectable payload-hash evidence for Verify and Attack Lab."""

from PySide6.QtWidgets import QFormLayout

from app.gui.widgets.file_info_panel import FileInfoPanel
from app.verification.verdicts import HashEvidence


class HashEvidencePanel(FileInfoPanel):
    def __init__(self, parent=None, *, title="Payload hashes (SHA-256)"):
        super().__init__(parent, title=title)
        # Each long digest gets the full width rather than competing with its label.
        self._form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)

    def show_evidence(self, evidence: HashEvidence) -> None:
        self.set_rows(evidence.display_rows())
        self.set_notice(
            "The manifest hash is an unverified claim until it agrees with the "
            "authenticated signed record. Hashes describe the payload, not every cover sample."
        )
