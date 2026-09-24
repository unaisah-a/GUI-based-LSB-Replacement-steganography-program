"""The application window: five tabs, a status bar, and demo key management.

Structure follows the layout in the project plan::

    Protect | Verify | Attack Lab | Steganalysis | Video

The window itself holds no steganography or cryptography logic. It builds the tabs,
offers the shared key-management actions they all depend on, and makes sure nothing
is still running when it closes.

Where the demo key pair lives
-----------------------------
Every tab needs the same key pair — the sender to sign, the receiver to verify — so
generating it belongs to the window rather than to any one tab. The action is
explicit rather than automatic: generating a key pair silently on startup would
overwrite nothing, but it would also hide the single most security-relevant thing
the application does. The unencrypted-private-key caveat is shown next to it.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QLabel,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTabWidget,
    QWidget,
)

from app.crypto import key_manager
from app.gui.attack_tab import AttackTab
from app.gui.protect_tab import ProtectTab
from app.gui.steganalysis_tab import SteganalysisTab
from app.gui.verify_tab import VerifyTab
from app.gui.video_tab import VideoTab
from app.gui.workers import BackgroundRunner
from app.utils import constants
from app.utils.logging_utils import get_logger

__all__ = ["MainWindow"]

_log = get_logger(__name__)


class MainWindow(QMainWindow):
    """The top-level window."""

    #: Emitted when the demo key pair has been created or located, with its paths.
    demoKeysReady = Signal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{constants.APP_NAME} - {constants.APP_SHORT_NAME}")
        self.resize(1180, 820)

        self._runner = BackgroundRunner()

        self.tabs = QTabWidget(self)
        self.tabs.setObjectName("mainTabs")
        self.setCentralWidget(self.tabs)

        self.protect_tab = ProtectTab(self)
        self.verify_tab = VerifyTab(self)
        self.attack_tab = AttackTab(self)
        self.steganalysis_tab = SteganalysisTab(self)
        self.video_tab = VideoTab(self)

        for tab in (
            self.protect_tab,
            self.verify_tab,
            self.attack_tab,
            self.steganalysis_tab,
            self.video_tab,
        ):
            self.tabs.addTab(tab, tab.TITLE)
            # Tabs report progress through the shared status bar rather than each
            # holding a status area of its own. Every tab has the signal now; the
            # guard stays so that adding a tab without one cannot crash the window.
            signal = getattr(tab, "statusMessage", None)
            if signal is not None:
                signal.connect(self.set_status)
            # Without this, keys generated from the menu only reached the tabs after
            # a restart, because each tab looks for them once, when it is built.
            use_demo_keys = getattr(tab, "use_demo_keys", None)
            if use_demo_keys is not None:
                self.demoKeysReady.connect(use_demo_keys)

        self._build_menus()
        self._build_status_bar()

    # -- construction ------------------------------------------------------ #

    def _build_menus(self) -> None:
        keys_menu = self.menuBar().addMenu("&Keys")

        self.generate_keys_action = QAction("&Generate demo key pair", self)
        self.generate_keys_action.setStatusTip(
            "Create an RSA key pair under keys/ for the demonstration"
        )
        self.generate_keys_action.triggered.connect(self.generate_demo_keys)
        keys_menu.addAction(self.generate_keys_action)

        help_menu = self.menuBar().addMenu("&Help")

        self.about_action = QAction("&About", self)
        self.about_action.triggered.connect(self.show_about)
        help_menu.addAction(self.about_action)

        self.scope_action = QAction("What &verification establishes", self)
        self.scope_action.triggered.connect(self.show_scope)
        help_menu.addAction(self.scope_action)

    def _build_status_bar(self) -> None:
        bar = QStatusBar(self)
        self.setStatusBar(bar)

        self._status_label = QLabel("Ready", self)
        self._status_label.setTextFormat(Qt.TextFormat.PlainText)
        bar.addWidget(self._status_label, 1)

        version = QLabel(f"v{constants.APP_VERSION}", self)
        version.setTextFormat(Qt.TextFormat.PlainText)
        bar.addPermanentWidget(version)

    # -- status ------------------------------------------------------------ #

    def set_status(self, message: str) -> None:
        self._status_label.setText(message)

    @property
    def status_text(self) -> str:
        return self._status_label.text()

    # -- key management ---------------------------------------------------- #

    def generate_demo_keys(self) -> None:
        """Create or locate the demo key pair, off the interface thread.

        Generating a 3072-bit RSA key takes long enough to be noticeable, so it does
        not run inline.
        """
        self.generate_keys_action.setEnabled(False)
        self.set_status("Preparing the demo key pair...")

        self._runner.submit(
            key_manager.ensure_demo_keys,
            on_success=self._on_keys_ready,
            on_error=self._on_keys_failed,
            on_finished=lambda: self.generate_keys_action.setEnabled(True),
        )

    def _on_keys_ready(self, pair: key_manager.DemoKeyPair) -> None:
        action = "Generated" if pair.created else "Found existing"
        self.set_status(
            f"{action} {pair.key_size}-bit demo key pair. {pair.notice}"
        )
        _log.info("%s demo key pair (%d bit)", action.lower(), pair.key_size)
        self.demoKeysReady.emit(pair.private_key_path, pair.public_key_path)

        QMessageBox.information(
            self,
            "Demo key pair",
            f"{action} a {pair.key_size}-bit RSA key pair.\n\n"
            f"Private key:\n{pair.private_key_path}\n\n"
            f"Public key:\n{pair.public_key_path}\n\n"
            f"{pair.notice}",
        )

    def _on_keys_failed(self, message: str, detail: str) -> None:
        self.set_status("Could not prepare the demo key pair.")
        _log.error("demo key preparation failed: %s", message)
        QMessageBox.critical(self, "Demo key pair", message)

    # -- help -------------------------------------------------------------- #

    def show_about(self) -> None:
        QMessageBox.information(
            self,
            f"About {constants.APP_SHORT_NAME}",
            f"{constants.APP_NAME}\n"
            f"Version {constants.APP_VERSION}\n\n"
            f"LSB replacement steganography with a signed verification record, "
            f"for image, audio and video cover objects.\n\n"
            f"Signature: {constants.SIGNATURE_ALGORITHM}, "
            f"RSA-{constants.RSA_KEY_SIZE_DEFAULT}\n"
            f"Encryption: {constants.CIPHER_AES_256_GCM} with a "
            f"{constants.KDF_SCRYPT}-derived key\n"
            f"LSB depth: {constants.MIN_LSB_DEPTH} to {constants.MAX_LSB_DEPTH}",
        )

    def show_scope(self) -> None:
        """State plainly what a successful verification does and does not mean."""
        QMessageBox.information(
            self,
            "What verification establishes",
            f"{constants.AUTHENTIC_SCOPE_NOTICE}\n\n"
            f"{constants.AMBIGUOUS_FAILURE_NOTICE}\n\n"
            f"{constants.START_LOCATION_NOTICE}\n\n"
            f"{constants.EXTRACTED_CONTENT_NOTICE}",
        )

    # -- shutdown ---------------------------------------------------------- #

    def closeEvent(self, event: QCloseEvent) -> None:
        """Wait for background work before closing.

        A protect operation writes a stego file and then its manifest. Abandoning it
        halfway would leave a stego file with no manifest, which a receiver cannot
        use, so the window waits rather than dropping the work.
        """
        for tab in (self.protect_tab, self.verify_tab, self.attack_tab,
                    self.steganalysis_tab, self.video_tab):
            if hasattr(tab, "shutdown"):
                tab.shutdown()
            else:
                tab._runner.wait()
        self._runner.wait()
        super().closeEvent(event)
