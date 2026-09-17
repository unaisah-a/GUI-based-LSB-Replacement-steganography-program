import os
import subprocess
import sys


def test_gui_passes_optional_outputs_to_service_and_reports_failure():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
from PySide6.QtWidgets import QApplication

from app.crypto.encryption import encode_key, generate_encryption_key
import app.gui.protect_tab as protect_tab

application = QApplication([])
tab = protect_tab.ProtectTab()
tab.input_path.setText("cover.png")
tab.output_path.setText("protected.png")
tab.manifest_path.setText("protected.json")
tab.private_key_path.setText("private.pem")
tab.start_method.setCurrentIndex(1)
tab.start_value.setText("0")
tab.preserve_size.setChecked(True)
tab.create_recovery.setChecked(True)
recovery_key = generate_encryption_key()
tab.recovery_key.setText(encode_key(recovery_key))
captured = {}

protect_tab.load_private_key_from_pem = lambda *_args: object()

def fail_protection(*args):
    captured["options"] = args[-1]
    raise RuntimeError("injected transaction failure")

protect_tab.protect_media = fail_protection
protect_tab.QMessageBox.critical = lambda *_args: None
previewed = []
tab.output_preview.set_file = previewed.append
tab._protect()

options = captured["options"]
assert options.preserve_size is True
assert options.recovery_key == recovery_key
assert previewed == []
assert tab.status.text() == "Protection failed: injected transaction failure"
tab.close()
application.processEvents()
'''
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
