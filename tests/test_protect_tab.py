import os
import subprocess
import sys


def test_gui_passes_optional_outputs_to_service_and_reports_failure():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
from PySide6.QtTest import QTest
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
tab.size_report_path.setText("size-report.json")
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
while tab.runner.busy:
    application.processEvents()
    QTest.qWait(1)

options = captured["options"]
assert options.preserve_size is True
assert str(options.size_report_path) == "size-report.json"
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


def test_gui_displays_exact_signed_envelope_capacity():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
import tempfile
from pathlib import Path

import numpy as np
from PySide6.QtWidgets import QApplication

from app.crypto.key_manager import generate_rsa_keys, save_private_key_to_pem
from app.gui.protect_tab import ProtectTab
from app.stego import image_io

directory = Path(tempfile.mkdtemp())
cover = directory / "cover.png"
key_path = directory / "private.pem"
pixels = np.arange(80 * 80 * 3, dtype=np.uint8).reshape(80, 80, 3)
image_io.save_image(pixels, cover, image_io.PNG)
private_key, _ = generate_rsa_keys()
save_private_key_to_pem(private_key, key_path, None)

application = QApplication([])
tab = ProtectTab()
tab.input_path.setText(str(cover))
tab.private_key_path.setText(str(key_path))
tab.start_method.setCurrentIndex(1)
tab.start_value.setText("7")
tab.lsb_count.setValue(2)
tab.robustness.setCurrentIndex(1)
tab.message.setPlainText("exact GUI estimate")
tab._update_capacity()

label = tab.capacity.text()
assert "Exact signed envelope:" in label
assert "stored payload:" in label
assert "carrier framing: 4 bytes" in label
assert "from index 7: fits" in label
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
