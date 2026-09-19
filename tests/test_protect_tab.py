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


def test_capacity_worker_keeps_ui_responsive_and_discards_stale_outcomes():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
import threading
import time
from types import SimpleNamespace
from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
import app.gui.protect_tab as module

application = QApplication([])
tab = module.ProtectTab()
main_thread = threading.get_ident()
entered = threading.Event()
release = threading.Event()
calls = []
heartbeat = []
timer = QTimer()
timer.timeout.connect(lambda: heartbeat.append(1))
timer.start(5)

class Key:
    def public_key(self):
        return self

def key_loader(*args):
    assert threading.get_ident() != main_thread
    return Key()

module.load_private_key_from_pem = key_loader
module.public_key_fingerprint = lambda key: 'fingerprint'

def estimate(path, payload, key, options):
    assert threading.get_ident() != main_thread
    calls.append(payload)
    if payload in (b'old-success', b'old-error'):
        entered.set()
        assert release.wait(5)
        if payload == b'old-error':
            raise ValueError('obsolete error')
    if payload == b'current-error':
        raise ValueError('current error')
    carrier = SimpleNamespace(carrier_header_bytes=4, required_samples=80,
                              available_samples=1000, start_location=7)
    return SimpleNamespace(carrier=carrier, fits=True, envelope_length=len(payload),
                           embedded_payload_length=len(payload))

module.estimate_protection_capacity = estimate

def wait_for(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline
        application.processEvents()
        QTest.qWait(5)
    application.processEvents()

tab.input_path.setText('cover.png')
tab.private_key_path.setText('private.pem')
tab.start_method.setCurrentIndex(1)
tab.start_value.setText('7')

for old in ('old-success', 'old-error'):
    entered.clear()
    release.clear()
    tab.message.setPlainText(old)
    wait_for(entered.is_set)
    before = len(heartbeat)
    for text in ('intermediate', 'latest'):
        tab.message.setPlainText(text)
    QTest.qWait(300)
    assert len(heartbeat) > before
    assert tab.capacity.text() == 'Updating capacity…'
    release.set()
    wait_for(lambda: not tab.capacity_runner.busy and not tab.capacity_timer.isActive())
    assert 'Exact signed envelope: 6 bytes' in tab.capacity.text()
    assert calls[-2:] == [old.encode(), b'latest']
    assert 'obsolete' not in tab.capacity.text()

tab.message.setPlainText('current-error')
wait_for(lambda: not tab.capacity_runner.busy and not tab.capacity_timer.isActive())
assert tab.capacity.text() == 'current error'
tab.private_key_path.clear()
wait_for(lambda: not tab.capacity_timer.isActive())
assert 'Choose a private signing key' in tab.capacity.text()
tab.lsb_count.setValue(3)
assert '·····XXX' in tab.bit_help.text()

# Closing with an estimate in flight cancels it and waits for thread ownership safely.
tab.private_key_path.setText('private.pem')
entered.clear()
release.clear()
tab.message.setPlainText('old-success')
wait_for(entered.is_set)
threading.Timer(0.05, release.set).start()
tab.close()
application.processEvents()
assert not tab.capacity_timer.isActive()
assert not tab.capacity_runner.busy
timer.stop()
'''
    completed = subprocess.run(
        [sys.executable, "-c", code], cwd=os.getcwd(), env=environment,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_gui_displays_exact_signed_envelope_capacity():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
import tempfile
from pathlib import Path

import numpy as np
from PySide6.QtTest import QTest
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

for _ in range(1000):
    application.processEvents()
    if not tab.capacity_timer.isActive() and not tab.capacity_runner.busy:
        break
    QTest.qWait(5)
else:
    raise AssertionError("Capacity worker did not finish")

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
