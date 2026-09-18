import os
import subprocess
import sys


def _run_offscreen(code: str, timeout: int = 45) -> None:
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_offscreen_image_and_audio_encrypted_file_workflows():
    _run_offscreen(
        r'''
import tempfile
import time
from pathlib import Path

import numpy as np
import soundfile as sf
from PySide6.QtWidgets import QApplication

from app.crypto.encryption import encode_key, generate_encryption_key
from app.crypto.key_manager import (
    generate_rsa_keys,
    save_private_key_to_pem,
    save_public_key_to_pem,
)
import app.gui.protect_tab as protect_tab
import app.gui.verify_tab as verify_tab
from app.stego import image_io
from app.verification.verdicts import Verdict


def wait_for(runner):
    deadline = time.monotonic() + 15
    while runner.busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.002)
    application.processEvents()
    assert not runner.busy


directory = Path(tempfile.mkdtemp(prefix="gui-workflows-"))
private_path = directory / "private.pem"
public_path = directory / "public.pem"
private_key, public_key = generate_rsa_keys()
save_private_key_to_pem(private_key, private_path, None)
save_public_key_to_pem(public_key, public_path)
encryption_key = generate_encryption_key()
application = QApplication([])
dialog_errors = []
protect_tab.QMessageBox.critical = lambda _parent, title, detail: dialog_errors.append((title, detail))
verify_tab.QMessageBox.critical = lambda _parent, title, detail: dialog_errors.append((title, detail))

image_path = directory / "image-cover.png"
pixels = np.arange(180 * 180 * 3, dtype=np.uint8).reshape(180, 180, 3)
image_io.save_image(pixels, image_path, image_io.PNG)

audio_path = directory / "audio-cover.wav"
samples = np.arange(36000 * 2, dtype=np.int16).reshape(36000, 2)
sf.write(audio_path, samples, 16000, subtype="PCM_16")

for index, cover in enumerate((image_path, audio_path)):
    if index == 0:
        payload_path = directory / "payload-image.png"
        image_io.save_image(np.full((8, 8, 3), 73, dtype=np.uint8), payload_path, image_io.PNG)
    else:
        payload_path = directory / "payload-audio.wav"
        sf.write(payload_path, np.arange(120, dtype=np.int16), 8000, subtype="PCM_16")
    payload_bytes = payload_path.read_bytes()

    protect = protect_tab.ProtectTab()
    protect._set_input(str(cover))
    protect.private_key_path.setText(str(private_path))
    protect.media_id.setText(f"GUI-{index}")
    protect.lsb_count.setValue(2)
    protect.payload_mode.setCurrentIndex(1)
    protect.payload_file_path.setText(str(payload_path))
    protect.start_method.setCurrentIndex(0)
    protect.start_value.setText("separate start secret")
    protect.encrypt.setChecked(True)
    protect.encryption_key.setText(encode_key(encryption_key))
    protect._protect()
    assert protect.runner.busy
    wait_for(protect.runner)
    assert protect.status.text().startswith("Protected "), (protect.status.text(), dialog_errors)
    protected_path = Path(protect.output_path.text())
    manifest_path = Path(protect.manifest_path.text())
    assert protected_path.is_file()
    assert manifest_path.is_file()
    protected_before_collision = protected_path.read_bytes()
    protect._protect()
    wait_for(protect.runner)
    assert protect.status.text().startswith("Protection failed: output already exists:")
    assert protected_path.read_bytes() == protected_before_collision
    assert dialog_errors[-1][0] == "Protection failed"
    dialog_errors.clear()

    verify = verify_tab.VerifyTab()
    verify.media_path.setText(str(protected_path))
    verify.manifest_path.setText(str(manifest_path))
    verify.public_key_path.setText(str(public_path))
    verify.start_secret.setText("separate start secret")
    verify.encryption_key.setText(encode_key(encryption_key))
    verify._update_key_fingerprint()
    assert "SHA-256" in verify.key_fingerprint.text()
    verify._verify()
    assert verify.runner.busy
    wait_for(verify.runner)
    assert verify._verified_result is not None
    assert verify._verified_result.verdict is Verdict.AUTHENTIC
    assert verify._verified_result.message == payload_bytes
    assert verify.save_button.isEnabled()
    assert "Trusted:" in verify.results.trust.text()
    assert verify.recovered_preview._path is not None
    assert Path(verify.recovered_preview._path).suffix == payload_path.suffix
    if index == 1:
        assert verify.recovered_preview._play.isEnabled()

    recovered_path = directory / f"recovered-{index}{payload_path.suffix}"
    verify_tab.QFileDialog.getSaveFileName = lambda *_args, p=recovered_path: (str(p), "")
    verify._save_recovered()
    assert recovered_path.read_bytes() == payload_bytes

    verify.start_secret.setText("wrong secret")
    assert verify._verified_result is None
    assert not verify.save_button.isEnabled()
    assert verify.results.verdict.text() == "Not verified"
    verify._verify()
    wait_for(verify.runner)
    assert verify._verified_result is None
    assert verify.results.verdict.text() == Verdict.CANNOT_VERIFY.value
    assert "Untrusted:" in verify.results.trust.text()

    verify.shutdown()
    protect.shutdown()
    verify.close()
    protect.close()

application.processEvents()
assert dialog_errors == []
'''
    )


def test_worker_keeps_event_loop_responsive_and_cancels():
    _run_offscreen(
        r'''
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from app.gui.task_runner import TaskRunner

application = QApplication([])
runner = TaskRunner()
events = []

def operation(token, progress):
    progress("working")
    while True:
        token.checkpoint()
        time.sleep(0.002)

runner.progress.connect(lambda message: events.append(message))
runner.cancelled.connect(lambda message: events.append(message))
runner.start(operation)
QTimer.singleShot(5, lambda: events.append("responsive"))
QTimer.singleShot(15, runner.cancel)
deadline = time.monotonic() + 5
while runner.busy and time.monotonic() < deadline:
    application.processEvents()
    time.sleep(0.001)
application.processEvents()
assert not runner.busy
assert "responsive" in events
assert "working" in events
assert "Operation cancelled." in events
'''
    )


def test_gui_errors_are_reported_without_unhandled_callbacks():
    _run_offscreen(
        r'''
import time
import tempfile
from pathlib import Path

from PySide6.QtWidgets import QApplication
import app.gui.protect_tab as protect_tab
import app.gui.verify_tab as verify_tab
from app.crypto.key_manager import generate_rsa_keys, save_private_key_to_pem

application = QApplication([])
messages = []
protect_tab.QMessageBox.critical = lambda _parent, title, detail: messages.append((title, detail))
verify_tab.QMessageBox.critical = lambda _parent, title, detail: messages.append((title, detail))

protect = protect_tab.ProtectTab()
protect.private_key_path.setText("missing-private.pem")
protect._protect()
assert not protect.runner.busy
assert protect.status.text().startswith("Protection failed:")

encrypted_key_path = Path(tempfile.mkdtemp()) / "encrypted-private.pem"
private_key, _public_key = generate_rsa_keys()
save_private_key_to_pem(private_key, encrypted_key_path, "correct password")
protect.private_key_path.setText(str(encrypted_key_path))
protect.key_password.setText("wrong password")
protect._protect()
assert not protect.runner.busy
assert protect.status.text().startswith("Protection failed:")

verify = verify_tab.VerifyTab()
verify.media_path.setText("missing.png")
verify.manifest_path.setText("missing.json")
verify.public_key_path.setText("missing-public.pem")
verify._verify()
deadline = time.monotonic() + 5
while verify.runner.busy and time.monotonic() < deadline:
    application.processEvents()
    time.sleep(0.001)
application.processEvents()
assert not verify.runner.busy
assert verify.status.text().startswith("Verification failed:")
assert verify.results.verdict.text() == "Not verified"
assert not verify.save_button.isEnabled()
assert [title for title, _detail in messages] == [
    "Protection failed", "Protection failed", "Verification failed"
]
verify.shutdown()
protect.shutdown()
'''
    )


def test_attack_lab_runs_paired_verification_and_exports_evidence():
    _run_offscreen(
        r'''
import json
import tempfile
import time
from pathlib import Path

import numpy as np
from PySide6.QtWidgets import QApplication

from app.crypto.key_manager import generate_rsa_keys, save_public_key_to_pem
from app.gui.attack_tab import AttackTab
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io


application = QApplication([])
directory = Path(tempfile.mkdtemp(prefix="attack-lab-"))
cover = directory / "cover.png"
protected = directory / "protected.png"
attacked = directory / "attacked.png"
manifest = directory / "manifest.json"
public_path = directory / "public.pem"
report = directory / "attack-evidence.json"
pixels = np.arange(160 * 160 * 3, dtype=np.uint8).reshape(160, 160, 3)
image_io.save_image(pixels, cover, image_io.PNG)
private_key, public_key = generate_rsa_keys()
save_public_key_to_pem(public_key, public_path)
protect_media(
    cover,
    protected,
    manifest,
    b"Attack Lab workflow",
    private_key,
    ProtectionOptions(
        media_id="GUI-ATTACK",
        lsb_count=3,
        start_method="manual",
        start_location=0,
    ),
)

tab = AttackTab()
tab.input_path.setText(str(protected))
tab.manifest_path.setText(str(manifest))
tab.public_key_path.setText(str(public_path))
tab.output_path.setText(str(attacked))
tab.report_path.setText(str(report))
tab.attack.setCurrentIndex(tab.attack.findData("signature-corruption"))
tab._run()
assert tab.runner.busy
deadline = time.monotonic() + 15
while tab.runner.busy and time.monotonic() < deadline:
    application.processEvents()
    time.sleep(0.002)
application.processEvents()
assert not tab.runner.busy
assert attacked.is_file()
assert report.is_file()
evidence = json.loads(report.read_text(encoding="utf-8"))
assert evidence["baseline"]["verdict"] == "AUTHENTIC"
assert evidence["outcome"]["verdict"] != "AUTHENTIC"
assert tab.baseline_status.text().startswith("Baseline: AUTHENTIC")
assert not tab.outcome_status.text().startswith("Outcome: AUTHENTIC")
assert tab.status.text().startswith("Completed signature-corruption")
tab.shutdown()
tab.close()
'''
    )


def test_recovery_panel_restores_png_bmp_and_wav_originals_exactly():
    _run_offscreen(
        r'''
import tempfile
import time
from pathlib import Path

import numpy as np
import soundfile as sf
from PySide6.QtWidgets import QApplication

from app.crypto.encryption import encode_key, generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
import app.gui.recovery_panel as recovery_panel
from app.gui.verify_tab import VerifyTab
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io


application = QApplication([])
directory = Path(tempfile.mkdtemp(prefix="recovery-gui-"))
private_key, _public_key = generate_rsa_keys()
errors = []
recovery_panel.QMessageBox.critical = lambda _parent, title, detail: errors.append((title, detail))

for media_type in ("png", "bmp", "wav"):
    original = directory / f"original.{media_type}"
    protected = directory / f"protected.{media_type}"
    manifest = directory / f"protected-{media_type}.json"
    sidecar = directory / f"protected-{media_type}.smir"
    restored = directory / f"restored.{media_type}"
    if media_type == "png":
        image_io.save_image(
            np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3),
            original,
            image_io.PNG,
        )
    elif media_type == "bmp":
        image_io.save_image(
            np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3),
            original,
            image_io.BMP,
        )
    else:
        sf.write(
            original,
            np.arange(25000 * 2, dtype=np.int16).reshape(25000, 2),
            16000,
            subtype="PCM_16",
        )
    expected = original.read_bytes()
    recovery_key = generate_encryption_key()
    protect_media(
        original,
        protected,
        manifest,
        b"GUI recovery",
        private_key,
        ProtectionOptions(
            media_id=f"GUI-RECOVERY-{media_type}",
            lsb_count=2,
            start_method="manual",
            start_location=0,
            recovery_key=recovery_key,
            recovery_path=sidecar,
        ),
    )

    tab = VerifyTab()
    tab.media_path.setText(str(protected))
    panel = tab.recovery_panel
    assert panel.protected_path.text() == str(protected)
    panel.sidecar_path.setText(str(sidecar))
    panel.output_path.setText(str(restored))
    panel.recovery_key.setText(encode_key(recovery_key))
    panel._inspect_sidecar()
    assert "Encrypted backup:" in panel.storage.text()
    assert "not reversible LSB" in panel.description.text()
    panel._restore()
    assert panel.runner.busy
    deadline = time.monotonic() + 15
    while panel.runner.busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.002)
    application.processEvents()
    assert not panel.runner.busy
    assert restored.read_bytes() == expected
    assert panel.status.text().startswith("Restored ")
    tab.shutdown()
    tab.close()

assert errors == []
'''
    )
