import os
import subprocess
import sys


def test_offscreen_video_protect_verify_preview_and_lossy_evidence():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
import json
import subprocess
import tempfile
import time
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from app.crypto.key_manager import generate_rsa_keys, save_private_key_to_pem, save_public_key_to_pem
import app.gui.protect_tab as protect_tab
import app.gui.verify_tab as verify_tab
import app.gui.video_tab as video_tab
from app.verification.verdicts import Verdict


def wait_for(runner, seconds=35):
    deadline = time.monotonic() + seconds
    while runner.busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.005)
    application.processEvents()
    assert not runner.busy


directory = Path(tempfile.mkdtemp(prefix="video-gui-"))
cover = directory / "cover.mkv"
created = subprocess.run([
    "ffmpeg", "-v", "error", "-y",
    "-f", "lavfi", "-i", "testsrc2=size=96x64:rate=5:duration=1",
    "-f", "lavfi", "-i", "sine=frequency=330:sample_rate=8000:duration=1",
    "-map", "0:v:0", "-map", "1:a:0", "-c:v", "ffv1", "-level", "3",
    "-pix_fmt", "bgr0", "-c:a", "pcm_s16le", str(cover)
], capture_output=True)
assert created.returncode == 0, created.stderr

private_key, public_key = generate_rsa_keys()
private_path = directory / "private.pem"
public_path = directory / "public.pem"
save_private_key_to_pem(private_key, private_path, None)
save_public_key_to_pem(public_key, public_path)

application = QApplication([])
errors = []
for module in (protect_tab, verify_tab, video_tab):
    module.QMessageBox.critical = lambda _parent, title, detail: errors.append((title, detail))
video_tab.QMessageBox.information = lambda *_args: None
video_tab.QMessageBox.question = lambda *_args: QMessageBox.StandardButton.Yes

protect = protect_tab.ProtectTab()
protect._set_input(str(cover))
protect.private_key_path.setText(str(private_path))
protect.media_id.setText("GUI-VIDEO")
protect.lsb_count.setValue(2)
protect.video_frame_index.setValue(2)
protect.start_method.setCurrentIndex(1)
protect.start_value.setText("13")
protect.message.setPlainText("video GUI payload")
protect._protect()
assert protect.runner.busy
wait_for(protect.runner)
assert not errors, errors
assert protect.status.text().startswith("Protected video created")
protected = Path(protect.output_path.text())
manifest = Path(protect.manifest_path.text())
assert protected.suffix == ".mkv" and protected.is_file() and manifest.is_file()

verify = verify_tab.VerifyTab()
verify.media_path.setText(str(protected))
verify.manifest_path.setText(str(manifest))
verify.public_key_path.setText(str(public_path))
verify._verify()
wait_for(verify.runner)
assert not errors, errors
assert verify._verified_result.verdict is Verdict.AUTHENTIC
assert verify._verified_result.message == b"video GUI payload"

video = video_tab.VideoTab()
video.video_path.setText(str(protected))
video.frame_index.setValue(2)
video._preview()
wait_for(video.runner)
assert not video.frame_preview.pixmap().isNull()
assert "5 frames" in video.video_info.text()

lossy = directory / "lossy.mkv"
evidence = directory / "lossy.json"
video.protected_path.setText(str(protected))
video.manifest_path.setText(str(manifest))
video.public_key_path.setText(str(public_path))
video.lossy_output_path.setText(str(lossy))
video.evidence_path.setText(str(evidence))
video._run_experiment()
assert video.runner.busy
wait_for(video.runner)
assert not errors, errors
assert "Actual verification verdict:" in video.result.toPlainText()
document = json.loads(evidence.read_text(encoding="utf-8"))
assert document["verification_verdict"] != "AUTHENTIC"
assert document["selected_frame"] == 2

protect.shutdown()
verify.shutdown()
video.shutdown()
'''
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
