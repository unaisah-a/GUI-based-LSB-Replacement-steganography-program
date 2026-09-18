import os
import subprocess
import sys


def test_offscreen_analysis_gui_renders_image_audio_and_exports():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = r'''
import json
import tempfile
import time
from pathlib import Path

import numpy as np
import soundfile as sf
from PySide6.QtWidgets import QApplication

import app.gui.steganalysis_tab as analysis_tab
from app.stego import image_io
from app.stego.audio_stego import embed_audio_lsb
from app.stego.image_stego import embed_image


def wait_for(runner):
    deadline = time.monotonic() + 20
    while runner.busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.002)
    application.processEvents()
    assert not runner.busy


directory = Path(tempfile.mkdtemp(prefix="analysis-gui-"))
image = directory / "original.png"
protected_image = directory / "protected.png"
pixels = np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3)
image_io.save_image(pixels, image, image_io.PNG)
embed_image(image, protected_image, b"GUI analysis", 2, 7)

audio = directory / "original.wav"
protected_audio = directory / "protected.wav"
samples = ((np.arange(6000 * 2) * 29) % 50000 - 25000).astype(np.int16).reshape(6000, 2)
sf.write(audio, samples, 16000, subtype="PCM_16")
embed_audio_lsb(audio, protected_audio, b"GUI analysis", 2, 7)

application = QApplication([])
errors = []
analysis_tab.QMessageBox.critical = lambda _parent, title, detail: errors.append((title, detail))
analysis_tab.QMessageBox.information = lambda *_args: None

for index, (original, modified, media_type) in enumerate((
    (image, protected_image, "image"),
    (audio, protected_audio, "audio"),
)):
    tab = analysis_tab.SteganalysisTab()
    tab.original.setText(str(original))
    tab.modified.setText(str(modified))
    tab.lsb_count.setValue(2)
    tab.experiment_bytes.setValue(12)
    tab.listening_observation.setText("No audible difference in a quiet-room check.")
    tab._compare()
    assert tab.runner.busy
    wait_for(tab.runner)
    assert not errors, errors
    assert tab._bundle is not None
    assert tab._bundle.media_type == media_type
    text = tab.report.toPlainText()
    assert "SHA-256" in text
    assert "CONTROLLED LSB-DEPTH EXPERIMENT" in text
    assert "not claimed to be invariably" in text
    assert tab.export_button.isEnabled()
    if media_type == "image":
        assert not tab.original_lsb.pixmap().isNull()
        assert not tab.modified_lsb.pixmap().isNull()
        assert not tab.difference.pixmap().isNull()
        assert not tab.histogram.pixmap().isNull()
        assert tab.views.isTabEnabled(1)
        assert not tab.views.isTabEnabled(2)
    else:
        assert not tab.waveforms.pixmap().isNull()
        assert not tab.audio_difference.pixmap().isNull()
        assert not tab.views.isTabEnabled(1)
        assert tab.views.isTabEnabled(2)

    report = directory / f"{media_type}-analysis.json"
    analysis_tab.QFileDialog.getSaveFileName = lambda *_args, value=str(report): (value, "JSON")
    tab._export()
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["media_type"] == media_type
    assert len(document["depth_experiment"]["rows"]) == 8
    if media_type == "audio":
        assert document["listening_observation"].startswith("No audible difference")
    tab.shutdown()
'''
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
