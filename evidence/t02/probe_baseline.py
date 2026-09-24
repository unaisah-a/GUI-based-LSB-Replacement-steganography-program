"""Read-only T02 environment, committed-sample and offscreen startup probe.
Run from the repository root: .venv/Scripts/python evidence/t02/probe_baseline.py
No source/sample regeneration or signing-key generation is performed.
"""
import importlib.metadata as md
import json
import os
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from packaging.requirements import Requirement  # noqa: E402

pins = []
for line in (ROOT / 'requirements.txt').read_text().splitlines():
    if not line.strip() or line.startswith('#'):
        continue
    req = Requirement(line)
    version = md.version(req.name)
    assert req.specifier.contains(version), (req.name, version)
    pins.append({'name': req.name, 'version': version})
print(json.dumps({'python': platform.python_version(), 'platform': platform.platform(), 'pins': pins}), flush=True)

from app.verification.verifier import verify_media  # noqa: E402

key = ROOT / 'keys/public/samples_public.pem'
for relative in ['samples/images/stego/cover_stego.png', 'samples/audio/stego/stego.wav', 'samples/video/stego/cover_stego.mkv']:
    result = verify_media(ROOT / relative, None, str(key), start_secret='demo-start-secret')
    print(json.dumps({'sample': relative, 'verdict': result.verdict, 'reason': result.reason}), flush=True)
    assert result.verdict == 'AUTHENTIC'

from unittest.mock import patch  # noqa: E402

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import main  # noqa: E402

original_exec = QApplication.exec

def timed_exec(self):
    QTimer.singleShot(1000, self.quit)
    return original_exec()

# Exercise the real entry point without creating application log files.
with patch.object(QApplication, 'exec', timed_exec), patch.object(main, 'configure_logging', lambda: None):
    exit_code = main.main(['t02-startup-probe'])
assert exit_code == 0
print(json.dumps({'startup': 'PASS', 'mode': 'offscreen', 'exit_code': exit_code, 'native_playback_or_drop_tested': False}), flush=True)
