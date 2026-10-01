"""Check installed pins and the real offscreen entry point."""

from __future__ import annotations

import importlib.metadata as md
import json
import os
import platform
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from packaging.requirements import Requirement  # noqa: E402
from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

import main  # noqa: E402


def probe():
    pins = []
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        req = Requirement(line)
        version = md.version(req.name)
        if not req.specifier.contains(version):
            raise RuntimeError(f"Dependency pin mismatch: {req.name} {version}")
        pins.append({"name": req.name, "version": version})
    original_exec = QApplication.exec

    def timed_exec(self):
        QTimer.singleShot(1000, self.quit)
        return original_exec()

    with patch.object(QApplication, "exec", timed_exec), patch.object(
        main, "configure_logging", lambda: None
    ):
        exit_code = main.main(["release-startup-probe"])
    if exit_code != 0:
        raise RuntimeError(f"Application startup failed: {exit_code}")
    return {"python": platform.python_version(), "platform": platform.platform(),
            "pins": pins,
            "startup": "PASS", "mode": "offscreen", "exit_code": exit_code,
            "native_playback_or_drop_tested": False}


if __name__ == "__main__":
    print(json.dumps(probe(), indent=2))
