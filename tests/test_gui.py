import os
import subprocess
import sys


def test_main_window_exposes_project_workflows():
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    code = """
from PySide6.QtWidgets import QApplication
from app.gui.main_window import MainWindow
application = QApplication([])
window = MainWindow()
assert window.tabs.count() == 5
assert [window.tabs.tabText(index) for index in range(5)] == [
    "Protect", "Verify", "Attack Lab", "Analysis", "Video"
]
assert "signed record" in window.statusBar().currentMessage()
window.close()
"""
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
