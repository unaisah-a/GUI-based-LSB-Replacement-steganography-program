"""Capture real Qt results after fresh verification; no mocked outcomes or demo claims."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

from app.gui.main_window import MainWindow
from app.utils import constants
from main import load_stylesheet
from scripts.verify_submission_samples import ROOT, write_json


def capture(root=ROOT, output=None, report_path=None):
    root = Path(root).resolve()
    output = Path(output or root / "evidence/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.glob("*.png")):
        raise FileExistsError("Screenshot output already contains captures")
    index = json.loads((root / "evidence/case-index.json").read_text())
    app = QApplication.instance() or QApplication([])
    # Windows offscreen Qt does not automatically discover installed fonts.
    if os.name == "nt":
        fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "consolab.ttf"):
            if QFontDatabase.addApplicationFont(str(fonts / name)) < 0:
                raise RuntimeError(f"Could not load capture font: {name}")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(load_stylesheet())
    window = MainWindow()
    window.resize(1600, 1600)
    window.show()
    captures = []

    def wait(predicate):
        deadline = time.monotonic() + 30
        while not predicate():
            if time.monotonic() > deadline:
                raise TimeoutError("GUI operation did not finish")
            QTest.qWait(20)
        QTest.qWait(150)

    def save(identifier, verdict):
        page = window.tabs.currentWidget()
        # Capture the full actual tab, including content below the normal viewport.
        height = max(1200, page.widget().minimumSizeHint().height() + 120)
        window.resize(1600, height)
        QTest.qWait(200)
        for _ in range(5):
            dx, dy = page.horizontalScrollBar().maximum(), page.verticalScrollBar().maximum()
            if not dx and not dy:
                break
            window.resize(window.width() + dx + 10, window.height() + dy + 10)
            QTest.qWait(150)
        if page.horizontalScrollBar().maximum() or page.verticalScrollBar().maximum():
            raise RuntimeError("Capture still clips tab contents")
        path = output / (identifier + ".png")
        if not window.grab().save(str(path)):
            raise RuntimeError(f"Cannot save screenshot {path}")
        captures.append(dict(id=identifier, file=path.name, result=verdict,
                             width=window.width(), height=window.height(),
                             horizontal_overflow=page.horizontalScrollBar().maximum(),
                             vertical_overflow=page.verticalScrollBar().maximum()))

    try:
        window.tabs.setCurrentIndex(1)
        tab = window.verify_tab
        for case in index["cases"]:
            if not case.get("screenshot"):
                continue
            tab.drop_zone.accept_path(str(root / case["media"]))
            tab.manifest_edit.setText(str(root / case["manifest"]))
            tab.key_edit.setText(str(root / case["public_key"]))
            tab.start_secret_edit.setText(case.get("start_secret") or "")
            tab.passphrase_edit.setText(case.get("passphrase") or "")
            tab.original_edit.setText(str(root / case["cover"]))
            if tab.validation_error():
                raise RuntimeError(tab.validation_error())
            tab.verify_button.click()
            wait(lambda: tab.result is not None and tab._runner.active_count == 0)
            if tab.result.verdict not in case["expected_verdicts"]:
                raise RuntimeError(f"Unexpected GUI verdict for {case['id']}")
            save(case["id"], tab.result.verdict)
            print(f"Captured {case['id']}", flush=True)
        window.tabs.setCurrentIndex(0)
        tab = window.protect_tab
        for case in index["capacity_cases"]:
            window.set_status("")
            tab.drop_zone.accept_path(str(root / case["cover"]))
            tab.key_edit.setText(str(root / "keys/demo_private/demo_private.pem"))
            tab.media_id_edit.setText(case["id"])
            tab.output_edit.setText(str(root / "samples/protected" / ("capacity-rejected" + Path(case["cover"]).suffix)))
            tab.depth_slider.setValue(case["depth"])
            tab.start_mode_combo.setCurrentIndex(tab.start_mode_combo.findData(constants.START_METHOD_MANUAL))
            tab.start_location_spin.setValue(case["start"])
            tab.set_payload_file(str(root / case["payload"]))
            wait(lambda: not tab.capacity_busy and not tab._key_read_timer.isActive())
            text = " ".join(label.text() for label in tab.info_panel.findChildren(QLabel))
            if "does not fit" not in text:
                raise RuntimeError("Capacity refusal is not visible")
            save(case["id"], "Does not fit; sender rejection separately verified")
        window.set_status("")
        window.tabs.setCurrentIndex(3)
        tab = window.video_tab
        case = next(c for c in index["cases"] if c["id"] == "video-text")
        tab.drop_zone.accept_path(str(root / case["media"]))
        wait(lambda: tab.descriptor is not None and tab._runner.active_count == 0)
        tab.manifest_edit.setText(str(root / case["manifest"]))
        tab.secret_edit.setText(case["start_secret"])
        tab.locate_payload()
        wait(lambda: tab.span is not None)
        save("video-properties", "Payload span located; authentication captured separately")
    finally:
        window.close()
        app.processEvents()
    report = dict(mode="Automated real Qt app captures using the offscreen platform",
                  mocked_results=False, earlier_demo_evidence=False, native_playback_tested=False,
                  captures=captures)
    write_json(report_path or root / "evidence/logs/gui-captures.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    print(json.dumps(dict(captures=len(capture(args.root, args.output, args.report)["captures"]))))
