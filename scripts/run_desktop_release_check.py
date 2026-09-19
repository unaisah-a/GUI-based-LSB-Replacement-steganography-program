"""Exercise receiver workflows through Qt and capture R12 screenshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QPixmap
from PySide6.QtWidgets import QApplication

import app.gui.verify_tab as verify_tab_module
from app.gui.main_window import MainWindow


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _wait(application: QApplication, tab, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while tab.runner.busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.005)
    application.processEvents()
    if tab.runner.busy:
        raise TimeoutError("desktop verification did not finish before the timeout")


def _save_screenshot(
    application: QApplication, window: MainWindow, destination: Path, platform_name: str
) -> dict[str, object]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    window.raise_()
    window.activateWindow()
    for _ in range(100):
        application.processEvents()
        time.sleep(0.01)
    window.repaint()
    for _ in range(10):
        application.processEvents()
        time.sleep(0.01)
    pixmap = QPixmap(window.size())
    pixmap.fill(Qt.GlobalColor.white)
    window.render(pixmap)
    if pixmap.isNull() or not pixmap.save(str(destination), "PNG"):
        raise RuntimeError(f"could not save screenshot: {destination.name}")
    return {
        "file": destination.name,
        "bytes": destination.stat().st_size,
        "sha256": _sha256(destination),
    }


def run_desktop_check(
    receiver_root: str | os.PathLike[str],
    screenshot_directory: str | os.PathLike[str],
    *,
    allow_offscreen: bool = False,
) -> dict[str, object]:
    receiver = Path(receiver_root).resolve()
    screenshots = Path(screenshot_directory).resolve()
    index = json.loads((receiver / "case-index.json").read_text(encoding="utf-8"))
    secrets = json.loads(
        (receiver / index["demo_secrets"]).read_text(encoding="utf-8")
    )
    cases = {case["id"]: case for case in index["cases"]}
    application = QApplication.instance() or QApplication([])
    platform_name = QGuiApplication.platformName()
    if platform_name == "offscreen" and not allow_offscreen:
        raise RuntimeError("native desktop check cannot use the offscreen Qt platform")
    errors: list[tuple[str, str]] = []
    original_critical = verify_tab_module.QMessageBox.critical
    verify_tab_module.QMessageBox.critical = (
        lambda _parent, title, detail: errors.append((title, str(detail)))
    )
    window = MainWindow()
    window.show()
    window.raise_()
    window.activateWindow()
    window.tabs.setCurrentIndex(1)
    application.processEvents()
    tab = window.verify_tab
    outcomes: list[dict[str, object]] = []
    screenshot_records: list[dict[str, object]] = []
    try:
        checks = (
            ("image-short-positive", "r12-image-authentic.png"),
            ("audio-long-positive", "r12-audio-authentic.png"),
            ("image-message-corruption-negative", "r12-image-rejected.png"),
        )
        for case_id, screenshot_name in checks:
            case = cases[case_id]
            tab._set_media(str(receiver / case["media_path"]))
            tab.manifest_path.setText(str(receiver / case["manifest_path"]))
            tab.public_key_path.setText(str(receiver / index["public_key"]))
            start_ref = case.get("start_secret_ref")
            tab.start_secret.setText(
                "" if start_ref is None else secrets["start_secrets"][start_ref]
            )
            tab.encryption_key.clear()
            tab._update_key_fingerprint()
            tab._verify()
            _wait(application, tab)
            if errors:
                raise RuntimeError(f"desktop GUI reported an error: {errors[-1][1]}")
            actual = tab.results.verdict.text()
            expected = case["expected_verdict"]
            passed = actual == expected
            if not passed:
                raise RuntimeError(
                    f"{case_id} displayed {actual!r}; expected {expected!r}"
                )
            outcomes.append(
                {
                    "id": case_id,
                    "medium": case["medium"],
                    "expected_verdict": expected,
                    "actual_verdict": actual,
                    "passed": passed,
                }
            )
            application.processEvents()
            screenshot_records.append(
                _save_screenshot(
                    application, window, screenshots / screenshot_name, platform_name
                )
            )
    finally:
        window.close()
        application.processEvents()
        verify_tab_module.QMessageBox.critical = original_critical
    screen = application.primaryScreen()
    geometry = None
    if screen is not None:
        available = screen.availableGeometry()
        geometry = {"width": available.width(), "height": available.height()}
    return {
        "format": "SMIV-DESKTOP-AUDIT",
        "version": 1,
        "qt_platform": platform_name,
        "native_platform_required": not allow_offscreen,
        "screen_available_geometry": geometry,
        "window": {"width": window.width(), "height": window.height()},
        "cases": outcomes,
        "screenshots": screenshot_records,
        "all_passed": all(case["passed"] for case in outcomes),
        "contains_secret_values": False,
    }


def _write_report(report: dict[str, object], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    handle, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receiver", type=Path, default=PROJECT_ROOT / "samples" / "r11" / "receiver"
    )
    parser.add_argument(
        "--screenshots",
        type=Path,
        default=PROJECT_ROOT / "evidence" / "screenshots",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "evidence" / "results" / "r12-desktop-audit.json",
    )
    parser.add_argument("--allow-offscreen", action="store_true")
    args = parser.parse_args(argv)
    report = run_desktop_check(
        args.receiver, args.screenshots, allow_offscreen=args.allow_offscreen
    )
    _write_report(report, args.output)
    print(
        f"Desktop audit passed on Qt platform {report['qt_platform']}: "
        f"{len(report['cases'])} cases."
    )
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
