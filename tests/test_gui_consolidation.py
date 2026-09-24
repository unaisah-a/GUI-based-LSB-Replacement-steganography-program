"""T04 regressions at GUI trust, worker and input boundaries."""
import threading

import pytest
from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl
from PySide6.QtGui import QDropEvent
from PySide6.QtWidgets import QFileDialog

from app.crypto import key_manager
from app.gui.attack_tab import AttackTab
from app.gui.protect_tab import ProtectTab
from app.gui.steganalysis_tab import SteganalysisTab
from app.gui.verify_tab import VerifyTab
from app.gui.widgets.drop_zone import DropZone
from app.stego import image_io
from app.utils import constants
from app.verification.verdicts import VerificationResult

from conftest import make_cover, write_cover


@pytest.fixture
def cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.PNG, "cover")


def widget(qtbot, cls):
    tab = cls()
    qtbot.addWidget(tab)
    return tab


def drop(zone, urls):
    mime = QMimeData()
    mime.setUrls(urls)
    event = QDropEvent(QPointF(5, 5), Qt.DropAction.CopyAction, mime,
                       Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    zone.dropEvent(event)


@pytest.mark.parametrize("kind", ["valid", "missing", "directory", "unsupported"])
def test_picker_and_drop_use_identical_validation(qtbot, cover, tmp_path, monkeypatch, kind):
    bad = tmp_path / "bad.txt"
    bad.write_text("not media", encoding="utf-8")
    path = {"valid": cover, "missing": str(tmp_path / "absent.png"),
            "directory": str(tmp_path), "unsupported": str(bad)}[kind]
    picker = widget(qtbot, DropZone)
    dropped = widget(qtbot, DropZone)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a: (path, ""))
    picker.open_file_dialog()
    drop(dropped, [QUrl.fromLocalFile(path)])
    assert picker.selected_path == dropped.selected_path
    assert (picker.selected_path is not None) == (kind == "valid")


@pytest.mark.parametrize("urls", ["remote", "mixed", "multiple"])
def test_ambiguous_or_remote_drop_preserves_previous_selection(qtbot, cover, urls):
    zone = widget(qtbot, DropZone)
    zone.accept_path(cover)
    local = QUrl.fromLocalFile(cover)
    remote = QUrl("https://example.com/file.png")
    rejected = []
    zone.selectionRejected.connect(rejected.append)
    drop(zone, {"remote": [remote], "mixed": [local, remote], "multiple": [local, local]}[urls])
    assert rejected
    assert zone.selected_path == cover


@pytest.mark.parametrize("verdict", [v for v in constants.VERDICTS if v != constants.VERDICT_AUTHENTIC])
def test_failed_verdict_never_displays_or_saves_attached_plaintext(qtbot, tmp_path, verdict):
    tab = widget(qtbot, VerifyTab)
    tab._on_verified(VerificationResult(verdict=constants.VERDICT_AUTHENTIC,
                                     reason="verified", message=b"previous"))
    assert tab.result_panel.save_enabled
    tab._on_verified(VerificationResult(verdict=verdict, reason="failure", message=b"untrusted"))
    assert not tab.result_panel.save_enabled
    assert tab.result_panel.payload_text == ""
    assert tab.payload_preview_path is None
    output = tmp_path / "must-not-exist.bin"
    with pytest.raises(OSError):
        tab.result_panel.save_payload(str(output))
    assert not output.exists()


def test_capacity_accounts_for_manual_offset(qtbot, cover):
    tab = widget(qtbot, ProtectTab)
    tab.drop_zone.accept_path(cover)
    tab.start_mode_combo.setCurrentIndex(tab.start_mode_combo.findData(constants.START_METHOD_MANUAL))
    tab.depth_slider.setValue(1)
    qtbot.waitUntil(lambda: not tab.capacity_busy)
    assert tab.info_panel.value_for("Fits") == "yes"
    tab.start_location_spin.setValue(96 * 96 * 3 - 100)
    qtbot.waitUntil(lambda: not tab.capacity_busy)
    assert tab.info_panel.value_for("Fits") == "no"
    assert "start" in tab.info_panel._notice_label.text()


def test_capacity_worker_ignores_superseded_result(qtbot, cover, monkeypatch):
    tab = widget(qtbot, ProtectTab)
    started, release = threading.Event(), threading.Event()
    real = tab._measure_capacity
    threads = []
    applied = []
    real_apply = tab._apply_capacity

    def measure(*args):
        threads.append(threading.get_ident())
        started.set()
        release.wait(5)
        return real(*args)

    def apply(generation, *args):
        if generation == tab._capacity_generation:
            applied.append(generation)
        return real_apply(generation, *args)

    monkeypatch.setattr(tab, "_measure_capacity", measure)
    monkeypatch.setattr(tab, "_apply_capacity", apply)
    tab.drop_zone.accept_path(cover)
    try:
        qtbot.waitUntil(started.is_set)
        tab.depth_slider.setValue(8)
        current = tab._capacity_generation
    finally:
        release.set()
    qtbot.waitUntil(lambda: not tab.capacity_busy, timeout=10000)
    assert applied == [current]
    assert all(t != threading.get_ident() for t in threads)
    assert len(threads) == 2


@pytest.mark.parametrize("cls,attr", [(ProtectTab, "_cover_path"), (VerifyTab, "_stego_path"),
                                     (AttackTab, "_stego_path"), (SteganalysisTab, "_path")])
def test_clear_forgets_tab_input(qtbot, cover, cls, attr):
    tab = widget(qtbot, cls)
    tab.drop_zone.accept_path(cover)
    tab.drop_zone.clear()
    assert getattr(tab, attr) is None
    assert tab.validation_error() is not None


def test_verification_result_for_old_input_is_discarded(qtbot, cover, tmp_path, monkeypatch):
    tab = widget(qtbot, VerifyTab)
    tab.drop_zone.accept_path(cover)
    tab.key_edit.setText("key.pem")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    tab.manifest_edit.setText(str(manifest))
    callbacks = {}
    monkeypatch.setattr(tab._runner, "submit", lambda *a, **kw: callbacks.update(kw))
    tab.verify()
    tab.key_edit.setText("different.pem")
    callbacks["on_success"](VerificationResult(verdict=constants.VERDICT_AUTHENTIC,
                                              reason="old input", message=b"old"))
    callbacks["on_finished"]()
    assert tab.result is None
    assert not tab.result_panel.save_enabled


def test_sender_receiver_fingerprints_match(qtbot, tmp_path):
    private, public = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    private_path, public_path = str(tmp_path / "private.pem"), str(tmp_path / "public.pem")
    key_manager.save_private_key(private, private_path)
    key_manager.save_public_key(public, public_path)
    sender = widget(qtbot, ProtectTab)
    receiver = widget(qtbot, VerifyTab)
    sender.key_edit.setText(private_path)
    receiver.key_edit.setText(public_path)
    fingerprint = key_manager.public_key_fingerprint(public)
    qtbot.waitUntil(lambda: fingerprint in sender.fingerprint_label.text())
    qtbot.waitUntil(lambda: fingerprint in receiver.fingerprint_label.text())


def test_cut_controls_are_absent(qtbot):
    attack = widget(qtbot, AttackTab)
    analysis = widget(qtbot, SteganalysisTab)
    for name in ("run_all_button", "bit_error_spin", "manifest_field_combo"):
        assert not hasattr(attack, name)
    assert not hasattr(analysis, "scaled_check")
