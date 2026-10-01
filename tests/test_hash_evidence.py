"""H03 trust boundaries, exported evidence and GUI invalidation."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QMessageBox

from app.attacks import registry
from app.crypto import envelope, key_manager, payload, signatures
from app.crypto import manifest as manifest_module
from app.crypto.encryption import MIN_SCRYPT_N
from app.gui.attack_tab import AttackTab
from app.gui.main_window import MainWindow
from app.gui.verify_tab import VerifyTab
from app.gui.widgets.result_panel import ResultPanel
from app.stego import image_io, media
from app.utils import constants
from app.verification import verifier
from app.verification.protect import protect_media
from app.verification.verdicts import HashEvidence
from main import load_stylesheet

from conftest import make_cover, write_cover

START_SECRET = "H03 test start secret"
PASSPHRASE = "H03 test passphrase"


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture
def protected(tmp_path, keys, request):
    cover = write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.PNG, "cover")
    message = image_io.encode_image(make_cover(8, 8, 3, "flat"), image_io.PNG)
    result = protect_media(
        cover, tmp_path / "stego.png", message, keys[0], media_id="H03",
        lsb_depth=3, start_secret=START_SECRET,
        passphrase=PASSPHRASE if getattr(request, "param", False) else None,
        scrypt_n=MIN_SCRYPT_N, scrypt_r=8, scrypt_p=1,
    )
    return result, message


def verify(protected, keys, **changes):
    result, _ = protected
    options = {"start_secret": START_SECRET, "passphrase": PASSPHRASE}
    options.update(changes)
    return verifier.verify_media(result.stego_path, result.manifest_path, keys[1], **options)


def change_manifest_hash(protected):
    result, _ = protected
    changed = replace(result.manifest, message_hash="00" * 32)
    manifest_module.write_manifest(changed, result.manifest_path, overwrite=True)
    return changed


@pytest.mark.parametrize("protected", [False, True], indirect=True)
def test_manifest_only_hash_tamper_withholds_plaintext(protected, keys):
    result, message = protected
    assert verify(protected, keys).authentic
    changed = change_manifest_hash(protected)
    assert manifest_module.cross_check(changed, result.record) == ("message_hash",)
    outcome = verify(protected, keys)
    assert outcome.verdict == constants.VERDICT_TAMPERED
    assert outcome.signature_valid is outcome.hash_valid is True
    assert outcome.manifest_consistent is False
    assert outcome.mismatched_fields == ("message_hash",)
    assert "message_hash" in outcome.reason
    assert outcome.message is None
    evidence = outcome.hash_evidence
    assert evidence.computed_hash == hashlib.sha256(message).hexdigest()
    assert evidence.payload_matches_manifest is False
    assert evidence.manifest_matches_record is False
    assert evidence.payload_matches_record is True


@pytest.mark.parametrize("protected", [True], indirect=True)
@pytest.mark.parametrize("tamper", [False, True])
def test_decryption_failure_keeps_signature_evidence(protected, keys, tamper):
    if tamper:
        change_manifest_hash(protected)
    outcome = verify(protected, keys, passphrase="wrong passphrase")
    assert outcome.verdict == constants.VERDICT_CANNOT_VERIFY
    assert outcome.details["stage"] == "decryption"
    assert outcome.signature_valid is True
    assert outcome.hash_valid is None
    assert outcome.message is None
    evidence = outcome.hash_evidence
    assert evidence.signed_record_hash == protected[0].record.message_hash
    assert evidence.manifest_matches_record is (not tamper)
    assert evidence.computed_hash is None
    assert evidence.as_dict()["payload_matches_manifest"] == "Not performed"


@pytest.mark.parametrize("attack", ["payload.message", "payload.signature", "verification.wrong_key"])
@pytest.mark.parametrize("protected", [True], indirect=True)
def test_signature_failure_never_recovers_or_trusts_record(
    protected, keys, tmp_path, monkeypatch, attack,
):
    context = registry.context_from_protect_result(protected[0], str(tmp_path / "attacked.png"))
    run = registry.run_attack(attack, context, keys[1], start_secret=START_SECRET, passphrase=PASSPHRASE)
    outcome = run.after
    assert outcome.verdict == constants.VERDICT_SIGNATURE_INVALID
    assert outcome.hash_evidence.manifest_hash == protected[0].manifest.message_hash
    assert outcome.hash_evidence.signed_record_hash is None
    assert outcome.hash_evidence.computed_hash is None
    assert outcome.hash_evidence.as_dict()["manifest_matches_record"] == "Not performed"

    # Direct receiver call: even a mismatching manifest cannot mask the signature failure.
    def unexpected(*args, **kwargs):
        pytest.fail("plaintext recovery happened before the signature passed")

    monkeypatch.setattr(payload, "recover_message", unexpected)
    _, wrong_key = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    change_manifest_hash(protected)
    failed = verifier.verify_media(
        protected[0].stego_path, protected[0].manifest_path, wrong_key,
        start_secret=START_SECRET, passphrase=PASSPHRASE,
    )
    assert failed.verdict == constants.VERDICT_SIGNATURE_INVALID
    assert failed.hash_evidence.computed_hash is None


def test_wrong_start_keeps_only_external_claim(protected, keys):
    outcome = verify(protected, keys, start_secret="wrong secret")
    assert not outcome.authentic
    evidence = outcome.hash_evidence
    assert evidence.manifest_hash == protected[0].manifest.message_hash
    assert evidence.signed_record_hash is evidence.computed_hash is None
    assert evidence.payload_matches_manifest is evidence.manifest_matches_record is None


def test_signed_but_changed_plaintext_retains_computed_digest(protected, keys):
    result, _ = protected
    extracted = media.extract(result.stego_path, result.record.lsb_depth, result.start_location)
    parsed = envelope.parse_envelope(extracted)
    changed = b"changed plaintext with a valid signature"
    signed = signatures.sign_envelope(parsed.record_bytes, changed, keys[0])
    outcome = verifier.verify_extracted_payload(signed, keys[1], manifest=result.manifest)
    assert outcome.verdict == constants.VERDICT_TAMPERED
    assert outcome.hash_valid is False
    assert outcome.message is None
    assert outcome.hash_evidence.computed_hash == hashlib.sha256(changed).hexdigest()
    assert outcome.hash_evidence.payload_matches_manifest is False
    assert outcome.hash_evidence.payload_matches_record is False
    assert outcome.hash_evidence.manifest_matches_record is True


def test_no_manifest_does_not_invent_external_hash(protected, keys):
    result, message = protected
    extracted = media.extract(result.stego_path, result.record.lsb_depth, result.start_location)
    outcome = verifier.verify_extracted_payload(extracted, keys[1])
    assert outcome.authentic
    assert outcome.hash_evidence.computed_hash == hashlib.sha256(message).hexdigest()
    assert outcome.hash_evidence.manifest_hash is None
    assert outcome.hash_evidence.payload_matches_manifest is None
    assert outcome.hash_evidence.manifest_matches_record is None


@pytest.mark.parametrize("attack", [
    "payload.message", "payload.signature", "verification.wrong_key",
    "verification.wrong_start", "image.outside",
])
def test_attack_exports_have_hash_evidence_without_secrets(protected, keys, tmp_path, attack):
    context = registry.context_from_protect_result(protected[0], str(tmp_path / "attacked.png"))
    run = registry.run_attack(attack, context, keys[1], start_secret=START_SECRET)
    summary = run.as_dict()
    assert summary["hash_evidence_before"]["payload_matches_manifest"] == "Yes"
    expected = "Yes" if attack == "image.outside" else "Not performed"
    assert summary["hash_evidence_after"]["payload_matches_manifest"] == expected
    if attack == "image.outside":
        assert run.after.authentic
        assert run.after.details["file_digest_matches"] is False
    text = "\n".join([json.dumps(summary), run.as_text(), AttackTab._describe(run),
                      json.dumps(run.before.as_dict())])
    assert "SHA-256" in text
    assert protected[0].record.message_hash in text
    assert START_SECRET not in text and PASSPHRASE not in text
    assert "PRIVATE KEY" not in text and "PUBLIC KEY" not in text


def make_tab(qtbot, cls):
    tab = cls()
    qtbot.addWidget(tab)
    return tab


def test_tamper_clears_existing_preview_and_blocks_save(qtbot, protected, keys, tmp_path):
    tab = make_tab(qtbot, VerifyTab)
    tab._on_verified(verify(protected, keys))
    assert tab.payload_preview_path is not None
    old_preview = Path(tab.payload_preview_path)
    change_manifest_hash(protected)
    tab._on_verified(verify(protected, keys))
    assert tab.result_panel.hash_panel.value_for("Payload matches manifest") == "No"
    assert tab.result_panel.hash_panel.value_for("Manifest hash matches signed record") == "No"
    assert tab.result_panel.flag_text("signature_valid") == "yes"
    assert tab.result_panel.flag_text("hash_valid") == "yes"
    assert tab.payload_preview_path is None and not old_preview.exists()
    assert not tab.result_panel.save_enabled and not tab.result_panel.payload_text
    with pytest.raises(OSError):
        tab.result_panel.save_payload(str(tmp_path / "withheld.bin"))


@pytest.mark.parametrize("field", ["manifest_edit", "key_edit", "start_secret_edit", "passphrase_edit", "file"])
def test_verify_input_changes_clear_hashes(qtbot, protected, keys, field):
    tab = make_tab(qtbot, VerifyTab)
    tab._on_verified(verify(protected, keys))
    assert tab.result_panel.hash_panel.labels
    if field == "file":
        tab._on_stego_selected(protected[0].stego_path)
    else:
        getattr(tab, field).setText("changed input")
    assert not tab.result_panel.hash_panel.labels
    assert tab.result is None
    assert tab.payload_preview_path is None


def test_typed_manifest_summary_refreshes_and_is_unverified(qtbot, protected, tmp_path):
    tab = make_tab(qtbot, VerifyTab)
    tab.manifest_edit.setText(protected[0].manifest_path)
    label = "Payload SHA-256 (unverified)"
    assert tab.manifest_panel.value_for(label) == protected[0].manifest.message_hash
    assert "unverified" in tab.manifest_panel.title()
    assert not tab.result_panel.hash_panel.labels
    tab.manifest_edit.setText(str(tmp_path / "missing.json"))
    assert tab.manifest_panel.value_for(label) is None


def test_shared_panel_full_hashes_selectable_and_unknown_status(qtbot, protected, keys):
    panel = make_tab(qtbot, ResultPanel)
    outcome = verify(protected, keys)
    panel.show_result(outcome)
    expected = protected[0].record.message_hash
    for label in ["Expected payload SHA-256 - manifest", "Authenticated record SHA-256", "Recomputed payload SHA-256"]:
        widget = panel.hash_panel._rows[label]
        assert widget.text() == expected
        assert widget.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse
        assert widget.wordWrap()
    panel.show_result(replace(outcome, hash_evidence=HashEvidence()))
    assert panel.hash_panel.value_for("Payload matches manifest") == "Not performed"
    assert panel.hash_panel.value_for("Recomputed payload SHA-256") == "Unavailable"
    panel.show_error("failed")
    assert not panel.hash_panel.labels


@pytest.mark.parametrize("kind,width", [("verify", 900), ("verify", 1180), ("attack", 1180)])
def test_hashes_fit_native_sized_window(qtbot, protected, keys, tmp_path, width, kind):
    window = MainWindow()
    qtbot.addWidget(window)
    window.setStyleSheet(load_stylesheet())
    window.resize(width, 820)
    tab = window.verify_tab if kind == "verify" else window.attack_tab
    window.tabs.setCurrentIndex(1 if kind == "verify" else 2)
    tab._on_stego_selected(protected[0].stego_path)
    if kind == "verify":
        tab._on_verified(verify(protected, keys))
        panel = tab.result_panel.hash_panel
    else:
        context = registry.context_from_protect_result(protected[0], str(tmp_path / "outside.png"))
        tab._on_attack_finished(registry.run_attack(
            "image.outside", context, keys[1], start_secret=START_SECRET))
        panel = tab.hash_panel
    window.show()
    page = window.tabs.currentWidget()
    qtbot.waitUntil(lambda: page.horizontalScrollBar().maximum() == 0)
    for field in panel._rows.values():
        assert field.width() > 0
        assert field.height() >= field.heightForWidth(field.width())
        assert field.geometry().right() < panel.width()
    assert panel.value_for("Recomputed payload SHA-256") == protected[0].record.message_hash
    window.close()


@pytest.mark.parametrize("field", ["manifest_edit", "key_edit", "start_secret_edit", "passphrase_edit", "file"])
def test_attack_input_changes_clear_current_evidence(qtbot, protected, keys, tmp_path, field):
    tab = make_tab(qtbot, AttackTab)
    context = registry.context_from_protect_result(protected[0], str(tmp_path / "outside.png"))
    run = registry.run_attack("image.outside", context, keys[1], start_secret=START_SECRET)
    tab._on_attack_finished(run)
    assert tab.hash_panel.value_for("Payload matches manifest") == "Yes"
    if field == "file":
        tab._on_stego_selected(protected[0].stego_path)
    else:
        getattr(tab, field).setText("changed input")
    assert not tab.hash_panel.labels
    assert not tab.summary_panel.labels
    # Completed runs remain labelled historical evidence in the accumulated log.
    assert "Payload hash evidence before:" in tab.log_view.toPlainText()


def test_saved_attack_log_contains_both_hash_results(qtbot, protected, keys, tmp_path, monkeypatch):
    tab = make_tab(qtbot, AttackTab)
    context = registry.context_from_protect_result(protected[0], str(tmp_path / "outside.png"))
    run = registry.run_attack("image.outside", context, keys[1], start_secret=START_SECRET)
    tab._on_attack_finished(run)
    destination = tmp_path / "attack.txt"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: (str(destination), ""))
    tab._save_log()
    text = destination.read_text(encoding="utf-8")
    assert "Payload hash evidence before:" in text and "Payload hash evidence after:" in text
    assert "Payload matches manifest: Yes" in text
    assert START_SECRET not in text


def test_failed_verification_clears_stale_hashes(qtbot, protected, keys, monkeypatch):
    tab = make_tab(qtbot, VerifyTab)
    tab._on_verified(verify(protected, keys))
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: None)
    tab._on_verify_failed("cannot load key", "")
    assert tab.result is None and not tab.result_panel.hash_panel.labels
    assert tab.payload_preview_path is None


def test_text_evidence_never_serialises_plaintext_or_passphrase(keys, caplog):
    message = b"H03 UNIQUE CONFIDENTIAL PLAINTEXT"
    prepared = payload.prepare_payload(
        message, keys[0], media_id="H03", media_type=constants.MEDIA_IMAGE,
        lsb_depth=3, passphrase=PASSPHRASE,
        scrypt_n=MIN_SCRYPT_N, scrypt_r=8, scrypt_p=1,
    )
    manifest = manifest_module.Manifest.from_record(
        prepared.record, envelope_length=prepared.envelope_length,
        container_format=constants.CONTAINER_PNG,
    )
    outcome = verifier.verify_extracted_payload(
        prepared.envelope, keys[1], manifest=manifest, passphrase=PASSPHRASE,
    )
    assert outcome.authentic
    text = json.dumps(outcome.as_dict()) + outcome.hash_evidence.as_text() + caplog.text
    assert message.decode() not in text
    assert PASSPHRASE not in text
    assert "PRIVATE KEY" not in text
    assert hashlib.sha256(message).hexdigest() in text


@pytest.mark.parametrize("kind", ["verify", "attack"])
def test_pending_worker_cannot_restore_hashes_after_input_change(
    qtbot, protected, keys, tmp_path, monkeypatch, kind,
):
    tab = make_tab(qtbot, VerifyTab if kind == "verify" else AttackTab)
    tab._on_stego_selected(protected[0].stego_path)
    public_path = tmp_path / "public.pem"
    key_manager.save_public_key(keys[1], public_path)
    tab.key_edit.setText(str(public_path))
    tab.start_secret_edit.setText(START_SECRET)
    callbacks = {}

    def submit(*args, **kwargs):
        callbacks.update(kwargs)

    monkeypatch.setattr(tab._runner, "submit", submit)
    if kind == "verify":
        result = verify(protected, keys)
        tab._on_verified(result)
        tab.verify()
        assert not tab.result_panel.hash_panel.labels
    else:
        context = registry.context_from_protect_result(protected[0], str(tmp_path / "outside.png"))
        result = registry.run_attack("image.outside", context, keys[1], start_secret=START_SECRET)
        tab.run_selected_attack()
    tab.key_edit.setText("a different key")
    callbacks["on_success"](result)
    callbacks["on_finished"]()
    panel = tab.result_panel.hash_panel if kind == "verify" else tab.hash_panel
    assert not panel.labels
