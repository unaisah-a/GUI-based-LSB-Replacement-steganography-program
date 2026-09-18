"""Tests for the Protect and Verify tabs.

The tabs are thin by design, so these tests concentrate on the seams where a mistake
would actually cost something:

* the live capacity read-out agrees with what an embed will really do, rather than
  being an estimate that drifts
* validation refuses incomplete settings with a message naming what is missing,
  before any file is written
* the backend call receives exactly the settings that were entered
* a verdict — including ``TAMPERED`` — is shown as a result, not raised as an error
* the tab prompts for exactly the secrets the manifest says are needed

Widget geometry and styling are not tested; they say nothing about whether the
application works.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("PySide6", reason="PySide6 is required for the interface tests")

from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.errors import KeyMaterialError
from app.gui.protect_tab import ProtectTab
from app.gui.verify_tab import VerifyTab
from app.stego import image_io, media
from app.utils import constants
from app.verification import verdicts
from app.verification.protect import protect_media

from conftest import make_audio, make_cover, write_audio_file, write_cover

START_SECRET = "the start secret"
PASSPHRASE = "the passphrase"
MESSAGE = "Integrity and authenticity for INF2005."


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture()
def key_files(tmp_path, keys):
    private_key, public_key = keys
    private_path = str(tmp_path / "private.pem")
    public_path = str(tmp_path / "public.pem")
    key_manager.save_private_key(private_key, private_path)
    key_manager.save_public_key(public_key, public_path)
    return private_path, public_path


@pytest.fixture()
def png_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.PNG, "cover")


@pytest.fixture()
def wav_cover(tmp_path):
    return write_audio_file(str(tmp_path), make_audio(40_000))


@pytest.fixture()
def protect_tab(qtbot):
    tab = ProtectTab()
    qtbot.addWidget(tab)
    return tab


@pytest.fixture()
def verify_tab(qtbot):
    tab = VerifyTab()
    qtbot.addWidget(tab)
    return tab


def configure(tab: ProtectTab, cover: str, private_path: str, output: str, **options):
    """Fill in a complete, valid set of protect settings."""
    tab.drop_zone.accept_path(cover)
    tab.media_id_edit.setText(options.pop("media_id", "IMG-001"))
    tab.depth_slider.setValue(options.pop("depth", 3))
    tab.message_edit.setPlainText(options.pop("message", MESSAGE))
    tab.output_edit.setText(output)
    tab.key_edit.setText(private_path)
    tab.start_secret_edit.setText(options.pop("start_secret", START_SECRET))
    return tab


# --------------------------------------------------------------------------- #
# Protect tab
# --------------------------------------------------------------------------- #


class TestProtectTabConstruction:
    def test_it_constructs(self, protect_tab):
        assert protect_tab.TITLE == "Protect"

    def test_the_depth_control_covers_one_to_eight(self, protect_tab):
        assert protect_tab.depth_slider.minimum() == constants.MIN_LSB_DEPTH
        assert protect_tab.depth_slider.maximum() == constants.MAX_LSB_DEPTH

    def test_the_depth_label_tracks_the_slider(self, protect_tab):
        protect_tab.depth_slider.setValue(6)
        assert protect_tab.depth_label.text() == "6"

    def test_both_start_methods_are_offered(self, protect_tab):
        offered = {
            protect_tab.start_mode_combo.itemData(index)
            for index in range(protect_tab.start_mode_combo.count())
        }
        assert offered == set(constants.START_METHODS)

    def test_the_drop_zone_accepts_every_registered_medium(
        self, protect_tab, tmp_path, video_factory
    ):
        """All three now, and the list comes from the registry rather than a literal."""
        clip = video_factory(frame_count=4, name="dropped")

        assert protect_tab.drop_zone.accept_path(clip) is True
        assert set(protect_tab.drop_zone._media_types) == set(
            media.SUPPORTED_MEDIA_TYPES
        )

    def test_the_drop_zone_still_refuses_an_unsupported_file(
        self, protect_tab, tmp_path
    ):
        path = tmp_path / "notes.txt"
        path.write_bytes(b"not media at all")

        assert protect_tab.drop_zone.accept_path(str(path)) is False

    def test_a_video_cover_is_offered_a_matroska_output_name(
        self, protect_tab, video_factory
    ):
        """The output is always FFV1 in Matroska, so the suggestion must say so."""
        clip = video_factory(frame_count=4, name="clip")
        protect_tab.drop_zone.accept_path(clip)

        assert protect_tab.output_edit.text().endswith(".mkv")

    def test_secret_and_location_controls_swap_with_the_mode(self, protect_tab):
        protect_tab.start_mode_combo.setCurrentIndex(
            protect_tab.start_mode_combo.findData(constants.START_METHOD_MANUAL)
        )
        assert protect_tab.start_location_spin.isEnabled() is True
        assert protect_tab.start_secret_edit.isEnabled() is False

        protect_tab.start_mode_combo.setCurrentIndex(
            protect_tab.start_mode_combo.findData(constants.START_METHOD_HMAC)
        )
        assert protect_tab.start_location_spin.isEnabled() is False
        assert protect_tab.start_secret_edit.isEnabled() is True

    def test_the_passphrase_field_follows_the_encryption_toggle(self, protect_tab):
        assert protect_tab.passphrase_edit.isEnabled() is False
        protect_tab.encrypt_check.setChecked(True)
        assert protect_tab.passphrase_edit.isEnabled() is True


class TestProtectTabReadout:
    def test_selecting_a_cover_fills_the_information_panel(
        self, protect_tab, png_cover
    ):
        protect_tab.drop_zone.accept_path(png_cover)

        assert protect_tab.cover_path == os.path.abspath(png_cover)
        assert protect_tab.info_panel.value_for("Media type") == constants.MEDIA_IMAGE
        assert protect_tab.info_panel.value_for("Dimensions") == "96 x 96"

    def test_selecting_a_cover_proposes_an_output_path(self, protect_tab, png_cover):
        protect_tab.drop_zone.accept_path(png_cover)
        assert protect_tab.output_edit.text().endswith("cover_stego.png")

    def test_selecting_a_cover_proposes_a_media_id(self, protect_tab, png_cover):
        protect_tab.drop_zone.accept_path(png_cover)
        assert protect_tab.media_id_edit.text() == "COVER"

    def test_the_message_length_is_reported(self, protect_tab):
        protect_tab.message_edit.setPlainText("hello")
        assert protect_tab.message_length_label.text() == "5 bytes"

    def test_a_non_ascii_message_reports_its_byte_length(self, protect_tab):
        """Bytes, not characters: capacity is measured in bytes."""
        protect_tab.message_edit.setPlainText("caf\u00e9")
        assert protect_tab.message_length_label.text() == "5 bytes"

    def test_the_signature_size_follows_the_selected_key(
        self, protect_tab, key_files, qtbot
    ):
        """A 2048-bit key signs in 256 bytes, not the 384 of the default size."""
        private_path, _ = key_files
        protect_tab.key_edit.setText(private_path)
        qtbot.waitUntil(
            lambda: protect_tab._signature_size == constants.RSA_MIN_KEY_SIZE // 8
        )

    def test_the_key_is_not_read_on_every_keystroke(
        self, protect_tab, key_files, monkeypatch, qtbot
    ):
        private_path, _ = key_files
        reads = []
        original = key_manager.load_private_key
        monkeypatch.setattr(
            key_manager,
            "load_private_key",
            lambda path, **kwargs: reads.append(path) or original(path, **kwargs),
        )
        for end in range(1, len(private_path) + 1):
            protect_tab.key_edit.setText(private_path[:end])

        qtbot.waitUntil(lambda: len(reads) == 1)
        assert reads == [private_path]

    def test_an_unreadable_key_path_falls_back_to_the_default_size(
        self, protect_tab, key_files, tmp_path, qtbot
    ):
        private_path, _ = key_files
        protect_tab.key_edit.setText(private_path)
        qtbot.waitUntil(
            lambda: protect_tab._signature_size == constants.RSA_MIN_KEY_SIZE // 8
        )
        protect_tab.key_edit.setText(str(tmp_path / "absent.pem"))
        qtbot.waitUntil(
            lambda: protect_tab._signature_size == constants.RSA_KEY_SIZE_DEFAULT // 8
        )

    def test_the_predicted_payload_length_matches_a_real_one(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        """The read-out must not drift from what is actually embedded."""
        private_path, _ = key_files
        output = str(tmp_path / "out.png")
        configure(protect_tab, png_cover, private_path, output)

        predicted = protect_tab._estimated_envelope_length()
        result = protect_media(
            png_cover,
            output,
            MESSAGE.encode("utf-8"),
            key_manager.load_private_key(private_path),
            media_id="IMG-001",
            lsb_depth=3,
            start_secret=START_SECRET,
            scrypt_n=MIN_SCRYPT_N,
            scrypt_r=8,
            scrypt_p=1,
        )
        assert predicted == result.envelope_length

    def test_capacity_rises_with_depth(self, protect_tab, png_cover):
        protect_tab.drop_zone.accept_path(png_cover)

        protect_tab.depth_slider.setValue(1)
        at_one = protect_tab.info_panel.value_for("Capacity")
        protect_tab.depth_slider.setValue(8)
        at_eight = protect_tab.info_panel.value_for("Capacity")

        assert at_one != at_eight

    def test_an_oversized_message_is_reported_before_any_attempt(
        self, protect_tab, tmp_path
    ):
        small = write_cover(str(tmp_path), make_cover(16, 16, 3), image_io.PNG, "small")
        protect_tab.drop_zone.accept_path(small)
        protect_tab.depth_slider.setValue(1)
        protect_tab.message_edit.setPlainText("x" * 5_000)

        assert protect_tab.info_panel.value_for("Fits") == "no"
        assert "does not fit" in protect_tab.info_panel._notice_label.text()
        assert "largest message that fits" in protect_tab.info_panel._notice_label.text()

    def test_the_overhead_is_explained_when_it_fits(self, protect_tab, png_cover):
        protect_tab.drop_zone.accept_path(png_cover)
        protect_tab.message_edit.setPlainText(MESSAGE)

        notice = protect_tab.info_panel._notice_label.text()
        assert "record and signature" in notice

    def test_encryption_increases_the_predicted_payload(self, protect_tab, png_cover):
        protect_tab.drop_zone.accept_path(png_cover)
        protect_tab.message_edit.setPlainText(MESSAGE)

        plain = protect_tab._estimated_envelope_length()
        protect_tab.encrypt_check.setChecked(True)
        encrypted = protect_tab._estimated_envelope_length()

        assert encrypted > plain

    def test_audio_shows_audio_specific_rows(self, protect_tab, wav_cover):
        protect_tab.drop_zone.accept_path(wav_cover)

        assert protect_tab.info_panel.value_for("Sample rate") == "44,100 Hz"
        assert protect_tab.info_panel.value_for("Dimensions") is None


class TestProtectTabValidation:
    def test_no_cover_is_refused(self, protect_tab):
        assert "cover object" in protect_tab.validation_error()

    def test_a_missing_media_id_is_refused(self, protect_tab, png_cover, key_files):
        private_path, _ = key_files
        protect_tab.drop_zone.accept_path(png_cover)
        protect_tab.media_id_edit.setText("")
        protect_tab.key_edit.setText(private_path)

        assert "media ID" in protect_tab.validation_error()

    def test_a_missing_key_is_refused_and_points_at_the_menu(
        self, protect_tab, png_cover
    ):
        protect_tab.drop_zone.accept_path(png_cover)
        protect_tab.key_edit.setText("")

        problem = protect_tab.validation_error()
        assert "private key" in problem
        assert "Keys menu" in problem

    def test_a_missing_start_secret_is_refused(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(
            protect_tab, png_cover, private_path, str(tmp_path / "o.png"),
            start_secret="",
        )
        assert "start secret" in protect_tab.validation_error()

    def test_manual_mode_needs_no_secret(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(
            protect_tab, png_cover, private_path, str(tmp_path / "o.png"),
            start_secret="",
        )
        protect_tab.start_mode_combo.setCurrentIndex(
            protect_tab.start_mode_combo.findData(constants.START_METHOD_MANUAL)
        )
        assert protect_tab.validation_error() is None

    def test_encryption_without_a_passphrase_is_refused(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(protect_tab, png_cover, private_path, str(tmp_path / "o.png"))
        protect_tab.encrypt_check.setChecked(True)

        assert "passphrase" in protect_tab.validation_error()

    def test_complete_settings_pass(self, protect_tab, png_cover, key_files, tmp_path):
        private_path, _ = key_files
        configure(protect_tab, png_cover, private_path, str(tmp_path / "o.png"))
        assert protect_tab.validation_error() is None

    def test_nothing_is_written_when_validation_fails(self, protect_tab, tmp_path, monkeypatch):
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
        before = sorted(entry.name for entry in tmp_path.iterdir())
        protect_tab.protect()
        assert sorted(entry.name for entry in tmp_path.iterdir()) == before


class TestProtectTabOperation:
    def test_it_protects_a_png_and_reports_quality(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        output = str(tmp_path / "stego.png")
        configure(protect_tab, png_cover, private_path, output)

        result = protect_tab._run_protect(protect_tab._collect_inputs())
        protect_tab._on_protected(result)

        assert Path(result.stego_path).is_file()
        assert Path(result.manifest_path).is_file()
        assert protect_tab.result is result
        assert protect_tab.quality_panel.value_for("MSE") is not None
        assert protect_tab.quality_panel.value_for("PSNR") is not None

    def test_edits_after_submission_do_not_reach_the_worker(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        """The worker reads a snapshot taken on the interface thread, not the widgets."""
        private_path, _ = key_files
        output = str(tmp_path / "stego.png")
        configure(protect_tab, png_cover, private_path, output, media_id="IMG-001")

        inputs = protect_tab._collect_inputs()
        protect_tab.media_id_edit.setText("IMG-EDITED")
        protect_tab.output_edit.setText(str(tmp_path / "elsewhere.png"))
        result = protect_tab._run_protect(inputs)

        assert result.record.media_id == "IMG-001"
        assert result.stego_path == output

    def test_the_settings_reach_the_backend(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        output = str(tmp_path / "stego.png")
        configure(
            protect_tab, png_cover, private_path, output, depth=5, media_id="IMG-777"
        )

        result = protect_tab._run_protect(protect_tab._collect_inputs())

        assert result.record.lsb_depth == 5
        assert result.record.media_id == "IMG-777"
        assert result.record.start_method == constants.START_METHOD_HMAC
        assert result.manifest.start_location is None

    def test_manual_mode_signs_the_chosen_location(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(protect_tab, png_cover, private_path, str(tmp_path / "stego.png"))
        protect_tab.start_mode_combo.setCurrentIndex(
            protect_tab.start_mode_combo.findData(constants.START_METHOD_MANUAL)
        )
        protect_tab.start_location_spin.setValue(1_234)

        result = protect_tab._run_protect(protect_tab._collect_inputs())
        assert result.record.start_location == 1_234
        assert result.start_location == 1_234

    def test_encryption_is_applied_when_requested(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(protect_tab, png_cover, private_path, str(tmp_path / "stego.png"))
        protect_tab.encrypt_check.setChecked(True)
        protect_tab.passphrase_edit.setText(PASSPHRASE)

        result = protect_tab._run_protect(protect_tab._collect_inputs())

        assert result.encrypted is True
        assert MESSAGE.encode("utf-8") not in Path(result.stego_path).read_bytes()

    def test_the_required_secrets_are_stated_after_protecting(
        self, protect_tab, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(protect_tab, png_cover, private_path, str(tmp_path / "stego.png"))

        protect_tab._on_protected(protect_tab._run_protect(protect_tab._collect_inputs()))

        assert protect_tab.secrets_label.isVisibleTo(protect_tab)
        text = protect_tab.secrets_label.text()
        assert "manifest together" in text
        assert "start-location secret" in text

    def test_an_audio_cover_works_the_same_way(
        self, protect_tab, wav_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        configure(
            protect_tab, wav_cover, private_path, str(tmp_path / "stego.wav"),
            media_id="AUD-001",
        )

        result = protect_tab._run_protect(protect_tab._collect_inputs())
        protect_tab._on_protected(result)

        assert result.media_type == constants.MEDIA_AUDIO
        assert protect_tab.quality_panel.value_for("SNR") is not None

    def test_a_failure_is_reported_without_raising(
        self, protect_tab, png_cover, key_files, tmp_path, monkeypatch
    ):
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
        messages: list[str] = []
        protect_tab.statusMessage.connect(messages.append)

        protect_tab._on_protect_failed("the payload does not fit", "traceback")
        assert messages == ["the payload does not fit"]


# --------------------------------------------------------------------------- #
# Verify tab
# --------------------------------------------------------------------------- #


@pytest.fixture()
def protected(tmp_path, png_cover, keys):
    """A protected file, its manifest, and the key that verifies it."""
    private_key, public_key = keys
    public_path = str(tmp_path / "public.pem")
    key_manager.save_public_key(public_key, public_path)

    result = protect_media(
        png_cover,
        str(tmp_path / "sent.png"),
        MESSAGE.encode("utf-8"),
        private_key,
        media_id="IMG-001",
        lsb_depth=3,
        start_secret=START_SECRET,
        scrypt_n=MIN_SCRYPT_N,
        scrypt_r=8,
        scrypt_p=1,
    )
    return result, public_path, png_cover


class TestVerifyTabConstruction:
    def test_it_constructs(self, verify_tab):
        assert verify_tab.TITLE == "Verify"

    def test_it_starts_with_no_verdict(self, verify_tab):
        assert verify_tab.result is None
        assert "No verification" in verify_tab.result_panel.verdict_text


class TestVerifyTabManifestDiscovery:
    def test_the_manifest_is_found_beside_the_file(self, verify_tab, protected):
        result, _, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)

        assert verify_tab.manifest_edit.text() == result.manifest_path

    def test_a_missing_manifest_is_reported(self, verify_tab, protected):
        result, _, _ = protected
        os.unlink(result.manifest_path)
        messages: list[str] = []
        verify_tab.statusMessage.connect(messages.append)

        verify_tab.drop_zone.accept_path(result.stego_path)

        assert verify_tab.manifest_edit.text() == ""
        assert any("required to locate the payload" in text for text in messages)

    def test_the_manifest_claims_are_shown_and_labelled_unverified(
        self, verify_tab, protected
    ):
        result, _, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)

        assert verify_tab.manifest_panel.value_for("LSB depth") == "3"
        assert verify_tab.manifest_panel.value_for("Media ID") == "IMG-001"
        assert (
            verify_tab.manifest_panel.value_for("Start location")
            == "derived from the secret"
        )
        notice = verify_tab.manifest_panel._notice_label.text()
        assert "Nothing here is authenticated" in notice
        assert "signature" in notice

    def test_it_prompts_for_only_the_secrets_this_file_needs(
        self, verify_tab, protected
    ):
        """A derived start location needs a secret; an unencrypted message does not
        need a passphrase, so that field is disabled rather than misleading."""
        result, _, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)

        assert verify_tab.start_secret_edit.isEnabled() is True
        assert verify_tab.passphrase_edit.isEnabled() is False

    def test_a_malformed_manifest_is_reported_in_the_panel(
        self, verify_tab, protected
    ):
        result, _, _ = protected
        Path(result.manifest_path).write_text("{not json", encoding="utf-8")
        verify_tab.drop_zone.accept_path(result.stego_path)

        assert verify_tab.manifest_panel._notice_label.text()


class TestVerifyTabValidation:
    def test_no_file_is_refused(self, verify_tab):
        assert "stego file" in verify_tab.validation_error()

    def test_a_missing_public_key_is_refused(self, verify_tab, protected):
        result, _, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)
        verify_tab.key_edit.setText("")

        assert "public key" in verify_tab.validation_error()

    def test_a_missing_manifest_is_refused_with_an_explanation(
        self, verify_tab, protected
    ):
        result, public_path, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)
        verify_tab.key_edit.setText(public_path)
        verify_tab.manifest_edit.setText("")

        problem = verify_tab.validation_error()
        assert "companion manifest" in problem
        assert "alongside" in problem

    def test_complete_inputs_pass(self, verify_tab, protected):
        result, public_path, _ = protected
        verify_tab.drop_zone.accept_path(result.stego_path)
        verify_tab.key_edit.setText(public_path)

        assert verify_tab.validation_error() is None


class TestVerifyTabOperation:
    def _prepare(self, verify_tab, protected, *, original: bool = False):
        result, public_path, cover = protected
        verify_tab.drop_zone.accept_path(result.stego_path)
        verify_tab.key_edit.setText(public_path)
        verify_tab.start_secret_edit.setText(START_SECRET)
        if original:
            verify_tab.original_edit.setText(cover)
        return result

    def test_a_good_file_verifies(self, verify_tab, protected):
        self._prepare(verify_tab, protected)

        outcome = verify_tab._run_verify(verify_tab._collect_inputs())
        verify_tab._on_verified(outcome)

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert verify_tab.result_panel.verdict_text == verdicts.VERDICT_AUTHENTIC
        assert verify_tab.result_panel.payload_text == MESSAGE

    def test_the_checks_are_displayed(self, verify_tab, protected):
        self._prepare(verify_tab, protected)
        verify_tab._on_verified(verify_tab._run_verify(verify_tab._collect_inputs()))

        assert verify_tab.result_panel.flag_text("signature_valid") == "yes"
        assert verify_tab.result_panel.flag_text("hash_valid") == "yes"
        assert verify_tab.result_panel.flag_text("manifest_consistent") == "yes"

    def test_a_wrong_secret_is_shown_as_a_verdict_not_an_error(
        self, verify_tab, protected
    ):
        """Detecting a problem is the application working, so it goes in the panel."""
        self._prepare(verify_tab, protected)
        verify_tab.start_secret_edit.setText("the wrong secret")

        outcome = verify_tab._run_verify(verify_tab._collect_inputs())
        verify_tab._on_verified(outcome)

        assert outcome.verdict != verdicts.VERDICT_AUTHENTIC
        assert verify_tab.result_panel.verdict_text == outcome.verdict
        assert verify_tab.result is outcome

    def test_a_tampered_manifest_is_shown_as_a_verdict(self, verify_tab, protected):
        import json

        result = self._prepare(verify_tab, protected)
        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["message_length"] = data["message_length"] + 1
        Path(result.manifest_path).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_tab._run_verify(verify_tab._collect_inputs())
        verify_tab._on_verified(outcome)

        assert outcome.verdict == verdicts.VERDICT_TAMPERED
        assert verify_tab.result_panel.verdict_text == verdicts.VERDICT_TAMPERED
        assert verify_tab.result_panel.flag_text("manifest_consistent") == "no"

    def test_an_unprotected_file_reports_a_missing_payload(
        self, verify_tab, protected, tmp_path
    ):
        result = self._prepare(verify_tab, protected)
        plain = write_cover(
            str(tmp_path), make_cover(96, 96, 3, seed=5), image_io.PNG, "plain"
        )
        verify_tab.drop_zone.accept_path(plain)
        verify_tab.manifest_edit.setText(result.manifest_path)

        outcome = verify_tab._run_verify(verify_tab._collect_inputs())
        verify_tab._on_verified(outcome)

        assert outcome.verdict == verdicts.VERDICT_PAYLOAD_MISSING
        assert verify_tab.result_panel.flag_text("payload_found") == "no"
        assert verify_tab.result_panel.flag_text("signature_valid") == "not established"

    def test_the_comparison_table_appears_when_the_original_is_given(
        self, verify_tab, protected
    ):
        self._prepare(verify_tab, protected, original=True)
        verify_tab._on_verified(verify_tab._run_verify(verify_tab._collect_inputs()))

        text = verify_tab.comparison_view.toPlainText()
        assert "Original" in text
        assert "MSE" in text
        assert "should be unchanged" in text

    def test_no_comparison_without_the_original(self, verify_tab, protected):
        self._prepare(verify_tab, protected)
        verify_tab._on_verified(verify_tab._run_verify(verify_tab._collect_inputs()))
        assert verify_tab.comparison_view.toPlainText() == ""

    def test_an_unusable_key_is_reported_as_an_error(
        self, verify_tab, protected, tmp_path, monkeypatch
    ):
        """This one genuinely is exceptional: it is not about the file."""
        from PySide6.QtWidgets import QMessageBox

        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
        self._prepare(verify_tab, protected)
        verify_tab.key_edit.setText(str(tmp_path / "absent.pem"))

        with pytest.raises(KeyMaterialError, match="not found"):
            verify_tab._run_verify(verify_tab._collect_inputs())

        verify_tab._on_verify_failed("key file not found: absent.pem", "traceback")
        assert "Could not complete" in verify_tab.result_panel.verdict_text


class TestProtectThenVerifyThroughTheTabs:
    """The demonstration path, driven entirely through the two tabs."""

    def test_the_full_round_trip(
        self, qtbot, png_cover, key_files, tmp_path
    ):
        private_path, public_path = key_files
        protect = ProtectTab()
        verify = VerifyTab()
        qtbot.addWidget(protect)
        qtbot.addWidget(verify)

        configure(protect, png_cover, private_path, str(tmp_path / "sent.png"))
        result = protect._run_protect(protect._collect_inputs())
        protect._on_protected(result)

        verify.drop_zone.accept_path(result.stego_path)
        verify.key_edit.setText(public_path)
        verify.start_secret_edit.setText(START_SECRET)
        verify.original_edit.setText(png_cover)

        outcome = verify._run_verify(verify._collect_inputs())
        verify._on_verified(outcome)

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert verify.result_panel.payload_text == MESSAGE
        assert constants.AUTHENTIC_SCOPE_NOTICE in verify.result_panel._notes_label.text()

    def test_the_round_trip_with_encryption(
        self, qtbot, png_cover, key_files, tmp_path
    ):
        private_path, public_path = key_files
        protect = ProtectTab()
        verify = VerifyTab()
        qtbot.addWidget(protect)
        qtbot.addWidget(verify)

        configure(protect, png_cover, private_path, str(tmp_path / "sent.png"))
        protect.encrypt_check.setChecked(True)
        protect.passphrase_edit.setText(PASSPHRASE)
        result = protect._run_protect(protect._collect_inputs())

        verify.drop_zone.accept_path(result.stego_path)
        verify.key_edit.setText(public_path)
        verify.start_secret_edit.setText(START_SECRET)
        verify.passphrase_edit.setText(PASSPHRASE)

        outcome = verify._run_verify(verify._collect_inputs())
        verify._on_verified(outcome)

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert verify.result_panel.payload_text == MESSAGE

    def test_the_receiver_is_told_which_secrets_are_needed(
        self, qtbot, png_cover, key_files, tmp_path
    ):
        private_path, _ = key_files
        protect = ProtectTab()
        verify = VerifyTab()
        qtbot.addWidget(protect)
        qtbot.addWidget(verify)

        configure(protect, png_cover, private_path, str(tmp_path / "sent.png"))
        protect.encrypt_check.setChecked(True)
        protect.passphrase_edit.setText(PASSPHRASE)
        result = protect._run_protect(protect._collect_inputs())
        protect._on_protected(result)

        assert "message passphrase" in protect.secrets_label.text()

        verify.drop_zone.accept_path(result.stego_path)
        assert verify.passphrase_edit.isEnabled() is True
        assert verify.start_secret_edit.isEnabled() is True
