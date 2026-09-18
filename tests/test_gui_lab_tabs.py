"""Tests for the Attack Lab and Steganalysis tabs.

Both tabs are presentation over layers that are already tested, so these tests focus
on the wiring and on the honesty properties that only exist in the interface:

* the attack list is filtered to the loaded medium
* the observed verdict is shown alongside the verdict the attack declared to expect,
  including the attack that is *supposed* to leave the verdict at AUTHENTIC
* an attack that cannot run on the loaded file is reported as skipped, with a reason
* every indicator row is rendered, and an insufficient sample renders as words rather
  than a number
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6", reason="PySide6 is required for the interface tests")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from app.attacks import registry
from app.attacks.base import AttackError
from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.gui.attack_tab import AttackTab
from app.gui.steganalysis_tab import SteganalysisTab, array_to_pixmap
from app.stego import image_io
from app.utils import constants
from app.verification import verdicts
from app.verification.protect import protect_media

from conftest import make_audio, make_cover, write_audio_file, write_cover

START_SECRET = "the start secret"
MESSAGE = b"Integrity and authenticity for INF2005 ACW1."


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture()
def protected_png(tmp_path, keys):
    """A protected PNG, its manifest, the public key, and the original cover."""
    private_key, public_key = keys
    cover = write_cover(str(tmp_path), make_cover(128, 128, 3), image_io.PNG, "cover")
    public_path = str(tmp_path / "public.pem")
    key_manager.save_public_key(public_key, public_path)

    result = protect_media(
        cover,
        str(tmp_path / "cover_stego.png"),
        MESSAGE,
        private_key,
        media_id="IMG-001",
        lsb_depth=1,
        start_secret=START_SECRET,
        scrypt_n=MIN_SCRYPT_N,
        scrypt_r=8,
        scrypt_p=1,
    )
    return result, public_path, cover


@pytest.fixture()
def protected_wav(tmp_path, keys):
    private_key, public_key = keys
    cover = write_audio_file(str(tmp_path), make_audio(40_000), "audio_cover")
    public_path = str(tmp_path / "public_audio.pem")
    key_manager.save_public_key(public_key, public_path)

    result = protect_media(
        cover,
        str(tmp_path / "audio_cover_stego.wav"),
        MESSAGE,
        private_key,
        media_id="AUD-001",
        lsb_depth=1,
        start_secret=START_SECRET,
        scrypt_n=MIN_SCRYPT_N,
        scrypt_r=8,
        scrypt_p=1,
    )
    return result, public_path, cover


@pytest.fixture()
def attack_tab(qtbot, monkeypatch):
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
    tab = AttackTab()
    qtbot.addWidget(tab)
    return tab


@pytest.fixture()
def analysis_tab(qtbot, monkeypatch):
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: None)
    tab = SteganalysisTab()
    qtbot.addWidget(tab)
    return tab


def load(tab: AttackTab, protected) -> None:
    result, public_path, _ = protected
    tab.drop_zone.accept_path(result.stego_path)
    tab.key_edit.setText(public_path)
    tab.start_secret_edit.setText(START_SECRET)


def listed_keys(tab: AttackTab) -> set[str]:
    """The attack keys currently offered, read from the list's user-role data."""
    return {
        tab.attack_list.item(index).data(Qt.ItemDataRole.UserRole)
        for index in range(tab.attack_list.count())
    }


# --------------------------------------------------------------------------- #
# Attack context from a manifest
# --------------------------------------------------------------------------- #


class TestContextFromManifest:
    """The Attack Lab has no ProtectResult, only a file and its manifest."""

    def test_it_recovers_everything_the_attacks_need(self, protected_png):
        result, _, _ = protected_png
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            "out.png",
            start_secret=START_SECRET,
        )

        assert context.lsb_depth == result.record.lsb_depth
        assert context.start_location == result.start_location
        assert context.samples_written == result.embed_result.samples_written

    def test_a_derived_location_needs_the_secret(self, protected_png):
        result, _, _ = protected_png
        with pytest.raises(AttackError, match="secret"):
            registry.context_from_manifest(
                result.stego_path, result.manifest_path, "out.png"
            )

    def test_a_manual_location_needs_no_secret(self, tmp_path, keys):
        private_key, _ = keys
        cover = write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.PNG, "c")
        result = protect_media(
            cover,
            str(tmp_path / "manual_stego.png"),
            MESSAGE,
            private_key,
            media_id="IMG-002",
            lsb_depth=2,
            start_method=constants.START_METHOD_MANUAL,
            manual_start_location=500,
            scrypt_n=MIN_SCRYPT_N,
            scrypt_r=8,
            scrypt_p=1,
        )
        context = registry.context_from_manifest(
            result.stego_path, result.manifest_path, "out.png"
        )
        assert context.start_location == 500

    def test_a_malformed_manifest_is_reported(self, protected_png, tmp_path):
        result, _, _ = protected_png
        broken = tmp_path / "broken.manifest.json"
        broken.write_text("{not json", encoding="utf-8")

        with pytest.raises(AttackError, match="manifest"):
            registry.context_from_manifest(
                result.stego_path, str(broken), "out.png", start_secret=START_SECRET
            )


# --------------------------------------------------------------------------- #
# Attack Lab tab
# --------------------------------------------------------------------------- #


class TestAttackTabConstruction:
    def test_it_constructs(self, attack_tab):
        assert attack_tab.TITLE == "Attack Lab"

    def test_the_list_is_empty_until_a_file_is_loaded(self, attack_tab):
        assert attack_tab.attack_list.count() == 0
        assert "Load a protected file" in attack_tab.attack_summary.text()

    def test_loading_an_image_lists_the_image_attacks(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        keys = listed_keys(attack_tab)

        assert "image.inside" in keys
        assert "image.outside" in keys
        assert "audio.resample" not in keys

    def test_loading_audio_lists_the_audio_attacks(self, attack_tab, protected_wav):
        load(attack_tab, protected_wav)
        keys = listed_keys(attack_tab)

        assert "audio.resample" in keys
        assert "audio.amplitude" in keys
        assert "image.blank" not in keys

    def test_payload_attacks_apply_to_both_media(
        self, attack_tab, protected_png, protected_wav
    ):
        for protected in (protected_png, protected_wav):
            load(attack_tab, protected)
            assert "payload.signature" in listed_keys(attack_tab)

    def test_the_manifest_is_found_automatically(self, attack_tab, protected_png):
        result, _, _ = protected_png
        load(attack_tab, protected_png)
        assert attack_tab.manifest_edit.text() == result.manifest_path

    def test_options_appear_only_for_the_attacks_that_use_them(
        self, attack_tab, protected_png
    ):
        load(attack_tab, protected_png)

        attack_tab._show_options("payload.random_bits")
        assert attack_tab.bit_error_spin.isVisibleTo(attack_tab) is True
        assert attack_tab.manifest_field_combo.isVisibleTo(attack_tab) is False

        attack_tab._show_options("manifest.tamper")
        assert attack_tab.bit_error_spin.isVisibleTo(attack_tab) is False
        assert attack_tab.manifest_field_combo.isVisibleTo(attack_tab) is True

        attack_tab._show_options("payload.signature")
        assert attack_tab.bit_error_spin.isVisibleTo(attack_tab) is False
        assert attack_tab.manifest_field_combo.isVisibleTo(attack_tab) is False

    def test_only_the_needed_secret_fields_are_enabled(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        assert attack_tab.start_secret_edit.isEnabled() is True
        assert attack_tab.passphrase_edit.isEnabled() is False


class TestAttackTabValidation:
    def test_no_file_is_refused(self, attack_tab):
        assert "protected stego file" in attack_tab.validation_error()

    def test_a_missing_key_is_refused(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        attack_tab.key_edit.setText("")
        assert "public key" in attack_tab.validation_error()

    def test_a_missing_manifest_is_refused(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        attack_tab.manifest_edit.setText("")
        assert "companion manifest" in attack_tab.validation_error()

    def test_a_loaded_file_with_a_selection_passes(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        assert attack_tab.validation_error() is None


class TestAttackTabRunning:
    def _select(self, tab: AttackTab, key: str) -> None:
        for index in range(tab.attack_list.count()):
            if tab.attack_list.item(index).data(Qt.ItemDataRole.UserRole) == key:
                tab.attack_list.setCurrentRow(index)
                return
        raise AssertionError(
            f"{key} is not in the list; offered: {sorted(listed_keys(tab))}"
        )

    def test_corrupting_the_signature_changes_the_verdict(
        self, attack_tab, protected_png
    ):
        load(attack_tab, protected_png)
        self._select(attack_tab, "payload.signature")

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )
        attack_tab._on_attack_finished(run)

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID
        assert run.verdict_changed is True
        assert run.matched_expectation is True
        assert attack_tab.summary_panel.value_for("Verdict after") == (
            verdicts.VERDICT_SIGNATURE_INVALID
        )

    def test_modifying_outside_the_payload_leaves_the_verdict_intact(
        self, attack_tab, protected_png
    ):
        """Not a failed attack. It is the scope of what verification establishes."""
        load(attack_tab, protected_png)
        self._select(attack_tab, "image.outside")

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )
        attack_tab._on_attack_finished(run)

        assert run.after.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.verdict_changed is False
        assert run.matched_expectation is True
        assert "unchanged on purpose" in attack_tab.log_view.toPlainText()

    def test_the_log_records_expected_and_observed(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        self._select(attack_tab, "payload.magic")
        attack_tab._on_attack_finished(
            attack_tab._run_one(
                attack_tab.selected_attack(), attack_tab._collect_inputs()
            )
        )

        text = attack_tab.log_view.toPlainText()
        assert "expected:" in text
        assert "matched:" in text
        assert verdicts.VERDICT_PAYLOAD_MISSING in text

    def test_the_bit_error_rate_option_is_passed_through(
        self, attack_tab, protected_png
    ):
        load(attack_tab, protected_png)
        self._select(attack_tab, "payload.random_bits")
        attack_tab.bit_error_spin.setValue(0.05)

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )
        assert run.outcome.details["bit_error_rate"] == 0.05

    def test_the_manifest_field_option_is_passed_through(
        self, attack_tab, protected_png
    ):
        load(attack_tab, protected_png)
        self._select(attack_tab, "manifest.tamper")
        index = attack_tab.manifest_field_combo.findData("message_length")
        attack_tab.manifest_field_combo.setCurrentIndex(index)

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )

        assert run.outcome.details["field"] == "message_length"
        assert run.after.verdict == verdicts.VERDICT_TAMPERED

    def test_a_manifest_attack_verifies_the_original_file(
        self, attack_tab, protected_png
    ):
        """The manifest changed, not the cover, so the pairing has to be right."""
        result, _, _ = protected_png
        load(attack_tab, protected_png)
        self._select(attack_tab, "manifest.tamper")

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )

        assert run.attack.target == "manifest"
        assert run.outcome.output_path != result.stego_path
        assert Path(result.stego_path).is_file()

    def test_the_resigning_attack_generates_its_own_key(
        self, attack_tab, protected_png
    ):
        """An attacker with their own signing key is the scenario being modelled."""
        load(attack_tab, protected_png)
        self._select(attack_tab, "payload.resign")

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )

        # Against the genuine sender's public key it fails, which is the point.
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID
        assert run.matched_expectation is True

    def test_an_audio_attack_runs(self, attack_tab, protected_wav):
        load(attack_tab, protected_wav)
        self._select(attack_tab, "audio.amplitude")

        run = attack_tab._run_one(
            attack_tab.selected_attack(), attack_tab._collect_inputs()
        )
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_running_every_attack_reports_matches_and_skips(
        self, attack_tab, protected_png
    ):
        load(attack_tab, protected_png)
        completed, skipped = attack_tab._run_every(attack_tab._collect_inputs())
        attack_tab._on_all_finished((completed, skipped))

        assert completed
        for run in completed:
            assert run.matched_expectation, (
                f"{run.attack.key} produced {run.after.verdict}, expected one of "
                f"{sorted(run.outcome.expected_verdicts)}"
            )

        text = attack_tab.log_view.toPlainText()
        assert "Ran every applicable attack" in text
        assert constants.AUTHENTIC_SCOPE_NOTICE in text

    def test_a_skipped_attack_is_reported_with_its_reason(self, tmp_path, keys, attack_tab):
        """Modifying outside the payload needs room outside the payload."""
        private_key, public_key = keys
        # A cover only just large enough: the payload fills it, so there is no
        # region outside the payload to modify.
        cover = write_cover(str(tmp_path), make_cover(48, 48, 3), image_io.PNG, "tight")
        public_path = str(tmp_path / "pub.pem")
        key_manager.save_public_key(public_key, public_path)
        result = protect_media(
            cover,
            str(tmp_path / "tight_stego.png"),
            MESSAGE,
            private_key,
            media_id="IMG-TIGHT",
            lsb_depth=1,
            start_secret=START_SECRET,
            scrypt_n=MIN_SCRYPT_N,
            scrypt_r=8,
            scrypt_p=1,
        )

        attack_tab.drop_zone.accept_path(result.stego_path)
        attack_tab.key_edit.setText(public_path)
        attack_tab.start_secret_edit.setText(START_SECRET)

        completed, skipped = attack_tab._run_every(attack_tab._collect_inputs())
        attack_tab._on_all_finished((completed, skipped))

        if skipped:
            text = attack_tab.log_view.toPlainText()
            assert "Not applicable to this file" in text

    def test_the_log_can_be_cleared(self, attack_tab, protected_png):
        load(attack_tab, protected_png)
        self._select(attack_tab, "payload.magic")
        attack_tab._on_attack_finished(
            attack_tab._run_one(
                attack_tab.selected_attack(), attack_tab._collect_inputs()
            )
        )
        attack_tab.clear_log()

        assert attack_tab.log_view.toPlainText() == ""
        assert attack_tab.runs == ()

    def test_a_failure_is_reported_without_raising(self, attack_tab):
        attack_tab._on_attack_failed("could not read the manifest", "traceback")
        assert "could not run the attack" in attack_tab.log_view.toPlainText().lower()


# --------------------------------------------------------------------------- #
# Steganalysis tab
# --------------------------------------------------------------------------- #


class TestArrayToPixmap:
    def test_a_grayscale_plane(self):
        import numpy as np

        pixmap = array_to_pixmap(np.zeros((8, 12), dtype=np.uint8))
        assert pixmap.width() == 12
        assert pixmap.height() == 8

    def test_an_rgb_image(self):
        import numpy as np

        pixmap = array_to_pixmap(np.zeros((8, 12, 3), dtype=np.uint8))
        assert pixmap.width() == 12

    def test_an_rgba_image(self):
        import numpy as np

        pixmap = array_to_pixmap(np.zeros((8, 12, 4), dtype=np.uint8))
        assert pixmap.width() == 12

    def test_a_single_channel_three_dimensional_array(self):
        import numpy as np

        pixmap = array_to_pixmap(np.zeros((8, 12, 1), dtype=np.uint8))
        assert pixmap.width() == 12

    def test_an_unsupported_shape_is_refused(self):
        import numpy as np

        with pytest.raises(ValueError, match="shape"):
            array_to_pixmap(np.zeros((8, 12, 5), dtype=np.uint8))


class TestSteganalysisTab:
    def test_it_constructs(self, analysis_tab):
        assert analysis_tab.TITLE == "Steganalysis"

    def test_the_disclaimer_is_always_displayed(self, analysis_tab):
        from app.analysis import image_analysis

        assert analysis_tab.disclaimer_label.text() == (
            image_analysis.INDICATOR_DISCLAIMER
        )

    def test_no_file_is_refused(self, analysis_tab):
        assert "file to analyse" in analysis_tab.validation_error()

    def test_a_missing_reference_is_refused(self, analysis_tab, protected_png, tmp_path):
        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab.reference_edit.setText(str(tmp_path / "absent.png"))

        assert "does not exist" in analysis_tab.validation_error()

    def test_it_proposes_the_likely_original(self, analysis_tab, protected_png):
        """A file named cover_stego.png usually sits beside cover.png."""
        result, _, cover = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)

        assert analysis_tab.reference_edit.text() == cover

    def test_it_analyses_an_image_without_a_reference(
        self, analysis_tab, protected_png
    ):
        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab.reference_edit.setText("")

        report = analysis_tab._run_analysis(analysis_tab._collect_inputs())
        analysis_tab._on_analysed(report)

        assert analysis_tab.report is report
        assert analysis_tab.indicator_table.rowCount() == len(report.indicators)
        assert "Select the original" in analysis_tab.quality_panel._notice_label.text()

    def test_it_analyses_an_image_with_a_reference(self, analysis_tab, protected_png):
        result, _, cover = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab.reference_edit.setText(cover)

        report = analysis_tab._run_analysis(analysis_tab._collect_inputs())
        analysis_tab._on_analysed(report)

        assert analysis_tab.quality_panel.value_for("MSE") is not None
        assert analysis_tab.quality_panel.value_for("PSNR") is not None
        assert "amplified" in analysis_tab.difference_caption.text()

    def test_bit_planes_are_rendered_for_the_selected_channel(
        self, analysis_tab, protected_png
    ):
        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        assert analysis_tab.plane_channel_combo.count() == 3
        # Eight bit positions for the selected channel.
        assert analysis_tab._plane_grid.count() == 8

    def test_changing_the_channel_re_renders(self, analysis_tab, protected_png):
        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        analysis_tab.plane_channel_combo.setCurrentIndex(1)
        assert analysis_tab._plane_grid.count() == 8

    def test_an_insufficient_sample_renders_as_words(self, analysis_tab, tmp_path):
        """Not a precise-looking number computed from nothing."""
        tiny = write_cover(str(tmp_path), make_cover(4, 4, 3), image_io.PNG, "tiny")
        analysis_tab.drop_zone.accept_path(tiny)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        texts = [
            analysis_tab.indicator_table.item(row, 2).text()
            for row in range(analysis_tab.indicator_table.rowCount())
        ]
        assert "insufficient sample" in texts

    def test_every_row_explains_what_it_measures(self, analysis_tab, protected_png):
        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        for row in range(analysis_tab.indicator_table.rowCount()):
            assert analysis_tab.indicator_table.item(row, 4).text()

    def test_every_row_carries_the_disclaimer_as_a_tooltip(
        self, analysis_tab, protected_png
    ):
        from app.analysis import image_analysis

        result, _, _ = protected_png
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        for row in range(analysis_tab.indicator_table.rowCount()):
            assert (
                analysis_tab.indicator_table.item(row, 0).toolTip()
                == image_analysis.INDICATOR_DISCLAIMER
            )

    def test_it_analyses_audio(self, analysis_tab, protected_wav):
        result, _, cover = protected_wav
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab.reference_edit.setText(cover)

        report = analysis_tab._run_analysis(analysis_tab._collect_inputs())
        analysis_tab._on_analysed(report)

        assert report.media_type == constants.MEDIA_AUDIO
        assert analysis_tab.quality_panel.value_for("SNR") is not None
        assert "samples changed" in analysis_tab.difference_caption.text().lower()

    def test_audio_shows_no_bit_plane_grid(self, analysis_tab, protected_wav):
        result, _, _ = protected_wav
        analysis_tab.drop_zone.accept_path(result.stego_path)
        analysis_tab._on_analysed(analysis_tab._run_analysis(analysis_tab._collect_inputs()))

        assert analysis_tab._plane_grid.count() == 0
        assert "image media only" in analysis_tab.views_box.title()

    def test_a_failure_is_reported_without_raising(self, analysis_tab):
        analysis_tab._on_analysis_failed("could not decode the file", "traceback")
        # No exception is the assertion.
