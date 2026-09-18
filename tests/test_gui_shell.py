"""Tests for the application shell: the window, the shared widgets and the worker.

These run headless. ``tests/conftest.py`` sets ``QT_QPA_PLATFORM=offscreen`` before
PySide6 is imported, so no display is needed.

What is worth testing in a user interface, and what is not
----------------------------------------------------------
Asserting on pixel positions or widget geometry is brittle and says nothing about
whether the application works. What these tests cover instead:

* the window constructs and has the tabs the plan specifies
* the drop zone accepts and rejects the right files, by content
* the worker reports both success and failure, and turns an exception into a message
  rather than losing it
* the result panel never renders recovered content as rich text, which is the one
  place a hostile payload could otherwise act

The last of those is a security property, not a cosmetic one, so it gets several
tests.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("PySide6", reason="PySide6 is required for the interface tests")

from PySide6.QtWidgets import QTabWidget

from app.crypto.errors import ManifestError
from app.gui.main_window import MainWindow
from app.gui.widgets.drop_zone import DropZone, file_dialog_filter
from app.gui.widgets.file_info_panel import FileInfoPanel
from app.gui.widgets.media_preview import MediaPreview
from app.gui.widgets.result_panel import ResultPanel, hex_dump
from app.gui.workers import BackgroundRunner, Worker, describe_exception
from app.stego import image_io, media
from app.stego.errors import CapacityError
from app.utils import constants, file_utils
from app.verification.verdicts import VerificationResult
from conftest import make_audio, make_cover, write_audio_file, write_cover


@pytest.fixture()
def png_file(tmp_path):
    return write_cover(str(tmp_path), make_cover(48, 48, 3), image_io.PNG, "cover")


@pytest.fixture()
def wav_file(tmp_path):
    return write_audio_file(str(tmp_path), make_audio(4_000))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


class TestEntryPoint:
    def test_main_module_imports_without_starting_qt(self):
        """Importing must not create a QApplication as a side effect."""
        import main

        assert callable(main.main)
        assert callable(main.load_stylesheet)

    def test_the_stylesheet_is_present_and_loads(self):
        import main

        assert main.STYLESHEET_PATH.is_file()
        assert main.load_stylesheet().strip()

    def test_a_missing_stylesheet_is_not_fatal(self, monkeypatch, tmp_path):
        """Cosmetic failures must not stop the application from starting."""
        import main

        monkeypatch.setattr(main, "STYLESHEET_PATH", tmp_path / "absent.qss")
        assert main.load_stylesheet() == ""

    def test_the_stylesheet_covers_every_verdict_style(self):
        """A verdict with no rule would render with no colour at all."""
        import main

        text = main.load_stylesheet()
        for style in ("authentic", "failed", "unknown"):
            assert f'verdict="{style}"' in text


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #


class TestMainWindow:
    def test_it_constructs(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        assert window.windowTitle()

    def test_it_has_the_five_tabs_from_the_plan(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)

        titles = [window.tabs.tabText(index) for index in range(window.tabs.count())]
        assert titles == [
            "Protect",
            "Verify",
            "Attack Lab",
            "Steganalysis",
            "Video",
        ]

    def test_every_tab_is_a_real_widget(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)

        for index in range(window.tabs.count()):
            assert window.tabs.widget(index) is not None

    def test_the_tab_widget_is_styleable(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        assert window.tabs.objectName() == "mainTabs"
        assert isinstance(window.tabs, QTabWidget)

    def test_the_status_bar_starts_ready(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        assert window.status_text == "Ready"

    def test_status_can_be_updated(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        window.set_status("Working")
        assert window.status_text == "Working"

    def test_the_key_and_help_menus_exist(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)

        titles = [action.text() for action in window.menuBar().actions()]
        assert "&Keys" in titles
        assert "&Help" in titles

    def test_key_actions_are_present(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        assert window.generate_keys_action.isEnabled()
        assert window.show_key_paths_action is not None

    def test_closing_an_idle_window_does_not_block(self, qtbot):
        window = MainWindow()
        qtbot.addWidget(window)
        window.close()
        assert not window.isVisible()


class TestTabs:
    """Every tab is now a real one; nothing in the window is a placeholder."""

    @pytest.mark.parametrize(
        "attribute",
        ["protect_tab", "verify_tab", "attack_tab", "steganalysis_tab", "video_tab"],
    )
    def test_each_tab_declares_a_title(self, qtbot, attribute):
        window = MainWindow()
        qtbot.addWidget(window)
        assert getattr(window, attribute).TITLE

    @pytest.mark.parametrize(
        "attribute",
        ["protect_tab", "verify_tab", "attack_tab", "steganalysis_tab", "video_tab"],
    )
    def test_each_tab_reports_progress_to_the_status_bar(self, qtbot, attribute):
        """A tab with no statusMessage signal was a placeholder; none are left."""
        window = MainWindow()
        qtbot.addWidget(window)
        assert hasattr(getattr(window, attribute), "statusMessage")


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #


class TestWorker:
    def test_a_successful_call_emits_its_result(self, qtbot):
        worker = Worker(lambda value: value * 2, 21)
        received: list[object] = []
        worker.signals.succeeded.connect(received.append)

        worker.run()
        assert received == [42]

    def test_a_failing_call_emits_a_message_and_a_traceback(self, qtbot):
        def explode():
            raise CapacityError("the payload does not fit")

        worker = Worker(explode)
        failures: list[tuple[str, str]] = []
        worker.signals.failed.connect(lambda message, detail: failures.append((message, detail)))

        worker.run()

        assert len(failures) == 1
        message, detail = failures[0]
        assert message == "the payload does not fit"
        assert "CapacityError" in detail

    def test_finished_is_emitted_on_success_and_on_failure(self, qtbot):
        for function in (lambda: 1, lambda: 1 / 0):
            worker = Worker(function)
            finished: list[bool] = []
            worker.signals.finished.connect(lambda: finished.append(True))
            worker.run()
            assert finished == [True]

    def test_an_exception_never_escapes_the_worker(self, qtbot):
        """There is no caller left on that stack to catch it."""
        worker = Worker(lambda: 1 / 0)
        worker.signals.failed.connect(lambda message, detail: None)
        worker.run()  # must not raise

    def test_keyword_arguments_are_passed_through(self, qtbot):
        worker = Worker(lambda a, b=0: a + b, 1, b=2)
        received: list[object] = []
        worker.signals.succeeded.connect(received.append)
        worker.run()
        assert received == [3]


class TestDescribeException:
    def test_application_errors_are_used_as_written(self):
        """Their messages are already written to be read by a user."""
        assert (
            describe_exception(CapacityError("the payload does not fit"))
            == "the payload does not fit"
        )

    def test_manifest_errors_are_used_as_written(self):
        assert describe_exception(ManifestError("manifest is missing")) == (
            "manifest is missing"
        )

    def test_unexpected_errors_get_their_type_named(self):
        """A bare KeyError message tells a user nothing on its own."""
        assert describe_exception(KeyError("nonce")) == "KeyError: 'nonce'"

    def test_an_empty_message_still_names_the_type(self):
        assert "RuntimeError" in describe_exception(RuntimeError())


class TestBackgroundRunner:
    def test_it_runs_a_task_and_reports_the_result(self, qtbot):
        runner = BackgroundRunner(max_thread_count=1)
        received: list[object] = []

        runner.submit(lambda: "done", on_success=received.append)
        assert runner.wait(10_000)
        qtbot.waitUntil(lambda: received == ["done"], timeout=5_000)

    def test_it_reports_a_failure(self, qtbot):
        runner = BackgroundRunner(max_thread_count=1)
        failures: list[str] = []

        def explode():
            raise CapacityError("no room")

        runner.submit(explode, on_error=lambda message, detail: failures.append(message))
        assert runner.wait(10_000)
        qtbot.waitUntil(lambda: failures == ["no room"], timeout=5_000)

    def test_the_active_count_returns_to_zero(self, qtbot):
        runner = BackgroundRunner(max_thread_count=2)
        runner.submit(lambda: None)
        runner.submit(lambda: None)
        assert runner.wait(10_000)
        qtbot.waitUntil(lambda: runner.active_count == 0, timeout=5_000)


# --------------------------------------------------------------------------- #
# Drop zone
# --------------------------------------------------------------------------- #


class TestDropZone:
    def test_it_accepts_a_supported_image(self, qtbot, png_file):
        zone = DropZone()
        qtbot.addWidget(zone)
        selected: list[str] = []
        zone.fileSelected.connect(selected.append)

        assert zone.accept_path(png_file) is True
        assert selected == [os.path.abspath(png_file)]
        assert zone.selected_path == os.path.abspath(png_file)

    def test_it_accepts_a_supported_audio_file(self, qtbot, wav_file):
        zone = DropZone()
        qtbot.addWidget(zone)
        assert zone.accept_path(wav_file) is True

    def test_it_rejects_an_unsupported_file_with_a_reason(self, qtbot, tmp_path):
        zone = DropZone()
        qtbot.addWidget(zone)
        rejections: list[str] = []
        zone.selectionRejected.connect(rejections.append)

        junk = tmp_path / "junk.dat"
        junk.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        assert zone.accept_path(str(junk)) is False
        assert len(rejections) == 1
        assert "junk.dat" in rejections[0]
        assert zone.selected_path is None

    def test_it_names_a_lossy_format_and_says_why(self, qtbot, tmp_path):
        zone = DropZone()
        qtbot.addWidget(zone)
        rejections: list[str] = []
        zone.selectionRejected.connect(rejections.append)

        photo = tmp_path / "photo.jpg"
        photo.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32)
        zone.accept_path(str(photo))

        assert "JPEG" in rejections[0]
        assert "lossy" in rejections[0]

    def test_it_rejects_a_missing_file(self, qtbot, tmp_path):
        zone = DropZone()
        qtbot.addWidget(zone)
        assert zone.accept_path(str(tmp_path / "absent.png")) is False

    def test_it_restricts_to_the_configured_media_types(self, qtbot, wav_file):
        """An image-only panel must refuse audio, and say so."""
        zone = DropZone(media_types=[constants.MEDIA_IMAGE])
        qtbot.addWidget(zone)
        rejections: list[str] = []
        zone.selectionRejected.connect(rejections.append)

        assert zone.accept_path(wav_file) is False
        assert "audio" in rejections[0]
        assert "image" in rejections[0]

    def test_detection_is_by_content_not_extension(self, qtbot, tmp_path):
        """A PNG named .wav is an image and must be accepted by an image panel."""
        zone = DropZone(media_types=[constants.MEDIA_IMAGE])
        qtbot.addWidget(zone)

        misleading = tmp_path / "confusing.wav"
        misleading.write_bytes(image_io.encode_image(make_cover(16, 16, 3), image_io.PNG))

        assert zone.accept_path(str(misleading)) is True

    def test_clearing_forgets_the_selection(self, qtbot, png_file):
        zone = DropZone()
        qtbot.addWidget(zone)
        zone.accept_path(png_file)
        zone.clear()
        assert zone.selected_path is None

    def test_it_accepts_drops(self, qtbot):
        zone = DropZone()
        qtbot.addWidget(zone)
        assert zone.acceptDrops() is True

    def test_the_dialog_filter_lists_supported_extensions(self):
        filter_text = file_dialog_filter()
        assert "*.png" in filter_text
        assert "*.bmp" in filter_text
        assert "*.wav" in filter_text
        assert "All files (*)" in filter_text

    def test_the_dialog_filter_can_be_restricted(self):
        filter_text = file_dialog_filter([constants.MEDIA_AUDIO])
        assert "*.wav" in filter_text
        assert "*.png" not in filter_text


# --------------------------------------------------------------------------- #
# File info panel
# --------------------------------------------------------------------------- #


class TestFileInfoPanel:
    def test_it_starts_empty(self, qtbot):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        assert panel.labels == ()

    def test_it_shows_a_description(self, qtbot, png_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        panel.show_description(file_utils.describe_file(png_file))

        assert panel.value_for("Media type") == constants.MEDIA_IMAGE
        assert panel.value_for("Container") == constants.CONTAINER_PNG
        assert "cover.png" in panel.value_for("File")

    def test_it_flags_an_extension_mismatch(self, qtbot, tmp_path):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)

        misleading = tmp_path / "mislabelled.bmp"
        misleading.write_bytes(image_io.encode_image(make_cover(16, 16, 3), image_io.PNG))
        panel.show_description(file_utils.describe_file(str(misleading)))

        # isVisibleTo rather than isVisible: the latter requires every ancestor to be
        # shown, and a widget under test is never actually on screen.
        assert panel._notice_label.isVisibleTo(panel)
        assert "content decides" in panel._notice_label.text()

    def test_a_matching_extension_shows_no_notice(self, qtbot, png_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        panel.show_description(file_utils.describe_file(png_file))

        assert panel._notice_label.isVisibleTo(panel) is False
        assert panel._notice_label.text() == ""

    def test_it_shows_image_capacity_rows(self, qtbot, png_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        capacity = media.measure(png_file, 3, payload_length=100)
        panel.show_capacity(
            file_utils.describe_file(png_file), capacity, payload_length=100, lsb_depth=3
        )

        assert panel.value_for("Dimensions") == "48 x 48"
        assert panel.value_for("LSB depth") == "3 of 8"
        assert panel.value_for("Fits") == "yes"
        assert panel.value_for("Capacity used") is not None

    def test_it_shows_audio_capacity_rows(self, qtbot, wav_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        capacity = media.measure(wav_file, 2)
        panel.show_capacity(file_utils.describe_file(wav_file), capacity, lsb_depth=2)

        assert panel.value_for("Sample rate") == "44,100 Hz"
        assert panel.value_for("Duration") is not None
        assert panel.value_for("Dimensions") is None

    def test_it_reports_a_payload_that_does_not_fit(self, qtbot, png_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        capacity = media.measure(png_file, 1, payload_length=10**6)
        panel.show_capacity(
            file_utils.describe_file(png_file),
            capacity,
            payload_length=10**6,
            lsb_depth=1,
        )
        assert panel.value_for("Fits") == "no"

    def test_clearing_removes_every_row(self, qtbot, png_file):
        panel = FileInfoPanel()
        qtbot.addWidget(panel)
        panel.show_description(file_utils.describe_file(png_file))
        panel.clear()
        assert panel.labels == ()


# --------------------------------------------------------------------------- #
# Media preview
# --------------------------------------------------------------------------- #


class TestMediaPreview:
    def test_it_shows_an_image(self, qtbot, png_file):
        preview = MediaPreview()
        qtbot.addWidget(preview)
        assert preview.show_file(png_file) is True
        assert preview.path == png_file

    def test_it_reports_an_unsupported_file(self, qtbot, tmp_path):
        preview = MediaPreview()
        qtbot.addWidget(preview)
        failures: list[str] = []
        preview.previewFailed.connect(failures.append)

        junk = tmp_path / "junk.dat"
        junk.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        assert preview.show_file(str(junk)) is False
        assert failures

    def test_it_reports_a_missing_file(self, qtbot, tmp_path):
        preview = MediaPreview()
        qtbot.addWidget(preview)
        assert preview.show_file(str(tmp_path / "absent.png")) is False

    def test_audio_either_plays_or_says_it_cannot(self, qtbot, wav_file):
        """A missing multimedia backend must degrade, not crash."""
        preview = MediaPreview()
        qtbot.addWidget(preview)

        shown = preview.show_file(wav_file)
        if preview.playback_available:
            assert shown is True
        else:
            assert shown is False

    def test_clearing_forgets_the_file(self, qtbot, png_file):
        preview = MediaPreview()
        qtbot.addWidget(preview)
        preview.show_file(png_file)
        preview.clear()
        assert preview.path is None

    def test_stopping_without_a_player_is_safe(self, qtbot):
        preview = MediaPreview()
        qtbot.addWidget(preview)
        preview.stop()  # must not raise
        preview.toggle_playback()  # must not raise


# --------------------------------------------------------------------------- #
# Result panel
# --------------------------------------------------------------------------- #


def make_result(**overrides) -> VerificationResult:
    values = {
        "verdict": constants.VERDICT_AUTHENTIC,
        "reason": "the signature verified",
        "payload_found": True,
        "signature_valid": True,
        "hash_valid": True,
        "start_location_valid": True,
        "manifest_consistent": True,
        "message": b"hello world",
        "notes": (constants.AUTHENTIC_SCOPE_NOTICE,),
    }
    values.update(overrides)
    return VerificationResult(**values)


class TestResultPanel:
    def test_it_starts_with_no_verdict(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        assert panel.result is None
        assert "No verification" in panel.verdict_text

    def test_it_shows_the_verdict(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result())

        assert panel.verdict_text == constants.VERDICT_AUTHENTIC
        assert panel.result is not None

    @pytest.mark.parametrize("verdict", constants.VERDICTS)
    def test_every_verdict_renders(self, qtbot, verdict):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(verdict=verdict, message=None))
        assert panel.verdict_text == verdict

    def test_the_flags_are_shown_in_words(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(signature_valid=False))

        assert panel.flag_text("signature_valid") == "no"
        assert panel.flag_text("payload_found") == "yes"

    def test_an_unestablished_flag_says_so_rather_than_no(self, qtbot):
        """None and False mean different things and must read differently."""
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(
            make_result(
                verdict=constants.VERDICT_PAYLOAD_MISSING,
                payload_found=False,
                signature_valid=None,
                hash_valid=None,
                message=None,
            )
        )

        assert panel.flag_text("payload_found") == "no"
        assert panel.flag_text("signature_valid") == "not established"

    def test_notes_are_displayed(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result())
        assert constants.AUTHENTIC_SCOPE_NOTICE in panel._notes_label.text()

    def test_mismatched_fields_are_listed(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(
            make_result(
                verdict=constants.VERDICT_TAMPERED,
                manifest_consistent=False,
                mismatched_fields=("lsb_depth", "media_id"),
            )
        )
        assert panel.flag_text("manifest_consistent") == "no"

    def test_an_error_can_be_shown_without_a_verdict(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_error("the cover could not be read")

        assert "Could not complete" in panel.verdict_text
        assert panel.result is None

    def test_clearing_resets_everything(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result())
        panel.clear()

        assert panel.result is None
        assert panel.payload_text == ""


class TestRecoveredContentIsInert:
    """The rule that recovered content is never executed or interpreted."""

    def test_text_is_shown_as_plain_text(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(message=b"hello world"))
        assert panel.payload_text == "hello world"

    def test_markup_is_not_rendered(self, qtbot):
        """A QLabel would interpret this; the payload view must not."""
        hostile = b"<b>bold</b><img src='http://example.invalid/x.png'>"
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(message=hostile))

        # The markup appears verbatim, which means it was not interpreted.
        assert "<b>bold</b>" in panel.payload_text
        assert "<img src=" in panel.payload_text

    def test_the_payload_view_is_read_only(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        assert panel._payload_view.isReadOnly() is True

    def test_binary_content_falls_back_to_a_hex_dump(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(message=b"\xff\xfe\x00\x01"))

        text = panel.payload_text
        assert "00000000" in text
        assert "ff fe 00 01" in text

    def test_the_inert_notice_is_displayed(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        labels = [
            child
            for child in panel.findChildren(object)
            if getattr(child, "objectName", lambda: "")() == "inertNotice"
        ]
        assert labels
        assert labels[0].text() == constants.EXTRACTED_CONTENT_NOTICE

    def test_no_message_leaves_the_view_empty(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(message=None))
        assert panel.payload_text == ""

    def test_switching_to_hex_and_back_works(self, qtbot):
        panel = ResultPanel()
        qtbot.addWidget(panel)
        panel.show_result(make_result(message=b"hello"))

        panel._render_payload(True)
        assert "68 65 6c 6c 6f" in panel.payload_text
        panel._render_payload(False)
        assert panel.payload_text == "hello"


class TestHexDump:
    def test_offsets_and_ascii_columns(self):
        dump = hex_dump(b"ABC")
        assert dump.startswith("00000000  41 42 43")
        assert dump.rstrip().endswith("ABC")

    def test_unprintable_bytes_become_dots(self):
        assert hex_dump(b"\x00\x01").rstrip().endswith("..")

    def test_empty_input(self):
        assert hex_dump(b"") == "(empty)"

    def test_long_input_is_truncated_with_a_note(self):
        dump = hex_dump(b"x" * 5_000, limit=64)
        assert "further bytes not shown" in dump
        assert "5000 bytes total" in dump

    def test_rows_use_the_configured_width(self):
        lines = hex_dump(b"x" * 32, width=8).splitlines()
        assert len(lines) == 4
