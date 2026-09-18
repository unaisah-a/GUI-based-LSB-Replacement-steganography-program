"""Tests for the shared utility layer.

Covers the three concerns of :mod:`app.utils`: cross-layer constants,
content-based media identification with atomic file writes, and logging setup.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from app.stego import bit_utils, image_io
from app.utils import constants, file_utils, logging_utils
from app.utils.file_utils import UnsupportedMediaError

from conftest import make_audio, make_cover, write_audio_file, write_cover

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #


class TestConstantsAgreeWithTheLibraryLayer:
    def test_every_offered_depth_is_accepted_by_the_stego_layer(self):
        for depth in constants.LSB_DEPTHS:
            assert bit_utils.validate_lsb_depth(depth) == depth

    def test_depth_list_is_exactly_one_to_eight(self):
        assert tuple(range(1, 9)) == constants.LSB_DEPTHS

    def test_image_containers_match_image_io(self):
        assert set(constants.SUPPORTED_CONTAINERS[constants.MEDIA_IMAGE]) == set(
            image_io.SUPPORTED_CONTAINERS
        )


class TestConstantsInternalConsistency:
    def test_every_media_type_has_containers(self):
        assert set(constants.SUPPORTED_CONTAINERS) == set(constants.MEDIA_TYPES)

    def test_every_written_container_has_an_extension(self):
        for containers in constants.SUPPORTED_CONTAINERS.values():
            for container in containers:
                assert container in constants.CONTAINER_EXTENSIONS

    def test_default_repetition_factor_is_odd(self):
        """An even factor could tie a majority vote, leaving the result arbitrary."""
        assert constants.ECC_REPETITION_DEFAULT_FACTOR % 2 == 1

    def test_verdict_tuple_covers_every_named_verdict(self):
        named = {
            value
            for name, value in vars(constants).items()
            if name.startswith("VERDICT_") and isinstance(value, str)
        }
        assert named == set(constants.VERDICTS)
        assert len(constants.VERDICTS) == 6

    def test_envelope_magic_is_eight_bytes(self):
        assert len(constants.ENVELOPE_MAGIC) == 8

    def test_envelope_flags_do_not_overlap(self):
        assert constants.ENVELOPE_FLAG_ENCRYPTED & constants.ENVELOPE_FLAG_ECC == 0

    def test_aes_and_gcm_sizes(self):
        assert constants.AES_KEY_BYTES == 32
        assert constants.GCM_NONCE_BYTES == 12
        assert constants.GCM_TAG_BYTES == 16

    def test_default_rsa_size_is_at_least_the_minimum(self):
        assert constants.RSA_KEY_SIZE_DEFAULT >= constants.RSA_MIN_KEY_SIZE

    def test_start_methods_are_the_two_named_ones(self):
        assert constants.START_METHODS == (
            constants.START_METHOD_MANUAL,
            constants.START_METHOD_HMAC,
        )


# --------------------------------------------------------------------------- #
# Media identification
# --------------------------------------------------------------------------- #


def _write_mkv_header(directory: str, name: str = "clip.mkv") -> str:
    """Write a file whose first bytes are the EBML signature.

    Detection reads only the head of the file, so a real encoded video is not
    needed to test detection, and generating one here would make a fast unit test
    depend on OpenCV codec availability. Round-tripping actual video is covered by
    the video layer's own tests.
    """
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(b"\x1a\x45\xdf\xa3" + b"\x00" * 64)
    return path


class TestDetection:
    def test_png_is_detected(self, tmp_path):
        path = write_cover(str(tmp_path), make_cover(4, 4, 3), image_io.PNG, "cover")
        assert file_utils.detect_container(path) == constants.CONTAINER_PNG
        assert file_utils.detect_media_type(path) == constants.MEDIA_IMAGE

    def test_bmp_is_detected(self, tmp_path):
        path = write_cover(str(tmp_path), make_cover(4, 4, 3), image_io.BMP, "cover")
        assert file_utils.detect_container(path) == constants.CONTAINER_BMP
        assert file_utils.detect_media_type(path) == constants.MEDIA_IMAGE

    def test_wav_is_detected(self, tmp_path):
        path = write_audio_file(str(tmp_path), make_audio(256))
        assert file_utils.detect_container(path) == constants.CONTAINER_WAV
        assert file_utils.detect_media_type(path) == constants.MEDIA_AUDIO

    def test_mkv_is_detected(self, tmp_path):
        path = _write_mkv_header(str(tmp_path))
        assert file_utils.detect_container(path) == constants.CONTAINER_MKV
        assert file_utils.detect_media_type(path) == constants.MEDIA_VIDEO

    def test_content_wins_over_a_misleading_extension(self, tmp_path):
        """A PNG named .bmp is a PNG. This is the whole point of sniffing."""
        png_bytes = image_io.encode_image(make_cover(4, 4, 3), image_io.PNG)
        path = tmp_path / "actually_a_png.bmp"
        path.write_bytes(png_bytes)

        assert file_utils.detect_container(str(path)) == constants.CONTAINER_PNG

    def test_wav_extension_on_image_content_is_still_an_image(self, tmp_path):
        png_bytes = image_io.encode_image(make_cover(4, 4, 1), image_io.PNG)
        path = tmp_path / "confusing.wav"
        path.write_bytes(png_bytes)

        assert file_utils.detect_media_type(str(path)) == constants.MEDIA_IMAGE

    def test_riff_that_is_not_wave_or_avi_is_unrecognised(self, tmp_path):
        path = tmp_path / "odd.riff"
        path.write_bytes(b"RIFF" + b"\x00\x00\x00\x00" + b"XXXX" + b"\x00" * 16)

        with pytest.raises(UnsupportedMediaError):
            file_utils.detect_container(str(path))

    def test_avi_is_recognised_as_video(self, tmp_path):
        path = tmp_path / "clip.avi"
        path.write_bytes(b"RIFF" + b"\x00\x00\x00\x00" + b"AVI " + b"\x00" * 16)

        assert file_utils.detect_media_type(str(path)) == constants.MEDIA_VIDEO


class TestDetectionRejections:
    @pytest.mark.parametrize(
        ("head", "expected_name"),
        [
            (b"\xff\xd8\xff\xe0" + b"\x00" * 16, "JPEG"),
            (b"GIF89a" + b"\x00" * 16, "GIF"),
            (b"fLaC" + b"\x00" * 16, "FLAC"),
            (b"OggS" + b"\x00" * 16, "OGG"),
            (b"ID3\x03" + b"\x00" * 16, "MP3"),
            (b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16, "MP4"),
            (b"\x00\x00\x00\x18ftypjp2 " + b"\x00" * 16, "JPEG2000"),
        ],
    )
    def test_known_unsupported_formats_are_named_in_the_error(
        self, tmp_path, head, expected_name
    ):
        """Saying "this is a JPEG and JPEG is lossy" beats "unrecognised file"."""
        path = tmp_path / "sample.bin"
        path.write_bytes(head)

        with pytest.raises(UnsupportedMediaError) as caught:
            file_utils.detect_container(str(path))

        assert caught.value.detected == expected_name
        assert expected_name in str(caught.value)

    def test_lossy_formats_say_why(self, tmp_path):
        path = tmp_path / "photo.jpg"
        path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 16)

        with pytest.raises(UnsupportedMediaError, match="lossy"):
            file_utils.detect_container(str(path))

    def test_unknown_content_reports_no_detected_format(self, tmp_path):
        path = tmp_path / "random.dat"
        path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 16)

        with pytest.raises(UnsupportedMediaError) as caught:
            file_utils.detect_container(str(path))
        assert caught.value.detected is None

    def test_missing_file(self, tmp_path):
        with pytest.raises(UnsupportedMediaError, match="not found"):
            file_utils.detect_container(str(tmp_path / "absent.png"))

    def test_directory(self, tmp_path):
        with pytest.raises(UnsupportedMediaError, match="directory"):
            file_utils.detect_container(str(tmp_path))

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.png"
        path.write_bytes(b"")
        with pytest.raises(UnsupportedMediaError):
            file_utils.detect_container(str(path))

    def test_error_message_omits_the_directory(self, tmp_path):
        """Messages may be screenshotted for evidence; do not leak paths."""
        path = tmp_path / "secretdir_marker.dat"
        path.write_bytes(b"\x01\x02\x03\x04")

        with pytest.raises(UnsupportedMediaError) as caught:
            file_utils.detect_container(str(path))

        assert "secretdir_marker.dat" in str(caught.value)
        assert str(tmp_path) not in str(caught.value)


class TestDescribeFile:
    def test_reports_type_container_and_size(self, tmp_path):
        path = write_cover(str(tmp_path), make_cover(8, 8, 3), image_io.PNG, "cover")
        description = file_utils.describe_file(path)

        assert description.media_type == constants.MEDIA_IMAGE
        assert description.container_format == constants.CONTAINER_PNG
        assert description.size_bytes == os.path.getsize(path)
        assert description.size_human.endswith(("B", "kB", "MB"))
        assert description.name == os.path.basename(path)
        assert description.extension == ".png"
        assert description.extension_mismatch is False

    def test_flags_an_extension_mismatch_without_failing(self, tmp_path):
        png_bytes = image_io.encode_image(make_cover(4, 4, 3), image_io.PNG)
        path = tmp_path / "mislabelled.bmp"
        path.write_bytes(png_bytes)

        description = file_utils.describe_file(str(path))
        assert description.container_format == constants.CONTAINER_PNG
        assert description.extension_mismatch is True


# --------------------------------------------------------------------------- #
# Presentation helpers
# --------------------------------------------------------------------------- #


class TestHumanSize:
    @pytest.mark.parametrize(
        ("size", "expected"),
        [
            (0, "0 B"),
            (1, "1 B"),
            (999, "999 B"),
            (1_000, "1.00 kB"),
            (1_500, "1.50 kB"),
            (999_999, "1000.00 kB"),
            (1_000_000, "1.00 MB"),
            (4_210_000, "4.21 MB"),
            (8_420_000_000, "8.42 GB"),
            (1_000_000_000_000, "1.00 TB"),
        ],
    )
    def test_formatting(self, size, expected):
        assert file_utils.human_size(size) == expected

    def test_very_large_values_stay_in_terabytes(self):
        assert file_utils.human_size(5_000_000_000_000_000).endswith(" TB")

    def test_negative_rejected(self):
        with pytest.raises(ValueError):
            file_utils.human_size(-1)

    def test_non_integer_rejected(self):
        with pytest.raises(TypeError):
            file_utils.human_size(1.5)

    def test_bool_rejected(self):
        with pytest.raises(TypeError):
            file_utils.human_size(True)


class TestDisplayName:
    def test_strips_the_directory(self):
        assert file_utils.display_name(os.path.join("a", "b", "c.png")) == "c.png"

    def test_handles_a_trailing_separator(self):
        assert file_utils.display_name("a/b/") == "b"

    def test_accepts_a_path_object(self, tmp_path):
        assert file_utils.display_name(tmp_path / "x.wav") == "x.wav"


# --------------------------------------------------------------------------- #
# Digests
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


class TestPaths:
    def test_manifest_path_keeps_the_full_name(self):
        assert file_utils.manifest_path_for("cover_stego.png") == (
            "cover_stego.png" + constants.MANIFEST_SUFFIX
        )

    def test_manifest_paths_of_different_containers_do_not_collide(self):
        """Keeping the extension stops a PNG manifest pairing with a WAV."""
        png = file_utils.manifest_path_for("clip.png")
        wav = file_utils.manifest_path_for("clip.wav")
        assert png != wav

    def test_suggest_output_path_adds_the_suffix_beside_the_input(self, tmp_path):
        source = str(tmp_path / "cover.png")
        suggested = file_utils.suggest_output_path(source)
        assert os.path.basename(suggested) == "cover_stego.png"
        assert os.path.dirname(suggested) == str(tmp_path)

    def test_suggest_output_path_honours_a_directory_and_extension(self, tmp_path):
        target = tmp_path / "out"
        target.mkdir()
        suggested = file_utils.suggest_output_path(
            str(tmp_path / "cover.bmp"), directory=str(target), extension=".png"
        )
        assert suggested == str(target / "cover_stego.png")

    def test_unique_path_returns_the_original_when_free(self, tmp_path):
        candidate = str(tmp_path / "free.png")
        assert file_utils.unique_path(candidate) == candidate

    def test_unique_path_increments_until_free(self, tmp_path):
        first = tmp_path / "taken.png"
        first.write_bytes(b"x")
        second = tmp_path / "taken (2).png"
        second.write_bytes(b"x")

        assert file_utils.unique_path(str(first)) == str(tmp_path / "taken (3).png")

    def test_ensure_directory_is_idempotent(self, tmp_path):
        target = str(tmp_path / "a" / "b")
        assert file_utils.ensure_directory(target) == target
        assert file_utils.ensure_directory(target) == target
        assert os.path.isdir(target)


# --------------------------------------------------------------------------- #
# Atomic writes
# --------------------------------------------------------------------------- #


class TestAtomicWrites:
    def test_bytes_round_trip(self, tmp_path):
        path = str(tmp_path / "out.bin")
        file_utils.write_bytes_atomic(path, b"payload")
        assert Path(path).read_bytes() == b"payload"

    def test_text_round_trip_is_utf8(self, tmp_path):
        path = str(tmp_path / "out.txt")
        file_utils.write_text_atomic(path, "café \u2713")
        assert Path(path).read_text(encoding="utf-8") == "café \u2713"

    def test_json_round_trip(self, tmp_path):
        path = str(tmp_path / "out.json")
        payload = {"b": 2, "a": [1, 2, 3], "nested": {"z": None, "y": True}}
        file_utils.write_json_atomic(path, payload)
        assert file_utils.read_json(path) == payload

    def test_json_is_readable_and_key_sorted(self, tmp_path):
        """The manifest is meant to be opened and read during the demo."""
        path = str(tmp_path / "out.json")
        file_utils.write_json_atomic(path, {"zebra": 1, "alpha": 2})
        text = Path(path).read_text(encoding="utf-8")

        assert "\n" in text
        assert text.index('"alpha"') < text.index('"zebra"')

    def test_existing_file_is_not_overwritten_by_default(self, tmp_path):
        path = tmp_path / "out.bin"
        path.write_bytes(b"original")

        with pytest.raises(FileExistsError):
            file_utils.write_bytes_atomic(str(path), b"replacement")
        assert path.read_bytes() == b"original"

    def test_overwrite_replaces_the_content(self, tmp_path):
        path = tmp_path / "out.bin"
        path.write_bytes(b"original")
        file_utils.write_bytes_atomic(str(path), b"replacement", overwrite=True)
        assert path.read_bytes() == b"replacement"

    def test_missing_directory_is_reported(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            file_utils.write_bytes_atomic(str(tmp_path / "absent" / "out.bin"), b"x")

    def test_directory_as_target_is_reported(self, tmp_path):
        with pytest.raises(IsADirectoryError):
            file_utils.write_bytes_atomic(str(tmp_path), b"x")

    def test_no_partial_file_survives_a_failed_write(self, tmp_path):
        """An interrupted write must not leave a file that would later verify."""
        with pytest.raises(TypeError):
            file_utils.write_bytes_atomic(str(tmp_path / "out.bin"), "not bytes")

        assert list(tmp_path.iterdir()) == []

    def test_no_temporary_files_remain_after_a_successful_write(self, tmp_path):
        file_utils.write_bytes_atomic(str(tmp_path / "out.bin"), b"x")
        names = sorted(entry.name for entry in tmp_path.iterdir())
        assert names == ["out.bin"]

    def test_non_bytes_payload_rejected(self, tmp_path):
        with pytest.raises(TypeError):
            file_utils.write_bytes_atomic(str(tmp_path / "out.bin"), 123)


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #


class TestLogging:
    def test_get_logger_returns_a_named_child(self):
        logger = logging_utils.get_logger("app.stego.image_stego")
        assert logger.name == "inf2005.app.stego.image_stego"

    def test_root_name_is_returned_unchanged(self):
        assert logging_utils.get_logger().name == "inf2005"
        assert logging_utils.get_logger("inf2005").name == "inf2005"

    def test_configuration_is_idempotent(self):
        logging_utils.reset_logging()
        try:
            first = logging_utils.configure_logging()
            count = len(first.handlers)
            for _ in range(5):
                logging_utils.configure_logging()
            assert len(first.handlers) == count
        finally:
            logging_utils.reset_logging()

    def test_records_do_not_propagate_to_the_root_logger(self):
        logging_utils.reset_logging()
        try:
            logger = logging_utils.configure_logging(to_file=False)
            assert logger.propagate is False
        finally:
            logging_utils.reset_logging()

    def test_writes_a_rotating_log_file_into_the_log_directory(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(logging_utils, "log_directory", lambda: tmp_path)
        logging_utils.reset_logging()
        try:
            logger = logging_utils.configure_logging(to_stderr=False)
            logger.info("probe record")
            (handler,) = logger.handlers
            handler.flush()

            assert isinstance(handler, logging.handlers.RotatingFileHandler)
            assert handler.maxBytes == logging_utils.MAX_LOG_BYTES
            target = tmp_path / logging_utils.DEFAULT_LOG_FILE_NAME
            assert "probe record" in target.read_text(encoding="utf-8")
        finally:
            logging_utils.reset_logging()

    def test_get_logger_does_not_configure_logging(self):
        logging_utils.reset_logging()
        logging_utils.get_logger("app.anything")
        assert logging.getLogger(logging_utils.LOGGER_NAME).handlers == []

    def test_log_directory_is_derived_from_the_package_not_the_cwd(self):
        expected = Path(__file__).resolve().parent.parent
        assert logging_utils.repository_root() == expected
        # log_directory() itself is redirected by conftest so tests never write into
        # the repository; the path it is built from is what matters here.
        assert Path(logging_utils.LOG_DIRECTORY_NAME) == Path("evidence", "logs")

    def test_importing_the_module_has_no_filesystem_side_effect(self):
        """Importing must not create directories or open log files."""
        probe = textwrap.dedent(
            """
            import logging
            from app.utils import logging_utils
            import app.verification.verifier  # calls get_logger at import time

            logger = logging.getLogger(logging_utils.LOGGER_NAME)
            print(len(logger.handlers))
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=str(Path(__file__).resolve().parent.parent),
            capture_output=True,
            text=True,
            check=True,
        )
        assert completed.stdout.strip() == "0"


# --------------------------------------------------------------------------- #
# Error hierarchy
# --------------------------------------------------------------------------- #


class TestErrorHierarchy:
    def test_every_error_family_derives_from_app_error(self):
        """The interface relies on this to tell expected failures from bugs."""
        from app.attacks.base import AttackError
        from app.crypto.errors import CryptoError
        from app.errors import AppError
        from app.robustness.redundancy import RedundancyError
        from app.stego.errors import StegoError
        from app.utils.media_utils import VideoInspectionError

        for family in (
            StegoError,
            CryptoError,
            RedundancyError,
            AttackError,
            UnsupportedMediaError,
            VideoInspectionError,
        ):
            assert issubclass(family, AppError), family.__name__

    def test_long_messages_are_capped(self):
        from app.errors import MAX_MESSAGE_LENGTH, AppError

        message = str(AppError("x" * (MAX_MESSAGE_LENGTH * 2)))
        assert len(message) == MAX_MESSAGE_LENGTH
        assert message.endswith("...")
