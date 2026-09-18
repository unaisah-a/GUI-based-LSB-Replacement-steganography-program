"""Tests for identifying, labelling and naming file payloads."""

from __future__ import annotations

import pytest

from app.stego import image_io
from app.utils import payload_files
from app.utils.payload_files import (
    detect_payload_type,
    metadata_for_file,
    safe_filename,
    suggested_filename,
)

from conftest import make_cover


class TestDetectPayloadType:
    @pytest.mark.parametrize(
        ("data", "kind", "extension"),
        [
            (b"\x89PNG\r\n\x1a\n" + bytes(20), payload_files.KIND_IMAGE, ".png"),
            (b"\xff\xd8\xff\xe0" + bytes(20), payload_files.KIND_IMAGE, ".jpg"),
            (b"BM" + bytes(40), payload_files.KIND_IMAGE, ".bmp"),
            (b"RIFF\x00\x00\x00\x00WAVEfmt ", payload_files.KIND_AUDIO, ".wav"),
            (b"ID3\x04\x00" + bytes(20), payload_files.KIND_AUDIO, ".mp3"),
            (b"\xff\xfb\x90\x00" + bytes(20), payload_files.KIND_AUDIO, ".mp3"),
            ("plain text, caf\u00e9".encode(), payload_files.KIND_TEXT, ".txt"),
            (b"\x00\xff\xfe\x80\x81", payload_files.KIND_BINARY, ".bin"),
        ],
    )
    def test_content_decides_the_type(self, data, kind, extension):
        detected = detect_payload_type(data)
        assert detected.kind == kind
        assert detected.extension == extension

    def test_a_real_png_is_an_image(self):
        data = image_io.encode_image(make_cover(8, 8, 3), image_io.PNG)
        assert detect_payload_type(data).content_type == "image/png"

    def test_a_riff_file_that_is_not_wave_is_not_audio(self):
        assert detect_payload_type(b"RIFF\x00\x00\x00\x00AVI LIST").kind != (
            payload_files.KIND_AUDIO
        )

    def test_only_images_and_audio_are_previewable(self):
        assert detect_payload_type(b"\x89PNG\r\n\x1a\n").previewable
        assert not detect_payload_type(b"hello").previewable
        assert not detect_payload_type(b"\x00\xff\xfe").previewable


class TestSafeFilename:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("logo.png", "logo.png"),
            ("../../etc/passwd", "passwd"),
            ("..\\..\\Startup\\run.bat", "run.bat"),
            ("C:\\Users\\x\\a.wav", "a.wav"),
            (".hidden", "hidden"),
            ('bad<>:"|?*name.txt', "bad_______name.txt"),
            ("trailing. ", "trailing"),
        ],
    )
    def test_names_are_reduced_to_a_bare_file_name(self, name, expected):
        assert safe_filename(name) == expected

    @pytest.mark.parametrize("name", ["", "..", "/", "\\", "CON", "nul.txt", "COM1.wav"])
    def test_unusable_names_are_refused(self, name):
        assert safe_filename(name) is None

    @pytest.mark.parametrize("name", [None, 42, ["a.png"]])
    def test_a_non_string_is_refused(self, name):
        assert safe_filename(name) is None

    def test_a_long_name_keeps_its_extension(self):
        result = safe_filename("x" * 500 + ".png")
        assert result.endswith(".png")
        assert len(result) <= 120


class TestMetadata:
    def test_the_sender_records_name_and_type(self, tmp_path):
        path = tmp_path / "photo.png"
        data = b"\x89PNG\r\n\x1a\n" + bytes(10)
        assert metadata_for_file(str(path), data) == {
            payload_files.METADATA_FILENAME: "photo.png",
            payload_files.METADATA_CONTENT_TYPE: "image/png",
        }

    def test_the_recorded_name_is_the_default(self):
        metadata = {payload_files.METADATA_FILENAME: "song.wav"}
        assert suggested_filename(metadata, b"anything") == "song.wav"

    def test_a_hostile_recorded_name_is_sanitised(self):
        metadata = {payload_files.METADATA_FILENAME: "..\\..\\Startup\\evil.bat"}
        assert suggested_filename(metadata, b"x") == "evil.bat"

    @pytest.mark.parametrize("metadata", [None, {}, {"filename": "CON"}])
    def test_without_a_usable_name_the_content_picks_the_extension(self, metadata):
        assert suggested_filename(metadata, b"\x89PNG\r\n\x1a\n") == (
            "recovered_payload.png"
        )
        assert suggested_filename(metadata, b"hello") == "recovered_payload.txt"
