"""Tests for the media-agnostic steganography facade.

Two things are being established:

* Dispatch is correct and driven by file **content**, not extension.
* The unified result shapes carry the same fields and the same meanings for both
  media, so a caller really can avoid branching.

The facade is thin by design, so most of these tests are about the seams: which
handler gets chosen, what happens for an unsupported medium, and whether the
normalised fields agree with the underlying layer's own results.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.stego import audio_stego, capacity, image_io, image_stego, media
from app.stego.errors import CapacityError, DecodeError, FileError, StegoError, ValidationError
from app.utils import constants
from conftest import make_audio, make_cover, write_audio_file, write_cover

PAYLOAD = b"INF2005 shared facade test"


@pytest.fixture()
def image_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")


@pytest.fixture()
def bmp_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.BMP, "cover_bmp")


@pytest.fixture()
def audio_cover(tmp_path):
    return write_audio_file(str(tmp_path), make_audio(8_000))


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


class TestRegistry:
    def test_every_media_type_is_supported(self):
        assert media.supports(constants.MEDIA_IMAGE)
        assert media.supports(constants.MEDIA_AUDIO)
        assert media.supports(constants.MEDIA_VIDEO)

    def test_the_registry_covers_every_known_type(self):
        """The facade's whole purpose is that callers need not branch."""
        assert set(media.SUPPORTED_MEDIA_TYPES) == set(constants.MEDIA_TYPES)

    def test_supported_types_are_a_subset_of_the_known_types(self):
        assert set(media.SUPPORTED_MEDIA_TYPES) <= set(constants.MEDIA_TYPES)

    def test_unknown_type_is_not_supported(self):
        assert not media.supports("hologram")


# --------------------------------------------------------------------------- #
# Detection and dispatch
# --------------------------------------------------------------------------- #


class TestDetection:
    def test_png_dispatches_to_image(self, image_cover):
        assert media.detect_media_type(image_cover) == constants.MEDIA_IMAGE

    def test_bmp_dispatches_to_image(self, bmp_cover):
        assert media.detect_media_type(bmp_cover) == constants.MEDIA_IMAGE

    def test_wav_dispatches_to_audio(self, audio_cover):
        assert media.detect_media_type(audio_cover) == constants.MEDIA_AUDIO

    def test_content_wins_over_the_extension(self, tmp_path):
        """A PNG named .wav must be embedded as an image."""
        png_bytes = image_io.encode_image(make_cover(64, 64, 3), image_io.PNG)
        misleading = tmp_path / "confusing.wav"
        misleading.write_bytes(png_bytes)

        assert media.detect_media_type(str(misleading)) == constants.MEDIA_IMAGE

        result = media.embed(
            str(misleading), str(tmp_path / "out.png"), PAYLOAD, 2, 0
        )
        assert result.media_type == constants.MEDIA_IMAGE
        assert result.container_format == constants.CONTAINER_PNG

    def test_a_wav_named_png_is_still_audio(self, tmp_path):
        source = write_audio_file(str(tmp_path), make_audio(8_000), "real_audio")
        misleading = tmp_path / "confusing.png"
        misleading.write_bytes(Path(source).read_bytes())

        assert media.detect_media_type(str(misleading)) == constants.MEDIA_AUDIO

    def test_describe_reports_the_container(self, image_cover):
        description = media.describe(image_cover)
        assert description.media_type == constants.MEDIA_IMAGE
        assert description.container_format == constants.CONTAINER_PNG
        assert description.size_bytes == os.path.getsize(image_cover)


class TestUnsupportedInput:
    def test_detection_failure_is_a_stego_error(self, tmp_path):
        """One error family for callers of this layer."""
        path = tmp_path / "random.dat"
        path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        with pytest.raises(DecodeError):
            media.detect_media_type(str(path))

    def test_the_detected_format_is_still_named(self, tmp_path):
        path = tmp_path / "photo.jpg"
        path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32)

        with pytest.raises(DecodeError, match="JPEG"):
            media.measure(str(path), 1)

    def test_lossy_input_still_explains_why(self, tmp_path):
        path = tmp_path / "photo.jpg"
        path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32)

        with pytest.raises(DecodeError, match="lossy"):
            media.embed(str(path), str(tmp_path / "out.png"), PAYLOAD, 1, 0)

    def test_a_video_container_with_no_decodable_stream_is_reported(self, tmp_path):
        """An EBML header alone is a container, not a clip. Named, not guessed at."""
        path = tmp_path / "clip.mkv"
        path.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 64)

        with pytest.raises(DecodeError):
            media.measure(str(path), 1)

    def test_an_unregistered_media_type_would_be_reported_clearly(self, tmp_path):
        """The facade's own guard, exercised by removing a handler temporarily.

        Every media type is registered now, so the only way to reach this branch is
        to take one away. Worth keeping: it is the message a future fourth medium
        would produce before its layer existed.
        """
        path = tmp_path / "cover.png"
        path.write_bytes(
            image_io.encode_image(make_cover(8, 8, 3), image_io.PNG)
        )

        handler = media._HANDLERS.pop(constants.MEDIA_IMAGE)
        try:
            with pytest.raises(DecodeError, match="cannot carry a payload"):
                media.measure(str(path), 1)
        finally:
            media._HANDLERS[constants.MEDIA_IMAGE] = handler

    def test_missing_file(self, tmp_path):
        with pytest.raises(DecodeError, match="not found"):
            media.measure(str(tmp_path / "absent.png"), 1)

    def test_directory(self, tmp_path):
        with pytest.raises(DecodeError, match="directory"):
            media.measure(str(tmp_path), 1)


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_image_round_trip(self, image_cover, tmp_path):
        output = str(tmp_path / "stego.png")
        media.embed(image_cover, output, PAYLOAD, 3, 100)
        assert media.extract(output, 3, 100) == PAYLOAD

    def test_audio_round_trip(self, audio_cover, tmp_path):
        output = str(tmp_path / "stego.wav")
        media.embed(audio_cover, output, PAYLOAD, 3, 100)
        assert media.extract(output, 3, 100) == PAYLOAD

    def test_bmp_round_trip(self, bmp_cover, tmp_path):
        output = str(tmp_path / "stego.bmp")
        media.embed(bmp_cover, output, PAYLOAD, 4, 7)
        assert media.extract(output, 4, 7) == PAYLOAD

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_every_depth_round_trips_for_both_media(
        self, image_cover, audio_cover, tmp_path, depth
    ):
        image_out = str(tmp_path / f"i{depth}.png")
        audio_out = str(tmp_path / f"a{depth}.wav")

        media.embed(image_cover, image_out, PAYLOAD, depth, 10)
        media.embed(audio_cover, audio_out, PAYLOAD, depth, 10)

        assert media.extract(image_out, depth, 10) == PAYLOAD
        assert media.extract(audio_out, depth, 10) == PAYLOAD

    def test_empty_payload_round_trips_for_both_media(
        self, image_cover, audio_cover, tmp_path
    ):
        media.embed(image_cover, str(tmp_path / "i.png"), b"", 1, 0)
        media.embed(audio_cover, str(tmp_path / "a.wav"), b"", 1, 0)

        assert media.extract(str(tmp_path / "i.png"), 1, 0) == b""
        assert media.extract(str(tmp_path / "a.wav"), 1, 0) == b""

    def test_manifest_length_cross_check_is_passed_through(
        self, image_cover, tmp_path
    ):
        output = str(tmp_path / "stego.png")
        media.embed(image_cover, output, PAYLOAD, 2, 0)

        assert (
            media.extract(output, 2, 0, manifest_payload_length=len(PAYLOAD))
            == PAYLOAD
        )
        with pytest.raises(StegoError, match="disagrees with the manifest"):
            media.extract(output, 2, 0, manifest_payload_length=999)


# --------------------------------------------------------------------------- #
# Unified result shapes
# --------------------------------------------------------------------------- #


class TestUnifiedCapacity:
    def test_fields_agree_with_the_image_layer(self, image_cover):
        unified = media.measure(image_cover, 3, 10, payload_length=50)
        report, descriptor = image_stego.measure_capacity(
            image_cover, 3, 10, payload_length=50
        )

        assert unified.media_type == constants.MEDIA_IMAGE
        assert unified.container_format == constants.CONTAINER_PNG
        assert unified.report == report
        assert unified.descriptor == descriptor

    def test_fields_agree_with_the_audio_layer(self, audio_cover):
        unified = media.measure(audio_cover, 3, 10, payload_length=50)
        report, descriptor = audio_stego.measure_capacity(
            audio_cover, 3, 10, payload_length=50
        )

        assert unified.media_type == constants.MEDIA_AUDIO
        assert unified.container_format == constants.CONTAINER_WAV
        assert unified.report == report
        assert unified.descriptor == descriptor

    def test_convenience_properties_mirror_the_report(self, image_cover):
        unified = media.measure(image_cover, 4, 0, payload_length=100)

        assert unified.total_samples == unified.report.total_embeddable_samples
        assert unified.available_capacity_bytes == (
            unified.report.available_capacity_bytes
        )
        assert unified.max_payload_length == unified.report.max_payload_length
        assert unified.payload_fits == unified.report.payload_fits

    def test_total_samples_is_the_start_location_domain(self, image_cover):
        """This is the value the start-location derivation needs."""
        unified = media.measure(image_cover, 1)
        # 64 x 64 RGB, alpha excluded: three embeddable channels per pixel.
        assert unified.total_samples == 64 * 64 * 3

    def test_audio_total_samples_counts_every_channel(self, tmp_path):
        stereo = write_audio_file(str(tmp_path), make_audio(1_000, channels=2))
        assert media.measure(stereo, 1).total_samples == 2_000

    def test_measuring_an_oversized_payload_does_not_raise(self, image_cover):
        unified = media.measure(image_cover, 1, 0, payload_length=10**9)
        assert unified.payload_fits is False

    def test_both_media_return_a_capacity_report(self, image_cover, audio_cover):
        for path in (image_cover, audio_cover):
            assert isinstance(media.measure(path, 1).report, capacity.CapacityReport)


class TestUnifiedEmbedResult:
    def test_fields_agree_with_the_image_layer(self, image_cover, tmp_path):
        unified = media.embed(
            image_cover, str(tmp_path / "u.png"), PAYLOAD, 3, 10
        )
        direct = image_stego.embed_image(
            image_cover, str(tmp_path / "d.png"), PAYLOAD, 3, 10
        )

        assert unified.media_type == constants.MEDIA_IMAGE
        assert unified.container_format == direct.container_format
        assert unified.report == direct.capacity
        assert unified.lsb_count == direct.lsb_count
        assert unified.start_location == direct.start_location
        assert unified.payload_length == direct.payload_length
        assert unified.encoded_length == direct.encoded_length
        assert unified.samples_written == direct.samples_written

    def test_fields_agree_with_the_audio_layer(self, audio_cover, tmp_path):
        unified = media.embed(
            audio_cover, str(tmp_path / "u.wav"), PAYLOAD, 3, 10
        )
        direct = audio_stego.embed_audio(
            audio_cover, str(tmp_path / "d.wav"), PAYLOAD, 3, 10
        )

        assert unified.media_type == constants.MEDIA_AUDIO
        assert unified.container_format == direct.container_format
        assert unified.report == direct.capacity
        assert unified.encoded_length == direct.encoded_length
        assert unified.samples_written == direct.samples_written

    def test_the_same_fields_are_present_for_both_media(
        self, image_cover, audio_cover, tmp_path
    ):
        """The whole point: a caller can render either without branching."""
        image_result = media.embed(
            image_cover, str(tmp_path / "i.png"), PAYLOAD, 3, 10
        )
        audio_result = media.embed(
            audio_cover, str(tmp_path / "a.wav"), PAYLOAD, 3, 10
        )

        assert set(vars(image_result)) == set(vars(audio_result))

    def test_identical_settings_give_identical_shared_figures(
        self, image_cover, audio_cover, tmp_path
    ):
        image_result = media.embed(
            image_cover, str(tmp_path / "i.png"), PAYLOAD, 3, 10
        )
        audio_result = media.embed(
            audio_cover, str(tmp_path / "a.wav"), PAYLOAD, 3, 10
        )

        assert image_result.encoded_length == audio_result.encoded_length
        assert image_result.samples_written == audio_result.samples_written
        assert image_result.payload_length == audio_result.payload_length

    def test_output_path_is_reported(self, image_cover, tmp_path):
        output = str(tmp_path / "stego.png")
        assert media.embed(image_cover, output, PAYLOAD, 1, 0).output_path == output

    def test_descriptor_remains_available(self, image_cover, audio_cover, tmp_path):
        image_result = media.embed(
            image_cover, str(tmp_path / "i.png"), PAYLOAD, 1, 0
        )
        audio_result = media.embed(
            audio_cover, str(tmp_path / "a.wav"), PAYLOAD, 1, 0
        )

        assert image_result.descriptor.width == 64
        assert audio_result.descriptor.sample_rate == 44_100


# --------------------------------------------------------------------------- #
# Errors propagate unchanged
# --------------------------------------------------------------------------- #


class TestErrorPropagation:
    def test_capacity_failure(self, image_cover, tmp_path):
        with pytest.raises(CapacityError, match="does not fit"):
            media.embed(image_cover, str(tmp_path / "o.png"), bytes(10**6), 1, 0)

    def test_depth_out_of_range(self, image_cover, tmp_path):
        with pytest.raises(ValidationError, match="lsb_count"):
            media.embed(image_cover, str(tmp_path / "o.png"), PAYLOAD, 99, 0)

    def test_start_location_out_of_range(self, audio_cover, tmp_path):
        with pytest.raises(ValidationError, match="start_location"):
            media.embed(audio_cover, str(tmp_path / "o.wav"), PAYLOAD, 1, 10**9)

    def test_in_place_write_is_refused_for_both_media(
        self, image_cover, audio_cover
    ):
        for path in (image_cover, audio_cover):
            with pytest.raises(ValidationError, match="must differ"):
                media.embed(path, path, PAYLOAD, 1, 0)

    def test_occupied_output_is_refused_for_both_media(
        self, image_cover, audio_cover, tmp_path
    ):
        for cover, name in ((image_cover, "o.png"), (audio_cover, "o.wav")):
            target = tmp_path / name
            target.write_bytes(b"existing")
            with pytest.raises(FileError, match="already occupied"):
                media.embed(cover, str(target), PAYLOAD, 1, 0)

    def test_overwrite_is_passed_through(self, image_cover, tmp_path):
        target = tmp_path / "o.png"
        target.write_bytes(b"existing")
        media.embed(image_cover, str(target), PAYLOAD, 1, 0, overwrite=True)
        assert media.extract(str(target), 1, 0) == PAYLOAD

    def test_one_handler_catches_every_medium(
        self, image_cover, audio_cover, tmp_path
    ):
        for cover, name in ((image_cover, "x.png"), (audio_cover, "x.wav")):
            with pytest.raises(StegoError):
                media.embed(cover, str(tmp_path / name), PAYLOAD, 0, 0)
