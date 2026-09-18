"""Tests for the media property comparison table and the quality metrics facade.

The emphasis is on reporting honestly. Two rows in the table are *expected* to
differ after embedding — the file digest and, for PNG, the file size — and the
tests check that those are reported as differing and excluded from the structural
equality flag, rather than being hidden to make the table look tidy.
"""

from __future__ import annotations

import json
import math
import os

import pytest

from app.analysis import quality_metrics
from app.stego import audio_stego, image_io, image_stego
from app.stego.errors import ComparisonError, DecodeError, ValidationError
from app.utils import constants
from app.verification import media_compare
from conftest import make_audio, make_cover, write_audio_file, write_cover

PAYLOAD = b"INF2005 comparison test payload"


@pytest.fixture()
def image_pair_files(tmp_path):
    cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")
    stego = str(tmp_path / "stego.png")
    image_stego.embed_image(cover, stego, PAYLOAD, 3, 100)
    return cover, stego


@pytest.fixture()
def bmp_pair_files(tmp_path):
    cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.BMP, "cover")
    stego = str(tmp_path / "stego.bmp")
    image_stego.embed_image(cover, stego, PAYLOAD, 3, 100)
    return cover, stego


@pytest.fixture()
def audio_pair_files(tmp_path):
    cover = write_audio_file(str(tmp_path), make_audio(20_000))
    stego = str(tmp_path / "stego.wav")
    audio_stego.embed_audio(cover, stego, PAYLOAD, 3, 100)
    return cover, stego


# --------------------------------------------------------------------------- #
# Quality metrics facade
# --------------------------------------------------------------------------- #


class TestDistortionBound:
    @pytest.mark.parametrize("depth", range(1, 9))
    def test_bound_is_two_to_the_depth_minus_one(self, depth):
        assert quality_metrics.distortion_bound(depth) == (1 << depth) - 1

    def test_out_of_range_depth_is_refused(self):
        with pytest.raises(ValidationError, match="lsb_count"):
            quality_metrics.distortion_bound(9)

    def test_boolean_depth_is_refused(self):
        with pytest.raises(ValidationError, match="lsb_count"):
            quality_metrics.distortion_bound(True)


class TestImageQuality:
    def test_reports_shared_figures(self, image_pair_files):
        cover, stego = image_pair_files
        report = quality_metrics.compare_quality(cover, stego, lsb_depth=3)

        assert report.media_type == constants.MEDIA_IMAGE
        assert report.mse > 0
        assert report.psnr_unbounded is False
        assert report.identical is False
        assert report.changed_samples > 0
        assert report.total_samples == 64 * 64 * 3
        assert 0 < report.changed_proportion < 1

    def test_snr_is_none_for_images(self, image_pair_files):
        """Not invented where it has no accepted definition."""
        cover, stego = image_pair_files
        assert quality_metrics.compare_quality(cover, stego).snr_db is None

    def test_per_channel_figures_are_present(self, image_pair_files):
        cover, stego = image_pair_files
        report = quality_metrics.compare_quality(cover, stego)

        assert [channel.label for channel in report.channels] == [
            "red",
            "green",
            "blue",
        ]

    def test_identical_files_report_unbounded_psnr(self, tmp_path):
        cover = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "a")
        copy = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "b")

        report = quality_metrics.compare_quality(cover, copy)
        assert report.identical is True
        assert report.mse == 0.0
        assert report.psnr_unbounded is True

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_observed_difference_stays_within_the_bound(self, tmp_path, depth):
        cover = write_cover(
            str(tmp_path), make_cover(64, 64, 3), image_io.PNG, f"c{depth}"
        )
        stego = str(tmp_path / f"s{depth}.png")
        image_stego.embed_image(cover, stego, PAYLOAD, depth, 0)

        report = quality_metrics.compare_quality(cover, stego, lsb_depth=depth)
        assert report.within_distortion_bound is True
        assert report.expected_distortion_bound == (1 << depth) - 1
        assert report.max_absolute_difference <= report.expected_distortion_bound

    def test_bound_check_is_omitted_without_a_depth(self, image_pair_files):
        cover, stego = image_pair_files
        report = quality_metrics.compare_quality(cover, stego)
        assert report.within_distortion_bound is None
        assert report.expected_distortion_bound is None

    def test_psnr_falls_as_depth_rises(self, tmp_path):
        """More replaced bits means more distortion."""
        cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")
        payload = bytes(range(200))
        values = []
        for depth in (1, 4, 8):
            stego = str(tmp_path / f"s{depth}.png")
            image_stego.embed_image(cover, stego, payload, depth, 0)
            values.append(quality_metrics.compare_quality(cover, stego).psnr_db)

        assert values == sorted(values, reverse=True)


class TestAudioQuality:
    def test_reports_shared_figures(self, audio_pair_files):
        cover, stego = audio_pair_files
        report = quality_metrics.compare_quality(cover, stego, lsb_depth=3)

        assert report.media_type == constants.MEDIA_AUDIO
        assert report.mse > 0
        assert report.identical is False
        assert report.changed_samples > 0
        assert report.total_samples == 20_000

    def test_snr_is_reported_for_audio(self, audio_pair_files):
        cover, stego = audio_pair_files
        report = quality_metrics.compare_quality(cover, stego)
        assert report.snr_db is not None
        assert report.snr_db > 0

    def test_audio_extras_are_kept(self, audio_pair_files):
        cover, stego = audio_pair_files
        report = quality_metrics.compare_quality(cover, stego)

        assert report.extra["sample_rate"] == 44_100
        assert report.extra["channels"] == 1
        assert "rmse" in report.extra
        assert "mae" in report.extra

    def test_identical_files_report_unbounded_psnr(self, tmp_path):
        samples = make_audio(4_000)
        first = write_audio_file(str(tmp_path), samples, "a")
        second = write_audio_file(str(tmp_path), samples, "b")

        report = quality_metrics.compare_quality(first, second)
        assert report.identical is True
        assert report.psnr_unbounded is True
        assert math.isinf(report.psnr_db)

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_observed_difference_stays_within_the_bound(self, tmp_path, depth):
        cover = write_audio_file(str(tmp_path), make_audio(20_000), f"c{depth}")
        stego = str(tmp_path / f"s{depth}.wav")
        audio_stego.embed_audio(cover, stego, PAYLOAD, depth, 0)

        report = quality_metrics.compare_quality(cover, stego, lsb_depth=depth)
        assert report.within_distortion_bound is True


class TestVideoQuality:
    def test_a_clip_that_decodes_short_is_refused_not_truncated(
        self, video_factory, monkeypatch
    ):
        """Containers can misreport frame counts; a short clip must not be averaged."""
        from app.stego import video_stego

        cover = video_factory(frame_count=4, name="cover")
        stego = video_factory(frame_count=4, name="stego")
        real = video_stego.iterate_frames

        def short_for_stego(path, descriptor):
            frames = list(real(path, descriptor))
            return iter(frames[:-1] if path == stego else frames)

        monkeypatch.setattr(video_stego, "iterate_frames", short_for_stego)

        with pytest.raises(ComparisonError, match="stego clip decoded only 3 frames"):
            quality_metrics.compare_quality(cover, stego)


class TestQualityDispatch:
    def test_mixed_media_is_refused(self, tmp_path):
        image = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "i")
        audio = write_audio_file(str(tmp_path), make_audio(4_000))

        with pytest.raises(ComparisonError, match="cannot compare"):
            quality_metrics.compare_quality(image, audio)

    def test_unsupported_media_is_refused(self, tmp_path):
        path = tmp_path / "junk.dat"
        path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        with pytest.raises(DecodeError):
            quality_metrics.compare_quality(str(path), str(path))

    def test_mismatched_audio_raises_the_shared_comparison_error(self, tmp_path):
        """audio_analysis raises bare ValueError; the facade must translate it.

        Without the translation a caller would have to catch ComparisonError for
        images and ValueError for audio, which defeats the point of the facade.
        """
        first = write_audio_file(str(tmp_path), make_audio(4_000), "a", 44_100)
        second = write_audio_file(str(tmp_path), make_audio(4_000), "b", 22_050)

        with pytest.raises(ComparisonError, match="cannot be compared"):
            quality_metrics.compare_quality(first, second)

    def test_mismatched_audio_lengths_also_raise_comparison_error(self, tmp_path):
        first = write_audio_file(str(tmp_path), make_audio(4_000), "a")
        second = write_audio_file(str(tmp_path), make_audio(8_000), "b")

        with pytest.raises(ComparisonError, match="cannot be compared"):
            quality_metrics.compare_quality(first, second)

    def test_report_is_json_serialisable(self, image_pair_files):
        cover, stego = image_pair_files
        report = quality_metrics.compare_quality(cover, stego, lsb_depth=3)
        json.dumps(report.as_dict())

    def test_unbounded_psnr_serialises_as_null(self, tmp_path):
        """math.inf is not valid JSON, so it must not appear in the summary."""
        cover = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "a")
        copy = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "b")

        summary = quality_metrics.compare_quality(cover, copy).as_dict()
        assert summary["psnr_db"] is None
        assert summary["psnr_unbounded"] is True
        json.dumps(summary)

    def test_extra_is_copied_not_aliased(self):
        shared = {"a": 1}
        report = quality_metrics.QualityReport(
            media_type=constants.MEDIA_IMAGE,
            mse=0.0,
            psnr_db=0.0,
            psnr_unbounded=False,
            max_absolute_difference=0.0,
            changed_samples=0,
            total_samples=1,
            identical=True,
            extra=shared,
        )
        shared["a"] = 2
        assert report.extra["a"] == 1


# --------------------------------------------------------------------------- #
# Image comparison table
# --------------------------------------------------------------------------- #


class TestImageComparison:
    def test_structural_properties_are_preserved(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)

        assert comparison.media_type == constants.MEDIA_IMAGE
        assert comparison.structure_identical is True

    def test_expected_rows_are_present(self, image_pair_files):
        cover, stego = image_pair_files
        labels = [row.label for row in media_compare.compare(cover, stego).rows]

        for expected in ("Container", "Width", "Height", "Channels", "File size", "SHA-256"):
            assert expected in labels

    def test_the_digest_row_differs_and_says_why(self, image_pair_files):
        """Reported, not hidden. Embedding changes the cover by definition."""
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego)
        digest_row = next(row for row in comparison.rows if row.label == "SHA-256")

        assert digest_row.equal is False
        assert digest_row.structural is False
        assert "expected to differ" in digest_row.note

    def test_the_digest_row_does_not_affect_structural_equality(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego)

        assert comparison.structure_identical is True
        assert any(not row.equal for row in comparison.rows)

    def test_the_size_row_makes_no_promise_for_png(self, image_pair_files):
        """PNG is compressed, so a size change is legitimate."""
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego)
        size_row = next(row for row in comparison.rows if row.label == "File size")

        assert size_row.structural is False
        assert "compressed" in size_row.note

    def test_bmp_normally_preserves_size(self, bmp_pair_files):
        cover, stego = bmp_pair_files
        size_row = next(
            row
            for row in media_compare.compare(cover, stego).rows
            if row.label == "File size"
        )
        assert size_row.equal is True

    def test_pixel_row_reports_that_pixels_changed(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)
        row = next(row for row in comparison.rows if row.label == "Pixels identical")

        assert row.stego == "no"
        assert row.structural is False

    def test_quality_report_is_attached(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)

        assert comparison.quality is not None
        assert comparison.quality.within_distortion_bound is True

    def test_differing_dimensions_are_reported_rather_than_raising(self, tmp_path):
        """The properties table is still useful without the metrics."""
        first = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "a")
        second = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "b")

        comparison = media_compare.compare(first, second)
        assert comparison.quality is None
        assert comparison.structure_identical is False
        assert any(row.label == "Width" and not row.equal for row in comparison.rows)


# --------------------------------------------------------------------------- #
# Audio comparison table
# --------------------------------------------------------------------------- #


class TestAudioComparison:
    def test_structural_properties_are_preserved(self, audio_pair_files):
        cover, stego = audio_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)

        assert comparison.media_type == constants.MEDIA_AUDIO
        assert comparison.structure_identical is True

    def test_expected_rows_are_present(self, audio_pair_files):
        cover, stego = audio_pair_files
        labels = [row.label for row in media_compare.compare(cover, stego).rows]

        for expected in (
            "Container",
            "Subtype",
            "Sample rate",
            "Channels",
            "Frames",
            "Duration",
            "Scalar samples",
            "File size",
            "SHA-256",
        ):
            assert expected in labels

    def test_wav_preserves_the_file_size(self, audio_pair_files):
        """PCM replaces sample bytes in place."""
        cover, stego = audio_pair_files
        size_row = next(
            row
            for row in media_compare.compare(cover, stego).rows
            if row.label == "File size"
        )
        assert size_row.equal is True

    def test_changed_sample_row_reports_a_proportion(self, audio_pair_files):
        cover, stego = audio_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)
        row = next(row for row in comparison.rows if row.label == "Samples changed")

        assert "of 20000" in row.stego
        assert "%" in row.stego

    def test_stereo_is_compared(self, tmp_path):
        cover = write_audio_file(str(tmp_path), make_audio(8_000, channels=2))
        stego = str(tmp_path / "stego.wav")
        audio_stego.embed_audio(cover, stego, PAYLOAD, 2, 0)

        comparison = media_compare.compare(cover, stego, lsb_depth=2)
        channels_row = next(row for row in comparison.rows if row.label == "Channels")
        assert channels_row.original == "2"
        assert comparison.structure_identical is True

    def test_differing_sample_rates_are_reported(self, tmp_path):
        first = write_audio_file(str(tmp_path), make_audio(4_000), "a", 44_100)
        second = write_audio_file(str(tmp_path), make_audio(4_000), "b", 22_050)

        comparison = media_compare.compare(first, second)
        assert comparison.structure_identical is False
        assert comparison.quality is None


# --------------------------------------------------------------------------- #
# Rendering and dispatch
# --------------------------------------------------------------------------- #


class TestRendering:
    def test_text_table_has_a_line_per_row_plus_a_header(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego, lsb_depth=3)
        lines = comparison.as_text().splitlines()

        assert lines[0].strip().startswith("Original")
        assert len(lines) == len(comparison.rows) + 1

    def test_text_table_marks_equality(self, image_pair_files):
        cover, stego = image_pair_files
        text = media_compare.compare(cover, stego).as_text()

        assert "ok" in text
        assert "differs" in text

    def test_summary_is_json_serialisable(self, image_pair_files, audio_pair_files):
        for cover, stego in (image_pair_files, audio_pair_files):
            comparison = media_compare.compare(cover, stego, lsb_depth=3)
            json.dumps(comparison.as_dict())

    def test_summary_uses_file_names_not_paths(self, image_pair_files):
        cover, stego = image_pair_files
        summary = media_compare.compare(cover, stego).as_dict()

        assert summary["original"] == os.path.basename(cover)
        assert os.sep not in summary["original"]

    def test_differing_rows_are_listed(self, image_pair_files):
        cover, stego = image_pair_files
        comparison = media_compare.compare(cover, stego)

        assert all(not row.equal for row in comparison.differing_rows)
        assert any(row.label == "SHA-256" for row in comparison.differing_rows)

    def test_notes_are_attached(self, image_pair_files):
        cover, stego = image_pair_files
        assert media_compare.compare(cover, stego).notes


class TestComparisonDispatch:
    def test_mixed_media_is_refused(self, tmp_path):
        image = write_cover(str(tmp_path), make_cover(32, 32, 3), image_io.PNG, "i")
        audio = write_audio_file(str(tmp_path), make_audio(4_000))

        with pytest.raises(ComparisonError, match="different media types"):
            media_compare.compare(image, audio)

    def test_unsupported_media_is_refused(self, tmp_path):
        path = tmp_path / "junk.dat"
        path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        with pytest.raises(DecodeError):
            media_compare.compare(str(path), str(path))

    def test_missing_file_is_refused(self, tmp_path, image_pair_files):
        cover, _ = image_pair_files
        with pytest.raises(DecodeError):
            media_compare.compare(cover, str(tmp_path / "absent.png"))


# --------------------------------------------------------------------------- #
# Video property reading
# --------------------------------------------------------------------------- #


class TestVideoProperties:
    def test_fourcc_conversion(self):
        from app.utils import media_utils

        # 'FFV1' packed little end first.
        packed = (
            ord("F") | (ord("F") << 8) | (ord("V") << 16) | (ord("1") << 24)
        )
        assert media_utils.fourcc_to_codec(packed) == "FFV1"

    def test_zero_fourcc_is_unknown(self):
        from app.utils import media_utils

        assert media_utils.fourcc_to_codec(0) == "unknown"

    def test_missing_file_is_reported(self, tmp_path):
        from app.utils import media_utils

        with pytest.raises(media_utils.VideoInspectionError, match="not found"):
            media_utils.read_video_properties(str(tmp_path / "absent.mkv"))

    def test_non_video_content_is_reported(self, tmp_path):
        from app.utils import media_utils

        path = tmp_path / "fake.mkv"
        path.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 128)

        with pytest.raises(media_utils.VideoInspectionError):
            media_utils.read_video_properties(str(path))
