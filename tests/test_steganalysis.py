"""Tests for the media-agnostic steganalysis facade.

The properties that matter are about honesty as much as arithmetic:

* indicators work **without** a reference file, because that is the realistic case
* an indicator with too little data reports an insufficient sample rather than a
  precise-looking number computed from nothing
* nothing anywhere in the report is a verdict, a confidence or a probability
* the disclaimer travels with every single indicator

Also checked: the audio indicators actually respond to embedding, since an indicator
that never moves would be worthless even if it were honestly labelled.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from app.analysis import image_analysis, steganalysis
from app.stego import audio_stego, image_io, image_stego
from app.stego.errors import ComparisonError, DecodeError
from app.utils import constants

from conftest import make_audio, make_cover, write_audio_file, write_cover

PAYLOAD = b"INF2005 steganalysis test payload, long enough to touch many samples."


@pytest.fixture()
def image_pair(tmp_path):
    cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")
    stego = str(tmp_path / "cover_stego.png")
    image_stego.embed_image(cover, stego, PAYLOAD, 1, 0)
    return cover, stego


@pytest.fixture()
def audio_pair(tmp_path):
    cover = write_audio_file(str(tmp_path), make_audio(20_000, pattern="tone"))
    stego = str(tmp_path / "cover_stego.wav")
    audio_stego.embed_audio(cover, stego, PAYLOAD, 1, 0)
    return cover, stego


# --------------------------------------------------------------------------- #
# Image analysis
# --------------------------------------------------------------------------- #


class TestImageAnalysis:
    def test_it_works_without_a_reference(self, image_pair):
        """The realistic case: an analyst has the file and nothing else."""
        _, stego = image_pair
        report = steganalysis.analyse(stego)

        assert report.media_type == constants.MEDIA_IMAGE
        assert report.indicators
        assert report.has_reference is False
        assert report.difference is None
        assert report.quality is None

    def test_a_reference_adds_the_comparison_views(self, image_pair):
        cover, stego = image_pair
        report = steganalysis.analyse(stego, reference=cover)

        assert report.has_reference is True
        assert report.difference is not None
        assert report.histograms is not None
        assert report.quality is not None

    def test_all_four_indicators_are_reported(self, image_pair):
        _, stego = image_pair
        names = {indicator.name for indicator in steganalysis.analyse(stego).indicators}

        assert names == {
            "lsb_distribution",
            "bit0_uniformity_chi_square",
            "pair_of_values_chi_square",
            "pair_of_values_neighbour",
        }

    def test_bit_planes_cover_every_channel_and_bit(self, image_pair):
        _, stego = image_pair
        report = steganalysis.analyse(stego)

        # Three channels, eight bit positions each.
        assert len(report.bit_planes) == 24
        assert {plane.bit_position for plane in report.bit_planes} == set(range(8))

    def test_the_difference_image_is_amplified(self, image_pair):
        """A one-bit change is indistinguishable from black otherwise."""
        cover, stego = image_pair
        report = steganalysis.analyse(stego, reference=cover)

        assert report.difference.mode == "amplified"
        assert int(report.difference.difference.max()) > 1

    def test_unscaled_planes_hold_only_zero_and_one(self, image_pair):
        _, stego = image_pair
        report = steganalysis.analyse(stego, scaled_planes=False)
        values = set(np.unique(report.bit_planes[0].plane).tolist())
        assert values <= {0, 1}

    def test_scaled_planes_are_viewable(self, image_pair):
        _, stego = image_pair
        report = steganalysis.analyse(stego, scaled_planes=True)
        values = set(np.unique(report.bit_planes[0].plane).tolist())
        assert values <= {0, 255}

    def test_a_threshold_is_recorded_as_a_comparison_not_a_detection(self, image_pair):
        _, stego = image_pair
        report = steganalysis.analyse(stego, threshold=1.0)

        thresholded = [
            indicator
            for indicator in report.indicators
            if indicator.threshold is not None
        ]
        assert thresholded
        for indicator in thresholded:
            assert indicator.threshold == 1.0
            assert indicator.threshold_exceeded in (True, False)


# --------------------------------------------------------------------------- #
# Audio analysis
# --------------------------------------------------------------------------- #


class TestAudioAnalysis:
    def test_it_works_without_a_reference(self, audio_pair):
        _, stego = audio_pair
        report = steganalysis.analyse(stego)

        assert report.media_type == constants.MEDIA_AUDIO
        assert report.indicators
        assert report.has_reference is False

    def test_no_bit_planes_for_audio(self, audio_pair):
        """Audio has no spatial planes; claiming otherwise would be nonsense."""
        _, stego = audio_pair
        assert steganalysis.analyse(stego).bit_planes == ()

    def test_a_reference_adds_the_sample_difference(self, audio_pair):
        cover, stego = audio_pair
        report = steganalysis.analyse(stego, reference=cover)

        assert report.sample_difference is not None
        assert report.quality is not None
        assert int(np.count_nonzero(report.sample_difference)) > 0

    def test_the_lsb_distribution_responds_to_embedding(self, tmp_path):
        """An indicator that never moves would be worthless."""
        # A tone has strongly patterned low bits; embedding randomises them.
        cover = write_audio_file(str(tmp_path), make_audio(20_000, pattern="tone"))
        stego = str(tmp_path / "stego.wav")
        payload = bytes(range(256)) * 8
        audio_stego.embed_audio(cover, stego, payload, 1, 0)

        before = next(
            indicator
            for indicator in steganalysis.audio_indicators(cover)
            if indicator.name == "lsb_distribution"
        )
        after = next(
            indicator
            for indicator in steganalysis.audio_indicators(stego)
            if indicator.name == "lsb_distribution"
        )
        assert before.value != after.value

    def test_the_neighbour_indicator_is_computed_per_channel(self, tmp_path):
        """Consecutive scalar samples of a stereo file are different channels."""
        stereo = write_audio_file(str(tmp_path), make_audio(8_000, channels=2))
        indicator = next(
            item
            for item in steganalysis.audio_indicators(stereo)
            if item.name == "pair_of_values_neighbour"
        )
        assert indicator.details["channels"] == 2.0
        # Two channels of 8000 frames give 2 * 7999 within-channel pairs.
        assert indicator.details["examined_pair_count"] == 2 * 7_999

    def test_the_histogram_pair_test_is_reported_as_not_applicable(self, audio_pair):
        """Stated rather than computed, because it does not transfer to 16-bit audio."""
        _, stego = audio_pair
        indicator = next(
            item
            for item in steganalysis.analyse(stego).indicators
            if item.name == "pair_of_values_chi_square"
        )
        assert indicator.value is None
        assert indicator.insufficient_sample is True
        assert "65,536" in indicator.explanation

    def test_a_very_short_file_reports_insufficient_samples(self, tmp_path):
        tiny = write_audio_file(str(tmp_path), make_audio(64))
        for indicator in steganalysis.audio_indicators(tiny):
            if indicator.name == "bit0_uniformity_chi_square":
                assert indicator.insufficient_sample is True
                assert indicator.value is None

    def test_a_silent_file_is_handled(self, tmp_path):
        """All-zero samples are the degenerate case for every ratio here."""
        silent = write_audio_file(str(tmp_path), make_audio(4_000, pattern="silence"))
        report = steganalysis.analyse(silent)

        distribution = next(
            item for item in report.indicators if item.name == "lsb_distribution"
        )
        assert distribution.value == 0.0

    def test_extreme_samples_are_handled(self, tmp_path):
        """-32768 and 32767 exercise the sign boundary of the reinterpretation."""
        extremes = write_audio_file(
            str(tmp_path), make_audio(4_000, pattern="extremes", seed=3)
        )
        assert steganalysis.analyse(extremes).indicators


# --------------------------------------------------------------------------- #
# Honesty properties
# --------------------------------------------------------------------------- #


class TestHonesty:
    def test_every_indicator_carries_the_disclaimer(self, image_pair, audio_pair):
        for _, stego in (image_pair, audio_pair):
            report = steganalysis.analyse(stego)
            assert report.indicators
            for indicator in report.indicators:
                assert indicator.disclaimer == image_analysis.INDICATOR_DISCLAIMER

    def test_the_report_carries_the_disclaimer(self, image_pair):
        _, stego = image_pair
        assert steganalysis.analyse(stego).disclaimer == (
            image_analysis.INDICATOR_DISCLAIMER
        )

    def test_the_disclaimer_denies_being_a_detector(self):
        text = image_analysis.INDICATOR_DISCLAIMER.lower()
        assert "does not establish" in text
        assert "indicator" in text

    def test_no_verdict_confidence_or_probability_anywhere(self, image_pair, audio_pair):
        """The whole point: these are statistics, not detections."""
        forbidden = ("verdict", "confidence", "probability", "detected", "likelihood")

        for _, stego in (image_pair, audio_pair):
            summary = json.dumps(steganalysis.analyse(stego).as_dict()).lower()
            for word in forbidden:
                assert word not in summary

    def test_an_insufficient_sample_reports_no_value(self, tmp_path):
        """Better than a precise-looking number computed from nothing."""
        tiny = write_cover(str(tmp_path), make_cover(4, 4, 3), image_io.PNG, "tiny")
        report = steganalysis.analyse(tiny)

        suppressed = [
            indicator for indicator in report.indicators if indicator.insufficient_sample
        ]
        assert suppressed
        for indicator in suppressed:
            if indicator.name != "lsb_distribution":
                assert indicator.value is None

    def test_every_indicator_explains_what_it_measures(self, image_pair):
        _, stego = image_pair
        for indicator in steganalysis.analyse(stego).indicators:
            assert indicator.explanation

    def test_the_summary_is_json_serialisable(self, image_pair, audio_pair):
        for _, stego in (image_pair, audio_pair):
            json.dumps(steganalysis.analyse(stego).as_dict())

    def test_details_are_copied_not_aliased(self):
        shared = {"a": 1.0}
        indicator = steganalysis.Indicator(
            name="x",
            scope="overall",
            value=0.5,
            insufficient_sample=False,
            analysed_sample_count=1,
            explanation="",
            details=shared,
        )
        shared["a"] = 2.0
        assert indicator.details["a"] == 1.0


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #


class TestDispatch:
    def test_a_mismatched_reference_is_refused(self, image_pair, audio_pair):
        _, image_stego_path = image_pair
        _, audio_stego_path = audio_pair

        with pytest.raises(ComparisonError, match="cannot compare"):
            steganalysis.analyse(image_stego_path, reference=audio_stego_path)

    def test_unsupported_media_is_refused(self, tmp_path):
        path = tmp_path / "junk.dat"
        path.write_bytes(b"\x01\x02\x03\x04" + b"\x00" * 32)

        with pytest.raises(DecodeError):
            steganalysis.analyse(str(path))

    def test_video_is_reported_as_not_implemented(self, tmp_path):
        path = tmp_path / "clip.mkv"
        path.write_bytes(b"\x1a\x45\xdf\xa3" + b"\x00" * 64)

        with pytest.raises((ComparisonError, DecodeError)):
            steganalysis.analyse(str(path))

    def test_a_bmp_is_analysed(self, tmp_path):
        cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.BMP, "cover")
        stego = str(tmp_path / "stego.bmp")
        image_stego.embed_image(cover, stego, PAYLOAD, 2, 0)

        report = steganalysis.analyse(stego, reference=cover)
        assert report.media_type == constants.MEDIA_IMAGE
        assert report.quality is not None

    def test_a_grayscale_image_is_analysed(self, tmp_path):
        cover = write_cover(str(tmp_path), make_cover(64, 64, 1), image_io.PNG, "gray")
        report = steganalysis.analyse(cover)

        assert len(report.bit_planes) == 8
        assert report.bit_planes[0].channel_label == "gray"
