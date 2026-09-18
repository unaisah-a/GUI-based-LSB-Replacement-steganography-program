"""Tests for quality metrics, bit planes, difference images and steganalysis.

Requirements 8 to 12, plus the metric-correctness and immutability properties of
Requirement 15.5 and 15.7.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import math
import os
import pathlib
import subprocess
import sys
import textwrap

import numpy as np
import pytest
from hypothesis import given

from app.analysis import image_analysis as analysis
from app.stego import image_io, image_stego
from app.stego.errors import ComparisonError, ValidationError

from conftest import image_pair, make_cover, write_cover

# --------------------------------------------------------------------------- #
# Requirement 8 and 15.5: quality metrics
# --------------------------------------------------------------------------- #


class TestMetricCorrectness:
    """Requirement 8.5 to 8.7 and 15.5."""

    @given(image_pair())
    def test_zero_error_exactly_when_identical(self, pair):
        first, second = pair
        result = analysis.compare_quality(first, second)
        identical = np.array_equal(first, second)

        assert result.pixel_identical is identical
        if identical:
            assert result.overall_mse == 0.0
            assert result.overall_psnr_db == math.inf
            assert result.overall_psnr_unbounded is True
        else:
            assert result.overall_mse > 0.0
            assert math.isfinite(result.overall_psnr_db)
            assert result.overall_psnr_unbounded is False

    @given(image_pair())
    def test_metrics_are_symmetric(self, pair):
        first, second = pair
        forward = analysis.compare_quality(first, second)
        backward = analysis.compare_quality(second, first)

        assert forward.overall_mse == backward.overall_mse
        assert forward.overall_psnr_db == backward.overall_psnr_db
        assert forward.max_absolute_difference == backward.max_absolute_difference
        assert forward.differing_samples == backward.differing_samples
        assert [channel.mse for channel in forward.channels] == [
            channel.mse for channel in backward.channels
        ]

    def test_no_unsigned_wraparound_on_subtraction(self):
        """uint8 subtraction wraps; the metrics must widen first.

        Without widening, 3 - 5 becomes 254 and the reported MSE would be 64516
        instead of 4.
        """
        low = np.full((1, 1, 3), 3, dtype=np.uint8)
        high = np.full((1, 1, 3), 5, dtype=np.uint8)
        result = analysis.compare_quality(low, high)
        assert result.overall_mse == 4.0
        assert result.max_absolute_difference == 2

    def test_no_overflow_on_squaring(self):
        """A uint8 difference of 255 squares to 65025, beyond uint8 and uint16 sums."""
        black = np.zeros((8, 8, 3), dtype=np.uint8)
        white = np.full((8, 8, 3), 255, dtype=np.uint8)
        result = analysis.compare_quality(black, white)
        assert result.overall_mse == 255.0**2
        assert result.overall_psnr_db == pytest.approx(0.0, abs=1e-9)

    def test_psnr_matches_the_formula(self):
        first = np.zeros((4, 4, 3), dtype=np.uint8)
        second = first.copy()
        second[0, 0, 0] = 16
        result = analysis.compare_quality(first, second)
        expected_mse = (16**2) / (4 * 4 * 3)
        assert result.overall_mse == pytest.approx(expected_mse)
        assert result.overall_psnr_db == pytest.approx(
            10 * math.log10(255**2 / expected_mse)
        )

    def test_shape_mismatch_is_reported_with_both_shapes(self):
        first = make_cover(4, 4, 3, "noise", 1)
        second = make_cover(5, 4, 3, "noise", 1)
        with pytest.raises(ComparisonError) as info:
            analysis.compare_quality(first, second)
        assert "4x4x3" in str(info.value) and "5x4x3" in str(info.value)

    def test_channel_count_mismatch_is_reported(self):
        with pytest.raises(ComparisonError):
            analysis.compare_quality(
                make_cover(4, 4, 3, "noise", 1), make_cover(4, 4, 4, "noise", 1)
            )


class TestAlphaHandling:
    """Requirement 8.9: alpha is excluded from the overall figures only."""

    def test_alpha_difference_does_not_move_the_overall_metrics(self):
        first = make_cover(8, 8, 4, "flat", 1)
        second = first.copy()
        second[:, :, 3] = (second[:, :, 3].astype(np.int16) ^ 0xFF).astype(np.uint8)

        result = analysis.compare_quality(first, second)
        assert result.overall_mse == 0.0
        assert result.overall_psnr_unbounded is True
        assert result.alpha_excluded_from_overall is True

        alpha = next(channel for channel in result.channels if channel.is_alpha)
        assert alpha.mse > 0.0
        assert alpha.label == "alpha"
        # But it is still visible as a difference at the sample level.
        assert result.pixel_identical is False
        assert result.differing_samples == 64

    def test_identical_channel_reports_unbounded_psnr(self):
        """Requirement 8.6."""
        first = make_cover(8, 8, 3, "noise", 1)
        second = first.copy()
        second[:, :, 0] = (second[:, :, 0].astype(np.int16) ^ 1).astype(np.uint8)
        result = analysis.compare_quality(first, second)
        assert result.channels[0].psnr_unbounded is False
        assert result.channels[1].psnr_unbounded is True
        assert result.channels[2].mse == 0.0


class TestReportedProperties:
    """Requirement 8.2, 8.3, 8.10 and 8.11."""

    def test_shape_facts_are_reported(self):
        result = analysis.compare_quality(
            make_cover(6, 7, 3, "noise", 1), make_cover(6, 7, 3, "noise", 2)
        )
        assert (result.height, result.width, result.channel_count) == (6, 7, 3)
        assert result.dimensions_equal and result.channel_count_equal

    def test_file_sizes_are_reported_for_paths(self, workspace):
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"payload" * 10, 1, 0)
        result = analysis.compare_quality(cover, output)
        assert result.file_size_a == os.path.getsize(cover)
        assert result.file_size_b == os.path.getsize(output)
        assert result.file_size_equal == (result.file_size_a == result.file_size_b)

    def test_file_sizes_are_absent_for_arrays(self):
        result = analysis.compare_quality(
            make_cover(4, 4, 3, "noise", 1), make_cover(4, 4, 3, "noise", 1)
        )
        assert result.file_size_a is None
        assert result.file_size_equal is None

    def test_no_cryptographic_digest_is_produced(self):
        """Requirement 8.11: digests belong to the cryptography layer."""
        result = analysis.compare_quality(
            make_cover(4, 4, 3, "noise", 1), make_cover(4, 4, 3, "noise", 1)
        )
        names = {field.name for field in dataclasses.fields(result)}
        assert not any(
            token in name
            for name in names
            for token in ("sha", "hash", "digest_value", "checksum")
        )
        assert "digest_note" in names


# --------------------------------------------------------------------------- #
# Requirement 9: bit planes
# --------------------------------------------------------------------------- #


class TestBitPlanes:
    def test_scaled_values(self):
        result = analysis.extract_bit_plane(
            make_cover(8, 8, 3, "noise", 1), 0, 0, scaled=True
        )
        assert set(np.unique(result.plane).tolist()) <= {0, 255}
        assert result.plane.dtype == np.uint8
        assert result.scaled is True

    def test_unscaled_values(self):
        result = analysis.extract_bit_plane(
            make_cover(8, 8, 3, "noise", 1), 0, 0, scaled=False
        )
        assert set(np.unique(result.plane).tolist()) <= {0, 1}

    def test_plane_shape_matches_the_image(self):
        result = analysis.extract_bit_plane(make_cover(5, 9, 3, "noise", 1), 3, 1)
        assert result.plane.shape == (5, 9)

    def test_plane_content_is_correct(self):
        array = np.array([[[0b1010_1010, 0, 0]]], dtype=np.uint8)
        for position, expected in enumerate([0, 1, 0, 1, 0, 1, 0, 1]):
            plane = analysis.extract_bit_plane(array, position, 0, scaled=False).plane
            assert int(plane[0, 0]) == expected

    def test_all_planes_ordering_and_count(self):
        """Requirement 9.7."""
        planes = analysis.extract_all_bit_planes(make_cover(4, 4, 4, "noise", 1))
        assert len(planes) == 4 * 8
        assert [(p.channel_index, p.bit_position) for p in planes[:9]] == [
            (0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7), (1, 0)
        ]

    def test_alpha_channel_is_addressable(self):
        """Requirement 9.6, even though embedding never touches alpha."""
        result = analysis.extract_bit_plane(make_cover(4, 4, 4, "noise", 1), 0, 3)
        assert result.channel_label == "alpha"

    @pytest.mark.parametrize("position", [-1, 8, 100])
    def test_invalid_bit_position(self, position):
        with pytest.raises(ValidationError, match="bit_position"):
            analysis.extract_bit_plane(make_cover(4, 4, 3, "noise", 1), position, 0)

    @pytest.mark.parametrize("channel", [-1, 3, 99])
    def test_invalid_channel_index(self, channel):
        with pytest.raises(ValidationError, match="channel"):
            analysis.extract_bit_plane(make_cover(4, 4, 3, "noise", 1), 0, channel)

    @pytest.mark.parametrize("position", [True, 1.0, "0"])
    def test_non_integer_bit_position(self, position):
        with pytest.raises(ValidationError, match="bit_position"):
            analysis.extract_bit_plane(make_cover(4, 4, 3, "noise", 1), position, 0)

    def test_lsb_plane_reveals_an_embedded_payload(self, workspace):
        """The demonstration this feature exists for.

        A flat cover has a uniform LSB plane; after embedding, the written region
        becomes visibly noisy while the untouched region stays uniform.
        """
        cover = write_cover(
            workspace, make_cover(64, 64, 3, "flat", 0) * 0, image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, bytes(range(256)) * 2, 1, 0)

        before = analysis.extract_bit_plane(cover, 0, 0, scaled=False).plane
        after = analysis.extract_bit_plane(output, 0, 0, scaled=False).plane
        assert int(before.sum()) == 0
        assert int(after.sum()) > 0


# --------------------------------------------------------------------------- #
# Requirement 10: difference images
# --------------------------------------------------------------------------- #


class TestDifferenceImage:
    def test_raw_difference(self):
        first = np.full((2, 2, 3), 10, dtype=np.uint8)
        second = np.full((2, 2, 3), 13, dtype=np.uint8)
        result = analysis.difference_image(first, second)
        assert result.mode == "raw"
        assert int(result.difference.max()) == 3
        assert result.max_absolute_difference == 3
        assert result.scale_factor == 1.0

    def test_raw_difference_does_not_wrap(self):
        first = np.full((2, 2, 3), 3, dtype=np.uint8)
        second = np.full((2, 2, 3), 5, dtype=np.uint8)
        assert int(analysis.difference_image(first, second).difference.max()) == 2

    def test_amplified_difference_reaches_full_scale(self):
        first = np.zeros((4, 4, 3), dtype=np.uint8)
        second = first.copy()
        second[0, 0, 0] = 1
        result = analysis.difference_image(first, second, amplify=True)
        assert result.mode == "amplified"
        assert result.max_absolute_difference == 1
        assert result.scale_factor == 255.0
        assert int(result.difference.max()) == 255

    def test_amplify_on_identical_images_does_not_divide_by_zero(self):
        """Requirement 10.3."""
        array = make_cover(4, 4, 3, "noise", 1)
        result = analysis.difference_image(array, array.copy(), amplify=True)
        assert result.scale_factor == 1.0
        assert int(result.difference.max()) == 0
        assert result.max_absolute_difference == 0

    def test_binary_mask_mode(self):
        first = np.zeros((2, 2, 3), dtype=np.uint8)
        second = first.copy()
        second[0, 0, 0] = 7
        result = analysis.difference_image(first, second, binary_mask=True)
        assert result.mode == "binary"
        assert set(np.unique(result.difference).tolist()) <= {0, 255}
        assert int(result.difference[0, 0, 0]) == 255

    def test_modes_are_mutually_exclusive(self):
        """Requirement 10.5."""
        array = make_cover(4, 4, 3, "noise", 1)
        with pytest.raises(ValidationError, match="mutually exclusive"):
            analysis.difference_image(array, array, amplify=True, binary_mask=True)

    def test_counts_and_changed_pixel_map(self):
        first = np.zeros((3, 3, 3), dtype=np.uint8)
        second = first.copy()
        second[0, 0, 0] = 1
        second[1, 1, 2] = 5
        result = analysis.difference_image(first, second)

        assert result.differing_samples == 2
        assert result.changed_pixels == 2
        assert result.total_samples == 27
        assert result.differing_proportion == pytest.approx(2 / 27)
        assert result.changed_pixel_map.dtype == np.bool_
        assert result.changed_pixel_map.shape == (3, 3)
        assert bool(result.changed_pixel_map[0, 0]) is True
        assert bool(result.changed_pixel_map[2, 2]) is False

    def test_alpha_is_included(self):
        """Requirement 10.6: the difference view reports alpha changes."""
        first = make_cover(4, 4, 4, "flat", 1)
        second = first.copy()
        second[0, 0, 3] = (int(second[0, 0, 3]) ^ 0xFF) & 0xFF
        result = analysis.difference_image(first, second)
        assert result.includes_alpha is True
        assert result.differing_samples == 1
        assert bool(result.changed_pixel_map[0, 0]) is True

    def test_shape_mismatch(self):
        with pytest.raises(ComparisonError):
            analysis.difference_image(
                make_cover(4, 4, 3, "noise", 1), make_cover(4, 5, 3, "noise", 1)
            )

    def test_difference_localises_the_embedding_window(self, workspace):
        cover_array = make_cover(40, 40, 3, "flat", 0) * 0
        cover = write_cover(workspace, cover_array, image_io.PNG, "cover")
        output = os.path.join(workspace, "stego.png")
        result = image_stego.embed_image(cover, output, b"\xff" * 100, 1, 0)

        difference = analysis.difference_image(cover, output)
        # Only samples inside the written window can differ.
        assert difference.differing_samples <= result.samples_written


# --------------------------------------------------------------------------- #
# Requirement 11: steganalysis indicators
# --------------------------------------------------------------------------- #


class TestLsbDistribution:
    def test_counts_and_proportion(self):
        array = np.zeros((16, 16, 3), dtype=np.uint8)
        array[:, :, 0] = 1  # every red sample has bit 0 set
        results = analysis.lsb_distribution(array)
        red = next(r for r in results if r.channel_index == 0)
        green = next(r for r in results if r.channel_index == 1)

        assert red.value == 1.0
        assert red.details["ones_count"] == 256.0
        assert green.value == 0.0
        assert red.analysed_sample_count == 256

    def test_overall_result_is_included(self):
        results = analysis.lsb_distribution(make_cover(16, 16, 3, "noise", 1))
        overall = [r for r in results if r.scope == "overall"]
        assert len(overall) == 1
        assert overall[0].analysed_sample_count == 16 * 16 * 3

    def test_alpha_is_excluded(self):
        array = make_cover(16, 16, 4, "noise", 1)
        results = analysis.lsb_distribution(array)
        assert {r.channel_index for r in results if r.channel_index is not None} == {
            0, 1, 2
        }

    def test_no_reference_cover_is_required(self):
        # A single argument suffices; a real analyst has no original.
        assert analysis.lsb_distribution(make_cover(16, 16, 3, "noise", 1))


class TestBit0Uniformity:
    def test_balanced_channel_gives_a_p_value_of_one(self):
        array = np.zeros((16, 16, 3), dtype=np.uint8)
        flat = array[:, :, 0].reshape(-1)
        flat[::2] = 1
        array[:, :, 0] = flat.reshape(16, 16)
        result = analysis.bit0_uniformity(array)[0]
        assert result.details["statistic"] == pytest.approx(0.0)
        assert result.value == pytest.approx(1.0)
        assert result.degrees_of_freedom == 1

    def test_all_zero_channel_gives_the_sample_count(self):
        array = np.zeros((16, 16, 3), dtype=np.uint8)
        result = analysis.bit0_uniformity(array)[0]
        # Every sample in one category: chi-square equals n, far out in the tail.
        assert result.details["statistic"] == pytest.approx(256.0)
        assert result.value == pytest.approx(0.0, abs=1e-12)

    def test_insufficient_samples_suppresses_the_value(self):
        """Requirement 11.10."""
        result = analysis.bit0_uniformity(make_cover(4, 4, 3, "noise", 1))[0]
        assert result.insufficient_sample is True
        assert result.value is None
        assert result.threshold_exceeded is None
        assert result.analysed_sample_count == 16


class TestPairOfValuesChiSquare:
    def test_reports_degrees_of_freedom_and_bin_accounting(self):
        array = make_cover(64, 64, 3, "noise", 1)
        result = analysis.pair_of_values_chi_square(array)[0]
        included = int(result.details["included_bin_pairs"])
        excluded = int(result.details["excluded_bin_pairs"])
        assert included + excluded == 128
        assert result.degrees_of_freedom == included - 1

    def test_low_expected_count_bins_are_excluded(self):
        """Requirement 11.9: the below-5 guard for the approximation."""
        # Only two distinct values, so 127 pairs have an expected count of 0.
        array = np.zeros((32, 32, 3), dtype=np.uint8)
        array[:, :16, 0] = 1
        result = analysis.pair_of_values_chi_square(array)[0]
        assert int(result.details["excluded_bin_pairs"]) == 127
        assert int(result.details["included_bin_pairs"]) == 1
        # One included pair leaves 0 degrees of freedom, so the value is withheld.
        assert result.insufficient_sample is True
        assert result.value is None

    def test_threshold_flag_and_direction(self):
        """Requirement 11.8."""
        array = make_cover(64, 64, 3, "gradient", 1)
        high = analysis.pair_of_values_chi_square(array, threshold=0.0)[0]
        assert high.threshold == 0.0
        assert high.threshold_exceeded is True
        assert high.threshold_direction == "value >= threshold"

        low = analysis.pair_of_values_chi_square(array, threshold=1e18)[0]
        assert low.threshold_exceeded is False

    def test_no_threshold_gives_no_flag(self):
        result = analysis.pair_of_values_chi_square(
            make_cover(64, 64, 3, "noise", 1)
        )[0]
        assert result.threshold is None
        assert result.threshold_exceeded is None

    def test_embedding_moves_the_statistic(self, workspace):
        """The indicator responds to embedding, without claiming detection."""
        cover = write_cover(
            workspace, make_cover(128, 128, 3, "gradient", 0), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        report, _ = image_stego.measure_capacity(cover, 1, 0)
        image_stego.embed_image(
            cover, output, bytes(range(256)) * (report.max_payload_length // 256), 1, 0
        )
        before = analysis.pair_of_values_chi_square(cover)[0].details["statistic"]
        after = analysis.pair_of_values_chi_square(output)[0].details["statistic"]
        assert before != after

    def test_embedding_raises_the_p_value_and_trips_the_threshold(self, workspace):
        """Replacement equalises the (2k, 2k+1) pairs, so the p-value rises toward 1.

        The cover holds only even values, so every pair starts maximally unequal and
        the clean p-value is essentially 0. Filling the cover at depth 1 must push it
        up and trip a threshold that the cover does not.
        """
        rng = np.random.default_rng(7)
        array = (rng.integers(0, 128, (96, 96, 3)) * 2).astype(np.uint8)
        cover = write_cover(workspace, array, image_io.PNG, "even")
        output = os.path.join(workspace, "stego.png")
        report, _ = image_stego.measure_capacity(cover, 1, 0)
        payload = rng.integers(0, 256, report.max_payload_length, dtype=np.uint8)
        image_stego.embed_image(cover, output, payload.tobytes(), 1, 0)

        clean = analysis.pair_of_values_chi_square(cover, threshold=0.5)[0]
        stego = analysis.pair_of_values_chi_square(output, threshold=0.5)[0]

        assert clean.value < 0.01
        assert stego.value > clean.value
        assert clean.threshold_exceeded is False
        assert stego.threshold_exceeded is True


class TestPairOfValuesNeighbour:
    def test_pair_count_formula(self):
        """Requirement 11.4: (width - 1) * height pairs, never across rows."""
        result = analysis.pair_of_values_neighbour(make_cover(20, 30, 3, "noise", 1))[0]
        assert int(result.details["examined_pair_count"]) == (30 - 1) * 20

    def test_matching_pairs_are_counted(self):
        # Alternating 0 and 1 differ only in bit 0, so every pair matches.
        row = np.tile(np.array([0, 1], dtype=np.uint8), 16)
        array = np.stack([np.tile(row, (20, 1))] * 3, axis=2)
        result = analysis.pair_of_values_neighbour(array)[0]
        assert result.value == pytest.approx(1.0)

    def test_flat_image_has_no_matching_pairs(self):
        array = np.full((20, 32, 3), 100, dtype=np.uint8)
        result = analysis.pair_of_values_neighbour(array)[0]
        assert result.value == pytest.approx(0.0)

    def test_single_column_has_no_pairs(self):
        """Requirement 11.10: no examined pairs means no value."""
        array = make_cover(300, 1, 3, "noise", 1)
        result = analysis.pair_of_values_neighbour(array)[0]
        assert int(result.details["examined_pair_count"]) == 0
        assert result.insufficient_sample is True
        assert result.value is None


class TestRegionOfInterest:
    """Requirement 11.11."""

    def test_region_restricts_the_analysed_samples(self):
        array = make_cover(64, 64, 3, "noise", 1)
        result = analysis.lsb_distribution(array, region=(10, 10, 20, 30))[0]
        assert result.analysed_sample_count == 20 * 30
        assert result.region == {"left": 10, "top": 10, "width": 20, "height": 30}

    def test_region_is_reported_on_every_indicator(self):
        array = make_cover(64, 64, 3, "noise", 1)
        region = analysis.Region(0, 0, 32, 32)
        for function in (
            analysis.lsb_distribution,
            analysis.bit0_uniformity,
            analysis.pair_of_values_chi_square,
            analysis.pair_of_values_neighbour,
        ):
            for result in function(array, region=region):
                assert result.region == region.as_dict()

    def test_region_changes_the_result(self):
        array = np.zeros((64, 64, 3), dtype=np.uint8)
        array[:32] = 1  # top half has bit 0 set
        top = analysis.lsb_distribution(array, region=(0, 0, 64, 32))[0]
        bottom = analysis.lsb_distribution(array, region=(0, 32, 64, 32))[0]
        assert top.value == 1.0
        assert bottom.value == 0.0

    @pytest.mark.parametrize(
        "region", [(0, 0, 0, 10), (0, 0, 10, 0), (-1, 0, 5, 5), (60, 60, 10, 10)]
    )
    def test_invalid_regions(self, region):
        with pytest.raises(ValidationError, match="region"):
            analysis.lsb_distribution(make_cover(64, 64, 3, "noise", 1), region=region)

    def test_malformed_region_type(self):
        with pytest.raises(ValidationError, match="region"):
            analysis.lsb_distribution(
                make_cover(64, 64, 3, "noise", 1), region="whole image"
            )


class TestHonestReporting:
    """Requirement 11.5 to 11.7."""

    @pytest.fixture()
    def every_indicator(self):
        array = make_cover(64, 64, 3, "noise", 1)
        return (
            analysis.lsb_distribution(array)
            + analysis.bit0_uniformity(array)
            + analysis.pair_of_values_chi_square(array)
            + analysis.pair_of_values_neighbour(array)
        )

    def test_every_result_carries_a_disclaimer(self, every_indicator):
        for result in every_indicator:
            assert result.disclaimer == analysis.INDICATOR_DISCLAIMER
            assert "does not establish" in result.disclaimer

    def test_every_result_names_itself_and_its_scope(self, every_indicator):
        for result in every_indicator:
            assert result.name
            assert result.scope
            assert result.analysed_sample_count >= 0

    def test_no_verdict_or_confidence_field_exists(self, every_indicator):
        """Requirement 11.7: no verdict, confidence or probability, anywhere."""
        forbidden = (
            "verdict",
            "confidence",
            "probability",
            "likelihood",
            "detected",
            "is_stego",
            "score",
        )
        names = {field.name for field in dataclasses.fields(analysis.Indicator)}
        for token in forbidden:
            assert not any(token in name for name in names), token
        for result in every_indicator:
            assert not any(token in key for key in result.details for token in forbidden)

    def test_histogram_comparison_also_carries_the_disclaimer(self):
        array = make_cover(32, 32, 3, "noise", 1)
        assert analysis.histogram_compare(array, array).disclaimer


class TestHistogramCompare:
    """Requirement 11.3."""

    def test_shape_and_channels(self):
        first = make_cover(32, 32, 3, "noise", 1)
        second = make_cover(32, 32, 3, "noise", 2)
        result = analysis.histogram_compare(first, second)
        assert result.histograms_a.shape == (3, 256)
        assert result.channel_indices == (0, 1, 2)
        assert result.channel_labels == ("red", "green", "blue")

    def test_histogram_totals_match_the_sample_count(self):
        array = make_cover(32, 32, 3, "noise", 1)
        result = analysis.histogram_compare(array, array)
        assert int(result.histograms_a.sum()) == 32 * 32 * 3
        assert result.analysed_sample_count_a == 32 * 32 * 3

    def test_identical_images_have_zero_difference(self):
        array = make_cover(16, 16, 3, "noise", 1)
        result = analysis.histogram_compare(array, array.copy())
        assert int(np.abs(result.difference_counts).sum()) == 0
        assert float(np.abs(result.difference_proportions).sum()) == 0.0

    def test_alpha_is_excluded(self):
        result = analysis.histogram_compare(
            make_cover(16, 16, 4, "noise", 1), make_cover(16, 16, 4, "noise", 2)
        )
        assert result.channel_indices == (0, 1, 2)

    def test_shared_channels_only(self):
        result = analysis.histogram_compare(
            make_cover(16, 16, 1, "noise", 1), make_cover(16, 16, 3, "noise", 2)
        )
        assert result.channel_indices == (0,)


# --------------------------------------------------------------------------- #
# Requirement 12 and 15.7: layer independence
# --------------------------------------------------------------------------- #


class TestLayerIndependence:
    def test_no_gui_or_plotting_module_is_imported(self):
        """Requirement 12.2.

        Checked in a clean subprocess rather than against the ambient
        ``sys.modules``. The pytest-qt plugin that drives the GUI widget tests
        imports PySide6 during plugin collection, so an in-process check would
        report that import and not this layer's imports, which is the opposite of
        what Requirement 12.2 is about.
        """
        probe = textwrap.dedent(
            """
            import sys
            import app.analysis.image_analysis  # noqa: F401

            offenders = sorted(
                name
                for name in sys.modules
                if name.startswith(("PySide", "PyQt", "matplotlib", "tkinter"))
            )
            print(",".join(offenders))
            """
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=str(pathlib.Path(__file__).resolve().parent.parent),
            capture_output=True,
            text=True,
            check=True,
        )
        assert completed.stdout.strip() == ""

    @given(image_pair())
    def test_inputs_are_never_modified(self, pair):
        """Requirement 12.4 and 15.7."""
        first, second = pair
        before_first = first.copy()
        before_second = second.copy()

        analysis.compare_quality(first, second)
        analysis.difference_image(first, second)
        analysis.extract_all_bit_planes(first)
        analysis.lsb_distribution(first)
        analysis.bit0_uniformity(first)
        analysis.pair_of_values_chi_square(first)
        analysis.pair_of_values_neighbour(first)
        analysis.histogram_compare(first, second)

        assert np.array_equal(first, before_first)
        assert np.array_equal(second, before_second)

    def test_returned_arrays_do_not_alias_the_input(self):
        """Requirement 12.4: mutating a result must not touch the caller's data."""
        array = make_cover(8, 8, 3, "noise", 1)
        original = array.copy()

        plane = analysis.extract_bit_plane(array, 0, 0).plane
        plane[:] = 7
        difference = analysis.difference_image(array, array).difference
        difference[:] = 9

        assert np.array_equal(array, original)

    def test_path_and_array_inputs_agree(self, workspace):
        """Requirement 12.6."""
        array = make_cover(20, 20, 3, "noise", 1)
        path = write_cover(workspace, array, image_io.PNG, "cover")

        from_path = analysis.compare_quality(path, path)
        from_array = analysis.compare_quality(array, array)
        assert from_path.overall_mse == from_array.overall_mse
        assert from_path.differing_samples == from_array.differing_samples

        assert (
            analysis.lsb_distribution(path)[0].value
            == analysis.lsb_distribution(array)[0].value
        )

    def test_results_are_deterministic(self):
        """Requirement 12.5."""
        array = make_cover(32, 32, 3, "noise", 1)
        first = analysis.pair_of_values_chi_square(array)
        second = analysis.pair_of_values_chi_square(array)
        assert [r.value for r in first] == [r.value for r in second]

    def test_concurrent_calls_agree_with_serial_calls(self):
        """Requirement 12.8: the GUI will call these off the main thread."""
        array = make_cover(48, 48, 3, "noise", 1)
        expected = analysis.pair_of_values_chi_square(array)[0].value

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(lambda: analysis.pair_of_values_chi_square(array)[0].value)
                for _ in range(8)
            ]
            values = [future.result() for future in futures]

        assert values == [expected] * 8

    def test_no_file_is_written_without_an_output_path(self, workspace):
        """Requirement 12.3."""
        array = make_cover(16, 16, 3, "noise", 1)
        before = set(os.listdir(workspace))
        analysis.compare_quality(array, array)
        analysis.extract_all_bit_planes(array)
        analysis.difference_image(array, array)
        analysis.pair_of_values_chi_square(array)
        assert set(os.listdir(workspace)) == before

    def test_metrics_are_plain_python_types(self):
        """Requirement 12.1."""
        result = analysis.compare_quality(
            make_cover(8, 8, 3, "noise", 1), make_cover(8, 8, 3, "noise", 2)
        )
        assert type(result.overall_mse) is float
        assert type(result.pixel_identical) is bool
        assert type(result.differing_samples) is int

        indicator = analysis.pair_of_values_chi_square(
            make_cover(64, 64, 3, "noise", 1)
        )[0]
        assert type(indicator.value) is float
        assert type(indicator.degrees_of_freedom) is int


class TestInputValidation:
    @pytest.mark.parametrize("bad", [42, None, [1, 2, 3], {"a": 1}])
    def test_rejects_unsupported_input_types(self, bad):
        with pytest.raises(ValidationError, match="file path or a numpy array"):
            analysis.lsb_distribution(bad)

    def test_a_string_is_treated_as_a_path(self, workspace):
        """A string input is a path, so a missing file is a FileError not a type error."""
        from app.stego.errors import FileError

        with pytest.raises(FileError, match="not found"):
            analysis.lsb_distribution(os.path.join(workspace, "absent.png"))

    def test_rejects_wrong_dtype(self):
        with pytest.raises(ValidationError, match="uint8"):
            analysis.lsb_distribution(np.zeros((4, 4, 3), dtype=np.uint16))

    def test_rejects_wrong_dimension_count(self):
        with pytest.raises(ValidationError, match="dimensions"):
            analysis.lsb_distribution(np.zeros((4, 4, 3, 2), dtype=np.uint8))

    def test_rejects_unsupported_channel_count(self):
        with pytest.raises(ValidationError, match="channels"):
            analysis.lsb_distribution(np.zeros((4, 4, 2), dtype=np.uint8))

    def test_accepts_two_dimensional_grayscale(self):
        results = analysis.lsb_distribution(np.zeros((16, 16), dtype=np.uint8))
        assert results[0].analysed_sample_count == 256
