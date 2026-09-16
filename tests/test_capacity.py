"""Tests for the shared capacity arithmetic (Requirements 5 and 7)."""

from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.stego import capacity as cap
from app.stego.errors import ValidationError


class TestEmbeddableChannelCount:
    """Requirement 5.1: alpha is excluded, so RGBA matches RGB."""

    @pytest.mark.parametrize(
        ("channels", "expected"), [(1, 1), (3, 3), (4, 3)]
    )
    def test_supported_counts(self, channels, expected):
        assert cap.embeddable_channel_count(channels) == expected

    @pytest.mark.parametrize("channels", [0, 2, 5, 6])
    def test_unsupported_counts(self, channels):
        with pytest.raises(ValidationError, match="channel_count"):
            cap.embeddable_channel_count(channels)


class TestCapacityFormula:
    """Requirement 5.2 and 5.3."""

    def test_worked_example(self):
        # 10x10 RGB at depth 1: 300 samples, 300 bits, 37 whole bytes.
        report = cap.image_capacity_report(10, 10, 3, 1)
        assert report.total_embeddable_samples == 300
        assert report.available_capacity_bytes == 37
        assert report.max_payload_length == 33
        assert report.embeddable_channel_count == 3

    def test_rgba_matches_rgb(self):
        rgb = cap.image_capacity_report(10, 10, 3, 2)
        rgba = cap.image_capacity_report(10, 10, 4, 2)
        assert rgba.available_capacity_bytes == rgb.available_capacity_bytes
        assert rgba.embeddable_channel_count == 3

    def test_grayscale_uses_one_channel(self):
        report = cap.image_capacity_report(10, 10, 1, 8)
        assert report.total_embeddable_samples == 100
        assert report.available_capacity_bytes == 100

    @given(st.integers(0, 5000), st.integers(1, 8), st.integers(0, 5000))
    def test_capacity_never_exceeds_the_bit_budget(self, samples, depth, start):
        report = cap.capacity_report(samples, depth, min(start, max(0, samples - 1)))
        assert report.available_capacity_bytes * 8 <= report.available_samples * depth

    @given(st.integers(1, 5000), st.integers(1, 8))
    def test_start_location_reduces_capacity(self, samples, depth):
        at_zero = cap.available_capacity_bytes(samples, depth, 0)
        later = cap.available_capacity_bytes(samples, depth, samples // 2)
        assert later <= at_zero


class TestMonotonicity:
    """Requirement 5.5: non-decreasing, not strictly increasing.

    Flooring to whole bytes means two adjacent depths can report the same
    capacity when few samples remain, which is why the property is stated as
    non-decreasing.
    """

    @given(st.integers(0, 4000), st.integers(0, 4000))
    def test_capacity_is_non_decreasing_in_depth(self, samples, start):
        start = min(start, max(0, samples - 1)) if samples else 0
        values = [
            cap.available_capacity_bytes(samples, depth, start) for depth in range(1, 9)
        ]
        assert values == sorted(values)

    def test_equal_capacity_between_adjacent_depths_is_possible(self):
        # 1 sample: depth 1 gives 0 bytes and depth 2 also gives 0 bytes.
        assert cap.available_capacity_bytes(1, 1) == cap.available_capacity_bytes(1, 2)


class TestPayloadLengthAccounting:
    """Requirement 5.7 and 5.8: the 4-byte header is always accounted for."""

    def test_max_payload_subtracts_the_header(self):
        report = cap.capacity_report(1000, 1, 0)
        assert report.max_payload_length == report.available_capacity_bytes - 4

    @given(st.integers(0, 2000), st.integers(1, 8))
    def test_max_payload_is_never_negative(self, samples, depth):
        report = cap.capacity_report(samples, depth, 0)
        assert report.max_payload_length >= 0

    @pytest.mark.parametrize("samples", [0, 1, 8, 24, 31])
    def test_tiny_images_report_no_room_without_raising(self, samples):
        report = cap.capacity_report(samples, 1, 0)
        assert report.available_capacity_bytes < 4
        assert report.max_payload_length == 0
        assert report.payload_fits is False

    def test_capacity_used_percent_is_none_below_the_header_size(self):
        """Requirement 5.8 reports 'not applicable' rather than a number."""
        report = cap.capacity_report(8, 1, 0, payload_length=0)
        assert report.available_capacity_bytes < 4
        assert report.capacity_used_percent is None

    def test_capacity_used_percent_is_reported_and_uncapped(self):
        """Requirement 5.9: an oversized payload is visibly oversized."""
        report = cap.capacity_report(800, 1, 0, payload_length=196)
        assert report.available_capacity_bytes == 100
        assert report.capacity_used_percent == 200.0

    def test_exact_fit_reports_one_hundred_percent(self):
        report = cap.capacity_report(800, 1, 0, payload_length=96)
        assert report.capacity_used_percent == 100.0


class TestPositionCounts:
    """Requirement 7.3 and 7.4."""

    @pytest.mark.parametrize(
        ("encoded", "depth", "expected"),
        [(4, 1, 32), (4, 3, 11), (4, 8, 4), (5, 3, 14), (0, 4, 0)],
    )
    def test_required_position_count(self, encoded, depth, expected):
        assert cap.required_position_count(encoded, depth) == expected

    @given(st.integers(0, 500), st.integers(1, 8))
    def test_required_position_count_is_a_ceiling(self, encoded, depth):
        assert cap.required_position_count(encoded, depth) == math.ceil(
            encoded * 8 / depth
        )

    def test_highest_valid_start_location(self):
        # 300 samples, 4-byte stream at depth 1 needs 32 samples, so 268 is the
        # last start location that still fits.
        assert cap.highest_valid_start_location(300, 4, 1) == 268

    @given(st.integers(1, 3000), st.integers(0, 200), st.integers(1, 8))
    def test_highest_start_location_is_consistent_with_capacity(
        self, samples, payload, depth
    ):
        encoded = payload + cap.LENGTH_HEADER_BYTES
        highest = cap.highest_valid_start_location(samples, encoded, depth)
        if highest >= 0:
            report = cap.capacity_report(samples, depth, highest, payload)
            assert report.required_position_count <= report.available_samples

    def test_empty_range_is_reported_not_raised(self):
        """Requirement 7.7: the cryptography layer needs to detect this itself."""
        report = cap.capacity_report(10, 1, 0, payload_length=1000)
        assert report.start_location_range_empty is True
        assert report.highest_valid_start_location < 0


class TestCheckEquivalence:
    """The byte-based and position-based capacity checks must never disagree.

    Requirement 6.1 compares encoded byte lengths while Requirement 7.3 compares
    sample position counts. If those two ever disagreed, a payload could pass one
    check and fail the other, so the equivalence is worth asserting directly.
    """

    @given(st.integers(1, 2000), st.integers(1, 8), st.integers(0, 300))
    def test_byte_and_position_checks_agree(self, samples, depth, payload):
        start = min(samples - 1, payload % samples)
        report = cap.capacity_report(samples, depth, start, payload)
        by_bytes = report.required_encoded_length <= report.available_capacity_bytes
        by_positions = report.required_position_count <= report.available_samples
        assert by_bytes == by_positions


class TestMediaIndependence:
    """Requirement 5.6: the audio layer must be able to reuse this."""

    def test_accepts_a_plain_sample_count(self):
        # An audio layer would pass frame_count * channel_count.
        report = cap.capacity_report(44_100 * 2, 2, 0)
        assert report.available_capacity_bytes == (44_100 * 2 * 2) // 8
        assert report.embeddable_channel_count is None

    @pytest.mark.parametrize("bad", ["100", 1.5, None, True])
    def test_rejects_non_integer_sample_counts(self, bad):
        with pytest.raises(ValidationError, match="total_embeddable_samples"):
            cap.capacity_report(bad, 1, 0)

    def test_rejects_negative_sample_counts(self):
        with pytest.raises(ValidationError, match="non-negative"):
            cap.capacity_report(-1, 1, 0)
