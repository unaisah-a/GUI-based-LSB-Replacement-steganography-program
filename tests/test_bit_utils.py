"""Tests for the shared bit helpers (Requirement 13)."""

from __future__ import annotations

import time

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.stego import bit_utils as bu
from app.stego.errors import ValidationError


class TestBitOrdering:
    """Requirement 13.1 and 13.2 fix a most-significant-bit-first convention."""

    def test_high_bit_comes_first(self):
        assert bu.bytes_to_bits(bytes([0b1000_0000])).tolist() == [1, 0, 0, 0, 0, 0, 0, 0]

    def test_low_bit_comes_last(self):
        assert bu.bytes_to_bits(bytes([0b0000_0001])).tolist() == [0, 0, 0, 0, 0, 0, 0, 1]

    def test_bit_count_is_eight_per_byte(self):
        assert bu.bytes_to_bits(b"abcd").size == 32

    def test_empty_input_gives_empty_output(self):
        assert bu.bytes_to_bits(b"").size == 0
        assert bu.bits_to_bytes(np.zeros(0, dtype=np.uint8)) == b""

    def test_elements_are_only_zero_or_one(self):
        """Requirement 13.8 fixes the unpacked 0/1 representation."""
        bits = bu.bytes_to_bits(bytes(range(256)))
        assert set(np.unique(bits).tolist()) <= {0, 1}
        assert bits.dtype == np.uint8


class TestByteBitRoundTrip:
    """Requirement 13.3."""

    @given(st.binary(max_size=512))
    def test_round_trip(self, data):
        assert bu.bits_to_bytes(bu.bytes_to_bits(data)) == data

    def test_non_multiple_of_eight_is_rejected(self):
        """Requirement 13.9: padding stays the caller's responsibility."""
        with pytest.raises(ValidationError, match="multiple of 8"):
            bu.bits_to_bytes(np.zeros(12, dtype=np.uint8))

    def test_rejects_oversized_input(self):
        with pytest.raises(ValidationError, match="at most"):
            bu.bytes_to_bits(_FakeOversizedBytes())

    def test_rejects_wrong_type(self):
        with pytest.raises(ValidationError, match="bytes"):
            bu.bytes_to_bits("not bytes")


class _FakeOversizedBytes(bytes):
    """A bytes subclass that reports a length above the documented maximum."""

    def __len__(self) -> int:
        return bu.MAX_CONVERTIBLE_BYTES + 1


class TestGroupPacking:
    """The group form is what embedding writes into one sample each."""

    @given(st.binary(min_size=1, max_size=256), st.integers(1, 8))
    def test_round_trip_ignoring_padding(self, data, depth):
        bits = bu.bytes_to_bits(data)
        groups = bu.pack_bits_to_groups(bits, depth)
        recovered = bu.unpack_groups_to_bits(groups, depth)
        assert recovered[: bits.size].tolist() == bits.tolist()

    @given(st.binary(min_size=1, max_size=256), st.integers(1, 8))
    def test_group_count_is_ceiling(self, data, depth):
        bits = bu.bytes_to_bits(data)
        groups = bu.pack_bits_to_groups(bits, depth)
        assert groups.size == bu.groups_needed(bits.size, depth)

    @given(st.binary(min_size=1, max_size=64), st.integers(1, 8))
    def test_group_values_fit_the_depth(self, data, depth):
        groups = bu.pack_bits_to_groups(bu.bytes_to_bits(data), depth)
        assert int(groups.max()) < 2**depth

    def test_padding_uses_zero_bits(self):
        """Requirement 2.6: a trailing partial group is zero padded."""
        # 8 bits at depth 3 gives 3 groups covering 9 bits; the last bit is padding.
        bits = bu.bytes_to_bits(bytes([0b1111_1111]))
        groups = bu.pack_bits_to_groups(bits, 3)
        assert groups.size == 3
        assert groups.tolist() == [0b111, 0b111, 0b110]

    def test_depth_one_maps_bits_to_groups_directly(self):
        bits = bu.bytes_to_bits(bytes([0b1010_1010]))
        assert bu.pack_bits_to_groups(bits, 1).tolist() == [1, 0, 1, 0, 1, 0, 1, 0]

    def test_depth_eight_maps_bytes_to_groups_directly(self):
        assert bu.pack_bits_to_groups(bu.bytes_to_bits(b"\x2a\xff"), 8).tolist() == [
            0x2A,
            0xFF,
        ]


class TestLowBitWriteRead:
    """Requirement 13.4 and 13.5."""

    @given(
        st.integers(0, 255),
        st.integers(1, 8),
        st.integers(0, 255),
    )
    def test_eight_bit_round_trip_and_preservation(self, cover, depth, raw_value):
        value = raw_value % (2**depth)
        covers = np.array([cover], dtype=np.uint8)
        written = bu.write_low_bits(covers, np.array([value], dtype=np.uint8), depth, 8)
        assert int(bu.read_low_bits(written, depth, 8)[0]) == value
        # Requirement 13.5: every bit at or above the depth is untouched.
        assert int(written[0]) >> depth == cover >> depth

    @given(
        st.integers(0, 65535),
        st.integers(1, 8),
        st.integers(0, 255),
    )
    def test_sixteen_bit_round_trip_and_preservation(self, cover, depth, raw_value):
        """16-bit support exists so the audio layer can share these helpers."""
        value = raw_value % (2**depth)
        covers = np.array([cover], dtype=np.uint16)
        written = bu.write_low_bits(covers, np.array([value], dtype=np.uint16), depth, 16)
        assert int(bu.read_low_bits(written, depth, 16)[0]) == value
        assert int(written[0]) >> depth == cover >> depth

    def test_depth_eight_on_eight_bit_sample_overwrites_completely(self):
        written = bu.write_low_bits(
            np.array([0xFF], dtype=np.uint8), np.array([0x00], dtype=np.uint8), 8, 8
        )
        assert int(written[0]) == 0x00

    def test_depth_eight_on_sixteen_bit_sample_keeps_high_byte(self):
        written = bu.write_low_bits(
            np.array([0xABCD], dtype=np.uint16),
            np.array([0x00], dtype=np.uint16),
            8,
            16,
        )
        assert int(written[0]) == 0xAB00

    def test_inputs_are_not_modified(self):
        covers = np.array([0xFF, 0x00], dtype=np.uint8)
        before = covers.copy()
        bu.write_low_bits(covers, np.array([0, 1], dtype=np.uint8), 1, 8)
        assert np.array_equal(covers, before)

    def test_shape_mismatch_is_rejected(self):
        with pytest.raises(ValidationError, match="same shape"):
            bu.write_low_bits(
                np.zeros(3, dtype=np.uint8), np.zeros(2, dtype=np.uint8), 1, 8
            )


class TestValidation:
    """Requirement 13.10 and 14.3."""

    @pytest.mark.parametrize("depth", [0, 9, -1, 100])
    def test_out_of_range_depth(self, depth):
        with pytest.raises(ValidationError, match="1 to 8"):
            bu.validate_lsb_depth(depth)

    @pytest.mark.parametrize("depth", [True, False, 1.0, "1", None])
    def test_non_integer_depth(self, depth):
        with pytest.raises(ValidationError, match="lsb_count"):
            bu.validate_lsb_depth(depth)

    @pytest.mark.parametrize("width", [7, 9, 24, 32, 0, -8])
    def test_unsupported_sample_width(self, width):
        with pytest.raises(ValidationError, match="sample_width"):
            bu.validate_sample_width(width)

    @pytest.mark.parametrize("width", [8, 16])
    def test_supported_sample_widths(self, width):
        assert bu.validate_sample_width(width) == width


class TestPerformanceBudget:
    """Requirement 13.8: 36 million elements within 5 seconds."""

    @settings(max_examples=1, deadline=None)
    @given(st.integers(1, 8))
    def test_large_sequence_within_budget(self, depth):
        count = 36_000_000
        bits = np.zeros(count, dtype=np.uint8)
        bits[::3] = 1

        start = time.perf_counter()
        groups = bu.pack_bits_to_groups(bits, depth)
        bu.unpack_groups_to_bits(groups, depth)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"pack and unpack took {elapsed:.2f}s at depth {depth}"
