"""Tests for LSB embedding and extraction (Requirements 2, 3, 4, 6, 7, 14, 15)."""

from __future__ import annotations

import math
import os
from pathlib import Path

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from PIL import Image

from app.analysis import image_analysis as analysis
from app.stego import bit_utils, image_io, image_stego
from app.stego.capacity import LENGTH_HEADER_BYTES
from app.stego.errors import (
    CapacityError,
    DecodeError,
    ExtractionError,
    FileError,
    ValidationError,
)
from conftest import ScratchDirectory, embedding_case, make_cover, write_cover


# --------------------------------------------------------------------------- #
# Requirement 15.1: round trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    """Requirement 3.1, 3.4 and 15.1."""

    @given(embedding_case())
    def test_extract_returns_the_embedded_payload(self, case):
        with ScratchDirectory() as directory:
            cover = case.write_cover(directory)
            output = os.path.join(
                directory, f"stego{os.path.splitext(cover)[1]}"
            )
            image_stego.embed_image(
                cover, output, case.payload, case.lsb_count, case.start_location
            )
            recovered = image_stego.extract_image(
                output, case.lsb_count, case.start_location
            )
        assert recovered == case.payload

    @pytest.mark.parametrize("depth", [3, 5, 6, 7])
    @pytest.mark.parametrize("payload_length", [0, 1, 2, 3, 5, 17, 64])
    def test_depths_that_do_not_divide_the_header(
        self, workspace, depth, payload_length
    ):
        """The header spans a partial sample at these depths.

        32 header bits at depth 3 occupy ceil(32/3) = 11 samples supplying 33
        bits, so the first payload bit is the last bit taken from sample 10.
        Realigning to sample 11 would drop a bit and corrupt every payload byte,
        which is exactly the off-by-one this test targets.
        """
        payload = bytes(range(payload_length))
        cover = write_cover(
            workspace, make_cover(32, 32, 3, "noise", 5), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, payload, depth, 7)
        assert image_stego.extract_image(output, depth, 7) == payload

    def test_header_spans_a_sample_boundary_at_depth_three(self, workspace):
        """Confirm the arithmetic above rather than only its consequence."""
        assert bit_utils.groups_needed(32, 3) == 11
        assert 11 * 3 == 33  # one bit beyond the header
        cover = write_cover(
            workspace, make_cover(16, 16, 3, "flat", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = b"\xff" * 10
        image_stego.embed_image(cover, output, payload, 3, 0)
        assert image_stego.extract_image(output, 3, 0) == payload

    @pytest.mark.parametrize("depth", range(1, 9))
    @pytest.mark.parametrize(
        ("channels", "container"),
        [
            (1, image_io.PNG),
            (3, image_io.PNG),
            (4, image_io.PNG),
            (3, image_io.BMP),
            (4, image_io.BMP),
        ],
    )
    def test_every_format_and_depth(self, workspace, depth, channels, container):
        payload = b"INF2005 ACW1 \x00\xff\x80 payload"
        suffix = ".png" if container == image_io.PNG else ".bmp"
        cover = write_cover(
            workspace, make_cover(40, 40, channels, "gradient", 2), container, "cover"
        )
        output = os.path.join(workspace, f"stego{suffix}")
        image_stego.embed_image(cover, output, payload, depth, 3)
        assert image_stego.extract_image(output, depth, 3) == payload

    def test_empty_payload(self, workspace):
        """Requirement 2.14 and 3.5: a zero-length payload is valid."""
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "noise", 3), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"", 1, 0)
        assert image_stego.extract_image(output, 1, 0) == b""


# --------------------------------------------------------------------------- #
# Requirement 15.2: capacity soundness
# --------------------------------------------------------------------------- #


class TestCapacitySoundness:
    """Requirement 6.2 to 6.4 and 15.2."""

    @given(embedding_case())
    def test_payload_within_capacity_is_written(self, case):
        with ScratchDirectory() as directory:
            cover = case.write_cover(directory)
            output = os.path.join(directory, f"stego{os.path.splitext(cover)[1]}")
            image_stego.embed_image(
                cover, output, case.payload, case.lsb_count, case.start_location
            )
            assert os.path.isfile(output)

    @given(embedding_case(), st.integers(1, 64))
    def test_payload_beyond_capacity_is_rejected_without_writing(self, case, excess):
        with ScratchDirectory() as directory:
            cover = case.write_cover(directory)
            output = os.path.join(directory, f"stego{os.path.splitext(cover)[1]}")
            report, _ = image_stego.measure_capacity(
                cover, case.lsb_count, case.start_location
            )
            oversized = b"\x5a" * (report.max_payload_length + excess)

            with pytest.raises(CapacityError):
                image_stego.embed_image(
                    cover, output, oversized, case.lsb_count, case.start_location
                )
            assert not os.path.exists(output)

    def test_exact_capacity_succeeds(self, workspace):
        """Requirement 6.3 names this boundary explicitly."""
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 9), image_io.PNG, "cover"
        )
        report, _ = image_stego.measure_capacity(cover, 1, 0)
        payload = b"Z" * report.max_payload_length
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, payload, 1, 0)
        assert image_stego.extract_image(output, 1, 0) == payload

    def test_one_byte_over_capacity_fails(self, workspace):
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 9), image_io.PNG, "cover"
        )
        report, _ = image_stego.measure_capacity(cover, 1, 0)
        payload = b"Z" * (report.max_payload_length + 1)
        output = os.path.join(workspace, "stego.png")
        with pytest.raises(CapacityError, match="does not fit"):
            image_stego.embed_image(cover, output, payload, 1, 0)
        assert not os.path.exists(output)

    def test_capacity_error_reports_both_figures(self, workspace):
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        with pytest.raises(CapacityError) as info:
            image_stego.embed_image(cover, output, b"x" * 5000, 1, 0)
        message = str(info.value)
        assert "needs" in message and "available" in message


# --------------------------------------------------------------------------- #
# Requirement 15.3 and 15.4: cover preservation and bounded distortion
# --------------------------------------------------------------------------- #


class TestCoverPreservation:
    """Requirement 2.8 to 2.10, 2.12, 2.13 and 15.3, 15.4."""

    @given(embedding_case())
    def test_only_low_bits_inside_the_window_change(self, case):
        with ScratchDirectory() as directory:
            cover_path = case.write_cover(directory)
            output = os.path.join(directory, f"stego{os.path.splitext(cover_path)[1]}")
            result = image_stego.embed_image(
                cover_path, output, case.payload, case.lsb_count, case.start_location
            )
            cover, _ = image_io.load_image(cover_path)
            stego, _ = image_io.load_image(output)

        flat_cover, channels_used = image_stego.embeddable_stream(cover)
        flat_stego, _ = image_stego.embeddable_stream(stego)

        window = slice(
            result.start_location, result.start_location + result.samples_written
        )
        outside = np.ones(flat_cover.size, dtype=bool)
        outside[window] = False

        # Bits at or above the depth survive inside the window.
        assert np.array_equal(
            flat_cover[window] >> case.lsb_count, flat_stego[window] >> case.lsb_count
        )
        # Everything outside the window is untouched.
        assert np.array_equal(flat_cover[outside], flat_stego[outside])
        # Alpha is never a carrier.
        if case.channels == 4:
            assert np.array_equal(cover[:, :, 3], stego[:, :, 3])
            assert channels_used == 3

    @given(embedding_case())
    def test_per_sample_change_is_bounded_by_the_depth(self, case):
        with ScratchDirectory() as directory:
            cover_path = case.write_cover(directory)
            output = os.path.join(directory, f"stego{os.path.splitext(cover_path)[1]}")
            image_stego.embed_image(
                cover_path, output, case.payload, case.lsb_count, case.start_location
            )
            cover, _ = image_io.load_image(cover_path)
            stego, _ = image_io.load_image(output)

        delta = np.abs(cover.astype(np.int32) - stego.astype(np.int32))
        assert int(delta.max(initial=0)) < 2**case.lsb_count

    def test_cover_file_is_left_unchanged(self, workspace):
        """Requirement 2.12."""
        array = make_cover(24, 24, 3, "noise", 11)
        cover = write_cover(workspace, array, image_io.PNG, "cover")
        original_bytes = Path(cover).read_bytes()
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"payload bytes", 4, 6)
        assert Path(cover).read_bytes() == original_bytes

    def test_depth_eight_overwrites_samples_entirely(self, workspace):
        """Requirement 2.13: nothing of the cover sample survives."""
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "flat", 4), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = bytes([0x00] * 8)
        result = image_stego.embed_image(cover, output, payload, 8, 0)
        stego, _ = image_io.load_image(output)
        flat, _ = image_stego.embeddable_stream(stego)
        encoded = len(payload).to_bytes(LENGTH_HEADER_BYTES, "big") + payload
        assert flat[: len(encoded)].tolist() == list(encoded)
        assert result.samples_written == len(encoded)

    def test_embedding_does_not_wrap_past_the_end(self, workspace):
        """Requirement 2.7: a payload that would wrap is rejected instead."""
        cover = write_cover(
            workspace, make_cover(10, 10, 3, "noise", 2), image_io.PNG, "cover"
        )
        total = 10 * 10 * 3
        output = os.path.join(workspace, "stego.png")
        with pytest.raises(CapacityError):
            image_stego.embed_image(cover, output, b"x" * 40, 1, total - 10)


class TestDistortionGrowsWithDepth:
    """Requirement 8.8 and 15.4: PSNR is non-increasing as depth rises."""

    def test_psnr_is_non_increasing(self, workspace):
        # Requirement 8.8 specifies a payload of at least 1024 bytes.
        payload = bytes((index * 7 + 11) % 256 for index in range(1500))
        cover = write_cover(
            workspace, make_cover(120, 120, 3, "gradient", 0), image_io.PNG, "cover"
        )
        previous = math.inf
        for depth in range(1, 9):
            output = os.path.join(workspace, f"stego{depth}.png")
            image_stego.embed_image(cover, output, payload, depth, 0)
            quality = analysis.compare_quality(cover, output)
            assert quality.overall_psnr_db <= previous + 0.5
            previous = quality.overall_psnr_db

    def test_deeper_embedding_is_measurably_worse(self, workspace):
        payload = b"q" * 1200
        cover = write_cover(
            workspace, make_cover(120, 120, 3, "gradient", 0), image_io.PNG, "cover"
        )
        shallow = os.path.join(workspace, "shallow.png")
        deep = os.path.join(workspace, "deep.png")
        image_stego.embed_image(cover, shallow, payload, 1, 0)
        image_stego.embed_image(cover, deep, payload, 8, 0)
        assert (
            analysis.compare_quality(cover, deep).overall_psnr_db
            < analysis.compare_quality(cover, shallow).overall_psnr_db
        )


# --------------------------------------------------------------------------- #
# Requirement 15.6: determinism
# --------------------------------------------------------------------------- #


class TestDeterminism:
    """Requirement 2.11, 3.11 and 15.6."""

    @given(embedding_case())
    def test_repeated_embedding_produces_identical_samples(self, case):
        with ScratchDirectory() as directory:
            cover = case.write_cover(directory)
            suffix = os.path.splitext(cover)[1]
            first = os.path.join(directory, f"first{suffix}")
            second = os.path.join(directory, f"second{suffix}")
            image_stego.embed_image(
                cover, first, case.payload, case.lsb_count, case.start_location
            )
            image_stego.embed_image(
                cover, second, case.payload, case.lsb_count, case.start_location
            )
            left, _ = image_io.load_image(first)
            right, _ = image_io.load_image(second)
        assert np.array_equal(left, right)

    def test_repeated_extraction_agrees(self, workspace):
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 6), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = b"stable"
        image_stego.embed_image(cover, output, payload, 2, 4)
        assert image_stego.extract_image(output, 2, 4) == image_stego.extract_image(
            output, 2, 4
        )


# --------------------------------------------------------------------------- #
# Requirement 15.8: error conditions
# --------------------------------------------------------------------------- #


class TestValidationOrderAndErrors:
    """Requirement 7, 14.1 to 14.10."""

    @pytest.fixture()
    def cover(self, workspace):
        return write_cover(
            workspace, make_cover(16, 16, 3, "noise", 8), image_io.PNG, "cover"
        )

    @pytest.mark.parametrize("depth", [0, 9, -1, 256])
    def test_depth_out_of_range(self, workspace, cover, depth):
        with pytest.raises(ValidationError, match="1 to 8"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x", depth, 0
            )

    @pytest.mark.parametrize("depth", [True, 1.0, "1", None])
    def test_depth_wrong_type(self, workspace, cover, depth):
        with pytest.raises(ValidationError, match="lsb_count"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x", depth, 0
            )

    def test_start_location_negative(self, workspace, cover):
        with pytest.raises(ValidationError, match="start_location"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x", 1, -1
            )

    def test_start_location_equal_to_sample_count(self, workspace, cover):
        total = 16 * 16 * 3
        with pytest.raises(ValidationError, match="start_location"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x", 1, total
            )

    @pytest.mark.parametrize("start", [True, 1.0, "0", None])
    def test_start_location_wrong_type(self, workspace, cover, start):
        with pytest.raises(ValidationError, match="start_location"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x", 1, start
            )

    @pytest.mark.parametrize("payload", ["text", 42, None, [1, 2, 3]])
    def test_payload_wrong_type(self, workspace, cover, payload):
        with pytest.raises(ValidationError, match="payload"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), payload, 1, 0
            )

    def test_bytearray_payload_is_accepted(self, workspace, cover):
        output = os.path.join(workspace, "o.png")
        image_stego.embed_image(cover, output, bytearray(b"fine"), 1, 0)
        assert image_stego.extract_image(output, 1, 0) == b"fine"

    def test_missing_input(self, workspace):
        with pytest.raises(FileError, match="not found"):
            image_stego.embed_image(
                os.path.join(workspace, "absent.png"),
                os.path.join(workspace, "o.png"),
                b"x",
                1,
                0,
            )

    def test_missing_output_directory(self, workspace, cover):
        with pytest.raises(FileError, match="output directory"):
            image_stego.embed_image(
                cover, os.path.join(workspace, "nope", "o.png"), b"x", 1, 0
            )

    def test_output_equal_to_input(self, workspace, cover):
        """Requirement 2.15: embedding in place would destroy the cover."""
        with pytest.raises(ValidationError, match="must differ"):
            image_stego.embed_image(cover, cover, b"x", 1, 0)

    def test_occupied_output_requires_overwrite(self, workspace, cover):
        """Requirement 6.6."""
        output = os.path.join(workspace, "o.png")
        image_stego.embed_image(cover, output, b"first", 1, 0)
        with pytest.raises(FileError, match="already occupied"):
            image_stego.embed_image(cover, output, b"second", 1, 0)
        image_stego.embed_image(cover, output, b"second", 1, 0, overwrite=True)
        assert image_stego.extract_image(output, 1, 0) == b"second"

    def test_missing_input_is_reported_before_output_problems(self, workspace):
        """Requirement 14.6 fixes the order of the checks."""
        with pytest.raises(FileError, match="not found"):
            image_stego.embed_image(
                os.path.join(workspace, "absent.png"),
                os.path.join(workspace, "also-absent-dir", "o.png"),
                "wrong type too",
                99,
                -5,
            )

    def test_error_messages_exclude_directories(self, workspace):
        """Requirement 14.9."""
        missing = os.path.join(workspace, "absent.png")
        with pytest.raises(FileError) as info:
            image_stego.extract_image(missing, 1, 0)
        message = str(info.value)
        assert "absent.png" in message
        assert workspace not in message

    def test_error_messages_are_bounded(self, workspace, cover):
        with pytest.raises(CapacityError) as info:
            image_stego.embed_image(
                cover, os.path.join(workspace, "o.png"), b"x" * 100_000, 1, 0
            )
        assert 1 <= len(str(info.value)) <= 500


class TestUnsupportedInputs:
    """Requirement 1.5 to 1.7 and 15.8."""

    def test_lossy_input_is_rejected(self, workspace):
        path = os.path.join(workspace, "photo.png")  # deliberate extension mismatch
        Image.fromarray(make_cover(16, 16, 3, "noise", 1), "RGB").save(
            path, format="JPEG"
        )
        with pytest.raises(DecodeError, match="JPEG"):
            image_stego.extract_image(path, 1, 0)

    def test_palette_png_is_rejected(self, workspace):
        path = os.path.join(workspace, "palette.png")
        Image.fromarray(make_cover(16, 16, 3, "noise", 1), "RGB").convert("P").save(path)
        with pytest.raises(DecodeError, match="palette"):
            image_stego.extract_image(path, 1, 0)

    def test_palette_bmp_is_rejected(self, workspace):
        path = os.path.join(workspace, "palette.bmp")
        Image.fromarray(make_cover(16, 16, 3, "noise", 1), "RGB").convert("P").save(
            path, format="BMP"
        )
        with pytest.raises(DecodeError, match="indexed-colour"):
            image_stego.extract_image(path, 1, 0)

    def test_sixteen_bit_png_is_rejected(self, workspace):
        path = os.path.join(workspace, "deep.png")
        Image.fromarray(
            np.arange(256, dtype=np.uint16).reshape(16, 16) * 200
        ).save(path)
        with pytest.raises(DecodeError, match="16 bits"):
            image_stego.extract_image(path, 1, 0)

    def test_grayscale_alpha_png_is_rejected(self, workspace):
        path = os.path.join(workspace, "la.png")
        Image.fromarray(make_cover(16, 16, 2, "noise", 1), "LA").save(path)
        with pytest.raises(DecodeError, match="2 channels"):
            image_stego.extract_image(path, 1, 0)

    def test_unidentified_content_is_rejected(self, workspace):
        path = os.path.join(workspace, "junk.png")
        with open(path, "wb") as handle:
            handle.write(b"this is not an image at all")
        with pytest.raises(DecodeError, match="could not be identified"):
            image_stego.extract_image(path, 1, 0)


class TestExtractionFailures:
    """Requirement 3.6 to 3.10 and 4.6, 4.7."""

    def test_truncated_stream_when_the_header_does_not_fit(self, workspace):
        """Fewer than 32 bits remain from the start location."""
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "noise", 1), image_io.PNG, "cover"
        )
        total = 8 * 8 * 3
        with pytest.raises(ExtractionError, match="truncated"):
            image_stego.extract_image(cover, 1, total - 4)

    def test_inconsistent_length_header_is_rejected_before_allocating(self, workspace):
        """Requirement 3.6 and 4.6.

        A crafted all-ones header decodes to 4294967295 bytes. Without the bound
        check that value would be used to size a buffer, so this is a
        denial-of-service guard as much as a correctness one.
        """
        array = make_cover(32, 32, 3, "noise", 1)
        flat, channels = image_stego.embeddable_stream(array)
        crafted = flat.copy()
        crafted[:32] = bit_utils.write_low_bits(
            crafted[:32], np.ones(32, dtype=np.uint8), 1, 8
        )
        array = array.copy()
        array[:, :, :channels] = crafted.reshape(32, 32, channels)
        path = write_cover(workspace, array, image_io.PNG, "crafted")

        with pytest.raises(ExtractionError, match="inconsistent"):
            image_stego.extract_image(path, 1, 0)

    def test_manifest_length_disagreement(self, workspace):
        """Requirement 4.7."""
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"twelve bytes", 1, 0)
        with pytest.raises(ExtractionError, match="disagrees"):
            image_stego.extract_image(output, 1, 0, manifest_payload_length=99)

    def test_manifest_length_agreement_is_accepted(self, workspace):
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = b"twelve bytes"
        image_stego.embed_image(cover, output, payload, 1, 0)
        assert (
            image_stego.extract_image(
                output, 1, 0, manifest_payload_length=len(payload)
            )
            == payload
        )

    def test_only_the_exact_parameters_recover_the_payload(self, workspace):
        """Requirement 3.1 and 3.9.

        Over a noise cover every wrong parameter pair happens to raise, because a
        random 32-bit header almost always decodes to a length far beyond the
        image capacity and trips the bound check. That is a property of the cover
        content, not a detection guarantee, which is why the module never claims
        to identify the cause of a failure. See
        :meth:`test_a_wrong_start_location_can_return_a_wrong_answer_silently`
        for the case that does not raise.
        """
        cover = write_cover(
            workspace, make_cover(48, 48, 3, "noise", 12), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = b"the quick brown fox jumps over the lazy dog"
        image_stego.embed_image(cover, output, payload, 4, 100)

        outcomes = {"raised": 0, "wrong_bytes": 0, "correct": 0}
        for depth in range(1, 9):
            for start in (0, 50, 100, 150):
                try:
                    result = image_stego.extract_image(output, depth, start)
                except ExtractionError:
                    outcomes["raised"] += 1
                else:
                    if result == payload:
                        outcomes["correct"] += 1
                    else:
                        outcomes["wrong_bytes"] += 1

        assert outcomes["correct"] == 1
        assert outcomes["raised"] == 31

    def test_a_wrong_start_location_can_return_a_wrong_answer_silently(
        self, workspace
    ):
        """Requirement 3.10, asserted rather than assumed.

        A cover whose low-order bits are zero decodes to a length header of 0 at
        any depth, so extraction at the wrong start location returns an empty
        payload and raises nothing at all. The caller receives a wrong answer
        with no indication of a problem. This is the concrete reason the module
        refuses to describe any returned byte sequence as verified, and the reason
        authenticity has to be established by the verification layer rather than
        inferred from a successful extraction.
        """
        cover = write_cover(
            workspace, make_cover(48, 48, 3, "flat", 0) * 0, image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        payload = b"a real payload that will be missed entirely"
        image_stego.embed_image(cover, output, payload, 4, 400)

        # The correct parameters recover the payload.
        assert image_stego.extract_image(output, 4, 400) == payload

        # A wrong start location silently yields an empty payload, no exception.
        for depth in range(1, 9):
            assert image_stego.extract_image(output, depth, 0) == b""

    def test_extraction_leaves_the_file_unchanged(self, workspace):
        """Requirement 3.8."""
        cover = write_cover(
            workspace, make_cover(20, 20, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"payload", 2, 3)
        before = Path(output).read_bytes()
        image_stego.extract_image(output, 2, 3)
        assert Path(output).read_bytes() == before


class TestAtomicWriting:
    """Requirement 6.5 to 6.8."""

    def test_no_temporary_files_survive_success(self, workspace):
        cover = write_cover(
            workspace, make_cover(16, 16, 3, "noise", 1), image_io.PNG, "cover"
        )
        image_stego.embed_image(
            cover, os.path.join(workspace, "stego.png"), b"payload", 1, 0
        )
        assert [name for name in os.listdir(workspace) if name.startswith(".partial-")] == []

    def test_no_temporary_files_survive_failure(self, workspace):
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "noise", 1), image_io.PNG, "cover"
        )
        with pytest.raises(CapacityError):
            image_stego.embed_image(
                cover, os.path.join(workspace, "stego.png"), b"x" * 9000, 1, 0
            )
        assert [name for name in os.listdir(workspace) if name.startswith(".partial-")] == []

    def test_existing_output_is_preserved_when_embedding_fails(self, workspace):
        cover = write_cover(
            workspace, make_cover(8, 8, 3, "noise", 1), image_io.PNG, "cover"
        )
        output = os.path.join(workspace, "stego.png")
        image_stego.embed_image(cover, output, b"keep me", 1, 0)
        original = Path(output).read_bytes()

        with pytest.raises(CapacityError):
            image_stego.embed_image(cover, output, b"x" * 9000, 1, 0, overwrite=True)
        assert Path(output).read_bytes() == original


class TestCapacityReporting:
    """Requirement 5.4 and 5.9 surfaced through the stego module."""

    def test_measure_capacity_matches_a_successful_embedding(self, workspace):
        cover = write_cover(
            workspace, make_cover(32, 32, 4, "noise", 1), image_io.PNG, "cover"
        )
        report, descriptor = image_stego.measure_capacity(cover, 3, 10, 100)
        assert descriptor.channel_count == 4
        assert report.embeddable_channel_count == 3
        assert report.total_embeddable_samples == 32 * 32 * 3

        output = os.path.join(workspace, "stego.png")
        result = image_stego.embed_image(cover, output, b"z" * 100, 3, 10)
        assert result.samples_written == report.required_position_count
        assert result.encoded_length == report.required_encoded_length

    def test_measure_capacity_does_not_raise_on_tiny_images(self, workspace):
        cover = write_cover(
            workspace, make_cover(1, 1, 3, "flat", 1), image_io.PNG, "cover"
        )
        report, _ = image_stego.measure_capacity(cover, 1, 0)
        assert report.payload_fits is False


class TestEmbeddableStream:
    """Requirement 2.1 and 2.2: the traversal order must be unambiguous."""

    def test_traversal_is_row_major_then_channel(self):
        array = np.arange(2 * 3 * 3, dtype=np.uint8).reshape(2, 3, 3)
        flat, channels = image_stego.embeddable_stream(array)
        assert channels == 3
        assert flat.tolist() == list(range(18))

    def test_alpha_is_excluded(self):
        array = np.zeros((2, 2, 4), dtype=np.uint8)
        array[:, :, 3] = 99
        flat, channels = image_stego.embeddable_stream(array)
        assert channels == 3
        assert flat.size == 2 * 2 * 3
        assert 99 not in flat.tolist()

    def test_index_maps_back_to_row_column_channel(self):
        height, width, channels = 4, 5, 3
        array = np.arange(height * width * channels, dtype=np.uint8).reshape(
            height, width, channels
        )
        flat, used = image_stego.embeddable_stream(array)
        for index in range(flat.size):
            row = index // (width * used)
            column = (index // used) % width
            channel = index % used
            assert flat[index] == array[row, column, channel]

    @settings(max_examples=25)
    @given(
        st.integers(1, 16),
        st.integers(1, 16),
        st.sampled_from([1, 3, 4]),
    )
    def test_sample_count_matches_capacity_arithmetic(self, height, width, channels):
        array = make_cover(height, width, channels, "noise", 1)
        flat, used = image_stego.embeddable_stream(array)
        assert flat.size == height * width * used
