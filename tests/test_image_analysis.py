"""Regression coverage for retained quality comparisons."""
from __future__ import annotations

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


class TestMetricCorrectness:
    """Requirement 8.5 to 8.7 and 15.5."""

    @given(image_pair())
    def test_zero_error_exactly_when_colour_channels_identical(self, pair):
        first, second = pair
        result = analysis.compare_quality(first, second)
        identical = np.array_equal(first, second)

        assert result.pixel_identical is identical
        # Overall metrics exclude RGBA alpha; pixel equality includes it.
        colour_identical = np.array_equal(first[..., :3], second[..., :3])
        if colour_identical:
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

        assert np.array_equal(first, before_first)
        assert np.array_equal(second, before_second)






    def test_metrics_are_plain_python_types(self):
        """Requirement 12.1."""
        result = analysis.compare_quality(
            make_cover(8, 8, 3, "noise", 1), make_cover(8, 8, 3, "noise", 2)
        )
        assert type(result.overall_mse) is float
        assert type(result.pixel_identical) is bool
        assert type(result.differing_samples) is int



class TestInputValidation:

    @pytest.mark.parametrize('bad', [42, None, [1, 2, 3], {'a': 1}])
    def test_rejects_unsupported_input_types(self, bad):
        with pytest.raises(ValidationError, match='file path or a numpy array'):
            analysis.compare_quality(bad, bad)

    def test_a_string_is_treated_as_a_path(self, workspace):
        """A string input is a path, so a missing file is a FileError not a type error."""
        from app.stego.errors import FileError
        with pytest.raises(FileError, match='not found'):
            analysis.compare_quality(os.path.join(workspace, 'absent.png'), os.path.join(workspace, 'absent.png'))

    def test_rejects_wrong_dtype(self):
        with pytest.raises(ValidationError, match='uint8'):
            analysis.compare_quality(np.zeros((4, 4, 3), dtype=np.uint16), np.zeros((4, 4, 3), dtype=np.uint16))

    def test_rejects_wrong_dimension_count(self):
        with pytest.raises(ValidationError, match='dimensions'):
            analysis.compare_quality(np.zeros((4, 4, 3, 2), dtype=np.uint8), np.zeros((4, 4, 3, 2), dtype=np.uint8))

    def test_rejects_unsupported_channel_count(self):
        with pytest.raises(ValidationError, match='channels'):
            analysis.compare_quality(np.zeros((4, 4, 2), dtype=np.uint8), np.zeros((4, 4, 2), dtype=np.uint8))

    def test_accepts_two_dimensional_grayscale(self):
        results = analysis.compare_quality(np.zeros((16, 16), dtype=np.uint8), np.zeros((16, 16), dtype=np.uint8))
        assert results.total_samples == 256
