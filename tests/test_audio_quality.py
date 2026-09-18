"""Tests for the audio quality metrics in :mod:`app.analysis.audio_analysis`.

Every test generates its own audio inside ``tmp_path``.
"""

from __future__ import annotations

import itertools
import math

import numpy as np
import pytest

from app.analysis import audio_analysis, quality_metrics
from app.stego.errors import ComparisonError

from conftest import AUDIO_SAMPLE_RATE, make_audio, write_audio_file


class TestMetrics:
    def test_identical_audio_has_zero_error_and_unbounded_psnr(self, tmp_path):
        samples = make_audio(2_048, pattern="tone")
        original = write_audio_file(str(tmp_path), samples, "original")
        copy = write_audio_file(str(tmp_path), samples, "copy")

        report = audio_analysis.compare_audio(original, copy)

        assert report.mse == 0.0
        assert report.rmse == 0.0
        assert report.mae == 0.0
        assert report.max_absolute_difference == 0.0
        assert report.changed_samples == 0
        assert report.changed_percentage == 0.0
        assert math.isinf(report.psnr_db)
        assert math.isinf(report.snr_db)

    def test_metrics_grow_with_distortion(self, tmp_path):
        base = make_audio(2_048, pattern="tone", seed=3)
        original = write_audio_file(str(tmp_path), base, "original")

        small = base.astype(np.int32).copy()
        small[:64] += 1
        large = base.astype(np.int32).copy()
        large[:64] += 64

        near = write_audio_file(
            str(tmp_path), np.clip(small, -32768, 32767).astype(np.int16), "near"
        )
        far = write_audio_file(
            str(tmp_path), np.clip(large, -32768, 32767).astype(np.int16), "far"
        )

        near_report = audio_analysis.compare_audio(original, near)
        far_report = audio_analysis.compare_audio(original, far)

        assert 0 < near_report.mse < far_report.mse
        assert near_report.psnr_db > far_report.psnr_db
        assert near_report.snr_db > far_report.snr_db
        assert near_report.max_absolute_difference == 1.0
        assert far_report.max_absolute_difference == 64.0

    def test_changed_sample_count_is_exact(self, tmp_path):
        base = make_audio(1_024, pattern="noise", seed=7)
        original = write_audio_file(str(tmp_path), base, "original")

        modified = base.astype(np.int32).copy()
        # Choose samples that are not already at the positive int16 ceiling, so
        # every increment genuinely changes a value rather than being clipped.
        headroom = np.flatnonzero(base < 32767)[:37]
        modified[headroom] += 1
        stego = write_audio_file(
            str(tmp_path), np.clip(modified, -32768, 32767).astype(np.int16), "stego"
        )

        report = audio_analysis.compare_audio(original, stego)
        assert report.changed_samples == 37

    def test_report_carries_media_properties(self, tmp_path):
        samples = make_audio(AUDIO_SAMPLE_RATE, channels=2, pattern="ramp")
        original = write_audio_file(str(tmp_path), samples, "original")
        copy = write_audio_file(str(tmp_path), samples, "copy")

        report = audio_analysis.compare_audio(original, copy)

        assert report.sample_rate == AUDIO_SAMPLE_RATE
        assert report.channels == 2
        assert report.total_frames == AUDIO_SAMPLE_RATE
        assert report.duration_seconds == pytest.approx(1.0)


class TestValidation:
    def test_differing_sample_rates_are_rejected(self, tmp_path):
        samples = make_audio(1_024)
        original = write_audio_file(str(tmp_path), samples, "original", sample_rate=44_100)
        other = write_audio_file(str(tmp_path), samples, "other", sample_rate=22_050)

        with pytest.raises(ComparisonError, match="sample rates differ"):
            audio_analysis.compare_audio(original, other)

    def test_differing_shapes_are_rejected(self, tmp_path):
        original = write_audio_file(str(tmp_path), make_audio(1_024), "original")
        other = write_audio_file(str(tmp_path), make_audio(2_048), "other")

        with pytest.raises(ComparisonError, match="shapes differ"):
            audio_analysis.compare_audio(original, other)


# --------------------------------------------------------------------------- #
# Evidence: distortion against depth
# --------------------------------------------------------------------------- #
#
# The sweep is also the evidence behind a claim the demonstration makes out loud: that
# audible distortion rises with depth. One depth cannot show a trend.


class TestDistortionAgainstDepth:
    def test_distortion_rises_monotonically_with_depth(
        self, tmp_path, evidence_directory
    ):
        """The trade-off the depth control exists to expose, measured.

        Every payload bit is filled from the same deterministic stream, so the only
        variable across the eight rows is the depth. The full capacity is used at each
        depth, because a fixed small payload would touch fewer samples at a greater
        depth and confound the comparison.
        """

        from app.stego import audio_stego
        from app.utils import file_utils

        frames = AUDIO_SAMPLE_RATE  # one second, mono
        cover = write_audio_file(
            str(tmp_path), make_audio(frames, pattern="tone"), "cover"
        )

        rows: list[dict[str, object]] = []
        for depth in range(1, 9):
            report_capacity, _ = audio_stego.measure_capacity(cover, depth)
            # Fill the whole cover so the comparison is at equal occupancy.
            payload_length = report_capacity.max_payload_length
            payload = bytes((index * 37 + 11) % 256 for index in range(payload_length))

            stego = str(tmp_path / f"stego_{depth}.wav")
            audio_stego.embed_audio(cover, stego, payload, depth, 0)
            assert audio_stego.extract_audio(stego, depth, 0) == payload

            report = audio_analysis.compare_audio(cover, stego)
            bound = quality_metrics.distortion_bound(depth)
            rows.append(
                {
                    "lsb_depth": depth,
                    "payload_bytes": payload_length,
                    "mse": report.mse,
                    "rmse": report.rmse,
                    "psnr_db": report.psnr_db,
                    "snr_db": report.snr_db,
                    "max_absolute_difference": report.max_absolute_difference,
                    "theoretical_max_difference": bound,
                    "within_expected_lsb_bound": (
                        report.max_absolute_difference <= bound
                    ),
                    "changed_samples": report.changed_samples,
                    "changed_percentage": report.changed_percentage,
                }
            )

        # The claim: more bits replaced means more distortion, at every step.
        for earlier, later in itertools.pairwise(rows):
            assert later["mse"] > earlier["mse"], later["lsb_depth"]
            assert later["psnr_db"] < earlier["psnr_db"], later["lsb_depth"]
            assert later["snr_db"] < earlier["snr_db"], later["lsb_depth"]
            assert later["max_absolute_difference"] >= (
                earlier["max_absolute_difference"]
            )

        # And every row stays inside the bound its depth allows.
        for row in rows:
            assert row["within_expected_lsb_bound"] is True

        if evidence_directory is None:
            return
        directory = evidence_directory

        file_utils.write_json_atomic(
            str(directory / "audio_quality_by_depth.json"),
            {
                "experiment": "audio distortion against LSB depth",
                "cover": "1 second of 16-bit PCM mono at 44.1 kHz, 440 Hz tone",
                "occupancy": "full capacity at each depth",
                "cases": rows,
            },
            overwrite=True,
        )

        lines = [
            "# Audio Distortion Against LSB Depth",
            "",
            "Generated by `tests/test_audio_quality.py`. Do not edit by hand.",
            "",
            "## What is being established",
            "",
            "That distortion rises with LSB depth, monotonically and by how much. This "
            "is the trade-off the Protect tab's depth slider exists to expose, and the "
            "demonstration states it out loud, so it is measured rather than asserted "
            "from theory.",
            "",
            "## Method",
            "",
            "- Cover: one second of 16-bit PCM mono at 44.1 kHz, a 440 Hz tone.",
            "- At each depth the cover is filled to **full capacity**, from a "
            "deterministic byte stream. A fixed small payload would touch fewer "
            "samples at a greater depth and confound the comparison.",
            "- Each payload is extracted and compared before its metrics are taken, so "
            "no row describes a broken embedding.",
            "",
            "## Results",
            "",
            "| Depth | Payload | MSE | RMSE | PSNR (dB) | SNR (dB) | Max change | "
            "Bound | Within bound | Samples changed |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|",
        ]
        for row in rows:
            lines.append(
                f"| {row['lsb_depth']} | {row['payload_bytes']:,} B | "
                f"{row['mse']:.4f} | {row['rmse']:.4f} | {row['psnr_db']:.2f} | "
                f"{row['snr_db']:.2f} | "
                f"{row['max_absolute_difference']:.0f} | "
                f"{row['theoretical_max_difference']} | "
                f"{'yes' if row['within_expected_lsb_bound'] else 'NO'} | "
                f"{row['changed_samples']:,} "
                f"({row['changed_percentage']:.2f}%) |"
            )

        lines += [
            "",
            "## Reading the table",
            "",
            "- **Max change against the bound.** Replacing the low *n* bits can move a "
            "sample by at most `2**n - 1`. Every row is inside its bound; a row that "
            "was not would mean more had been written than the depth accounts for.",
            "- **PSNR falls by roughly 6 dB per bit.** That is what doubling the "
            "amplitude of the error term does, and it is the clearest single number "
            "for the cost of extra capacity.",
            "- **At depth 8 the whole low byte is replaced**, so a sample can move by "
            "up to 255. The phrase \"least significant bit\" has stopped meaning much "
            "well before that point, and the distortion is audible.",
            "",
            "## What this does not establish",
            "",
            "Audibility is not a number. These are objective metrics; whether a given "
            "PSNR is noticeable depends on the material and the listener, which is why "
            "the demonstration plays the files rather than only quoting figures. The "
            "application recommends no depth: the right answer depends on the cover.",
            "",
        ]
        file_utils.write_text_atomic(
            str(directory / "audio_quality_by_depth.md"),
            "\n".join(lines),
            overwrite=True,
        )
