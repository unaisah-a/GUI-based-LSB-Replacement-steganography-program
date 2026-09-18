import math

import numpy as np
import pytest
import soundfile as sf

from app.analysis.audio_analysis import calculate_quality_report
from app.stego.audio_stego import embed_audio_lsb


@pytest.mark.parametrize("channels", [1, 2])
@pytest.mark.parametrize("lsb_count", [1, 4, 8])
def test_audio_quality_report_uses_assertions(tmp_path, channels, lsb_count):
    frames = 8_000
    rate = 32_000
    values = ((np.arange(frames * channels) * 41) % 40_000 - 20_000).astype(
        np.int16
    )
    samples = values if channels == 1 else values.reshape(frames, channels)
    original = tmp_path / "original.wav"
    protected = tmp_path / "protected.wav"
    sf.write(original, samples, rate, format="WAV", subtype="PCM_16")

    embed_audio_lsb(
        original,
        protected,
        b"assertion-based audio quality",
        lsb_count=lsb_count,
        start_location=19,
    )
    report = calculate_quality_report(original, protected, lsb_count=lsb_count)

    assert report["sample_rate"] == rate
    assert report["channels"] == channels
    assert report["total_frames"] == frames
    assert report["total_scalar_samples"] == frames * channels
    assert report["mse"] >= 0
    assert report["rmse"] == pytest.approx(math.sqrt(report["mse"]))
    assert report["mae"] >= 0
    assert report["changed_samples"] > 0
    assert 0 < report["changed_percentage"] <= 100
    assert report["max_absolute_difference"] <= (2**lsb_count) - 1
    assert report["theoretical_max_difference"] == (2**lsb_count) - 1
    assert report["within_expected_lsb_bound"] is True


def test_audio_quality_rejects_mismatched_properties(tmp_path):
    first = tmp_path / "first.wav"
    second = tmp_path / "second.wav"
    sf.write(first, np.zeros(100, dtype=np.int16), 8_000, subtype="PCM_16")
    sf.write(second, np.zeros(100, dtype=np.int16), 16_000, subtype="PCM_16")
    with pytest.raises(ValueError, match="Sample rates differ"):
        calculate_quality_report(first, second)
