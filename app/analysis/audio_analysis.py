"""Distortion between a 16-bit PCM WAV cover and a copy of it.

Samples are read with :func:`app.stego.audio_stego.read_audio`, so this module
accepts exactly the files the audio stego layer accepts, validated the same way.
The two sample arrays are compared once, in float64 so squared differences cannot
overflow, and every figure is derived from that single error array.

The LSB distortion bound is not repeated here; it is the same for every medium and
lives in :func:`app.analysis.quality_metrics.distortion_bound`.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Final

import numpy as np

from app.stego import audio_stego
from app.stego.errors import ComparisonError

__all__ = ["PCM16_PEAK", "AudioQuality", "compare_audio"]

#: The largest positive 16-bit PCM sample, used as the PSNR peak.
PCM16_PEAK: Final[int] = 32767


@dataclass(frozen=True)
class AudioQuality:
    """How far a copy's samples are from the original's."""

    sample_rate: int
    channels: int
    total_frames: int
    #: Scalar samples across all channels: ``total_frames * channels``.
    total_samples: int
    duration_seconds: float
    mse: float
    rmse: float
    mae: float
    #: ``inf`` when the files are identical, ``-inf`` when the original is silent.
    snr_db: float
    #: ``inf`` when the files are identical.
    psnr_db: float
    max_absolute_difference: int
    changed_samples: int

    @property
    def changed_percentage(self) -> float:
        return self.changed_samples / self.total_samples * 100.0


def compare_audio(
    original_path: str | os.PathLike[str], stego_path: str | os.PathLike[str]
) -> AudioQuality:
    """Compare two WAV files sample by sample.

    :raises ComparisonError: the files differ in sample rate, channel count or
        length, so there is no sample-to-sample correspondence to measure.
    :raises app.stego.errors.StegoError: either file is not a 16-bit PCM WAV file.
    """
    original, cover = audio_stego.read_audio(original_path)
    copy, other = audio_stego.read_audio(stego_path)

    if cover.sample_rate != other.sample_rate:
        raise ComparisonError(
            f"the two audio files cannot be compared: sample rates differ "
            f"({cover.sample_rate} Hz against {other.sample_rate} Hz)"
        )
    if original.shape != copy.shape:
        raise ComparisonError(
            f"the two audio files cannot be compared: sample shapes differ "
            f"({original.shape} against {copy.shape})"
        )

    reference = original.astype(np.float64)
    error = copy.astype(np.float64) - reference
    magnitude = np.abs(error)
    mse = float(np.mean(error**2))
    signal_power = float(np.mean(reference**2))

    if mse == 0:
        snr = psnr = math.inf
    else:
        snr = -math.inf if signal_power == 0 else 10 * math.log10(signal_power / mse)
        psnr = 10 * math.log10(PCM16_PEAK**2 / mse)

    return AudioQuality(
        sample_rate=cover.sample_rate,
        channels=cover.channel_count,
        total_frames=cover.frame_count,
        total_samples=int(original.size),
        duration_seconds=cover.duration_seconds,
        mse=mse,
        rmse=math.sqrt(mse),
        mae=float(np.mean(magnitude)),
        snr_db=snr,
        psnr_db=psnr,
        max_absolute_difference=int(magnitude.max()),
        changed_samples=int(np.count_nonzero(error)),
    )
