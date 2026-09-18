"""
Audio Quality and Distortion Metrics

Supports:
- 16-bit PCM WAV audio
- Mono and multi-channel audio
- Basic audio information
- Mean Squared Error (MSE)
- Root Mean Squared Error (RMSE)
- Mean Absolute Error (MAE)
- Signal-to-Noise Ratio (SNR)
- Peak Signal-to-Noise Ratio (PSNR)
- Maximum absolute sample difference
- Changed sample count and percentage
- Complete quality comparison report
"""

from pathlib import Path

import numpy as np
import soundfile as sf


# ============================================================
# CONSTANTS
# ============================================================

SUPPORTED_FORMAT = "WAV"
SUPPORTED_SUBTYPE = "PCM_16"

# Maximum positive value of a signed 16-bit PCM sample.
PCM16_MAX_VALUE = 32767


# ============================================================
# READ AUDIO
# ============================================================

def load_audio(audio_path):
    """
    Load a supported 16-bit PCM WAV file.

    Returns:
        samples:
            NumPy array converted to float64 for safe
            mathematical calculations.

        sample_rate:
            Audio sampling rate in Hz.
    """

    audio_path = Path(audio_path)

    if not audio_path.is_file():
        raise FileNotFoundError(
            f"Audio file not found: {audio_path}"
        )

    info = sf.info(str(audio_path))

    if info.format != SUPPORTED_FORMAT:
        raise ValueError(
            f"Unsupported audio format '{info.format}'. "
            "Only WAV audio is supported."
        )

    if info.subtype != SUPPORTED_SUBTYPE:
        raise ValueError(
            f"Unsupported WAV subtype '{info.subtype}'. "
            "Only 16-bit PCM WAV (PCM_16) is supported."
        )

    samples, sample_rate = sf.read(
        str(audio_path),
        dtype="int16",
        always_2d=False
    )

    if samples.size == 0:
        raise ValueError(
            "Audio file contains no samples."
        )

    return (
        samples.astype(np.float64),
        sample_rate
    )


# ============================================================
# ALIGN AUDIO
# ============================================================

def align_audio(original, modified):
    """
    Validate that two audio sample arrays can be compared.
    """

    original = np.asarray(
        original,
        dtype=np.float64
    )

    modified = np.asarray(
        modified,
        dtype=np.float64
    )

    if original.shape != modified.shape:
        raise ValueError(
            "Original and modified audio shapes differ. "
            f"Original: {original.shape}, "
            f"Modified: {modified.shape}"
        )

    if original.size == 0:
        raise ValueError(
            "Audio arrays cannot be empty."
        )

    return original, modified


# ============================================================
# MSE - MEAN SQUARED ERROR
# ============================================================

def calculate_mse(original, modified):
    """
    Calculate Mean Squared Error.

    Lower values mean the modified audio is closer
    to the original audio.
    """

    original, modified = align_audio(
        original,
        modified
    )

    error = (
        original - modified
    )

    mse = np.mean(
        error ** 2
    )

    return float(mse)


# ============================================================
# RMSE - ROOT MEAN SQUARED ERROR
# ============================================================

def calculate_rmse(original, modified):
    """
    Calculate Root Mean Squared Error.

    RMSE is expressed using the same sample-value scale
    as the original PCM samples.
    """

    mse = calculate_mse(
        original,
        modified
    )

    return float(
        np.sqrt(mse)
    )


# ============================================================
# MAE - MEAN ABSOLUTE ERROR
# ============================================================

def calculate_mae(original, modified):
    """
    Calculate Mean Absolute Error.

    This indicates the average absolute change in
    PCM sample values.
    """

    original, modified = align_audio(
        original,
        modified
    )

    difference = np.abs(
        original - modified
    )

    mae = np.mean(
        difference
    )

    return float(mae)


# ============================================================
# MAXIMUM ABSOLUTE DIFFERENCE
# ============================================================

def calculate_max_difference(
    original,
    modified
):
    """
    Calculate the largest absolute change between
    any original and modified sample.

    For n-bit LSB replacement, the theoretical maximum
    change is:

        (2 ** n) - 1
    """

    original, modified = align_audio(
        original,
        modified
    )

    difference = np.abs(
        original - modified
    )

    return float(
        np.max(difference)
    )


# ============================================================
# CHANGED SAMPLE STATISTICS
# ============================================================

def calculate_changed_samples(
    original,
    modified
):
    """
    Count how many scalar samples changed.

    Returns:
        changed_samples:
            Number of individual PCM values that changed.

        total_scalar_samples:
            Total number of PCM values compared.

        changed_percentage:
            Percentage of PCM values that changed.
    """

    original, modified = align_audio(
        original,
        modified
    )

    changed_mask = (
        original != modified
    )

    changed_samples = int(
        np.count_nonzero(
            changed_mask
        )
    )

    total_scalar_samples = int(
        original.size
    )

    changed_percentage = (
        changed_samples
        / total_scalar_samples
        * 100.0
    )

    return {
        "changed_samples":
            changed_samples,
        "total_scalar_samples":
            total_scalar_samples,
        "changed_percentage":
            float(changed_percentage)
    }


# ============================================================
# SNR - SIGNAL-TO-NOISE RATIO
# ============================================================

def calculate_snr(original, modified):
    """
    Calculate Signal-to-Noise Ratio in decibels.

    Higher SNR generally indicates less distortion.
    """

    original, modified = align_audio(
        original,
        modified
    )

    noise = (
        original - modified
    )

    signal_power = np.mean(
        original ** 2
    )

    noise_power = np.mean(
        noise ** 2
    )

    if noise_power == 0:
        return float("inf")

    if signal_power == 0:
        return float("-inf")

    snr = 10 * np.log10(
        signal_power
        / noise_power
    )

    return float(snr)


# ============================================================
# PSNR - PEAK SIGNAL-TO-NOISE RATIO
# ============================================================

def calculate_psnr(
    original,
    modified,
    max_value=PCM16_MAX_VALUE
):
    """
    Calculate Peak Signal-to-Noise Ratio in decibels.

    Uses the maximum positive PCM-16 sample value by default.
    """

    if max_value <= 0:
        raise ValueError(
            "max_value must be positive."
        )

    mse = calculate_mse(
        original,
        modified
    )

    if mse == 0:
        return float("inf")

    psnr = 10 * np.log10(
        (max_value ** 2)
        / mse
    )

    return float(psnr)


# ============================================================
# LSB DISTORTION BOUND
# ============================================================

def calculate_lsb_max_difference(
    lsb_count
):
    """
    Return the theoretical maximum sample change caused
    by replacing the selected number of LSBs.

    Examples:
        1 LSB -> 1
        2 LSB -> 3
        4 LSB -> 15
        8 LSB -> 255
    """

    if (
        isinstance(lsb_count, bool)
        or not isinstance(lsb_count, int)
    ):
        raise TypeError(
            "lsb_count must be an integer"
        )

    if not 1 <= lsb_count <= 8:
        raise ValueError(
            "lsb_count must be between 1 and 8"
        )

    return (
        (2 ** lsb_count) - 1
    )


# ============================================================
# COMPLETE QUALITY REPORT
# ============================================================

def calculate_quality_report(
    original_path,
    stego_path,
    lsb_count=None
):
    """
    Compare an original WAV file with a stego WAV file.

    Optionally provide lsb_count to verify whether the
    observed maximum difference is within the expected
    theoretical LSB replacement bound.

    Returns:
        Dictionary containing audio quality and
        distortion measurements.
    """

    original, original_rate = load_audio(
        original_path
    )

    stego, stego_rate = load_audio(
        stego_path
    )

    # --------------------------------------------------------
    # Validate audio compatibility
    # --------------------------------------------------------

    if original_rate != stego_rate:
        raise ValueError(
            "Sample rates differ. "
            f"Original: {original_rate} Hz, "
            f"Stego: {stego_rate} Hz"
        )

    if original.shape != stego.shape:
        raise ValueError(
            "Audio shapes differ. "
            f"Original: {original.shape}, "
            f"Stego: {stego.shape}"
        )

    # --------------------------------------------------------
    # Basic information
    # --------------------------------------------------------

    if original.ndim == 1:
        channels = 1
        total_frames = original.shape[0]

    else:
        channels = original.shape[1]
        total_frames = original.shape[0]

    duration_seconds = (
        total_frames / original_rate
    )

    # --------------------------------------------------------
    # Quality metrics
    # --------------------------------------------------------

    mse = calculate_mse(
        original,
        stego
    )

    rmse = calculate_rmse(
        original,
        stego
    )

    mae = calculate_mae(
        original,
        stego
    )

    snr = calculate_snr(
        original,
        stego
    )

    psnr = calculate_psnr(
        original,
        stego
    )

    max_difference = (
        calculate_max_difference(
            original,
            stego
        )
    )

    changed_stats = (
        calculate_changed_samples(
            original,
            stego
        )
    )

    # --------------------------------------------------------
    # Build report
    # --------------------------------------------------------

    report = {
        "sample_rate":
            original_rate,

        "channels":
            channels,

        "total_frames":
            int(total_frames),

        "total_scalar_samples":
            int(original.size),

        "duration_seconds":
            float(duration_seconds),

        "mse":
            mse,

        "rmse":
            rmse,

        "mae":
            mae,

        "snr_db":
            snr,

        "psnr_db":
            psnr,

        "max_absolute_difference":
            max_difference,

        "changed_samples":
            changed_stats[
                "changed_samples"
            ],

        "changed_percentage":
            changed_stats[
                "changed_percentage"
            ]
    }

    # --------------------------------------------------------
    # Optional LSB validation
    # --------------------------------------------------------

    if lsb_count is not None:

        theoretical_max = (
            calculate_lsb_max_difference(
                lsb_count
            )
        )

        report[
            "lsb_count"
        ] = lsb_count

        report[
            "theoretical_max_difference"
        ] = theoretical_max

        report[
            "within_expected_lsb_bound"
        ] = (
            max_difference
            <= theoretical_max
        )

    return report