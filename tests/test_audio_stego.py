import numpy as np
import pytest
import soundfile as sf

from app.stego.audio_stego import (
    embed_audio_lsb,
    extract_audio_lsb,
)


def create_test_wav(path):
    """
    Create a temporary PCM-16 WAV file for testing.
    """

    sample_rate = 44100
    duration = 1.0
    frequency = 440

    t = np.linspace(
        0,
        duration,
        int(sample_rate * duration),
        endpoint=False
    )

    samples = (
        0.5
        * np.sin(2 * np.pi * frequency * t)
        * 32767
    ).astype(np.int16)

    sf.write(
        path,
        samples,
        sample_rate,
        subtype="PCM_16"
    )


@pytest.mark.parametrize(
    "lsb_count",
    range(1, 9)
)
def test_audio_lsb_round_trip(tmp_path, lsb_count):

    # ----------------------------------------
    # Arrange
    # ----------------------------------------

    original_path = (
        tmp_path / "original.wav"
    )

    stego_path = (
        tmp_path
        / f"stego_{lsb_count}bit.wav"
    )

    create_test_wav(
        original_path
    )

    payload = (
        b"INF2005 Audio LSB Test"
    )

    # Use a non-zero location so we also
    # confirm embedding away from sample 0.
    start_location = 100

    # ----------------------------------------
    # Act - Embed
    # ----------------------------------------

    embed_audio_lsb(
        input_path=original_path,
        output_path=stego_path,
        payload=payload,
        lsb_count=lsb_count,
        start_location=start_location
    )

    # ----------------------------------------
    # Act - Extract
    # ----------------------------------------

    extracted_payload = (
        extract_audio_lsb(
            input_path=stego_path,
            lsb_count=lsb_count,
            start_location=start_location
        )
    )

    # ----------------------------------------
    # Assert
    # ----------------------------------------

    assert extracted_payload == payload


def test_audio_extraction_cross_checks_manifest_payload_length(tmp_path):
    original_path = tmp_path / "original.wav"
    stego_path = tmp_path / "stego.wav"
    create_test_wav(original_path)
    payload = b"manifest-bounded audio payload"
    embed_audio_lsb(
        input_path=original_path,
        output_path=stego_path,
        payload=payload,
        lsb_count=3,
        start_location=100,
    )

    assert extract_audio_lsb(
        input_path=stego_path,
        lsb_count=3,
        start_location=100,
        manifest_payload_length=len(payload),
    ) == payload
    with pytest.raises(ValueError, match="manifest payload length"):
        extract_audio_lsb(
            input_path=stego_path,
            lsb_count=3,
            start_location=100,
            manifest_payload_length=len(payload) + 1,
        )
