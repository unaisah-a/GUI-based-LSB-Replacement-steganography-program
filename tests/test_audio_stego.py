import numpy as np
import pytest
import soundfile as sf

from app.stego.audio_stego import (
    embed_audio,
    embed_audio_lsb,
    extract_audio,
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


def test_shared_audio_adapters_retain_the_low_level_packet_format(tmp_path):
    original = tmp_path / "original.wav"
    protected = tmp_path / "protected.wav"
    create_test_wav(original)
    payload = b"legacy low-level transport"

    result = embed_audio(original, protected, payload, 3, 17)

    assert result["packet_size"] == len(payload) + len(b"INF2005") + 4
    assert extract_audio(protected, 3, 17) == payload


def test_audio_embedding_rejects_aliases_and_requires_explicit_overwrite(tmp_path):
    original = tmp_path / "original.wav"
    protected = tmp_path / "protected.wav"
    alias = tmp_path / "alias.wav"
    create_test_wav(original)

    with pytest.raises(ValueError, match="differ"):
        embed_audio_lsb(original, original, b"message", start_location=0)
    alias.hardlink_to(original)
    with pytest.raises(ValueError, match="differ"):
        embed_audio_lsb(original, alias, b"message", start_location=0, overwrite=True)

    protected.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        embed_audio_lsb(original, protected, b"message", start_location=0)
    embed_audio_lsb(
        original, protected, b"message", start_location=0, overwrite=True
    )
    assert extract_audio_lsb(protected, start_location=0) == b"message"


def test_audio_rejects_non_pcm16_wav(tmp_path):
    source = tmp_path / "pcm24.wav"
    output = tmp_path / "protected.wav"
    sf.write(source, np.zeros(100, dtype=np.int32), 8_000, subtype="PCM_24")
    with pytest.raises(ValueError, match="PCM_16"):
        embed_audio_lsb(source, output, b"message", start_location=0)
