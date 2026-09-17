import numpy as np
import pytest
import soundfile as sf

from app.crypto.encryption import generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
from app.services.protection import (
    ProtectionOptions,
    estimate_protection_capacity,
    protect_media,
)
from app.stego import image_io
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _image(path, *, channels=3, height=64, width=64):
    values = np.arange(height * width * channels, dtype=np.uint32)
    pixels = (values % 256).astype(np.uint8).reshape(height, width, channels)
    image_io.save_image(pixels, path, image_io.PNG)
    return pixels


def _audio(path, *, channels=1, frames=12_000, rate=32_000):
    values = ((np.arange(frames * channels) * 37) % 50_000 - 25_000).astype(
        np.int16
    )
    samples = values if channels == 1 else values.reshape(frames, channels)
    sf.write(path, samples, rate, format="WAV", subtype="PCM_16")
    return samples


def _options(depth, **changes):
    values = {
        "media_id": "CAPACITY-001",
        "lsb_count": depth,
        "start_method": "manual",
        "start_location": 7,
        "metadata": {"application": "integration-test"},
    }
    values.update(changes)
    return ProtectionOptions(**values)


@pytest.mark.parametrize("depth", range(1, 9))
@pytest.mark.parametrize("media,channels", [("image", 3), ("audio", 1), ("audio", 2)])
def test_service_round_trip_at_every_depth(
    tmp_path, signer, depth, media, channels
):
    private_key, public_key = signer
    suffix = ".png" if media == "image" else ".wav"
    source = tmp_path / f"cover-{media}-{channels}{suffix}"
    output = tmp_path / f"protected-{media}-{channels}-{depth}{suffix}"
    manifest = tmp_path / f"protected-{media}-{channels}-{depth}.json"
    if media == "image":
        _image(source)
    else:
        _audio(source, channels=channels)
    message = "Unicode payload: 你好".encode("utf-8") + b"\x00\xff"
    options = _options(depth)

    estimate = estimate_protection_capacity(source, message, private_key, options)
    result = protect_media(source, output, manifest, message, private_key, options)
    verified = verify_media(output, manifest, public_key)

    assert estimate.fits
    assert estimate.envelope_length == result.payload_length
    assert estimate.embedded_payload_length == result.embedded_payload_length
    assert estimate.required_samples == result.required_samples
    assert estimate.carrier.encoded_length == (
        result.embedded_payload_length + estimate.carrier.carrier_header_bytes
    )
    assert verified.verdict is Verdict.AUTHENTIC
    assert verified.message == message


@pytest.mark.parametrize("media", ["image", "audio"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_derived_start_and_encryption_use_exact_capacity(
    tmp_path, signer, media, encrypted
):
    private_key, public_key = signer
    suffix = ".png" if media == "image" else ".wav"
    source = tmp_path / f"derived-cover-{media}{suffix}"
    output = tmp_path / f"derived-protected-{media}-{encrypted}{suffix}"
    manifest = tmp_path / f"derived-{media}-{encrypted}.json"
    _image(source) if media == "image" else _audio(source)
    message = b"\x00binary\xff payload"
    encryption_key = generate_encryption_key() if encrypted else None
    options = _options(
        3,
        start_method="hmac-sha256",
        start_location=None,
        start_secret="capacity secret",
        encryption_key=encryption_key,
    )

    estimate = estimate_protection_capacity(source, message, private_key, options)
    result = protect_media(source, output, manifest, message, private_key, options)
    verified = verify_media(
        output,
        manifest,
        public_key,
        start_secret="capacity secret",
        encryption_key=encryption_key,
    )

    assert estimate.encrypted is encrypted
    assert estimate.fits
    assert estimate.required_samples == result.required_samples
    assert 0 <= result.start_location <= estimate.carrier.highest_valid_start_location
    assert verified.verdict is Verdict.AUTHENTIC
    assert verified.message == message


@pytest.mark.parametrize("media", ["image", "audio"])
def test_exact_fit_boundary_succeeds(tmp_path, signer, media):
    private_key, public_key = signer
    message = b"exact fit"
    options = _options(5, start_location=0)
    sizing_source = tmp_path / ("sizing.png" if media == "image" else "sizing.wav")
    _image(sizing_source) if media == "image" else _audio(sizing_source)
    sizing = estimate_protection_capacity(sizing_source, message, private_key, options)
    required = sizing.required_samples

    if media == "image":
        source = tmp_path / "exact.png"
        _image(source, channels=1, height=1, width=required)
        output = tmp_path / "exact-protected.png"
    else:
        source = tmp_path / "exact.wav"
        _audio(source, channels=1, frames=required)
        output = tmp_path / "exact-protected.wav"
    manifest = tmp_path / f"exact-{media}.json"

    exact = estimate_protection_capacity(source, message, private_key, options)
    result = protect_media(source, output, manifest, message, private_key, options)

    assert exact.required_samples == exact.carrier.total_samples
    assert exact.carrier.highest_valid_start_location == 0
    assert exact.fits
    assert result.required_samples == required
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


@pytest.mark.parametrize("media", ["image", "audio"])
def test_over_capacity_rejects_before_output_creation(tmp_path, signer, media):
    private_key, _ = signer
    source = tmp_path / ("tiny.png" if media == "image" else "tiny.wav")
    if media == "image":
        _image(source, channels=1, height=1, width=8)
        output = tmp_path / "protected.png"
    else:
        _audio(source, channels=1, frames=8)
        output = tmp_path / "protected.wav"
    manifest = tmp_path / "protected.json"
    options = _options(1, start_location=0)

    estimate = estimate_protection_capacity(source, b"too large", private_key, options)
    assert not estimate.fits
    with pytest.raises(ValueError, match="protected payload needs"):
        protect_media(source, output, manifest, b"too large", private_key, options)
    assert not output.exists()
    assert not manifest.exists()


def test_image_alpha_and_audio_properties_are_preserved(tmp_path, signer):
    private_key, _ = signer
    image_source = tmp_path / "rgba.png"
    original_image = _image(image_source, channels=4)
    image_output = tmp_path / "rgba-protected.png"
    protect_media(
        image_source,
        image_output,
        tmp_path / "rgba.json",
        b"alpha",
        private_key,
        _options(2),
    )
    protected_image, descriptor = image_io.load_image(image_output)
    assert descriptor.channel_count == 4
    assert np.array_equal(protected_image[:, :, 3], original_image[:, :, 3])

    audio_source = tmp_path / "stereo.wav"
    _audio(audio_source, channels=2, frames=10_000, rate=48_000)
    before = sf.info(audio_source)
    audio_output = tmp_path / "stereo-protected.wav"
    protect_media(
        audio_source,
        audio_output,
        tmp_path / "stereo.json",
        b"properties",
        private_key,
        _options(2),
    )
    after = sf.info(audio_output)
    assert (after.format, after.subtype) == ("WAV", "PCM_16")
    assert (after.samplerate, after.channels, after.frames) == (
        before.samplerate,
        before.channels,
        before.frames,
    )


def test_repetition_capacity_is_exactly_tripled(tmp_path, signer):
    private_key, _ = signer
    source = tmp_path / "cover.png"
    _image(source)
    estimate = estimate_protection_capacity(
        source,
        b"robust",
        private_key,
        _options(2, robustness="repetition-3"),
    )
    assert estimate.embedded_payload_length == estimate.envelope_length * 3
    assert estimate.carrier.encoded_length == (
        estimate.embedded_payload_length + estimate.carrier.carrier_header_bytes
    )
