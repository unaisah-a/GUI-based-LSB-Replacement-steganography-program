import numpy as np
import pytest
import soundfile as sf

from app.crypto.encryption import generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _image_cover(path):
    y, x = np.indices((96, 128))
    array = np.stack(
        (
            (x * 2) % 256,
            (y * 3) % 256,
            ((x + y) * 5) % 256,
        ),
        axis=2,
    ).astype(np.uint8)
    image_io.save_image(array, path, image_io.PNG)


def _audio_cover(path):
    rate = 44_100
    time = np.arange(rate, dtype=np.float64) / rate
    samples = (np.sin(2 * np.pi * 440 * time) * 16_000).astype(np.int16)
    sf.write(path, samples, rate, subtype="PCM_16")


@pytest.mark.parametrize("media_type", ["image", "audio"])
@pytest.mark.parametrize("encrypted", [False, True])
def test_protect_and_verify_round_trip(tmp_path, signer, media_type, encrypted):
    private_key, public_key = signer
    suffix = ".png" if media_type == "image" else ".wav"
    source = tmp_path / f"cover{suffix}"
    output = tmp_path / f"protected{suffix}"
    manifest = tmp_path / "protected.manifest.json"
    if media_type == "image":
        _image_cover(source)
    else:
        _audio_cover(source)
    encryption_key = generate_encryption_key() if encrypted else None
    message = "INF2005 integrity message: 你好".encode()

    protected = protect_media(
        source,
        output,
        manifest,
        message,
        private_key,
        ProtectionOptions(
            media_id=f"{media_type.upper()}-001",
            lsb_count=3,
            start_secret="separate start secret",
            encryption_key=encryption_key,
        ),
    )
    result = verify_media(
        protected.output_path,
        protected.manifest_path,
        public_key,
        start_secret="separate start secret",
        encryption_key=encryption_key,
    )

    assert result.verdict is Verdict.AUTHENTIC
    assert result.message == message
    assert result.summary == "Message and signed record verified."
    assert protected.start_location > 0


def test_wrong_public_key_is_signature_invalid(tmp_path, signer):
    private_key, _ = signer
    _, wrong_public_key = generate_rsa_keys()
    source = tmp_path / "cover.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    _image_cover(source)
    protect_media(
        source,
        output,
        manifest,
        b"signed message",
        private_key,
        ProtectionOptions(media_id="IMG-WRONG-KEY", start_location=7, start_method="manual"),
    )

    result = verify_media(output, manifest, wrong_public_key)
    assert result.verdict is Verdict.SIGNATURE_INVALID


def test_wrong_start_secret_cannot_claim_exact_cause(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "cover.wav"
    output = tmp_path / "protected.wav"
    manifest = tmp_path / "protected.json"
    _audio_cover(source)
    protect_media(
        source,
        output,
        manifest,
        b"hidden message",
        private_key,
        ProtectionOptions(media_id="AUD-WRONG-START", start_secret="right secret"),
    )

    result = verify_media(
        output,
        manifest,
        public_key,
        start_secret="wrong secret",
    )
    assert result.verdict is Verdict.CANNOT_VERIFY
    assert "wrong" not in result.summary.lower()


def test_repetition_coding_recovers_one_corrupted_copy(tmp_path, signer):
    from app.attacks.payload_attacks import corrupt_embedded_payload

    private_key, public_key = signer
    source = tmp_path / "cover.png"
    protected = tmp_path / "protected.png"
    attacked = tmp_path / "attacked.png"
    manifest = tmp_path / "protected.json"
    _image_cover(source)
    protect_media(
        source,
        protected,
        manifest,
        b"robust payload",
        private_key,
        ProtectionOptions(
            media_id="IMG-ROBUST",
            lsb_count=3,
            start_secret="robust secret",
            robustness="repetition-3",
        ),
    )
    corrupt_embedded_payload(
        protected,
        attacked,
        manifest,
        start_secret="robust secret",
    )

    result = verify_media(
        attacked,
        manifest,
        public_key,
        start_secret="robust secret",
    )
    assert result.verdict is Verdict.AUTHENTIC
    assert result.message == b"robust payload"
