from dataclasses import replace

import numpy as np
import pytest
import soundfile as sf

from app.attacks.payload_attacks import (
    _mutate_sample,
    corrupt_embedded_payload,
    corrupt_transport_header,
    modify_outside_payload,
)
from app.crypto.key_manager import generate_rsa_keys
from app.crypto.manifest import load_manifest, save_manifest
from app.services.media import inspect_carrier
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io
from app.stego.audio_stego import extract_audio_lsb
from app.stego.errors import ExtractionError
from app.stego.image_stego import extract_image
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _cover(path, media_type):
    if media_type == "image":
        pixels = np.arange(120 * 120 * 3, dtype=np.uint8).reshape(120, 120, 3)
        image_io.save_image(pixels, path, image_io.PNG)
    else:
        samples = np.arange(30_000 * 2, dtype=np.int16).reshape(30_000, 2)
        sf.write(path, samples, 16_000, subtype="PCM_16")


def _protected(tmp_path, signer, media_type, depth):
    private_key, public_key = signer
    suffix = ".png" if media_type == "image" else ".wav"
    cover = tmp_path / f"cover{suffix}"
    protected = tmp_path / f"protected{suffix}"
    manifest_path = tmp_path / "protected.json"
    _cover(cover, media_type)
    protect_media(
        cover,
        protected,
        manifest_path,
        b"bounded repetition payload",
        private_key,
        ProtectionOptions(
            media_id=f"ROBUST-{media_type}-{depth}",
            lsb_count=depth,
            start_method="manual",
            start_location=0,
            robustness="repetition-3",
        ),
    )
    return protected, manifest_path, public_key


@pytest.mark.parametrize("media_type", ["image", "audio"])
@pytest.mark.parametrize("depth", [3, 5, 6, 7])
def test_manifest_bounded_repetition_survives_damaged_transport_header(
    tmp_path, signer, media_type, depth
):
    protected, manifest_path, public_key = _protected(
        tmp_path, signer, media_type, depth
    )
    attacked = tmp_path / protected.name.replace("protected", "header-damaged")
    corrupt_transport_header(protected, attacked, manifest_path)
    manifest = load_manifest(manifest_path)

    if media_type == "image":
        with pytest.raises(ExtractionError):
            extract_image(
                str(attacked),
                depth,
                0,
                manifest_payload_length=manifest.embedded_payload_length,
            )
    else:
        with pytest.raises(ValueError):
            extract_audio_lsb(
                attacked,
                lsb_count=depth,
                start_location=0,
                manifest_payload_length=manifest.embedded_payload_length,
            )

    result = verify_media(attacked, manifest_path, public_key)
    assert result.verdict is Verdict.AUTHENTIC
    assert result.message == b"bounded repetition payload"
    extraction = next(check for check in result.checks if check.name == "Extraction")
    assert "bounded manifest length" in extraction.detail


@pytest.mark.parametrize("media_type", ["image", "audio"])
@pytest.mark.parametrize("depth", [3, 5, 7])
def test_single_copy_fault_recovers_near_actual_expanded_boundary(
    tmp_path, signer, media_type, depth
):
    protected, manifest_path, public_key = _protected(
        tmp_path, signer, media_type, depth
    )
    attacked = tmp_path / protected.name.replace("protected", "one-copy")
    attack = corrupt_embedded_payload(protected, attacked, manifest_path)
    manifest = load_manifest(manifest_path)
    carrier = inspect_carrier(protected)
    unexpanded_end = carrier.required_samples(manifest.payload_length, depth)
    expanded_end = carrier.required_samples(manifest.embedded_payload_length, depth)

    assert unexpanded_end <= attack.changed_sample_index < expanded_end
    result = verify_media(attacked, manifest_path, public_key)
    assert result.verdict is Verdict.AUTHENTIC
    assert result.message == b"bounded repetition payload"


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_two_copy_fault_is_not_claimed_as_recoverable(
    tmp_path, signer, media_type
):
    depth = 5
    protected, manifest_path, public_key = _protected(
        tmp_path, signer, media_type, depth
    )
    manifest = load_manifest(manifest_path)
    carrier = inspect_carrier(protected)
    envelope_byte = manifest.payload_length - 1
    first = tmp_path / protected.name.replace("protected", "copy-one")
    attacked = tmp_path / protected.name.replace("protected", "copy-two")

    def flip(source, destination, copy_index):
        relative_bit = (
            (carrier.carrier_header_bytes + envelope_byte * 3 + copy_index) * 8
        )
        sample = relative_bit // depth
        bit_offset = relative_bit % depth
        mask = 1 << (depth - 1 - bit_offset)
        _mutate_sample(
            source,
            destination,
            media_type,
            sample,
            mask,
            False,
        )

    flip(protected, first, 0)
    flip(first, attacked, 1)
    result = verify_media(attacked, manifest_path, public_key)
    assert result.verdict is Verdict.SIGNATURE_INVALID


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_outside_attack_at_start_zero_uses_expanded_region(
    tmp_path, signer, media_type
):
    depth = 3
    protected, manifest_path, public_key = _protected(
        tmp_path, signer, media_type, depth
    )
    attacked = tmp_path / protected.name.replace("protected", "outside")
    manifest = load_manifest(manifest_path)
    carrier = inspect_carrier(protected)
    occupied = carrier.required_samples(manifest.embedded_payload_length, depth)
    result = modify_outside_payload(protected, attacked, manifest_path)

    assert result.changed_sample_index == occupied
    verified = verify_media(attacked, manifest_path, public_key)
    assert verified.verdict is Verdict.AUTHENTIC


def test_misleading_and_out_of_bounds_robust_manifests_never_authenticate(
    tmp_path, signer
):
    protected, manifest_path, public_key = _protected(tmp_path, signer, "image", 3)
    manifest = load_manifest(manifest_path)

    misleading_path = tmp_path / "misleading.json"
    misleading = replace(
        manifest,
        payload_length=manifest.payload_length + 1,
        carrier_payload_length=(manifest.payload_length + 1) * 3,
    )
    save_manifest(misleading, misleading_path)
    assert verify_media(protected, misleading_path, public_key).verdict is not Verdict.AUTHENTIC

    oversized_path = tmp_path / "oversized.json"
    oversized = replace(
        manifest,
        payload_length=1_000_000,
        carrier_payload_length=3_000_000,
    )
    save_manifest(oversized, oversized_path)
    oversized_result = verify_media(protected, oversized_path, public_key)
    assert oversized_result.verdict is Verdict.CANNOT_VERIFY
    assert any(
        check.name == "Start location" and check.status.value == "FAIL"
        for check in oversized_result.checks
    )
