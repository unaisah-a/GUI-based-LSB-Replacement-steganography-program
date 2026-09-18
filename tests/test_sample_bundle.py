import json
import shutil

import pytest

from scripts.generate_samples import (
    CONFIDENTIAL_MESSAGE,
    LONG_MESSAGE,
    SHORT_MESSAGE,
    _create_audio,
    _create_image,
    generate_bundle,
)
from scripts.verify_sample_bundle import verify_receiver_bundle


@pytest.fixture(scope="module")
def generated_bundle(tmp_path_factory):
    include_video = shutil.which("ffmpeg") is not None and shutil.which("ffprobe") is not None
    root = tmp_path_factory.mktemp("sample-bundle") / "r11"
    index = generate_bundle(root, include_video=include_video)
    return root, index, include_video


def test_receiver_bundle_reproduces_all_indexed_outcomes(generated_bundle):
    root, index, include_video = generated_bundle
    report = verify_receiver_bundle(root / "receiver")

    assert report["all_passed"] is True
    assert report["capacity_case_passed"] is True
    assert len(report["cases"]) == index["case_count"]
    by_id = {case["id"]: case for case in report["cases"]}
    assert by_id["image-short-positive"]["actual_verdict"] == "AUTHENTIC"
    assert by_id["audio-long-positive"]["actual_verdict"] == "AUTHENTIC"
    assert by_id["image-message-corruption-negative"]["actual_verdict"] != "AUTHENTIC"
    assert by_id["audio-signature-corruption-negative"]["actual_verdict"] != "AUTHENTIC"
    assert by_id["audio-robust-one-copy-corrected"]["actual_verdict"] == "AUTHENTIC"
    assert by_id["audio-robust-two-copy-negative"]["actual_verdict"] != "AUTHENTIC"
    if include_video:
        assert by_id["video-short-positive"]["actual_verdict"] == "AUTHENTIC"
        assert by_id["video-h264-lossy-negative"]["actual_verdict"] != "AUTHENTIC"


def test_bundle_has_exact_messages_fresh_public_material_and_no_private_key(generated_bundle):
    root, index, _include_video = generated_bundle
    assert (root / "messages" / "short.txt").read_bytes() == SHORT_MESSAGE.encode()
    assert (root / "messages" / "long.txt").read_bytes() == LONG_MESSAGE.encode()
    assert (root / "messages" / "confidential.txt").read_bytes() == CONFIDENTIAL_MESSAGE.encode()
    assert index["cryptographic_generation"] == "fresh-on-every-run"
    assert not list(root.rglob("*private*"))
    assert b"PRIVATE KEY" not in b"\n".join(
        path.read_bytes() for path in root.rglob("*") if path.is_file()
    )
    secrets = json.loads(
        (root / "receiver" / "demo-only-secrets.json").read_text(encoding="utf-8")
    )
    assert secrets["format"] == "SMIV-DEMO-SECRETS"
    assert "signing" not in secrets


def test_required_case_matrix_and_portable_paths(generated_bundle):
    root, index, include_video = generated_bundle
    cases = index["cases"]
    authentic_media = {case["medium"] for case in cases if case["expected_verdict"] == "AUTHENTIC"}
    negative_media = {case["medium"] for case in cases if case["expected_verdict"] != "AUTHENTIC"}
    assert {"image", "audio"} <= authentic_media
    assert {"image", "audio"} <= negative_media
    assert sum(case["expected_verdict"] != "AUTHENTIC" for case in cases) >= 3
    assert any(case["encryption_key_ref"] for case in cases)
    assert (root / "receiver" / "capacity-rejection.json").is_file()
    if include_video:
        assert "video" in authentic_media and "video" in negative_media
    for document in root.rglob("*.json"):
        text = document.read_text(encoding="utf-8")
        assert str(root) not in text


def test_cover_generators_are_byte_deterministic(tmp_path):
    first_image, second_image = tmp_path / "one.png", tmp_path / "two.png"
    first_audio, second_audio = tmp_path / "one.wav", tmp_path / "two.wav"
    _create_image(first_image)
    _create_image(second_image)
    _create_audio(first_audio, channels=2, frames=2048, rate=16_000)
    _create_audio(second_audio, channels=2, frames=2048, rate=16_000)
    assert first_image.read_bytes() == second_image.read_bytes()
    assert first_audio.read_bytes() == second_audio.read_bytes()


def test_regeneration_uses_fresh_keys_secrets_and_payload_nonces(
    generated_bundle, tmp_path
):
    first_root, first_index, _include_video = generated_bundle
    second_root = tmp_path / "regenerated"
    second_index = generate_bundle(second_root, include_video=False)

    assert second_index["public_key_fingerprint"] != first_index["public_key_fingerprint"]
    first_secrets = json.loads(
        (first_root / "receiver" / "demo-only-secrets.json").read_text(encoding="utf-8")
    )
    second_secrets = json.loads(
        (second_root / "receiver" / "demo-only-secrets.json").read_text(encoding="utf-8")
    )
    assert second_secrets["start_secrets"] != first_secrets["start_secrets"]
    assert second_secrets["encryption_keys"] != first_secrets["encryption_keys"]
    first_manifest = json.loads(
        (first_root / "sender" / "manifests" / "image-short-positive.json").read_text(
            encoding="utf-8"
        )
    )
    second_manifest = json.loads(
        (second_root / "sender" / "manifests" / "image-short-positive.json").read_text(
            encoding="utf-8"
        )
    )
    assert second_manifest["nonce"] != first_manifest["nonce"]


def test_existing_bundle_requires_explicit_overwrite(generated_bundle):
    root, _index, _include_video = generated_bundle
    with pytest.raises(FileExistsError, match="already exists"):
        generate_bundle(root, include_video=False)
