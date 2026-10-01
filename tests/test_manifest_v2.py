"""H02: required plaintext hashes, strict parsing and real published sidecars."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.crypto import key_manager
from app.crypto import manifest as manifest_module
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.envelope import ErrorCorrectionParameters, VerificationRecord
from app.crypto.errors import ManifestError
from app.stego import image_io
from app.utils import constants
from app.verification import verifier
from app.verification.protect import protect_media

from conftest import (
    make_audio,
    make_cover,
    make_video_frames,
    write_audio_file,
    write_cover,
    write_video_file,
)

INVALID_HASHES = [
    None, True, 42, 1.5, [], {}, "", "a" * 63, "a" * 65, "g" * 64,
    "ab" * 31 + "  ", "ab" * 31 + "\r\n", "\t" * 64, "\uff21" * 64,
]


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture
def manifest():
    record = VerificationRecord(
        media_id="H02", media_type=constants.MEDIA_IMAGE,
        timestamp="2026-10-01T00:00:00+00:00", nonce_hex="0f" * 16,
        message_hash=hashlib.sha256(b"original bytes").hexdigest(),
        message_length=14, lsb_depth=3,
        start_method=constants.START_METHOD_MANUAL, start_location=0,
    )
    return manifest_module.Manifest.from_record(
        record, envelope_length=1802, container_format=constants.CONTAINER_PNG,
        resolved_start_location=0,
    )


def test_version_two_and_hash_survive_json_round_trip(manifest, tmp_path):
    path = manifest_module.write_manifest(manifest, tmp_path / "manifest.json")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["format_version"] == 2
    assert data["message_hash"] == hashlib.sha256(b"original bytes").hexdigest()
    assert manifest_module.read_manifest(path) == manifest


def test_uppercase_is_normalised_when_parsed_and_written(manifest, tmp_path):
    data = manifest.as_dict()
    data["message_hash"] = data["message_hash"].upper()
    parsed = manifest_module.Manifest.from_dict(data)
    assert parsed.message_hash == manifest.message_hash
    path = manifest_module.write_manifest(parsed, tmp_path / "manifest.json")
    assert json.loads(Path(path).read_text())["message_hash"] == manifest.message_hash
    assert replace(manifest, message_hash=data["message_hash"]) == manifest


@pytest.mark.parametrize("value", INVALID_HASHES)
def test_invalid_hash_is_rejected_in_parser_and_constructor(manifest, value):
    data = manifest.as_dict()
    data["message_hash"] = value
    with pytest.raises(ManifestError, match=r"message_hash.*Regenerate"):
        manifest_module.Manifest.from_dict(data)
    with pytest.raises(ManifestError, match=r"message_hash.*Regenerate"):
        replace(manifest, message_hash=value)


def test_missing_hash_is_not_inferred_from_another_digest(manifest):
    data = manifest.as_dict()
    del data["message_hash"]
    data["stego_sha256"] = manifest.message_hash
    with pytest.raises(ManifestError, match=r"message_hash.*Regenerate"):
        manifest_module.Manifest.from_dict(data)


@pytest.mark.parametrize("include_hash", [False, True])
def test_version_one_is_rejected_even_with_a_hash(manifest, include_hash):
    data = manifest.as_dict()
    data["format_version"] = 1
    if not include_hash:
        del data["message_hash"]
    with pytest.raises(ManifestError, match=r"format version 1.*Regenerate"):
        manifest_module.Manifest.from_dict(data)


@pytest.mark.parametrize("change", [
    {"format_version": 1}, {"remove_hash": True},
    *({"message_hash": value} for value in INVALID_HASHES),
])
def test_invalid_manifest_cannot_reach_media_processing(
    manifest, change, tmp_path, keys, monkeypatch,
):
    data = manifest.as_dict()
    if change.get("remove_hash"):
        del data["message_hash"]
    else:
        data.update(change)
    path = tmp_path / "invalid.manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    def unexpected(*args, **kwargs):
        pytest.fail("invalid manifest reached media processing")

    monkeypatch.setattr(verifier.media, "measure", unexpected)
    monkeypatch.setattr(verifier.media, "extract", unexpected)
    outcome = verifier.verify_media(tmp_path / "absent.png", path, keys[1])
    assert outcome.verdict == constants.VERDICT_CANNOT_VERIFY
    assert outcome.details["stage"] == "manifest"
    assert "Regenerate the protected output and matching manifest" in outcome.reason
    assert outcome.message is None


@pytest.mark.parametrize("medium", ["image", "audio", "video"])
@pytest.mark.parametrize("payload_kind", ["text", "file"])
@pytest.mark.parametrize("encrypted,repeated", [
    (False, False), (True, False), (False, True), (True, True),
])
def test_protection_publishes_original_byte_hash(
    medium, payload_kind, encrypted, repeated, tmp_path, keys,
):
    if medium == "image":
        cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")
    elif medium == "audio":
        cover = write_audio_file(str(tmp_path), make_audio(20_000))
    else:
        cover = write_video_file(str(tmp_path), make_video_frames())

    metadata = None
    if payload_kind == "file":
        source = tmp_path / "payload.bin"
        source.write_bytes(bytes(range(256)))
        message = source.read_bytes()
        metadata = {"payload_kind": "file", "payload_name": source.name}
    else:
        message = "Original text: caf\u00e9\r\nwith trailing spaces  ".encode()

    passphrase = "H02 test passphrase" if encrypted else None
    ecc = ErrorCorrectionParameters(constants.ECC_REPETITION, 3) if repeated else None
    result = protect_media(
        cover, tmp_path / f"stego{Path(cover).suffix}", message, keys[0],
        media_id="H02", lsb_depth=4, start_method=constants.START_METHOD_MANUAL,
        manual_start_location=0, passphrase=passphrase, ecc=ecc, metadata=metadata,
        scrypt_n=MIN_SCRYPT_N, scrypt_r=8, scrypt_p=1,
    )
    data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
    digest = hashlib.sha256(message).hexdigest()
    assert data["format_version"] == 2
    assert data["message_hash"] == result.record.message_hash == digest
    assert manifest_module.read_manifest(result.manifest_path) == result.manifest
    assert data["stego_sha256"] == hashlib.sha256(Path(result.stego_path).read_bytes()).hexdigest()
    assert data["stego_sha256"] != digest
    outcome = verifier.verify_media(
        result.stego_path, result.manifest_path, keys[1], passphrase=passphrase,
    )
    assert outcome.verdict == constants.VERDICT_AUTHENTIC
    assert outcome.message == message
    evidence = outcome.hash_evidence
    assert evidence.manifest_hash == evidence.signed_record_hash == evidence.computed_hash == digest
    assert evidence.payload_matches_manifest is True
    assert evidence.manifest_matches_record is True
    assert evidence.payload_matches_record is True


def test_legacy_sample_is_rejected_without_modification(keys, tmp_path):
    cover = write_cover(str(tmp_path), make_cover(128, 128, 3), "PNG", "cover")
    result = protect_media(
        cover, tmp_path / "protected.png", b"legacy regression", keys[0],
        media_id="legacy", start_method=constants.START_METHOD_MANUAL,
        manual_start_location=0, lsb_depth=2,
    )
    stego = Path(result.stego_path)
    manifest_path = Path(result.manifest_path)
    data = json.loads(manifest_path.read_text())
    data["format_version"] = 1
    data.pop("message_hash")
    manifest_path.write_text(json.dumps(data))
    before = (stego.read_bytes(), manifest_path.read_bytes())
    outcome = verifier.verify_media(stego, manifest_path, keys[1])
    assert outcome.verdict == constants.VERDICT_CANNOT_VERIFY
    assert outcome.details["stage"] == "manifest"
    assert "format version 1" in outcome.reason
    assert "Regenerate" in outcome.reason
    assert (stego.read_bytes(), manifest_path.read_bytes()) == before
