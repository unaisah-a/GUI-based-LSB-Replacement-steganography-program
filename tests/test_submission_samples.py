"""Flat submission verification must detect altered inputs and avoid private keys."""
import hashlib
import json
from pathlib import Path

import pytest

from app.crypto import key_manager
from app.utils import constants
from app.verification.protect import protect_media
from scripts.generate_submission_samples import ORIGINALS, build
from scripts.verify_submission_samples import digest, local_file, verify

from conftest import make_cover, write_cover


@pytest.fixture(scope="module")
def signing_keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture()
def receiver(tmp_path, signing_keys):
    original = tmp_path / "samples/original"
    original.mkdir(parents=True)
    protected = tmp_path / "samples/protected"
    protected.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    cover = Path(write_cover(str(original), make_cover(128, 128, 3), "PNG", "cover"))
    message = original / "message.txt"
    message.write_bytes(b"Receiver-side regression")
    result = protect_media(cover, protected / "positive.png", message.read_bytes(), signing_keys[0],
                           media_id="test", lsb_depth=1, start_method=constants.START_METHOD_MANUAL,
                           manual_start_location=37)
    public = tmp_path / "keys/public/submission_public.pem"
    key_manager.save_public_key(signing_keys[1], public)
    def rel(p):
        return Path(p).relative_to(tmp_path).as_posix()
    index = dict(schema="submission-samples-v1", capacity_cases=[], cases=[dict(
        id="positive", media=rel(result.stego_path), manifest=rel(result.manifest_path),
        cover=rel(cover), payload=rel(message), public_key=rel(public),
        payload_sha256=hashlib.sha256(message.read_bytes()).hexdigest(),
        expected_verdicts=["AUTHENTIC"], expected_hash_checks=dict(
            payload_matches_manifest="Yes", manifest_matches_record="Yes", payload_matches_record="Yes"))])
    (evidence / "case-index.json").write_text(json.dumps(index))
    refresh_checksums(tmp_path)
    return tmp_path


def refresh_checksums(root):
    checks = {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*")
              if p.is_file() and p.name != "checksums.json"}
    (root / "evidence/checksums.json").write_text(json.dumps(checks))


def test_public_only_receiver_recovers_exact_payload(receiver, tmp_path_factory):
    recovered = tmp_path_factory.mktemp("recovered") / "new"
    report = verify(receiver, recovered)
    assert report["passed"] and report["private_keys_used"] is False
    assert (recovered / report["cases"][0]["saved"]).read_bytes() == b"Receiver-side regression"
    assert not (receiver / "keys/demo_private").exists()


def test_changed_media_fails_checksum_before_verification(receiver):
    path = receiver / "samples/protected/positive.png"
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="Checksum mismatch"):
        verify(receiver)


def test_wrong_expected_hash_fails_without_saving_recovery(receiver, tmp_path_factory):
    path = receiver / "evidence/case-index.json"
    index = json.loads(path.read_text())
    index["cases"][0]["payload_sha256"] = "00" * 32
    path.write_text(json.dumps(index))
    refresh_checksums(receiver)
    recovered = tmp_path_factory.mktemp("bad-recovery") / "new"
    assert verify(receiver, recovered)["passed"] is False
    assert list(recovered.iterdir()) == []


def test_missing_checksum_coverage_is_rejected(receiver):
    (receiver / "evidence/checksums.json").write_text("{}")
    with pytest.raises(ValueError, match="cover every"):
        verify(receiver)


def test_receiver_refuses_overwriting_inputs(receiver):
    with pytest.raises(ValueError, match="outside submission inputs"):
        verify(receiver, receiver / "samples/new")


def test_local_file_rejects_escape(receiver):
    with pytest.raises(ValueError, match="unsafe"):
        local_file(receiver, "../outside")


def test_generation_refuses_collision_without_modifying_it(tmp_path):
    path = tmp_path / "samples/protected/existing.png"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        build(tmp_path)
    assert path.read_bytes() == b"preserve"
    assert not (tmp_path / "keys").exists()


def test_key_mismatch_is_rejected_before_any_output(tmp_path, signing_keys):
    original = tmp_path / "samples/original"
    original.mkdir(parents=True)
    for name in ORIGINALS:
        (original / name).write_bytes(b"unchanged")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    key_manager.save_private_key(signing_keys[0], private)
    _, unrelated = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    key_manager.save_public_key(unrelated, public)
    with pytest.raises(ValueError, match="do not match"):
        build(tmp_path, private, public)
    assert not (tmp_path / "samples/protected").exists()
    assert {p.name for p in original.iterdir()} == set(ORIGINALS)
