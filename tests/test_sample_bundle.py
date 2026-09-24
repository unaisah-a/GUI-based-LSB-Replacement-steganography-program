"""T07 transfer, fresh receiver process and failure handling."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.build_sample_bundle import build
from scripts.verify_sample_bundle import local_file, sha256, verify_bundle

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    output = tmp_path_factory.mktemp("t07") / "bundle"
    report = build(output)
    assert report["passed"]
    return output


def test_receiver_in_fresh_process_without_sender(bundle, tmp_path):
    isolated = tmp_path / "independent"
    shutil.copytree(ROOT / "app", isolated / "app", ignore=shutil.ignore_patterns("__pycache__"))
    (isolated / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts/verify_sample_bundle.py", isolated / "scripts/verify_sample_bundle.py")
    shutil.copytree(bundle / "party-b", isolated / "received")
    result = subprocess.run(
        [sys.executable, "-I", str(isolated / "scripts/verify_sample_bundle.py"),
         str(isolated / "received"), "--report", str(isolated / "result.json"),
         "--recovered", str(isolated / "recovered")], cwd=isolated, capture_output=True,
        text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((isolated / "result.json").read_text())
    assert report["passed"] and report["private_key_files"] == 0
    assert len(report["cases"]) == 27
    assert len(report["steganalysis"]["cases"]) == 18
    assert all(c["passed"] for c in report["capacity_checks"])
    assert not (isolated / "party-a").exists()
    rows = {r["id"]: r for r in report["cases"]}
    for identifier, verdict in (("image-payload-corruption", "SIGNATURE_INVALID"),
                                 ("audio-signature-corruption", "SIGNATURE_INVALID"),
                                 ("audio-repetition3-damage2", "SIGNATURE_INVALID")):
        assert rows[identifier]["actual"]["verdict"] == verdict
        assert rows[identifier]["saved"] is None
    for case, source in (("image-file", "payload.png"), ("audio-file", "payload.wav"),
                         ("image-short", "short.txt"), ("audio-long", "long.txt"),
                         ("image-confidential", "custom.txt")):
        saved = isolated / "recovered" / rows[case]["saved"]
        assert saved.read_bytes() == (bundle / "party-a/messages" / source).read_bytes()
    assert rows["audio-repetition3-damage1"]["actual"]["details"]["error_correction"]["bits_corrected"] > 0


def test_generator_refuses_existing_destination(bundle):
    index = (bundle / "party-b/case-index.json").read_bytes()
    with pytest.raises(FileExistsError):
        build(bundle)
    assert (bundle / "party-b/case-index.json").read_bytes() == index


def test_receiver_refuses_private_key_material(bundle, tmp_path):
    shutil.copytree(bundle / "party-b", tmp_path / "received")
    (tmp_path / "received/accidental.txt").write_text("-----BEGIN PRIVATE KEY-----\nnot a real key")
    with pytest.raises(ValueError, match="Private key"):
        verify_bundle(tmp_path / "received")


def test_receiver_detects_transfer_damage(bundle, tmp_path):
    shutil.copytree(bundle / "party-b", tmp_path / "received")
    path = tmp_path / "received/protected/image-short.png"
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_bundle(tmp_path / "received")


def test_receiver_rejects_unexpected_verdict_without_export(bundle, tmp_path):
    destination = tmp_path / "received"
    shutil.copytree(bundle / "party-b", destination)
    path = destination / "case-index.json"
    index = json.loads(path.read_text())
    index["cases"][0]["public_key"] = "unrelated-public.pem"
    path.write_text(json.dumps(index), encoding="utf-8")
    checksums = destination / "checksums.json"
    inventory = json.loads(checksums.read_text())
    inventory["case-index.json"] = sha256(path.read_bytes())
    checksums.write_text(json.dumps(inventory), encoding="utf-8")
    report = verify_bundle(destination, tmp_path / "recovered")
    assert not report["passed"]
    assert not report["cases"][0]["passed"]
    assert report["cases"][0]["saved"] is None
    assert not list((tmp_path / "recovered").glob("image-short.*"))


def test_bundle_paths_cannot_escape(tmp_path):
    root = tmp_path / "received"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("outside")
    with pytest.raises(ValueError, match="escapes"):
        local_file(root, "../outside.txt")
