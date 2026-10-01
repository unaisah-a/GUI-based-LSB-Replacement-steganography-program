"""T07 transfer, fresh receiver process and failure handling."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.build_sample_bundle import build
from scripts.check_receiver_isolation import check
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
    assert len(report["cases"]) == 20
    assert "steganalysis" not in report
    assert report["schema"] == "t07-receiver-report-v2"
    assert len(list((isolated / "recovered").iterdir())) == 11
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
    for identifier in ("image-manifest-hash-mismatch", "encrypted-manifest-hash-mismatch"):
        row = rows[identifier]
        assert row["actual"]["verdict"] == "TAMPERED"
        assert row["actual"]["signature_valid"] is True
        assert row["actual"]["hash_valid"] is True
        assert row["actual"]["mismatched_fields"] == ["message_hash"]
        assert row["actual"]["hash_evidence"]["payload_matches_manifest"] == "No"
        assert row["actual"]["hash_evidence"]["manifest_matches_record"] == "No"
        assert row["saved"] is None


def test_generator_refuses_existing_destination(bundle):
    index = (bundle / "party-b/case-index.json").read_bytes()
    with pytest.raises(FileExistsError):
        build(bundle)
    assert (bundle / "party-b/case-index.json").read_bytes() == index


def test_version_two_manifests_and_portable_instructions(bundle):
    for path in bundle.rglob("*.manifest.json"):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        assert manifest["format_version"] == 2
        assert len(manifest["message_hash"]) == 64
        assert bytes.fromhex(manifest["message_hash"])
    index = json.loads((bundle / "party-b/case-index.json").read_text())
    assert index["manifest_version"] == 2
    assert all(len(case["expected_hash_checks"]) == 3 for case in index["cases"])
    for path in (bundle / "README.md", bundle / "party-b/README.md"):
        text = path.read_text(encoding="utf-8")
        assert "python -I scripts/verify_sample_bundle.py RECEIVED" in text
        assert "20 verification cases" in text
        assert "docs/" not in text and "IMPLEMENTATION_PLAN.md" not in text
    for path in bundle.rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY-----" not in path.read_bytes()


def test_receiver_checks_hash_status_expectations(bundle, tmp_path):
    destination = tmp_path / "received"
    shutil.copytree(bundle / "party-b", destination)
    path = destination / "case-index.json"
    index = json.loads(path.read_text())
    index["cases"][0]["expected_hash_checks"]["payload_matches_manifest"] = "No"
    path.write_text(json.dumps(index), encoding="utf-8")
    checksums = destination / "checksums.json"
    inventory = json.loads(checksums.read_text())
    inventory["case-index.json"] = sha256(path.read_bytes())
    checksums.write_text(json.dumps(inventory), encoding="utf-8")
    report = verify_bundle(destination, tmp_path / "recovered")
    assert not report["passed"]
    assert report["cases"][0]["actual"]["verdict"] == "AUTHENTIC"
    assert report["cases"][0]["saved"] is None


def test_isolation_command_records_results_and_refuses_overwrite(bundle, tmp_path):
    output = tmp_path / "isolated-command"
    report = check(bundle / "party-b", output)
    assert report["all_expectations_passed"]
    assert report["cases"] == 20 and report["capacity_checks"] == 2
    assert report["recovered_files"] == 11 and report["private_key_files"] == 0
    assert not (output / "party-a").exists()
    with pytest.raises(FileExistsError):
        check(bundle / "party-b", output)


def test_isolation_refuses_output_inside_receiver_bundle(bundle):
    output = bundle / "party-b" / "recursive-copy"
    with pytest.raises(ValueError, match="outside the receiver bundle"):
        check(bundle / "party-b", output)
    assert not output.exists()


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


def test_legacy_index_verifies_payloads_without_retired_analysis(bundle, tmp_path):
    receiver = tmp_path / "legacy"
    shutil.copytree(bundle / "party-b", receiver)
    path = receiver / "case-index.json"
    index = json.loads(path.read_text())
    index["schema"] = "t07-v1"
    index["analysis_pairs"] = [{"cover": "absent.png", "stego": "absent-stego.png"}]
    path.write_text(json.dumps(index), encoding="utf-8")
    inventory_path = receiver / "checksums.json"
    inventory = json.loads(inventory_path.read_text())
    inventory["case-index.json"] = sha256(path.read_bytes())
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    report = verify_bundle(receiver)
    assert report["passed"]
    assert len(report["cases"]) == 20
    assert "steganalysis" not in report
