"""Verify the flat submission samples using public keys only.

python -m scripts.verify_submission_samples --report tmp/sample-check.json
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.stego import media
from app.utils import payload_files
from app.verification.verifier import verify_media

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def local_file(root, name):
    if not isinstance(name, str):
        raise ValueError("Expected a relative file path")
    path = (root / name).resolve()
    if Path(name).is_absolute() or not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"Missing or unsafe sample path: {name}")
    return path


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def verify(root=ROOT, recovered=None):
    root = Path(root).resolve()
    index = json.loads(local_file(root, "evidence/case-index.json").read_text(encoding="utf-8"))
    checksums = json.loads(local_file(root, "evidence/checksums.json").read_text(encoding="utf-8"))
    if index.get("schema") != "submission-samples-v1" or not index.get("cases"):
        raise ValueError("Unsupported or empty sample index")
    referenced = {"evidence/case-index.json"}
    identifiers = set()
    for case in index["cases"]:
        if not re.fullmatch(r"[a-z0-9-]+", case["id"]) or case["id"] in identifiers:
            raise ValueError("Invalid or duplicate case identifier")
        identifiers.add(case["id"])
        referenced.update(case[field] for field in ("media", "manifest", "public_key", "cover", "payload"))
    for case in index["capacity_cases"]:
        referenced.update((case["cover"], case["payload"]))
    if not referenced <= checksums.keys():
        raise ValueError("Checksums do not cover every indexed input")
    for name, expected in checksums.items():
        path = local_file(root, name)
        if digest(path) != expected:
            raise ValueError(f"Checksum mismatch: {name}")
        if re.search(rb"(?m)^-----BEGIN [^-\r\n]*PRIVATE KEY-----", path.read_bytes()):
            raise ValueError(f"Private key in receiver inputs: {name}")
    if recovered is not None:
        recovered = Path(recovered).resolve()
        if any(recovered.is_relative_to(root / name) for name in ("samples", "keys", "evidence")):
            raise ValueError("Recovery output must be outside submission inputs")
        recovered.mkdir(parents=True, exist_ok=False)
    rows = []
    for case in index["cases"]:
        result = verify_media(
            local_file(root, case["media"]), local_file(root, case["manifest"]),
            str(local_file(root, case["public_key"])),
            start_secret=case.get("start_secret"), passphrase=case.get("passphrase"),
        )
        good = result.verdict in case["expected_verdicts"]
        hashes = result.hash_evidence.as_dict()
        good &= all(hashes.get(k) == v for k, v in case["expected_hash_checks"].items())
        actual_hash, saved = None, None
        corrections = result.details.get("error_correction", {}).get("bits_corrected", 0)
        if result.verdict == "AUTHENTIC":
            actual_hash = hashlib.sha256(result.message).hexdigest()
            expected_bytes = local_file(root, case["payload"]).read_bytes()
            good &= result.message == expected_bytes
            good &= actual_hash == case["payload_sha256"]
            good &= result.signature_valid is True and result.hash_valid is True
            good &= corrections >= case.get("minimum_corrections", 0)
            if case.get("file_payload"):
                good &= payload_files.suggested_filename(result.record.metadata, result.message) == Path(case["payload"]).name
            if good and recovered is not None:
                saved = case["id"] + payload_files.detect_payload_type(result.message).extension
                (recovered / saved).write_bytes(result.message)
        else:
            good &= result.message is None
        rows.append(dict(id=case["id"], passed=bool(good), expected=case["expected_verdicts"],
                         actual=result.as_dict(), payload_sha256=actual_hash,
                         recovered_bytes_match=(result.message == local_file(root, case["payload"]).read_bytes()
                                                if result.verdict == "AUTHENTIC" else None),
                         corrections=corrections, saved=saved))
    capacities = []
    for case in index["capacity_cases"]:
        measured = media.measure(local_file(root, case["cover"]), case["depth"], case["start"],
                                 local_file(root, case["payload"]).stat().st_size)
        capacities.append(dict(id=case["id"], passed=not measured.payload_fits,
                               message_bytes=local_file(root, case["payload"]).stat().st_size,
                               maximum_raw_payload_bytes=measured.max_payload_length,
                               note="Receiver capacity check; sender rejection is recorded in generation.json"))
    return dict(schema="submission-verification-v1", python=platform.python_version(),
                platform=platform.platform(), passed=all(r["passed"] for r in rows + capacities),
                cases=rows, capacity_checks=capacities, private_keys_used=False)


def write_csv(path, report, index):
    cases = {case["id"]: case for case in index["cases"]}
    fields = ["id", "media", "manifest", "public_key", "expected", "actual", "passed",
              "signature_valid", "hash_valid", "payload_matches_manifest", "manifest_matches_record",
              "payload_matches_record", "recovered_bytes_match", "corrections", "screenshot", "log"]
    with Path(path).open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["cases"]:
            case, actual = cases[row["id"]], row["actual"]
            writer.writerow(dict(id=row["id"], media=case["media"], manifest=case["manifest"],
                                 public_key=case["public_key"], expected=" / ".join(row["expected"]),
                                 actual=actual["verdict"], passed=row["passed"],
                                 signature_valid=actual["signature_valid"], hash_valid=actual["hash_valid"],
                                 **{k: actual["hash_evidence"][k] for k in fields[9:12]},
                                 recovered_bytes_match=row["recovered_bytes_match"], corrections=row["corrections"],
                                 screenshot=case.get("screenshot", ""), log="logs/verification.json"))
        for row in report["capacity_checks"]:
            writer.writerow(dict(id=row["id"], expected="Capacity rejection", actual="Does not fit",
                                 passed=row["passed"], screenshot=f"screenshots/{row['id']}.png",
                                 log="logs/generation.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--recovered", type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Report already exists; choose a new path")
    report = verify(args.root, args.recovered)
    write_json(args.report, report)
    print(json.dumps(dict(passed=report["passed"], cases=len(report["cases"]),
                          capacity_checks=len(report["capacity_checks"]), private_keys_used=False)))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
