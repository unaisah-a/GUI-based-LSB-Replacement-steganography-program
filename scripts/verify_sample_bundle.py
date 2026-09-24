"""Verify a transferred T07 Party B folder without sender files or private keys.

python -m scripts.verify_sample_bundle samples/t07/party-b --report tmp/receiver.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.analysis.steganalysis import analyse
from app.crypto import key_manager
from app.stego import media
from app.utils import constants, payload_files
from app.verification.verifier import verify_media


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def local_file(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"Bundle file is missing or escapes its folder: {name}")
    return path


def verify_bundle(root, recovered=None):
    root = Path(root).resolve()
    index = json.loads(local_file(root, "case-index.json").read_text(encoding="utf-8"))
    if index["schema"] != "t07-v1" or not index["cases"]:
        raise ValueError("Unsupported or empty case index")
    # Check only the transferred tree. No original workspace or sender path is used.
    for path in root.rglob("*"):
        if path.is_file():
            data = local_file(root, str(path.relative_to(root))).read_bytes()
            if re.search(rb"-----BEGIN [^-\r\n]*PRIVATE KEY-----", data):
                raise ValueError("Private key material must not be present in Party B")
    inventory = json.loads(local_file(root, "checksums.json").read_text(encoding="utf-8"))
    for name, expected in inventory.items():
        if sha256(local_file(root, name).read_bytes()) != expected:
            raise ValueError(f"Transfer checksum mismatch: {name}")
    demo = json.loads(local_file(root, "demo-only-secrets.json").read_text(encoding="utf-8"))
    if recovered is not None:
        recovered = Path(recovered)
        recovered.mkdir(parents=True, exist_ok=False)
    results = []
    identifiers = set()
    for case in index["cases"]:
        identifier = case["id"]
        if not re.fullmatch(r"[a-z0-9_-]+", identifier) or identifier in identifiers:
            raise ValueError("Invalid or duplicate case identifier")
        identifiers.add(identifier)
        result = verify_media(
            local_file(root, case["media"]), local_file(root, case["manifest"]),
            str(local_file(root, case["public_key"])),
            start_secret=demo.get(case.get("start_secret")),
            passphrase=demo.get(case.get("passphrase")),
        )
        good = result.verdict in case["expected_verdicts"]
        actual_hash = None
        saved = None
        if result.verdict == constants.VERDICT_AUTHENTIC:
            actual_hash = sha256(result.message)
            good &= actual_hash == case.get("message_sha256")
            good &= len(result.message) == case.get("message_bytes")
            good &= payload_files.detect_payload_type(result.message).kind == case["payload_kind"]
            if case.get("expected_filename"):
                good &= payload_files.suggested_filename(result.record.metadata, result.message) == case["expected_filename"]
            good &= result.signature_valid is True and result.hash_valid is True
            corrected = result.details.get("error_correction", {}).get("bits_corrected", 0)
            good &= corrected >= case.get("minimum_corrections", 0)
            if good and recovered is not None:
                extension = payload_files.detect_payload_type(result.message).extension
                saved = identifier + extension
                (recovered / saved).write_bytes(result.message)
        else:
            good &= result.message is None
        results.append(dict(id=identifier, passed=bool(good), expected=case["expected_verdicts"],
                            actual=result.as_dict(), message_sha256=actual_hash, saved=saved))

    analysis = []
    for pair in index["analysis_pairs"]:
        for label, name in (("cover", pair["cover"]), ("stego", pair["stego"])):
            report = analyse(local_file(root, name), threshold=0.05,
                             reference=local_file(root, pair["cover"]) if label == "stego" else None)
            indicator = next(i for i in report.indicators
                             if i.name == "bit0_uniformity_chi_square" and i.channel_index == 0)
            if indicator.value is None:
                raise ValueError("Steganalysis fixture has insufficient data")
            analysis.append(dict(family=pair["family"], seed=pair["seed"], label=label,
                                 flagged=bool(indicator.value >= 0.05), report=report.as_dict()))
    capacities = []
    for case in index["capacity_cases"]:
        result = media.measure(local_file(root, case["cover"]), case["depth"],
                               case["start"], case["message_bytes"])
        capacities.append(dict(id=case["id"], passed=not result.report.payload_fits,
                               requested_message_bytes=case["message_bytes"],
                               maximum_raw_payload_bytes=result.report.max_payload_length))
    public = key_manager.load_public_key(str(local_file(root, "sender-public.pem")))
    return dict(schema="t07-receiver-report-v1", python=platform.python_version(),
                platform=platform.platform(), private_key_files=0,
                sender_fingerprint=key_manager.public_key_fingerprint(public),
                passed=all(c["passed"] for c in results + capacities), cases=results,
                capacity_checks=capacities,
                steganalysis=dict(rule="channel-0 bit0 uniformity p >= 0.05",
                                 false_positives=sum(c["flagged"] for c in analysis if c["label"] == "cover"),
                                 misses=sum(not c["flagged"] for c in analysis if c["label"] == "stego"),
                                 caveat="18 synthetic fixtures; not natural-media detection accuracy",
                                 cases=analysis))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--recovered", type=Path)
    args = parser.parse_args()
    if args.report.exists():
        parser.error("Report already exists; choose a new path")
    result = verify_bundle(args.bundle, args.recovered)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    print(json.dumps(dict(passed=result["passed"], cases=len(result["cases"]),
                          report=str(args.report))))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
