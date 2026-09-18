"""Verify every indexed case in an R11 receiver sample bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.crypto.encryption import decode_key
from app.crypto.key_manager import load_public_key_from_pem, public_key_fingerprint
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


def _inside(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty relative path")
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{label} escapes the receiver bundle")
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {relative}")
    return path


def verify_receiver_bundle(receiver_root: str | Path) -> dict[str, object]:
    root = Path(receiver_root).resolve()
    index = json.loads((root / "case-index.json").read_text(encoding="utf-8"))
    if index.get("format") != "SMIV-RECEIVER-BUNDLE" or index.get("version") != 1:
        raise ValueError("unsupported receiver bundle format")
    public_key = load_public_key_from_pem(_inside(root, index.get("public_key"), "public key"))
    fingerprint = public_key_fingerprint(public_key)
    if fingerprint != index.get("public_key_fingerprint"):
        raise ValueError("receiver public-key fingerprint does not match the case index")
    secrets_doc = json.loads(
        _inside(root, index.get("demo_secrets"), "demo secrets").read_text(encoding="utf-8")
    )
    start_secrets = secrets_doc.get("start_secrets", {})
    encryption_keys = secrets_doc.get("encryption_keys", {})
    results: list[dict[str, object]] = []
    for case in index.get("cases", []):
        if not isinstance(case, dict):
            raise ValueError("receiver case entries must be objects")
        start_ref = case.get("start_secret_ref")
        encryption_ref = case.get("encryption_key_ref")
        start_secret = None if start_ref is None else start_secrets.get(start_ref)
        encryption_key = (
            None
            if encryption_ref is None
            else decode_key(encryption_keys.get(encryption_ref, ""))
        )
        result = verify_media(
            _inside(root, case.get("media_path"), "case media"),
            _inside(root, case.get("manifest_path"), "case manifest"),
            public_key,
            start_secret=start_secret,
            encryption_key=encryption_key,
        )
        expected_message_path = case.get("expected_message_path")
        message_matches = None
        if expected_message_path is not None:
            expected_message = _inside(
                root, expected_message_path, "expected message"
            ).read_bytes()
            message_matches = result.message == expected_message
        expected_verdict = case.get("expected_verdict")
        passed = result.verdict.value == expected_verdict and message_matches is not False
        results.append(
            {
                "id": case.get("id"),
                "medium": case.get("medium"),
                "expected_verdict": expected_verdict,
                "actual_verdict": result.verdict.value,
                "message_matches": message_matches,
                "passed": passed,
                "summary": result.summary,
                "checks": [
                    {
                        "name": check.name,
                        "status": check.status.value,
                        "detail": check.detail,
                    }
                    for check in result.checks
                ],
            }
        )
    capacity = json.loads(
        _inside(root, index.get("capacity_case"), "capacity case").read_text(
            encoding="utf-8"
        )
    )
    capacity_passed = (
        capacity.get("expected") == "REJECTED_BEFORE_OUTPUT"
        and capacity.get("actual") == capacity.get("expected")
        and capacity.get("output_created") is False
    )
    return {
        "format": "SMIV-RECEIVER-VERIFICATION",
        "version": 1,
        "public_key_fingerprint": fingerprint,
        "all_passed": all(item["passed"] for item in results) and capacity_passed,
        "capacity_case_passed": capacity_passed,
        "cases": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receiver", type=Path)
    args = parser.parse_args(argv)
    report = verify_receiver_bundle(args.receiver)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
