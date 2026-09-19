"""Validate the collected R12 artifacts and write their release summary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_validation_summary(
    evidence_root: str | os.PathLike[str],
    receiver_root: str | os.PathLike[str],
    *,
    screenshots_visually_reviewed: bool = False,
) -> dict[str, object]:
    evidence = Path(evidence_root).resolve()
    receiver = Path(receiver_root).resolve()
    release_path = evidence / "results" / "r12-release-audit.json"
    desktop_path = evidence / "results" / "r12-desktop-audit.json"
    suite_path = evidence / "logs" / "r12-full-suite.txt"
    install_path = evidence / "logs" / "r12-clean-install.txt"
    smoke_path = evidence / "logs" / "r12-main-smoke.txt"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    desktop = json.loads(desktop_path.read_text(encoding="utf-8"))
    suite_text = suite_path.read_text(encoding="utf-8")
    install_text = install_path.read_text(encoding="utf-8")
    smoke_text = smoke_path.read_text(encoding="utf-8")
    match = re.search(r"(?m)^(\d+) passed in ([0-9.]+)s", suite_text)
    if match is None:
        raise ValueError("full-suite log does not contain a passing pytest summary")
    if "No broken requirements found." not in install_text:
        raise ValueError("clean-install log does not contain a successful pip check")
    if "Application startup smoke check passed." not in smoke_text:
        raise ValueError("startup smoke log does not contain a successful result")
    if not release["receiver_bundle"]["all_passed"]:
        raise ValueError("receiver release audit did not pass")
    if not release["optional_tool_absence"]["passed"]:
        raise ValueError("optional-tool absence audit did not pass")
    if not desktop["all_passed"] or desktop["qt_platform"] == "offscreen":
        raise ValueError("native desktop audit did not pass on a native Qt platform")

    artifact_paths = [release_path, desktop_path, suite_path, install_path, smoke_path]
    screenshot_directory = evidence / "screenshots"
    for item in desktop["screenshots"]:
        screenshot = screenshot_directory / item["file"]
        if not screenshot.is_file() or _sha256(screenshot) != item["sha256"]:
            raise ValueError(f"desktop screenshot does not match its hash: {item['file']}")
        artifact_paths.append(screenshot)

    secrets_document = json.loads(
        (receiver / "demo-only-secrets.json").read_text(encoding="utf-8")
    )
    secret_values = [
        *secrets_document["start_secrets"].values(),
        *secrets_document["encryption_keys"].values(),
    ]
    text_evidence = "\n".join(
        path.read_text(encoding="utf-8")
        for path in artifact_paths
        if path.suffix.lower() in {".json", ".txt"}
    )
    if any(value in text_evidence for value in secret_values):
        raise ValueError("release evidence contains a demonstration secret value")
    if "BEGIN PRIVATE KEY" in text_evidence or "BEGIN RSA PRIVATE KEY" in text_evidence:
        raise ValueError("release evidence contains private-key material")

    return {
        "format": "SMIV-RELEASE-VALIDATION",
        "version": 1,
        "all_passed": True,
        "clean_environment": {
            "python": release["environment"]["python"],
            "requirements_sha256": release["requirements_sha256"],
            "pip_check_passed": True,
            "main_startup_passed": True,
        },
        "test_suite": {
            "passed": int(match.group(1)),
            "duration_seconds": float(match.group(2)),
        },
        "receiver_cases": len(release["receiver_bundle"]["cases"]),
        "receiver_all_passed": True,
        "optional_tool_absence_passed": True,
        "desktop": {
            "qt_platform": desktop["qt_platform"],
            "cases": len(desktop["cases"]),
            "all_passed": True,
            "screenshots_visually_reviewed": screenshots_visually_reviewed,
        },
        "artifacts": [
            {
                "path": path.relative_to(evidence).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in artifact_paths
        ],
        "contains_private_key_material": False,
        "contains_secret_values": False,
    }


def write_summary(summary: dict[str, object], destination: str | Path) -> None:
    output = Path(destination).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8")
    handle, temporary = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=PROJECT_ROOT / "evidence")
    parser.add_argument(
        "--receiver", type=Path, default=PROJECT_ROOT / "samples" / "r11" / "receiver"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "evidence" / "results" / "r12-validation-summary.json",
    )
    parser.add_argument(
        "--screenshots-visually-reviewed",
        action="store_true",
        help="Record that a person or reviewing agent inspected all three current PNGs.",
    )
    args = parser.parse_args(argv)
    summary = build_validation_summary(
        args.evidence,
        args.receiver,
        screenshots_visually_reviewed=args.screenshots_visually_reviewed,
    )
    write_summary(summary, args.output)
    print(
        f"Release validation passed: {summary['test_suite']['passed']} tests, "
        f"{summary['receiver_cases']} receiver cases, "
        f"Qt {summary['desktop']['qt_platform']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
