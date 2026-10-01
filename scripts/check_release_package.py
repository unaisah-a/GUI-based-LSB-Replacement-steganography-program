"""Audit and extract a source archive, then check dependencies and app startup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def inspect_archive(archive_path: Path, source: Path) -> dict[str, str]:
    """Independently check member safety and byte identity before extraction."""
    hashes = {}
    inventory = set((source / "scripts/release_samples.txt").read_text().splitlines())
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise ValueError("Archive CRC check failed")
        for member in archive.infolist():
            name = member.filename
            path = PurePosixPath(name)
            if (name in hashes or path.is_absolute() or ".." in path.parts
                    or "\\" in name or ":" in name or path.as_posix() != name
                    or member.is_dir() or not path.parts):
                raise ValueError(f"Unsafe or duplicate archive member: {name}")
            if (any(p.startswith(".venv") or p in {".git", ".github", ".gitignore",
                                                  ".gitattributes", "AGENTS.md", "pytest.ini",
                                                  "__pycache__", ".pytest_cache",
                                                  ".hypothesis", ".ruff_cache"} for p in path.parts)
                    or name.startswith(("tests/", "keys/demo_private/", "keys/private/", "docs/"))
                    or (path.parts[0] == "samples" and (name not in inventory
                        or len(path.parts) < 3
                        or path.parts[1] not in {"original", "protected", "tampered"}))):
                raise ValueError(f"Excluded archive member: {name}")
            data = archive.read(member)
            if re.search(rb"(?m)^-----BEGIN [^-\r\n]*PRIVATE KEY-----", data):
                raise ValueError(f"Private key in archive: {name}")
            original = (source / path).resolve()
            if (not original.is_relative_to(source.resolve()) or not original.is_file()
                    or data != original.read_bytes()):
                raise ValueError(f"Archive differs from source: {name}")
            hashes[name] = hashlib.sha256(data).hexdigest()
        required = {"main.py", "scripts/release_samples.txt",
                    "scripts/probe_release.py", "README.md", "requirements.txt",
                    "samples/original/.gitkeep", "samples/protected/.gitkeep",
                    "samples/tampered/.gitkeep"} | inventory
        if not required <= hashes.keys():
            raise ValueError(f"Missing release members: {sorted(required - hashes.keys())}")
    return hashes


def check(archive_path: Path, output: Path, source: Path = ROOT) -> dict:
    archive_path, output = archive_path.resolve(), output.resolve()
    if output.exists():
        raise ValueError("Package check requires a new output directory")
    hashes = inspect_archive(archive_path, source)
    extracted = output / "extracted"
    extracted.mkdir(parents=True)
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    env.pop("PYTHONPATH", None)
    commands = [[sys.executable, "-I", str(extracted / "scripts/probe_release.py")]]
    has_index = (extracted / "evidence/case-index.json").is_file()
    if has_index:
        commands.append([sys.executable, "-I", str(extracted / "scripts/verify_submission_samples.py"),
                         "--root", str(extracted), "--report", str(output / "receiver.json"),
                         "--recovered", str(output / "recovered")])
    runs = []
    for command in commands:
        result = subprocess.run(command, cwd=extracted, env=env, capture_output=True,
                                text=True, timeout=120, check=True)
        runs.append({"command": command, "cwd": str(extracted), "returncode": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr})
    sample_files = [name for name in hashes
                    if name.startswith("samples/") and not name.endswith("/.gitkeep")]
    sample_validation = {
        "status": "PENDING",
        "reason": ("Sample verification has not been performed." if sample_files
                   else "New original, protected and tampered samples have not been added."),
        "files": len(sample_files),
    }
    submission_ready = False
    if has_index:
        receiver = json.loads((output / "receiver.json").read_text())
        if (not receiver["passed"] or len(receiver["cases"]) != 27
                or len(receiver["capacity_checks"]) != 2 or receiver["private_keys_used"]):
            raise ValueError("Extracted receiver acceptance failed")
        required_evidence = {"evidence/verification-results.csv", "evidence/logs/verification.json",
                             "evidence/logs/generation.json", "evidence/logs/quality-and-size.json",
                             "evidence/logs/attacks.json", "evidence/logs/gui-captures.json",
                             "evidence/logs/full-suite.xml", "evidence/logs/validation.json"}
        if not required_evidence <= hashes.keys():
            raise ValueError("Required submission evidence is missing")
        index = json.loads((extracted / "evidence/case-index.json").read_text())
        for case in index["cases"]:
            if case.get("screenshot") and f"evidence/{case['screenshot']}" not in hashes:
                raise ValueError("An indexed screenshot is missing")
        for name in ("capacity-image", "capacity-audio", "video-properties"):
            if f"evidence/screenshots/{name}.png" not in hashes:
                raise ValueError("A required capacity/video screenshot is missing")
        validation = json.loads((extracted / "evidence/logs/validation.json").read_text())
        if not validation.get("passed") or not validation.get("screenshots_visually_reviewed"):
            raise ValueError("Current validation evidence is incomplete")
        for name, expected in validation["source_sha256_lf"].items():
            # Retain the tested development-source hashes as evidence, although
            # tests and their configuration are intentionally not distributed.
            if name.startswith("tests/") or name == "pytest.ini":
                continue
            path = (extracted / name).resolve()
            if not path.is_relative_to(extracted.resolve()) or not path.is_file():
                raise ValueError("Unsafe or missing source snapshot member")
            if hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != expected:
                raise ValueError(f"Source differs from tested snapshot: {name}")
        suites = ET.parse(extracted / "evidence/logs/full-suite.xml").getroot()
        entries = [suites] if suites.tag == "testsuite" else list(suites.iter("testsuite"))
        if not entries or any(int(s.get("failures", 0)) or int(s.get("errors", 0)) for s in entries):
            raise ValueError("Full test suite evidence contains failures")
        if sum(int(s.get("tests", 0)) for s in entries) <= 0:
            raise ValueError("Full test suite evidence is empty")
        gui = json.loads((extracted / "evidence/logs/gui-captures.json").read_text())
        if len(gui["captures"]) != 15 or any(c["horizontal_overflow"] or c["vertical_overflow"] for c in gui["captures"]):
            raise ValueError("GUI captures are incomplete or clipped")
        generation = json.loads((extracted / "evidence/logs/generation.json").read_text())
        if len(generation["capacity_checks"]) != 2 or not all(
                c["rejected"] and not c["output_created"] for c in generation["capacity_checks"]):
            raise ValueError("Sender capacity rejection evidence is incomplete")
        quality = json.loads((extracted / "evidence/logs/quality-and-size.json").read_text())
        if len(quality) != 16 or not all(c["quality"]["within_distortion_bound"] for c in quality):
            raise ValueError("Quality evidence is incomplete or outside bounds")
        sample_validation = dict(status="PASS", cases=27, capacity_checks=2,
                                 private_keys_used=False, report=str(output / "receiver.json"))
        submission_ready = True
    report = {"archive": str(archive_path), "archive_sha256": hashlib.sha256(
        archive_path.read_bytes()).hexdigest(), "files": len(hashes),
        "source": str(source.resolve()), "extracted": str(extracted),
        "sample_validation": sample_validation, "submission_ready": submission_ready,
        "commands": runs, "member_sha256": hashes, "passed": True,
        "validation_scope": "Archive safety, source byte identity, dependencies, offscreen startup and indexed sample verification"}
    (output / "package-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = check(args.archive, args.output)
    print(json.dumps({key: report[key] for key in ("archive", "archive_sha256", "files", "passed",
                                                                  "sample_validation", "submission_ready")},
                     indent=2))


if __name__ == "__main__":
    main()
