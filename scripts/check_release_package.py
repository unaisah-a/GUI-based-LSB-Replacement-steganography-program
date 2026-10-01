"""Audit and extract a source archive, then check dependencies and app startup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
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
            if (any(p.startswith(".venv") or p in {".git", "__pycache__", ".pytest_cache",
                                                  ".hypothesis", ".ruff_cache"} for p in path.parts)
                    or name.startswith(("keys/demo_private/", "keys/private/", "docs/"))
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
        required = {"main.py", "AGENTS.md", ".gitattributes", "scripts/release_samples.txt",
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
    report = {"archive": str(archive_path), "archive_sha256": hashlib.sha256(
        archive_path.read_bytes()).hexdigest(), "files": len(hashes),
        "source": str(source.resolve()), "extracted": str(extracted),
        "sample_validation": sample_validation, "submission_ready": False,
        "commands": runs, "member_sha256": hashes, "passed": True,
        "validation_scope": "Archive safety, source byte identity, dependencies and offscreen startup"}
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
