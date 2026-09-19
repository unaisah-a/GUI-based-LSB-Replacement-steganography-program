"""Package the current source, docs, samples, and evidence, including untracked work.

No Git mutation or upload. A deterministic ZIP includes a per-file SHA-256 inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = ("README.md", "main.py", "requirements.txt", "pytest.ini", ".gitignore")
DIRECTORIES = {
    "app": {".py"}, "scripts": {".py"}, "tests": {".py"}, "docs": {".md"},
    "samples": {".md", ".txt", ".json", ".png", ".bmp", ".wav", ".mkv", ".bin", ".pem"},
    "evidence": {".md", ".txt", ".json", ".png"},
}
PUBLIC_DEMO_KEY = "samples/r11/receiver/demo-public-key.pem"


def build_package(root: Path, destination: Path) -> dict:
    root = root.resolve()
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError("Release destination already exists")
    paths = [root / name for name in ROOT_FILES]
    for folder, suffixes in DIRECTORIES.items():
        paths.extend(p for p in (root / folder).rglob("*")
                     if p.is_file() and p.suffix.lower() in suffixes
                     and "__pycache__" not in p.parts)
    members = {}
    for path in sorted(set(paths)):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Release inputs must be regular files inside the repository")
        name = path.relative_to(root).as_posix()
        if path.resolve() == destination:
            raise ValueError("Archive must be outside the selected input files")
        if path.suffix.lower() == ".pem" and name != PUBLIC_DEMO_KEY:
            raise ValueError("Only the named public demonstration PEM may be packaged")
        raw = path.read_bytes()
        if re.search(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", raw):
            # Source files contain marker literals used by the leak-check tests.
            if path.suffix.lower() != ".py":
                raise ValueError(f"Private key material found in {name}")
        members[name] = raw
    inventory = {
        "format": "SMIV-RELEASE-INVENTORY", "version": 1,
        "scope": "Current workspace snapshot, including untracked deliverables; excludes environments, Git metadata and local editor settings. Public demonstration secrets remain labelled in the sample bundle.",
        "files": [{"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                  for name, raw in sorted(members.items())],
    }
    members["RELEASE_INVENTORY.json"] = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, raw in sorted(members.items()):
                    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, raw)
    except FileExistsError:
        raise
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = build_package(PROJECT_ROOT, args.output)
    print(f"Packaged {len(inventory['files'])} files; SHA-256: "
          f"{hashlib.sha256(args.output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
