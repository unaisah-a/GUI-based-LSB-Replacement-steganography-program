"""Build the submission zip from the repository, and nothing else.

Run from the repository root::

    python scripts/package_submission.py
    python scripts/package_submission.py --output dist/P1-1_ACW1.zip

Only the paths in :data:`INCLUDED` are packaged. Samples must also appear in
``scripts/release_samples.txt``; local practice outputs are not shipped. Within
the included paths, anything matching
:data:`EXCLUDED_NAMES` or :data:`EXCLUDED_PATHS` is left out: the virtual
environment, caches, the local demo key pair, and the local application logs. The
runtime application log holds local diagnostics. Pass ``--include-logs`` to package
it anyway. Fresh verification reports under evidence/logs are always included.

As a last check, the build refuses to finish if any packaged file contains a PEM
private key. Archive creation alone does not establish submission readiness;
run the release checker to validate the packaged samples and application.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

#: Directories and files packaged, relative to the repository root.
INCLUDED: tuple[str, ...] = (
    "app",
    "samples",
    "scripts",
    "keys/public",
    "evidence",
    "assets",
    "main.py",
    "requirements.txt",
    "pyproject.toml",
    "README.md",
)

#: Any path component with one of these names is skipped wherever it appears.
EXCLUDED_NAMES: frozenset[str] = frozenset(
    {
        ".venv",
        ".git",
        ".github",
        ".gitignore",
        ".gitattributes",
        "AGENTS.md",
        "pytest.ini",
        ".hypothesis",
        ".ruff_cache",
        ".pytest_cache",
        "__pycache__",
        ".pytest_out.txt",
        ".coverage",
        "coverage.xml",
        "htmlcov",
    }
)

#: Specific paths skipped, relative to the root, in POSIX form.
EXCLUDED_PATHS: frozenset[str] = frozenset(
    {
        "tests",
        "keys/demo_private",
        # The local default is copied to submission_public.pem for receiver use.
        "keys/public/demo_public.pem",
    }
)

LOG_DIRECTORY = "evidence/logs"

DEFAULT_OUTPUT = REPOSITORY_ROOT / "dist" / "INF2005_ACW1_submission.zip"

#: A PEM private key header at the start of a line, in any of the PEM key formats.
_PRIVATE_KEY_HEADER = re.compile(rb"(?m)^-----BEGIN [A-Z ]*PRIVATE KEY-----")


class PackagingError(Exception):
    """The submission could not be built safely."""


def _excluded(relative: PurePosixPath, excluded_paths: frozenset[str]) -> bool:
    if any(part in EXCLUDED_NAMES for part in relative.parts):
        return True
    if relative.suffix == ".pyc":
        return True
    text = relative.as_posix()
    return any(text == path or text.startswith(path + "/") for path in excluded_paths)


def collect(root: Path, *, include_logs: bool = False) -> list[PurePosixPath]:
    """Every file to package, relative to *root*, in a stable order.

    :raises PackagingError: an included path does not exist.
    """
    excluded_paths = EXCLUDED_PATHS | (frozenset() if include_logs else {f"{LOG_DIRECTORY}/application.log"})
    missing = [entry for entry in INCLUDED if not (root / entry).exists()]
    if missing:
        raise PackagingError(f"missing from the repository: {', '.join(missing)}")

    inventory = root / "scripts/release_samples.txt"
    if not inventory.is_file():
        raise PackagingError("missing sample inventory: scripts/release_samples.txt")
    samples = set(inventory.read_text(encoding="utf-8").splitlines())
    for name in samples:
        path = PurePosixPath(name)
        if (len(path.parts) < 3 or path.parts[0] != "samples"
                or path.parts[1] not in {"original", "protected", "tampered"}
                or ".." in path.parts or "\\" in name
                or ":" in name or path.as_posix() != name
                or not (root / path).is_file()
                or not (root / path).resolve().is_relative_to((root / "samples").resolve())):
            raise PackagingError(f"invalid or missing sample inventory entry: {name}")

    found: set[PurePosixPath] = set()
    for entry in INCLUDED:
        path = root / entry
        candidates: Iterator[Path] = (
            iter([path]) if path.is_file() else (p for p in path.rglob("*") if p.is_file())
        )
        for candidate in candidates:
            relative = PurePosixPath(candidate.relative_to(root).as_posix())
            if relative.parts[0] == "samples" and relative.as_posix() not in samples:
                continue
            if not _excluded(relative, excluded_paths):
                found.add(relative)
    return sorted(found)


def check_no_private_keys(root: Path, files: list[PurePosixPath]) -> None:
    """Refuse to package any file holding a PEM private key."""
    offenders = [
        str(relative)
        for relative in files
        if _PRIVATE_KEY_HEADER.search((root / relative).read_bytes())
    ]
    if offenders:
        raise PackagingError(
            f"refusing to package private key material: {', '.join(offenders)}"
        )


def build(
    output: Path, *, root: Path = REPOSITORY_ROOT, include_logs: bool = False
) -> tuple[int, int]:
    """Write the zip to *output* and return ``(file count, size in bytes)``."""
    files = collect(root, include_logs=include_logs)
    check_no_private_keys(root, files)

    output = output.resolve()
    if any(output.is_relative_to((root / entry).resolve()) for entry in INCLUDED):
        raise PackagingError(
            f"the output {output} lies inside a packaged directory and would include "
            f"itself"
        )
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary = output.with_suffix(output.suffix + ".partial")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            archive.write(root / relative, arcname=relative.as_posix())
    os.replace(temporary, output)
    return len(files), output.stat().st_size


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the zip"
    )
    parser.add_argument(
        "--include-logs",
        action="store_true",
        help=f"also package {LOG_DIRECTORY}/application.log (off by default)",
    )
    arguments = parser.parse_args(argv)

    try:
        count, size = build(arguments.output, include_logs=arguments.include_logs)
    except PackagingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {arguments.output}")
    print(f"{count:,} files, {size:,} bytes ({size / (1024 * 1024):.2f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
