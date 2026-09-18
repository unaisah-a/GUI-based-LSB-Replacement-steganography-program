"""Build the submission zip from the repository, and nothing else.

Run from the repository root::

    python scripts/package_submission.py
    python scripts/package_submission.py --output dist/P1-1_ACW1.zip

Only the paths in :data:`INCLUDED` are packaged. Within them, anything matching
:data:`EXCLUDED_NAMES` or :data:`EXCLUDED_PATHS` is left out: the virtual
environment, caches, the local demo key pair, and the local application logs. The
logs hold tracebacks from development runs with local paths in them; they are not
evidence. Pass ``--include-logs`` to package them anyway.

As a last check, the build refuses to finish if any packaged file contains a PEM
private key. The committed samples need only ``keys/public/samples_public.pem``, and
a marker creates their own key pair from *Keys → Generate demo key pair*.
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
    "tests",
    "docs",
    "samples",
    "scripts",
    "keys/public",
    "evidence",
    "assets",
    ".github",
    "main.py",
    "requirements.txt",
    "pyproject.toml",
    "pytest.ini",
    "README.md",
    ".gitignore",
)

#: Any path component with one of these names is skipped wherever it appears.
EXCLUDED_NAMES: frozenset[str] = frozenset(
    {
        ".venv",
        ".git",
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
        "keys/demo_private",
        # The public half of the local demo key pair. Its private half is not
        # packaged, so it could verify nothing and would only pre-fill the Verify tab
        # with a key the marker does not hold.
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
    excluded_paths = EXCLUDED_PATHS | (frozenset() if include_logs else {LOG_DIRECTORY})
    missing = [entry for entry in INCLUDED if not (root / entry).exists()]
    if missing:
        raise PackagingError(f"missing from the repository: {', '.join(missing)}")

    found: set[PurePosixPath] = set()
    for entry in INCLUDED:
        path = root / entry
        candidates: Iterator[Path] = (
            iter([path]) if path.is_file() else (p for p in path.rglob("*") if p.is_file())
        )
        for candidate in candidates:
            relative = PurePosixPath(candidate.relative_to(root).as_posix())
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
        help=f"also package {LOG_DIRECTORY}/ (local runs; off by default)",
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
