"""Stage and publish a media/manifest pair with exception rollback.

Adapted from gin's bundle-publication approach, within Tristan's sender layer.
Each rename is atomic, but two files are not a filesystem transaction: concurrent
readers can briefly see a mixed pair, and power loss/process termination is not
recoverable automatically. Do not run concurrent writers against the same pair.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.crypto.errors import ManifestError
from app.stego import paths
from app.stego.errors import FileError, ValidationError
from app.utils.logging_utils import get_logger

_log = get_logger(__name__)


class PublicationError(FileError):
    """Publication failed; recovery_paths identifies backups needing manual recovery."""

    def __init__(self, message: str, recovery_paths: tuple[Path, ...] = ()):
        super().__init__(message)
        self.recovery_paths = recovery_paths


def validate_bundle(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    overwrite: bool,
) -> None:
    """Reject aliases and invalid destinations before encoding or signing."""
    if not isinstance(overwrite, bool):
        raise ValidationError("overwrite must be a boolean")
    paths.assert_distinct_paths(source, output)
    paths.assert_distinct_paths(source, manifest)
    paths.assert_distinct_paths(output, manifest)
    for target in (output, manifest):
        if Path(target).is_symlink():
            raise ValidationError("output destinations must not be symbolic links")
    paths.check_output_writable(output, overwrite)
    if os.path.lexists(manifest) and not overwrite:
        raise ManifestError("manifest path is already occupied; choose another path or enable overwrite")
    paths.check_output_writable(manifest, overwrite)


def _temporary(target: Path, kind: str) -> Path:
    fd, name = tempfile.mkstemp(
        prefix=f".{target.name}.{kind}-", suffix=target.suffix, dir=target.parent
    )
    os.close(fd)
    return Path(name)


def _replace(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _install(source: Path, destination: Path, overwrite: bool) -> None:
    if overwrite:
        _replace(source, destination)
    elif os.name == "nt":
        # Windows rename refuses an existing destination (including FAT volumes).
        os.rename(source, destination)
    else:
        # Atomic create-if-absent: a file appearing since validation is not clobbered.
        # Staging is in the same directory/filesystem. Cleanup removes the stage link.
        os.link(source, destination)


def _cleanup(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        _log.warning("could not clean temporary file %s", path.name)


def _publish(staged: dict[Path, Path], overwrite: bool) -> None:
    backups: dict[Path, Path] = {}
    published: list[Path] = []
    retained: set[Path] = set()
    try:
        # Copy backups before replacing anything; a backup failure leaves originals.
        for target in staged:
            if target.exists():
                if not overwrite:
                    raise FileExistsError(target.name)
                backup = _temporary(target, "backup")
                backups[target] = backup
                shutil.copy2(target, backup)
        for target, stage in staged.items():
            _install(stage, target, overwrite)
            published.append(target)
    except BaseException as exc:
        rollback_failed = False
        for target in reversed(published):
            try:
                if target in backups:
                    _replace(backups[target], target)
                else:
                    target.unlink(missing_ok=True)
            except OSError:
                rollback_failed = True
                if target in backups:
                    retained.add(backups[target])
        if rollback_failed:
            names = ", ".join(path.name for path in sorted(retained))
            raise PublicationError(
                "bundle publication failed and rollback was incomplete; "
                f"retained recovery backups: {names or 'none; remove incomplete new outputs manually'}",
                tuple(sorted(retained)),
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise PublicationError("bundle publication failed; previous outputs were restored") from exc
    finally:
        for backup in backups.values():
            if backup not in retained:
                _cleanup(backup)


@contextmanager
def staged_bundle(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    *,
    overwrite: bool,
) -> Iterator[tuple[str, str]]:
    """Yield isolated writable paths; publish both only after successful staging."""
    validate_bundle(source, output, manifest, overwrite)
    staged: dict[Path, Path] = {}
    try:
        for target in (Path(output).absolute(), Path(manifest).absolute()):
            staged[target] = _temporary(target, "stage")
        yield tuple(str(stage) for stage in staged.values())
        validate_bundle(source, output, manifest, overwrite)
        _publish(staged, overwrite)
    finally:
        for stage in staged.values():
            _cleanup(stage)
