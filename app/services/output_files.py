"""Safe writers for explicitly exported GUI data."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping


def _atomic_write(path: Path, data: bytes, overwrite: bool) -> None:
    destination = path.resolve()
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {destination.parent}")
    if destination.is_dir():
        raise IsADirectoryError(f"output path is a directory: {destination.name}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {destination.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def save_recovered_payload(
    path: str | Path, data: bytes, *, overwrite: bool = False
) -> None:
    if not isinstance(data, bytes):
        raise TypeError("recovered payload must be bytes")
    _atomic_write(Path(path), data, overwrite)


def export_secret_bundle(
    path: str | Path, secrets: Mapping[str, str], *, overwrite: bool = False
) -> None:
    """Export only explicitly selected secrets, separate from the manifest."""
    cleaned = {name: value for name, value in secrets.items() if value}
    if not cleaned:
        raise ValueError("there are no configured secrets to export")
    if not all(isinstance(name, str) and isinstance(value, str) for name, value in cleaned.items()):
        raise TypeError("secret names and values must be text")
    document = {
        "format": "SMIV-SECRET-BUNDLE",
        "version": 1,
        "warning": "Keep this file private and transfer it separately from the manifest.",
        "secrets": cleaned,
    }
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(Path(path), encoded, overwrite)
