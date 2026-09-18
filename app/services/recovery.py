"""Application orchestration for safe sidecar-assisted restoration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from app.robustness.recovery import (
    RecoveryInspection,
    RecoveryResult,
    inspect_recovery_sidecar,
    restore_original,
)
from app.services.operations import OperationControl


@dataclass(frozen=True)
class RecoveryWorkflowResult:
    recovery: RecoveryResult
    inspection: RecoveryInspection


def restore_recovery_bundle(
    protected_path: str | Path,
    sidecar_path: str | Path,
    output_path: str | Path,
    key: bytes,
    *,
    overwrite: bool = False,
    operation: OperationControl | None = None,
) -> RecoveryWorkflowResult:
    """Inspect, authenticate, restore, and independently re-hash an original file."""
    if operation is not None:
        operation.checkpoint("Inspecting encrypted recovery sidecar…")
    inspection = inspect_recovery_sidecar(sidecar_path)
    if operation is not None:
        operation.checkpoint("Authenticating sidecar and protected-file binding…")
    recovery = restore_original(
        protected_path,
        sidecar_path,
        output_path,
        key,
        overwrite=overwrite,
    )
    restored_hash = hashlib.sha256(Path(recovery.output_path).read_bytes()).hexdigest()
    if restored_hash != recovery.original_sha256:
        raise RuntimeError("restored output changed after its verified atomic write")
    return RecoveryWorkflowResult(recovery, inspection)
