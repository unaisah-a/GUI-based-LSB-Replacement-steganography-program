"""End-to-end protect/sign/embed workflow for image and audio media."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field, is_dataclass, replace
from pathlib import Path
from typing import Any

from app.crypto.key_manager import public_key_fingerprint
from app.crypto.manifest import Manifest, save_manifest
from app.crypto.payload import BuiltEnvelope, build_envelope
from app.crypto.start_location import derive_start_location
from app.robustness.recovery import (
    MAX_ORIGINAL_BYTES,
    RecoveryResult,
    create_recovery_sidecar,
)
from app.robustness.redundancy import encode_repetition3
from app.services.media import CarrierCapacity, CarrierInfo, inspect_carrier
from app.services.operations import OperationControl
from app.services.size_preservation import (
    SizePreservationResult,
    export_size_preservation_result,
    preserve_protected_size,
)
from app.stego.audio_stego import embed_audio_lsb
from app.stego.image_stego import embed_image
from app.stego.video_stego import embed_video


@dataclass(frozen=True)
class ProtectionOptions:
    media_id: str
    lsb_count: int = 1
    start_method: str = "hmac-sha256"
    start_secret: str | bytes | None = None
    start_location: int | None = None
    content_type: str = "text/plain; charset=utf-8"
    metadata: dict[str, Any] = field(default_factory=dict)
    encryption_key: bytes | None = None
    robustness: str = "none"
    preserve_size: bool = False
    size_report_path: str | Path | None = None
    recovery_key: bytes | None = None
    recovery_path: str | Path | None = None
    overwrite: bool = False
    video_frame_index: int = 0
    operation: OperationControl | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ProtectionResult:
    output_path: str
    manifest_path: str
    media_type: str
    start_location: int
    payload_length: int
    embedded_payload_length: int
    required_samples: int
    total_samples: int
    public_key_fingerprint: str
    encrypted: bool
    carrier_result: object
    record: dict[str, Any]
    size_preservation: SizePreservationResult | None = None
    size_report_path: str | None = None
    recovery: RecoveryResult | None = None


@dataclass(frozen=True)
class ProtectionCapacity:
    """Exact signed-envelope and carrier cost for one protection request."""

    media_type: str
    envelope_length: int
    embedded_payload_length: int
    encrypted: bool
    robustness: str
    carrier: CarrierCapacity

    @property
    def fits(self) -> bool:
        return self.carrier.fits

    @property
    def start_location(self) -> int:
        return self.carrier.start_location

    @property
    def required_samples(self) -> int:
        return self.carrier.required_samples


@dataclass(frozen=True)
class _PreparedProtection:
    carrier: CarrierInfo
    envelope: BuiltEnvelope
    carrier_payload: bytes
    capacity: ProtectionCapacity


class PublicationError(RuntimeError):
    """A complete protected-media bundle could not be published safely."""


def _checkpoint(options: ProtectionOptions, message: str) -> None:
    if options.operation is not None:
        options.operation.checkpoint(message)


def _validate_paths(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    options: ProtectionOptions,
) -> tuple[Path, Path, Path, Path | None, Path | None]:
    if not isinstance(options.overwrite, bool):
        raise TypeError("overwrite must be a boolean")
    if not isinstance(options.preserve_size, bool):
        raise TypeError("preserve_size must be a boolean")
    if options.size_report_path is not None and not options.preserve_size:
        raise ValueError("size_report_path requires preserve_size")
    source = Path(input_path).resolve()
    output = Path(output_path).resolve()
    manifest = Path(manifest_path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"cover object not found: {source.name}")
    if options.recovery_path is not None and options.recovery_key is None:
        raise ValueError("recovery_path requires a recovery_key")
    if options.recovery_key is not None:
        if not isinstance(options.recovery_key, bytes) or len(options.recovery_key) != 32:
            raise ValueError("recovery key must contain exactly 32 bytes")
        if source.stat().st_size > MAX_ORIGINAL_BYTES:
            raise ValueError(
                f"{source.name} exceeds the {MAX_ORIGINAL_BYTES:,}-byte recovery limit"
            )
        recovery = Path(
            options.recovery_path
            if options.recovery_path is not None
            else f"{output}.recovery.smir"
        ).resolve()
    else:
        recovery = None
    size_report = (
        Path(options.size_report_path).resolve()
        if options.size_report_path is not None
        else None
    )

    named_paths: list[tuple[str, Path]] = [
        ("input", source),
        ("protected output", output),
        ("manifest", manifest),
    ]
    if recovery is not None:
        named_paths.append(("recovery sidecar", recovery))
    if size_report is not None:
        named_paths.append(("size report", size_report))
    for index, (first_name, first) in enumerate(named_paths):
        for second_name, second in named_paths[index + 1 :]:
            if _paths_alias(first, second):
                raise ValueError(f"{first_name} and {second_name} paths must be different")

    for destination in (output, manifest, recovery, size_report):
        if destination is None:
            continue
        if not destination.parent.is_dir():
            raise FileNotFoundError(
                f"output directory does not exist: {destination.parent.name}"
            )
        if destination.is_dir():
            raise IsADirectoryError(f"output path is a directory: {destination.name}")
        if not os.access(destination.parent, os.W_OK):
            raise PermissionError(
                f"output directory is not writable: {destination.parent.name}"
            )
        if destination.exists() and not options.overwrite:
            raise FileExistsError(f"output already exists: {destination.name}")
    return source, output, manifest, recovery, size_report


def _paths_alias(first: Path, second: Path) -> bool:
    if first == second:
        return True
    if first.exists() and second.exists():
        try:
            return os.path.samefile(first, second)
        except OSError:
            return False
    return False


def _staging_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-",
        suffix=destination.suffix,
        dir=str(destination.parent),
    )
    os.close(descriptor)
    os.unlink(name)
    return Path(name)


def _backup_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.backup-", dir=str(destination.parent)
    )
    os.close(descriptor)
    os.unlink(name)
    return Path(name)


def _replace_path(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _remove_path(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _publish_bundle(staged: dict[Path, Path], overwrite: bool) -> None:
    backups: dict[Path, Path] = {}
    published: list[Path] = []
    try:
        for destination in staged:
            if destination.exists():
                if not overwrite:
                    raise FileExistsError(
                        f"output appeared during processing: {destination.name}"
                    )
                backup = _backup_path(destination)
                _replace_path(destination, backup)
                backups[destination] = backup
        for destination, temporary in staged.items():
            _replace_path(temporary, destination)
            published.append(destination)
    except Exception as exc:
        rollback_errors: list[str] = []
        for destination in reversed(published):
            try:
                _remove_path(destination)
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        for destination, backup in reversed(tuple(backups.items())):
            try:
                if destination.exists():
                    _remove_path(destination)
                _replace_path(backup, destination)
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise PublicationError(
                "bundle publication failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise PublicationError("bundle publication failed; previous files were restored") from exc
    else:
        for backup in backups.values():
            _remove_path(backup)
    finally:
        for temporary in staged.values():
            _remove_path(temporary)


def _carrier_result_at(carrier_result: object, output: Path) -> object:
    if is_dataclass(carrier_result) and hasattr(carrier_result, "output_path"):
        return replace(carrier_result, output_path=str(output))
    if isinstance(carrier_result, dict):
        result = dict(carrier_result)
        result["output_path"] = str(output)
        return result
    return carrier_result


def _make_envelope(
    message: bytes,
    options: ProtectionOptions,
    private_key,
    media_type: str,
) -> BuiltEnvelope:
    return build_envelope(
        message,
        media_id=options.media_id,
        media_type=media_type,
        lsb_count=options.lsb_count,
        start_method=options.start_method,
        private_key=private_key,
        content_type=options.content_type,
        metadata=options.metadata,
        encryption_key=options.encryption_key,
        manual_start_location=options.start_location,
        robustness=options.robustness,
        video_frame_index=(options.video_frame_index if media_type == "video" else None),
    )


def _assess_capacity(
    carrier: CarrierInfo,
    envelope: BuiltEnvelope,
    carrier_payload_length: int,
    options: ProtectionOptions,
) -> ProtectionCapacity:
    at_zero = carrier.capacity(carrier_payload_length, options.lsb_count)
    if options.start_method == "manual":
        if options.start_location is None:
            raise ValueError("manual start mode requires start_location")
        start = options.start_location
    elif options.start_method == "hmac-sha256":
        if options.start_secret is None:
            raise ValueError("derived start mode requires a start-location secret")
        if not at_zero.fits:
            start = 0
        else:
            record = envelope.record
            start = derive_start_location(
                options.start_secret,
                total_samples=carrier.total_samples,
                required_samples=at_zero.required_samples,
                media_type=carrier.media_type,
                media_id=options.media_id,
                nonce=str(record["nonce"]),
                lsb_count=options.lsb_count,
            )
    else:
        raise ValueError("start_method must be manual or hmac-sha256")
    report = carrier.capacity(carrier_payload_length, options.lsb_count, start)
    return ProtectionCapacity(
        media_type=carrier.media_type,
        envelope_length=len(envelope.data),
        embedded_payload_length=carrier_payload_length,
        encrypted=envelope.encrypted,
        robustness=options.robustness,
        carrier=report,
    )


def _prepare_protection(
    input_path: str | Path,
    message: bytes,
    private_key,
    options: ProtectionOptions,
) -> _PreparedProtection:
    carrier = inspect_carrier(
        input_path, video_frame_index=options.video_frame_index
    )
    if carrier.media_type == "video" and options.preserve_size:
        raise ValueError("exact file-size preservation is not supported for video")
    envelope = _make_envelope(message, options, private_key, carrier.media_type)
    if options.robustness == "none":
        carrier_payload = envelope.data
    elif options.robustness == "repetition-3":
        carrier_payload = encode_repetition3(envelope.data)
    else:
        raise ValueError("robustness must be none or repetition-3")
    capacity = _assess_capacity(carrier, envelope, len(carrier_payload), options)
    return _PreparedProtection(carrier, envelope, carrier_payload, capacity)


def estimate_protection_capacity(
    input_path: str | Path,
    message: bytes,
    private_key,
    options: ProtectionOptions,
) -> ProtectionCapacity:
    """Build the actual envelope and report its exact carrier cost without writing."""
    return _prepare_protection(input_path, message, private_key, options).capacity


def _require_capacity(capacity: ProtectionCapacity) -> None:
    report = capacity.carrier
    if not report.fits:
        raise ValueError(
            f"protected payload needs {report.required_samples} samples from start "
            f"{report.start_location}, but only {report.available_samples} are "
            "available; reduce the payload, start location, or robustness overhead"
        )


def protect_media(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    message: bytes,
    private_key,
    options: ProtectionOptions,
) -> ProtectionResult:
    """Create and transactionally publish a protected-media bundle."""
    _checkpoint(options, "Validating paths and settings…")
    (
        source,
        output,
        manifest_path_value,
        recovery_path_value,
        size_report_path_value,
    ) = _validate_paths(input_path, output_path, manifest_path, options)
    _checkpoint(options, "Signing payload and checking capacity…")
    prepared = _prepare_protection(source, message, private_key, options)
    carrier = prepared.carrier
    envelope = prepared.envelope
    carrier_payload = prepared.carrier_payload
    capacity = prepared.capacity
    _require_capacity(capacity)
    start = capacity.start_location
    required = capacity.required_samples

    fingerprint = public_key_fingerprint(private_key.public_key())
    manifest_value = Manifest(
        media_type=carrier.media_type,
        media_id=options.media_id,
        nonce=str(envelope.record["nonce"]),
        lsb_count=options.lsb_count,
        start_method=options.start_method,
        start_location=start if options.start_method == "manual" else None,
        payload_length=len(envelope.data),
        carrier_payload_length=(
            len(carrier_payload) if len(carrier_payload) != len(envelope.data) else None
        ),
        public_key_fingerprint=fingerprint,
        robustness=options.robustness,
        video_frame_index=(
            options.video_frame_index if carrier.media_type == "video" else None
        ),
    ).validate()

    destinations = [output, manifest_path_value]
    if recovery_path_value is not None:
        destinations.append(recovery_path_value)
    if size_report_path_value is not None:
        destinations.append(size_report_path_value)
    staged: dict[Path, Path] = {}
    size_result: SizePreservationResult | None = None
    recovery_result: RecoveryResult | None = None
    try:
        for destination in destinations:
            staged[destination] = _staging_path(destination)
        staged_output = staged[output]
        _checkpoint(options, f"Embedding payload in {carrier.media_type} carrier…")
        if carrier.media_type == "image":
            carrier_result = embed_image(
                str(source),
                str(staged_output),
                carrier_payload,
                options.lsb_count,
                start,
                overwrite=False,
            )
        elif carrier.media_type == "audio":
            carrier_result = embed_audio_lsb(
                str(source),
                str(staged_output),
                carrier_payload,
                lsb_count=options.lsb_count,
                start_location=start,
            )
        else:
            carrier_result = embed_video(
                str(source),
                str(staged_output),
                carrier_payload,
                lsb_count=options.lsb_count,
                start_location=start,
                frame_index=options.video_frame_index,
            )

        _checkpoint(options, "Preparing optional output artifacts…")
        if options.preserve_size:
            size_result = preserve_protected_size(source, staged_output)
            if size_report_path_value is not None:
                export_size_preservation_result(
                    replace(size_result, output_path=str(output)),
                    staged[size_report_path_value],
                )

        _checkpoint(options, "Writing companion manifest…")
        save_manifest(manifest_value, staged[manifest_path_value])
        if recovery_path_value is not None:
            _checkpoint(options, "Creating encrypted recovery sidecar…")
            recovery_result = create_recovery_sidecar(
                source,
                staged_output,
                staged[recovery_path_value],
                options.recovery_key,
            )
        _checkpoint(options, "Publishing complete output bundle…")
        _publish_bundle(staged, options.overwrite)
    except Exception:
        for temporary in staged.values():
            _remove_path(temporary)
        raise

    return ProtectionResult(
        output_path=str(output),
        manifest_path=str(manifest_path_value),
        media_type=carrier.media_type,
        start_location=start,
        payload_length=len(envelope.data),
        embedded_payload_length=len(carrier_payload),
        required_samples=required,
        total_samples=carrier.total_samples,
        public_key_fingerprint=fingerprint,
        encrypted=envelope.encrypted,
        carrier_result=_carrier_result_at(carrier_result, output),
        record=envelope.record,
        size_preservation=(
            replace(size_result, output_path=str(output))
            if size_result is not None
            else None
        ),
        size_report_path=(
            str(size_report_path_value)
            if size_report_path_value is not None
            else None
        ),
        recovery=(
            replace(recovery_result, output_path=str(recovery_path_value))
            if recovery_result is not None
            else None
        ),
    )
