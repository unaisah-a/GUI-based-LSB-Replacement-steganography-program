"""End-to-end protect/sign/embed workflow for image and audio media."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.crypto.key_manager import public_key_fingerprint
from app.crypto.manifest import Manifest, save_manifest
from app.crypto.payload import BuiltEnvelope, build_envelope
from app.crypto.start_location import derive_start_location
from app.services.media import CarrierInfo, inspect_carrier
from app.robustness.redundancy import encode_repetition3
from app.stego.audio_stego import embed_audio_lsb
from app.stego.image_stego import embed_image


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
    overwrite: bool = False


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


def _validate_paths(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    overwrite: bool,
) -> tuple[Path, Path, Path]:
    source = Path(input_path).resolve()
    output = Path(output_path).resolve()
    manifest = Path(manifest_path).resolve()
    if source == output or source == manifest or output == manifest:
        raise ValueError("input, output, and manifest paths must be different")
    if not source.is_file():
        raise FileNotFoundError(f"cover object not found: {source.name}")
    for destination in (output, manifest):
        if not destination.parent.is_dir():
            raise FileNotFoundError(
                f"output directory does not exist: {destination.parent.name}"
            )
        if destination.exists() and not overwrite:
            raise FileExistsError(f"output already exists: {destination.name}")
    return source, output, manifest


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
    )


def _resolve_start(
    carrier: CarrierInfo,
    envelope: BuiltEnvelope,
    carrier_payload_length: int,
    options: ProtectionOptions,
) -> tuple[int, int]:
    required = carrier.required_samples(carrier_payload_length, options.lsb_count)
    if required > carrier.total_samples:
        raise ValueError(
            f"protected payload needs {required} samples but the cover has "
            f"{carrier.total_samples}; reduce the payload or LSB depth overhead"
        )
    if options.start_method == "manual":
        if options.start_location is None:
            raise ValueError("manual start mode requires start_location")
        start = options.start_location
    elif options.start_method == "hmac-sha256":
        if options.start_secret is None:
            raise ValueError("derived start mode requires a start-location secret")
        record = envelope.record
        start = derive_start_location(
            options.start_secret,
            total_samples=carrier.total_samples,
            required_samples=required,
            media_type=carrier.media_type,
            media_id=options.media_id,
            nonce=str(record["nonce"]),
            lsb_count=options.lsb_count,
        )
    else:
        raise ValueError("start_method must be manual or hmac-sha256")
    if start < 0 or start + required > carrier.total_samples:
        raise ValueError(
            f"start location {start} leaves too little capacity for {required} samples"
        )
    return start, required


def protect_media(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    message: bytes,
    private_key,
    options: ProtectionOptions,
) -> ProtectionResult:
    """Create a signed payload, embed it, and export its companion manifest."""
    source, output, manifest_path_value = _validate_paths(
        input_path, output_path, manifest_path, options.overwrite
    )
    carrier = inspect_carrier(source)
    envelope = _make_envelope(message, options, private_key, carrier.media_type)
    if options.robustness == "none":
        carrier_payload = envelope.data
    elif options.robustness == "repetition-3":
        carrier_payload = encode_repetition3(envelope.data)
    else:
        raise ValueError("robustness must be none or repetition-3")
    start, required = _resolve_start(
        carrier, envelope, len(carrier_payload), options
    )

    if carrier.media_type == "image":
        carrier_result = embed_image(
            str(source),
            str(output),
            carrier_payload,
            options.lsb_count,
            start,
            overwrite=options.overwrite,
        )
    else:
        carrier_result = embed_audio_lsb(
            str(source),
            str(output),
            carrier_payload,
            lsb_count=options.lsb_count,
            start_location=start,
        )

    fingerprint = public_key_fingerprint(private_key.public_key())
    manifest = Manifest(
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
    )
    try:
        save_manifest(manifest, manifest_path_value)
    except Exception:
        # This output was created by this call, so roll it back if its required
        # companion manifest cannot be written.
        output.unlink(missing_ok=True)
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
        carrier_result=carrier_result,
        record=envelope.record,
    )
