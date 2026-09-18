"""Measured lossy-video verification experiments and evidence export."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

from app.crypto.manifest import load_manifest
from app.stego.video_stego import decode_video_frame, probe_video, transcode_video_lossy
from app.verification.verifier import verify_media


@dataclass(frozen=True)
class LossyVideoExperiment:
    protected_path: str
    lossy_output_path: str
    codec: str
    crf: int
    selected_frame: int
    protected_properties: dict[str, object]
    lossy_properties: dict[str, object]
    selected_frame_differing_samples: int
    selected_frame_total_samples: int
    verification_verdict: str
    verification_summary: str
    verification_checks: tuple[dict[str, str], ...]
    interpretation: str = (
        "This is a measured result for this file and CRF. Lossy transcoding can "
        "change carrier bits; the result does not predict every codec or setting."
    )

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["verification_checks"] = list(value["verification_checks"])
        return value


def _properties(info) -> dict[str, object]:
    return {
        "codec": info.codec_name,
        "width": info.width,
        "height": info.height,
        "frames": info.frame_count,
        "frame_rate": info.frame_rate,
        "duration_seconds": info.duration_seconds,
        "audio_streams": list(info.audio_streams),
    }


def run_lossy_video_experiment(
    protected_path: str | Path,
    lossy_output_path: str | Path,
    manifest_path: str | Path,
    public_key,
    *,
    start_secret: str | bytes | None = None,
    encryption_key: bytes | None = None,
    crf: int = 23,
    overwrite: bool = False,
) -> LossyVideoExperiment:
    manifest = load_manifest(manifest_path)
    if manifest.media_type != "video" or manifest.video_frame_index is None:
        raise ValueError("lossy experiment requires a video manifest")
    source = Path(protected_path).resolve()
    destination = Path(lossy_output_path).resolve()
    original_info = probe_video(source)
    transcode_video_lossy(source, destination, crf=crf, overwrite=overwrite)
    lossy_info = probe_video(destination)
    protected_frame, _ = decode_video_frame(source, manifest.video_frame_index)
    lossy_frame, _ = decode_video_frame(destination, manifest.video_frame_index)
    differing = (
        int(np.not_equal(protected_frame, lossy_frame).sum())
        if protected_frame.shape == lossy_frame.shape
        else int(protected_frame.size)
    )
    verification = verify_media(
        destination,
        manifest_path,
        public_key,
        start_secret=start_secret,
        encryption_key=encryption_key,
    )
    return LossyVideoExperiment(
        str(source),
        str(destination),
        lossy_info.codec_name,
        crf,
        manifest.video_frame_index,
        _properties(original_info),
        _properties(lossy_info),
        differing,
        int(protected_frame.size),
        verification.verdict.value,
        verification.summary,
        tuple(
            {
                "name": check.name,
                "status": check.status.value,
                "detail": check.detail,
            }
            for check in verification.checks
        ),
    )


def export_lossy_video_experiment(
    result: LossyVideoExperiment,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(result, LossyVideoExperiment):
        raise TypeError("result must be a LossyVideoExperiment")
    encoded = (
        json.dumps(result.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    destination = Path(output_path).resolve()
    if destination in {
        Path(result.protected_path).resolve(),
        Path(result.lossy_output_path).resolve(),
    }:
        raise ValueError("video evidence path must differ from media paths")
    if not destination.parent.is_dir():
        raise FileNotFoundError("video evidence directory does not exist")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"video evidence already exists: {destination.name}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
