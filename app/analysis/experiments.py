"""Complete comparison evidence and controlled LSB-depth experiments."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

import numpy as np
import numpy.typing as npt

from app.analysis.audio_analysis import calculate_quality_report
from app.analysis.image_analysis import (
    INDICATOR_DISCLAIMER,
    bit0_uniformity,
    compare_quality,
    difference_image,
    extract_bit_plane,
    histogram_compare,
    lsb_distribution,
    pair_of_values_chi_square,
    pair_of_values_neighbour,
)
from app.services.media import inspect_carrier
from app.stego.audio_stego import embed_audio_lsb, read_audio
from app.stego.image_stego import embed_image


MAX_EXPERIMENT_PAYLOAD_BYTES = 1_048_576
MAX_PLOT_POINTS = 2_000


@dataclass(frozen=True)
class DepthExperimentRow:
    lsb_count: int
    message_bytes: int
    encoded_bytes: int
    carrier_samples_written: int
    carrier_samples_total: int
    embedding_density: float
    mse: float
    psnr_db: float | None
    psnr_unbounded: bool
    snr_db: float | None
    snr_unbounded: bool
    max_absolute_difference: int
    changed_sample_percentage: float


@dataclass(frozen=True)
class DepthExperiment:
    media_type: str
    message_bytes: int
    start_location: int
    rows: tuple[DepthExperimentRow, ...]
    method: str = (
        "The same deterministic message is embedded from sample 0 at each LSB "
        "depth. Embedding density is the encoded carrier region divided by all "
        "eligible scalar samples."
    )
    interpretation: str = (
        "These measurements describe this cover and message only. Greater LSB "
        "depth is not claimed to be invariably more visible or audible. Listening "
        "observations require a human listener and are not generated automatically."
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "media_type": self.media_type,
            "message_bytes": self.message_bytes,
            "start_location": self.start_location,
            "method": self.method,
            "interpretation": self.interpretation,
            "rows": [asdict(row) for row in self.rows],
        }


@dataclass(frozen=True)
class AnalysisBundle:
    media_type: str
    evidence: dict[str, object]
    experiment: DepthExperiment
    image_original_lsb: npt.NDArray[np.uint8] | None = None
    image_modified_lsb: npt.NDArray[np.uint8] | None = None
    image_difference: npt.NDArray[np.uint8] | None = None
    histogram_original: npt.NDArray[np.int64] | None = None
    histogram_modified: npt.NDArray[np.int64] | None = None
    audio_original: npt.NDArray[np.float64] | None = None
    audio_modified: npt.NDArray[np.float64] | None = None
    audio_difference: npt.NDArray[np.float64] | None = None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _finite(value: object) -> object:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, (float, np.floating)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, (int, np.integer)):
        return int(value)
    return value


def _indicator_dict(result) -> dict[str, object]:
    value = asdict(result)
    value["value"] = _finite(value["value"])
    value["details"] = {key: _finite(item) for key, item in value["details"].items()}
    return value


def _file_facts(path: Path, description: dict[str, object]) -> dict[str, object]:
    return {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "properties": description,
    }


def _downsample(values: npt.NDArray[np.generic]) -> npt.NDArray[np.float64]:
    flat = np.asarray(values, dtype=np.float64)
    if flat.ndim == 2:
        flat = flat.mean(axis=1)
    flat = flat.reshape(-1)
    if flat.size <= MAX_PLOT_POINTS:
        return flat.copy()
    indices = np.linspace(0, flat.size - 1, MAX_PLOT_POINTS, dtype=np.int64)
    return flat[indices].copy()


def _comparison_evidence(
    original: Path,
    modified: Path,
    lsb_count: int,
    listening_observation: str,
) -> tuple[dict[str, object], dict[str, npt.NDArray]]:
    first = inspect_carrier(original)
    second = inspect_carrier(modified)
    if first.media_type != second.media_type:
        raise ValueError("both files must be the same media type")

    common: dict[str, object] = {
        "format": "SMIV-ANALYSIS-EVIDENCE",
        "version": 1,
        "media_type": first.media_type,
        "selected_lsb_count": lsb_count,
        "original": _file_facts(original, first.description),
        "modified": _file_facts(modified, second.description),
    }
    visuals: dict[str, npt.NDArray] = {}
    if first.media_type == "image":
        quality = compare_quality(original, modified)
        difference = difference_image(original, modified, amplify=True)
        histogram = histogram_compare(original, modified)
        indicator_functions = (
            lsb_distribution,
            bit0_uniformity,
            pair_of_values_chi_square,
            pair_of_values_neighbour,
        )
        indicators = {
            label: [
                _indicator_dict(result)
                for function in indicator_functions
                for result in function(path)
            ]
            for label, path in (("original", original), ("modified", modified))
        }
        common["quality"] = {
            "colour_mse": quality.overall_mse,
            "colour_psnr_db": (
                None if quality.overall_psnr_unbounded else quality.overall_psnr_db
            ),
            "colour_psnr_unbounded": quality.overall_psnr_unbounded,
            "colour_samples_identical": quality.colour_samples_identical,
            "all_samples_identical": quality.pixel_identical,
            "alpha_excluded_from_colour_metrics": quality.alpha_excluded_from_overall,
            "max_absolute_difference": quality.max_absolute_difference,
            "differing_samples": quality.differing_samples,
            "total_samples": quality.total_samples,
            "differing_proportion": quality.differing_proportion,
            "channels": [
                {
                    "index": channel.index,
                    "label": channel.label,
                    "mse": channel.mse,
                    "psnr_db": None if channel.psnr_unbounded else channel.psnr_db,
                    "psnr_unbounded": channel.psnr_unbounded,
                    "is_alpha": channel.is_alpha,
                }
                for channel in quality.channels
            ],
        }
        common["difference"] = {
            "display_mode": difference.mode,
            "display_scale_factor": difference.scale_factor,
            "changed_pixels": difference.changed_pixels,
            "differing_samples": difference.differing_samples,
            "includes_alpha": difference.includes_alpha,
        }
        common["histogram"] = {
            "channel_labels": list(histogram.channel_labels),
            "original_counts": histogram.histograms_a.tolist(),
            "modified_counts": histogram.histograms_b.tolist(),
            "difference_counts": histogram.difference_counts.tolist(),
            "disclaimer": histogram.disclaimer,
        }
        common["indicators"] = indicators
        common["indicator_disclaimer"] = INDICATOR_DISCLAIMER
        visuals = {
            "image_original_lsb": extract_bit_plane(original, 0, 0).plane,
            "image_modified_lsb": extract_bit_plane(modified, 0, 0).plane,
            "image_difference": difference.difference,
            "histogram_original": histogram.histograms_a,
            "histogram_modified": histogram.histograms_b,
        }
    else:
        quality = calculate_quality_report(original, modified, lsb_count)
        original_samples, _ = read_audio(original)
        modified_samples, _ = read_audio(modified)
        finite_quality = {key: _finite(value) for key, value in quality.items()}
        finite_quality["snr_unbounded"] = math.isinf(float(quality["snr_db"]))
        finite_quality["psnr_unbounded"] = math.isinf(float(quality["psnr_db"]))
        common["quality"] = finite_quality
        common["listening_observation"] = listening_observation.strip() or (
            "Not recorded. Listen under documented conditions and add a human "
            "observation before using this as final evidence."
        )
        original_plot = _downsample(original_samples)
        modified_plot = _downsample(modified_samples)
        visuals = {
            "audio_original": original_plot,
            "audio_modified": modified_plot,
            "audio_difference": modified_plot - original_plot,
        }
    return common, visuals


def run_depth_experiment(
    original_path: str | os.PathLike[str],
    message_bytes: int,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> DepthExperiment:
    """Embed one deterministic message at depths 1–8 and measure each result."""
    if isinstance(message_bytes, bool) or not isinstance(message_bytes, int):
        raise TypeError("experiment message size must be an integer")
    if not 1 <= message_bytes <= MAX_EXPERIMENT_PAYLOAD_BYTES:
        raise ValueError(
            f"experiment message size must be between 1 and "
            f"{MAX_EXPERIMENT_PAYLOAD_BYTES:,} bytes"
        )
    original = Path(original_path).resolve()
    carrier = inspect_carrier(original)
    capacity = carrier.capacity(message_bytes, 1, 0)
    if not capacity.fits:
        raise ValueError(
            f"the experiment message does not fit at depth 1; maximum is "
            f"{capacity.max_payload_length:,} bytes"
        )
    payload = bytes(index % 251 for index in range(message_bytes))
    rows: list[DepthExperimentRow] = []
    with tempfile.TemporaryDirectory(prefix="smiv-analysis-") as directory:
        for depth in range(1, 9):
            if checkpoint is not None:
                checkpoint()
            suffix = original.suffix if carrier.media_type == "image" else ".wav"
            output = Path(directory) / f"depth-{depth}{suffix}"
            if carrier.media_type == "image":
                embedded = embed_image(original, output, payload, depth, 0)
                quality = compare_quality(original, output)
                mse = quality.overall_mse
                psnr = None if quality.overall_psnr_unbounded else quality.overall_psnr_db
                snr = None
                snr_unbounded = False
                changed = quality.differing_proportion * 100.0
                maximum = quality.max_absolute_difference
                encoded = embedded.encoded_length
                written = embedded.samples_written
            else:
                embedded = embed_audio_lsb(original, output, payload, depth, 0)
                quality = calculate_quality_report(original, output, depth)
                mse = float(quality["mse"])
                psnr_value = float(quality["psnr_db"])
                snr_value = float(quality["snr_db"])
                psnr = None if math.isinf(psnr_value) else psnr_value
                snr = None if math.isinf(snr_value) else snr_value
                snr_unbounded = math.isinf(snr_value)
                changed = float(quality["changed_percentage"])
                maximum = int(quality["max_absolute_difference"])
                encoded = int(embedded["packet_size"])
                written = int(embedded["samples_modified_region"])
            rows.append(
                DepthExperimentRow(
                    lsb_count=depth,
                    message_bytes=message_bytes,
                    encoded_bytes=encoded,
                    carrier_samples_written=written,
                    carrier_samples_total=carrier.total_samples,
                    embedding_density=written / carrier.total_samples,
                    mse=mse,
                    psnr_db=psnr,
                    psnr_unbounded=psnr is None,
                    snr_db=snr,
                    snr_unbounded=snr_unbounded,
                    max_absolute_difference=maximum,
                    changed_sample_percentage=changed,
                )
            )
    return DepthExperiment(carrier.media_type, message_bytes, 0, tuple(rows))


def prepare_analysis(
    original_path: str | os.PathLike[str],
    modified_path: str | os.PathLike[str],
    lsb_count: int,
    experiment_message_bytes: int,
    *,
    listening_observation: str = "",
    checkpoint: Callable[[], None] | None = None,
) -> AnalysisBundle:
    original = Path(original_path).resolve()
    modified = Path(modified_path).resolve()
    if not isinstance(listening_observation, str):
        raise TypeError("listening observation must be text")
    evidence, visuals = _comparison_evidence(
        original, modified, lsb_count, listening_observation
    )
    if checkpoint is not None:
        checkpoint()
    experiment = run_depth_experiment(
        original, experiment_message_bytes, checkpoint=checkpoint
    )
    evidence["depth_experiment"] = experiment.to_dict()
    return AnalysisBundle(
        media_type=str(evidence["media_type"]),
        evidence=evidence,
        experiment=experiment,
        **visuals,
    )


def export_analysis_evidence(
    bundle: AnalysisBundle,
    output_path: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(bundle, AnalysisBundle):
        raise TypeError("bundle must be an AnalysisBundle")
    encoded = (
        json.dumps(bundle.evidence, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    destination = Path(output_path).resolve()
    if not destination.parent.is_dir():
        raise FileNotFoundError("analysis output directory does not exist")
    if destination.is_dir():
        raise IsADirectoryError(f"analysis output is a directory: {destination.name}")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"analysis output already exists: {destination.name}")
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
