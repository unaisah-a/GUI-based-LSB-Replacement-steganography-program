"""Measure image-indicator false alarms and repetition recovery under independent bit noise.

Defaults are explicitly synthetic. Pass --images with your own PNG/BMP photographs
to evaluate real covers without modifying them. Reports contain hashes, not paths.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.analysis.image_analysis import pair_of_values_chi_square
from app.robustness.redundancy import encode_repetition3, decode_repetition3
from app.stego import image_io
from app.stego.image_stego import embed_image, measure_capacity


def indicator_decision(image) -> dict:
    indicators = pair_of_values_chi_square(image)
    ratios = [row.value / row.degrees_of_freedom for row in indicators
              if row.value is not None and row.degrees_of_freedom]
    # Illustrative fixed rule, intentionally not calibrated on the evaluation set.
    suspected = any(value <= 1.5 for value in ratios) if ratios else None
    return {"chi_square_per_degree": ratios, "suspected": suspected}


def image_evaluation(paths: list[Path], seed: int, provenance: str) -> dict:
    rng = np.random.default_rng(seed)
    rows = []
    with tempfile.TemporaryDirectory(prefix="smiv-evaluation-") as temporary:
        output = Path(temporary) / "embedded.png"
        for index, path in enumerate(paths):
            cover, _ = image_io.load_image(path)
            capacity, _ = measure_capacity(str(path), 1, 0)
            rows.append({"cover": index, "embedded": False, "fraction": 0.0,
                         "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                         **indicator_decision(cover)})
            for fraction in (0.1, 0.5, 0.9):
                size = int(capacity.max_payload_length * fraction)
                if size < 1:
                    continue
                payload = rng.bytes(size)
                embed_image(path, output, payload, 1, 0, overwrite=True)
                embedded, _ = image_io.load_image(output)
                rows.append({"cover": index, "embedded": True, "fraction": fraction,
                             "message_bytes": size,
                             "output_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                             **indicator_decision(embedded)})
    clean = [r for r in rows if not r["embedded"]]
    embedded = [r for r in rows if r["embedded"]]
    return {
        "provenance": provenance, "lsb_depth": 1, "start_location": 0,
        "rule": "Suspect if any usable channel has pair-of-values chi-square/df <= 1.5; otherwise negative; no usable channel = inconclusive.",
        "scope": "Illustrative, uncalibrated rule. Clean covers can trigger it and embedded covers can evade it. This is not proof of tampering or a validated detector.",
        "counts": {
            "clean": len(clean), "embedded": len(embedded),
            "false_positives": sum(r["suspected"] is True for r in clean),
            "true_negatives": sum(r["suspected"] is False for r in clean),
            "true_positives": sum(r["suspected"] is True for r in embedded),
            "false_negatives": sum(r["suspected"] is False for r in embedded),
            "inconclusive_clean": sum(r["suspected"] is None for r in clean),
            "inconclusive_embedded": sum(r["suspected"] is None for r in embedded),
        },
        "cases": rows,
    }


def noise_evaluation(seed: int, trials: int = 50) -> dict:
    rng = np.random.default_rng(seed)
    payload = rng.bytes(256)
    rows = []
    for probability in (0.0, 0.001, 0.01, 0.05, 0.1):
        for mode in ("none", "repetition-3"):
            stored = payload if mode == "none" else encode_repetition3(payload)
            bits = np.unpackbits(np.frombuffer(stored, dtype=np.uint8))
            recovered_trials = bit_errors = 0
            for _ in range(trials):
                flips = rng.random(bits.size) < probability
                damaged = np.packbits(bits ^ flips.astype(np.uint8)).tobytes()
                recovered = damaged if mode == "none" else decode_repetition3(damaged, len(payload))
                recovered_trials += recovered == payload
                difference = np.frombuffer(recovered, dtype=np.uint8) ^ np.frombuffer(payload, dtype=np.uint8)
                bit_errors += int(np.unpackbits(difference).sum())
            rows.append({"mode": mode, "bit_flip_probability": probability,
                         "trials": trials, "exact_recoveries": recovered_trials,
                         "recovered_bit_errors": bit_errors,
                         "recovered_bits_evaluated": trials * len(payload) * 8,
                         "stored_bytes": len(stored)})
    return {"message_bytes": len(payload), "cases": rows,
            "scope": "Independent random flips across all stored payload bits, including every repetition copy. Same error probability, three times the storage with repetition. No carrier header, signature, compression, resampling, or burst-error resilience claim."}


def build_report(images: list[Path] | None = None, seed: int = 2005) -> dict:
    if images:
        image_report = image_evaluation(images, seed, "User-supplied covers; provenance must be documented by the team.")
    else:
        with tempfile.TemporaryDirectory(prefix="smiv-controls-") as temporary:
            rng = np.random.default_rng(seed)
            gradient = np.tile(np.arange(128, dtype=np.uint8) * 2, (128, 1))
            controls = [np.repeat(gradient[:, :, None], 3, axis=2),
                        rng.integers(0, 256, (128, 128, 3), dtype=np.uint8),
                        np.zeros((8, 8, 3), dtype=np.uint8)]
            paths = []
            for index, cover in enumerate(controls):
                path = Path(temporary) / f"control-{index}.png"
                image_io.save_image(cover, path, image_io.PNG)
                paths.append(path)
            image_report = image_evaluation(paths, seed, "Synthetic even-valued gradient, random noise, and undersized flat control; no natural-image detection claim.")
    return {"format": "SMIV-EXTENSION-EVALUATION", "version": 1, "seed": seed,
            "steganalysis": image_report, "robustness": noise_evaluation(seed)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, nargs="+")
    parser.add_argument("--seed", type=int, default=2005)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new report path")
    report = build_report(args.images, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps(report["steganalysis"]["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
