"""Reproducible T05 experiments; synthetic media only, never detection accuracy claims.

Run: python -m scripts.evaluate_challenges --output tmp/t05-demo
The output directory must be new. Keys stay in memory; only the public key is saved.
"""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

import cv2
import numpy as np
import soundfile as sf
from PIL import Image

from app.attacks import registry
from app.crypto import key_manager
from app.crypto.envelope import ErrorCorrectionParameters
from app.stego import media
from app.utils import constants
from app.verification.protect import protect_media
from app.verification.verifier import verify_media

# Public demonstration value, never use for real messages.
DEMO_SECRET = "t05-public-demo-start"
MESSAGE = b"T05 synthetic challenge demonstration."


def evaluate(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    private, public = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    key_manager.save_public_key(public, str(output / "public.pem"))
    rng = np.random.default_rng(5005)
    image = output / "cover.png"
    Image.fromarray(rng.integers(0, 256, (256, 256, 3), dtype=np.uint8)).save(image)
    audio = output / "cover.wav"
    sf.write(audio, rng.integers(-20000, 20000, 100000, dtype=np.int16), 22050,
             subtype="PCM_16")
    video = output / "cover.mkv"
    writer = cv2.VideoWriter(str(video), cv2.VideoWriter_fourcc(*"FFV1"), 10, (128, 128))
    if not writer.isOpened():
        raise RuntimeError("FFV1 writer unavailable")
    try:
        for _ in range(10):
            writer.write(rng.integers(0, 256, (128, 128, 3), dtype=np.uint8))
    finally:
        writer.release()

    def protect(cover, name, ecc=None):
        return protect_media(cover, output / (name + cover.suffix), MESSAGE, private,
                             media_id=name, lsb_depth=1, start_secret=DEMO_SECRET, ecc=ecc)

    def verify(result, path=None):
        return verify_media(path or result.stego_path, result.manifest_path, public,
                            start_secret=DEMO_SECRET)

    results = {}
    for cover in (image, audio, video):
        result = protect(cover, "protected_" + cover.stem + cover.suffix[1:])
        assert verify(result).verdict == constants.VERDICT_AUTHENTIC
        runs = []
        for key in ("verification.wrong_key", "verification.wrong_start",
                    "payload.message", "payload.signature", result.record.media_type + ".outside"):
            context = registry.context_from_protect_result(
                result, str(output / (key.replace(".", "_") + cover.suffix)))
            run = registry.run_attack(key, context, public, start_secret=DEMO_SECRET)
            assert run.matched_expectation, run.as_text()
            runs.append(run.as_dict())
        results[cover.suffix] = {"protected": Path(result.stego_path).name,
                                "start_location": result.start_location, "attacks": runs}
        if cover == video:
            def frames(path):
                cap = cv2.VideoCapture(str(path))
                data = []
                try:
                    while True:
                        ok, frame = cap.read()
                        if not ok:
                            break
                        data.append(frame)
                finally:
                    cap.release()
                return data
            before, after = frames(video), frames(result.stego_path)
            assert len(before) == len(after) == 10
            changed = [i for i, (a, b) in enumerate(zip(before, after, strict=True)) if np.any(a != b)]
            first = result.start_location // (128 * 128 * 3)
            last = (result.start_location + result.embed_result.samples_written - 1) // (128 * 128 * 3)
            assert changed and all(first <= i <= last for i in changed)
            results[cover.suffix].update(changed_frames=changed, claimed_span=[first, last],
                                        video_only=True, frames=10, fps=10)

    robustness = []
    for cover in (image, audio):
        for factor in (1, 3):
            ecc = ErrorCorrectionParameters(constants.ECC_REPETITION, 3) if factor == 3 else None
            result = protect(cover, f"robust_{cover.suffix[1:]}_{factor}", ecc)
            raw = media.extract(result.stego_path, 1, result.start_location)
            # Same logical damage: last signature bit in first copy; then in two
            # copies. Header is untouched. No probabilistic success selection.
            length = len(raw) // factor
            for copies in ((1,) if factor == 1 else (1, 2)):
                damaged = bytearray(raw)
                for copy in range(copies):
                    damaged[(copy + 1) * length - 1] ^= 1
                target = output / f"damage_{cover.suffix[1:]}_{factor}_{copies}{cover.suffix}"
                media.embed(result.stego_path, target, bytes(damaged), 1, result.start_location)
                verdict = verify(result, target)
                corrected = verdict.details.get("error_correction", {}).get("bits_corrected", 0)
                expected = constants.VERDICT_AUTHENTIC if factor == 3 and copies == 1 else constants.VERDICT_SIGNATURE_INVALID
                assert verdict.verdict == expected
                if expected == constants.VERDICT_AUTHENTIC:
                    assert corrected > 0
                robustness.append(dict(media=cover.suffix, factor=factor, flipped_bits=copies,
                                       logical_bit="last signature bit", verdict=verdict.verdict,
                                       bits_corrected=corrected, file=target.name,
                                       manifest=Path(result.manifest_path).name))

    summary = dict(python=platform.python_version(), provenance="Synthetic generators",
                   workflows=results, robustness=robustness)
    (output / "results.json").write_text(json.dumps(summary, indent=2, allow_nan=False), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = evaluate(args.output)
    print(json.dumps({"output": str(args.output), "workflows": len(summary["workflows"]),
                      "robustness_cases": len(summary["robustness"])}))
