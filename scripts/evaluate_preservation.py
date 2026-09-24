"""T06 saved-file size/property evaluation. Run with --output NEW_DIRECTORY.

Uses the photographic face.dat bundled with the pinned SciPy, without downloads.
Keys remain in memory. Covers are deterministic; signatures/nonces are fresh, so
compressed output sizes can vary between runs. No release samples are modified.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
import platform
import struct
from pathlib import Path

import cv2
import numpy as np
import scipy
import soundfile as sf
from PIL import Image

from app.analysis.size_preservation import size_outcome
from app.crypto import key_manager
from app.stego import image_io, video_stego
from app.utils import constants
from app.verification.protect import protect_media
from app.verification.verifier import verify_media


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inspect(path):
    """Decode saved files, independently of the protect result's descriptor."""
    path = Path(path)
    if path.suffix in (".png", ".bmp"):
        data, _ = image_io.load_image(path)
        return data, dict(height=data.shape[0], width=data.shape[1], channels=data.shape[2])
    if path.suffix == ".wav":
        data, rate = sf.read(path, dtype="int16", always_2d=True)
        return data, dict(frames=len(data), channels=data.shape[1], sample_rate=rate,
                          subtype=sf.info(path).subtype, duration_seconds=len(data) / rate)
    capture = cv2.VideoCapture(str(path))
    frames = []
    try:
        if not capture.isOpened():
            raise RuntimeError(f"Cannot open {path}")
        fps = capture.get(cv2.CAP_PROP_FPS)
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            frames.append(frame)
    finally:
        capture.release()
    data = np.stack(frames)
    return data, dict(frames=len(data), width=data.shape[2], height=data.shape[1],
                      channels=3, fps=fps, duration_seconds=len(data) / fps)


def make_covers(output):
    photo_source = Path(scipy.__file__).parent / "misc" / "face.dat"
    photo = np.frombuffer(bz2.decompress(photo_source.read_bytes()), np.uint8).reshape(768, 1024, 3)
    photo = np.asarray(Image.fromarray(photo).resize((256, 192)))
    flat = np.full((192, 256, 3), 128, dtype=np.uint8)
    covers = []
    for name, pixels, level in (("flat", flat, 6), ("photo", photo, 6),
                                ("flat_uncompressed", flat, 0)):
        path = output / f"{name}.png"
        Image.fromarray(pixels).save(path, compress_level=level)
        covers.append(path)
    bmp = output / "photo.bmp"
    bmp.write_bytes(image_io.encode_image(photo, image_io.BMP))
    covers.append(bmp)
    # A legal pre-pixel gap: fixed-width pixel storage does not imply fixed file size.
    raw = bytearray(bmp.read_bytes())
    offset = struct.unpack_from("<I", raw, 10)[0]
    raw[offset:offset] = b"\0" * 128
    struct.pack_into("<I", raw, 2, len(raw))
    struct.pack_into("<I", raw, 10, offset + 128)
    gap = output / "photo_gap.bmp"
    gap.write_bytes(raw)
    covers.append(gap)
    for channels, rate in ((1, 22050), (2, 44100)):
        t = np.arange(rate * 2) / rate
        data = np.column_stack([np.rint(18000 * np.sin(2 * np.pi * (440 + 110 * c) * t))
                                for c in range(channels)]).astype(np.int16)
        path = output / f"tone_{channels}ch.wav"
        sf.write(path, data, rate, subtype="PCM_16")
        covers.append(path)
    raw = bytearray(covers[-1].read_bytes())
    raw.extend(b"JUNK" + struct.pack("<I", 128) + b"\0" * 128)
    struct.pack_into("<I", raw, 4, len(raw) - 8)
    extra = output / "tone_metadata.wav"
    extra.write_bytes(raw)
    covers.append(extra)
    for codec, fps, suffix in (("FFV1", 10, ".mkv"), ("FFV1", 30000 / 1001, ".mkv"),
                                ("MJPG", 25, ".avi")):
        path = output / f"video_{codec}_{fps:.3f}{suffix}"
        writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*codec), fps, (256, 192))
        if not writer.isOpened():
            raise RuntimeError(f"{codec} writer unavailable")
        try:
            for index in range(12):
                writer.write(np.roll(photo[:, :, ::-1], index * 2, axis=1))
        finally:
            writer.release()
        covers.append(path)
    return covers, dict(source="SciPy misc/face.dat: raccoon photograph from public-domain-image.com",
                        source_sha256=digest(photo_source), resize=[256, 192],
                        other_media="Flat RGB, generated sine waves, photographic moving frames; no audio in video")


def evaluate(output):
    output.mkdir(parents=True, exist_ok=False)
    covers, provenance = make_covers(output)
    private, public = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    key_manager.save_public_key(public, str(output / "public.pem"))
    rows = []
    for cover in covers:
        source_hash = digest(cover)
        before, properties = inspect(cover)
        video = cover.suffix in (".mkv", ".avi")
        # Same encoder with no embedding isolates codec/container overhead.
        baseline = output / (cover.stem + "_baseline" + (".mkv" if video else cover.suffix))
        if video:
            video_stego.write_frames(iter(before), baseline, video_stego.describe_only(cover))
        elif cover.suffix == ".wav":
            sf.write(baseline, before, properties["sample_rate"], subtype="PCM_16")
        else:
            baseline.write_bytes(image_io.encode_image(before, cover.suffix[1:].upper()))
        for depth in (1, 4, 8):
            for match in (False, True):
                name = f"{cover.stem}_{cover.suffix[1:]}_d{depth}_match{int(match)}"
                target = output / (name + (".mkv" if video else cover.suffix))
                message = b"T06 size and media-property preservation. " * 8
                result = protect_media(cover, target, message, private, media_id=name,
                                       lsb_depth=depth, start_method=constants.START_METHOD_MANUAL,
                                       manual_start_location=17, match_cover_size=match)
                verdict = verify_media(target, result.manifest_path, public)
                assert verdict.verdict == constants.VERDICT_AUTHENTIC and verdict.message == message
                after, after_properties = inspect(target)
                assert before.shape == after.shape
                for key in properties:
                    if key in ("fps", "duration_seconds"):
                        assert np.isclose(properties[key], after_properties[key], rtol=1e-5, atol=1e-6)
                    else:
                        assert properties[key] == after_properties[key]
                delta = np.abs(after.astype(np.int32) - before.astype(np.int32))
                assert delta.max() <= (1 << depth) - 1
                begin = result.start_location
                end = begin + result.embed_result.samples_written
                assert np.array_equal(before.reshape(-1)[:begin], after.reshape(-1)[:begin])
                assert np.array_equal(before.reshape(-1)[end:], after.reshape(-1)[end:])
                assert digest(cover) == source_hash
                outcome = result.size_preservation or size_outcome(cover, target)
                rows.append(dict(case=name, cover=cover.name, cover_sha256=source_hash,
                                 output_sha256=digest(target), depth=depth, matching_requested=match,
                                 size=outcome.as_dict(), manifest_bytes=Path(result.manifest_path).stat().st_size,
                                 baseline_bytes=baseline.stat().st_size,
                                 delta_from_baseline=target.stat().st_size - baseline.stat().st_size,
                                 before=properties, after=after_properties, verdict=verdict.verdict,
                                 max_sample_change=int(delta.max()), outside_payload_unchanged=True))
    summary = dict(python=platform.python_version(), platform=platform.platform(),
                   scipy=scipy.__version__, opencv=cv2.__version__, provenance=provenance,
                   cases=rows, public_key_bytes=(output / "public.pem").stat().st_size)
    (output / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = evaluate(args.output)
    print(json.dumps(dict(cases=len(report["cases"]), all_authentic=True, output=str(args.output))))
