"""Generate the agreed flat submission set, refusing existing outputs.

python -m scripts.generate_submission_samples
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.analysis import quality_metrics
from app.analysis.size_preservation import size_outcome
from app.attacks import registry
from app.crypto import key_manager
from app.crypto import manifest as manifest_module
from app.crypto.envelope import ErrorCorrectionParameters
from app.stego import media, video_stego
from app.stego.errors import CapacityError
from app.utils import constants, payload_files
from app.verification.protect import protect_media
from scripts.verify_submission_samples import (
    ROOT,
    digest,
    verify,
    write_csv,
    write_json,
)

START = "sample-start-2026"
PASSPHRASE = "sample-encryption-2026"
SHORT = "Explain how steganography can be used to embed hidden verification data in image and audio cover objects."
CUSTOM = ("FICTIONAL DEMONSTRATION: the release team shares a draft media approval message. "
          "Encryption keeps the message confidential, while its signature and SHA-256 hash verify its integrity.")
ORIGINALS = ("audio_cover.wav", "encryption_cover.png", "forest-cover.mkv", "huge_text_payload .txt",
             "image_cover.png", "image_payload.png", "text_payload.txt")
CHECK_NAMES = ("payload_matches_manifest", "manifest_matches_record", "payload_matches_record")


def build(root=ROOT, private_path=None, public_path=None):
    root = Path(root).resolve()
    original, protected, tampered = (root / "samples" / folder for folder in ("original", "protected", "tampered"))
    evidence, public_dir = root / "evidence", root / "keys/public"
    # Preflight every destination before writing anything.
    for folder in (protected, tampered, evidence):
        if folder.exists() and any(p.is_file() and p.name != ".gitkeep" for p in folder.rglob("*")):
            raise FileExistsError(f"Output folder already contains files: {folder}")
    for path in (original / "short_text_payload.txt", original / "custom_text_payload.txt",
                 public_dir / "submission_public.pem", public_dir / "unrelated_public.pem"):
        if path.exists():
            raise FileExistsError(path)
    for name in ORIGINALS:
        if not (original / name).is_file():
            raise FileNotFoundError(original / name)
    originals_before = {name: digest(original / name) for name in ORIGINALS}
    private = key_manager.load_private_key(private_path or root / "keys/demo_private/demo_private.pem")
    public = key_manager.load_public_key(public_path or public_dir / "demo_public.pem")
    if private.public_key().public_numbers() != public.public_numbers():
        raise ValueError("Signing key and public key do not match")
    for folder in (protected, tampered, evidence / "logs", evidence / "screenshots", public_dir):
        folder.mkdir(parents=True, exist_ok=True)
    (original / "short_text_payload.txt").write_bytes(SHORT.encode("utf-8"))
    (original / "custom_text_payload.txt").write_bytes(CUSTOM.encode("utf-8"))
    key_manager.save_public_key(public, public_dir / "submission_public.pem")
    wrong_private, wrong_public = key_manager.generate_key_pair()
    key_manager.save_public_key(wrong_public, public_dir / "unrelated_public.pem")
    del wrong_private
    cases, outputs, attacks, capacities = [], {}, [], []
    def rel(path):
        return Path(path).relative_to(root).as_posix()

    def add(identifier, base, *, path=None, manifest=None, expected=("AUTHENTIC",),
            checks=None, start=None, passphrase=None, wrong_key=False, corrections=0, purpose=""):
        source = outputs[base]
        case = dict(source["case"], id=identifier,
                    media=rel(path or source["result"].stego_path),
                    manifest=rel(manifest or source["result"].manifest_path),
                    public_key="keys/public/unrelated_public.pem" if wrong_key else "keys/public/submission_public.pem",
                    expected_verdicts=list(expected), minimum_corrections=corrections, purpose=purpose,
                    expected_hash_checks=checks or dict.fromkeys(CHECK_NAMES, "Yes" if expected == ("AUTHENTIC",) else "Not performed"))
        if start is not None:
            case["start_secret"] = start
        if passphrase is not None:
            case["passphrase"] = passphrase
        cases.append(case)
        return case

    def protect(identifier, cover_name, payload_name, depth, *, manual=False, encrypt=False,
                repetition=False, file_payload=False, match=False):
        cover, payload = original / cover_name, original / payload_name
        message = payload.read_bytes()
        ecc = ErrorCorrectionParameters(constants.ECC_REPETITION, 3) if repetition else None
        result = protect_media(
            cover, protected / (identifier + cover.suffix), message, private,
            media_id=identifier, lsb_depth=depth,
            start_method=constants.START_METHOD_MANUAL if manual else constants.START_METHOD_HMAC,
            manual_start_location=37 if manual else None, start_secret=None if manual else START,
            passphrase=PASSPHRASE if encrypt else None, ecc=ecc, match_cover_size=match,
            metadata=payload_files.metadata_for_file(payload, message) if file_payload else None)
        # protect_media measures the complete encoded envelope before publication.
        outputs[identifier] = dict(result=result, case=dict(
            cover=rel(cover), payload=rel(payload), payload_sha256=hashlib.sha256(message).hexdigest(),
            payload_bytes=len(message), file_payload=file_payload, lsb_depth=depth,
            start_method=result.record.start_method, start_location=result.start_location,
            start_secret=None if manual else START, passphrase=PASSPHRASE if encrypt else None,
            repetition=3 if repetition else 1))
        add(identifier, identifier, purpose="Protected positive")
        print(f"Protected {identifier}", flush=True)

    for depth in range(1, 9):
        protect(f"image-short-depth{depth}", "image_cover.png", "short_text_payload.txt", depth, manual=True)
    protect("image-long", "image_cover.png", "text_payload.txt", 1, match=True)
    protect("image-file", "image_cover.png", "image_payload.png", 2, file_payload=True)
    protect("image-encrypted", "encryption_cover.png", "custom_text_payload.txt", 2, encrypt=True)
    protect("image-audio-file", "encryption_cover.png", "audio_cover.wav", 3, file_payload=True)
    protect("audio-long", "audio_cover.wav", "text_payload.txt", 1, manual=True)
    protect("audio-large-file", "audio_cover.wav", "huge_text_payload .txt", 2, file_payload=True)
    protect("audio-robust", "audio_cover.wav", "text_payload.txt", 1, manual=True, repetition=True)
    protect("video-text", "forest-cover.mkv", "text_payload.txt", 1)
    protected_hashes = {rel(p): digest(p) for p in protected.iterdir() if p.is_file()}

    for identifier, base, attack in (
        ("image-message-corrupt", "image-short-depth1", "payload.message"),
        ("audio-signature-corrupt", "audio-long", "payload.signature"),
        ("image-outside-payload", "image-short-depth1", "image.outside"),
    ):
        result = outputs[base]["result"]
        target = tampered / (identifier + Path(result.stego_path).suffix)
        run = registry.run_attack(attack, registry.context_from_protect_result(result, str(target)), public)
        if not run.matched_expectation:
            raise RuntimeError(run.as_text())
        expected = ("AUTHENTIC",) if attack == "image.outside" else ("SIGNATURE_INVALID",)
        add(identifier, base, path=target, expected=expected, purpose=run.outcome.description)
        attacks.append(run.as_dict())

    for base, factor in (("audio-long", 1), ("audio-robust", 3)):
        result = outputs[base]["result"]
        raw = media.extract(result.stego_path, 1, result.start_location)
        for copies in ((1,) if factor == 1 else (1, 2)):
            damaged = bytearray(raw)
            for copy in range(copies):
                damaged[(copy + 1) * (len(raw) // factor) - 1] ^= 1
            identifier = f"audio-repetition{factor}-damage{copies}"
            target = tampered / (identifier + ".wav")
            media.embed(result.stego_path, target, bytes(damaged), 1, result.start_location)
            recovered = factor == 3 and copies == 1
            add(identifier, base, path=target, expected=("AUTHENTIC" if recovered else "SIGNATURE_INVALID",),
                corrections=1 if recovered else 0, purpose=f"Last signature bit flipped in {copies} stored copies")

    for base in ("image-short-depth1", "image-encrypted"):
        result = outputs[base]["result"]
        target = tampered / (base + "-hash-mismatch.manifest.json")
        changed = "00" * 32 if result.manifest.message_hash != "00" * 32 else "11" * 32
        manifest_module.write_manifest(replace(result.manifest, message_hash=changed), target)
        add(base + "-hash-mismatch", base, manifest=target, expected=("TAMPERED",),
            checks=dict(zip(CHECK_NAMES, ("No", "No", "Yes"), strict=True)), purpose="Only external message hash changed")
    add("audio-wrong-key", "audio-long", wrong_key=True, expected=("SIGNATURE_INVALID",), purpose="Unchanged media; unrelated key")
    result = outputs["audio-large-file"]["result"]
    for attempt in range(64):
        wrong_start = f"sample-wrong-start-{attempt}"
        context = registry.context_from_manifest(result.stego_path, result.manifest_path, "unused.wav", start_secret=wrong_start)
        if context.start_location != result.start_location:
            break
    else:
        raise RuntimeError("No distinct wrong start found")
    add("audio-wrong-start", "audio-large-file", start=wrong_start,
        expected=("PAYLOAD_MISSING", "CANNOT_VERIFY", "SIGNATURE_INVALID"), purpose="Unchanged media; distinct derived location")
    add("image-wrong-passphrase", "image-encrypted", passphrase="sample-wrong-passphrase",
        expected=("CANNOT_VERIFY",), checks=dict(zip(CHECK_NAMES, ("Not performed", "Yes", "Not performed"), strict=True)),
        purpose="Unchanged media; wrong decryption passphrase")

    for kind, name in (("image", "image_cover.png"), ("audio", "audio_cover.wav")):
        target = protected / ("capacity-rejected" + Path(name).suffix)
        payload = original / ("image_payload.png" if kind == "image" else "huge_text_payload .txt")
        message = payload.read_bytes()
        try:
            protect_media(original / name, target, message, private,
                          media_id=f"capacity-{kind}", lsb_depth=1, start_method=constants.START_METHOD_MANUAL,
                          manual_start_location=37, metadata=payload_files.metadata_for_file(payload, message))
        except CapacityError as exc:
            if target.exists() or Path(str(target) + ".manifest.json").exists():
                raise RuntimeError("Rejected capacity attempt created output") from exc
            capacities.append(dict(id=f"capacity-{kind}", cover=rel(original / name),
                                   payload=rel(payload), depth=1, start=37,
                                   rejected=True, output_created=False, reason=str(exc)))
        else:
            raise RuntimeError("Capacity case unexpectedly fitted")
    if {rel(p): digest(p) for p in protected.iterdir() if p.is_file()} != protected_hashes:
        raise RuntimeError("Attack changed a protected original")
    if {name: digest(original / name) for name in ORIGINALS} != originals_before:
        raise RuntimeError("Supplied original changed")
    metrics = []
    for identifier, source in outputs.items():
        result = source["result"]
        cover = root / source["case"]["cover"]
        metrics.append(dict(id=identifier, quality=quality_metrics.compare_quality(
            cover, result.stego_path, lsb_depth=result.record.lsb_depth).as_dict(),
            size=(result.size_preservation or size_outcome(cover, result.stego_path)).as_dict(),
            envelope_bytes=result.envelope_length, embedded_bytes=result.embed_result.payload_length,
            manifest_bytes=Path(result.manifest_path).stat().st_size))
    video = outputs["video-text"]["result"]
    descriptor = video_stego.describe_only(original / "forest-cover.mkv")
    written = video_stego.describe_only(video.stego_path)
    first = video.start_location // descriptor.samples_per_frame
    last = (video.start_location + video.embed_result.samples_written - 1) // descriptor.samples_per_frame
    changed_frames = [i for i, (a, b) in enumerate(zip(video_stego.iterate_frames(original / "forest-cover.mkv"),
                                                       video_stego.iterate_frames(video.stego_path), strict=True)) if np.any(a != b)]
    if not changed_frames or any(i < first or i > last for i in changed_frames):
        raise RuntimeError("Video modifications outside the embedded span")
    if (descriptor.width, descriptor.height, descriptor.frame_count, descriptor.frame_rate) != (
            written.width, written.height, written.frame_count, written.frame_rate):
        raise RuntimeError("Video properties changed")
    screenshots = {"image-short-depth1", "audio-long", "image-message-corrupt", "audio-signature-corrupt",
                   "audio-repetition3-damage2", "audio-repetition3-damage1", "image-encrypted", "image-file",
                   "image-audio-file", "image-outside-payload", "image-short-depth1-hash-mismatch", "video-text"}
    for case in cases:
        if case["id"] in screenshots:
            case["screenshot"] = f"screenshots/{case['id']}.png"
    index = dict(schema="submission-samples-v1", notice="Public demonstration inputs only; not real secrets.",
                 cases=cases, capacity_cases=capacities)
    if len(cases) != 27 or len(capacities) != 2:
        raise RuntimeError("Unexpected case count")
    write_json(evidence / "case-index.json", index)
    write_json(evidence / "logs/generation.json", dict(
        created_utc=datetime.now(UTC).isoformat(), python=platform.python_version(), platform=platform.platform(),
        base_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        state="Uncommitted submission generation changes", originals_sha256=originals_before,
        sender_fingerprint=key_manager.public_key_fingerprint(public), protected_unchanged_by_attacks=True,
        capacity_checks=capacities, video=dict(width=written.width, height=written.height,
        frames=written.frame_count, fps=written.frame_rate, changed_frames=changed_frames,
        claimed_span=[first, last], output_video_only=True, native_playback_tested=False)))
    write_json(evidence / "logs/quality-and-size.json", metrics)
    write_json(evidence / "logs/attacks.json", attacks)
    checksums = {rel(p): digest(p) for p in (root / "samples").rglob("*") if p.is_file()}
    for p in (public_dir / "submission_public.pem", public_dir / "unrelated_public.pem", evidence / "case-index.json"):
        checksums[rel(p)] = digest(p)
    write_json(evidence / "checksums.json", checksums)
    report = verify(root)
    write_json(evidence / "logs/verification.json", report)
    write_csv(evidence / "verification-results.csv", report, index)
    if not report["passed"]:
        raise RuntimeError("Sample verification failed; inspect verification.json")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--public-key", type=Path)
    args = parser.parse_args()
    report = build(args.root, args.private_key, args.public_key)
    print(json.dumps(dict(passed=report["passed"], cases=len(report["cases"]), capacity_checks=len(report["capacity_checks"]))))


if __name__ == "__main__":
    main()
