"""Build fresh T07 samples; refuses existing destinations and never saves private keys.

python -m scripts.build_sample_bundle --output samples/t07
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import numpy as np
import soundfile as sf
from PIL import Image

from app.analysis import quality_metrics
from app.analysis.size_preservation import size_outcome
from app.attacks import registry
from app.crypto import key_manager
from app.crypto.envelope import ErrorCorrectionParameters
from app.stego import image_io, media, video_stego
from app.stego.errors import CapacityError
from app.utils import constants, payload_files
from app.verification.protect import protect_media
from scripts.generate_samples import make_image_cover, make_video_cover
from scripts.verify_sample_bundle import sha256, verify_bundle

SHORT = ("Explain how steganography can be used to embed hidden verification data "
         "in image and audio cover objects.")
LONG = (
    "This undergraduate project requires student teams to design, implement and demonstrate a "
    "GUI-based LSB Replacement steganography program (window-based or web-based) that protects "
    "and verifies both image and audio cover objects using steganography, hashing and digital signatures.\n\n"
    "The project focuses on practical cybersecurity concepts: hiding a verification payload inside "
    "an image and an audio file, signing relevant verification data, extracting the hidden payload, "
    "checking the digital signature, and demonstrating positive and negative verification cases. "
    "Video as a cover object is not required for the main assignment, but may be attempted as an optional challenge."
)
CUSTOM = ("FICTIONAL DEMONSTRATION ONLY. Team Member 1 shares the draft release note with "
          "Team Member 2: inspect the image and audio examples before tomorrow's practice. "
          "AES-GCM protects this message's confidentiality; the signature and SHA-256 digest "
          "authenticate the payload. These public demo credentials protect no real information.")
DEMO = dict(notice="PUBLIC DEMONSTRATION VALUES ONLY. Never use for real messages.",
            start="t07-public-demo-start", passphrase="t07-public-demo-passphrase",
            wrong_passphrase="t07-deliberately-wrong-passphrase")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def build(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    sender, receiver = output / "party-a", output / "party-b"
    for folder in (sender / "original", sender / "protected", sender / "tampered",
                   sender / "messages", receiver):
        folder.mkdir(parents=True)
    private, public = key_manager.generate_key_pair(constants.RSA_KEY_SIZE_DEFAULT)
    _, wrong_public = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    key_manager.save_public_key(public, str(receiver / "sender-public.pem"))
    key_manager.save_public_key(wrong_public, str(receiver / "unrelated-public.pem"))
    for name, text in (("short", SHORT), ("long", LONG), ("custom", CUSTOM)):
        (sender / "messages" / (name + ".txt")).write_bytes(text.encode("utf-8"))
    write_json(sender / "messages" / "sources.json", dict(
        source_document="INF2005-ACW1-spec_v5-f2f.pdf", page=1,
        short="Learning Outcome 1, wording checked against the original PDF",
        long="Both Project Overview paragraphs; layout whitespace normalised",
        custom="Fictional demonstration authored for T07; no real confidential information"))
    image = sender / "original" / "image.png"
    make_image_cover(image)
    pixels, _ = image_io.load_image(image)
    bmp = sender / "original" / "image.bmp"
    bmp.write_bytes(image_io.encode_image(pixels, image_io.BMP))
    audio = sender / "original" / "audio-mono.wav"
    stereo = sender / "original" / "audio-stereo.wav"
    t = np.arange(44100) / 22050
    tones = np.column_stack((16000 * np.sin(2 * np.pi * 440 * t),
                             14000 * np.sin(2 * np.pi * 660 * t))).astype(np.int16)
    sf.write(audio, tones[:, 0], 22050, subtype="PCM_16")
    sf.write(stereo, tones, 22050, subtype="PCM_16")
    video = sender / "original" / "video.mkv"
    make_video_cover(video)
    payload_image = sender / "messages" / "payload.png"
    Image.fromarray(pixels[::10, ::10]).save(payload_image)
    payload_audio = sender / "messages" / "payload.wav"
    sf.write(payload_audio, tones[:2205, 0], 22050, subtype="PCM_16")

    cases, sender_rows, capacities = [], [], []
    originals = {p: sha256(p.read_bytes()) for p in (sender / "original").iterdir()}

    def transfer(path):
        path = Path(path)
        relative = path.relative_to(sender)
        target = receiver / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != path.read_bytes():
            raise ValueError(f"Conflicting receiver file: {relative}")
        if not target.exists():
            shutil.copy2(path, target)
        return relative.as_posix()

    def add_case(identifier, result, message, *, expected=("AUTHENTIC",), path=None,
                 start="start", passphrase=None, key="sender-public.pem", corrections=0, purpose=""):
        row = dict(id=identifier, media=transfer(path or result.stego_path),
                   manifest=transfer(result.manifest_path), public_key=key,
                   expected_verdicts=list(expected), start_secret=start, passphrase=passphrase,
                   message_sha256=sha256(message), message_bytes=len(message),
                   payload_kind=payload_files.detect_payload_type(message).kind,
                   expected_filename=result.record.metadata.get(payload_files.METADATA_FILENAME),
                   minimum_corrections=corrections, purpose=purpose,
                   depth=result.record.lsb_depth, start_method=result.record.start_method,
                   sender_start_location=result.start_location)
        cases.append(row)
        return row

    def protect(identifier, cover, message, *, depth=2, manual=False, encrypt=False,
                ecc=None, file_payload=None, match=False):
        metadata = dict(team="Member 1 / Member 2 / Member 3 / Member 4 / Member 5 (placeholders)")
        if file_payload:
            metadata.update(payload_files.metadata_for_file(file_payload, message))
        result = protect_media(
            cover, sender / "protected" / (identifier + cover.suffix), message, private,
            media_id=identifier, lsb_depth=depth, metadata=metadata, ecc=ecc,
            start_method=constants.START_METHOD_MANUAL if manual else constants.START_METHOD_HMAC,
            manual_start_location=37 if manual else None, start_secret=None if manual else DEMO["start"],
            passphrase=DEMO["passphrase"] if encrypt else None, match_cover_size=match)
        add_case(identifier, result, message, start=None if manual else "start",
                 passphrase="passphrase" if encrypt else None, purpose="Protected positive")
        outcome = result.size_preservation or size_outcome(cover, result.stego_path)
        sender_rows.append(dict(id=identifier, cover=transfer(cover),
                                message_source=str(file_payload.relative_to(sender)) if file_payload else None,
                                size=outcome.as_dict(), manifest_bytes=Path(result.manifest_path).stat().st_size,
                                quality=quality_metrics.compare_quality(cover, result.stego_path,
                                                                        lsb_depth=depth).as_dict()))
        return result

    short, long, custom = (text.encode("utf-8") for text in (SHORT, LONG, CUSTOM))
    image_short = protect("image-short", image, short, manual=True, match=True)
    audio_long = protect("audio-long", audio, long)
    encrypted = protect("image-confidential", image, custom, encrypt=True)
    protect("image-file", image, payload_image.read_bytes(), file_payload=payload_image, depth=4)
    protect("audio-file", stereo, payload_audio.read_bytes(), file_payload=payload_audio, depth=4)
    protect("bmp-manual", bmp, short, manual=True, depth=8)
    video_result = protect("video-positive", video, short, depth=1)
    descriptor = video_stego.describe_only(video)
    first = video_result.start_location // descriptor.samples_per_frame
    last = (video_result.start_location + video_result.embed_result.samples_written - 1) // descriptor.samples_per_frame
    changed_frames = [i for i, (before, after) in enumerate(zip(
        video_stego.iterate_frames(video), video_stego.iterate_frames(video_result.stego_path), strict=True))
        if np.any(before != after)]
    if not changed_frames or any(i < first or i > last for i in changed_frames):
        raise RuntimeError("Video changes do not match the payload frame span")
    video_evidence = dict(frames=descriptor.frame_count, fps=descriptor.frame_rate,
                          duration_seconds=descriptor.duration_seconds,
                          claimed_span=[first, last], actual_changed_frames=changed_frames,
                          source_audio_present=False, output_video_only=True)
    uncoded = protect("audio-uncoded", stereo, short, depth=1, manual=True)
    robust = protect("audio-robust", stereo, short, depth=1, manual=True,
                     ecc=ErrorCorrectionParameters(constants.ECC_REPETITION, 3))
    attacks = []
    for name, result, message, attack, start in (
        ("image-payload-corruption", image_short, short, "payload.message", None),
        ("audio-signature-corruption", audio_long, long, "payload.signature", "start"),
        ("image-outside-payload", image_short, short, "image.outside", None),
    ):
        target = sender / "tampered" / (name + Path(result.stego_path).suffix)
        run = registry.run_attack(attack, registry.context_from_protect_result(result, str(target)),
                                  public, start_secret=DEMO.get(start))
        if not run.matched_expectation:
            raise RuntimeError(run.as_text())
        add_case(name, result, message, path=target, start=start,
                 expected=sorted(run.outcome.expected_verdicts), purpose=run.outcome.description)
        attacks.append(run.as_dict())

    for result, factor in ((uncoded, 1), (robust, 3)):
        raw = media.extract(result.stego_path, 1, result.start_location)
        for copies in ((1,) if factor == 1 else (1, 2)):
            damaged = bytearray(raw)
            for copy in range(copies):
                damaged[(copy + 1) * (len(raw) // factor) - 1] ^= 1
            name = f"audio-repetition{factor}-damage{copies}"
            target = sender / "tampered" / (name + ".wav")
            media.embed(result.stego_path, target, bytes(damaged), 1, result.start_location)
            recovered = factor == 3 and copies == 1
            add_case(name, result, short, path=target, start=None,
                     expected=("AUTHENTIC" if recovered else "SIGNATURE_INVALID",),
                     corrections=1 if recovered else 0,
                     purpose=f"Last signature bit flipped in {copies} stored copy/copies; factor {factor}")
    add_case("audio-wrong-key", audio_long, long, key="unrelated-public.pem",
             expected=("SIGNATURE_INVALID",), purpose="Unrelated public key; media unchanged")
    for attempt in range(64):
        candidate = f"t07-public-wrong-start-{attempt}"
        context = registry.context_from_manifest(audio_long.stego_path, audio_long.manifest_path,
                                                  "unused.wav", start_secret=candidate)
        if context.start_location != audio_long.start_location:
            DEMO["wrong_start"] = candidate
            break
    else:
        raise RuntimeError("Could not demonstrate a distinct wrong start")
    add_case("audio-wrong-start", audio_long, long, start="wrong_start",
             expected=("PAYLOAD_MISSING", "CANNOT_VERIFY", "SIGNATURE_INVALID"),
             purpose="Different derived location; failure cause alone remains ambiguous")
    add_case("image-wrong-passphrase", encrypted, custom, passphrase="wrong_passphrase",
             expected=("CANNOT_VERIFY",), purpose="Signature can verify but decryption fails")

    for cover in (image, audio):
        maximum = media.measure(cover, 1, 37).report.max_payload_length
        message = b"X" * (maximum + 1)
        target = sender / "protected" / ("capacity-rejected" + cover.suffix)
        try:
            protect_media(cover, target, message, private, media_id="capacity-rejected", lsb_depth=1,
                          start_method=constants.START_METHOD_MANUAL, manual_start_location=37)
        except CapacityError as exc:
            if target.exists() or Path(str(target) + ".manifest.json").exists():
                raise RuntimeError("Capacity rejection published output") from exc
            capacities.append(dict(id="capacity-" + cover.suffix[1:], cover=transfer(cover),
                                   depth=1, start=37, message_bytes=len(message),
                                   sender_exception=type(exc).__name__, sender_reason=str(exc),
                                   output_created=False))
        else:
            raise RuntimeError("Oversized message was accepted")
    for path, original_hash in originals.items():
        if sha256(path.read_bytes()) != original_hash:
            raise RuntimeError("Original cover modified")
    write_json(receiver / "demo-only-secrets.json", DEMO)
    write_json(receiver / "case-index.json", dict(schema="t07-v2", cases=cases,
                                                   capacity_cases=capacities))
    write_json(sender / "generation-report.json", dict(cases=sender_rows, attacks=attacks,
                                                        capacity=capacities, video=video_evidence,
                                                        private_keys_saved=0))
    lines = ["# T07 case index", "", "Paths are relative to party-b. Explicitly select each listed manifest.",
             "", "| Case | Media | Manifest | Expected |", "| --- | --- | --- | --- |"]
    lines += [f"| {c['id']} | {c['media']} | {c['manifest']} | {', '.join(c['expected_verdicts'])} |"
              for c in cases]
    (output / "CASE_INDEX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Self-contained instructions travel with Party B as well as with the whole bundle.
    guide = Path(__file__).resolve().parents[1] / "docs" / "sample_bundle.md"
    shutil.copy2(guide, output / "README.md")
    shutil.copy2(guide, receiver / "README.md")
    inventory = {p.relative_to(receiver).as_posix(): sha256(p.read_bytes())
                 for p in sorted(receiver.rglob("*")) if p.is_file()}
    write_json(receiver / "checksums.json", inventory)
    # A convenient initial check; acceptance also requires a separate process.
    report = verify_bundle(receiver)
    if not report["passed"]:
        write_json(output / "failed-report.json", report)
        raise RuntimeError("Receiver cases did not match their expectations")
    write_json(output / "generation-verification.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.output)
    print(json.dumps(dict(cases=len(result["cases"]), passed=result["passed"], output=str(args.output))))
