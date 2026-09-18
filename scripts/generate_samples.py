"""Generate the reproducible R11 sender/receiver sample bundle.

Cover pixels/samples and message bytes are deterministic. Cryptographic keys,
nonces, and derived-start secrets are intentionally fresh on every run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import wave
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.attacks.experiments import run_attack_experiment
from app.crypto.encryption import encode_key, generate_encryption_key
from app.crypto.hashing import compute_sha256
from app.crypto.key_manager import (
    generate_rsa_keys,
    public_key_fingerprint,
    save_public_key_to_pem,
)
from app.services.protection import ProtectionOptions, protect_media
from app.services.video import run_lossy_video_experiment
from app.stego import image_io
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


SHORT_MESSAGE = (
    "Explain how steganography can be used to embed hidden verification data "
    "in image and audio cover objects."
)
LONG_MESSAGE = (
    "This undergraduate project requires student teams to design, implement and "
    "demonstrate a GUI-based LSB Replacement steganography program (window-based "
    "or web-based) that protects and verifies both image and audio cover objects "
    "using steganography, hashing and digital signatures.\n\n"
    "The project focuses on practical cybersecurity concepts: hiding a "
    "verification payload inside an image and an audio file, signing relevant "
    "verification data, extracting the hidden payload, checking the digital "
    "signature, and demonstrating positive and negative verification cases. "
    "Video as a cover object is not required for the main assignment, but may "
    "be attempted as an optional challenge."
)
CONFIDENTIAL_MESSAGE = (
    "Fictional confidential demo: incident response token IR-2047; rotate before "
    "the 16:30 exercise. This value has no operational use."
)

BUNDLE_FORMAT = "SMIV-SAMPLE-BUNDLE"
BUNDLE_VERSION = 1


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_messages(root: Path) -> dict[str, Path]:
    messages = root / "messages"
    messages.mkdir(parents=True)
    values = {
        "short": SHORT_MESSAGE,
        "long": LONG_MESSAGE,
        "confidential": CONFIDENTIAL_MESSAGE,
    }
    result: dict[str, Path] = {}
    for name, value in values.items():
        path = messages / f"{name}.txt"
        path.write_bytes(value.encode("utf-8"))
        result[name] = path
    _write_json(
        messages / "sources.json",
        {
            "source_document": "INF2005-ACW1-spec_v5-f2f.pdf",
            "short": "INF2005 ACW1 Learning Outcome 1; PDF layout whitespace normalised.",
            "long": "INF2005 ACW1 Project Overview; PDF layout whitespace normalised.",
            "confidential": "Fictional, non-operational payload created for this demonstration.",
        },
    )
    return result


def _create_image(path: Path, width: int = 320, height: int = 240) -> None:
    y, x = np.indices((height, width), dtype=np.uint16)
    pixels = np.stack(
        ((x * 5 + y * 3) % 256, (x * 2 + y * 7) % 256, (x * 11 + y) % 256),
        axis=2,
    ).astype(np.uint8)
    image_io.save_image(pixels, path, image_io.PNG)


def _create_audio(path: Path, *, channels: int, frames: int, rate: int) -> None:
    sample_index = np.arange(frames, dtype=np.float64)
    waves = []
    for channel in range(channels):
        frequency = 330.0 + channel * 220.0
        values = np.rint(12_000 * np.sin(2 * np.pi * frequency * sample_index / rate))
        waves.append(values.astype("<i2"))
    samples = waves[0] if channels == 1 else np.column_stack(waves).reshape(-1)
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as stream:
        stream.setnchannels(channels)
        stream.setsampwidth(2)
        stream.setframerate(rate)
        stream.writeframes(samples.tobytes())


def _create_video(path: Path, audio_path: Path) -> None:
    if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
        raise RuntimeError("FFmpeg and ffprobe are required to generate the video samples")
    height, width, frame_count = 64, 96, 6
    y, x = np.indices((height, width), dtype=np.uint16)
    frames = []
    for frame in range(frame_count):
        frames.append(
            np.stack(
                (
                    (x * 3 + y * 2 + frame * 17) % 256,
                    (x + y * 5 + frame * 29) % 256,
                    (x * 7 + y + frame * 11) % 256,
                ),
                axis=2,
            ).astype(np.uint8)
        )
    command = [
        "ffmpeg",
        "-v",
        "error",
        "-y",
        "-f",
        "rawvideo",
        "-pixel_format",
        "rgb24",
        "-video_size",
        f"{width}x{height}",
        "-framerate",
        "6",
        "-i",
        "pipe:0",
        "-i",
        str(audio_path),
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-frames:v",
        str(frame_count),
        "-map_metadata",
        "-1",
        "-c:v",
        "ffv1",
        "-level",
        "3",
        "-pix_fmt",
        "bgr0",
        "-c:a",
        "pcm_s16le",
        "-fflags",
        "+bitexact",
        str(path),
    ]
    completed = subprocess.run(
        command,
        input=np.ascontiguousarray(frames).tobytes(),
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"FFmpeg could not generate the deterministic cover: {detail}")


def _portable(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {key: _portable(item, root) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_portable(item, root) for item in value]
    if isinstance(value, str):
        try:
            path = Path(value)
            if path.is_absolute() and path.is_relative_to(root):
                return path.relative_to(root).as_posix()
        except (OSError, ValueError):
            pass
    return value


def _copy_receiver_case(
    receiver: Path,
    case_id: str,
    media: Path,
    manifest: Path,
    message: Path | None,
) -> tuple[str, str, str | None]:
    directory = receiver / "cases" / case_id
    directory.mkdir(parents=True, exist_ok=True)
    media_copy = directory / f"media{media.suffix.lower()}"
    manifest_copy = directory / "manifest.json"
    shutil.copyfile(media, media_copy)
    shutil.copyfile(manifest, manifest_copy)
    message_copy: Path | None = None
    if message is not None:
        message_copy = directory / "expected-message.bin"
        shutil.copyfile(message, message_copy)
    return (
        media_copy.relative_to(receiver).as_posix(),
        manifest_copy.relative_to(receiver).as_posix(),
        None if message_copy is None else message_copy.relative_to(receiver).as_posix(),
    )


def _case(
    *,
    case_id: str,
    medium: str,
    purpose: str,
    media: Path,
    manifest: Path,
    message: Path | None,
    expected_verdict: str,
    receiver: Path,
    start_secret_ref: str | None = None,
    encryption_key_ref: str | None = None,
) -> dict[str, object]:
    media_path, manifest_path, message_path = _copy_receiver_case(
        receiver, case_id, media, manifest, message
    )
    return {
        "id": case_id,
        "medium": medium,
        "purpose": purpose,
        "media_path": media_path,
        "manifest_path": manifest_path,
        "expected_message_path": message_path,
        "expected_verdict": expected_verdict,
        "start_secret_ref": start_secret_ref,
        "encryption_key_ref": encryption_key_ref,
    }


def _protect(
    cover: Path,
    output: Path,
    manifest: Path,
    message: Path,
    private_key,
    options: ProtectionOptions,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    protect_media(
        cover,
        output,
        manifest,
        message.read_bytes(),
        private_key,
        options,
    )


def _inventory(root: Path) -> list[dict[str, object]]:
    records = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.name == "bundle-index.json":
            continue
        data = path.read_bytes()
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return records


def _publish(stage: Path, destination: Path, overwrite: bool) -> None:
    if destination.exists() and not overwrite:
        raise FileExistsError(f"sample bundle already exists: {destination}")
    backup: Path | None = None
    try:
        if destination.exists():
            backup = destination.with_name(f".{destination.name}.backup-{secrets.token_hex(6)}")
            os.replace(destination, backup)
        os.replace(stage, destination)
    except Exception:
        if backup is not None and backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    else:
        if backup is not None:
            shutil.rmtree(backup)


def generate_bundle(
    output_root: str | os.PathLike[str],
    *,
    overwrite: bool = False,
    include_video: bool = True,
) -> dict[str, object]:
    """Create and verify a complete R11 bundle, then publish it atomically."""
    destination = Path(output_root).resolve()
    if destination == destination.parent:
        raise ValueError("sample output must not be a filesystem root")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not overwrite:
        raise FileExistsError(f"sample bundle already exists: {destination}")
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=destination.parent))
    try:
        sender = stage / "sender"
        receiver = stage / "receiver"
        evidence = sender / "evidence"
        evidence.mkdir(parents=True)
        receiver.mkdir(parents=True)
        messages = _write_messages(stage)

        image_cover = sender / "image" / "original" / "deterministic-cover.png"
        tiny_cover = sender / "image" / "original" / "capacity-cover-8x8.png"
        mono_cover = sender / "audio" / "original" / "deterministic-mono.wav"
        stereo_cover = sender / "audio" / "original" / "deterministic-stereo.wav"
        video_audio = sender / "video" / "original" / "deterministic-audio.wav"
        video_cover = sender / "video" / "original" / "deterministic-cover.mkv"
        image_cover.parent.mkdir(parents=True)
        _create_image(image_cover)
        _create_image(tiny_cover, 8, 8)
        _create_audio(mono_cover, channels=1, frames=32_000, rate=16_000)
        _create_audio(stereo_cover, channels=2, frames=48_000, rate=24_000)
        if include_video:
            _create_audio(video_audio, channels=1, frames=8_000, rate=8_000)
            _create_video(video_cover, video_audio)

        private_key, public_key = generate_rsa_keys()
        public_path = receiver / "demo-public-key.pem"
        save_public_key_to_pem(public_key, public_path)
        fingerprint = public_key_fingerprint(public_key)
        start_secrets = {
            "audio_long": secrets.token_urlsafe(24),
            "image_confidential": secrets.token_urlsafe(24),
        }
        encryption_key = generate_encryption_key()
        secrets_path = receiver / "demo-only-secrets.json"
        _write_json(
            secrets_path,
            {
                "format": "SMIV-DEMO-SECRETS",
                "version": 1,
                "warning": (
                    "Fictional evidence-only values. Transfer real secrets separately "
                    "and never commit them. No signing private key is present."
                ),
                "start_secrets": start_secrets,
                "encryption_keys": {"image_confidential": encode_key(encryption_key)},
            },
        )

        cases: list[dict[str, object]] = []
        manifests = sender / "manifests"
        protected_image = sender / "image" / "protected" / "short-positive.png"
        image_manifest = manifests / "image-short-positive.json"
        _protect(
            image_cover,
            protected_image,
            image_manifest,
            messages["short"],
            private_key,
            ProtectionOptions(
                media_id="R11-IMAGE-SHORT",
                lsb_count=1,
                start_method="manual",
                start_location=257,
                metadata={"case": "image-short-positive", "source": "brief-learning-outcome-1"},
            ),
        )
        cases.append(
            _case(
                case_id="image-short-positive",
                medium="image",
                purpose="Required positive image case with the brief-derived short message.",
                media=protected_image,
                manifest=image_manifest,
                message=messages["short"],
                expected_verdict=Verdict.AUTHENTIC.value,
                receiver=receiver,
            )
        )

        tampered_image = sender / "image" / "tampered" / "message-corruption.png"
        tampered_image.parent.mkdir(parents=True, exist_ok=True)
        image_attack = run_attack_experiment(
            protected_image,
            image_manifest,
            public_key,
            "message-corruption",
            output_path=tampered_image,
        )
        _write_json(evidence / "image-message-corruption.json", _portable(image_attack.to_dict(), stage))
        cases.append(
            _case(
                case_id="image-message-corruption-negative",
                medium="image",
                purpose="Required negative image case with a measured embedded-message mutation.",
                media=tampered_image,
                manifest=image_manifest,
                message=None,
                expected_verdict=image_attack.outcome.verdict,
                receiver=receiver,
            )
        )

        protected_audio = sender / "audio" / "protected" / "long-positive.wav"
        audio_manifest = manifests / "audio-long-positive.json"
        _protect(
            mono_cover,
            protected_audio,
            audio_manifest,
            messages["long"],
            private_key,
            ProtectionOptions(
                media_id="R11-AUDIO-LONG",
                lsb_count=2,
                start_method="hmac-sha256",
                start_secret=start_secrets["audio_long"],
                metadata={"case": "audio-long-positive", "source": "brief-project-overview"},
            ),
        )
        cases.append(
            _case(
                case_id="audio-long-positive",
                medium="audio",
                purpose="Required positive mono-audio case with the brief-derived long message.",
                media=protected_audio,
                manifest=audio_manifest,
                message=messages["long"],
                expected_verdict=Verdict.AUTHENTIC.value,
                receiver=receiver,
                start_secret_ref="audio_long",
            )
        )
        tampered_audio = sender / "audio" / "tampered" / "signature-corruption.wav"
        tampered_audio.parent.mkdir(parents=True, exist_ok=True)
        audio_attack = run_attack_experiment(
            protected_audio,
            audio_manifest,
            public_key,
            "signature-corruption",
            output_path=tampered_audio,
            start_secret=start_secrets["audio_long"],
        )
        _write_json(evidence / "audio-signature-corruption.json", _portable(audio_attack.to_dict(), stage))
        cases.append(
            _case(
                case_id="audio-signature-corruption-negative",
                medium="audio",
                purpose="Required negative audio case with a measured signature mutation.",
                media=tampered_audio,
                manifest=audio_manifest,
                message=None,
                expected_verdict=audio_attack.outcome.verdict,
                receiver=receiver,
                start_secret_ref="audio_long",
            )
        )

        confidential_image = sender / "image" / "protected" / "confidential-positive.png"
        confidential_manifest = manifests / "image-confidential-positive.json"
        _protect(
            image_cover,
            confidential_image,
            confidential_manifest,
            messages["confidential"],
            private_key,
            ProtectionOptions(
                media_id="R11-IMAGE-CONFIDENTIAL",
                lsb_count=2,
                start_method="hmac-sha256",
                start_secret=start_secrets["image_confidential"],
                encryption_key=encryption_key,
                metadata={"case": "image-confidential-positive", "fictional": True},
            ),
        )
        cases.append(
            _case(
                case_id="image-confidential-positive",
                medium="image",
                purpose="AES-256-GCM confidentiality and signed plaintext-integrity demonstration.",
                media=confidential_image,
                manifest=confidential_manifest,
                message=messages["confidential"],
                expected_verdict=Verdict.AUTHENTIC.value,
                receiver=receiver,
                start_secret_ref="image_confidential",
                encryption_key_ref="image_confidential",
            )
        )

        robust_audio = sender / "audio" / "protected" / "robust-stereo.wav"
        robust_manifest = manifests / "audio-robust-stereo.json"
        _protect(
            stereo_cover,
            robust_audio,
            robust_manifest,
            messages["short"],
            private_key,
            ProtectionOptions(
                media_id="R11-AUDIO-ROBUST",
                lsb_count=2,
                start_method="manual",
                start_location=509,
                robustness="repetition-3",
                metadata={"case": "audio-robust-stereo"},
            ),
        )
        cases.append(
            _case(
                case_id="audio-robust-stereo-positive",
                medium="audio",
                purpose="Stereo PCM repetition-3 extension baseline.",
                media=robust_audio,
                manifest=robust_manifest,
                message=messages["short"],
                expected_verdict=Verdict.AUTHENTIC.value,
                receiver=receiver,
            )
        )
        corrected_audio = sender / "audio" / "tampered" / "robust-one-copy.wav"
        corrected_audio.parent.mkdir(parents=True, exist_ok=True)
        corrected = run_attack_experiment(
            robust_audio,
            robust_manifest,
            public_key,
            "message-corruption",
            output_path=corrected_audio,
            fault_copies=1,
        )
        _write_json(evidence / "audio-robust-one-copy.json", _portable(corrected.to_dict(), stage))
        cases.append(
            _case(
                case_id="audio-robust-one-copy-corrected",
                medium="audio",
                purpose="One repetition-copy fault is corrected and remains authentic.",
                media=corrected_audio,
                manifest=robust_manifest,
                message=messages["short"],
                expected_verdict=corrected.outcome.verdict,
                receiver=receiver,
            )
        )
        rejected_audio = sender / "audio" / "tampered" / "robust-two-copy.wav"
        rejected = run_attack_experiment(
            robust_audio,
            robust_manifest,
            public_key,
            "message-corruption",
            output_path=rejected_audio,
            fault_copies=2,
        )
        _write_json(evidence / "audio-robust-two-copy.json", _portable(rejected.to_dict(), stage))
        cases.append(
            _case(
                case_id="audio-robust-two-copy-negative",
                medium="audio",
                purpose="Two repetition-copy faults exceed the demonstrated correction boundary.",
                media=rejected_audio,
                manifest=robust_manifest,
                message=None,
                expected_verdict=rejected.outcome.verdict,
                receiver=receiver,
            )
        )

        capacity_output = sender / "image" / "protected" / "capacity-must-not-exist.png"
        capacity_manifest = manifests / "capacity-must-not-exist.json"
        try:
            _protect(
                tiny_cover,
                capacity_output,
                capacity_manifest,
                messages["long"],
                private_key,
                ProtectionOptions(
                    media_id="R11-CAPACITY-REJECTION",
                    lsb_count=1,
                    start_method="manual",
                    start_location=0,
                ),
            )
        except ValueError as exc:
            capacity_error = str(exc)
        else:
            raise RuntimeError("capacity rejection fixture unexpectedly fit the tiny cover")
        if capacity_output.exists() or capacity_manifest.exists():
            raise RuntimeError("capacity rejection fixture published an output")
        _write_json(
            receiver / "capacity-rejection.json",
            {
                "id": "image-capacity-rejection",
                "expected": "REJECTED_BEFORE_OUTPUT",
                "actual": "REJECTED_BEFORE_OUTPUT",
                "error": capacity_error,
                "cover": "sender-only deterministic 8x8 RGB PNG",
                "output_created": False,
            },
        )

        if include_video:
            protected_video = sender / "video" / "protected" / "short-positive.mkv"
            video_manifest = manifests / "video-short-positive.json"
            _protect(
                video_cover,
                protected_video,
                video_manifest,
                messages["short"],
                private_key,
                ProtectionOptions(
                    media_id="R11-VIDEO-SHORT",
                    lsb_count=3,
                    start_method="manual",
                    start_location=17,
                    video_frame_index=2,
                    metadata={"case": "video-short-positive"},
                ),
            )
            cases.append(
                _case(
                    case_id="video-short-positive",
                    medium="video",
                    purpose="FFV1 selected-frame extension with PCM audio remuxing.",
                    media=protected_video,
                    manifest=video_manifest,
                    message=messages["short"],
                    expected_verdict=Verdict.AUTHENTIC.value,
                    receiver=receiver,
                )
            )
            lossy_video = sender / "video" / "tampered" / "h264-lossy-negative.mkv"
            lossy_video.parent.mkdir(parents=True, exist_ok=True)
            lossy = run_lossy_video_experiment(
                protected_video,
                lossy_video,
                video_manifest,
                public_key,
                crf=23,
            )
            if lossy.verification_verdict == Verdict.AUTHENTIC.value:
                raise RuntimeError("lossy video fixture unexpectedly remained authentic")
            _write_json(evidence / "video-h264-lossy.json", _portable(lossy.to_dict(), stage))
            cases.append(
                _case(
                    case_id="video-h264-lossy-negative",
                    medium="video",
                    purpose="Measured H.264 lossy-transcode verification failure.",
                    media=lossy_video,
                    manifest=video_manifest,
                    message=None,
                    expected_verdict=lossy.verification_verdict,
                    receiver=receiver,
                )
            )

        receiver_index = {
            "format": "SMIV-RECEIVER-BUNDLE",
            "version": 1,
            "public_key": public_path.relative_to(receiver).as_posix(),
            "public_key_fingerprint": fingerprint,
            "demo_secrets": secrets_path.relative_to(receiver).as_posix(),
            "cases": cases,
            "capacity_case": "capacity-rejection.json",
            "private_signing_key_included": False,
        }
        _write_json(receiver / "case-index.json", receiver_index)

        from scripts.verify_sample_bundle import verify_receiver_bundle

        verification = verify_receiver_bundle(receiver)
        if not verification["all_passed"]:
            raise RuntimeError("generated receiver bundle did not reproduce its expected outcomes")
        _write_json(receiver / "verification-report.json", verification)

        readme = r"""# R11 reproducible evidence bundle

The image pixels, PCM samples, video frames, and three message files are generated
deterministically. The short and long text use whitespace-normalised wording from
the assignment brief. The custom message is fictional and non-operational.

The generator creates a fresh RSA signing key, AES-256-GCM key, start secrets, and
payload nonces each time. It discards the signing private key after generation.
Only the public key and clearly labelled evidence-only AES/start values are placed
in `receiver/`; this lets a receiver reproduce every expected result without
sender memory or a private signing key. In a real transfer, secret values must use
a separate secure channel and must not be committed.

From the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\generate_samples.py --output samples\r11 --overwrite
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
```

`receiver/case-index.json` is the authoritative case list. It contains required
positive and negative image/audio cases, confidentiality, repetition-3 robustness,
capacity rejection, and FFV1/H.264 video extension evidence. JSON reports under
`sender/evidence/` record the actual paired verification outcomes.
"""
        (stage / "README.md").write_text(readme, encoding="utf-8")
        index = {
            "format": BUNDLE_FORMAT,
            "version": BUNDLE_VERSION,
            "cover_generation": "deterministic",
            "cryptographic_generation": "fresh-on-every-run",
            "public_key_fingerprint": fingerprint,
            "messages": {
                name: {
                    "path": path.relative_to(stage).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": compute_sha256(path.read_bytes()),
                }
                for name, path in messages.items()
            },
            "case_count": len(cases),
            "case_path_base": "receiver",
            "cases": cases,
            "capacity_case": "receiver/capacity-rejection.json",
            "files": _inventory(stage),
        }
        _write_json(stage / "bundle-index.json", index)
        _publish(stage, destination, overwrite)
        return index
    except Exception:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "samples" / "r11")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--skip-video",
        action="store_true",
        help="Omit optional video fixtures when FFmpeg is unavailable.",
    )
    args = parser.parse_args(argv)
    result = generate_bundle(
        args.output, overwrite=args.overwrite, include_video=not args.skip_video
    )
    print(
        f"Generated {result['case_count']} cases at {args.output.resolve()} "
        f"with public-key fingerprint {result['public_key_fingerprint']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
