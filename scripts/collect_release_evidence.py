"""Collect portable, secret-free R12 release evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.media import inspect_carrier
from app.stego.video_stego import probe_video
from scripts.verify_sample_bundle import verify_receiver_bundle


DEPENDENCIES = (
    "numpy",
    "Pillow",
    "soundfile",
    "scipy",
    "cryptography",
    "PySide6",
    "pytest",
    "hypothesis",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool(name: str) -> dict[str, object]:
    executable = shutil.which(name)
    if executable is None:
        return {"available": False, "version": None}
    completed = subprocess.run(
        [executable, "-version"], capture_output=True, text=True, timeout=15, check=False
    )
    first_line = (completed.stdout or completed.stderr).splitlines()
    return {
        "available": completed.returncode == 0,
        "version": first_line[0] if first_line else "unknown",
    }


def _case(index: dict, case_id: str) -> dict:
    for value in index.get("cases", []):
        if value.get("id") == case_id:
            return value
    raise ValueError(f"receiver case is missing: {case_id}")


def _optional_tool_check(receiver: Path, index: dict) -> dict[str, object]:
    image = receiver / _case(index, "image-short-positive")["media_path"]
    audio = receiver / _case(index, "audio-long-positive")["media_path"]
    video = receiver / _case(index, "video-short-positive")["media_path"]
    with patch("app.stego.video_stego.shutil.which", return_value=None):
        image_type = inspect_carrier(image).media_type
        audio_type = inspect_carrier(audio).media_type
        try:
            probe_video(video)
        except RuntimeError as exc:
            video_error = str(exc)
        else:
            raise RuntimeError("video probing unexpectedly succeeded without FFmpeg tools")
    return {
        "image_without_ffmpeg": image_type,
        "audio_without_ffmpeg": audio_type,
        "video_error": video_error,
        "passed": image_type == "image" and audio_type == "audio" and "not found" in video_error,
    }


def collect_release_evidence(receiver_root: str | os.PathLike[str]) -> dict[str, object]:
    receiver = Path(receiver_root).resolve()
    index_path = receiver / "case-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    verification = verify_receiver_bundle(receiver)
    return {
        "format": "SMIV-RELEASE-AUDIT",
        "version": 1,
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
            "machine": platform.machine(),
        },
        "dependencies": {
            name: importlib.metadata.version(name) for name in DEPENDENCIES
        },
        "requirements_sha256": _sha256(PROJECT_ROOT / "requirements.txt"),
        "tools": {"ffmpeg": _tool("ffmpeg"), "ffprobe": _tool("ffprobe")},
        "receiver_bundle": {
            "case_index_sha256": _sha256(index_path),
            "public_key_fingerprint": verification["public_key_fingerprint"],
            "all_passed": verification["all_passed"],
            "capacity_case_passed": verification["capacity_case_passed"],
            "cases": [
                {
                    "id": case["id"],
                    "medium": case["medium"],
                    "expected_verdict": case["expected_verdict"],
                    "actual_verdict": case["actual_verdict"],
                    "message_matches": case["message_matches"],
                    "passed": case["passed"],
                }
                for case in verification["cases"]
            ],
        },
        "optional_tool_absence": _optional_tool_check(receiver, index),
        "scope": [
            "Verification authenticates the hidden signed message record, not every cover byte.",
            "Replay prevention requires an external freshness policy.",
            "Lossy-video results apply only to the recorded file, codec, and settings.",
            "Demonstration AES/start values are evidence-only and are not production secrets.",
        ],
        "contains_private_signing_key": False,
        "contains_secret_values": False,
    }


def write_release_evidence(report: dict[str, object], output_path: str | Path) -> None:
    destination = Path(output_path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receiver", type=Path, default=PROJECT_ROOT / "samples" / "r11" / "receiver"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "evidence" / "results" / "r12-release-audit.json",
    )
    args = parser.parse_args(argv)
    report = collect_release_evidence(args.receiver)
    write_release_evidence(report, args.output)
    passed = bool(
        report["receiver_bundle"]["all_passed"]
        and report["optional_tool_absence"]["passed"]
    )
    print(
        f"Release audit {'passed' if passed else 'failed'}: "
        f"{len(report['receiver_bundle']['cases'])} receiver cases."
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
