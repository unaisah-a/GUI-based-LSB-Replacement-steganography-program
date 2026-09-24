"""Development-only audio-track omission check; FFmpeg is not an app dependency."""
# ruff: noqa: E402 -- executable evidence script locates the repository first.
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import cv2

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.crypto import key_manager
from app.utils import constants
from app.verification.protect import protect_media
from app.verification.verifier import verify_media


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE)


def probe(tool, path):
    return json.loads(run(tool, "-v", "error", "-show_streams", "-of", "json", str(path)))


def decoded(path):
    capture = cv2.VideoCapture(str(path))
    fps = capture.get(cv2.CAP_PROP_FPS)
    frames = 0
    shape = None
    try:
        while True:
            ok, frame = capture.read()
            if not ok:
                break
            shape = frame.shape
            frames += 1
    finally:
        capture.release()
    return {"frames": frames, "fps": fps, "shape": shape, "duration": frames / fps}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ffmpeg, ffprobe = shutil.which("ffmpeg"), shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        parser.error("This development check requires ffmpeg and ffprobe on PATH")
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.output / "source-with-audio.mkv"
    original = ROOT / "samples/t07/party-a/original"
    run(ffmpeg, "-v", "error", "-nostdin", "-i", str(original / "video.mkv"),
        "-i", str(original / "audio-mono.wav"), "-map", "0:v:0", "-map", "1:a:0",
        "-c:v", "copy", "-c:a", "pcm_s16le", "-shortest", str(source))
    private, public = key_manager.generate_key_pair(constants.RSA_KEY_SIZE_DEFAULT)
    message = b"T08 video with source audio: authenticated video-only output."
    result = protect_media(source, args.output / "protected.mkv", message, private,
                           media_id="t08-audio-omission", lsb_depth=2,
                           start_method=constants.START_METHOD_MANUAL, manual_start_location=37)
    verified = verify_media(result.stego_path, result.manifest_path, public)
    source_probe, output_probe = probe(ffprobe, source), probe(ffprobe, result.stego_path)
    source_types = [stream["codec_type"] for stream in source_probe["streams"]]
    output_types = [stream["codec_type"] for stream in output_probe["streams"]]
    source_decoded, output_decoded = decoded(source), decoded(result.stego_path)
    assert "audio" in source_types and output_types == ["video"]
    assert output_probe["streams"][0]["codec_name"] == "ffv1"
    assert source_decoded == output_decoded
    assert verified.verdict == constants.VERDICT_AUTHENTIC and verified.message == message
    report = {"ffmpeg": run(ffmpeg, "-version").splitlines()[0],
              "source_streams": source_types, "output_streams": output_types,
              "source_decoded": source_decoded, "output_decoded": output_decoded,
              "verdict": verified.verdict, "exact_message": True,
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "output_sha256": hashlib.sha256(Path(result.stego_path).read_bytes()).hexdigest(),
              "private_key_saved": False}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
