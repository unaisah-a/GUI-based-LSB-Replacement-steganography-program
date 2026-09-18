import json
import shutil
import subprocess

import numpy as np
import pytest
import soundfile as sf

from app.crypto.encryption import generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
from app.services.media import inspect_carrier
from app.services.protection import ProtectionOptions, protect_media
from app.services.video import export_lossy_video_experiment, run_lossy_video_experiment
from app.stego import image_io
from app.stego.video_stego import (
    decode_video_frames,
    embed_video,
    extract_video,
    extract_video_bounded,
    probe_video,
)
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def video_cover(tmp_path_factory):
    if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
        pytest.skip("FFmpeg tools are unavailable")
    directory = tmp_path_factory.mktemp("video-cover")
    path = directory / "cover.mkv"
    completed = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=96x64:rate=6:duration=1",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=8000:duration=1",
            "-map",
            "0:v:0",
            "-map",
            "1:a:0",
            "-c:v",
            "ffv1",
            "-level",
            "3",
            "-pix_fmt",
            "bgr0",
            "-c:a",
            "pcm_s16le",
            str(path),
        ],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return path


def _audio_bytes(path):
    completed = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            str(path),
            "-map",
            "0:a:0",
            "-f",
            "s16le",
            "-acodec",
            "pcm_s16le",
            "pipe:1",
        ],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def test_ffv1_selected_frame_round_trip_preserves_frames_timing_and_audio(video_cover, tmp_path):
    output = tmp_path / "protected.mkv"
    payload = bytes(range(251)) * 2
    original_info = probe_video(video_cover)
    original_frames = decode_video_frames(video_cover, original_info)

    embedded = embed_video(video_cover, output, payload, 3, 17, 2)
    output_info = probe_video(output)
    output_frames = decode_video_frames(output, output_info)

    assert extract_video(output, 3, 17, 2, manifest_payload_length=len(payload)) == payload
    assert extract_video_bounded(output, len(payload), 3, 17, 2) == payload
    assert embedded.colour_bytes_verified is True
    assert output_info.codec_name == "ffv1"
    assert (output_info.width, output_info.height) == (96, 64)
    assert output_info.frame_count == original_info.frame_count == 6
    assert output_info.frame_rate == original_info.frame_rate == "6/1"
    assert output_info.duration_seconds == pytest.approx(
        original_info.duration_seconds, abs=1 / 6
    )
    assert output_info.audio_streams == original_info.audio_streams
    assert np.array_equal(output_frames[:2], original_frames[:2])
    assert np.array_equal(output_frames[3:], original_frames[3:])
    assert not np.array_equal(output_frames[2], original_frames[2])
    assert _audio_bytes(output) == _audio_bytes(video_cover)


def test_invalid_frame_and_missing_tools_fail_clearly_without_affecting_image(video_cover, tmp_path, monkeypatch):
    invalid_output = tmp_path / "invalid.mkv"
    with pytest.raises(ValueError, match="frame index"):
        embed_video(video_cover, invalid_output, b"payload", frame_index=99)
    assert not invalid_output.exists()

    from app.stego import video_stego

    monkeypatch.setattr(video_stego.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="ffprobe.*not found"):
        probe_video(video_cover)

    image = tmp_path / "still.png"
    image_io.save_image(np.zeros((16, 16, 3), dtype=np.uint8), image, image_io.PNG)
    assert inspect_carrier(image).media_type == "image"
    audio = tmp_path / "sound.wav"
    sf.write(audio, np.zeros(80, dtype=np.int16), 8_000, subtype="PCM_16")
    assert inspect_carrier(audio).media_type == "audio"


@pytest.fixture(scope="module")
def protected_video(video_cover, tmp_path_factory):
    directory = tmp_path_factory.mktemp("protected-video")
    output = directory / "protected.mkv"
    manifest = directory / "protected.json"
    private_key, public_key = generate_rsa_keys()
    encryption_key = generate_encryption_key()
    result = protect_media(
        video_cover,
        output,
        manifest,
        b"authenticated video payload",
        private_key,
        ProtectionOptions(
            media_id="VIDEO-ROUNDTRIP",
            lsb_count=2,
            start_method="manual",
            start_location=19,
            video_frame_index=3,
            encryption_key=encryption_key,
            robustness="repetition-3",
        ),
    )
    return output, manifest, public_key, encryption_key, result


def test_service_video_round_trip_authenticates_frame_settings(protected_video):
    output, manifest, public_key, encryption_key, result = protected_video
    verification = verify_media(
        output, manifest, public_key, encryption_key=encryption_key
    )
    document = json.loads(manifest.read_text(encoding="utf-8"))

    assert result.media_type == "video"
    assert result.carrier_result.frame_index == 3
    assert result.carrier_result.colour_bytes_verified is True
    assert result.carrier_result.audio_streams_preserved is True
    assert result.record["extraction"]["video_frame_index"] == 3
    assert document["video_frame_index"] == 3
    assert verification.verdict is Verdict.AUTHENTIC
    assert verification.message == b"authenticated video payload"


def test_manifest_frame_change_cannot_authenticate(protected_video, tmp_path):
    output, manifest, public_key, encryption_key, _result = protected_video
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["video_frame_index"] = 2
    changed = tmp_path / "changed-frame.json"
    changed.write_text(json.dumps(document), encoding="utf-8")
    verification = verify_media(
        output, changed, public_key, encryption_key=encryption_key
    )
    assert verification.verdict is not Verdict.AUTHENTIC


def test_lossy_transcode_records_actual_failed_verification(protected_video, tmp_path):
    output, manifest, public_key, encryption_key, _result = protected_video
    lossy = tmp_path / "lossy.mkv"
    evidence_path = tmp_path / "lossy-evidence.json"
    evidence = run_lossy_video_experiment(
        output,
        lossy,
        manifest,
        public_key,
        encryption_key=encryption_key,
        crf=23,
    )
    export_lossy_video_experiment(evidence, evidence_path)
    document = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert evidence.codec == "h264"
    assert evidence.selected_frame_differing_samples > 0
    assert evidence.verification_verdict != Verdict.AUTHENTIC.value
    assert document["verification_verdict"] == evidence.verification_verdict
    assert document["selected_frame"] == 3
    assert "does not predict every codec" in document["interpretation"]
    with pytest.raises(FileExistsError):
        export_lossy_video_experiment(evidence, evidence_path)
