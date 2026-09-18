"""Bounded FFmpeg/FFV1 selected-frame LSB video carrier."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

import numpy as np
import numpy.typing as npt

from app.stego.bit_utils import (
    bits_to_bytes,
    bytes_to_bits,
    groups_needed,
    pack_bits_to_groups,
    read_low_bits,
    unpack_groups_to_bits,
    validate_lsb_depth,
    write_low_bits,
)
from app.stego.capacity import LENGTH_HEADER_BYTES, required_position_count


MAX_VIDEO_WIDTH = 1_920
MAX_VIDEO_HEIGHT = 1_080
MAX_VIDEO_FRAMES = 300
MAX_DECODE_BYTES = 256 * 1024 * 1024
MAX_VIDEO_PAYLOAD_BYTES = 16 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 90
VIDEO_SAMPLE_WIDTH_BITS = 8


@dataclass(frozen=True)
class VideoInfo:
    path: str
    width: int
    height: int
    frame_count: int
    frame_rate: str
    duration_seconds: float
    codec_name: str
    pixel_format: str
    audio_streams: tuple[dict[str, object], ...]

    @property
    def samples_per_frame(self) -> int:
        return self.width * self.height * 3


@dataclass(frozen=True)
class VideoEmbedResult:
    output_path: str
    frame_index: int
    payload_length: int
    encoded_length: int
    samples_written: int
    frame_sha256_before: str
    frame_sha256_after: str
    colour_bytes_verified: bool
    frame_count: int
    frame_rate: str
    width: int
    height: int
    audio_streams_preserved: bool


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(
            f"{name} is required for video support but was not found on PATH"
        )
    return path


def _run(command: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            command,
            input=input_data,
            capture_output=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("video tool exceeded the configured time limit") from exc
    except OSError as exc:
        raise RuntimeError(f"video tool could not be started: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 1_000:
            detail = detail[-1_000:]
        raise RuntimeError(f"video tool failed: {detail or 'unknown error'}")
    return completed.stdout


def _fraction(value: str) -> Fraction:
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"unsupported video frame rate: {value!r}") from exc
    if result <= 0 or result > 240:
        raise ValueError("video frame rate is outside the supported range")
    return result


def probe_video(path: str | os.PathLike[str]) -> VideoInfo:
    """Inspect one bounded constant-frame-rate video with ffprobe."""
    source = Path(path).resolve()
    if not source.is_file():
        raise FileNotFoundError(f"video file not found: {source.name}")
    output = _run(
        [
            _tool("ffprobe"),
            "-v",
            "error",
            "-count_frames",
            "-show_entries",
            "format=duration:stream=index,codec_type,codec_name,pix_fmt,width,height,"
            "avg_frame_rate,r_frame_rate,nb_frames,nb_read_frames,sample_rate,channels,"
            "channel_layout,duration,time_base",
            "-of",
            "json",
            str(source),
        ]
    )
    try:
        document = json.loads(output.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("ffprobe returned invalid video metadata") from exc
    streams = document.get("streams")
    if not isinstance(streams, list):
        raise ValueError("video metadata does not contain streams")
    video_streams = [stream for stream in streams if stream.get("codec_type") == "video"]
    if len(video_streams) != 1:
        raise ValueError("video input must contain exactly one video stream")
    video = video_streams[0]
    try:
        width = int(video["width"])
        height = int(video["height"])
        frame_count = int(video.get("nb_read_frames") or video.get("nb_frames"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("video dimensions or frame count are unavailable") from exc
    if not 1 <= width <= MAX_VIDEO_WIDTH or not 1 <= height <= MAX_VIDEO_HEIGHT:
        raise ValueError(
            f"video dimensions exceed the {MAX_VIDEO_WIDTH}x{MAX_VIDEO_HEIGHT} limit"
        )
    if not 1 <= frame_count <= MAX_VIDEO_FRAMES:
        raise ValueError(
            f"video must contain between 1 and {MAX_VIDEO_FRAMES} frames"
        )
    decode_bytes = width * height * 3 * frame_count
    if decode_bytes > MAX_DECODE_BYTES:
        raise ValueError(
            f"decoded video exceeds the {MAX_DECODE_BYTES:,}-byte safety limit"
        )
    average_rate = str(video.get("avg_frame_rate") or "")
    average = _fraction(average_rate)
    duration_text = document.get("format", {}).get("duration") or video.get("duration")
    try:
        duration = float(duration_text)
    except (TypeError, ValueError):
        duration = frame_count / float(average)
    audio_streams = tuple(
        {
            "codec_name": str(stream.get("codec_name") or "unknown"),
            "sample_rate": int(stream["sample_rate"]) if stream.get("sample_rate") else None,
            "channels": int(stream["channels"]) if stream.get("channels") else None,
            "channel_layout": str(stream.get("channel_layout") or "unknown"),
        }
        for stream in streams
        if stream.get("codec_type") == "audio"
    )
    return VideoInfo(
        str(source),
        width,
        height,
        frame_count,
        f"{average.numerator}/{average.denominator}",
        duration,
        str(video.get("codec_name") or "unknown"),
        str(video.get("pix_fmt") or "unknown"),
        audio_streams,
    )


def _validate_frame_index(frame_index: object, frame_count: int) -> int:
    if isinstance(frame_index, bool) or not isinstance(frame_index, int):
        raise TypeError("video frame index must be an integer")
    if not 0 <= frame_index < frame_count:
        raise ValueError(
            f"video frame index must be between 0 and {frame_count - 1}"
        )
    return frame_index


def decode_video_frames(
    path: str | os.PathLike[str], info: VideoInfo | None = None
) -> npt.NDArray[np.uint8]:
    """Decode the bounded video stream to contiguous RGB colour bytes."""
    details = probe_video(path) if info is None else info
    raw = _run(
        [
            _tool("ffmpeg"),
            "-v",
            "error",
            "-i",
            str(Path(path).resolve()),
            "-map",
            "0:v:0",
            "-an",
            "-sn",
            "-dn",
            "-vsync",
            "0",
            "-frames:v",
            str(details.frame_count + 1),
            "-pix_fmt",
            "rgb24",
            "-f",
            "rawvideo",
            "pipe:1",
        ]
    )
    expected = details.frame_count * details.samples_per_frame
    if len(raw) != expected:
        raise ValueError(
            f"decoded frame data has {len(raw):,} bytes; expected {expected:,}"
        )
    return np.frombuffer(raw, dtype=np.uint8).reshape(
        details.frame_count, details.height, details.width, 3
    ).copy()


def decode_video_frame(
    path: str | os.PathLike[str], frame_index: int
) -> tuple[npt.NDArray[np.uint8], VideoInfo]:
    info = probe_video(path)
    index = _validate_frame_index(frame_index, info.frame_count)
    frames = decode_video_frames(path, info)
    return frames[index].copy(), info


def _validate_output(
    source: Path, output: Path, overwrite: bool
) -> None:
    if not isinstance(overwrite, bool):
        raise TypeError("overwrite must be a boolean")
    if source == output or (source.exists() and output.exists() and os.path.samefile(source, output)):
        raise ValueError("video output must differ from the input file")
    if not output.parent.is_dir():
        raise FileNotFoundError("video output directory does not exist")
    if output.is_dir():
        raise IsADirectoryError(f"video output is a directory: {output.name}")
    if output.exists() and not overwrite:
        raise FileExistsError(f"video output already exists: {output.name}")
    if output.suffix.lower() != ".mkv":
        raise ValueError("video output must use the .mkv Matroska extension")


def _encode_ffv1(
    frames: npt.NDArray[np.uint8], source: Path, output: Path, info: VideoInfo
) -> None:
    command = [
        _tool("ffmpeg"),
        "-v",
        "error",
        "-y",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "-video_size",
        f"{info.width}x{info.height}",
        "-framerate",
        info.frame_rate,
        "-i",
        "pipe:0",
        "-i",
        str(source),
        "-map",
        "0:v:0",
        "-map",
        "1:a?",
        "-map_metadata",
        "1",
        "-c:v",
        "ffv1",
        "-level",
        "3",
        "-coder",
        "1",
        "-context",
        "1",
        "-g",
        "1",
        "-pix_fmt",
        "bgr0",
        "-c:a",
        "copy",
        "-f",
        "matroska",
        str(output),
    ]
    _run(command, input_data=np.ascontiguousarray(frames).tobytes())


def embed_video(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    payload: bytes,
    lsb_count: int = 1,
    start_location: int = 0,
    frame_index: int = 0,
    *,
    overwrite: bool = False,
) -> VideoEmbedResult:
    """Embed one framed payload in one selected decoded RGB frame and save FFV1."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) > MAX_VIDEO_PAYLOAD_BYTES:
        raise ValueError("video payload exceeds the configured safety limit")
    depth = validate_lsb_depth(lsb_count)
    source = Path(input_path).resolve()
    destination = Path(output_path).resolve()
    _validate_output(source, destination, overwrite)
    info = probe_video(source)
    index = _validate_frame_index(frame_index, info.frame_count)
    if isinstance(start_location, bool) or not isinstance(start_location, int):
        raise TypeError("start_location must be an integer")
    frames = decode_video_frames(source, info)
    selected = frames[index]
    flat = selected.reshape(-1)
    if not 0 <= start_location < flat.size:
        raise ValueError(f"start_location must be between 0 and {flat.size - 1}")
    encoded = len(payload).to_bytes(LENGTH_HEADER_BYTES, "big") + payload
    bits = bytes_to_bits(encoded)
    required = groups_needed(int(bits.size), depth)
    if start_location + required > flat.size:
        raise ValueError(
            f"video payload needs {required} frame samples from start "
            f"{start_location}, but only {flat.size - start_location} are available"
        )
    before = hashlib.sha256(selected.tobytes()).hexdigest()
    groups = pack_bits_to_groups(bits, depth)
    flat[start_location : start_location + required] = write_low_bits(
        flat[start_location : start_location + required],
        groups,
        depth,
        VIDEO_SAMPLE_WIDTH_BITS,
    )
    after = hashlib.sha256(selected.tobytes()).hexdigest()

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", suffix=".mkv", dir=str(destination.parent)
    )
    os.close(descriptor)
    os.unlink(temporary_name)
    temporary = Path(temporary_name)
    try:
        _encode_ffv1(frames, source, temporary, info)
        output_info = probe_video(temporary)
        decoded = decode_video_frames(temporary, output_info)
        if decoded.shape != frames.shape or not np.array_equal(decoded, frames):
            raise RuntimeError("FFV1 output did not preserve the intended RGB colour bytes")
        if (
            output_info.frame_count != info.frame_count
            or output_info.width != info.width
            or output_info.height != info.height
            or Fraction(output_info.frame_rate) != Fraction(info.frame_rate)
        ):
            raise RuntimeError("FFV1 output changed video frame properties")
        frame_seconds = 1.0 / float(Fraction(info.frame_rate))
        if abs(output_info.duration_seconds - info.duration_seconds) > frame_seconds + 0.01:
            raise RuntimeError("FFV1 output changed video timing")
        audio_preserved = output_info.audio_streams == info.audio_streams
        if not audio_preserved:
            raise RuntimeError("FFV1 output changed compatible audio stream properties")
        if destination.exists() and not overwrite:
            raise FileExistsError(f"video output already exists: {destination.name}")
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return VideoEmbedResult(
        str(destination),
        index,
        len(payload),
        len(encoded),
        required,
        before,
        after,
        True,
        info.frame_count,
        info.frame_rate,
        info.width,
        info.height,
        True,
    )


def _frame_stream(path: str | os.PathLike[str], frame_index: int) -> npt.NDArray[np.uint8]:
    frame, _info = decode_video_frame(path, frame_index)
    return frame.reshape(-1)


def extract_video_bounded(
    input_path: str | os.PathLike[str],
    payload_length: int,
    lsb_count: int = 1,
    start_location: int = 0,
    frame_index: int = 0,
) -> bytes:
    if isinstance(payload_length, bool) or not isinstance(payload_length, int):
        raise TypeError("payload_length must be an integer")
    if not 0 <= payload_length <= MAX_VIDEO_PAYLOAD_BYTES:
        raise ValueError("payload_length is outside the supported range")
    depth = validate_lsb_depth(lsb_count)
    stream = _frame_stream(input_path, frame_index)
    if isinstance(start_location, bool) or not isinstance(start_location, int):
        raise TypeError("start_location must be an integer")
    required = required_position_count(LENGTH_HEADER_BYTES + payload_length, depth)
    if start_location < 0 or start_location + required > stream.size:
        raise ValueError("manifest-bounded video payload exceeds the selected frame")
    bits = unpack_groups_to_bits(
        read_low_bits(
            stream[start_location : start_location + required],
            depth,
            VIDEO_SAMPLE_WIDTH_BITS,
        ),
        depth,
    )
    header_bits = LENGTH_HEADER_BYTES * 8
    return bits_to_bytes(bits[header_bits : header_bits + payload_length * 8])


def extract_video(
    input_path: str | os.PathLike[str],
    lsb_count: int = 1,
    start_location: int = 0,
    frame_index: int = 0,
    *,
    manifest_payload_length: int | None = None,
) -> bytes:
    depth = validate_lsb_depth(lsb_count)
    stream = _frame_stream(input_path, frame_index)
    header_samples = required_position_count(LENGTH_HEADER_BYTES, depth)
    if start_location < 0 or start_location + header_samples > stream.size:
        raise ValueError("video payload header exceeds the selected frame")
    header_bits = unpack_groups_to_bits(
        read_low_bits(
            stream[start_location : start_location + header_samples],
            depth,
            VIDEO_SAMPLE_WIDTH_BITS,
        ),
        depth,
    )
    payload_length = int.from_bytes(
        bits_to_bytes(header_bits[: LENGTH_HEADER_BYTES * 8]), "big"
    )
    if payload_length > MAX_VIDEO_PAYLOAD_BYTES:
        raise ValueError("declared video payload length exceeds the safety limit")
    if manifest_payload_length is not None and payload_length != manifest_payload_length:
        raise ValueError("video payload length does not match the manifest")
    encoded_length = LENGTH_HEADER_BYTES + payload_length
    required = required_position_count(encoded_length, depth)
    if start_location + required > stream.size:
        raise ValueError("declared video payload exceeds the selected frame")
    bits = unpack_groups_to_bits(
        read_low_bits(
            stream[start_location : start_location + required],
            depth,
            VIDEO_SAMPLE_WIDTH_BITS,
        ),
        depth,
    )
    encoded = bits_to_bytes(bits[: encoded_length * 8])
    return encoded[LENGTH_HEADER_BYTES:]


def transcode_video_lossy(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    crf: int = 23,
    overwrite: bool = False,
) -> str:
    """Create a separate H.264 test copy; callers must measure verification."""
    if isinstance(crf, bool) or not isinstance(crf, int) or not 0 <= crf <= 51:
        raise ValueError("CRF must be an integer from 0 to 51")
    source = Path(input_path).resolve()
    destination = Path(output_path).resolve()
    _validate_output(source, destination, overwrite)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", suffix=".mkv", dir=str(destination.parent)
    )
    os.close(descriptor)
    os.unlink(temporary_name)
    temporary = Path(temporary_name)
    try:
        _run(
            [
                _tool("ffmpeg"),
                "-v",
                "error",
                "-y",
                "-i",
                str(source),
                "-map",
                "0:v:0",
                "-map",
                "0:a?",
                "-c:v",
                "libx264",
                "-crf",
                str(crf),
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "copy",
                "-f",
                "matroska",
                str(temporary),
            ]
        )
        probe_video(temporary)
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return str(destination)
