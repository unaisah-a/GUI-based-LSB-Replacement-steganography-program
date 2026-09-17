"""Media detection and carrier-capacity helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.stego import image_io
from app.stego.audio_stego import HEADER_BYTES as AUDIO_HEADER_BYTES
from app.stego.audio_stego import audio_to_samples, read_audio
from app.stego.capacity import LENGTH_HEADER_BYTES, required_position_count
from app.stego.image_stego import embeddable_stream


@dataclass(frozen=True)
class CarrierInfo:
    media_type: str
    total_samples: int
    carrier_header_bytes: int
    description: dict[str, object]

    def required_samples(self, payload_length: int, lsb_count: int) -> int:
        return required_position_count(
            payload_length + self.carrier_header_bytes, lsb_count
        )


def inspect_carrier(path: str | Path, media_type: str | None = None) -> CarrierInfo:
    """Inspect a supported cover object and count eligible scalar samples."""
    source = Path(path)
    candidates = (media_type,) if media_type else ("image", "audio")
    failures: list[str] = []
    for candidate in candidates:
        if candidate == "image":
            try:
                array, descriptor = image_io.load_image(source)
                stream, usable_channels = embeddable_stream(array)
                return CarrierInfo(
                    "image",
                    int(stream.size),
                    LENGTH_HEADER_BYTES,
                    {
                        "container": descriptor.container_format,
                        "width": descriptor.width,
                        "height": descriptor.height,
                        "channels": descriptor.channel_count,
                        "embeddable_channels": usable_channels,
                    },
                )
            except Exception as exc:
                failures.append(f"image: {exc}")
        elif candidate == "audio":
            try:
                samples, sample_rate = read_audio(source)
                channels = 1 if samples.ndim == 1 else int(samples.shape[1])
                return CarrierInfo(
                    "audio",
                    int(audio_to_samples(samples).size),
                    AUDIO_HEADER_BYTES,
                    {
                        "container": "WAV/PCM-16",
                        "sample_rate": sample_rate,
                        "channels": channels,
                        "frames": int(samples.shape[0]),
                    },
                )
            except Exception as exc:
                failures.append(f"audio: {exc}")
        else:
            raise ValueError("media_type must be image or audio")
    raise ValueError(
        f"{source.name} is not a supported image or PCM-16 WAV file ("
        + "; ".join(failures)
        + ")"
    )
