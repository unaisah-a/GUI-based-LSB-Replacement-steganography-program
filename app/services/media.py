"""Media detection and carrier-capacity helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.stego import image_io
from app.stego.audio_stego import HEADER_BYTES as AUDIO_HEADER_BYTES
from app.stego.audio_stego import audio_to_samples, read_audio
from app.stego.bit_utils import validate_lsb_depth
from app.stego.capacity import LENGTH_HEADER_BYTES, required_position_count


@dataclass(frozen=True)
class CarrierCapacity:
    """Exact carrier cost for one already-encoded payload."""

    total_samples: int
    lsb_count: int
    start_location: int
    carrier_header_bytes: int
    payload_length: int
    encoded_length: int
    required_samples: int
    available_samples: int
    highest_valid_start_location: int
    max_payload_length: int
    fits: bool
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

    def capacity(
        self, payload_length: int, lsb_count: int, start_location: int = 0
    ) -> CarrierCapacity:
        """Return the single capacity contract used by services and the GUI."""
        if isinstance(payload_length, bool) or not isinstance(payload_length, int):
            raise TypeError("payload_length must be a non-negative integer")
        if payload_length < 0:
            raise ValueError("payload_length must be a non-negative integer")
        if isinstance(start_location, bool) or not isinstance(start_location, int):
            raise TypeError("start_location must be a non-negative integer")
        if start_location < 0:
            raise ValueError("start_location must be a non-negative integer")
        depth = validate_lsb_depth(lsb_count)
        encoded_length = payload_length + self.carrier_header_bytes
        required = required_position_count(encoded_length, depth)
        available = max(0, self.total_samples - start_location)
        byte_capacity = (available * depth) // 8
        return CarrierCapacity(
            total_samples=self.total_samples,
            lsb_count=depth,
            start_location=start_location,
            carrier_header_bytes=self.carrier_header_bytes,
            payload_length=payload_length,
            encoded_length=encoded_length,
            required_samples=required,
            available_samples=available,
            highest_valid_start_location=self.total_samples - required,
            max_payload_length=max(0, byte_capacity - self.carrier_header_bytes),
            fits=required <= available,
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
