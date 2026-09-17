"""Deterministic media-copy attacks for negative verification demonstrations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.crypto.manifest import load_manifest
from app.stego import image_io
from app.stego.audio_stego import audio_to_samples, read_audio, samples_to_audio, write_audio
from app.stego.image_stego import embeddable_stream
from app.verification.verifier import resolve_start_location


@dataclass(frozen=True)
class AttackResult:
    input_path: str
    output_path: str
    media_type: str
    attack: str
    changed_sample_index: int
    detail: str


def _check_output(input_path: Path, output_path: Path, overwrite: bool) -> None:
    if input_path.resolve() == output_path.resolve():
        raise ValueError("attack output must be different from its input")
    if not output_path.parent.is_dir():
        raise FileNotFoundError("attack output directory does not exist")
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"attack output already exists: {output_path.name}")


def _mutate_sample(
    input_path: Path,
    output_path: Path,
    media_type: str,
    sample_index: int,
    bit_mask: int,
    overwrite: bool,
) -> None:
    _check_output(input_path, output_path, overwrite)
    if media_type == "image":
        array, descriptor = image_io.load_image(input_path)
        _, usable_channels = embeddable_stream(array)
        width = array.shape[1]
        row = sample_index // (width * usable_channels)
        remainder = sample_index % (width * usable_channels)
        column = remainder // usable_channels
        channel = remainder % usable_channels
        changed = array.copy()
        changed[row, column, channel] ^= np.uint8(bit_mask)
        image_io.save_image(
            changed,
            output_path,
            descriptor.container_format,
            overwrite=overwrite,
        )
    elif media_type == "audio":
        samples, sample_rate = read_audio(input_path)
        flat = audio_to_samples(samples).copy()
        unsigned = int(flat[sample_index]) & 0xFFFF
        unsigned ^= bit_mask
        flat[sample_index] = np.array(unsigned, dtype=np.uint16).view(np.int16)
        write_audio(output_path, samples_to_audio(flat, samples.shape), sample_rate)
    else:
        raise ValueError("only image and audio attacks are supported")


def corrupt_embedded_payload(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    *,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Flip a bit near the signed payload's end, normally invalidating its signature."""
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, carrier = resolve_start_location(source, manifest, start_secret)
    protected_bits = (
        carrier.carrier_header_bytes + max(0, manifest.payload_length - 2)
    ) * 8
    relative_sample = protected_bits // manifest.lsb_count
    target = start + relative_sample
    if target >= carrier.total_samples:
        raise ValueError("calculated attack position is outside the carrier")
    _mutate_sample(source, output, manifest.media_type, target, 1, overwrite)
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "corrupt-embedded-payload",
        target,
        "Flipped one least-significant bit near the signed payload boundary.",
    )


def modify_outside_payload(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    *,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Modify a sample outside the embedded region to demonstrate scope limits."""
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, carrier = resolve_start_location(source, manifest, start_secret)
    occupied = carrier.required_samples(manifest.payload_length, manifest.lsb_count)
    if start > 0:
        target = start - 1
    elif start + occupied < carrier.total_samples:
        target = start + occupied
    else:
        raise ValueError("the payload occupies every eligible carrier sample")
    _mutate_sample(source, output, manifest.media_type, target, 0x80, overwrite)
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "modify-outside-payload",
        target,
        "Flipped a high-order bit outside the embedded payload region.",
    )
