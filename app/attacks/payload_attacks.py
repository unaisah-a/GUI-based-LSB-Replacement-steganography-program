"""Deterministic media-copy attacks for negative verification demonstrations."""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.crypto.manifest import load_manifest
from app.crypto.payload import HEADER, parse_envelope
from app.robustness.redundancy import decode_repetition3
from app.stego import image_io
from app.stego.audio_stego import (
    audio_to_samples,
    extract_audio_lsb_bounded,
    read_audio,
    samples_to_audio,
    write_audio,
)
from app.stego.image_stego import embeddable_stream, extract_image_bounded
from app.verification.verifier import resolve_start_location


@dataclass(frozen=True)
class AttackResult:
    input_path: str
    output_path: str
    media_type: str
    attack: str
    changed_sample_index: int
    detail: str
    changed_sample_count: int = 1


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
    _edit_samples(
        input_path,
        output_path,
        media_type,
        {sample_index: bit_mask},
        {},
        overwrite,
    )


def _edit_samples(
    input_path: Path,
    output_path: Path,
    media_type: str,
    xor_masks: dict[int, int],
    clear_masks: dict[int, int],
    overwrite: bool,
) -> None:
    _check_output(input_path, output_path, overwrite)
    if media_type == "image":
        array, descriptor = image_io.load_image(input_path)
        _, usable_channels = embeddable_stream(array)
        width = array.shape[1]
        changed = array.copy()
        for sample_index in set(xor_masks) | set(clear_masks):
            row = sample_index // (width * usable_channels)
            remainder = sample_index % (width * usable_channels)
            column = remainder // usable_channels
            channel = remainder % usable_channels
            value = int(changed[row, column, channel])
            value &= ~clear_masks.get(sample_index, 0)
            value ^= xor_masks.get(sample_index, 0)
            changed[row, column, channel] = np.uint8(value)
        image_io.save_image(
            changed,
            output_path,
            descriptor.container_format,
            overwrite=overwrite,
        )
    elif media_type == "audio":
        samples, sample_rate = read_audio(input_path)
        flat = audio_to_samples(samples).copy()
        for sample_index in set(xor_masks) | set(clear_masks):
            unsigned = int(flat[sample_index]) & 0xFFFF
            unsigned &= ~clear_masks.get(sample_index, 0)
            unsigned ^= xor_masks.get(sample_index, 0)
            flat[sample_index] = np.array(unsigned, dtype=np.uint16).view(np.int16)
        write_audio(
            output_path,
            samples_to_audio(flat, samples.shape),
            sample_rate,
            overwrite=overwrite,
        )
    else:
        raise ValueError("only image and audio attacks are supported")


def _stored_payload(input_path: Path, manifest, start: int) -> bytes:
    if manifest.media_type == "image":
        return extract_image_bounded(
            str(input_path),
            manifest.lsb_count,
            start,
            manifest.embedded_payload_length,
        )
    if manifest.media_type == "audio":
        return extract_audio_lsb_bounded(
            input_path,
            manifest.embedded_payload_length,
            lsb_count=manifest.lsb_count,
            start_location=start,
        )
    raise ValueError("only image and audio attacks are supported")


def _carrier_bit(
    start: int, header_bytes: int, lsb_count: int, stored_bit_index: int
) -> tuple[int, int]:
    stream_bit = header_bytes * 8 + stored_bit_index
    sample = start + stream_bit // lsb_count
    offset = stream_bit % lsb_count
    return sample, 1 << (lsb_count - 1 - offset)


def _xor_stored_bits(
    source: Path,
    output: Path,
    manifest,
    start: int,
    header_bytes: int,
    stored_bits: list[int],
    overwrite: bool,
) -> tuple[int, int]:
    masks: dict[int, int] = {}
    for stored_bit in stored_bits:
        sample, mask = _carrier_bit(
            start, header_bytes, manifest.lsb_count, stored_bit
        )
        masks[sample] = masks.get(sample, 0) ^ mask
    masks = {sample: mask for sample, mask in masks.items() if mask}
    if not masks:
        raise ValueError("attack produced no carrier changes")
    _edit_samples(source, output, manifest.media_type, masks, {}, overwrite)
    return min(masks), len(masks)


def corrupt_envelope_region(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    region: str,
    *,
    copies: int = 1,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Flip one bit in a signed record, stored message, or signature region."""
    if region not in {"record", "message", "signature"}:
        raise ValueError("region must be record, message, or signature")
    if isinstance(copies, bool) or not isinstance(copies, int) or not 1 <= copies <= 3:
        raise ValueError("copies must be an integer from 1 to 3")
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, carrier = resolve_start_location(source, manifest, start_secret)
    stored = _stored_payload(source, manifest, start)
    envelope = (
        decode_repetition3(stored, manifest.payload_length)
        if manifest.robustness == "repetition-3"
        else stored
    )
    parsed = parse_envelope(envelope)
    record_start = HEADER.size
    message_start = record_start + len(parsed.record_bytes)
    signature_start = message_start + len(parsed.stored_message)
    bounds = {
        "record": (record_start, message_start),
        "message": (message_start, signature_start),
        "signature": (signature_start, len(envelope)),
    }
    lower, upper = bounds[region]
    if lower == upper:
        raise ValueError(f"the {region} region is empty")
    logical_byte = lower + (upper - lower) // 2
    if manifest.robustness == "repetition-3":
        stored_bits = [(logical_byte * 3 + copy) * 8 for copy in range(copies)]
    else:
        if copies != 1:
            raise ValueError("multiple copies apply only to repetition-3 payloads")
        stored_bits = [logical_byte * 8]
    first, count = _xor_stored_bits(
        source,
        output,
        manifest,
        start,
        carrier.carrier_header_bytes,
        stored_bits,
        overwrite,
    )
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        f"corrupt-{region}",
        first,
        f"Flipped one bit in {copies} stored copy/copies of the {region} region.",
        count,
    )


def add_seeded_payload_noise(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    *,
    seed: int,
    severity: int,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Flip a deterministic selection of unique bits in the stored payload."""
    for value, name in ((seed, "seed"), (severity, "severity")):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if severity < 1:
        raise ValueError("severity must be at least one bit")
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, carrier = resolve_start_location(source, manifest, start_secret)
    payload_bits = manifest.embedded_payload_length * 8
    if severity > payload_bits:
        raise ValueError("severity exceeds the stored payload bit count")
    selected = random.Random(seed).sample(range(payload_bits), severity)
    first, count = _xor_stored_bits(
        source,
        output,
        manifest,
        start,
        carrier.carrier_header_bytes,
        selected,
        overwrite,
    )
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "seeded-payload-noise",
        first,
        f"Flipped {severity} seeded bit(s) within the stored payload.",
        count,
    )


def erase_payload_tail(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    *,
    byte_count: int = 8,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Erase trailing stored payload bits while retaining a valid media container."""
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 1:
        raise ValueError("byte_count must be a positive integer")
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, carrier = resolve_start_location(source, manifest, start_secret)
    count = min(byte_count, manifest.embedded_payload_length)
    first_bit = (manifest.embedded_payload_length - count) * 8
    masks: dict[int, int] = {}
    for stored_bit in range(first_bit, manifest.embedded_payload_length * 8):
        sample, mask = _carrier_bit(
            start, carrier.carrier_header_bytes, manifest.lsb_count, stored_bit
        )
        masks[sample] = masks.get(sample, 0) | mask
    _edit_samples(source, output, manifest.media_type, {}, masks, overwrite)
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "erase-payload-tail",
        min(masks),
        f"Cleared the final {count} stored payload byte(s) to simulate truncation.",
        len(masks),
    )


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
    final_payload_bit = (
        carrier.carrier_header_bytes + manifest.embedded_payload_length
    ) * 8 - 1
    relative_sample = final_payload_bit // manifest.lsb_count
    bit_offset = final_payload_bit % manifest.lsb_count
    bit_mask = 1 << (manifest.lsb_count - 1 - bit_offset)
    target = start + relative_sample
    if target >= carrier.total_samples:
        raise ValueError("calculated attack position is outside the carrier")
    _mutate_sample(source, output, manifest.media_type, target, bit_mask, overwrite)
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "corrupt-embedded-payload",
        target,
        "Flipped the final stored payload bit near the expanded payload boundary.",
    )


def corrupt_transport_header(
    input_path: str | Path,
    output_path: str | Path,
    manifest_path: str | Path,
    *,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
) -> AttackResult:
    """Flip the first carrier-header bit without touching stored payload bytes."""
    source = Path(input_path)
    output = Path(output_path)
    manifest = load_manifest(manifest_path)
    start, _carrier = resolve_start_location(source, manifest, start_secret)
    bit_mask = 1 << (manifest.lsb_count - 1)
    _mutate_sample(source, output, manifest.media_type, start, bit_mask, overwrite)
    return AttackResult(
        str(source),
        str(output),
        manifest.media_type,
        "corrupt-transport-header",
        start,
        "Flipped the first carrier-header bit without changing payload bits.",
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
    occupied = carrier.required_samples(
        manifest.embedded_payload_length, manifest.lsb_count
    )
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
