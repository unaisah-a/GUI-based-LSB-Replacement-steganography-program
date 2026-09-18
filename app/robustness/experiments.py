"""Deterministic repetition-3 corruption experiments and JSON evidence export."""

from __future__ import annotations

import json
import os
import random
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from app.robustness.redundancy import decode_repetition3, encode_repetition3
from app.stego.capacity import required_position_count


@dataclass(frozen=True)
class Corruption:
    source_byte_index: int
    bit_index: int
    repetition_copy: int


@dataclass(frozen=True)
class ExperimentMode:
    robustness: str
    stored_payload_bytes: int
    required_carrier_samples: int
    recovered_exactly: bool


@dataclass(frozen=True)
class RobustnessExperiment:
    seed: int
    payload_bytes: int
    lsb_count: int
    carrier_header_bytes: int
    corruptions: tuple[Corruption, ...]
    without_redundancy: ExperimentMode
    repetition_3: ExperimentMode
    scope: str = (
        "Controlled stored-bit corruption only; this does not claim resilience "
        "to compression, resampling, or arbitrary multi-copy damage."
    )

    def to_dict(self) -> dict:
        value = asdict(self)
        value["corruptions"] = list(value["corruptions"])
        return value


def run_repetition_experiment(
    payload: bytes,
    *,
    seed: int,
    corruption_count: int,
    lsb_count: int = 1,
    carrier_header_bytes: int = 4,
) -> RobustnessExperiment:
    """Compare identical seeded bit faults with and without repetition coding."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    for value, name in (
        (seed, "seed"),
        (corruption_count, "corruption_count"),
        (carrier_header_bytes, "carrier_header_bytes"),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
    if corruption_count < 0 or corruption_count > len(payload):
        raise ValueError("corruption_count must be between zero and payload length")
    if carrier_header_bytes < 0:
        raise ValueError("carrier_header_bytes must not be negative")

    rng = random.Random(seed)
    selected = rng.sample(range(len(payload)), corruption_count)
    plain = bytearray(payload)
    repeated = bytearray(encode_repetition3(payload))
    corruptions: list[Corruption] = []
    for source_index in selected:
        bit_index = rng.randrange(8)
        copy_index = rng.randrange(3)
        mask = 1 << bit_index
        plain[source_index] ^= mask
        repeated[source_index * 3 + copy_index] ^= mask
        corruptions.append(Corruption(source_index, bit_index, copy_index))

    decoded = decode_repetition3(bytes(repeated), len(payload))
    plain_stored = len(payload)
    repeated_stored = len(repeated)
    return RobustnessExperiment(
        seed=seed,
        payload_bytes=len(payload),
        lsb_count=lsb_count,
        carrier_header_bytes=carrier_header_bytes,
        corruptions=tuple(corruptions),
        without_redundancy=ExperimentMode(
            robustness="none",
            stored_payload_bytes=plain_stored,
            required_carrier_samples=required_position_count(
                carrier_header_bytes + plain_stored, lsb_count
            ),
            recovered_exactly=bytes(plain) == payload,
        ),
        repetition_3=ExperimentMode(
            robustness="repetition-3",
            stored_payload_bytes=repeated_stored,
            required_carrier_samples=required_position_count(
                carrier_header_bytes + repeated_stored, lsb_count
            ),
            recovered_exactly=decoded == payload,
        ),
    )


def export_repetition_experiment(
    result: RobustnessExperiment,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(result, RobustnessExperiment):
        raise TypeError("result must be a RobustnessExperiment")
    encoded = (json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    destination = Path(output_path).resolve()
    if not destination.parent.is_dir():
        raise FileNotFoundError("experiment output directory does not exist")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"experiment output already exists: {destination.name}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
