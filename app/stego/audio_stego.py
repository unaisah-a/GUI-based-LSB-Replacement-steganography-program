"""
The code:
1) Opens the original WAV.
2) Converts audio samples into numbers.
3) Converts the payload into bits.
4) Replaces selected least significant bits in the samples.
5) Saves the modified samples as a new WAV.

"""

"""
Audio LSB Steganography

Baseline audio steganography for INF2005 ACW1.

Supports:
- 16-bit PCM WAV audio
- Mono and multi-channel audio
- LSB replacement using 1-8 selectable LSBs
- Payload capacity checking
- Payload embedding and extraction
- Manual or passcode-derived start location
"""

from pathlib import Path
from math import ceil

import numpy as np
import soundfile as sf

try:
    from app.crypto.start_location import calculate_audio_start_location
except ImportError:
    calculate_audio_start_location = None


MAGIC = b"INF2005"
LENGTH_BYTES = 4
HEADER_BYTES = len(MAGIC) + LENGTH_BYTES
SUPPORTED_FORMAT = "WAV"
SUPPORTED_SUBTYPE = "PCM_16"


def read_audio(input_path):
    """Read a supported 16-bit PCM WAV file."""
    input_path = Path(input_path)

    if not input_path.is_file():
        raise FileNotFoundError(f"Audio file not found: {input_path}")

    info = sf.info(str(input_path))

    if info.format != SUPPORTED_FORMAT:
        raise ValueError(
            f"Unsupported audio format '{info.format}'. "
            "Only WAV is supported."
        )

    if info.subtype != SUPPORTED_SUBTYPE:
        raise ValueError(
            f"Unsupported WAV subtype '{info.subtype}'. "
            "Only 16-bit PCM WAV (PCM_16) is supported."
        )

    samples, sample_rate = sf.read(
        str(input_path),
        dtype="int16",
        always_2d=False,
    )

    if samples.size == 0:
        raise ValueError("Audio file contains no samples.")

    return samples, sample_rate


def write_audio(output_path, samples, sample_rate):
    """Write stego audio as 16-bit PCM WAV."""
    output_path = Path(output_path)

    if output_path.suffix.lower() != ".wav":
        raise ValueError("Output file must use the .wav extension.")

    samples = np.asarray(samples, dtype=np.int16)

    sf.write(
        str(output_path),
        samples,
        sample_rate,
        format="WAV",
        subtype=SUPPORTED_SUBTYPE,
    )


def validate_lsb_count(lsb_count):
    """Validate that the selected LSB count is an integer from 1 to 8."""
    if isinstance(lsb_count, bool) or not isinstance(lsb_count, int):
        raise TypeError("lsb_count must be an integer")

    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be between 1 and 8")


def validate_start_location(start_location, total_samples):
    """Validate a flattened sample index used as the embedding start."""
    if isinstance(start_location, bool) or not isinstance(start_location, int):
        raise TypeError("start_location must be an integer")

    if total_samples <= 0:
        raise ValueError("Audio contains no usable samples")

    if start_location < 0:
        raise ValueError("start_location cannot be negative")

    if start_location >= total_samples:
        raise ValueError(
            f"start_location must be between 0 and {total_samples - 1}"
        )


def audio_to_samples(samples):
    """Flatten mono/stereo/multi-channel samples into scalar sample values."""
    return np.asarray(samples, dtype=np.int16).reshape(-1)


def samples_to_audio(flat_samples, original_shape):
    """Restore a flattened scalar-sample array to the original audio shape."""
    return np.asarray(flat_samples, dtype=np.int16).reshape(original_shape)


def get_channel_count(samples):
    """Return the number of channels represented by a SoundFile sample array."""
    return 1 if samples.ndim == 1 else int(samples.shape[1])


def bytes_to_bits(data):
    """Convert bytes to an MSB-first NumPy array of bits."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if not data:
        return np.array([], dtype=np.uint8)

    return np.unpackbits(
        np.frombuffer(data, dtype=np.uint8),
        bitorder="big",
    )


def bits_to_bytes(bits):
    """Convert an MSB-first sequence of bits to bytes."""
    bits = np.asarray(bits, dtype=np.uint8)

    if bits.size % 8 != 0:
        raise ValueError("Number of bits must be divisible by 8")

    if bits.size == 0:
        return b""

    if np.any((bits != 0) & (bits != 1)):
        raise ValueError("bits must contain only 0 and 1")

    return np.packbits(bits, bitorder="big").tobytes()


def build_packet(payload):
    """
    Build:
        MAGIC | 4-byte big-endian payload length | payload
    """
    if not isinstance(payload, bytes):
        raise TypeError("Payload must be bytes")

    max_payload_length = (1 << (8 * LENGTH_BYTES)) - 1
    if len(payload) > max_payload_length:
        raise ValueError("Payload is too large for the 4-byte length field")

    return (
        MAGIC
        + len(payload).to_bytes(LENGTH_BYTES, byteorder="big")
        + payload
    )


def parse_packet(packet):
    """Validate a complete packet and return only its payload."""
    if not isinstance(packet, bytes):
        raise TypeError("packet must be bytes")

    if len(packet) < HEADER_BYTES:
        raise ValueError("Packet is too short")

    if packet[:len(MAGIC)] != MAGIC:
        raise ValueError("Invalid audio payload magic")

    length_start = len(MAGIC)
    length_end = length_start + LENGTH_BYTES
    payload_length = int.from_bytes(
        packet[length_start:length_end],
        byteorder="big",
    )

    payload_start = HEADER_BYTES
    payload_end = payload_start + payload_length

    if payload_end != len(packet):
        raise ValueError("Packet length does not match embedded payload length")

    return packet[payload_start:payload_end]


def samples_required_for_packet(packet_size_bytes, lsb_count):
    """Return scalar audio samples required to store a packet."""
    validate_lsb_count(lsb_count)

    if packet_size_bytes < 0:
        raise ValueError("packet_size_bytes cannot be negative")

    return ceil((packet_size_bytes * 8) / lsb_count)


def calculate_capacity(input_path, lsb_count=1, start_location=0):
    """
    Return maximum user payload size in bytes from a given manual start location.

    Header overhead is excluded from the returned payload capacity.
    """
    validate_lsb_count(lsb_count)

    samples, _ = read_audio(input_path)
    flat_samples = audio_to_samples(samples)
    total_samples = len(flat_samples)

    validate_start_location(start_location, total_samples)

    available_samples = total_samples - start_location
    available_bits = available_samples * lsb_count
    payload_capacity = (available_bits // 8) - HEADER_BYTES

    return max(0, int(payload_capacity))


def _resolve_start_location(
    samples,
    sample_rate,
    lsb_count,
    start_location=None,
    passcode=None,
):
    """
    Resolve either a manual start location or a passcode-derived location.

    Supplying both is rejected because they describe two different modes.
    """
    flat_samples = audio_to_samples(samples)
    total_samples = len(flat_samples)

    if start_location is not None and passcode is not None:
        raise ValueError(
            "Use either start_location or passcode, not both."
        )

    if passcode is not None:
        if calculate_audio_start_location is None:
            raise ImportError(
                "calculate_audio_start_location is unavailable. "
                "Add it to app/crypto/start_location.py."
            )

        channels = get_channel_count(samples)
        derived = calculate_audio_start_location(
            passcode=passcode,
            total_samples=total_samples,
            sample_rate=sample_rate,
            channels=channels,
            lsb_count=lsb_count,
        )
        validate_start_location(derived, total_samples)
        return derived, "passcode"

    if start_location is None:
        start_location = 0

    validate_start_location(start_location, total_samples)
    return start_location, "manual"


def _iter_lsb_bits(flat_samples, start_location, lsb_count):
    """
    Yield embedded bits continuously from samples.

    This is important when lsb_count does not divide the 88-bit header
    exactly (for example 3, 5, 6 or 7 LSBs).
    """
    mask = (1 << lsb_count) - 1

    for sample_value in flat_samples[start_location:]:
        extracted_value = int(sample_value) & mask

        for bit_position in range(lsb_count - 1, -1, -1):
            yield (extracted_value >> bit_position) & 1


def _read_bits(bit_stream, count, error_message):
    """Read exactly count bits from an iterator or raise a controlled error."""
    output = []

    try:
        for _ in range(count):
            output.append(next(bit_stream))
    except StopIteration as exc:
        raise ValueError(error_message) from exc

    return output


def embed_audio_lsb(
    input_path,
    output_path,
    payload,
    lsb_count=1,
    start_location=None,
    passcode=None,
):
    """
    Embed payload bytes using LSB replacement.

    Start location can be supplied manually or derived from a passcode.
    """
    validate_lsb_count(lsb_count)

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    samples, sample_rate = read_audio(input_path)
    original_shape = samples.shape
    flat_samples = audio_to_samples(samples)
    total_samples = len(flat_samples)

    resolved_start, start_mode = _resolve_start_location(
        samples=samples,
        sample_rate=sample_rate,
        lsb_count=lsb_count,
        start_location=start_location,
        passcode=passcode,
    )

    packet = build_packet(payload)
    packet_bits = bytes_to_bits(packet)

    required_samples = samples_required_for_packet(
        len(packet),
        lsb_count,
    )
    available_samples = total_samples - resolved_start

    if required_samples > available_samples:
        capacity = calculate_capacity(
            input_path,
            lsb_count=lsb_count,
            start_location=resolved_start,
        )
        raise ValueError(
            "Payload too large for the selected start location. "
            f"Maximum payload capacity is {capacity} bytes."
        )

    stego_samples = flat_samples.copy()
    mask = (1 << lsb_count) - 1

    bit_index = 0
    sample_index = resolved_start

    while bit_index < len(packet_bits):
        remaining_bits = len(packet_bits) - bit_index
        bits_to_write = min(lsb_count, remaining_bits)

        value = 0
        for bit in packet_bits[bit_index:bit_index + bits_to_write]:
            value = (value << 1) | int(bit)

        # Pad only the final partial group on the right.
        value <<= (lsb_count - bits_to_write)

        original_sample = int(stego_samples[sample_index])
        cleared_sample = original_sample & ~mask
        stego_samples[sample_index] = cleared_sample | value

        bit_index += bits_to_write
        sample_index += 1

    stego_audio = samples_to_audio(stego_samples, original_shape)
    write_audio(output_path, stego_audio, sample_rate)

    capacity = calculate_capacity(
        input_path,
        lsb_count=lsb_count,
        start_location=resolved_start,
    )

    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "payload_size": len(payload),
        "packet_size": len(packet),
        "lsb_count": lsb_count,
        "start_location": resolved_start,
        "start_location_mode": start_mode,
        "capacity": capacity,
        "sample_rate": sample_rate,
        "channels": get_channel_count(samples),
        "total_scalar_samples": total_samples,
        "samples_modified_region": required_samples,
    }


def extract_audio_lsb(
    input_path,
    lsb_count=1,
    start_location=None,
    passcode=None,
):
    """
    Extract a payload from a stego WAV.

    Uses the same manual start index or passcode-derived location as embedding.
    """
    validate_lsb_count(lsb_count)

    samples, sample_rate = read_audio(input_path)
    flat_samples = audio_to_samples(samples)
    total_samples = len(flat_samples)

    resolved_start, _ = _resolve_start_location(
        samples=samples,
        sample_rate=sample_rate,
        lsb_count=lsb_count,
        start_location=start_location,
        passcode=passcode,
    )

    bit_stream = _iter_lsb_bits(
        flat_samples,
        resolved_start,
        lsb_count,
    )

    header_bits = _read_bits(
        bit_stream,
        HEADER_BYTES * 8,
        "Audio ended before a complete payload header could be extracted.",
    )
    header = bits_to_bytes(header_bits)

    if not header.startswith(MAGIC):
        raise ValueError(
            "Payload not found: wrong start location, passcode, "
            "LSB count, or audio has been altered."
        )

    length_start = len(MAGIC)
    length_end = length_start + LENGTH_BYTES
    payload_length = int.from_bytes(
        header[length_start:length_end],
        byteorder="big",
    )

    maximum_payload = calculate_capacity(
        input_path,
        lsb_count=lsb_count,
        start_location=resolved_start,
    )
    if payload_length > maximum_payload:
        raise ValueError(
            "Embedded payload length is invalid or the audio payload is corrupted."
        )

    payload_bits = _read_bits(
        bit_stream,
        payload_length * 8,
        "Audio ended before the payload was fully extracted.",
    )
    payload = bits_to_bytes(payload_bits)

    packet = header + payload
    return parse_packet(packet)