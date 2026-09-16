import hmac
import hashlib

def calculate_start_location(passcode: str, cover_capacity: int, payload_len: int) -> int:
    "FR7: Derives a secure start location using HMAC-SHA256 to prevent unauthorized discovery."
    if not passcode:
        raise ValueError("Passcode cannot be empty.")

    key = passcode.encode('utf-8')
    msg = str(cover_capacity).encode('utf-8')
    mac = hmac.new(key, msg, hashlib.sha256).digest()

    seed_int = int.from_bytes(mac, byteorder='big')
    max_start = cover_capacity - payload_len

    if max_start <= 0:
        raise ValueError(f"Payload capacity check failed: Payload ({payload_len} B) > Capacity ({cover_capacity} B).")

    return seed_int % max_start

def calculate_audio_start_location(
    passcode: str,
    total_samples: int,
    sample_rate: int,
    channels: int,
    lsb_count: int
) -> int:
    """
    Derive a reproducible start location for audio using HMAC-SHA256.

    Only information known during BOTH embedding and extraction is used.
    Payload length is deliberately excluded.
    """

    if not passcode:
        raise ValueError("Passcode cannot be empty.")

    if total_samples <= 0:
        raise ValueError("total_samples must be positive.")

    if sample_rate <= 0:
        raise ValueError("sample_rate must be positive.")

    if channels <= 0:
        raise ValueError("channels must be positive.")

    if not 1 <= lsb_count <= 8:
        raise ValueError("lsb_count must be between 1 and 8.")

    key = passcode.encode("utf-8")

    message = (
        f"INF2005|audio|{total_samples}|"
        f"{sample_rate}|{channels}|{lsb_count}"
    ).encode("utf-8")

    digest = hmac.new(
        key,
        message,
        hashlib.sha256
    ).digest()

    seed_int = int.from_bytes(
        digest,
        byteorder="big"
    )

    # Restrict the derived start to the first quarter
    # so most of the WAV remains available for payload data.
    start_region_size = max(
        1,
        total_samples // 4
    )

    return seed_int % start_region_size