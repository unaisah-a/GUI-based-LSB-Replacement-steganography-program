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