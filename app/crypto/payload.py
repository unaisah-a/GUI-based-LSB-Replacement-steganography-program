import json
import struct
import time
import secrets
from cryptography.hazmat.primitives import hashes

def build_payload_block(media_bytes: bytes, media_id: str, metadata: dict = None) -> bytes:
    "FR3: Constructs JSON verification payload with media SHA-256, timestamp, nonce, 
    and metadata. Prepends 4-byte big-endian payload length header."

    if metadata is None:
        metadata = {}

    digest = hashes.Hash(hashes.SHA256())
    digest.update(media_bytes)
    media_hash = digest.finalize().hex()

    payload_dict = {
        "id": media_id,
        "ts": int(time.time()),
        "hash": media_hash,
        "nonce": secrets.token_hex(8),
        "meta": metadata
    }

    json_bytes = json.dumps(payload_dict, separators=(',', ':')).encode('utf-8')
    header = struct.pack(">I", len(json_bytes))
    return header + json_bytes

def parse_payload_block(raw_payload_block: bytes) -> dict:
    "Extracts JSON dictionary from raw payload bytes."
    payload_len = struct.unpack(">I", raw_payload_block[:4])[0]
    json_bytes = raw_payload_block[4 : 4 + payload_len]
    return json.loads(json_bytes.decode('utf-8'))