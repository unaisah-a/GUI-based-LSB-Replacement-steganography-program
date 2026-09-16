import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

RSA_SIG_SIZE = 256  # 2048-bit RSA produces 256-byte signatures
SIG_HEADER_SIZE = 4

def sign_payload_block(raw_payload_block: bytes, private_key) -> bytes:
    "FR4: Digitally signs payload block with RSA-PSS SHA-256.
    Appends 4-byte signature length header + 256-byte signature."

    signature = private_key.sign(
        raw_payload_block,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    sig_header = struct.pack(">I", len(signature))
    return raw_payload_block + sig_header + signature

def verify_signature(full_extracted_bytes: bytes, public_key) -> tuple[bytes, bool]:
    "FR4: Extracts signature and verifies authenticity against raw payload block."
    total_sig_block_len = SIG_HEADER_SIZE + RSA_SIG_SIZE
    if len(full_extracted_bytes) < total_sig_block_len + 4:
        return b"", False

    sig_start_idx = len(full_extracted_bytes) - total_sig_block_len
    raw_payload_block = full_extracted_bytes[:sig_start_idx]
    
    sig_len_bytes = full_extracted_bytes[sig_start_idx : sig_start_idx + SIG_HEADER_SIZE]
    extracted_sig_len = struct.unpack(">I", sig_len_bytes)[0]
    extracted_signature = full_extracted_bytes[sig_start_idx + SIG_HEADER_SIZE :]

    if extracted_sig_len != RSA_SIG_SIZE or len(extracted_signature) != RSA_SIG_SIZE:
        return raw_payload_block, False

    try:
        public_key.verify(
            extracted_signature,
            raw_payload_block,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return raw_payload_block, True
    except Exception:
        return raw_payload_block, False