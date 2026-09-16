## Audio Steganography

### Supported cover format

The baseline implementation supports 16-bit PCM WAV files.
PCM-16 was selected because it provides uncompressed integer
sample values suitable for deterministic LSB replacement.

### Embedding

Audio samples are flattened into scalar sample values.

For stereo audio:

L0, R0, L1, R1, L2, R2, ...

The payload packet is:

MAGIC | PAYLOAD LENGTH | PAYLOAD

MAGIC:
INF2005

Payload length:
4-byte unsigned big-endian integer.

The user may select between 1 and 8 least-significant bits.

### Start location

Two modes are supported:

1. Manual start location
2. Passcode-derived HMAC-SHA256 start location

The passcode-derived approach allows the verifier to derive the
same position without storing the position directly.

### Extraction

The selected LSBs are read as a continuous bitstream. The magic
value is validated, the payload length is decoded, and the
specified number of payload bytes is extracted.