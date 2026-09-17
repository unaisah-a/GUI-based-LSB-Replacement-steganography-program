## Audio Steganography Limitations

- The baseline implementation supports PCM-16 WAV only.
- Lossy formats such as MP3 are not supported because lossy
  encoding can modify or destroy LSB data.
- Increasing the number of LSBs increases capacity but may also
  increase distortion.
- The fixed packet magic value "INF2005" is not secret and could
  theoretically be detected by exhaustive scanning.
- A passcode-derived start location makes the embedding position
  less predictable, but start-location secrecy is not equivalent
  to payload encryption.
- Basic LSB embedding is fragile against operations such as
  resampling, compression and deliberate sample modification.

## Payload confidentiality boundary

- AES-256-GCM encrypts the stored message, but the signed record contains the
  SHA-256 hash of the recovered plaintext. That visible hash can confirm guesses
  of short or predictable messages. Encryption therefore protects the message
  bytes but does not make low-entropy message content resistant to offline
  guessing. Use messages with sufficient entropy or include unpredictable
  context when that threat matters.
- Envelope version 1 binds interpretation by requiring the unauthenticated
  encryption header flag to agree with the signed encryption metadata. Invalid,
  missing, duplicate, non-canonical or wrongly typed controlling fields are
  rejected before the application acts on them.
