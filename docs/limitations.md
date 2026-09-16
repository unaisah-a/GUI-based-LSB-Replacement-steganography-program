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