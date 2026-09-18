# Sample media

Run the R11 generator from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\generate_samples.py --output samples\r11 --overwrite
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
```

The generated `r11/` directory contains deterministic covers and message bytes,
fresh cryptographic artifacts, sender evidence, and a standalone receiver folder.
Its own README and case indexes describe every expected outcome.

The pre-existing `audio/original/original.wav` and `audio/stego/stego.wav` files
are retained as legacy low-level audio-LSB examples. They are not signed bundles,
have no companion manifest, and must not be presented as authentication evidence.
