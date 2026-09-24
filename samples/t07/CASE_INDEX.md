# T07 case index

Paths are relative to party-b. Explicitly select each listed manifest.

| Case | Media | Manifest | Expected |
| --- | --- | --- | --- |
| image-short | protected/image-short.png | protected/image-short.png.manifest.json | AUTHENTIC |
| audio-long | protected/audio-long.wav | protected/audio-long.wav.manifest.json | AUTHENTIC |
| image-confidential | protected/image-confidential.png | protected/image-confidential.png.manifest.json | AUTHENTIC |
| image-file | protected/image-file.png | protected/image-file.png.manifest.json | AUTHENTIC |
| audio-file | protected/audio-file.wav | protected/audio-file.wav.manifest.json | AUTHENTIC |
| bmp-manual | protected/bmp-manual.bmp | protected/bmp-manual.bmp.manifest.json | AUTHENTIC |
| video-positive | protected/video-positive.mkv | protected/video-positive.mkv.manifest.json | AUTHENTIC |
| audio-uncoded | protected/audio-uncoded.wav | protected/audio-uncoded.wav.manifest.json | AUTHENTIC |
| audio-robust | protected/audio-robust.wav | protected/audio-robust.wav.manifest.json | AUTHENTIC |
| image-payload-corruption | tampered/image-payload-corruption.png | protected/image-short.png.manifest.json | SIGNATURE_INVALID |
| audio-signature-corruption | tampered/audio-signature-corruption.wav | protected/audio-long.wav.manifest.json | SIGNATURE_INVALID |
| image-outside-payload | tampered/image-outside-payload.png | protected/image-short.png.manifest.json | AUTHENTIC |
| audio-repetition1-damage1 | tampered/audio-repetition1-damage1.wav | protected/audio-uncoded.wav.manifest.json | SIGNATURE_INVALID |
| audio-repetition3-damage1 | tampered/audio-repetition3-damage1.wav | protected/audio-robust.wav.manifest.json | AUTHENTIC |
| audio-repetition3-damage2 | tampered/audio-repetition3-damage2.wav | protected/audio-robust.wav.manifest.json | SIGNATURE_INVALID |
| audio-wrong-key | protected/audio-long.wav | protected/audio-long.wav.manifest.json | SIGNATURE_INVALID |
| audio-wrong-start | protected/audio-long.wav | protected/audio-long.wav.manifest.json | PAYLOAD_MISSING, CANNOT_VERIFY, SIGNATURE_INVALID |
| image-wrong-passphrase | protected/image-confidential.png | protected/image-confidential.png.manifest.json | CANNOT_VERIFY |
| analysis-noise-0 | protected/analysis-noise-0.png | protected/analysis-noise-0.png.manifest.json | AUTHENTIC |
| analysis-noise-1 | protected/analysis-noise-1.png | protected/analysis-noise-1.png.manifest.json | AUTHENTIC |
| analysis-noise-2 | protected/analysis-noise-2.png | protected/analysis-noise-2.png.manifest.json | AUTHENTIC |
| analysis-even-0 | protected/analysis-even-0.png | protected/analysis-even-0.png.manifest.json | AUTHENTIC |
| analysis-even-1 | protected/analysis-even-1.png | protected/analysis-even-1.png.manifest.json | AUTHENTIC |
| analysis-even-2 | protected/analysis-even-2.png | protected/analysis-even-2.png.manifest.json | AUTHENTIC |
| analysis-gradient-0 | protected/analysis-gradient-0.png | protected/analysis-gradient-0.png.manifest.json | AUTHENTIC |
| analysis-gradient-1 | protected/analysis-gradient-1.png | protected/analysis-gradient-1.png.manifest.json | AUTHENTIC |
| analysis-gradient-2 | protected/analysis-gradient-2.png | protected/analysis-gradient-2.png.manifest.json | AUTHENTIC |
