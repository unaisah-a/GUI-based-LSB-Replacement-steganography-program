"""Generate the committed demo WAV cover in ``samples/audio/original/``.

Not a test: the file name does not match pytest's ``test_*.py`` pattern, so it is
never collected. Run it directly to regenerate the sample media:

    .venv\\Scripts\\python tests/create_test_audio.py

Paths are resolved from this file's location rather than the working directory, so
the sample lands in the repository regardless of where the command is run.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import soundfile as sf

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPOSITORY_ROOT / "samples" / "audio" / "original" / "original.wav"

SAMPLE_RATE = 44_100
DURATION_SECONDS = 10
FREQUENCY_HZ = 440.0
AMPLITUDE = 0.3


def main() -> None:
    frame_count = SAMPLE_RATE * DURATION_SECONDS
    time = np.arange(frame_count, dtype=np.float64) / SAMPLE_RATE
    # Rounded to integers here rather than handed to soundfile as floats, so the
    # stored sample values are exactly what this script computed.
    samples = np.rint(
        AMPLITUDE * 32_767 * np.sin(2 * np.pi * FREQUENCY_HZ * time)
    ).astype(np.int16)

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    sf.write(str(TARGET), samples, SAMPLE_RATE, format="WAV", subtype="PCM_16")

    print(f"wrote {TARGET.relative_to(REPOSITORY_ROOT)}")
    print(f"  {DURATION_SECONDS} s, {SAMPLE_RATE} Hz, mono, PCM_16")
    print(f"  {frame_count} frames, {TARGET.stat().st_size} bytes")


if __name__ == "__main__":
    main()
