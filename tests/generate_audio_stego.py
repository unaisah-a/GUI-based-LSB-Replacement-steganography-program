"""Generate the committed demo stego WAV and print its quality report.

Not a test: the file name does not match pytest's ``test_*.py`` pattern, so it is
never collected. Run it directly after ``create_test_audio.py``:

    .venv\\Scripts\\python tests/generate_audio_stego.py

Updated for the current audio interface. It previously called
``embed_audio_lsb`` / ``extract_audio_lsb``, which no longer exist, and resolved
its paths against the working directory.

Note that this exercises the steganography layer on its own, with a raw byte
payload and no envelope. It is a distortion-measurement utility, not a
demonstration of the protect workflow; for that see the end-to-end tests, which go
through signing, the envelope and the companion manifest.
"""

from __future__ import annotations

from pathlib import Path

from app.analysis.audio_analysis import calculate_quality_report
from app.stego.audio_stego import embed_audio, extract_audio

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COVER = REPOSITORY_ROOT / "samples" / "audio" / "original" / "original.wav"

PAYLOAD = b"INF2005 Audio Steganography Test"
START_LOCATION = 100


def main(lsb_count: int = 4) -> None:
    if not COVER.is_file():
        raise SystemExit(
            f"cover not found: {COVER.relative_to(REPOSITORY_ROOT)}. "
            f"Run tests/create_test_audio.py first."
        )

    stego = (
        REPOSITORY_ROOT / "samples" / "audio" / "stego" / f"stego_lsb{lsb_count}.wav"
    )
    stego.parent.mkdir(parents=True, exist_ok=True)

    result = embed_audio(
        str(COVER),
        str(stego),
        PAYLOAD,
        lsb_count,
        START_LOCATION,
        # Regenerating the committed sample is the whole point of this script.
        overwrite=True,
    )

    print(f"wrote {stego.relative_to(REPOSITORY_ROOT)}")
    print(f"  depth {result.lsb_count}, start location {result.start_location}")
    print(
        f"  {result.payload_length} payload bytes in "
        f"{result.samples_written} of {result.descriptor.total_samples} samples"
    )
    print(f"  capacity at this depth: {result.capacity.max_payload_length} bytes")

    recovered = extract_audio(str(stego), lsb_count, START_LOCATION)
    if recovered != PAYLOAD:
        raise SystemExit("round trip failed: the recovered payload differs")
    print(f"  round trip verified: {recovered.decode('utf-8')!r}")

    print("\nquality report")
    for key, value in calculate_quality_report(
        str(COVER), str(stego), lsb_count=lsb_count
    ).items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
