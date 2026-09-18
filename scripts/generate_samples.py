"""Generate the committed demo media in ``samples/``, with manifests.

    .venv\\Scripts\\python scripts/generate_samples.py

For each medium this writes a cover under ``samples/<media>/original/`` and a protected
stego file with its ``.manifest.json`` under ``samples/<media>/stego/``, using the
real protect workflow: sign, derive the start location, embed, publish the manifest.

The stego files are signed with a key pair made for the samples. Its public half is
written to ``keys/public/samples_public.pem`` and committed, so anyone can verify the
samples; the private half is discarded. Running this again makes a new key pair and
re-signs everything, so commit the key and the samples together.

The audio cover is created by ``create_test_audio.py`` if it is missing. The image and
video covers are synthetic and seeded, so they are identical on every run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from app.crypto import key_manager  # noqa: E402
from app.verification.protect import protect_media  # noqa: E402
from app.verification.verifier import verify_media  # noqa: E402
from scripts import create_test_audio  # noqa: E402

SAMPLES = REPOSITORY_ROOT / "samples"
PUBLIC_KEY = REPOSITORY_ROOT / "keys" / "public" / "samples_public.pem"

START_SECRET = "demo-start-secret"
MESSAGE = b"INF2005 sample: this file was protected by party A and signed."

IMAGE_COVER = SAMPLES / "images" / "original" / "cover.png"
IMAGE_STEGO = SAMPLES / "images" / "stego" / "cover_stego.png"
AUDIO_COVER = SAMPLES / "audio" / "original" / "original.wav"
AUDIO_STEGO = SAMPLES / "audio" / "stego" / "stego.wav"
VIDEO_COVER = SAMPLES / "video" / "original" / "cover.mkv"
VIDEO_STEGO = SAMPLES / "video" / "stego" / "cover_stego.mkv"


def make_image_cover(path: Path) -> None:
    """A 320x240 RGB picture: smooth gradients, soft shapes and mild sensor noise."""
    height, width = 240, 320
    rows, columns = np.mgrid[0:height, 0:width].astype(np.float64)
    red = 60 + 150 * columns / width
    green = 40 + 120 * rows / height + 40 * np.sin(columns / 23.0)
    blue = 120 + 80 * np.cos((rows + columns) / 41.0)
    circle = (rows - 110) ** 2 + (columns - 190) ** 2 < 55**2
    red[circle] += 45
    green[circle] -= 25
    noise = np.random.default_rng(2005).normal(0.0, 3.0, (height, width, 3))
    array = np.stack([red, green, blue], axis=-1) + noise
    path.parent.mkdir(parents=True, exist_ok=True)
    Image.fromarray(np.clip(np.rint(array), 0, 255).astype(np.uint8), "RGB").save(path)


def make_video_cover(path: Path) -> None:
    """A 2-second 128x96 FFV1 clip of a gradient drifting past a moving square."""
    height, width, frame_count, frame_rate = 96, 128, 30, 15.0
    rows, columns = np.mgrid[0:height, 0:width]
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = cv2.VideoWriter(
        str(path), cv2.VideoWriter_fourcc(*"FFV1"), frame_rate, (width, height)
    )
    if not writer.isOpened():
        raise SystemExit("OpenCV could not open an FFV1 encoder")
    try:
        for index in range(frame_count):
            frame = np.empty((height, width, 3), dtype=np.uint8)
            frame[..., 0] = (columns * 2 + index * 6) % 256
            frame[..., 1] = (rows * 2 + index * 3) % 256
            frame[..., 2] = 128
            top, left = 20 + index, 10 + 3 * index
            frame[top : top + 24, left : left + 24] = (40, 200, 240)
            writer.write(frame)
    finally:
        writer.release()


def protect(cover: Path, stego: Path, media_id: str, lsb_depth: int, key) -> None:
    stego.parent.mkdir(parents=True, exist_ok=True)
    result = protect_media(
        cover,
        stego,
        MESSAGE,
        key,
        media_id=media_id,
        lsb_depth=lsb_depth,
        start_secret=START_SECRET,
        overwrite=True,
    )
    verdict = verify_media(stego, None, str(PUBLIC_KEY), start_secret=START_SECRET)
    if verdict.verdict != "AUTHENTIC":
        raise SystemExit(f"{stego.name} did not verify: {verdict.reason}")
    print(
        f"wrote {stego.relative_to(REPOSITORY_ROOT)} and its manifest "
        f"(depth {lsb_depth}, start {result.start_location}, verified AUTHENTIC)"
    )


def main() -> None:
    if not AUDIO_COVER.is_file():
        create_test_audio.main()
    make_image_cover(IMAGE_COVER)
    make_video_cover(VIDEO_COVER)

    private_key, _ = key_manager.generate_key_pair()
    key_manager.save_public_key(private_key, PUBLIC_KEY, overwrite=True)
    print(f"wrote {PUBLIC_KEY.relative_to(REPOSITORY_ROOT)}")

    protect(IMAGE_COVER, IMAGE_STEGO, "SAMPLE-IMG-001", 2, private_key)
    protect(AUDIO_COVER, AUDIO_STEGO, "SAMPLE-AUD-001", 2, private_key)
    protect(VIDEO_COVER, VIDEO_STEGO, "SAMPLE-VID-001", 1, private_key)
    print(f"start-location secret for every sample: {START_SECRET!r}")


if __name__ == "__main__":
    main()
