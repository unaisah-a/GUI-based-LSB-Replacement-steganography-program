import numpy as np
import pytest
import soundfile as sf

from app.attacks.payload_attacks import (
    corrupt_embedded_payload,
    modify_outside_payload,
)
from app.crypto.key_manager import generate_rsa_keys
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_payload_corruption_fails_verification(tmp_path, media_type):
    private_key, public_key = generate_rsa_keys()
    suffix = ".png" if media_type == "image" else ".wav"
    cover = tmp_path / f"cover{suffix}"
    protected = tmp_path / f"protected{suffix}"
    attacked = tmp_path / f"attacked{suffix}"
    manifest = tmp_path / "payload.json"
    if media_type == "image":
        array = np.arange(128 * 128 * 3, dtype=np.uint8).reshape(128, 128, 3)
        image_io.save_image(array, cover, image_io.PNG)
    else:
        samples = np.arange(44_100, dtype=np.int16)
        sf.write(cover, samples, 44_100, subtype="PCM_16")
    options = ProtectionOptions(
        media_id=f"{media_type}-attack",
        lsb_count=2,
        start_secret="attack start secret",
    )
    protect_media(
        cover,
        protected,
        manifest,
        b"payload corruption demonstration",
        private_key,
        options,
    )

    corrupt_embedded_payload(
        protected,
        attacked,
        manifest,
        start_secret="attack start secret",
    )
    result = verify_media(
        attacked,
        manifest,
        public_key,
        start_secret="attack start secret",
    )
    assert result.verdict in {Verdict.SIGNATURE_INVALID, Verdict.CANNOT_VERIFY}


def test_outside_payload_edit_documents_message_verification_boundary(tmp_path):
    private_key, public_key = generate_rsa_keys()
    cover = tmp_path / "cover.png"
    protected = tmp_path / "protected.png"
    attacked = tmp_path / "outside-change.png"
    manifest = tmp_path / "payload.json"
    array = np.zeros((128, 128, 3), dtype=np.uint8)
    image_io.save_image(array, cover, image_io.PNG)
    protect_media(
        cover,
        protected,
        manifest,
        b"signed message remains intact",
        private_key,
        ProtectionOptions(
            media_id="outside-edit",
            lsb_count=1,
            start_location=1_000,
            start_method="manual",
        ),
    )

    modify_outside_payload(protected, attacked, manifest)
    result = verify_media(attacked, manifest, public_key)
    assert result.verdict is Verdict.AUTHENTIC
    assert result.message == b"signed message remains intact"
