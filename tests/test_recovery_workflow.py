import hashlib

import numpy as np
import pytest
import soundfile as sf

from app.crypto.encryption import generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
from app.robustness.recovery import (
    HEADER,
    create_recovery_sidecar,
    inspect_recovery_sidecar,
    restore_original,
)
from app.services.protection import ProtectionOptions, protect_media
from app.services.recovery import restore_recovery_bundle
from app.stego import image_io


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _cover(path, media_type):
    if media_type == "png":
        pixels = np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3)
        image_io.save_image(pixels, path, image_io.PNG)
    elif media_type == "bmp":
        pixels = np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3)
        image_io.save_image(pixels, path, image_io.BMP)
    else:
        samples = np.arange(25_000 * 2, dtype=np.int16).reshape(25_000, 2)
        sf.write(path, samples, 16_000, subtype="PCM_16")


@pytest.mark.parametrize("media_type", ["png", "bmp", "wav"])
def test_service_restores_each_supported_original_exactly(tmp_path, signer, media_type):
    private_key, _public_key = signer
    source = tmp_path / f"original.{media_type}"
    protected = tmp_path / f"protected.{media_type}"
    manifest = tmp_path / f"protected-{media_type}.json"
    sidecar = tmp_path / f"protected-{media_type}.smir"
    restored = tmp_path / f"restored.{media_type}"
    key = generate_encryption_key()
    _cover(source, media_type)
    original = source.read_bytes()

    protected_result = protect_media(
        source,
        protected,
        manifest,
        b"sidecar recovery workflow",
        private_key,
        ProtectionOptions(
            media_id=f"RECOVERY-{media_type}",
            lsb_count=2,
            start_method="manual",
            start_location=0,
            preserve_size=True,
            recovery_key=key,
            recovery_path=sidecar,
        ),
    )
    result = restore_recovery_bundle(protected, sidecar, restored, key)

    assert restored.read_bytes() == original
    assert result.recovery.original_sha256 == hashlib.sha256(original).hexdigest()
    assert result.recovery.protected_sha256 == hashlib.sha256(protected.read_bytes()).hexdigest()
    assert result.inspection.original_bytes == len(original)
    assert result.inspection.sidecar_bytes == sidecar.stat().st_size
    assert result.inspection.storage_overhead_bytes == HEADER.size + 16
    assert protected_result.recovery.sidecar_bytes == sidecar.stat().st_size


def _files(tmp_path):
    original = tmp_path / "original.bin"
    protected = tmp_path / "protected.bin"
    sidecar = tmp_path / "recovery.smir"
    original.write_bytes(bytes(range(256)) * 8)
    protected.write_bytes(b"final protected bytes")
    key = generate_encryption_key()
    create_recovery_sidecar(original, protected, sidecar, key)
    return original, protected, sidecar, key


def test_wrong_key_and_corrupted_or_truncated_sidecars_fail_without_output(tmp_path):
    _original, protected, sidecar, key = _files(tmp_path)
    wrong_key = generate_encryption_key()

    with pytest.raises(ValueError, match="authentication failed"):
        restore_original(protected, sidecar, tmp_path / "wrong-key.bin", wrong_key)
    assert not (tmp_path / "wrong-key.bin").exists()

    corrupted = tmp_path / "corrupted.smir"
    damaged = bytearray(sidecar.read_bytes())
    damaged[-1] ^= 1
    corrupted.write_bytes(damaged)
    with pytest.raises(ValueError, match="authentication failed"):
        restore_original(protected, corrupted, tmp_path / "corrupt.bin", key)
    assert not (tmp_path / "corrupt.bin").exists()

    truncated = tmp_path / "truncated.smir"
    truncated.write_bytes(sidecar.read_bytes()[:-1])
    with pytest.raises(ValueError, match="length is invalid"):
        restore_original(protected, truncated, tmp_path / "truncated.bin", key)
    assert not (tmp_path / "truncated.bin").exists()


def test_wrong_protected_file_unsafe_destinations_and_overwrite_preserve_files(tmp_path):
    _original, protected, sidecar, key = _files(tmp_path)
    wrong_protected = tmp_path / "wrong-protected.bin"
    wrong_protected.write_bytes(b"different")
    existing = tmp_path / "existing.bin"
    existing.write_bytes(b"retain me")

    with pytest.raises(ValueError, match="different protected file"):
        restore_original(wrong_protected, sidecar, tmp_path / "wrong.bin", key)
    with pytest.raises(FileExistsError):
        restore_original(protected, sidecar, existing, key)
    with pytest.raises(ValueError, match="authentication failed"):
        restore_original(
            protected,
            sidecar,
            existing,
            generate_encryption_key(),
            overwrite=True,
        )
    assert existing.read_bytes() == b"retain me"

    with pytest.raises(ValueError, match="differ from every input"):
        restore_original(protected, sidecar, protected, key, overwrite=True)
    with pytest.raises(ValueError, match="differ from every input"):
        restore_original(protected, sidecar, sidecar, key, overwrite=True)


def test_inspection_rejects_unsupported_or_unsafe_framing(tmp_path):
    _original, _protected, sidecar, _key = _files(tmp_path)
    unsupported = tmp_path / "unsupported.smir"
    raw = bytearray(sidecar.read_bytes())
    raw[4] = 99
    unsupported.write_bytes(raw)
    with pytest.raises(ValueError, match="format is unsupported"):
        inspect_recovery_sidecar(unsupported)

    trailing = tmp_path / "trailing.smir"
    trailing.write_bytes(sidecar.read_bytes() + b"extra")
    with pytest.raises(ValueError, match="length is invalid"):
        inspect_recovery_sidecar(trailing)
