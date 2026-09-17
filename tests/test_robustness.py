import numpy as np
import pytest

from app.crypto.encryption import generate_encryption_key
from app.robustness.recovery import create_recovery_sidecar, restore_original
from app.robustness.redundancy import decode_repetition3, encode_repetition3
from app.services.size_preservation import pad_png_to_size
from app.stego import image_io


def test_repetition3_majority_corrects_one_copy_per_byte():
    original = b"repetition coding"
    encoded = bytearray(encode_repetition3(original))
    for offset in range(0, len(encoded), 3):
        encoded[offset] ^= 0b01010101
    assert decode_repetition3(bytes(encoded), len(original)) == original


def test_encrypted_sidecar_restores_exact_original(tmp_path):
    original = tmp_path / "original.bin"
    protected = tmp_path / "protected.bin"
    sidecar = tmp_path / "recovery.smir"
    restored = tmp_path / "restored.bin"
    original.write_bytes(bytes(range(256)) * 20)
    protected.write_bytes(b"protected representation")
    key = generate_encryption_key()

    create_recovery_sidecar(original, protected, sidecar, key)
    result = restore_original(protected, sidecar, restored, key)

    assert restored.read_bytes() == original.read_bytes()
    assert result.restored_bytes == original.stat().st_size


def test_recovery_sidecar_rejects_different_protected_file(tmp_path):
    original = tmp_path / "original.bin"
    protected = tmp_path / "protected.bin"
    sidecar = tmp_path / "recovery.smir"
    original.write_bytes(b"original")
    protected.write_bytes(b"protected")
    key = generate_encryption_key()
    create_recovery_sidecar(original, protected, sidecar, key)
    protected.write_bytes(b"changed")

    with pytest.raises(ValueError, match="different protected file"):
        restore_original(protected, sidecar, tmp_path / "restored.bin", key)


def test_recovery_helpers_require_explicit_overwrite_and_reject_collisions(tmp_path):
    original = tmp_path / "original.bin"
    protected = tmp_path / "protected.bin"
    sidecar = tmp_path / "recovery.smir"
    restored = tmp_path / "restored.bin"
    original.write_bytes(b"original")
    protected.write_bytes(b"protected")
    sidecar.write_bytes(b"existing")
    restored.write_bytes(b"existing restored")
    key = generate_encryption_key()

    with pytest.raises(FileExistsError):
        create_recovery_sidecar(original, protected, sidecar, key)
    create_recovery_sidecar(original, protected, sidecar, key, overwrite=True)
    with pytest.raises(FileExistsError):
        restore_original(protected, sidecar, restored, key)
    restore_original(protected, sidecar, restored, key, overwrite=True)
    assert restored.read_bytes() == original.read_bytes()

    with pytest.raises(ValueError, match="differ"):
        create_recovery_sidecar(original, protected, original, key, overwrite=True)
    with pytest.raises(ValueError, match="differ"):
        restore_original(protected, sidecar, sidecar, key, overwrite=True)


def test_png_ancillary_padding_reaches_exact_size_without_pixel_change(tmp_path):
    source = tmp_path / "image.png"
    padded = tmp_path / "padded.png"
    array = np.arange(32 * 32 * 3, dtype=np.uint8).reshape(32, 32, 3)
    image_io.save_image(array, source, image_io.PNG)
    target = source.stat().st_size + 100

    result = pad_png_to_size(source, target, padded)
    decoded, _ = image_io.load_image(padded)

    assert result.exact
    assert padded.stat().st_size == target
    assert np.array_equal(decoded, array)


def test_png_padding_requires_explicit_overwrite(tmp_path):
    source = tmp_path / "image.png"
    output = tmp_path / "padded.png"
    array = np.arange(16 * 16 * 3, dtype=np.uint8).reshape(16, 16, 3)
    image_io.save_image(array, source, image_io.PNG)
    output.write_bytes(b"existing")

    with pytest.raises(FileExistsError):
        pad_png_to_size(source, source.stat().st_size + 100, output)
    pad_png_to_size(source, source.stat().st_size + 100, output, overwrite=True)
    assert output.stat().st_size == source.stat().st_size + 100
