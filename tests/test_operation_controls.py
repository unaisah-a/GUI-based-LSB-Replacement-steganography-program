from pathlib import Path

import numpy as np
import pytest

import app.services.protection as protection
from app.crypto.key_manager import generate_rsa_keys
from app.services.operations import CancellationToken, OperationCancelled, OperationControl
from app.services.output_files import export_secret_bundle, save_recovered_payload
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io


def test_cancelled_protection_removes_staging_and_publishes_nothing(tmp_path, monkeypatch):
    cover = tmp_path / "cover.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    image_io.save_image(np.zeros((100, 100, 3), dtype=np.uint8), cover, image_io.PNG)
    private_key, _ = generate_rsa_keys()
    token = CancellationToken()
    progress = []

    def cancel_after_staged_embed(_source, staged, *_args, **_kwargs):
        Path(staged).write_bytes(b"complete staged media")
        token.cancel()
        return {"output_path": str(staged)}

    monkeypatch.setattr(protection, "embed_image", cancel_after_staged_embed)
    options = ProtectionOptions(
        media_id="CANCEL-GUI",
        start_method="manual",
        start_location=0,
        operation=OperationControl(token, progress.append),
    )

    with pytest.raises(OperationCancelled, match="cancelled"):
        protect_media(cover, output, manifest, b"message", private_key, options)

    assert not output.exists()
    assert not manifest.exists()
    assert not list(tmp_path.glob(".*.stage-*"))
    assert any("Embedding" in message for message in progress)


def test_explicit_output_writers_preserve_existing_files(tmp_path):
    recovered = tmp_path / "recovered.bin"
    recovered.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        save_recovered_payload(recovered, b"new")
    assert recovered.read_bytes() == b"existing"
    save_recovered_payload(recovered, b"new", overwrite=True)
    assert recovered.read_bytes() == b"new"

    secret_path = tmp_path / "private-secrets.json"
    export_secret_bundle(secret_path, {"start_location_secret": "private"})
    text = secret_path.read_text(encoding="utf-8")
    assert "SMIV-SECRET-BUNDLE" in text
    assert '"start_location_secret": "private"' in text
    assert "manifest" in text
    with pytest.raises(FileExistsError):
        export_secret_bundle(secret_path, {"start_location_secret": "replacement"})
    assert secret_path.read_text(encoding="utf-8") == text
