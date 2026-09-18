import hashlib
from pathlib import Path

import numpy as np
import pytest

from app.crypto.encryption import generate_encryption_key
from app.crypto.key_manager import generate_rsa_keys
from app.services import protection
from app.services.protection import ProtectionOptions, PublicationError, protect_media
from app.services.size_preservation import pad_png_to_size
from app.stego import image_io


@pytest.fixture(scope="module")
def private_key():
    return generate_rsa_keys()[0]


def _cover(path: Path) -> None:
    y, x = np.indices((96, 128))
    pixels = np.stack(
        ((x * 2) % 256, (y * 3) % 256, ((x + y) * 5) % 256), axis=2
    ).astype(np.uint8)
    image_io.save_image(pixels, path, image_io.PNG)


def _paths(tmp_path: Path):
    source = tmp_path / "cover.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    _cover(source)
    return source, output, manifest


def _options(**values) -> ProtectionOptions:
    defaults = {
        "media_id": "TX-001",
        "start_method": "manual",
        "start_location": 0,
    }
    defaults.update(values)
    return ProtectionOptions(**defaults)


def _transaction_files(tmp_path: Path) -> list[Path]:
    return [
        path
        for path in tmp_path.iterdir()
        if ".stage-" in path.name or ".backup-" in path.name
    ]


@pytest.mark.parametrize("existing", [False, True])
def test_manifest_failure_leaves_no_partial_bundle(
    tmp_path, private_key, monkeypatch, existing
):
    source, output, manifest = _paths(tmp_path)
    if existing:
        output.write_bytes(b"old protected")
        manifest.write_bytes(b"old manifest")

    def fail_manifest(*_args, **_kwargs):
        raise OSError("injected manifest failure")

    monkeypatch.setattr(protection, "save_manifest", fail_manifest)
    with pytest.raises(OSError, match="injected manifest failure"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(overwrite=existing),
        )

    if existing:
        assert output.read_bytes() == b"old protected"
        assert manifest.read_bytes() == b"old manifest"
    else:
        assert not output.exists()
        assert not manifest.exists()
    assert not _transaction_files(tmp_path)


@pytest.mark.parametrize("phase", ["media", "postprocess"])
def test_generation_failure_leaves_no_partial_bundle(
    tmp_path, private_key, monkeypatch, phase
):
    source, output, manifest = _paths(tmp_path)

    if phase == "media":
        monkeypatch.setattr(
            protection,
            "embed_image",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("injected media failure")
            ),
        )
        expected = "injected media failure"
        options = _options()
    else:
        monkeypatch.setattr(
            protection,
            "preserve_protected_size",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                OSError("injected postprocess failure")
            ),
        )
        expected = "injected postprocess failure"
        options = _options(preserve_size=True)

    with pytest.raises(OSError, match=expected):
        protect_media(source, output, manifest, b"message", private_key, options)

    assert not output.exists()
    assert not manifest.exists()
    assert not _transaction_files(tmp_path)


def test_recovery_failure_preserves_existing_bundle(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    recovery = tmp_path / "protected.recovery.smir"
    previous = {
        output: b"old protected",
        manifest: b"old manifest",
        recovery: b"old recovery",
    }
    for path, content in previous.items():
        path.write_bytes(content)

    def fail_recovery(*_args, **_kwargs):
        raise OSError("injected sidecar failure")

    monkeypatch.setattr(protection, "create_recovery_sidecar", fail_recovery)
    with pytest.raises(OSError, match="injected sidecar failure"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(
                overwrite=True,
                recovery_key=generate_encryption_key(),
                recovery_path=recovery,
            ),
        )

    assert {path: path.read_bytes() for path in previous} == previous
    assert not _transaction_files(tmp_path)


def test_publish_failure_restores_all_existing_destinations(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    recovery = tmp_path / "protected.recovery.smir"
    previous = {
        output: b"old protected",
        manifest: b"old manifest",
        recovery: b"old recovery",
    }
    for path, content in previous.items():
        path.write_bytes(content)

    real_replace = protection._replace_path
    injected = False

    def fail_manifest_publish(source_path, destination_path):
        nonlocal injected
        if destination_path == manifest and ".stage-" in source_path.name and not injected:
            injected = True
            raise OSError("injected final publication failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(protection, "_replace_path", fail_manifest_publish)
    with pytest.raises(PublicationError, match="previous files were restored"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(
                overwrite=True,
                recovery_key=generate_encryption_key(),
                recovery_path=recovery,
            ),
        )

    assert {path: path.read_bytes() for path in previous} == previous
    assert not _transaction_files(tmp_path)


def test_publish_failure_removes_newly_published_destinations(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    real_replace = protection._replace_path

    def fail_manifest_publish(source_path, destination_path):
        if destination_path == manifest and ".stage-" in source_path.name:
            raise OSError("injected final publication failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(protection, "_replace_path", fail_manifest_publish)
    with pytest.raises(PublicationError, match="previous files were restored"):
        protect_media(
            source, output, manifest, b"message", private_key, _options()
        )

    assert not output.exists()
    assert not manifest.exists()
    assert not _transaction_files(tmp_path)


@pytest.mark.parametrize("destination_name", ["output", "manifest", "recovery"])
def test_overwrite_false_rejects_each_existing_destination_before_embedding(
    tmp_path, private_key, monkeypatch, destination_name
):
    source, output, manifest = _paths(tmp_path)
    recovery = tmp_path / "protected.recovery.smir"
    destinations = {"output": output, "manifest": manifest, "recovery": recovery}
    destinations[destination_name].write_bytes(b"existing")
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(FileExistsError):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(recovery_key=generate_encryption_key(), recovery_path=recovery),
        )
    assert not embedded


def test_hard_link_collision_is_rejected_before_embedding(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    output.hardlink_to(source)
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(ValueError, match="paths must be different"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(overwrite=True),
        )
    assert not embedded
    assert source.exists() and output.exists()


@pytest.mark.parametrize("collision", ["source_manifest", "source_recovery", "output_manifest"])
def test_all_artifact_alias_classes_are_rejected_before_embedding(
    tmp_path, private_key, monkeypatch, collision
):
    source, output, manifest = _paths(tmp_path)
    recovery = tmp_path / "protected.recovery.smir"
    if collision == "source_manifest":
        manifest.hardlink_to(source)
    elif collision == "source_recovery":
        recovery.hardlink_to(source)
    else:
        output.write_bytes(b"existing output")
        manifest.hardlink_to(output)
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(ValueError, match="paths must be different"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(
                overwrite=True,
                recovery_key=generate_encryption_key(),
                recovery_path=recovery,
            ),
        )
    assert not embedded


@pytest.mark.parametrize(
    "values, message",
    [
        ({"recovery_key": b"short"}, "32 bytes"),
        ({"recovery_path": "unused.smir"}, "requires a recovery_key"),
    ],
)
def test_invalid_recovery_settings_fail_before_embedding(
    tmp_path, private_key, monkeypatch, values, message
):
    source, output, manifest = _paths(tmp_path)
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(ValueError, match=message):
        protect_media(
            source, output, manifest, b"message", private_key, _options(**values)
        )
    assert not embedded


def test_invalid_size_setting_fails_before_embedding(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(TypeError, match="preserve_size"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(preserve_size="yes"),
        )
    assert not embedded


def test_size_report_requires_preservation_before_embedding(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    embedded = False

    def unexpected_embed(*_args, **_kwargs):
        nonlocal embedded
        embedded = True

    monkeypatch.setattr(protection, "embed_image", unexpected_embed)
    with pytest.raises(ValueError, match="requires preserve_size"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(size_report_path=tmp_path / "size.json"),
        )
    assert not embedded


def test_size_report_failure_leaves_no_partial_bundle(
    tmp_path, private_key, monkeypatch
):
    source, output, manifest = _paths(tmp_path)
    report = tmp_path / "size.json"

    def fail_report(*_args, **_kwargs):
        raise OSError("injected size report failure")

    monkeypatch.setattr(protection, "export_size_preservation_result", fail_report)
    with pytest.raises(OSError, match="injected size report failure"):
        protect_media(
            source,
            output,
            manifest,
            b"message",
            private_key,
            _options(preserve_size=True, size_report_path=report),
        )
    assert not output.exists()
    assert not manifest.exists()
    assert not report.exists()
    assert not _transaction_files(tmp_path)


def test_successful_bundle_replaces_destinations_and_binds_recovery_to_final_bytes(
    tmp_path, private_key
):
    source, output, manifest = _paths(tmp_path)
    pad_png_to_size(source, source.stat().st_size + 5_000)
    recovery = tmp_path / "protected.recovery.smir"
    output.write_bytes(b"old protected")
    manifest.write_bytes(b"old manifest")
    recovery.write_bytes(b"old recovery")

    result = protect_media(
        source,
        output,
        manifest,
        b"message",
        private_key,
        _options(
            overwrite=True,
            preserve_size=True,
            recovery_key=generate_encryption_key(),
            recovery_path=recovery,
        ),
    )

    assert result.output_path == str(output.resolve())
    assert result.manifest_path == str(manifest.resolve())
    assert result.size_preservation is not None
    assert result.size_preservation.output_path == str(output.resolve())
    assert result.size_preservation.exact
    assert result.recovery is not None
    assert result.recovery.output_path == str(recovery.resolve())
    assert result.recovery.protected_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()
    assert output.stat().st_size == source.stat().st_size
    assert not _transaction_files(tmp_path)


def test_unavailable_exact_size_is_reported_without_failing_bundle(
    tmp_path, private_key
):
    source, output, manifest = _paths(tmp_path)

    result = protect_media(
        source,
        output,
        manifest,
        b"message",
        private_key,
        _options(preserve_size=True),
    )

    assert output.is_file() and manifest.is_file()
    assert result.size_preservation is not None
    if not result.size_preservation.exact:
        assert result.size_preservation.method.startswith("unavailable:")
