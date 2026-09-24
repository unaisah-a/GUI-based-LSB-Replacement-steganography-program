"""T03 failure injection and security-boundary regressions."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from app.crypto import encryption, key_manager
from app.crypto.errors import EncryptionError
from app.stego import image_io, media
from app.stego.errors import CapacityError, ValidationError
from app.utils import constants
from app.verification import publication
from app.verification.protect import protect_media
from app.verification.verifier import verify_media

from conftest import make_audio, make_cover, write_audio_file, write_cover


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture(params=["image", "audio"])
def cover(request, tmp_path):
    if request.param == "image":
        return Path(write_cover(str(tmp_path), make_cover(128, 128, 3), image_io.PNG, "cover"))
    return Path(write_audio_file(str(tmp_path), make_audio(50000)))


def protect(cover, keys, output, **kwargs):
    settings = dict(media_id="T03", lsb_depth=3, start_method="manual", manual_start_location=10)
    settings.update(kwargs)
    return protect_media(cover, output, b"trusted message", keys[0], **settings)


@pytest.mark.parametrize("alias", ["source", "output", "hardlink_source", "hardlink_output"])
def test_manifest_alias_rejected_without_changes(cover, keys, tmp_path, alias):
    output = tmp_path / ("stego" + cover.suffix)
    output.write_bytes(b"previous output")
    if alias == "source":
        manifest = cover
    elif alias == "output":
        manifest = output
    else:
        manifest = tmp_path / "alias.json"
        os.link(cover if alias == "hardlink_source" else output, manifest)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ValidationError):
        protect(cover, keys, output, manifest_path=manifest, overwrite=True)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["embed", "manifest", "backup", "first_install", "second_install", "interrupt"])
def test_failures_preserve_originals_and_remove_staging(cover, keys, tmp_path, monkeypatch, existing, phase):
    from app.crypto import manifest as manifest_module

    output = tmp_path / ("stego" + cover.suffix)
    manifest = Path(str(output) + ".manifest.json")
    if existing:
        output.write_bytes(b"old media")
        manifest.write_bytes(b"old manifest")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}

    def fail(*args, **kwargs):
        raise OSError("injected failure")

    if phase == "embed":
        monkeypatch.setattr(media, "embed", fail)
    elif phase == "manifest":
        monkeypatch.setattr(manifest_module, "write_manifest", fail)
    elif phase == "backup" and existing:
        monkeypatch.setattr(publication.shutil, "copy2", fail)
    else:
        install = publication._install
        calls = 0

        def inject(source, target, overwrite):
            nonlocal calls
            calls += 1
            at = 1 if phase in ("first_install", "backup") else 2
            if calls == at:
                if phase == "interrupt":
                    raise KeyboardInterrupt()
                raise OSError("injected publication failure")
            install(source, target, overwrite)

        monkeypatch.setattr(publication, "_install", inject)
    with pytest.raises((OSError, publication.PublicationError, KeyboardInterrupt)):
        protect(cover, keys, output, overwrite=existing)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("media_exists,manifest_exists", [(True, False), (False, True)])
def test_partial_existing_bundle_restored(cover, keys, tmp_path, monkeypatch, media_exists, manifest_exists):
    output = tmp_path / ("stego" + cover.suffix)
    manifest = Path(str(output) + ".manifest.json")
    if media_exists:
        output.write_bytes(b"old media")
    if manifest_exists:
        manifest.write_bytes(b"old manifest")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    install = publication._install

    def fail_second(stage, target, overwrite):
        if target == manifest:
            raise OSError("second installation failed")
        install(stage, target, overwrite)

    monkeypatch.setattr(publication, "_install", fail_second)
    with pytest.raises(publication.PublicationError):
        protect(cover, keys, output, overwrite=True)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_rollback_failure_retains_recovery_backup(cover, keys, tmp_path, monkeypatch):
    output = tmp_path / ("stego" + cover.suffix)
    manifest = Path(str(output) + ".manifest.json")
    output.write_bytes(b"original media")
    manifest.write_bytes(b"original manifest")
    replace = publication._replace

    def inject(source, target):
        if target == manifest or ".backup-" in source.name:
            raise PermissionError("locked")
        replace(source, target)

    monkeypatch.setattr(publication, "_replace", inject)
    with pytest.raises(publication.PublicationError) as caught:
        protect(cover, keys, output, overwrite=True)
    assert len(caught.value.recovery_paths) == 1
    assert caught.value.recovery_paths[0].read_bytes() == b"original media"
    assert manifest.read_bytes() == b"original manifest"
    assert not list(tmp_path.glob("*.stage-*"))


def test_no_overwrite_race_keeps_newly_arrived_file(cover, keys, tmp_path, monkeypatch):
    output = tmp_path / ("stego" + cover.suffix)
    manifest = Path(str(output) + ".manifest.json")
    install = publication._install

    def race(source, target, overwrite):
        if target == manifest:
            target.write_bytes(b"concurrent file")
        install(source, target, overwrite)

    monkeypatch.setattr(publication, "_install", race)
    with pytest.raises(publication.PublicationError):
        protect(cover, keys, output)
    assert manifest.read_bytes() == b"concurrent file"
    assert not output.exists()


def test_successful_overwrite_verifies_and_leaves_no_artifacts(cover, keys, tmp_path):
    output = tmp_path / ("stego" + cover.suffix)
    manifest = Path(str(output) + ".manifest.json")
    output.write_bytes(b"old media")
    manifest.write_bytes(b"old manifest")
    before = cover.read_bytes()
    result = protect(cover, keys, output, overwrite=True)
    assert result.manifest_path == str(manifest)
    assert verify_media(output, manifest, keys[1]).verdict == "AUTHENTIC"
    assert cover.read_bytes() == before
    assert set(tmp_path.iterdir()) == {cover, output, manifest}


@pytest.mark.parametrize("coding", [False, True])
def test_manual_capacity_exact_fit_and_one_sample_overflow(cover, keys, tmp_path, coding):
    from app.crypto.envelope import ErrorCorrectionParameters

    options = dict(lsb_depth=8, passphrase="demo only", scrypt_n=encryption.MIN_SCRYPT_N)
    if coding:
        options["ecc"] = ErrorCorrectionParameters(constants.ECC_REPETITION, 3)
    # Use the same five-digit offset width: the signed offset itself costs bytes.
    first = protect(cover, keys, tmp_path / ("first" + cover.suffix),
                    **options, manual_start_location=10000)
    total = media.measure(cover, 8).total_samples
    last_start = total - first.embedded_length - 4
    second = protect(cover, keys, tmp_path / ("exact" + cover.suffix),
                     **options, manual_start_location=last_start)
    assert second.embedded_length == first.embedded_length
    assert verify_media(second.stego_path, None, keys[1], passphrase="demo only").verdict == "AUTHENTIC"
    output = tmp_path / ("overflow" + cover.suffix)
    with pytest.raises(CapacityError):
        protect(cover, keys, output, **options, manual_start_location=last_start + 1)
    assert not output.exists()
    assert not Path(str(output) + ".manifest.json").exists()


def test_manifest_failure_withholds_recovered_plaintext(cover, keys, tmp_path):
    result = protect(cover, keys, tmp_path / ("stego" + cover.suffix))
    manifest = Path(result.manifest_path)
    data = json.loads(manifest.read_text())
    data["message_length"] += 1
    manifest.write_text(json.dumps(data))
    received = verify_media(result.stego_path, manifest, keys[1])
    assert received.verdict == "TAMPERED"
    assert received.signature_valid and received.hash_valid
    assert received.message is None


@pytest.mark.parametrize("n,r,p", [(1 << 21, 8, 1), (1 << 15, 64, 1), (1 << 10, 8, 1024)])
def test_excessive_kdf_cost_rejected_before_library(monkeypatch, n, r, p):
    def unexpected(**kwargs):
        pytest.fail("Scrypt was instantiated before resource validation")
    monkeypatch.setattr(encryption, "Scrypt", unexpected)
    with pytest.raises(EncryptionError, match="limit"):
        encryption.derive_key("secret", b"s" * 16, n=n, r=r, p=p)
    with pytest.raises(EncryptionError, match="limit"):
        encryption.new_parameters(n=n, r=r, p=p)


def test_fingerprint_is_canonical_and_key_specific(keys):
    private, public = keys
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    reloaded = serialization.load_pem_public_key(pem)
    expected = hashlib.sha256(der).hexdigest()
    assert key_manager.public_key_fingerprint(private) == expected
    assert key_manager.public_key_fingerprint(reloaded) == expected
    _, other = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    assert key_manager.public_key_fingerprint(other) != expected


def test_signed_excessive_kdf_rejected_and_bad_signature_never_decrypts(keys, monkeypatch):
    from dataclasses import replace

    from app.crypto import envelope, payload, signatures
    from app.verification.verifier import verify_extracted_payload

    prepared = payload.prepare_payload(
        b"secret", keys[0], media_id="KDF", media_type="image", lsb_depth=1,
        start_method="manual", start_location=0, passphrase="demo",
        scrypt_n=encryption.MIN_SCRYPT_N,
    )
    parsed = envelope.parse_envelope(prepared.envelope)
    record = replace(prepared.record, encryption=replace(prepared.record.encryption, n=1 << 24))
    oversized = signatures.sign_envelope(record.to_bytes(), parsed.message, keys[0], record.flags)

    def unexpected(**kwargs):
        pytest.fail("Scrypt instantiated for unsupported signed cost")

    monkeypatch.setattr(encryption, "Scrypt", unexpected)
    result = verify_extracted_payload(oversized, keys[1], passphrase="demo")
    assert result.verdict == "CANNOT_VERIFY"
    assert result.signature_valid
    assert result.message is None

    def forbidden(*args, **kwargs):
        pytest.fail("decryption attempted before signature verification")

    monkeypatch.setattr(payload, "recover_message", forbidden)
    damaged = prepared.envelope[:-1] + bytes([prepared.envelope[-1] ^ 1])
    result = verify_extracted_payload(damaged, keys[1], passphrase="demo")
    assert result.verdict == "SIGNATURE_INVALID"
    assert result.message is None


def test_case_alias_of_absent_destinations_rejected(tmp_path):
    if os.name != "nt":
        pytest.skip("case-insensitive Windows path check")
    with pytest.raises(ValidationError):
        publication.validate_bundle(tmp_path / "cover.png", tmp_path / "stego.png",
                                    tmp_path / "STEGO.PNG", False)


def test_oversized_manifest_refused_before_json_parser(tmp_path, monkeypatch):
    from app.crypto import manifest
    from app.crypto.errors import ManifestError

    path = tmp_path / "large.json"
    path.write_bytes(b" " * (manifest.MAX_MANIFEST_BYTES + 1))

    def unexpected(*args, **kwargs):
        pytest.fail("oversized manifest reached JSON parser")

    monkeypatch.setattr(manifest.json, "loads", unexpected)
    with pytest.raises(ManifestError, match="1 MiB"):
        manifest.read_manifest(path)


def test_deeply_nested_untrusted_json_reports_domain_errors(tmp_path):
    from app.crypto import envelope, manifest
    from app.crypto.errors import ManifestError, RecordError

    nested = b"[" * 2000 + b"0" + b"]" * 2000
    path = tmp_path / "nested.json"
    path.write_bytes(nested)
    with pytest.raises(ManifestError):
        manifest.read_manifest(path)
    with pytest.raises(RecordError):
        envelope.decode_record(nested)
