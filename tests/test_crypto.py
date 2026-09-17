import json

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto.encryption import (
    decode_key,
    encode_key,
    generate_encryption_key,
)
from app.crypto.key_manager import (
    generate_rsa_keys,
    load_private_key_from_pem,
    public_key_fingerprint,
    save_private_key_to_pem,
)
from app.crypto.manifest import Manifest, ManifestError, load_manifest, save_manifest
from app.crypto.payload import (
    build_envelope,
    message_hash_is_valid,
    parse_envelope,
    recover_message,
    verify_envelope_signature,
)
from app.crypto.start_location import derive_start_location


@pytest.fixture(scope="module")
def key_pair():
    return generate_rsa_keys()


def _build(private_key, message=b"confidential test message", encryption_key=None):
    return build_envelope(
        message,
        media_id="IMG-001",
        media_type="image",
        lsb_count=3,
        start_method="hmac-sha256",
        private_key=private_key,
        metadata={"team": "test"},
        encryption_key=encryption_key,
        record_nonce="fixed-record-nonce",
        timestamp="2026-09-17T12:00:00+00:00",
    )


def test_signed_envelope_round_trip(key_pair):
    private_key, public_key = key_pair
    built = _build(private_key)
    parsed = parse_envelope(built.data)

    assert verify_envelope_signature(parsed, public_key)
    assert recover_message(parsed) == built.plaintext_message
    assert message_hash_is_valid(parsed, built.plaintext_message)
    assert parsed.record["extraction"]["payload_length"] == len(built.data)
    assert parsed.record["public_key_fingerprint"] == public_key_fingerprint(public_key)


def test_encrypted_envelope_requires_correct_key(key_pair):
    private_key, public_key = key_pair
    encryption_key = generate_encryption_key()
    built = _build(private_key, encryption_key=encryption_key)
    parsed = parse_envelope(built.data)

    assert parsed.encrypted
    assert verify_envelope_signature(parsed, public_key)
    assert recover_message(parsed, encryption_key) == built.plaintext_message
    with pytest.raises(InvalidTag):
        recover_message(parsed, generate_encryption_key())


def test_cipher_key_text_round_trip():
    key = generate_encryption_key()
    assert decode_key(encode_key(key)) == key


def test_signature_detects_changed_stored_message(key_pair):
    private_key, public_key = key_pair
    built = _build(private_key)
    changed = bytearray(built.data)
    changed[-257] ^= 1
    parsed = parse_envelope(bytes(changed))
    assert not verify_envelope_signature(parsed, public_key)


def test_password_protected_private_key_round_trip(tmp_path, key_pair):
    private_key, _ = key_pair
    path = tmp_path / "private.pem"
    save_private_key_to_pem(private_key, path, password="demo password")
    loaded = load_private_key_from_pem(path, password="demo password")
    assert loaded.private_numbers() == private_key.private_numbers()


def test_start_location_supports_exact_fit():
    assert derive_start_location(
        "secret",
        total_samples=100,
        required_samples=100,
        media_type="image",
        media_id="IMG-001",
        nonce="nonce",
        lsb_count=1,
    ) == 0


def test_manifest_round_trip(tmp_path, key_pair):
    _, public_key = key_pair
    manifest = Manifest(
        media_type="image",
        media_id="IMG-001",
        nonce="nonce",
        lsb_count=2,
        start_method="hmac-sha256",
        payload_length=512,
        public_key_fingerprint=public_key_fingerprint(public_key),
    )
    path = tmp_path / "payload.json"
    save_manifest(manifest, path)
    assert load_manifest(path) == manifest


def test_manifest_rejects_disclosed_derived_start(tmp_path, key_pair):
    _, public_key = key_pair
    value = {
        "media_type": "image",
        "media_id": "IMG-001",
        "nonce": "nonce",
        "lsb_count": 2,
        "start_method": "hmac-sha256",
        "start_location": 3,
        "payload_length": 512,
        "public_key_fingerprint": public_key_fingerprint(public_key),
        "robustness": "none",
        "manifest_version": 1,
        "payload_format": 1,
    }
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(path)
