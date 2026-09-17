import json

import pytest

from app.crypto.key_manager import generate_rsa_keys
from app.crypto.manifest import (
    MAX_MANIFEST_BYTES,
    Manifest,
    ManifestError,
    load_manifest,
)
from app.crypto.payload import (
    FLAG_ENCRYPTED,
    FORMAT_VERSION,
    HEADER,
    MAGIC,
    MAX_MESSAGE_BYTES,
    MAX_RECORD_BYTES,
    MAX_SIGNATURE_BYTES,
    PayloadFormatError,
    build_envelope,
    parse_envelope,
)
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def rsa_keys():
    return generate_rsa_keys()


def _built(private_key, *, encrypted=False):
    return build_envelope(
        b"a message long enough to exercise either encryption flag",
        media_id="IMG-BOUNDARY",
        media_type="image",
        lsb_count=3,
        start_method="manual",
        manual_start_location=7,
        private_key=private_key,
        encryption_key=b"e" * 32 if encrypted else None,
        record_nonce="fixed-record-nonce",
        timestamp="2026-09-17T12:00:00+00:00",
    )


def _with_record(built, mutate, *, repair_payload_length=True):
    _, version, flags, record_len, message_len, signature_len = HEADER.unpack_from(
        built.data
    )
    cursor = HEADER.size
    record = json.loads(built.data[cursor : cursor + record_len].decode("utf-8"))
    message = built.data[cursor + record_len : cursor + record_len + message_len]
    signature = built.data[-signature_len:]
    mutate(record)
    for _ in range(8):
        record_bytes = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        total = HEADER.size + len(record_bytes) + len(message) + len(signature)
        extraction = record.get("extraction")
        if (
            not repair_payload_length
            or not isinstance(extraction, dict)
            or extraction.get("payload_length") == total
        ):
            break
        extraction["payload_length"] = total
    header = HEADER.pack(
        MAGIC,
        version,
        flags,
        len(record_bytes),
        len(message),
        len(signature),
    )
    return header + record_bytes + message + signature


def _manifest_dict():
    return {
        "manifest_version": 1,
        "payload_format": 1,
        "media_type": "image",
        "media_id": "IMG-BOUNDARY",
        "nonce": "nonce",
        "lsb_count": 2,
        "start_method": "manual",
        "start_location": 0,
        "payload_length": 700,
        "carrier_payload_length": None,
        "public_key_fingerprint": "a" * 64,
        "robustness": "none",
    }


@pytest.mark.parametrize("encrypted", [False, True])
def test_builder_output_always_passes_bounded_parser(rsa_keys, encrypted):
    private_key, _ = rsa_keys
    built = _built(private_key, encrypted=encrypted)
    parsed = parse_envelope(built.data)
    assert parsed.serialized_length == len(built.data)
    assert parsed.encrypted is encrypted


@pytest.mark.parametrize("encrypted", [False, True])
def test_encryption_flag_must_match_signed_metadata(rsa_keys, encrypted):
    private_key, _ = rsa_keys
    built = _built(private_key, encrypted=encrypted)
    changed = bytearray(built.data)
    changed[5] ^= FLAG_ENCRYPTED
    with pytest.raises(PayloadFormatError, match="encryption"):
        parse_envelope(bytes(changed))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda record: record.__setitem__("record_version", True),
        lambda record: record.__setitem__("media_id", []),
        lambda record: record.__setitem__("nonce", 1.5),
        lambda record: record.__setitem__("timestamp", False),
        lambda record: record.__setitem__("content_type", []),
        lambda record: record.__setitem__("message_hash", ["0" * 64]),
        lambda record: record.__setitem__("public_key_fingerprint", 123),
        lambda record: record.__setitem__("metadata", []),
        lambda record: record["extraction"].__setitem__("lsb_count", 1.5),
        lambda record: record["extraction"].__setitem__("media_type", []),
        lambda record: record["extraction"].__setitem__("start_method", False),
        lambda record: record["extraction"].__setitem__("start_location", 1.5),
        lambda record: record["extraction"].__setitem__("robustness", []),
        lambda record: record["encryption"].__setitem__("algorithm", []),
    ],
)
def test_signed_record_rejects_non_scalar_controlling_fields(rsa_keys, mutate):
    private_key, _ = rsa_keys
    with pytest.raises(PayloadFormatError):
        parse_envelope(_with_record(_built(private_key), mutate))


def test_signed_record_requires_version_and_exact_payload_length(rsa_keys):
    private_key, _ = rsa_keys
    built = _built(private_key)
    with pytest.raises(PayloadFormatError, match="record_version"):
        parse_envelope(_with_record(built, lambda value: value.pop("record_version")))
    with pytest.raises(PayloadFormatError, match="payload_length"):
        parse_envelope(
            _with_record(
                built,
                lambda value: value["extraction"].__setitem__("payload_length", 1),
                repair_payload_length=False,
            )
        )


def test_encrypted_record_requires_a_canonical_twelve_byte_nonce(rsa_keys):
    private_key, _ = rsa_keys
    built = _built(private_key, encrypted=True)
    for nonce in ("not base64!", "YQ==", [], None):
        with pytest.raises(PayloadFormatError, match="nonce"):
            parse_envelope(
                _with_record(
                    built,
                    lambda value, replacement=nonce: value["encryption"].__setitem__(
                        "nonce", replacement
                    ),
                )
            )


def test_builder_rejects_unsuitable_private_key():
    with pytest.raises(TypeError, match="RSA private key"):
        build_envelope(
            b"message",
            media_id="IMG-KEY",
            media_type="image",
            lsb_count=1,
            start_method="manual",
            manual_start_location=0,
            private_key=object(),
        )


def test_signed_record_rejects_duplicate_json_fields(rsa_keys):
    private_key, _ = rsa_keys
    built = _built(private_key)
    _, version, flags, record_len, message_len, signature_len = HEADER.unpack_from(
        built.data
    )
    cursor = HEADER.size
    record = built.data[cursor : cursor + record_len]
    duplicated = record[:-1] + b',"record_version":1}'
    remainder = built.data[cursor + record_len :]
    raw = HEADER.pack(
        MAGIC, version, flags, len(duplicated), message_len, signature_len
    ) + duplicated + remainder
    with pytest.raises(PayloadFormatError, match="duplicate"):
        parse_envelope(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"short",
        HEADER.pack(MAGIC, FORMAT_VERSION + 1, 0, 1, 0, 256)
        + b"{}"
        + b"x" * 255,
        HEADER.pack(MAGIC, FORMAT_VERSION, 0x80, 1, 0, 256)
        + b"{}"
        + b"x" * 255,
        HEADER.pack(MAGIC, FORMAT_VERSION, 0, MAX_RECORD_BYTES + 1, 0, 256),
        HEADER.pack(MAGIC, FORMAT_VERSION, 0, 1, MAX_MESSAGE_BYTES + 17, 256),
        HEADER.pack(MAGIC, FORMAT_VERSION, 0, 1, 0, MAX_SIGNATURE_BYTES + 1),
        HEADER.pack(MAGIC, FORMAT_VERSION, 0, 1, 0, 256) + b"\xff" + b"x" * 256,
    ],
)
def test_envelope_rejects_truncated_oversized_and_invalid_encoding(raw):
    with pytest.raises(PayloadFormatError):
        parse_envelope(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("manifest_version", True),
        ("payload_format", 1.5),
        ("media_type", []),
        ("media_id", False),
        ("nonce", []),
        ("lsb_count", 1.5),
        ("start_method", []),
        ("start_location", False),
        ("payload_length", 2.5),
        ("carrier_payload_length", []),
        ("public_key_fingerprint", False),
        ("robustness", []),
    ],
)
def test_manifest_rejects_wrong_scalar_types(field, value):
    manifest = _manifest_dict()
    manifest[field] = value
    with pytest.raises(ManifestError):
        Manifest.from_dict(manifest)


@pytest.mark.parametrize("field", ["manifest_version", "payload_format", "media_id"])
def test_manifest_rejects_missing_required_fields(field):
    manifest = _manifest_dict()
    del manifest[field]
    with pytest.raises(ManifestError, match="missing required"):
        Manifest.from_dict(manifest)


@pytest.mark.parametrize(
    ("field", "version"), [("manifest_version", 2), ("payload_format", 2)]
)
def test_manifest_rejects_unsupported_versions(field, version):
    manifest = _manifest_dict()
    manifest[field] = version
    with pytest.raises(ManifestError, match="unsupported"):
        Manifest.from_dict(manifest)


def test_manifest_loader_rejects_duplicates_invalid_utf8_and_oversize(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"manifest_version":1,"manifest_version":1}', encoding="utf-8")
    with pytest.raises(ManifestError, match="duplicate"):
        load_manifest(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ManifestError, match="UTF-8"):
        load_manifest(path)
    path.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ManifestError, match="1 MiB"):
        load_manifest(path)


def test_unsuitable_public_key_returns_structured_failure(monkeypatch):
    manifest = Manifest.from_dict(_manifest_dict())
    monkeypatch.setattr("app.verification.verifier.load_manifest", lambda _: manifest)
    result = verify_media("unused", "unused", object())
    assert result.verdict is Verdict.CANNOT_VERIFY
    assert any(check.name == "Trusted key" for check in result.checks)


def test_malformed_extracted_envelope_never_returns_authentic(monkeypatch, rsa_keys):
    _, public_key = rsa_keys
    manifest = Manifest.from_dict(_manifest_dict())
    monkeypatch.setattr("app.verification.verifier.load_manifest", lambda _: manifest)
    monkeypatch.setattr(
        "app.verification.verifier.resolve_start_location", lambda *args: (0, object())
    )
    monkeypatch.setattr("app.verification.verifier._extract", lambda *args: b"malformed")
    result = verify_media("unused", "unused", public_key)
    assert result.verdict is Verdict.CANNOT_VERIFY
    assert not result.authentic
