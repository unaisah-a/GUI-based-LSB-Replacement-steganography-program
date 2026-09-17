"""Tests for the companion manifest and the payload composition module.

The manifest is untrusted input, so the emphasis is on rejection: every field is
checked for type, range and supported value before any of it can drive an
extraction. The second emphasis is the cross-check against the signed record,
which is what makes a manifest's claims trustworthy in retrospect.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.crypto import envelope as env
from app.crypto import key_manager, manifest as manifest_module, payload, signatures
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.envelope import EncryptionParameters, ErrorCorrectionParameters
from app.crypto.errors import EncryptionError, ManifestError, RecordError
from app.utils import constants, file_utils

FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}
SECRET_PASSPHRASE = "shared out of band"
START_SECRET = "start location secret"


@pytest.fixture(scope="module")
def key_pair():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


def make_record(**overrides) -> env.VerificationRecord:
    values = {
        "media_id": "IMG-001",
        "media_type": constants.MEDIA_IMAGE,
        "timestamp": "2026-09-17T12:00:00+00:00",
        "nonce_hex": "0f" * 16,
        "message_hash": "ab" * 32,
        "message_length": 11,
        "lsb_depth": 3,
        "start_method": constants.START_METHOD_HMAC,
    }
    values.update(overrides)
    return env.VerificationRecord(**values)


def make_manifest(**overrides) -> manifest_module.Manifest:
    record = overrides.pop("record", make_record())
    values = {
        "envelope_length": 1802,
        "container_format": constants.CONTAINER_PNG,
    }
    values.update(overrides)
    return manifest_module.Manifest.from_record(record, **values)


# --------------------------------------------------------------------------- #
# Construction from a record
# --------------------------------------------------------------------------- #


class TestFromRecord:
    def test_copies_the_signed_parameters(self):
        record = make_record()
        result = make_manifest(record=record)

        assert result.media_id == record.media_id
        assert result.media_type == record.media_type
        assert result.nonce_hex == record.nonce_hex
        assert result.lsb_depth == record.lsb_depth
        assert result.start_method == record.start_method
        assert result.message_length == record.message_length
        assert result.encrypted == record.encrypted

    def test_derived_mode_never_publishes_the_location(self):
        """Publishing it would hand over the one value the secret protects."""
        result = make_manifest(resolved_start_location=91_234)
        assert result.start_method == constants.START_METHOD_HMAC
        assert result.start_location is None
        assert result.as_dict()["start_location"] is None

    def test_manual_mode_publishes_the_location(self):
        record = make_record(
            start_method=constants.START_METHOD_MANUAL, start_location=4096
        )
        result = make_manifest(record=record, resolved_start_location=4096)
        assert result.start_location == 4096

    def test_envelope_length_is_supplied_not_read_from_the_record(self):
        """The record cannot carry it; see the VerificationRecord docstring."""
        assert "envelope_length" not in make_record().as_dict()
        assert make_manifest(envelope_length=2048).envelope_length == 2048

    def test_created_timestamp_is_filled_in(self):
        assert make_manifest().created is not None

    def test_encryption_and_ecc_are_carried_through(self):
        parameters = EncryptionParameters(
            constants.CIPHER_AES_256_GCM,
            constants.KDF_SCRYPT,
            "ab" * 16,
            MIN_SCRYPT_N,
            8,
            1,
        )
        correction = ErrorCorrectionParameters(constants.ECC_REPETITION, 3)
        record = make_record(encryption=parameters, ecc=correction)
        result = make_manifest(record=record)

        assert result.encrypted is True
        assert result.encryption == parameters
        assert result.ecc == correction


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_dictionary_round_trip(self):
        original = make_manifest()
        assert manifest_module.Manifest.from_dict(original.as_dict()) == original

    def test_file_round_trip(self, tmp_path):
        original = make_manifest()
        path = manifest_module.write_manifest(
            original, str(tmp_path / "cover_stego.png.manifest.json")
        )
        assert manifest_module.read_manifest(path) == original

    def test_written_next_to_the_stego_file_by_convention(self, tmp_path):
        stego = tmp_path / "cover_stego.png"
        stego.write_bytes(b"not really a png")
        path = manifest_module.write_manifest(make_manifest(), stego_path=str(stego))

        assert path == str(tmp_path / "cover_stego.png.manifest.json")
        assert Path(path).is_file()

    def test_manifest_is_human_readable(self, tmp_path):
        """It is meant to be opened and read during the demonstration."""
        path = manifest_module.write_manifest(
            make_manifest(), str(tmp_path / "m.json")
        )
        text = Path(path).read_text(encoding="utf-8")

        assert "\n" in text
        assert '"lsb_depth": 3' in text

    def test_every_manual_field_round_trips(self, tmp_path):
        record = make_record(
            start_method=constants.START_METHOD_MANUAL,
            start_location=4096,
            encryption=EncryptionParameters(
                constants.CIPHER_AES_256_GCM,
                constants.KDF_SCRYPT,
                "cd" * 16,
                MIN_SCRYPT_N,
                8,
                1,
            ),
            ecc=ErrorCorrectionParameters(constants.ECC_REPETITION, 5),
        )
        original = manifest_module.Manifest.from_record(
            record,
            envelope_length=4096,
            container_format=constants.CONTAINER_BMP,
            resolved_start_location=4096,
            stego_file_name="cover_stego.bmp",
            stego_sha256="ef" * 32,
        )
        path = manifest_module.write_manifest(original, str(tmp_path / "m.json"))
        assert manifest_module.read_manifest(path) == original

    def test_notice_about_start_location_is_included(self):
        assert make_manifest().as_dict()["notice"] == constants.START_LOCATION_NOTICE

    def test_existing_manifest_is_not_overwritten_by_default(self, tmp_path):
        path = str(tmp_path / "m.json")
        manifest_module.write_manifest(make_manifest(), path)
        with pytest.raises(ManifestError, match="already occupied"):
            manifest_module.write_manifest(make_manifest(), path)

    def test_overwrite_replaces_it(self, tmp_path):
        path = str(tmp_path / "m.json")
        manifest_module.write_manifest(make_manifest(envelope_length=100_000), path)
        manifest_module.write_manifest(
            make_manifest(envelope_length=2048), path, overwrite=True
        )
        assert manifest_module.read_manifest(path).envelope_length == 2048

    def test_write_requires_a_destination(self):
        with pytest.raises(ManifestError, match="path or stego_path"):
            manifest_module.write_manifest(make_manifest())

    def test_write_rejects_a_non_manifest(self, tmp_path):
        with pytest.raises(ManifestError, match="must be a Manifest"):
            manifest_module.write_manifest({"lsb_depth": 3}, str(tmp_path / "m.json"))


# --------------------------------------------------------------------------- #
# No secrets
# --------------------------------------------------------------------------- #


class TestNoSecrets:
    def test_a_real_protect_manifest_contains_neither_secret(self, tmp_path, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"a confidential message",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        result = manifest_module.Manifest.from_record(
            prepared.record,
            envelope_length=prepared.envelope_length,
            container_format=constants.CONTAINER_PNG,
        )
        path = manifest_module.write_manifest(result, str(tmp_path / "m.json"))
        text = Path(path).read_text(encoding="utf-8")

        assert SECRET_PASSPHRASE not in text
        assert START_SECRET not in text

    def test_the_salt_is_published_because_it_is_not_a_secret(self, tmp_path, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"message",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        result = manifest_module.Manifest.from_record(
            prepared.record,
            envelope_length=prepared.envelope_length,
            container_format=constants.CONTAINER_PNG,
        )
        assert result.encryption is not None
        assert result.as_dict()["encryption"]["salt"] == result.encryption.salt_hex

    def test_the_plaintext_is_not_in_the_manifest(self, tmp_path, key_pair):
        private_key, _ = key_pair
        message = b"UNIQUE-PLAINTEXT-MARKER"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        result = manifest_module.Manifest.from_record(
            prepared.record,
            envelope_length=prepared.envelope_length,
            container_format=constants.CONTAINER_PNG,
        )
        assert b"UNIQUE-PLAINTEXT-MARKER" not in json.dumps(result.as_dict()).encode()


# --------------------------------------------------------------------------- #
# Validation of untrusted input
# --------------------------------------------------------------------------- #


class TestManifestValidation:
    def _mutated(self, **changes):
        data = make_manifest().as_dict()
        data.update(changes)
        return data

    def test_unsupported_format_version(self):
        with pytest.raises(ManifestError, match="format version"):
            manifest_module.Manifest.from_dict(self._mutated(format_version=99))

    def test_missing_field_is_named(self):
        data = make_manifest().as_dict()
        del data["lsb_depth"]
        with pytest.raises(ManifestError, match="lsb_depth"):
            manifest_module.Manifest.from_dict(data)

    def test_not_an_object(self):
        with pytest.raises(ManifestError, match="JSON object"):
            manifest_module.Manifest.from_dict([1, 2, 3])

    @pytest.mark.parametrize("depth", [0, 9, -1, 1000])
    def test_depth_out_of_range(self, depth):
        with pytest.raises(ManifestError, match="lsb_depth"):
            manifest_module.Manifest.from_dict(self._mutated(lsb_depth=depth))

    @pytest.mark.parametrize("depth", list(range(1, 9)))
    def test_every_valid_depth_is_accepted(self, depth):
        assert (
            manifest_module.Manifest.from_dict(
                self._mutated(lsb_depth=depth)
            ).lsb_depth
            == depth
        )

    def test_boolean_depth_is_refused(self):
        with pytest.raises(ManifestError, match="boolean"):
            manifest_module.Manifest.from_dict(self._mutated(lsb_depth=True))

    def test_unknown_media_type(self):
        with pytest.raises(ManifestError, match="media_type"):
            manifest_module.Manifest.from_dict(self._mutated(media_type="hologram"))

    def test_container_must_match_the_media_type(self):
        """A WAV container on image media is nonsense and must not be acted on."""
        with pytest.raises(ManifestError, match="container_format"):
            manifest_module.Manifest.from_dict(
                self._mutated(container_format=constants.CONTAINER_WAV)
            )

    def test_unknown_start_method(self):
        with pytest.raises(ManifestError, match="start_method"):
            manifest_module.Manifest.from_dict(self._mutated(start_method="guess"))

    def test_envelope_length_below_the_minimum_envelope(self):
        with pytest.raises(ManifestError, match="envelope_length"):
            manifest_module.Manifest.from_dict(self._mutated(envelope_length=4))

    def test_absurd_envelope_length_is_refused_before_extraction(self):
        """A hostile length must not reach the stego layer's allocator."""
        with pytest.raises(ManifestError, match="envelope_length"):
            manifest_module.Manifest.from_dict(
                self._mutated(envelope_length=2**40)
            )

    def test_negative_message_length(self):
        with pytest.raises(ManifestError, match="message_length"):
            manifest_module.Manifest.from_dict(self._mutated(message_length=-1))

    def test_zero_message_length_is_allowed(self):
        assert (
            manifest_module.Manifest.from_dict(
                self._mutated(message_length=0)
            ).message_length
            == 0
        )

    def test_derived_method_must_not_publish_a_location(self):
        with pytest.raises(ManifestError, match="must be null"):
            manifest_module.Manifest.from_dict(self._mutated(start_location=1234))

    def test_manual_method_requires_a_location(self):
        data = self._mutated(start_method=constants.START_METHOD_MANUAL)
        data["start_location"] = None
        with pytest.raises(ManifestError, match="must be an integer"):
            manifest_module.Manifest.from_dict(data)

    def test_manual_method_rejects_a_negative_location(self):
        data = self._mutated(start_method=constants.START_METHOD_MANUAL)
        data["start_location"] = -5
        with pytest.raises(ManifestError, match="negative"):
            manifest_module.Manifest.from_dict(data)

    def test_missing_start_location_key(self):
        data = make_manifest().as_dict()
        del data["start_location"]
        with pytest.raises(ManifestError, match="start_location"):
            manifest_module.Manifest.from_dict(data)

    def test_encrypted_without_parameters_is_refused(self):
        """Otherwise the key could not be derived and the failure would be obscure."""
        with pytest.raises(ManifestError, match="no 'encryption' parameters"):
            manifest_module.Manifest.from_dict(self._mutated(encrypted=True))

    def test_parameters_without_the_encrypted_flag_are_refused(self):
        data = self._mutated()
        data["encryption"] = {
            "cipher": constants.CIPHER_AES_256_GCM,
            "kdf": constants.KDF_SCRYPT,
            "salt": "ab" * 16,
            "n": MIN_SCRYPT_N,
            "r": 8,
            "p": 1,
        }
        with pytest.raises(ManifestError, match="not encrypted"):
            manifest_module.Manifest.from_dict(data)

    def test_invalid_encryption_block_is_a_manifest_error(self):
        """One error category for callers handling manifest input."""
        data = self._mutated(encrypted=True)
        data["encryption"] = {
            "cipher": "DES",
            "kdf": constants.KDF_SCRYPT,
            "salt": "ab" * 16,
            "n": MIN_SCRYPT_N,
            "r": 8,
            "p": 1,
        }
        with pytest.raises(ManifestError, match="parameter block is invalid"):
            manifest_module.Manifest.from_dict(data)

    def test_invalid_ecc_block_is_a_manifest_error(self):
        data = self._mutated()
        data["ecc"] = {"scheme": constants.ECC_REPETITION, "factor": 4}
        with pytest.raises(ManifestError, match="parameter block is invalid"):
            manifest_module.Manifest.from_dict(data)

    def test_non_hex_nonce(self):
        with pytest.raises(ManifestError, match="nonce"):
            manifest_module.Manifest.from_dict(self._mutated(nonce="zzz"))

    def test_wrong_length_stego_digest(self):
        with pytest.raises(ManifestError, match="stego_sha256"):
            manifest_module.Manifest.from_dict(self._mutated(stego_sha256="abcd"))

    def test_non_hex_stego_digest(self):
        with pytest.raises(ManifestError, match="stego_sha256"):
            manifest_module.Manifest.from_dict(self._mutated(stego_sha256="z" * 64))

    def test_null_stego_digest_is_allowed(self):
        assert (
            manifest_module.Manifest.from_dict(
                self._mutated(stego_sha256=None)
            ).stego_sha256
            is None
        )

    def test_non_string_stego_file_name(self):
        with pytest.raises(ManifestError, match="stego_file"):
            manifest_module.Manifest.from_dict(self._mutated(stego_file=42))

    def test_non_boolean_encrypted_flag(self):
        with pytest.raises(ManifestError, match="encrypted"):
            manifest_module.Manifest.from_dict(self._mutated(encrypted="yes"))


class TestManifestReadErrors:
    def test_missing_file_explains_the_manifest_is_required(self, tmp_path):
        with pytest.raises(ManifestError, match="sent alongside"):
            manifest_module.read_manifest(str(tmp_path / "absent.manifest.json"))

    def test_directory(self, tmp_path):
        with pytest.raises(ManifestError, match="directory"):
            manifest_module.read_manifest(str(tmp_path))

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ManifestError, match="not valid JSON"):
            manifest_module.read_manifest(str(path))

    def test_json_array(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text("[1,2,3]", encoding="utf-8")
        with pytest.raises(ManifestError, match="JSON object"):
            manifest_module.read_manifest(str(path))

    def test_error_message_omits_the_directory(self, tmp_path):
        path = tmp_path / "manifest_marker.json"
        path.write_text("{not json", encoding="utf-8")

        with pytest.raises(ManifestError) as caught:
            manifest_module.read_manifest(str(path))

        assert "manifest_marker.json" in str(caught.value)
        assert str(tmp_path) not in str(caught.value)


# --------------------------------------------------------------------------- #
# Cross-checking against the signed record
# --------------------------------------------------------------------------- #


class TestCrossCheck:
    def test_a_matching_pair_reports_nothing(self):
        record = make_record()
        assert manifest_module.cross_check(make_manifest(record=record), record) == ()

    def test_envelope_length_is_confirmed_when_supplied(self):
        record = make_record()
        result = make_manifest(record=record, envelope_length=1802)
        assert manifest_module.cross_check(result, record, envelope_length=1802) == ()

    def test_a_mutated_envelope_length_is_caught(self):
        """This is how a manifest length claim gets checked against signed bytes."""
        record = make_record()
        result = make_manifest(record=record, envelope_length=1802)
        assert manifest_module.cross_check(
            result, record, envelope_length=1900
        ) == ("envelope_length",)

    @pytest.mark.parametrize(
        ("field", "value", "expected"),
        [
            ("media_id", "IMG-999", "media_id"),
            ("nonce_hex", "ff" * 16, "nonce"),
            ("lsb_depth", 7, "lsb_depth"),
            ("message_length", 999, "message_length"),
        ],
    )
    def test_each_mutated_field_is_reported(self, field, value, expected):
        record = make_record()
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{**vars(original), field: value}
        )
        assert expected in manifest_module.cross_check(mutated, record)

    def test_a_mutated_media_type_is_caught(self):
        record = make_record()
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{**vars(original), "media_type": constants.MEDIA_AUDIO}
        )
        assert "media_type" in manifest_module.cross_check(mutated, record)

    def test_a_mutated_start_method_is_caught(self):
        record = make_record()
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{**vars(original), "start_method": constants.START_METHOD_MANUAL}
        )
        assert "start_method" in manifest_module.cross_check(mutated, record)

    def test_a_mutated_manual_start_location_is_caught(self):
        record = make_record(
            start_method=constants.START_METHOD_MANUAL, start_location=4096
        )
        original = make_manifest(record=record, resolved_start_location=4096)
        mutated = manifest_module.Manifest(
            **{**vars(original), "start_location": 5000}
        )
        assert "start_location" in manifest_module.cross_check(mutated, record)

    def test_a_derived_location_is_not_compared(self):
        """There is nothing to compare: both sides are null by design."""
        record = make_record()
        assert "start_location" not in manifest_module.cross_check(
            make_manifest(record=record), record
        )

    def test_a_flipped_encrypted_flag_is_caught(self):
        record = make_record()
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(**{**vars(original), "encrypted": True})
        assert "encrypted" in manifest_module.cross_check(mutated, record)

    def test_mutated_encryption_parameters_are_caught(self):
        parameters = EncryptionParameters(
            constants.CIPHER_AES_256_GCM,
            constants.KDF_SCRYPT,
            "ab" * 16,
            MIN_SCRYPT_N,
            8,
            1,
        )
        record = make_record(encryption=parameters)
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{
                **vars(original),
                "encryption": EncryptionParameters(
                    constants.CIPHER_AES_256_GCM,
                    constants.KDF_SCRYPT,
                    "cd" * 16,
                    MIN_SCRYPT_N,
                    8,
                    1,
                ),
            }
        )
        assert "encryption" in manifest_module.cross_check(mutated, record)

    def test_mutated_ecc_parameters_are_caught(self):
        record = make_record(ecc=ErrorCorrectionParameters(constants.ECC_REPETITION, 3))
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{
                **vars(original),
                "ecc": ErrorCorrectionParameters(constants.ECC_REPETITION, 5),
            }
        )
        assert "ecc" in manifest_module.cross_check(mutated, record)

    def test_several_mutations_are_all_reported(self):
        record = make_record()
        original = make_manifest(record=record)
        mutated = manifest_module.Manifest(
            **{**vars(original), "media_id": "IMG-999", "lsb_depth": 8}
        )
        reported = manifest_module.cross_check(mutated, record)
        assert set(reported) == {"media_id", "lsb_depth"}

    def test_type_checks(self):
        record = make_record()
        with pytest.raises(ManifestError, match="must be a Manifest"):
            manifest_module.cross_check({"media_id": "x"}, record)
        with pytest.raises(ManifestError, match="VerificationRecord"):
            manifest_module.cross_check(make_manifest(), {"media_id": "x"})


# --------------------------------------------------------------------------- #
# Payload composition
# --------------------------------------------------------------------------- #


class TestPreparePayload:
    def test_produces_a_parseable_signed_envelope(self, key_pair):
        private_key, public_key = key_pair
        prepared = payload.prepare_payload(
            b"hello world",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        parsed = env.parse_envelope(prepared.envelope)

        assert signatures.verify_envelope_signature(parsed, public_key) is True
        assert prepared.envelope_length == len(prepared.envelope)
        assert prepared.envelope_length == parsed.total_length

    def test_records_the_plaintext_digest_even_when_encrypted(self, key_pair):
        from app.crypto.hashing import compute_media_hash

        private_key, _ = key_pair
        message = b"a confidential message"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        assert prepared.record.message_hash == compute_media_hash(message)
        assert prepared.record.message_length == len(message)

    def test_encryption_grows_the_stored_message_by_the_overhead(self, key_pair):
        from app.crypto.encryption import OVERHEAD_BYTES

        private_key, _ = key_pair
        message = b"a confidential message"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        assert prepared.stored_message_length == len(message) + OVERHEAD_BYTES
        assert prepared.encrypted is True
        assert prepared.flags & constants.ENVELOPE_FLAG_ENCRYPTED

    def test_plaintext_is_not_in_the_envelope_when_encrypted(self, key_pair):
        private_key, _ = key_pair
        message = b"UNIQUE-PLAINTEXT-MARKER"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        assert message not in prepared.envelope

    def test_plaintext_is_in_the_envelope_when_not_encrypted(self, key_pair):
        """Integrity without confidentiality is the honest default to demonstrate."""
        private_key, _ = key_pair
        message = b"UNIQUE-PLAINTEXT-MARKER"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        assert message in prepared.envelope

    def test_nonce_is_fresh_per_call(self, key_pair):
        private_key, _ = key_pair
        nonces = {
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=1,
            ).record.nonce_hex
            for _ in range(10)
        }
        assert len(nonces) == 10

    def test_nonce_length(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"m",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=1,
        )
        assert len(prepared.record.nonce_hex) == constants.RECORD_NONCE_BYTES * 2

    def test_empty_message_is_allowed(self, key_pair):
        private_key, public_key = key_pair
        prepared = payload.prepare_payload(
            b"",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=1,
        )
        parsed = env.parse_envelope(prepared.envelope)
        assert signatures.verify_envelope_signature(parsed, public_key)
        assert prepared.message_length == 0

    def test_manual_mode_signs_the_location(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"m",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            start_method=constants.START_METHOD_MANUAL,
            start_location=4096,
        )
        assert prepared.record.start_location == 4096

    def test_manual_mode_requires_a_location(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="requires start_location"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=3,
                start_method=constants.START_METHOD_MANUAL,
            )

    def test_derived_mode_refuses_a_location(self, key_pair):
        """Accepting it would imply it gets signed, and it cannot be."""
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="must not be supplied"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=3,
                start_method=constants.START_METHOD_HMAC,
                start_location=4096,
            )

    def test_encryption_parameters_without_a_passphrase_are_refused(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="without a passphrase"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=3,
                encryption_parameters=EncryptionParameters(
                    constants.CIPHER_AES_256_GCM,
                    constants.KDF_SCRYPT,
                    "ab" * 16,
                    MIN_SCRYPT_N,
                    8,
                    1,
                ),
            )

    def test_invalid_depth_is_reported_at_prepare_time(self, key_pair):
        """Better here than as a puzzling failure on the receiver."""
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="lsb_depth"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=99,
            )

    def test_unknown_media_type_is_reported(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="media_type"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type="hologram",
                lsb_depth=3,
            )

    def test_unknown_start_method_is_reported(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="start_method"):
            payload.prepare_payload(
                b"m",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=3,
                start_method="telepathy",
            )

    def test_non_bytes_message_is_refused(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(RecordError, match="bytes-like"):
            payload.prepare_payload(
                "a string",
                private_key,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                lsb_depth=3,
            )

    def test_metadata_is_carried_into_the_record(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"m",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            metadata={"team": "P1-1"},
        )
        assert prepared.record.metadata == {"team": "P1-1"}


class TestRecoverMessage:
    def test_plain_message_round_trips(self, key_pair):
        private_key, public_key = key_pair
        message = b"hello world"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        parsed = env.parse_envelope(prepared.envelope)
        assert signatures.verify_envelope_signature(parsed, public_key)

        recovered = payload.recover_message(
            parsed, env.VerificationRecord.from_dict(parsed.record)
        )
        assert recovered.message == message
        assert recovered.hash_matches is True
        assert recovered.was_encrypted is False

    def test_encrypted_message_round_trips(self, key_pair):
        private_key, public_key = key_pair
        message = b"a confidential message"
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        parsed = env.parse_envelope(prepared.envelope)
        assert signatures.verify_envelope_signature(parsed, public_key)

        recovered = payload.recover_message(
            parsed,
            env.VerificationRecord.from_dict(parsed.record),
            passphrase=SECRET_PASSPHRASE,
        )
        assert recovered.message == message
        assert recovered.hash_matches is True
        assert recovered.was_encrypted is True

    def test_wrong_passphrase_is_an_encryption_error(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"a confidential message",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        parsed = env.parse_envelope(prepared.envelope)
        with pytest.raises(EncryptionError, match="authentication tag"):
            payload.recover_message(
                parsed,
                env.VerificationRecord.from_dict(parsed.record),
                passphrase="wrong",
            )

    def test_missing_passphrase_explains_it_is_shared_separately(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"a confidential message",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        parsed = env.parse_envelope(prepared.envelope)
        with pytest.raises(EncryptionError, match="shared separately"):
            payload.recover_message(
                parsed, env.VerificationRecord.from_dict(parsed.record)
            )

    def test_hash_mismatch_is_reported_without_raising(self, key_pair):
        """A mismatch is a verdict input, not an exception."""
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"hello world",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        parsed = env.parse_envelope(prepared.envelope)
        record = env.VerificationRecord.from_dict(parsed.record)
        lying = env.VerificationRecord(
            **{**vars(record), "message_hash": "00" * 32}
        )

        recovered = payload.recover_message(parsed, lying)
        assert recovered.hash_matches is False
        assert recovered.message == b"hello world"

    def test_length_mismatch_alone_fails_the_check(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"hello world",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        parsed = env.parse_envelope(prepared.envelope)
        record = env.VerificationRecord.from_dict(parsed.record)
        lying = env.VerificationRecord(**{**vars(record), "message_length": 999})

        assert payload.recover_message(parsed, lying).hash_matches is False

    def test_type_checks(self, key_pair):
        private_key, _ = key_pair
        prepared = payload.prepare_payload(
            b"m",
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        parsed = env.parse_envelope(prepared.envelope)
        with pytest.raises(RecordError, match="ParsedEnvelope"):
            payload.recover_message(b"raw", make_record())
        with pytest.raises(RecordError, match="VerificationRecord"):
            payload.recover_message(parsed, {"media_id": "x"})


class TestRemovedPayloadFunctions:
    """The superseded envelope helpers must not come back.

    ``build_payload_block`` serialised its JSON without ``sort_keys``, so
    re-serialising a parsed record could produce different bytes and break the
    signature over it.
    """

    def test_build_payload_block_is_gone(self):
        assert not hasattr(payload, "build_payload_block")

    def test_parse_payload_block_is_gone(self):
        assert not hasattr(payload, "parse_payload_block")


class TestEnvelopeLengthPrediction:
    def test_prediction_matches_a_real_unencrypted_payload(self, key_pair):
        private_key, _ = key_pair
        message = b"x" * 200
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
        )
        predicted = payload.predict_envelope_length(
            len(message), private_key, record=prepared.record, encrypted=False
        )
        assert predicted == prepared.envelope_length

    def test_prediction_matches_a_real_encrypted_payload(self, key_pair):
        private_key, _ = key_pair
        message = b"x" * 200
        prepared = payload.prepare_payload(
            message,
            private_key,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            lsb_depth=3,
            passphrase=SECRET_PASSPHRASE,
            **FAST_SCRYPT,
        )
        predicted = payload.predict_envelope_length(
            len(message), private_key, record=prepared.record, encrypted=True
        )
        assert predicted == prepared.envelope_length
