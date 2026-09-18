"""Tests for RSA-PSS signing, verification and key management.

Two behaviours matter most here and both were defects in the earlier
implementation:

* The signature block is located from the declared length fields, not by counting
  backwards from the end of the buffer, so a trailing byte cannot shift the split.
* Nothing assumes a 256-byte signature, so key sizes other than 2048 bits work.

Also pinned down: a signature that does not verify is reported as ``False``, not
raised, because it is a verification outcome that maps to a verdict.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto import envelope as env
from app.crypto import key_manager, signatures
from app.crypto.errors import KeyMaterialError, SignatureError
from app.utils import constants

# Generating RSA keys is slow, so the module-scoped fixtures below are shared by
# every test that only needs *a* valid key rather than a fresh one.


@pytest.fixture(scope="module")
def key_pair():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture(scope="module")
def other_key_pair():
    """A second, unrelated pair, for the wrong-key case."""
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture(scope="module")
def large_key_pair():
    return key_manager.generate_key_pair(3072)


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


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #


class TestKeyGeneration:
    def test_default_size_is_3072(self, large_key_pair):
        private_key, public_key = large_key_pair
        assert private_key.key_size == 3072
        assert public_key.key_size == 3072
        assert constants.RSA_KEY_SIZE_DEFAULT == 3072

    def test_public_exponent_is_65537(self, key_pair):
        _, public_key = key_pair
        assert public_key.public_numbers().e == 65537

    def test_sizes_below_the_minimum_are_refused(self):
        with pytest.raises(KeyMaterialError, match="at least"):
            key_manager.generate_key_pair(1024)

    def test_non_integer_size_is_refused(self):
        with pytest.raises(KeyMaterialError, match="integer"):
            key_manager.generate_key_pair("3072")

    def test_signature_size_follows_the_modulus(self, key_pair, large_key_pair):
        assert signatures.signature_size_bytes(key_pair[0]) == 256
        assert signatures.signature_size_bytes(large_key_pair[0]) == 384

    def test_signature_size_accepts_a_public_key(self, large_key_pair):
        assert signatures.signature_size_bytes(large_key_pair[1]) == 384

    def test_signature_size_rejects_a_non_key(self):
        with pytest.raises(KeyMaterialError):
            signatures.signature_size_bytes("key")


# --------------------------------------------------------------------------- #
# Signing and verification
# --------------------------------------------------------------------------- #


class TestSignAndVerify:
    def test_round_trip(self, key_pair):
        private_key, public_key = key_pair
        record = make_record().to_bytes()
        envelope = signatures.sign_envelope(record, b"hello world", private_key)

        parsed = env.parse_envelope(envelope)
        assert signatures.verify_envelope_signature(parsed, public_key) is True

    def test_signature_length_matches_the_key(self, large_key_pair):
        private_key, _ = large_key_pair
        envelope = signatures.sign_envelope(
            make_record().to_bytes(), b"hello", private_key
        )
        assert len(env.parse_envelope(envelope).signature) == 384

    def test_3072_bit_keys_work(self, large_key_pair):
        """Nothing may assume the 256-byte signature of a 2048-bit key."""
        private_key, public_key = large_key_pair
        envelope = signatures.sign_envelope(
            make_record().to_bytes(), b"hello", private_key
        )
        parsed = env.parse_envelope(envelope)
        assert signatures.verify_envelope_signature(parsed, public_key) is True

    def test_wrong_public_key_fails_verification(self, key_pair, other_key_pair):
        private_key, _ = key_pair
        _, wrong_public_key = other_key_pair
        envelope = signatures.sign_envelope(
            make_record().to_bytes(), b"hello", private_key
        )
        parsed = env.parse_envelope(envelope)

        assert signatures.verify_envelope_signature(parsed, wrong_public_key) is False

    def test_verification_failure_returns_false_rather_than_raising(
        self, key_pair, other_key_pair
    ):
        private_key, _ = key_pair
        _, wrong_public_key = other_key_pair
        signed = env.signing_input(b"{}", b"m")
        signature = signatures.sign_signed_region(signed, private_key)

        assert (
            signatures.verify_signed_region(signed, signature, wrong_public_key)
            is False
        )

    def test_pss_signatures_are_randomised(self, key_pair):
        """MAX_LENGTH salt means two valid signatures over the same bytes differ."""
        private_key, public_key = key_pair
        signed = env.signing_input(make_record().to_bytes(), b"hello")

        first = signatures.sign_signed_region(signed, private_key)
        second = signatures.sign_signed_region(signed, private_key)

        assert first != second
        assert signatures.verify_signed_region(signed, first, public_key)
        assert signatures.verify_signed_region(signed, second, public_key)

    def test_signing_input_is_the_shared_definition(self, key_pair):
        """Signing and verification must agree on the covered bytes."""
        private_key, public_key = key_pair
        record = make_record().to_bytes()
        message = b"payload"
        envelope = signatures.sign_envelope(record, message, private_key)
        parsed = env.parse_envelope(envelope)

        assert parsed.signed_region == env.signing_input(record, message, 0)
        assert signatures.verify_signed_region(
            env.signing_input(record, message, 0), parsed.signature, public_key
        )


class TestTamperDetection:
    @pytest.fixture()
    def signed_envelope(self, key_pair):
        private_key, _ = key_pair
        return signatures.sign_envelope(
            make_record().to_bytes(), b"transfer 100 units", private_key
        )

    def test_modified_record_fails(self, signed_envelope, key_pair):
        """Substitute a different but structurally valid record.

        A blind byte flip would usually corrupt the record's JSON, so parsing
        would fail before the signature was ever checked. Swapping in a
        well-formed record with one changed field is the case that actually
        exercises the signature.
        """
        _, public_key = key_pair
        parsed = env.parse_envelope(signed_envelope)
        forged_record = make_record(media_id="IMG-999").to_bytes()
        assert forged_record != parsed.record_bytes

        forged = env.build_envelope(
            forged_record, parsed.message, parsed.signature, parsed.flags
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_single_byte_flip_inside_a_record_string_fails(self, signed_envelope, key_pair):
        """A flip that keeps the JSON parseable still fails the signature."""
        _, public_key = key_pair
        parsed = env.parse_envelope(signed_envelope)
        original = parsed.record_bytes
        index = original.index(b"IMG-001")
        mutated = bytearray(original)
        mutated[index] = ord("J")

        forged = env.build_envelope(
            bytes(mutated), parsed.message, parsed.signature, parsed.flags
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_modified_message_fails(self, signed_envelope, key_pair):
        _, public_key = key_pair
        parsed = env.parse_envelope(signed_envelope)
        forged = env.build_envelope(
            parsed.record_bytes,
            b"transfer 900 units",
            parsed.signature,
            parsed.flags,
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_modified_signature_fails(self, signed_envelope, key_pair):
        _, public_key = key_pair
        parsed = env.parse_envelope(signed_envelope)
        mutated = bytearray(parsed.signature)
        mutated[0] ^= 0x01

        forged = env.build_envelope(
            parsed.record_bytes, parsed.message, bytes(mutated), parsed.flags
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_flipped_encrypted_flag_fails(self, signed_envelope, key_pair):
        """The flags byte is inside the signed region."""
        _, public_key = key_pair
        parsed = env.parse_envelope(signed_envelope)
        forged = env.build_envelope(
            parsed.record_bytes,
            parsed.message,
            parsed.signature,
            constants.ENVELOPE_FLAG_ENCRYPTED,
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_moving_a_byte_across_a_section_boundary_fails(self, key_pair):
        """Length-prefixed sections stop a boundary shift going unnoticed."""
        private_key, public_key = key_pair
        envelope = signatures.sign_envelope(b'{"a":"bc"}', b"d", private_key)
        parsed = env.parse_envelope(envelope)

        forged = env.build_envelope(
            b'{"a":"b"}', b"cd", parsed.signature, parsed.flags
        )
        assert (
            signatures.verify_envelope_signature(env.parse_envelope(forged), public_key)
            is False
        )

    def test_every_single_bit_flip_in_the_signed_region_is_detected(self, key_pair):
        """Sampled rather than exhaustive: a full sweep would be very slow."""
        private_key, public_key = key_pair
        signed = env.signing_input(make_record().to_bytes(), b"hello world")
        signature = signatures.sign_signed_region(signed, private_key)

        for index in range(0, len(signed), 17):
            mutated = bytearray(signed)
            mutated[index] ^= 0x01
            assert (
                signatures.verify_signed_region(
                    bytes(mutated), signature, public_key
                )
                is False
            )

    def test_truncated_signature_fails_rather_than_raising(self, key_pair):
        private_key, public_key = key_pair
        signed = env.signing_input(b"{}", b"m")
        signature = signatures.sign_signed_region(signed, private_key)

        assert (
            signatures.verify_signed_region(signed, signature[:-1], public_key) is False
        )

    def test_empty_signature_fails_rather_than_raising(self, key_pair):
        _, public_key = key_pair
        assert (
            signatures.verify_signed_region(env.signing_input(b"{}", b""), b"", public_key)
            is False
        )


class TestKeyTypeChecks:
    def test_signing_with_a_public_key_is_refused(self, key_pair):
        _, public_key = key_pair
        with pytest.raises(KeyMaterialError, match="private key is required"):
            signatures.sign_signed_region(b"data", public_key)

    def test_verifying_with_a_private_key_is_refused(self, key_pair):
        """Catches the common slip of passing the signing key to the verifier."""
        private_key, _ = key_pair
        with pytest.raises(KeyMaterialError, match="public key is required"):
            signatures.verify_signed_region(b"data", b"sig", private_key)

    def test_non_rsa_key_is_refused(self):
        elliptic = ec.generate_private_key(ec.SECP256R1())
        with pytest.raises(KeyMaterialError, match="RSA private key"):
            signatures.sign_signed_region(b"data", elliptic)

    def test_non_key_object_is_refused(self):
        with pytest.raises(KeyMaterialError):
            signatures.sign_signed_region(b"data", "not a key")

    def test_non_bytes_region_is_refused(self, key_pair):
        private_key, _ = key_pair
        with pytest.raises(SignatureError, match="bytes-like"):
            signatures.sign_signed_region("text", private_key)

    def test_non_bytes_signature_is_refused(self, key_pair):
        _, public_key = key_pair
        with pytest.raises(SignatureError, match="bytes-like"):
            signatures.verify_signed_region(b"data", "sig", public_key)

    def test_non_parsed_envelope_is_refused(self, key_pair):
        _, public_key = key_pair
        with pytest.raises(SignatureError, match="ParsedEnvelope"):
            signatures.verify_envelope_signature(b"raw bytes", public_key)


# --------------------------------------------------------------------------- #
# Key storage
# --------------------------------------------------------------------------- #


class TestKeyStorage:
    def test_private_key_round_trips(self, tmp_path, key_pair):
        private_key, _ = key_pair
        path = str(tmp_path / "private.pem")
        key_manager.save_private_key(private_key, path)

        loaded = key_manager.load_private_key(path)
        assert loaded.key_size == private_key.key_size
        assert loaded.private_numbers().p == private_key.private_numbers().p

    def test_public_key_round_trips(self, tmp_path, key_pair):
        _, public_key = key_pair
        path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, path)

        loaded = key_manager.load_public_key(path)
        assert loaded.public_numbers().n == public_key.public_numbers().n

    def test_saved_private_key_is_pkcs8_pem(self, tmp_path, key_pair):
        private_key, _ = key_pair
        path = str(tmp_path / "private.pem")
        key_manager.save_private_key(private_key, path)

        text = (tmp_path / "private.pem").read_bytes()
        assert text.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_saved_public_key_is_spki_pem(self, tmp_path, key_pair):
        _, public_key = key_pair
        path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, path)

        text = (tmp_path / "public.pem").read_bytes()
        assert text.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_save_public_key_accepts_a_private_key_and_stores_only_the_public_half(
        self, tmp_path, key_pair
    ):
        """A common slip; writing the private key here would be a serious one."""
        private_key, _ = key_pair
        path = str(tmp_path / "public.pem")
        key_manager.save_public_key(private_key, path)

        text = (tmp_path / "public.pem").read_bytes()
        assert b"PRIVATE" not in text
        assert key_manager.load_public_key(path).public_numbers().n == (
            private_key.public_key().public_numbers().n
        )

    def test_passphrase_protected_private_key_round_trips(self, tmp_path, key_pair):
        private_key, _ = key_pair
        path = str(tmp_path / "protected.pem")
        key_manager.save_private_key(private_key, path, passphrase=b"correct horse")

        with pytest.raises(KeyMaterialError):
            key_manager.load_private_key(path)

        loaded = key_manager.load_private_key(path, passphrase=b"correct horse")
        assert loaded.key_size == private_key.key_size

    def test_missing_directory_is_created(self, tmp_path, key_pair):
        private_key, _ = key_pair
        path = str(tmp_path / "nested" / "deeper" / "private.pem")
        key_manager.save_private_key(private_key, path)
        assert os.path.isfile(path)

    def test_existing_file_is_not_overwritten_by_default(self, tmp_path, key_pair):
        private_key, _ = key_pair
        path = str(tmp_path / "private.pem")
        key_manager.save_private_key(private_key, path)

        with pytest.raises(FileExistsError):
            key_manager.save_private_key(private_key, path)

    def test_no_temporary_files_remain(self, tmp_path, key_pair):
        private_key, public_key = key_pair
        key_manager.save_private_key(private_key, str(tmp_path / "private.pem"))
        key_manager.save_public_key(public_key, str(tmp_path / "public.pem"))

        assert sorted(entry.name for entry in tmp_path.iterdir()) == [
            "private.pem",
            "public.pem",
        ]


class TestKeyLoadingErrors:
    def test_missing_private_key_file(self, tmp_path):
        with pytest.raises(KeyMaterialError, match="not found"):
            key_manager.load_private_key(str(tmp_path / "absent.pem"))

    def test_missing_public_key_file(self, tmp_path):
        with pytest.raises(KeyMaterialError, match="not found"):
            key_manager.load_public_key(str(tmp_path / "absent.pem"))

    def test_directory_instead_of_a_file(self, tmp_path):
        with pytest.raises(KeyMaterialError, match="directory"):
            key_manager.load_private_key(str(tmp_path))

    def test_garbage_content(self, tmp_path):
        path = tmp_path / "junk.pem"
        path.write_bytes(b"this is not a PEM file")
        with pytest.raises(KeyMaterialError, match="could not be loaded"):
            key_manager.load_private_key(str(path))

    def test_private_key_supplied_where_a_public_key_is_expected(
        self, tmp_path, key_pair
    ):
        """The receiver in the A-to-B demo should hold only a public key."""
        private_key, _ = key_pair
        path = str(tmp_path / "private.pem")
        key_manager.save_private_key(private_key, path)

        with pytest.raises(KeyMaterialError, match="private key file"):
            key_manager.load_public_key(path)

    def test_public_key_supplied_where_a_private_key_is_expected(
        self, tmp_path, key_pair
    ):
        _, public_key = key_pair
        path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, path)

        with pytest.raises(KeyMaterialError):
            key_manager.load_private_key(path)

    def test_non_rsa_private_key_is_refused(self, tmp_path):
        from cryptography.hazmat.primitives import serialization

        elliptic = ec.generate_private_key(ec.SECP256R1())
        path = tmp_path / "ec.pem"
        path.write_bytes(
            elliptic.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        with pytest.raises(KeyMaterialError, match="RSA private key is "):
            key_manager.load_private_key(str(path))

    def test_error_messages_omit_the_directory(self, tmp_path):
        path = tmp_path / "keyfile_marker.pem"
        path.write_bytes(b"not a pem")

        with pytest.raises(KeyMaterialError) as caught:
            key_manager.load_private_key(str(path))

        assert "keyfile_marker.pem" in str(caught.value)
        assert str(tmp_path) not in str(caught.value)

    def test_saving_a_non_key_is_refused(self, tmp_path):
        with pytest.raises(KeyMaterialError):
            key_manager.save_private_key("not a key", str(tmp_path / "x.pem"))


# --------------------------------------------------------------------------- #
# Demo key pair
# --------------------------------------------------------------------------- #


class TestDemoKeys:
    def test_first_call_creates_the_pair(self, tmp_path):
        result = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )

        assert result.created is True
        assert os.path.isfile(result.private_key_path)
        assert os.path.isfile(result.public_key_path)
        assert result.key_size == constants.RSA_MIN_KEY_SIZE

    def test_second_call_reuses_the_pair(self, tmp_path):
        """A file protected earlier in a session must still verify later in it."""
        first = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )
        before = Path(first.private_key_path).read_bytes()

        second = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )

        assert second.created is False
        assert Path(second.private_key_path).read_bytes() == before

    def test_regenerate_replaces_the_pair(self, tmp_path):
        first = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )
        before = Path(first.public_key_path).read_bytes()

        second = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE, regenerate=True
        )

        assert second.created is True
        assert Path(second.public_key_path).read_bytes() != before

    def test_generated_pair_signs_and_verifies(self, tmp_path):
        result = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )
        private_key = key_manager.load_private_key(result.private_key_path)
        public_key = key_manager.load_public_key(result.public_key_path)

        envelope = signatures.sign_envelope(
            make_record().to_bytes(), b"demo", private_key
        )
        assert signatures.verify_envelope_signature(
            env.parse_envelope(envelope), public_key
        )

    def test_paths_follow_the_configured_directories(self, tmp_path):
        private_path, public_path = key_manager.demo_key_paths(tmp_path)
        assert constants.DEMO_PRIVATE_KEY_DIR.replace("/", os.sep) in private_path
        assert constants.PUBLIC_KEY_DIR.replace("/", os.sep) in public_path

    def test_default_root_is_the_repository_not_the_cwd(self):
        private_path, _ = key_manager.demo_key_paths()
        expected_root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(key_manager.__file__)
        )))
        assert private_path.startswith(expected_root)

    def test_result_carries_the_demo_key_notice(self, tmp_path):
        """The unencrypted private key must be stated, not implied."""
        result = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )
        assert result.notice == constants.DEMO_KEY_NOTICE
        assert "unencrypted" in result.notice

    def test_private_key_is_written_without_a_passphrase(self, tmp_path):
        """Deliberate for the demo; loading without a passphrase must work."""
        result = key_manager.ensure_demo_keys(
            tmp_path, key_size=constants.RSA_MIN_KEY_SIZE
        )
        assert key_manager.load_private_key(result.private_key_path) is not None
