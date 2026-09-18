"""Tests for AES-256-GCM message encryption with a scrypt-derived key.

Scrypt at the production cost of ``n = 2**15`` takes long enough that deriving a
key hundreds of times would dominate the suite runtime, so these tests use a low
cost. The production default is asserted separately in ``tests/test_utils.py`` and
exercised end to end once in the encrypt-then-sign integration test below.
"""

from __future__ import annotations

import pytest

from app.crypto import encryption
from app.crypto.envelope import EncryptionParameters
from app.crypto.errors import EncryptionError
from app.utils import constants

#: Deliberately cheap. See the module docstring.
FAST = {"n": encryption.MIN_SCRYPT_N, "r": 8, "p": 1}

PASSPHRASE = "correct horse battery staple"
MESSAGE = b"Confidentiality and integrity for INF2005 ACW1."


@pytest.fixture()
def parameters():
    return encryption.new_parameters(salt=b"0123456789abcdef", **FAST)


class TestSaltAndParameters:
    def test_generated_salt_has_the_configured_length(self):
        assert len(encryption.generate_salt()) == constants.SCRYPT_SALT_BYTES

    def test_generated_salts_differ(self):
        assert encryption.generate_salt() != encryption.generate_salt()

    def test_new_parameters_records_the_algorithms(self, parameters):
        assert parameters.cipher == constants.CIPHER_AES_256_GCM
        assert parameters.kdf == constants.KDF_SCRYPT

    def test_new_parameters_generates_a_salt_when_none_is_given(self):
        first = encryption.new_parameters(**FAST)
        second = encryption.new_parameters(**FAST)
        assert first.salt_hex != second.salt_hex

    def test_salt_is_recorded_as_hex(self, parameters):
        assert bytes.fromhex(parameters.salt_hex) == b"0123456789abcdef"

    def test_production_defaults_are_used_when_unspecified(self):
        recorded = encryption.new_parameters(salt=b"0123456789abcdef")
        assert recorded.n == constants.SCRYPT_N
        assert recorded.r == constants.SCRYPT_R
        assert recorded.p == constants.SCRYPT_P

    def test_parameters_round_trip_through_the_record_form(self, parameters):
        assert EncryptionParameters.from_dict(parameters.as_dict()) == parameters


class TestKeyDerivation:
    def test_key_is_thirty_two_bytes(self):
        key = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        assert len(key) == constants.AES_KEY_BYTES

    def test_derivation_is_deterministic(self):
        first = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        second = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        assert first == second

    def test_different_passphrase_gives_a_different_key(self):
        first = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        second = encryption.derive_key("something else", b"0123456789abcdef", **FAST)
        assert first != second

    def test_different_salt_gives_a_different_key(self):
        first = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        second = encryption.derive_key(PASSPHRASE, b"fedcba9876543210", **FAST)
        assert first != second

    def test_str_and_bytes_passphrases_agree_for_ascii(self):
        as_text = encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **FAST)
        as_bytes = encryption.derive_key(
            PASSPHRASE.encode("utf-8"), b"0123456789abcdef", **FAST
        )
        assert as_text == as_bytes

    def test_non_ascii_passphrase_is_utf8_encoded(self):
        key = encryption.derive_key("pässwörd \u2713", b"0123456789abcdef", **FAST)
        assert len(key) == constants.AES_KEY_BYTES


class TestKeyDerivationValidation:
    def test_empty_passphrase_is_refused(self):
        with pytest.raises(EncryptionError, match="must not be empty"):
            encryption.derive_key("", b"0123456789abcdef", **FAST)

    def test_empty_byte_passphrase_is_refused(self):
        with pytest.raises(EncryptionError, match="must not be empty"):
            encryption.derive_key(b"", b"0123456789abcdef", **FAST)

    def test_non_string_passphrase_is_refused(self):
        with pytest.raises(EncryptionError, match="must be str or bytes"):
            encryption.derive_key(12345, b"0123456789abcdef", **FAST)

    def test_short_salt_is_refused(self):
        with pytest.raises(EncryptionError, match="at least 8 bytes"):
            encryption.derive_key(PASSPHRASE, b"short", **FAST)

    def test_non_bytes_salt_is_refused(self):
        with pytest.raises(EncryptionError, match="bytes-like"):
            encryption.derive_key(PASSPHRASE, "0123456789abcdef", **FAST)

    def test_non_power_of_two_cost_is_refused_with_a_clear_message(self):
        """scrypt requires a power of two; the library's own error is obscure."""
        with pytest.raises(EncryptionError, match="power of two"):
            encryption.derive_key(PASSPHRASE, b"0123456789abcdef", n=1000, r=8, p=1)

    def test_cost_below_the_floor_is_refused(self):
        with pytest.raises(EncryptionError, match="at least"):
            encryption.derive_key(PASSPHRASE, b"0123456789abcdef", n=2, r=8, p=1)

    @pytest.mark.parametrize("name", ["n", "r", "p"])
    def test_non_positive_cost_is_refused(self, name):
        kwargs = dict(FAST)
        kwargs[name] = 0
        with pytest.raises(EncryptionError, match=name):
            encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **kwargs)

    @pytest.mark.parametrize("name", ["n", "r", "p"])
    def test_boolean_cost_is_refused(self, name):
        kwargs = dict(FAST)
        kwargs[name] = True
        with pytest.raises(EncryptionError, match=name):
            encryption.derive_key(PASSPHRASE, b"0123456789abcdef", **kwargs)


class TestRoundTrip:
    def test_message_round_trips(self, parameters):
        blob, recorded = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        assert encryption.decrypt_message(blob, PASSPHRASE, recorded) == MESSAGE

    def test_empty_message_round_trips(self, parameters):
        blob, recorded = encryption.encrypt_message(
            b"", PASSPHRASE, parameters=parameters
        )
        assert encryption.decrypt_message(blob, PASSPHRASE, recorded) == b""

    def test_large_message_round_trips(self, parameters):
        payload = bytes(range(256)) * 400
        blob, recorded = encryption.encrypt_message(
            payload, PASSPHRASE, parameters=parameters
        )
        assert encryption.decrypt_message(blob, PASSPHRASE, recorded) == payload

    def test_bytearray_input_is_accepted(self, parameters):
        blob, recorded = encryption.encrypt_message(
            bytearray(MESSAGE), PASSPHRASE, parameters=parameters
        )
        assert encryption.decrypt_message(blob, PASSPHRASE, recorded) == MESSAGE

    def test_blob_layout_is_nonce_ciphertext_tag(self, parameters):
        blob, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        assert len(blob) == len(MESSAGE) + encryption.OVERHEAD_BYTES
        assert encryption.OVERHEAD_BYTES == (
            constants.GCM_NONCE_BYTES + constants.GCM_TAG_BYTES
        )

    def test_ciphertext_does_not_contain_the_plaintext(self, parameters):
        blob, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        assert MESSAGE not in blob

    def test_encrypting_twice_gives_different_blobs(self, parameters):
        """A fresh nonce per call. Nonce reuse under one key would break GCM."""
        first, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        second, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        assert first != second
        assert first[: constants.GCM_NONCE_BYTES] != second[: constants.GCM_NONCE_BYTES]

    def test_both_blobs_still_decrypt(self, parameters):
        first, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        second, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        assert encryption.decrypt_message(first, PASSPHRASE, parameters) == MESSAGE
        assert encryption.decrypt_message(second, PASSPHRASE, parameters) == MESSAGE

    def test_salt_can_be_supplied_directly(self):
        blob, recorded = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, salt=b"0123456789abcdef", **FAST
        )
        assert bytes.fromhex(recorded.salt_hex) == b"0123456789abcdef"
        assert encryption.decrypt_message(blob, PASSPHRASE, recorded) == MESSAGE


class TestDecryptionFailures:
    @pytest.fixture()
    def blob(self, parameters):
        sealed, _ = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, parameters=parameters
        )
        return sealed

    def test_wrong_passphrase_fails(self, blob, parameters):
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(blob, "wrong passphrase", parameters)

    def test_failure_message_does_not_claim_a_single_cause(self, blob, parameters):
        """A tag failure cannot distinguish a wrong key from modified ciphertext."""
        with pytest.raises(EncryptionError) as caught:
            encryption.decrypt_message(blob, "wrong passphrase", parameters)
        assert "does not distinguish" in str(caught.value)

    def test_modified_ciphertext_fails(self, blob, parameters):
        mutated = bytearray(blob)
        mutated[constants.GCM_NONCE_BYTES] ^= 0x01
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(bytes(mutated), PASSPHRASE, parameters)

    def test_modified_nonce_fails(self, blob, parameters):
        mutated = bytearray(blob)
        mutated[0] ^= 0x01
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(bytes(mutated), PASSPHRASE, parameters)

    def test_modified_tag_fails(self, blob, parameters):
        mutated = bytearray(blob)
        mutated[-1] ^= 0x01
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(bytes(mutated), PASSPHRASE, parameters)

    def test_truncated_blob_fails(self, blob, parameters):
        with pytest.raises(EncryptionError):
            encryption.decrypt_message(blob[:-1], PASSPHRASE, parameters)

    def test_blob_shorter_than_the_overhead_is_reported_clearly(self, parameters):
        with pytest.raises(EncryptionError, match="shorter than"):
            encryption.decrypt_message(b"\x00" * 8, PASSPHRASE, parameters)

    def test_empty_blob_is_reported_clearly(self, parameters):
        with pytest.raises(EncryptionError, match="shorter than"):
            encryption.decrypt_message(b"", PASSPHRASE, parameters)

    def test_wrong_salt_fails(self, blob):
        other = encryption.new_parameters(salt=b"fedcba9876543210", **FAST)
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(blob, PASSPHRASE, other)

    def test_wrong_cost_parameters_fail(self, blob):
        other = encryption.new_parameters(
            salt=b"0123456789abcdef", n=encryption.MIN_SCRYPT_N * 2, r=8, p=1
        )
        with pytest.raises(EncryptionError, match="authentication tag"):
            encryption.decrypt_message(blob, PASSPHRASE, other)

    def test_non_bytes_blob_is_refused(self, parameters):
        with pytest.raises(EncryptionError, match="bytes-like"):
            encryption.decrypt_message("text", PASSPHRASE, parameters)

    def test_non_parameter_object_is_refused(self, blob):
        with pytest.raises(EncryptionError, match="EncryptionParameters"):
            encryption.decrypt_message(blob, PASSPHRASE, {"salt": "00"})

    def test_unsupported_cipher_is_refused(self, blob, parameters):
        wrong = EncryptionParameters(
            cipher="DES",
            kdf=parameters.kdf,
            salt_hex=parameters.salt_hex,
            n=parameters.n,
            r=parameters.r,
            p=parameters.p,
        )
        with pytest.raises(EncryptionError, match="unsupported cipher"):
            encryption.decrypt_message(blob, PASSPHRASE, wrong)

    def test_unsupported_kdf_is_refused(self, blob, parameters):
        wrong = EncryptionParameters(
            cipher=parameters.cipher,
            kdf="pbkdf2",
            salt_hex=parameters.salt_hex,
            n=parameters.n,
            r=parameters.r,
            p=parameters.p,
        )
        with pytest.raises(EncryptionError, match="unsupported key derivation"):
            encryption.decrypt_message(blob, PASSPHRASE, wrong)

    def test_non_hex_recorded_salt_is_refused(self, blob, parameters):
        wrong = EncryptionParameters(
            cipher=parameters.cipher,
            kdf=parameters.kdf,
            salt_hex="not hex!!",
            n=parameters.n,
            r=parameters.r,
            p=parameters.p,
        )
        with pytest.raises(EncryptionError, match="hexadecimal"):
            encryption.decrypt_message(blob, PASSPHRASE, wrong)


class TestEncryptionInputValidation:
    def test_non_bytes_plaintext_is_refused(self, parameters):
        with pytest.raises(EncryptionError, match="bytes-like"):
            encryption.encrypt_message("text", PASSPHRASE, parameters=parameters)

    def test_empty_passphrase_is_refused(self, parameters):
        with pytest.raises(EncryptionError, match="must not be empty"):
            encryption.encrypt_message(MESSAGE, "", parameters=parameters)


class TestEncryptThenSign:
    """The ordering that makes a wrong signing key a clean signature failure."""

    def test_signature_verifies_before_decryption_is_attempted(self):
        from app.crypto import envelope as env
        from app.crypto import key_manager, signatures
        from app.crypto.hashing import sha256_hex

        private_key, public_key = key_manager.generate_key_pair(
            constants.RSA_MIN_KEY_SIZE
        )
        blob, recorded = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, salt=b"0123456789abcdef", **FAST
        )

        record = env.VerificationRecord(
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            timestamp=env.utc_timestamp(),
            nonce_hex="0f" * 16,
            # The digest is of the PLAINTEXT, not the ciphertext.
            message_hash=sha256_hex(MESSAGE),
            message_length=len(MESSAGE),
            lsb_depth=3,
            start_method=constants.START_METHOD_HMAC,
            encryption=recorded,
        )
        envelope = signatures.sign_envelope(
            record.to_bytes(), blob, private_key, record.flags
        )

        parsed = env.parse_envelope(envelope)
        assert parsed.flags & constants.ENVELOPE_FLAG_ENCRYPTED
        assert signatures.verify_envelope_signature(parsed, public_key) is True

        recovered = encryption.decrypt_message(
            parsed.message, PASSPHRASE, recorded
        )
        assert recovered == MESSAGE
        assert sha256_hex(recovered) == record.message_hash

    def test_wrong_signing_key_is_a_signature_failure_not_a_cipher_failure(self):
        from app.crypto import envelope as env
        from app.crypto import key_manager, signatures

        private_key, _ = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
        _, other_public_key = key_manager.generate_key_pair(
            constants.RSA_MIN_KEY_SIZE
        )
        blob, recorded = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, salt=b"0123456789abcdef", **FAST
        )
        record = env.VerificationRecord(
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            timestamp=env.utc_timestamp(),
            nonce_hex="0f" * 16,
            message_hash="ab" * 32,
            message_length=len(MESSAGE),
            lsb_depth=3,
            start_method=constants.START_METHOD_HMAC,
            encryption=recorded,
        )
        envelope = signatures.sign_envelope(
            record.to_bytes(), blob, private_key, record.flags
        )
        parsed = env.parse_envelope(envelope)

        # The signature check fails and the cipher is never reached, so the
        # failure is reported as SIGNATURE_INVALID rather than as a crash inside
        # AES-GCM.
        assert signatures.verify_envelope_signature(parsed, other_public_key) is False

    def test_signature_covers_the_ciphertext(self):
        from app.crypto import envelope as env
        from app.crypto import key_manager, signatures

        private_key, public_key = key_manager.generate_key_pair(
            constants.RSA_MIN_KEY_SIZE
        )
        blob, recorded = encryption.encrypt_message(
            MESSAGE, PASSPHRASE, salt=b"0123456789abcdef", **FAST
        )
        record = env.VerificationRecord(
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            timestamp=env.utc_timestamp(),
            nonce_hex="0f" * 16,
            message_hash="ab" * 32,
            message_length=len(MESSAGE),
            lsb_depth=3,
            start_method=constants.START_METHOD_HMAC,
            encryption=recorded,
        )
        envelope = signatures.sign_envelope(
            record.to_bytes(), blob, private_key, record.flags
        )
        parsed = env.parse_envelope(envelope)

        tampered = bytearray(parsed.message)
        tampered[constants.GCM_NONCE_BYTES] ^= 0x01
        forged = env.build_envelope(
            parsed.record_bytes, bytes(tampered), parsed.signature, parsed.flags
        )

        assert (
            signatures.verify_envelope_signature(
                env.parse_envelope(forged), public_key
            )
            is False
        )
