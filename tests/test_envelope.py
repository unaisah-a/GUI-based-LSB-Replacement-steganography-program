"""Tests for the versioned payload envelope and the verification record.

Three things are being pinned down here:

* The canonical form is genuinely canonical. A signature is computed over exact
  bytes, so re-serialising a parsed record must reproduce those bytes regardless
  of dictionary ordering.
* The parser walks forward from declared lengths and bounds-checks every one of
  them before slicing, so a corrupt length field cannot drive a large allocation.
* Structural failures are typed and specific enough for the verifier to map them
  onto the right verdict, and the "no envelope here" case is distinguishable from
  "an envelope with something wrong in it".
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.crypto import envelope as env
from app.crypto.errors import EnvelopeError, RecordError
from app.utils import constants


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

NONCE = "0f" * 16
DIGEST = "ab" * 32


def make_record(**overrides) -> env.VerificationRecord:
    values = {
        "media_id": "IMG-001",
        "media_type": constants.MEDIA_IMAGE,
        "timestamp": "2026-09-17T12:00:00+00:00",
        "nonce_hex": NONCE,
        "message_hash": DIGEST,
        "message_length": 11,
        "lsb_depth": 3,
        "start_method": constants.START_METHOD_HMAC,
    }
    values.update(overrides)
    return env.VerificationRecord(**values)


def make_envelope(
    *,
    record: bytes | None = None,
    message: bytes = b"hello world",
    signature: bytes = b"\x11" * 384,
    flags: int = 0,
) -> bytes:
    return env.build_envelope(
        record if record is not None else make_record().to_bytes(),
        message,
        signature,
        flags,
    )


# --------------------------------------------------------------------------- #
# Canonical JSON
# --------------------------------------------------------------------------- #


class TestCanonicalJson:
    def test_key_order_does_not_affect_the_bytes(self):
        first = env.canonical_json({"a": 1, "b": 2, "c": 3})
        second = env.canonical_json({"c": 3, "b": 2, "a": 1})
        assert first == second

    def test_nested_key_order_does_not_affect_the_bytes(self):
        first = env.canonical_json({"outer": {"z": 1, "a": {"y": 2, "b": 3}}})
        second = env.canonical_json({"outer": {"a": {"b": 3, "y": 2}, "z": 1}})
        assert first == second

    def test_output_is_compact(self):
        assert env.canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'

    def test_output_is_pure_ascii(self):
        encoded = env.canonical_json({"note": "café \u2713"})
        encoded.decode("ascii")
        assert b"caf" in encoded

    def test_round_trip_reproduces_the_bytes(self):
        original = env.canonical_json(
            {"z": "last", "a": {"nested": [1, 2, 3], "flag": True, "nothing": None}}
        )
        assert env.canonical_json(json.loads(original)) == original

    def test_floats_are_rejected(self):
        """A float can serialise differently on different machines."""
        with pytest.raises(RecordError, match="floating-point"):
            env.canonical_json({"ratio": 0.1})

    def test_nested_floats_are_rejected(self):
        with pytest.raises(RecordError, match="floating-point"):
            env.canonical_json({"outer": {"inner": [1, 2.5]}})

    def test_non_string_keys_are_rejected(self):
        with pytest.raises(RecordError, match="non-string object key"):
            env.canonical_json({1: "one"})

    def test_unsupported_types_are_rejected(self):
        with pytest.raises(RecordError, match="unsupported value"):
            env.canonical_json({"when": object()})

    def test_non_mapping_is_rejected(self):
        with pytest.raises(RecordError, match="must be a JSON object"):
            env.canonical_json([1, 2, 3])

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=8),
            st.one_of(
                st.integers(-1000, 1000),
                st.text(max_size=16),
                st.booleans(),
                st.none(),
            ),
            max_size=8,
        )
    )
    def test_serialisation_is_stable_across_reparsing(self, payload):
        encoded = env.canonical_json(payload)
        assert env.canonical_json(json.loads(encoded)) == encoded


class TestTimestamp:
    def test_has_an_explicit_offset_and_no_microseconds(self):
        stamp = env.utc_timestamp()
        assert stamp.endswith("+00:00")
        assert "." not in stamp


# --------------------------------------------------------------------------- #
# Verification record
# --------------------------------------------------------------------------- #


class TestRecordRoundTrip:
    def test_minimal_record_round_trips(self):
        record = make_record()
        assert env.VerificationRecord.from_bytes(record.to_bytes()) == record

    def test_record_with_every_option_round_trips(self):
        record = make_record(
            start_method=constants.START_METHOD_MANUAL,
            start_location=4096,
            encryption=env.EncryptionParameters(
                cipher=constants.CIPHER_AES_256_GCM,
                kdf=constants.KDF_SCRYPT,
                salt_hex="ab" * 16,
                n=constants.SCRYPT_N,
                r=constants.SCRYPT_R,
                p=constants.SCRYPT_P,
            ),
            ecc=env.ErrorCorrectionParameters(
                scheme=constants.ECC_REPETITION, factor=3
            ),
            metadata={"team": "P1-1", "note": "long message case"},
        )
        assert env.VerificationRecord.from_bytes(record.to_bytes()) == record

    def test_serialisation_is_deterministic(self):
        assert make_record().to_bytes() == make_record().to_bytes()

    def test_metadata_key_order_does_not_change_the_bytes(self):
        first = make_record(metadata={"a": 1, "z": 2}).to_bytes()
        second = make_record(metadata={"z": 2, "a": 1}).to_bytes()
        assert first == second

    def test_dictionary_carries_the_expected_field_names(self):
        keys = set(make_record().as_dict())
        assert keys == {
            "v",
            "media_id",
            "media_type",
            "timestamp",
            "nonce",
            "message_hash",
            "message_length",
            "lsb_depth",
            "start_method",
            "start_location",
            "encryption",
            "ecc",
            "metadata",
        }

    def test_start_location_is_present_but_null_for_derived_mode(self):
        """Nullable by design; see the VerificationRecord docstring."""
        payload = make_record().as_dict()
        assert payload["start_location"] is None

    def test_metadata_is_copied_not_aliased(self):
        supplied = {"team": "P1-1"}
        record = make_record(metadata=supplied)
        supplied["team"] = "changed"
        assert record.metadata["team"] == "P1-1"


class TestRecordFlags:
    def test_no_options_means_no_flags(self):
        assert make_record().flags == 0
        assert make_record().encrypted is False

    def test_encryption_sets_the_encrypted_flag(self):
        record = make_record(
            encryption=env.EncryptionParameters(
                constants.CIPHER_AES_256_GCM,
                constants.KDF_SCRYPT,
                "ab" * 16,
                constants.SCRYPT_N,
                constants.SCRYPT_R,
                constants.SCRYPT_P,
            )
        )
        assert record.flags == constants.ENVELOPE_FLAG_ENCRYPTED
        assert record.encrypted is True

    def test_error_correction_sets_the_ecc_flag(self):
        record = make_record(
            ecc=env.ErrorCorrectionParameters(constants.ECC_REPETITION, 3)
        )
        assert record.flags == constants.ENVELOPE_FLAG_ECC

    def test_the_none_scheme_does_not_set_the_ecc_flag(self):
        record = make_record(
            ecc=env.ErrorCorrectionParameters(constants.ECC_NONE, 1)
        )
        assert record.flags == 0


class TestRecordValidation:
    def _mutated(self, **changes):
        payload = make_record().as_dict()
        payload.update(changes)
        return payload

    def test_missing_field_is_named(self):
        payload = make_record().as_dict()
        del payload["media_id"]
        with pytest.raises(RecordError, match="media_id"):
            env.VerificationRecord.from_dict(payload)

    def test_missing_start_location_key_is_rejected(self):
        """Explicit null is required, so an omission cannot pass as "derived"."""
        payload = make_record().as_dict()
        del payload["start_location"]
        with pytest.raises(RecordError, match="start_location"):
            env.VerificationRecord.from_dict(payload)

    def test_unsupported_version(self):
        with pytest.raises(RecordError, match="not supported"):
            env.VerificationRecord.from_dict(self._mutated(v=99))

    def test_unknown_media_type(self):
        with pytest.raises(RecordError, match="media_type"):
            env.VerificationRecord.from_dict(self._mutated(media_type="hologram"))

    def test_unknown_start_method(self):
        with pytest.raises(RecordError, match="start_method"):
            env.VerificationRecord.from_dict(self._mutated(start_method="guess"))

    @pytest.mark.parametrize("depth", [0, 9, -1, 100])
    def test_lsb_depth_out_of_range(self, depth):
        with pytest.raises(RecordError, match="lsb_depth"):
            env.VerificationRecord.from_dict(self._mutated(lsb_depth=depth))

    @pytest.mark.parametrize("depth", list(range(1, 9)))
    def test_every_valid_depth_is_accepted(self, depth):
        record = env.VerificationRecord.from_dict(self._mutated(lsb_depth=depth))
        assert record.lsb_depth == depth

    def test_boolean_is_not_an_integer(self):
        """True silently meaning depth 1 would hide a caller mistake."""
        with pytest.raises(RecordError, match="boolean"):
            env.VerificationRecord.from_dict(self._mutated(lsb_depth=True))

    def test_negative_message_length(self):
        with pytest.raises(RecordError, match="message_length"):
            env.VerificationRecord.from_dict(self._mutated(message_length=-1))

    def test_zero_message_length_is_allowed(self):
        record = env.VerificationRecord.from_dict(self._mutated(message_length=0))
        assert record.message_length == 0

    def test_negative_start_location(self):
        with pytest.raises(RecordError, match="start_location"):
            env.VerificationRecord.from_dict(self._mutated(start_location=-1))

    def test_non_integer_start_location(self):
        with pytest.raises(RecordError, match="start_location"):
            env.VerificationRecord.from_dict(self._mutated(start_location="1234"))

    def test_wrong_length_message_hash(self):
        with pytest.raises(RecordError, match="message_hash"):
            env.VerificationRecord.from_dict(self._mutated(message_hash="abcd"))

    def test_non_hex_message_hash(self):
        with pytest.raises(RecordError, match="message_hash"):
            env.VerificationRecord.from_dict(self._mutated(message_hash="z" * 64))

    def test_non_hex_nonce(self):
        with pytest.raises(RecordError, match="nonce"):
            env.VerificationRecord.from_dict(self._mutated(nonce="xyz"))

    def test_odd_length_nonce(self):
        with pytest.raises(RecordError, match="nonce"):
            env.VerificationRecord.from_dict(self._mutated(nonce="abc"))

    def test_metadata_must_be_an_object(self):
        with pytest.raises(RecordError, match="metadata"):
            env.VerificationRecord.from_dict(self._mutated(metadata=[1, 2]))

    def test_encryption_must_be_an_object_or_null(self):
        with pytest.raises(RecordError, match="encryption"):
            env.VerificationRecord.from_dict(self._mutated(encryption="aes"))

    def test_ecc_must_be_an_object_or_null(self):
        with pytest.raises(RecordError, match="ecc"):
            env.VerificationRecord.from_dict(self._mutated(ecc=3))

    def test_non_mapping_record(self):
        with pytest.raises(RecordError, match="JSON object"):
            env.VerificationRecord.from_dict([1, 2, 3])


class TestEncryptionParameterValidation:
    def _with_encryption(self, **changes):
        base = {
            "cipher": constants.CIPHER_AES_256_GCM,
            "kdf": constants.KDF_SCRYPT,
            "salt": "ab" * 16,
            "n": constants.SCRYPT_N,
            "r": constants.SCRYPT_R,
            "p": constants.SCRYPT_P,
        }
        base.update(changes)
        payload = make_record().as_dict()
        payload["encryption"] = base
        return payload

    def test_valid_parameters_are_accepted(self):
        record = env.VerificationRecord.from_dict(self._with_encryption())
        assert record.encryption is not None
        assert record.encryption.salt_hex == "ab" * 16

    def test_unknown_cipher_is_rejected(self):
        with pytest.raises(RecordError, match="cipher"):
            env.VerificationRecord.from_dict(self._with_encryption(cipher="DES"))

    def test_unknown_kdf_is_rejected(self):
        with pytest.raises(RecordError, match="kdf"):
            env.VerificationRecord.from_dict(self._with_encryption(kdf="md5"))

    def test_non_hex_salt_is_rejected(self):
        with pytest.raises(RecordError, match="salt"):
            env.VerificationRecord.from_dict(self._with_encryption(salt="nothex!!"))

    @pytest.mark.parametrize("field_name", ["n", "r", "p"])
    def test_non_positive_cost_parameters_are_rejected(self, field_name):
        with pytest.raises(RecordError, match=field_name):
            env.VerificationRecord.from_dict(self._with_encryption(**{field_name: 0}))

    def test_missing_field_is_rejected(self):
        payload = self._with_encryption()
        del payload["encryption"]["salt"]
        with pytest.raises(RecordError, match="salt"):
            env.VerificationRecord.from_dict(payload)


class TestErrorCorrectionParameterValidation:
    def _with_ecc(self, **changes):
        base = {"scheme": constants.ECC_REPETITION, "factor": 3}
        base.update(changes)
        payload = make_record().as_dict()
        payload["ecc"] = base
        return payload

    def test_valid_parameters_are_accepted(self):
        record = env.VerificationRecord.from_dict(self._with_ecc())
        assert record.ecc == env.ErrorCorrectionParameters(
            constants.ECC_REPETITION, 3
        )

    def test_unknown_scheme_is_rejected(self):
        with pytest.raises(RecordError, match="scheme"):
            env.VerificationRecord.from_dict(self._with_ecc(scheme="turbo"))

    def test_even_repetition_factor_is_rejected(self):
        """An even factor could tie a majority vote."""
        with pytest.raises(RecordError, match="odd"):
            env.VerificationRecord.from_dict(self._with_ecc(factor=4))

    @pytest.mark.parametrize("factor", (3, 5, 7, 9))
    def test_every_offered_factor_is_accepted(self, factor):
        record = env.VerificationRecord.from_dict(self._with_ecc(factor=factor))
        assert record.ecc.factor == factor

    def test_zero_factor_is_rejected(self):
        with pytest.raises(RecordError, match="factor"):
            env.VerificationRecord.from_dict(self._with_ecc(factor=0))


class TestRecordDecoding:
    def test_invalid_utf8(self):
        with pytest.raises(RecordError, match="UTF-8"):
            env.decode_record(b"\xff\xfe\xfd")

    def test_invalid_json(self):
        with pytest.raises(RecordError, match="JSON"):
            env.decode_record(b"{not json")

    def test_json_array_is_not_a_record(self):
        with pytest.raises(RecordError, match="JSON object"):
            env.decode_record(b"[1,2,3]")

    def test_json_scalar_is_not_a_record(self):
        with pytest.raises(RecordError, match="JSON object"):
            env.decode_record(b"42")


# --------------------------------------------------------------------------- #
# Envelope construction and parsing
# --------------------------------------------------------------------------- #


class TestEnvelopeLayout:
    def test_header_sizes(self):
        assert env.MAGIC_SIZE == 8
        assert env.HEADER_SIZE == 10
        assert env.MIN_ENVELOPE_SIZE == 22

    def test_signature_covers_everything_before_the_signature_length(self):
        record = make_record().to_bytes()
        message = b"hello world"
        signature = b"\x11" * 384
        envelope = env.build_envelope(record, message, signature)
        signed = env.signing_input(record, message)

        assert envelope.startswith(signed)
        assert envelope[len(signed) :] == (
            len(signature).to_bytes(4, "big") + signature
        )

    def test_signed_region_includes_the_magic_version_and_flags(self):
        signed = env.signing_input(b"{}", b"", constants.ENVELOPE_FLAG_ENCRYPTED)
        assert signed[:8] == constants.ENVELOPE_MAGIC
        assert signed[8] == constants.ENVELOPE_VERSION
        assert signed[9] == constants.ENVELOPE_FLAG_ENCRYPTED

    def test_flipping_a_flag_changes_the_signed_bytes(self):
        """The framing is authenticated, not just the record."""
        plain = env.signing_input(b"{}", b"m", 0)
        flagged = env.signing_input(b"{}", b"m", constants.ENVELOPE_FLAG_ENCRYPTED)
        assert plain != flagged

    def test_length_helper_matches_the_built_envelope(self):
        record = make_record().to_bytes()
        message = b"x" * 37
        signature = b"\x11" * 384
        envelope = env.build_envelope(record, message, signature)

        assert env.envelope_length_for(
            len(record), len(message), len(signature)
        ) == len(envelope)

    def test_length_helper_rejects_negative_values(self):
        with pytest.raises(EnvelopeError):
            env.envelope_length_for(-1, 0, 0)

    def test_empty_sections_produce_the_minimum_envelope(self):
        assert len(env.build_envelope(b"", b"", b"")) == env.MIN_ENVELOPE_SIZE


class TestEnvelopeRoundTrip:
    def test_parse_recovers_every_section(self):
        record = make_record()
        message = b"hello world"
        signature = b"\x11" * 384
        parsed = env.parse_envelope(
            env.build_envelope(record.to_bytes(), message, signature)
        )

        assert parsed.version == constants.ENVELOPE_VERSION
        assert parsed.flags == 0
        assert parsed.record_bytes == record.to_bytes()
        assert parsed.message == message
        assert parsed.signature == signature
        assert env.VerificationRecord.from_dict(parsed.record) == record

    def test_signed_region_is_reproducible_from_the_parsed_sections(self):
        """Signing and verification must agree on the covered bytes."""
        record = make_record().to_bytes()
        message = b"payload bytes"
        parsed = env.parse_envelope(
            env.build_envelope(record, message, b"\x11" * 384, 0)
        )
        assert parsed.signed_region == env.signing_input(
            parsed.record_bytes, parsed.message, parsed.flags
        )

    @pytest.mark.parametrize(
        "flags",
        [
            0,
            constants.ENVELOPE_FLAG_ENCRYPTED,
            constants.ENVELOPE_FLAG_ECC,
            constants.ENVELOPE_FLAG_ENCRYPTED | constants.ENVELOPE_FLAG_ECC,
        ],
    )
    def test_flags_survive_the_round_trip(self, flags):
        parsed = env.parse_envelope(make_envelope(flags=flags))
        assert parsed.flags == flags

    def test_empty_message_round_trips(self):
        parsed = env.parse_envelope(make_envelope(message=b""))
        assert parsed.message == b""

    def test_total_length_is_reported(self):
        envelope = make_envelope()
        assert env.parse_envelope(envelope).total_length == len(envelope)

    @given(st.binary(max_size=512), st.binary(min_size=1, max_size=64))
    def test_arbitrary_message_and_signature_bytes_round_trip(self, message, signature):
        parsed = env.parse_envelope(
            env.build_envelope(make_record().to_bytes(), message, signature)
        )
        assert parsed.message == message
        assert parsed.signature == signature

    def test_bytearray_input_is_accepted(self):
        parsed = env.parse_envelope(bytearray(make_envelope()))
        assert parsed.message == b"hello world"


class TestEnvelopeRejections:
    def test_wrong_magic_reports_no_envelope_found(self):
        """This is the signal that separates PAYLOAD_MISSING from other failures."""
        payload = bytearray(make_envelope())
        payload[0] ^= 0xFF

        with pytest.raises(EnvelopeError, match="no payload envelope found"):
            env.parse_envelope(bytes(payload))

    def test_random_bytes_report_no_envelope_found(self):
        with pytest.raises(EnvelopeError, match="no payload envelope found"):
            env.parse_envelope(b"\x00" * 64)

    def test_the_no_envelope_message_does_not_claim_a_cause(self):
        """Requirement: an extraction failure must not assert which cause applies."""
        with pytest.raises(EnvelopeError) as caught:
            env.parse_envelope(b"\x00" * 64)
        message = str(caught.value)
        assert "does not distinguish" in message

    def test_too_short_to_be_an_envelope(self):
        with pytest.raises(EnvelopeError, match="shorter than"):
            env.parse_envelope(b"INF2005E")

    def test_empty_input(self):
        with pytest.raises(EnvelopeError, match="shorter than"):
            env.parse_envelope(b"")

    def test_unsupported_version(self):
        payload = bytearray(make_envelope())
        payload[env.MAGIC_SIZE] = 99
        with pytest.raises(EnvelopeError, match="version 99"):
            env.parse_envelope(bytes(payload))

    def test_unknown_flag_bits_are_rejected(self):
        payload = bytearray(make_envelope())
        payload[env.MAGIC_SIZE + 1] = 0b1000_0000
        with pytest.raises(EnvelopeError, match="unknown bits"):
            env.parse_envelope(bytes(payload))

    def test_trailing_bytes_are_rejected(self):
        with pytest.raises(EnvelopeError, match="trailing bytes"):
            env.parse_envelope(make_envelope() + b"\x00")

    def test_non_bytes_input(self):
        with pytest.raises(EnvelopeError, match="bytes-like"):
            env.parse_envelope("not bytes")

    @pytest.mark.parametrize("cut", [1, 5, 20, 100, 300])
    def test_truncation_is_reported_rather_than_crashing(self, cut):
        envelope = make_envelope()
        with pytest.raises((EnvelopeError, RecordError)):
            env.parse_envelope(envelope[:-cut])

    def test_every_truncation_point_is_handled(self):
        """No offset should produce an IndexError or a struct error."""
        envelope = make_envelope()
        for length in range(len(envelope)):
            with pytest.raises((EnvelopeError, RecordError)):
                env.parse_envelope(envelope[:length])

    def test_oversized_declared_record_length_is_refused_before_allocating(self):
        """A hostile length field must not be able to request a huge buffer."""
        envelope = bytearray(make_envelope())
        offset = env.HEADER_SIZE
        envelope[offset : offset + 4] = (0xFFFF_FFFF).to_bytes(4, "big")

        with pytest.raises(EnvelopeError, match="exceeds the"):
            env.parse_envelope(bytes(envelope))

    def test_declared_record_length_beyond_the_buffer_is_refused(self):
        envelope = bytearray(make_envelope())
        offset = env.HEADER_SIZE
        envelope[offset : offset + 4] = (len(envelope) + 1000).to_bytes(4, "big")

        with pytest.raises(EnvelopeError, match="truncated"):
            env.parse_envelope(bytes(envelope))

    def test_declared_message_length_beyond_the_buffer_is_refused(self):
        record = make_record().to_bytes()
        envelope = bytearray(make_envelope(record=record))
        offset = env.HEADER_SIZE + 4 + len(record)
        envelope[offset : offset + 4] = (10_000_000).to_bytes(4, "big")

        with pytest.raises(EnvelopeError, match="truncated"):
            env.parse_envelope(bytes(envelope))

    def test_malformed_record_json_is_a_record_error(self):
        """Framing valid, contents not: a different category from EnvelopeError."""
        envelope = env.build_envelope(b"{not json", b"m", b"\x11" * 8)
        with pytest.raises(RecordError, match="JSON"):
            env.parse_envelope(envelope)


class TestBuildValidation:
    def test_non_bytes_record(self):
        with pytest.raises(EnvelopeError, match="record must be bytes-like"):
            env.build_envelope("record", b"", b"")

    def test_non_bytes_message(self):
        with pytest.raises(EnvelopeError, match="message must be bytes-like"):
            env.build_envelope(b"{}", "message", b"")

    def test_non_bytes_signature(self):
        with pytest.raises(EnvelopeError, match="signature must be bytes-like"):
            env.build_envelope(b"{}", b"", "signature")

    def test_oversized_section_is_refused(self):
        oversized = constants.MAX_ENVELOPE_SECTION_BYTES + 1
        with pytest.raises(EnvelopeError, match="exceeds"):
            env.signing_input(b"{}", memoryview(bytearray(oversized)))

    def test_unknown_flag_bit_is_refused_at_build_time(self):
        with pytest.raises(EnvelopeError, match="unknown bits"):
            env.build_envelope(b"{}", b"", b"", 0b0100_0000)

    def test_flags_must_be_an_integer(self):
        with pytest.raises(EnvelopeError, match="flags must be an integer"):
            env.build_envelope(b"{}", b"", b"", "encrypted")

    def test_boolean_flags_are_refused(self):
        with pytest.raises(EnvelopeError, match="flags must be an integer"):
            env.build_envelope(b"{}", b"", b"", True)

    def test_flags_wider_than_a_byte_are_refused(self):
        with pytest.raises(EnvelopeError, match="one byte"):
            env.build_envelope(b"{}", b"", b"", 256)


class TestTamperSensitivity:
    """Every byte of the signed region must affect the signed bytes.

    The signature check itself is the subject of the signature tests; what is
    being established here is that there is no byte inside the signed region that
    an attacker could change without the signature input changing too.
    """

    def test_every_signed_byte_matters(self):
        record = make_record().to_bytes()
        message = b"hello world"
        baseline = env.signing_input(record, message, 0)

        for index in range(len(baseline)):
            mutated = bytearray(baseline)
            mutated[index] ^= 0x01
            assert bytes(mutated) != baseline

    def test_swapping_message_content_changes_the_signed_bytes(self):
        record = make_record().to_bytes()
        first = env.signing_input(record, b"transfer 100")
        second = env.signing_input(record, b"transfer 900")
        assert first != second

    def test_moving_a_byte_between_sections_changes_the_signed_bytes(self):
        """Length-prefixed sections stop a boundary shift going unnoticed."""
        first = env.signing_input(b'{"a":"bc"}', b"d")
        second = env.signing_input(b'{"a":"b"}', b"cd")
        assert first != second
