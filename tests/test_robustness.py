"""Tests for repetition coding and its effect end to end.

The claim being tested is narrow and specific: with the code applied, a payload
survives scattered bit damage that destroys it without the code. Both halves of that
sentence matter, so both are asserted — including the threshold where the code stops
helping, and the attacks it cannot help against at all.

Overstating robustness would be the easy mistake here, so there are tests for the
limits as well as the successes.
"""

from __future__ import annotations

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.attacks import registry
from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.envelope import ErrorCorrectionParameters
from app.robustness import error_correction, redundancy
from app.robustness.redundancy import RedundancyError
from app.stego import image_io
from app.utils import constants
from app.verification import verdicts
from app.verification.protect import protect_media
from app.verification.verifier import verify_media
from conftest import make_audio, make_cover, write_audio_file, write_cover

START_SECRET = "the start secret"
MESSAGE = b"Repetition coding lets a damaged payload still verify."
FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}

REPETITION_3 = ErrorCorrectionParameters(constants.ECC_REPETITION, 3)
REPETITION_5 = ErrorCorrectionParameters(constants.ECC_REPETITION, 5)
NO_CODE = ErrorCorrectionParameters(constants.ECC_NONE, 1)

# Bit-error rates chosen from measurement rather than guessed, because a repetition
# code has no hard threshold — it has a probability of residual error per bit, and a
# rate picked carelessly gives a test that passes on one seed and fails on the next.
#
# For a ~700-byte envelope (about 5 600 bits) and a fixed seed:
#
#   rate   uncoded     factor 3       factor 5
#   ----   ---------   ------------   ------------
#   0.005  27 bad      fully repaired fully repaired
#   0.02   110 bad     5 bad          fully repaired
#   0.40   687 bad     677 bad        668 bad
#
# So each rate below sits well clear of the boundary in both directions.
RATE_CODE_HOLDS = 0.005  # fatal uncoded, repaired at factor 3
RATE_NEEDS_FACTOR_5 = 0.02  # defeats factor 3, repaired at factor 5
RATE_HOPELESS = 0.40  # defeats every factor on offer
CORRUPTION_SEED = 7


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


# --------------------------------------------------------------------------- #
# The primitive
# --------------------------------------------------------------------------- #


class TestFactorValidation:
    @pytest.mark.parametrize("factor", [1, 3, 5, 7, 9])
    def test_odd_factors_are_accepted(self, factor):
        assert redundancy.validate_factor(factor) == factor

    @pytest.mark.parametrize("factor", [2, 4, 6, 100])
    def test_even_factors_are_refused(self, factor):
        """A tie in the vote would have to be broken arbitrarily."""
        with pytest.raises(RedundancyError, match="odd"):
            redundancy.validate_factor(factor)

    def test_zero_and_negative_are_refused(self):
        for factor in (0, -1, -3):
            with pytest.raises(RedundancyError):
                redundancy.validate_factor(factor)

    def test_booleans_are_refused(self):
        with pytest.raises(RedundancyError, match="integer"):
            redundancy.validate_factor(True)

    def test_every_offered_factor_is_valid(self):
        for factor in constants.ECC_REPETITION_FACTORS:
            assert redundancy.validate_factor(factor) == factor


class TestEncodedLength:
    @pytest.mark.parametrize("factor", [1, 3, 5, 7])
    def test_length_is_exactly_the_factor(self, factor):
        assert redundancy.encoded_length(100, factor) == 100 * factor

    def test_the_encoding_matches_the_predicted_length(self):
        data = b"x" * 37
        for factor in (1, 3, 5):
            assert len(redundancy.repetition_encode(data, factor)) == (
                redundancy.encoded_length(len(data), factor)
            )

    def test_no_padding_is_ever_needed(self):
        """A byte count times a factor is always a whole number of bytes."""
        for length in range(0, 20):
            for factor in (3, 5, 7):
                encoded = redundancy.repetition_encode(b"a" * length, factor)
                assert len(encoded) == length * factor

    def test_largest_raw_payload_divides_the_capacity(self):
        assert redundancy.max_raw_length(300, 3) == 100
        assert redundancy.max_raw_length(301, 3) == 100
        assert redundancy.max_raw_length(2, 3) == 0

    def test_negative_lengths_are_refused(self):
        with pytest.raises(RedundancyError):
            redundancy.encoded_length(-1, 3)


class TestRoundTrip:
    @pytest.mark.parametrize("factor", [1, 3, 5, 7, 9])
    def test_undamaged_data_round_trips(self, factor):
        data = bytes(range(256))
        encoded = redundancy.repetition_encode(data, factor)
        recovered, disagreed = redundancy.repetition_decode(encoded, factor)

        assert recovered == data
        assert not disagreed.any()

    def test_empty_data_round_trips(self):
        for factor in (1, 3, 5):
            encoded = redundancy.repetition_encode(b"", factor)
            recovered, _ = redundancy.repetition_decode(encoded, factor)
            assert recovered == b""

    @given(st.binary(max_size=200), st.sampled_from([1, 3, 5, 7]))
    @settings(max_examples=50)
    def test_round_trip_for_arbitrary_data(self, data, factor):
        encoded = redundancy.repetition_encode(data, factor)
        recovered, _ = redundancy.repetition_decode(encoded, factor)
        assert recovered == data

    def test_a_truncated_payload_is_refused(self):
        encoded = redundancy.repetition_encode(b"hello world", 3)
        with pytest.raises(RedundancyError, match="whole number"):
            redundancy.repetition_decode(encoded[:-1], 3)

    def test_the_wrong_factor_is_refused_when_the_length_disagrees(self):
        encoded = redundancy.repetition_encode(b"hello", 3)
        with pytest.raises(RedundancyError, match="whole number"):
            redundancy.repetition_decode(encoded, 7)


class TestInterleaving:
    """The copies are whole and spread out, which is what survives a burst."""

    def test_copies_are_laid_end_to_end(self):
        data = b"\xff\x00"
        encoded = redundancy.repetition_encode(data, 3)
        assert encoded == data * 3

    def test_a_burst_destroying_one_whole_copy_is_survivable(self):
        """With consecutive repetition this would destroy all copies of those bits."""
        data = bytes(range(64))
        encoded = bytearray(redundancy.repetition_encode(data, 3))

        # Obliterate the entire first copy.
        for index in range(len(data)):
            encoded[index] = 0x00

        recovered, disagreed = redundancy.repetition_decode(bytes(encoded), 3)
        assert recovered == data
        assert disagreed.any()

    def test_a_burst_destroying_two_of_three_copies_is_not_survivable(self):
        """Stated rather than glossed over: the code has a limit."""
        data = bytes(range(64))
        encoded = bytearray(redundancy.repetition_encode(data, 3))

        for index in range(2 * len(data)):
            encoded[index] = 0x00

        recovered, _ = redundancy.repetition_decode(bytes(encoded), 3)
        assert recovered != data


class TestMajorityVote:
    def test_it_takes_the_majority(self):
        copies = np.array([[1, 0, 1], [1, 0, 0], [0, 0, 1]], dtype=np.uint8)
        assert error_correction.majority_vote(copies).tolist() == [1, 0, 1]

    def test_an_even_number_of_copies_is_refused(self):
        copies = np.array([[1, 0], [0, 1]], dtype=np.uint8)
        with pytest.raises(RedundancyError, match="odd"):
            error_correction.majority_vote(copies)

    def test_a_one_dimensional_array_is_refused(self):
        with pytest.raises(RedundancyError, match="two-dimensional"):
            error_correction.majority_vote(np.array([1, 0, 1], dtype=np.uint8))


# --------------------------------------------------------------------------- #
# Correction reporting
# --------------------------------------------------------------------------- #


class TestCorrectionReport:
    def test_no_code_reports_no_corrections(self):
        recovered, report = error_correction.decode(b"hello", None)

        assert recovered == b"hello"
        assert report.scheme == constants.ECC_NONE
        assert report.bits_corrected == 0
        assert report.any_corrections is False
        assert "No error-correcting code" in report.summary()

    def test_the_explicit_none_scheme_is_also_inactive(self):
        assert error_correction.is_active(NO_CODE) is False
        assert error_correction.is_active(None) is False
        assert error_correction.is_active(REPETITION_3) is True

    def test_undamaged_data_reports_nothing_repaired(self):
        encoded = error_correction.encode(b"hello world", REPETITION_3)
        _, report = error_correction.decode(encoded, REPETITION_3)

        assert report.bits_corrected == 0
        assert "nothing needed repairing" in report.summary()

    def test_damaged_data_reports_the_repairs(self):
        data = bytes(range(64))
        encoded = bytearray(error_correction.encode(data, REPETITION_3))
        encoded[5] ^= 0xFF  # eight bits in the first copy

        recovered, report = error_correction.decode(bytes(encoded), REPETITION_3)

        assert recovered == data
        assert report.bits_corrected == 8
        assert report.any_corrections is True
        assert "repaired 8 of" in report.summary()

    def test_the_report_records_both_lengths(self):
        data = b"x" * 40
        encoded = error_correction.encode(data, REPETITION_3)
        _, report = error_correction.decode(encoded, REPETITION_3)

        assert report.raw_length == 40
        assert report.encoded_length == 120
        assert report.factor == 3

    def test_the_report_is_json_serialisable(self):
        import json

        encoded = error_correction.encode(b"hello", REPETITION_3)
        _, report = error_correction.decode(encoded, REPETITION_3)
        json.dumps(report.as_dict())

    def test_an_unsupported_scheme_is_refused(self):
        bogus = ErrorCorrectionParameters("turbo", 3)
        with pytest.raises(RedundancyError, match="unsupported"):
            error_correction.encode(b"hello", bogus)


class TestEncodedLengthHelpers:
    def test_inactive_parameters_change_nothing(self):
        assert error_correction.encoded_length(100, None) == 100
        assert error_correction.encoded_length(100, NO_CODE) == 100
        assert error_correction.largest_raw_payload(100, None) == 100

    def test_active_parameters_multiply(self):
        assert error_correction.encoded_length(100, REPETITION_3) == 300
        assert error_correction.largest_raw_payload(300, REPETITION_3) == 100

    def test_the_helper_matches_the_real_encoding(self):
        for parameters in (None, NO_CODE, REPETITION_3, REPETITION_5):
            data = b"y" * 71
            assert len(error_correction.encode(data, parameters)) == (
                error_correction.encoded_length(len(data), parameters)
            )


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


@pytest.fixture()
def big_cover(tmp_path):
    """Large enough to hold a tripled payload at a modest depth."""
    return write_cover(str(tmp_path), make_cover(200, 200, 3), image_io.PNG, "cover")


def protect(cover, tmp_path, keys, *, ecc, name="stego", depth=2):
    private_key, public_key = keys
    public_path = str(tmp_path / "public.pem")
    key_manager.save_public_key(public_key, public_path, overwrite=True)

    result = protect_media(
        cover,
        str(tmp_path / f"{name}.png"),
        MESSAGE,
        private_key,
        media_id="IMG-ECC",
        lsb_depth=depth,
        start_secret=START_SECRET,
        ecc=ecc,
        **FAST_SCRYPT,
    )
    return result, public_path


class TestProtectWithCoding:
    def test_the_embedded_payload_is_larger_than_the_envelope(
        self, big_cover, tmp_path, keys
    ):
        result, _ = protect(big_cover, tmp_path, keys, ecc=REPETITION_3)

        assert result.embedded_length == result.envelope_length * 3
        assert result.embed_result.payload_length == result.embedded_length

    def test_without_coding_the_two_lengths_agree(self, big_cover, tmp_path, keys):
        result, _ = protect(big_cover, tmp_path, keys, ecc=None)
        assert result.embedded_length == result.envelope_length

    def test_the_manifest_records_the_envelope_length_not_the_embedded_length(
        self, big_cover, tmp_path, keys
    ):
        """So the cross-check against the signed bytes still works."""
        result, _ = protect(big_cover, tmp_path, keys, ecc=REPETITION_3)

        assert result.manifest.envelope_length == result.envelope_length
        assert result.manifest.ecc == REPETITION_3

    def test_a_coded_payload_verifies(self, big_cover, tmp_path, keys):
        result, public_path = protect(big_cover, tmp_path, keys, ecc=REPETITION_3)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == MESSAGE
        assert outcome.details["error_correction"]["factor"] == 3
        assert outcome.details["error_correction"]["bits_corrected"] == 0

    def test_coding_costs_capacity(self, tmp_path, keys):
        """The cost is exact and worth demonstrating, not hiding."""
        from app.stego.errors import CapacityError

        # Sized so the payload fits without coding and not with it.
        cover = write_cover(str(tmp_path), make_cover(56, 56, 3), image_io.PNG, "tight")
        protect(cover, tmp_path, keys, ecc=None, name="plain", depth=1)

        with pytest.raises(CapacityError, match="coding at factor"):
            protect(cover, tmp_path, keys, ecc=REPETITION_3, name="coded", depth=1)

    def test_the_capacity_message_names_the_coding_cost(self, tmp_path, keys):
        from app.stego.errors import CapacityError

        cover = write_cover(str(tmp_path), make_cover(56, 56, 3), image_io.PNG, "tight")
        with pytest.raises(CapacityError) as caught:
            protect(cover, tmp_path, keys, ecc=REPETITION_3, depth=1)

        message = str(caught.value)
        assert "repetition" in message
        assert "largest message that fits" in message

    def test_audio_works_the_same_way(self, tmp_path, keys):
        private_key, public_key = keys
        cover = write_audio_file(str(tmp_path), make_audio(80_000))
        public_path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, public_path)

        result = protect_media(
            cover,
            str(tmp_path / "stego.wav"),
            MESSAGE,
            private_key,
            media_id="AUD-ECC",
            lsb_depth=2,
            start_secret=START_SECRET,
            ecc=REPETITION_3,
            **FAST_SCRYPT,
        )
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC


class TestRecoveryUnderCorruption:
    """The claim: coding turns a fatal corruption into a recoverable one."""

    def _attack(self, result, public_path, tmp_path, rate, name):
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / f"{name}.png"),
            start_secret=START_SECRET,
            bit_error_rate=rate,
            seed=CORRUPTION_SEED,
        )
        return registry.run_attack(
            "payload.random_bits", context, public_path, start_secret=START_SECRET
        )

    def test_corruption_that_is_fatal_without_coding(
        self, big_cover, tmp_path, keys
    ):
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=None, name="plain"
        )
        run = self._attack(
            result, public_path, tmp_path, RATE_CODE_HOLDS, "plain_attacked"
        )

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_the_same_corruption_is_survived_with_coding(
        self, big_cover, tmp_path, keys
    ):
        """The whole point of the extension.

        Same rate, same seed, same cover as the test above; the only difference is
        the code. That pairing is what makes this a demonstration rather than an
        assertion.
        """
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        run = self._attack(
            result, public_path, tmp_path, RATE_CODE_HOLDS, "coded_attacked"
        )

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.details["error_correction"]["bits_corrected"] > 0

    def test_the_repair_is_reported_on_the_successful_verdict(
        self, big_cover, tmp_path, keys
    ):
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        run = self._attack(
            result, public_path, tmp_path, RATE_CODE_HOLDS, "coded_attacked"
        )

        assert any("repaired" in note for note in run.after.notes)

    def test_surviving_is_a_verdict_the_attack_itself_predicts(
        self, big_cover, tmp_path, keys
    ):
        """The catalogue must not call a survived attack an unexpected result."""
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        run = self._attack(
            result, public_path, tmp_path, RATE_CODE_HOLDS, "coded_attacked"
        )

        assert run.matched_expectation
        assert run.outcome.details["error_correction_active"] is True

    def test_heavy_corruption_defeats_the_code(self, big_cover, tmp_path, keys):
        """There is a threshold, and pretending otherwise would be dishonest."""
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        run = self._attack(result, public_path, tmp_path, RATE_HOPELESS, "heavy")

        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_a_higher_factor_survives_more(self, big_cover, tmp_path, keys):
        """Both halves of the comparison, at one rate, so the claim is real.

        Factor 3 is asserted to *fail* at this rate as well as factor 5 to succeed.
        Without the first half, the second would only show that factor 5 works here,
        not that the extra copies bought anything.
        """
        rate = RATE_NEEDS_FACTOR_5

        three, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="three", depth=3
        )
        run_three = self._attack(three, public_path, tmp_path, rate, "three_attacked")
        assert run_three.after.verdict != verdicts.VERDICT_AUTHENTIC

        five, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_5, name="five", depth=3
        )
        run_five = self._attack(five, public_path, tmp_path, rate, "five_attacked")
        assert run_five.after.verdict == verdicts.VERDICT_AUTHENTIC
        assert run_five.after.details["error_correction"]["bits_corrected"] > 0


class TestWhatCodingCannotFix:
    """Limits, asserted rather than implied."""

    def test_amplitude_scaling_is_not_survivable(self, tmp_path, keys):
        """It changes every sample, so every copy is damaged at once."""
        private_key, public_key = keys
        cover = write_audio_file(str(tmp_path), make_audio(80_000))
        public_path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, public_path)

        result = protect_media(
            cover,
            str(tmp_path / "stego.wav"),
            MESSAGE,
            private_key,
            media_id="AUD-ECC",
            lsb_depth=2,
            start_secret=START_SECRET,
            ecc=REPETITION_5,
            **FAST_SCRYPT,
        )
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / "scaled.wav"),
            start_secret=START_SECRET,
            factor=0.9,
        )
        run = registry.run_attack(
            "audio.amplitude", context, public_path, start_secret=START_SECRET
        )
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_lossy_recompression_is_not_survivable(self, big_cover, tmp_path, keys):
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_5, name="coded"
        )
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / "lossy.jpg"),
            start_secret=START_SECRET,
        )
        run = registry.run_attack(
            "image.lossy", context, public_path, start_secret=START_SECRET
        )
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_a_wrong_signature_is_not_something_coding_repairs(
        self, big_cover, tmp_path, keys
    ):
        """Coding repairs transmission damage, not a deliberate valid-looking forgery."""
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / "forged.png"),
            start_secret=START_SECRET,
        )
        run = registry.run_attack(
            "payload.record", context, public_path, start_secret=START_SECRET
        )
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID


class TestVerifierRobustnessHandling:
    def test_a_truncated_coded_payload_is_reported_clearly(
        self, big_cover, tmp_path, keys
    ):
        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        context = registry.context_from_manifest(
            result.stego_path,
            result.manifest_path,
            str(tmp_path / "truncated.png"),
            start_secret=START_SECRET,
            keep_fraction=0.5,
        )
        run = registry.run_attack(
            "payload.truncate", context, public_path, start_secret=START_SECRET
        )
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_a_manifest_claiming_the_wrong_factor_fails(
        self, big_cover, tmp_path, keys
    ):
        """The factor is in the signed record too, so a lie is detectable."""
        import json
        from pathlib import Path

        result, public_path = protect(
            big_cover, tmp_path, keys, ecc=REPETITION_3, name="coded"
        )
        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["ecc"]["factor"] = 5
        Path(result.manifest_path).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict != verdicts.VERDICT_AUTHENTIC
