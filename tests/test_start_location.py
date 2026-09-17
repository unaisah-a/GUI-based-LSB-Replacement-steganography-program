"""Tests for keyed start-location derivation.

The properties that matter:

* **Reproducible.** A receiver holding the secret and the manifest arrives at the
  same index the sender used. This is what makes the scheme usable at all.
* **In range.** The result always leaves room for the whole payload, and the
  highest valid index is reachable.
* **Sensitive to every input.** Changing the secret, the media identity or any
  extraction parameter moves the location.
* **No silent fallback.** A missing argument is reported, never defaulted to
  sample 0.

The arithmetic is restated inside the crypto layer to keep it independent of the
stego layer, so there is also a test asserting it agrees with
``app.stego.capacity``.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.crypto import start_location as sl
from app.crypto.errors import StartLocationError
from app.stego import capacity
from app.utils import constants

SECRET = "shared start secret"
NONCE = "0f" * 16

BASE = {
    "media_id": "IMG-001",
    "media_type": constants.MEDIA_IMAGE,
    "nonce_hex": NONCE,
    "total_samples": 100_000,
    "lsb_depth": 3,
    "envelope_length": 800,
}


def derive(**overrides) -> int:
    values = dict(BASE)
    values.update(overrides)
    return sl.derive_start_location(overrides.pop("secret", SECRET), **values)


# --------------------------------------------------------------------------- #
# Arithmetic
# --------------------------------------------------------------------------- #


class TestArithmeticAgreesWithTheStegoLayer:
    """The duplication is deliberate; these tests keep it safe."""

    @given(st.integers(0, 50_000), st.integers(1, 8))
    def test_required_sample_count_matches_capacity(self, envelope_length, depth):
        expected = capacity.required_position_count(
            envelope_length + capacity.LENGTH_HEADER_BYTES, depth
        )
        assert sl.required_sample_count(envelope_length, depth) == expected

    @given(st.integers(0, 100_000), st.integers(0, 20_000), st.integers(1, 8))
    def test_highest_valid_start_matches_capacity(self, total, envelope_length, depth):
        expected = capacity.highest_valid_start_location(
            total, envelope_length + capacity.LENGTH_HEADER_BYTES, depth
        )
        assert sl.highest_valid_start_location(total, envelope_length, depth) == expected

    def test_the_stego_length_header_is_accounted_for(self):
        """The envelope is the payload; the stego layer adds 4 bytes in front."""
        # 4 header bytes + 4 envelope bytes = 8 bytes = 64 bits, one bit per sample.
        assert sl.required_sample_count(4, 1) == 64

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_deeper_embedding_needs_no_more_samples(self, depth):
        counts = [sl.required_sample_count(1000, d) for d in range(1, 9)]
        assert counts == sorted(counts, reverse=True)


# --------------------------------------------------------------------------- #
# Derivation
# --------------------------------------------------------------------------- #


class TestReproducibility:
    def test_identical_inputs_give_identical_results(self):
        assert derive() == derive()

    def test_a_receiver_reproduces_the_senders_location(self):
        """The whole point: only the secret is not in the manifest."""
        sender = sl.derive_start_location(SECRET, **BASE)
        receiver = sl.derive_start_location(SECRET, **BASE)
        assert sender == receiver

    def test_matches_an_independent_computation_of_the_scheme(self):
        """Pins the documented message layout, not just self-consistency."""
        message = sl.DERIVATION_MESSAGE_TEMPLATE.format(
            domain=constants.START_LOCATION_DOMAIN,
            version=constants.START_LOCATION_SCHEME_VERSION,
            media_type=BASE["media_type"],
            media_id=BASE["media_id"],
            nonce=BASE["nonce_hex"],
            total_samples=BASE["total_samples"],
            lsb_depth=BASE["lsb_depth"],
            envelope_length=BASE["envelope_length"],
        ).encode("utf-8")
        digest = hmac.new(SECRET.encode("utf-8"), message, hashlib.sha256).digest()
        highest = sl.highest_valid_start_location(
            BASE["total_samples"], BASE["envelope_length"], BASE["lsb_depth"]
        )
        expected = int.from_bytes(digest, "big") % (highest + 1)

        assert sl.derive_start_location(SECRET, **BASE) == expected

    def test_message_includes_the_domain_and_version(self):
        rendered = sl.DERIVATION_MESSAGE_TEMPLATE.format(
            domain=constants.START_LOCATION_DOMAIN,
            version=constants.START_LOCATION_SCHEME_VERSION,
            media_type="image",
            media_id="X",
            nonce="00",
            total_samples=1,
            lsb_depth=1,
            envelope_length=0,
        )
        assert rendered.startswith(f"{constants.START_LOCATION_DOMAIN}|v1|")

    def test_str_and_bytes_secrets_agree(self):
        assert sl.derive_start_location(SECRET, **BASE) == sl.derive_start_location(
            SECRET.encode("utf-8"), **BASE
        )


class TestSensitivity:
    def test_different_secret_moves_the_location(self):
        first = sl.derive_start_location(SECRET, **BASE)
        second = sl.derive_start_location("a different secret", **BASE)
        assert first != second

    def test_different_media_id_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "media_id": "IMG-002"}
        )

    def test_different_nonce_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "nonce_hex": "ff" * 16}
        )

    def test_different_media_type_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "media_type": constants.MEDIA_AUDIO}
        )

    def test_different_depth_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "lsb_depth": 4}
        )

    def test_different_envelope_length_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "envelope_length": 801}
        )

    def test_different_total_samples_moves_the_location(self):
        assert sl.derive_start_location(SECRET, **BASE) != sl.derive_start_location(
            SECRET, **{**BASE, "total_samples": 100_001}
        )

    def test_two_files_with_one_secret_land_in_different_places(self):
        """Reusing a secret across files must not reuse the location."""
        locations = {
            sl.derive_start_location(
                SECRET, **{**BASE, "media_id": f"IMG-{index:03d}"}
            )
            for index in range(25)
        }
        assert len(locations) > 20


class TestRange:
    @given(
        st.integers(1, 8),
        st.integers(0, 4_000),
        st.integers(1_000, 200_000),
    )
    def test_result_always_leaves_room_for_the_payload(
        self, depth, envelope_length, total_samples
    ):
        highest = sl.highest_valid_start_location(total_samples, envelope_length, depth)
        if highest < 0:
            with pytest.raises(StartLocationError, match="does not fit"):
                sl.derive_start_location(
                    SECRET,
                    media_id="IMG-001",
                    media_type=constants.MEDIA_IMAGE,
                    nonce_hex=NONCE,
                    total_samples=total_samples,
                    lsb_depth=depth,
                    envelope_length=envelope_length,
                )
            return

        start = sl.derive_start_location(
            SECRET,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            nonce_hex=NONCE,
            total_samples=total_samples,
            lsb_depth=depth,
            envelope_length=envelope_length,
        )
        assert 0 <= start <= highest
        assert start + sl.required_sample_count(envelope_length, depth) <= total_samples

    def test_the_highest_valid_index_is_reachable(self):
        """An off-by-one in the modulus would make the last position unusable."""
        # A medium with exactly one spare sample leaves two valid positions.
        needed = sl.required_sample_count(0, 8)
        total = needed + 1
        highest = sl.highest_valid_start_location(total, 0, 8)
        assert highest == 1

        seen = {
            sl.derive_start_location(
                f"secret-{index}",
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                nonce_hex=NONCE,
                total_samples=total,
                lsb_depth=8,
                envelope_length=0,
            )
            for index in range(60)
        }
        assert seen == {0, 1}

    def test_an_exact_fit_yields_only_position_zero(self):
        needed = sl.required_sample_count(100, 4)
        start = sl.derive_start_location(
            SECRET,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            nonce_hex=NONCE,
            total_samples=needed,
            lsb_depth=4,
            envelope_length=100,
        )
        assert start == 0

    def test_one_sample_too_few_is_refused(self):
        needed = sl.required_sample_count(100, 4)
        with pytest.raises(StartLocationError, match="does not fit"):
            sl.derive_start_location(
                SECRET,
                media_id="IMG-001",
                media_type=constants.MEDIA_IMAGE,
                nonce_hex=NONCE,
                total_samples=needed - 1,
                lsb_depth=4,
                envelope_length=100,
            )


class TestDerivationValidation:
    def test_empty_secret_is_refused(self):
        with pytest.raises(StartLocationError, match="must not be empty"):
            sl.derive_start_location("", **BASE)

    def test_empty_byte_secret_is_refused(self):
        with pytest.raises(StartLocationError, match="must not be empty"):
            sl.derive_start_location(b"", **BASE)

    def test_non_string_secret_is_refused(self):
        with pytest.raises(StartLocationError, match="str or bytes"):
            sl.derive_start_location(12345, **BASE)

    def test_empty_media_id_is_refused(self):
        with pytest.raises(StartLocationError, match="media_id"):
            sl.derive_start_location(SECRET, **{**BASE, "media_id": ""})

    def test_unknown_media_type_is_refused(self):
        with pytest.raises(StartLocationError, match="media_type"):
            sl.derive_start_location(SECRET, **{**BASE, "media_type": "hologram"})

    def test_empty_nonce_is_refused(self):
        with pytest.raises(StartLocationError, match="nonce_hex"):
            sl.derive_start_location(SECRET, **{**BASE, "nonce_hex": ""})

    @pytest.mark.parametrize("depth", [0, 9, -1])
    def test_depth_out_of_range_is_refused(self, depth):
        with pytest.raises(StartLocationError, match="lsb_depth"):
            sl.derive_start_location(SECRET, **{**BASE, "lsb_depth": depth})

    def test_boolean_depth_is_refused(self):
        with pytest.raises(StartLocationError, match="lsb_depth"):
            sl.derive_start_location(SECRET, **{**BASE, "lsb_depth": True})

    def test_zero_total_samples_is_refused(self):
        with pytest.raises(StartLocationError, match="total_samples"):
            sl.derive_start_location(SECRET, **{**BASE, "total_samples": 0})

    def test_negative_envelope_length_is_refused(self):
        with pytest.raises(StartLocationError, match="envelope_length"):
            sl.derive_start_location(SECRET, **{**BASE, "envelope_length": -1})


# --------------------------------------------------------------------------- #
# Manual mode
# --------------------------------------------------------------------------- #


class TestManualStartLocation:
    def test_a_valid_value_is_returned_unchanged(self):
        assert (
            sl.validate_manual_start_location(
                1234, total_samples=100_000, lsb_depth=3, envelope_length=800
            )
            == 1234
        )

    def test_zero_is_valid(self):
        assert (
            sl.validate_manual_start_location(
                0, total_samples=100_000, lsb_depth=3, envelope_length=800
            )
            == 0
        )

    def test_the_highest_valid_value_is_accepted(self):
        highest = sl.highest_valid_start_location(100_000, 800, 3)
        assert (
            sl.validate_manual_start_location(
                highest, total_samples=100_000, lsb_depth=3, envelope_length=800
            )
            == highest
        )

    def test_one_past_the_highest_valid_value_is_refused(self):
        highest = sl.highest_valid_start_location(100_000, 800, 3)
        with pytest.raises(StartLocationError, match="too little room"):
            sl.validate_manual_start_location(
                highest + 1, total_samples=100_000, lsb_depth=3, envelope_length=800
            )

    def test_beyond_the_medium_is_refused(self):
        with pytest.raises(StartLocationError, match="beyond the medium"):
            sl.validate_manual_start_location(
                100_000, total_samples=100_000, lsb_depth=3, envelope_length=0
            )

    def test_negative_is_refused(self):
        with pytest.raises(StartLocationError, match="start_location"):
            sl.validate_manual_start_location(
                -1, total_samples=100_000, lsb_depth=3, envelope_length=800
            )

    def test_boolean_is_refused(self):
        with pytest.raises(StartLocationError, match="start_location"):
            sl.validate_manual_start_location(
                True, total_samples=100_000, lsb_depth=3, envelope_length=800
            )

    def test_payload_larger_than_the_medium_is_refused(self):
        with pytest.raises(StartLocationError, match="does not fit"):
            sl.validate_manual_start_location(
                0, total_samples=100, lsb_depth=1, envelope_length=1_000_000
            )


# --------------------------------------------------------------------------- #
# Unified resolution
# --------------------------------------------------------------------------- #


class TestResolve:
    def test_manual_mode_uses_the_supplied_value(self):
        assert (
            sl.resolve_start_location(
                constants.START_METHOD_MANUAL,
                total_samples=100_000,
                lsb_depth=3,
                envelope_length=800,
                manual_start_location=4096,
            )
            == 4096
        )

    def test_derived_mode_matches_the_derivation_function(self):
        resolved = sl.resolve_start_location(
            constants.START_METHOD_HMAC,
            total_samples=BASE["total_samples"],
            lsb_depth=BASE["lsb_depth"],
            envelope_length=BASE["envelope_length"],
            secret=SECRET,
            media_id=BASE["media_id"],
            media_type=BASE["media_type"],
            nonce_hex=BASE["nonce_hex"],
        )
        assert resolved == sl.derive_start_location(SECRET, **BASE)

    def test_manual_mode_without_a_value_is_refused(self):
        """Never silently fall back to sample 0."""
        with pytest.raises(StartLocationError, match="manual_start_location"):
            sl.resolve_start_location(
                constants.START_METHOD_MANUAL,
                total_samples=100_000,
                lsb_depth=3,
                envelope_length=800,
            )

    def test_derived_mode_names_every_missing_argument(self):
        with pytest.raises(StartLocationError) as caught:
            sl.resolve_start_location(
                constants.START_METHOD_HMAC,
                total_samples=100_000,
                lsb_depth=3,
                envelope_length=800,
            )
        message = str(caught.value)
        for name in ("secret", "media_id", "media_type", "nonce_hex"):
            assert name in message

    def test_unknown_method_is_refused(self):
        with pytest.raises(StartLocationError, match="start_method"):
            sl.resolve_start_location(
                "telepathy",
                total_samples=100_000,
                lsb_depth=3,
                envelope_length=800,
            )

    @pytest.mark.parametrize("method", constants.START_METHODS)
    def test_every_offered_method_is_implemented(self, method):
        resolved = sl.resolve_start_location(
            method,
            total_samples=100_000,
            lsb_depth=3,
            envelope_length=800,
            secret=SECRET,
            manual_start_location=10,
            media_id="IMG-001",
            media_type=constants.MEDIA_IMAGE,
            nonce_hex=NONCE,
        )
        assert isinstance(resolved, int)


class TestRemovedDerivations:
    """The two superseded functions must not come back.

    Both were reproducibility or layering defects, described in the module
    docstring. A future merge that reinstates either would reintroduce a scheme a
    receiver cannot follow.
    """

    def test_payload_length_dependent_derivation_is_gone(self):
        assert not hasattr(sl, "calculate_start_location")

    def test_audio_only_derivation_is_gone(self):
        assert not hasattr(sl, "calculate_audio_start_location")

    def test_no_result_is_confined_to_the_first_quarter(self):
        """The old audio scheme wasted three quarters of every file."""
        total = 100_000
        highest = sl.highest_valid_start_location(total, 800, 3)
        locations = [
            sl.derive_start_location(
                f"secret-{index}",
                media_id="IMG-001",
                media_type=constants.MEDIA_AUDIO,
                nonce_hex=NONCE,
                total_samples=total,
                lsb_depth=3,
                envelope_length=800,
            )
            for index in range(60)
        ]
        assert max(locations) > total // 2
        assert all(location <= highest for location in locations)
