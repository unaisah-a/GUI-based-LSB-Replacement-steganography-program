"""Tests for the attack simulator.

Every attack is run against a real protected file and the resulting verdict is
checked against the set the attack declared it expects. That pairing is the point:
an attack that claims ``SIGNATURE_INVALID`` and produces ``PAYLOAD_MISSING`` is a
bug in the attack's description, and a demonstration built on it would mislead.

Two results are asserted deliberately even though they are unflattering:

* Modifying the cover *outside* the payload region still verifies as
  ``AUTHENTIC``. That is the honest scope of what baseline verification covers.
* Amplitude scaling and resampling destroy the payload completely. LSB embedding is
  not robust to ordinary audio processing, and the tests say so rather than
  implying otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attacks import registry
from app.attacks.base import AttackError
from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.stego import image_io
from app.utils import constants
from app.verification import verdicts
from app.verification.protect import protect_media
from conftest import make_audio, make_cover, write_audio_file, write_cover

FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}
START_SECRET = "start location secret"
MESSAGE = b"A message worth protecting, and worth attacking."


@pytest.fixture(scope="module")
def keys():
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture(scope="module")
def attacker_keys():
    """A key pair the attacker controls, for the re-signing attack."""
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


def protect_image(tmp_path, keys, **overrides):
    private_key, _ = keys
    # A cover with plenty of room past the payload, so the "outside" attacks have
    # somewhere to write.
    cover = write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")
    options = {
        "media_id": "IMG-001",
        "lsb_depth": 1,
        "start_method": constants.START_METHOD_MANUAL,
        "manual_start_location": 0,
    }
    options.update(overrides)
    return protect_media(
        cover,
        str(tmp_path / "stego.png"),
        MESSAGE,
        private_key,
        **options,
        **FAST_SCRYPT,
    )


def protect_audio(tmp_path, keys, **overrides):
    private_key, _ = keys
    cover = write_audio_file(str(tmp_path), make_audio(60_000))
    options = {
        "media_id": "AUD-001",
        "lsb_depth": 1,
        "start_method": constants.START_METHOD_MANUAL,
        "manual_start_location": 0,
    }
    options.update(overrides)
    return protect_media(
        cover,
        str(tmp_path / "stego.wav"),
        MESSAGE,
        private_key,
        **options,
        **FAST_SCRYPT,
    )


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #


class TestCatalogue:
    def test_keys_are_unique(self):
        keys = [attack.key for attack in registry.ATTACKS]
        assert len(keys) == len(set(keys))

    def test_every_attack_has_a_label_and_summary(self):
        for attack in registry.ATTACKS:
            assert attack.label
            assert attack.summary

    def test_image_catalogue_excludes_other_media_attacks(self):
        keys = {a.key for a in registry.available_attacks(constants.MEDIA_IMAGE)}
        assert "image.inside" in keys
        assert not any(key.startswith(("audio.", "video.")) for key in keys)

    def test_audio_catalogue_excludes_other_media_attacks(self):
        keys = {a.key for a in registry.available_attacks(constants.MEDIA_AUDIO)}
        assert "audio.inside" in keys
        assert not any(key.startswith(("image.", "video.")) for key in keys)

    def test_payload_attacks_apply_to_every_medium(self):
        for media_type in constants.MEDIA_TYPES:
            keys = {a.key for a in registry.available_attacks(media_type)}
            assert "payload.signature" in keys, media_type
            assert "manifest.tamper" in keys, media_type

    def test_video_offers_its_own_attacks_and_no_others(self):
        keys = {a.key for a in registry.available_attacks(constants.MEDIA_VIDEO)}
        assert "video.lossy" in keys
        assert "video.drop_frames" in keys
        assert "payload.signature" in keys
        assert not any(key.startswith(("image.", "audio.")) for key in keys)

    def test_unknown_key_is_reported_with_the_available_ones(self):
        with pytest.raises(AttackError, match="unknown attack"):
            registry.attack_by_key("payload.nonsense")

    def test_every_expected_verdict_is_a_real_verdict(self, tmp_path, keys):
        """A typo in an expectation would make the pairing meaningless."""
        result = protect_image(tmp_path, keys)
        for attack in registry.available_attacks(constants.MEDIA_IMAGE):
            if attack.key in ("payload.resign",):
                continue
            context = registry.context_from_protect_result(
                result, str(tmp_path / f"out_{attack.key.replace('.', '_')}.png")
            )
            if attack.target == "manifest":
                context = registry.context_from_protect_result(
                    result,
                    str(tmp_path / f"out_{attack.key.replace('.', '_')}.json"),
                )
            outcome = attack.invoke(context)
            assert outcome.expected_verdicts <= set(verdicts.VERDICTS)


# --------------------------------------------------------------------------- #
# Every attack, against both media
# --------------------------------------------------------------------------- #


def _output_for(tmp_path, attack, extension):
    stem = attack.key.replace(".", "_")
    suffix = ".json" if attack.target == "manifest" else extension
    return str(tmp_path / f"attacked_{stem}{suffix}")


class TestImageAttacks:
    @pytest.mark.parametrize(
        "key",
        [
            attack.key
            for attack in registry.available_attacks(constants.MEDIA_IMAGE)
            if attack.key != "payload.resign"
        ],
    )
    def test_verdict_matches_the_declared_expectation(self, tmp_path, keys, key):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        attack = registry.attack_by_key(key)
        context = registry.context_from_protect_result(
            result, _output_for(tmp_path, attack, ".png")
        )

        run = registry.run_attack(key, context, public_key)

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation, (
            f"{key} produced {run.after.verdict}, expected one of "
            f"{sorted(run.outcome.expected_verdicts)}"
        )

    def test_modifying_outside_the_payload_still_verifies(self, tmp_path, keys):
        """The honest limitation, asserted rather than avoided."""
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "outside.png")
        )

        run = registry.run_attack("image.outside", context, public_key)

        assert run.after.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.verdict_changed is False
        assert constants.AUTHENTIC_SCOPE_NOTICE in run.after.notes

    def test_modifying_inside_the_payload_breaks_verification(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "inside.png")
        )

        run = registry.run_attack("image.inside", context, public_key)

        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.verdict_changed is True

    def test_lossy_recompression_destroys_the_payload(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "lossy.jpg")
        )

        run = registry.run_attack("image.lossy", context, public_key)

        assert run.after.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert Path(run.outcome.output_path).is_file()

    def test_the_original_is_never_modified(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        before = Path(result.stego_path).read_bytes()

        for key in ("image.inside", "image.outside", "payload.signature"):
            context = registry.context_from_protect_result(
                result, str(tmp_path / f"copy_{key.replace('.', '_')}.png")
            )
            registry.run_attack(key, context, public_key)

        assert Path(result.stego_path).read_bytes() == before


class TestAudioAttacks:
    @pytest.mark.parametrize(
        "key",
        [
            attack.key
            for attack in registry.available_attacks(constants.MEDIA_AUDIO)
            if attack.key != "payload.resign"
        ],
    )
    def test_verdict_matches_the_declared_expectation(self, tmp_path, keys, key):
        _, public_key = keys
        result = protect_audio(tmp_path, keys)
        attack = registry.attack_by_key(key)
        context = registry.context_from_protect_result(
            result, _output_for(tmp_path, attack, ".wav")
        )

        run = registry.run_attack(key, context, public_key)

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation, (
            f"{key} produced {run.after.verdict}, expected one of "
            f"{sorted(run.outcome.expected_verdicts)}"
        )

    def test_modifying_outside_the_payload_still_verifies(self, tmp_path, keys):
        _, public_key = keys
        result = protect_audio(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "outside.wav")
        )

        run = registry.run_attack("audio.outside", context, public_key)
        assert run.after.verdict == verdicts.VERDICT_AUTHENTIC

    def test_amplitude_scaling_destroys_the_payload(self, tmp_path, keys):
        """LSB embedding is not robust to a volume change, and we say so."""
        _, public_key = keys
        result = protect_audio(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "scaled.wav")
        )

        run = registry.run_attack("audio.amplitude", context, public_key)
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_resampling_destroys_the_payload(self, tmp_path, keys):
        _, public_key = keys
        result = protect_audio(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "resampled.wav")
        )

        run = registry.run_attack("audio.resample", context, public_key)
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC

    def test_resampling_changes_the_frame_count(self, tmp_path, keys):
        from app.stego import audio_stego

        _, public_key = keys
        result = protect_audio(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "resampled.wav")
        )
        run = registry.run_attack("audio.resample", context, public_key)

        original = audio_stego.describe_only(result.stego_path)
        attacked = audio_stego.describe_only(run.outcome.output_path)
        assert attacked.sample_rate != original.sample_rate
        assert attacked.frame_count != original.frame_count


# --------------------------------------------------------------------------- #
# Payload-section attacks
# --------------------------------------------------------------------------- #


class TestPayloadSectionAttacks:
    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            ("payload.record", verdicts.VERDICT_SIGNATURE_INVALID),
            ("payload.message", verdicts.VERDICT_SIGNATURE_INVALID),
            ("payload.signature", verdicts.VERDICT_SIGNATURE_INVALID),
            ("payload.magic", verdicts.VERDICT_PAYLOAD_MISSING),
        ],
    )
    def test_each_section_produces_its_specific_verdict(
        self, tmp_path, keys, key, expected
    ):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / f"{key.replace('.', '_')}.png")
        )

        run = registry.run_attack(key, context, public_key)
        assert run.after.verdict == expected

    def test_corrupting_the_message_is_a_signature_failure_not_tampering(
        self, tmp_path, keys
    ):
        """The signature covers the message, so a byte change fails the signature.

        Reaching TAMPERED requires re-signing, which needs a key.
        """
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "message.png")
        )

        run = registry.run_attack("payload.message", context, public_key)
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID
        assert run.after.hash_valid is None

    def test_random_bit_corruption_breaks_verification(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "bits.png"), bit_error_rate=0.05, seed=1
        )

        run = registry.run_attack("payload.random_bits", context, public_key)
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.outcome.details["bits_flipped"] > 0

    def test_an_impossible_bit_error_rate_is_refused(self, tmp_path, keys):
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "bits.png"), bit_error_rate=0
        )
        with pytest.raises(AttackError, match="bit_error_rate"):
            registry.attack_by_key("payload.random_bits").invoke(context)

    def test_truncation_is_reported_as_missing_or_unverifiable(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "truncated.png")
        )

        run = registry.run_attack("payload.truncate", context, public_key)
        assert run.after.verdict in (
            verdicts.VERDICT_PAYLOAD_MISSING,
            verdicts.VERDICT_CANNOT_VERIFY,
        )


class TestResigningAttack:
    def test_it_fails_against_the_genuine_public_key(
        self, tmp_path, keys, attacker_keys
    ):
        """The important result: re-signing does not fool the right receiver."""
        _, public_key = keys
        attacker_private_key, _ = attacker_keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result,
            str(tmp_path / "resigned.png"),
            attacker_private_key=attacker_private_key,
        )

        run = registry.run_attack("payload.resign", context, public_key)
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID

    def test_it_reaches_tampered_only_against_the_attackers_key(
        self, tmp_path, keys, attacker_keys
    ):
        """The only route to TAMPERED, and it needs the receiver to hold a wrong key."""
        attacker_private_key, attacker_public_key = attacker_keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result,
            str(tmp_path / "resigned.png"),
            attacker_private_key=attacker_private_key,
        )

        run = registry.run_attack("payload.resign", context, attacker_public_key)
        assert run.after.verdict == verdicts.VERDICT_TAMPERED
        assert run.after.signature_valid is True
        assert run.after.hash_valid is False

    def test_a_missing_attacker_key_is_reported(self, tmp_path, keys):
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "resigned.png")
        )
        with pytest.raises(AttackError, match="attacker_private_key"):
            registry.attack_by_key("payload.resign").invoke(context)


# --------------------------------------------------------------------------- #
# Manifest attacks
# --------------------------------------------------------------------------- #


class TestManifestAttacks:
    def test_editing_the_depth_breaks_verification(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "tampered.manifest.json"), field="lsb_depth"
        )

        run = registry.run_attack("manifest.tamper", context, public_key)

        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation

    def test_editing_the_media_id_is_caught_by_the_cross_check(self, tmp_path, keys):
        """Extraction still succeeds, so the comparison is what catches it."""
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "tampered.manifest.json"), field="media_id"
        )

        run = registry.run_attack("manifest.tamper", context, public_key)

        assert run.after.verdict == verdicts.VERDICT_TAMPERED
        assert "media_id" in run.after.mismatched_fields
        assert run.after.signature_valid is True
        assert run.after.hash_valid is True

    def test_the_original_manifest_is_untouched(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        before = Path(result.manifest_path).read_bytes()

        context = registry.context_from_protect_result(
            result, str(tmp_path / "tampered.manifest.json"), field="media_id"
        )
        registry.run_attack("manifest.tamper", context, public_key)

        assert Path(result.manifest_path).read_bytes() == before

    def test_the_stego_file_is_untouched_by_a_manifest_attack(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        before = Path(result.stego_path).read_bytes()

        context = registry.context_from_protect_result(
            result, str(tmp_path / "tampered.manifest.json"), field="media_id"
        )
        registry.run_attack("manifest.tamper", context, public_key)

        assert Path(result.stego_path).read_bytes() == before

    def test_an_unknown_field_is_reported(self, tmp_path, keys):
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "t.json"), field="not_a_field"
        )
        with pytest.raises(AttackError, match="no field"):
            registry.attack_by_key("manifest.tamper").invoke(context)

    def test_an_explicit_replacement_value_is_used(self, tmp_path, keys):
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "t.json"), field="media_id", value="IMG-XYZ"
        )
        outcome = registry.attack_by_key("manifest.tamper").invoke(context)

        data = json.loads(Path(outcome.output_path).read_text(encoding="utf-8"))
        assert data["media_id"] == "IMG-XYZ"


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


class TestReporting:
    def test_run_summary_is_json_serialisable(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "out.png")
        )

        run = registry.run_attack("payload.signature", context, public_key)
        json.dumps(run.as_dict())

    def test_text_summary_shows_before_and_after(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "out.png")
        )

        text = registry.run_attack("payload.signature", context, public_key).as_text()
        assert "before:" in text
        assert "after:" in text
        assert verdicts.VERDICT_AUTHENTIC in text

    def test_outcome_describes_what_changed(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "out.png")
        )

        run = registry.run_attack("payload.record", context, public_key)
        assert "record" in run.outcome.description
        assert run.outcome.details["section"] == "record"

    def test_details_are_copied_not_aliased(self, tmp_path, keys):
        from app.attacks.base import AttackOutcome

        shared = {"a": 1}
        outcome = AttackOutcome(
            name="x",
            output_path="out.png",
            description="d",
            expected_verdicts={verdicts.VERDICT_AUTHENTIC},
            details=shared,
        )
        shared["a"] = 2
        assert outcome.details["a"] == 1

    def test_expected_verdicts_are_a_frozenset(self):
        from app.attacks.base import AttackOutcome

        outcome = AttackOutcome(
            name="x",
            output_path="out.png",
            description="d",
            expected_verdicts={verdicts.VERDICT_AUTHENTIC},
        )
        assert isinstance(outcome.expected_verdicts, frozenset)


class TestOutputSafety:
    def test_an_occupied_output_is_refused(self, tmp_path, keys):
        _, public_key = keys
        result = protect_image(tmp_path, keys)
        occupied = tmp_path / "occupied.png"
        occupied.write_bytes(b"existing")

        context = registry.context_from_protect_result(result, str(occupied))
        with pytest.raises(Exception):
            registry.run_attack("payload.signature", context, public_key)
        assert occupied.read_bytes() == b"existing"

    def test_a_missing_output_directory_is_refused(self, tmp_path, keys):
        result = protect_image(tmp_path, keys)
        context = registry.context_from_protect_result(
            result, str(tmp_path / "absent" / "out.png")
        )
        with pytest.raises(Exception):
            registry.attack_by_key("payload.signature").invoke(context)
