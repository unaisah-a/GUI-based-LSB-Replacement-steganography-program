"""Tests for the protect and verify workflows, and for every verdict.

There is one test per verdict, plus the cases that establish the two honesty rules
the verdict vocabulary depends on:

* ``AUTHENTIC`` is about the signed message, not the whole file. A change to the
  cover outside the embedded region still verifies, and that is demonstrated here
  rather than glossed over.
* ``WRONG_START_LOCATION`` is only used when it is provable. A wrong depth, a wrong
  secret and an absent payload all produce ``PAYLOAD_MISSING`` or
  ``CANNOT_VERIFY``, never a confident guess.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.crypto import hashing, key_manager
from app.crypto import manifest as manifest_module
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.envelope import ErrorCorrectionParameters
from app.crypto.errors import KeyMaterialError
from app.stego import image_io, image_stego
from app.stego.errors import CapacityError
from app.utils import constants, file_utils
from app.verification import verdicts
from app.verification.protect import protect_media
from app.verification.verifier import verify_media

from conftest import make_audio, make_cover, write_audio_file, write_cover

FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}
START_SECRET = "start location secret"
PASSPHRASE = "message passphrase"
MESSAGE = b"Steganography hides the existence of a message."


@pytest.fixture(scope="module")
def keys():
    private_key, public_key = key_manager.generate_key_pair(
        constants.RSA_MIN_KEY_SIZE
    )
    return private_key, public_key


@pytest.fixture(scope="module")
def other_public_key():
    _, public_key = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
    return public_key


@pytest.fixture()
def png_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(64, 64, 3), image_io.PNG, "cover")


@pytest.fixture()
def wav_cover(tmp_path):
    return write_audio_file(str(tmp_path), make_audio(20_000))


def do_protect(
    cover,
    tmp_path,
    keys,
    *,
    message: bytes = MESSAGE,
    output_path: str | None = None,
    **options,
):
    """Protect *cover* with sensible defaults, returning the ProtectResult.

    ``output_path`` defaults to ``stego<extension of the cover>`` inside
    ``tmp_path``, so a caller only names it when a test needs two outputs in one
    directory.
    """
    private_key, _ = keys
    settings = {
        "media_id": "IMG-001",
        "lsb_depth": 3,
        "start_method": constants.START_METHOD_HMAC,
        "start_secret": START_SECRET,
    }
    settings.update(options)

    if output_path is None:
        output_path = str(tmp_path / f"stego{os.path.splitext(cover)[1]}")

    return protect_media(
        cover, output_path, message, private_key, **settings, **FAST_SCRYPT
    )


# --------------------------------------------------------------------------- #
# The positive path
# --------------------------------------------------------------------------- #


class TestAuthentic:
    def test_image_round_trip_is_authentic(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.authentic is True
        assert outcome.message == MESSAGE
        assert outcome.payload_found is True
        assert outcome.signature_valid is True
        assert outcome.hash_valid is True
        assert outcome.start_location_valid is True
        assert outcome.manifest_consistent is True
        assert outcome.mismatched_fields == ()

    def test_audio_round_trip_is_authentic(self, wav_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(wav_cover, tmp_path, keys, media_id="AUD-001")

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == MESSAGE

    def test_encrypted_message_is_authentic(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys, passphrase=PASSPHRASE)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
            passphrase=PASSPHRASE,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == MESSAGE
        assert outcome.details["was_encrypted"] is True

    def test_manual_start_location_is_authentic(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=1_500,
        )

        outcome = verify_media(result.stego_path, result.manifest_path, public_key)
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.start_location == 1_500

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_every_depth_verifies(self, png_cover, tmp_path, keys, depth):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys, lsb_depth=depth)
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC

    def test_empty_message_verifies(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys, message=b"")
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == b""

    def test_manifest_is_found_by_convention_when_not_named(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path, None, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC

    def test_a_public_key_path_is_accepted(self, png_cover, tmp_path, keys):
        _, public_key = keys
        key_path = str(tmp_path / "public.pem")
        key_manager.save_public_key(public_key, key_path)
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            key_path,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC

    def test_the_scope_caveat_travels_with_success(self, png_cover, tmp_path, keys):
        """AUTHENTIC must not be allowed to imply more than it establishes."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )

        assert constants.AUTHENTIC_SCOPE_NOTICE in outcome.notes
        assert constants.EXTRACTED_CONTENT_NOTICE in outcome.notes
        assert constants.START_LOCATION_NOTICE in outcome.notes


# --------------------------------------------------------------------------- #
# The negative cases
# --------------------------------------------------------------------------- #


class TestSignatureInvalid:
    def test_wrong_public_key(self, png_cover, tmp_path, keys, other_public_key):
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            other_public_key,
            start_secret=START_SECRET,
        )

        assert outcome.verdict == verdicts.VERDICT_SIGNATURE_INVALID
        assert outcome.signature_valid is False
        assert outcome.payload_found is True
        assert outcome.message is None

    def test_wrong_key_with_an_encrypted_message_is_still_a_signature_failure(
        self, png_cover, tmp_path, keys, other_public_key
    ):
        """Encrypt-then-sign: the cipher is never reached."""
        result = do_protect(png_cover, tmp_path, keys, passphrase=PASSPHRASE)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            other_public_key,
            start_secret=START_SECRET,
            passphrase=PASSPHRASE,
        )
        assert outcome.verdict == verdicts.VERDICT_SIGNATURE_INVALID


class TestTampered:
    def test_corrupted_message_bytes_inside_the_payload(
        self, png_cover, tmp_path, keys
    ):
        """The record still verifies; the message no longer matches its digest.

        Achieved by re-signing a record over modified message bytes, which is what
        an attacker who holds a signing key but not the original message can do.
        """
        from app.crypto import envelope as env
        from app.crypto import signatures as sig

        private_key, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        parsed = env.parse_envelope(
            image_stego.extract_image(
                result.stego_path, result.manifest.lsb_depth, result.start_location
            )
        )
        forged = sig.sign_envelope(
            parsed.record_bytes, b"a completely different message", private_key
        )
        forged_stego = str(tmp_path / "forged.png")
        image_stego.embed_image(
            png_cover,
            forged_stego,
            forged,
            result.manifest.lsb_depth,
            result.start_location,
        )

        from app.verification.verifier import verify_extracted_payload

        outcome = verify_extracted_payload(forged, public_key)
        assert outcome.verdict == verdicts.VERDICT_TAMPERED
        assert outcome.signature_valid is True
        assert outcome.hash_valid is False

    def test_manifest_depth_disagrees_with_the_signed_record(
        self, png_cover, tmp_path, keys
    ):
        """A manifest edit that still extracts is caught by the cross-check."""
        from app.verification.verifier import verify_extracted_payload

        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        extracted = image_stego.extract_image(
            result.stego_path, result.manifest.lsb_depth, result.start_location
        )

        lying = manifest_module.Manifest(
            **{**vars(result.manifest), "lsb_depth": 7}
        )
        outcome = verify_extracted_payload(
            extracted, public_key, manifest=lying
        )

        assert outcome.verdict == verdicts.VERDICT_TAMPERED
        assert outcome.manifest_consistent is False
        assert "lsb_depth" in outcome.mismatched_fields
        assert outcome.hash_valid is True

    def test_manifest_media_id_disagrees(self, png_cover, tmp_path, keys):
        from app.verification.verifier import verify_extracted_payload

        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        extracted = image_stego.extract_image(
            result.stego_path, result.manifest.lsb_depth, result.start_location
        )
        lying = manifest_module.Manifest(
            **{**vars(result.manifest), "media_id": "IMG-999"}
        )

        outcome = verify_extracted_payload(extracted, public_key, manifest=lying)
        assert outcome.verdict == verdicts.VERDICT_TAMPERED
        assert "media_id" in outcome.mismatched_fields

    def test_manifest_envelope_length_disagrees(self, png_cover, tmp_path, keys):
        """Recomputed from the signed bytes, so a length claim is checkable."""
        from app.verification.verifier import verify_extracted_payload

        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        extracted = image_stego.extract_image(
            result.stego_path, result.manifest.lsb_depth, result.start_location
        )
        lying = manifest_module.Manifest(
            **{**vars(result.manifest), "envelope_length": result.envelope_length + 8}
        )

        outcome = verify_extracted_payload(extracted, public_key, manifest=lying)
        assert outcome.verdict == verdicts.VERDICT_TAMPERED
        assert "envelope_length" in outcome.mismatched_fields


class TestPayloadMissing:
    def test_an_unprotected_cover(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        plain = write_cover(
            str(tmp_path), make_cover(64, 64, 3, seed=7), image_io.PNG, "plain"
        )

        outcome = verify_media(
            plain, result.manifest_path, public_key, start_secret=START_SECRET
        )

        assert outcome.verdict == verdicts.VERDICT_PAYLOAD_MISSING
        assert outcome.payload_found is False

    def test_wrong_start_secret(self, png_cover, tmp_path, keys):
        """Reported as missing or unverifiable, never as a confident diagnosis."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret="the wrong secret",
        )

        assert outcome.verdict in (
            verdicts.VERDICT_PAYLOAD_MISSING,
            verdicts.VERDICT_CANNOT_VERIFY,
        )
        assert outcome.verdict != verdicts.VERDICT_WRONG_START_LOCATION

    def test_wrong_depth_in_the_manifest(self, tmp_path, png_cover, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["lsb_depth"] = 6
        edited = str(tmp_path / "edited.manifest.json")
        Path(edited).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_media(
            result.stego_path, edited, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict in (
            verdicts.VERDICT_PAYLOAD_MISSING,
            verdicts.VERDICT_CANNOT_VERIFY,
        )

    def test_the_ambiguity_note_is_attached(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        plain = write_cover(
            str(tmp_path), make_cover(64, 64, 3, seed=7), image_io.PNG, "plain"
        )

        outcome = verify_media(
            plain, result.manifest_path, public_key, start_secret=START_SECRET
        )
        assert constants.AMBIGUOUS_FAILURE_NOTICE in outcome.notes

    def test_random_bytes_are_not_an_envelope(self, keys):
        from app.verification.verifier import verify_extracted_payload

        _, public_key = keys
        outcome = verify_extracted_payload(os.urandom(512), public_key)

        assert outcome.verdict == verdicts.VERDICT_PAYLOAD_MISSING
        assert "does not distinguish" in outcome.reason


class TestWrongStartLocation:
    def test_a_declared_location_beyond_the_medium(self, png_cover, tmp_path, keys):
        """The one provable case, caught before extraction is attempted."""
        _, public_key = keys
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=100,
        )

        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["start_location"] = 10**9
        edited = str(tmp_path / "edited.manifest.json")
        Path(edited).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_media(result.stego_path, edited, public_key)

        assert outcome.verdict == verdicts.VERDICT_WRONG_START_LOCATION
        assert outcome.start_location_valid is False

    def test_a_declared_location_leaving_too_little_room(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=100,
        )

        total = result.embed_result.total_samples
        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["start_location"] = total - 5
        edited = str(tmp_path / "edited.manifest.json")
        Path(edited).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_media(result.stego_path, edited, public_key)
        assert outcome.verdict == verdicts.VERDICT_WRONG_START_LOCATION

    def test_this_verdict_is_not_used_for_ambiguous_failures(
        self, png_cover, tmp_path, keys
    ):
        """The rule that keeps the vocabulary honest."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        for secret in ("wrong", "also wrong", START_SECRET + "!"):
            outcome = verify_media(
                result.stego_path,
                result.manifest_path,
                public_key,
                start_secret=secret,
            )
            assert outcome.verdict != verdicts.VERDICT_WRONG_START_LOCATION


class TestCannotVerify:
    def test_missing_manifest(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        os.unlink(result.manifest_path)

        outcome = verify_media(
            result.stego_path, None, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert "manifest" in outcome.reason

    def test_malformed_manifest(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        Path(result.manifest_path).write_text("{not json", encoding="utf-8")

        outcome = verify_media(
            result.stego_path, None, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY

    def test_manifest_with_an_out_of_range_depth_is_refused_early(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        data = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
        data["lsb_depth"] = 99
        Path(result.manifest_path).write_text(json.dumps(data), encoding="utf-8")

        outcome = verify_media(
            result.stego_path, None, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY

    def test_missing_start_secret_for_a_derived_location(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(result.stego_path, result.manifest_path, public_key)

        # A missing secret is a missing input, not evidence that the location is
        # wrong. Reporting WRONG_START_LOCATION here would claim knowledge the
        # verifier does not have.
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert "secret is required" in outcome.reason
        assert "shared separately" in outcome.reason

    def test_missing_passphrase_for_an_encrypted_message(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys, passphrase=PASSPHRASE)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert outcome.signature_valid is True
        assert "passphrase" in outcome.reason

    def test_wrong_passphrase(self, png_cover, tmp_path, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys, passphrase=PASSPHRASE)

        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
            passphrase="the wrong passphrase",
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert outcome.signature_valid is True

    def test_manifest_for_a_different_medium(self, png_cover, wav_cover, tmp_path, keys):
        _, public_key = keys
        image_result = do_protect(png_cover, tmp_path, keys)
        audio_result = do_protect(
            wav_cover, tmp_path, keys, media_id="AUD-001"
        )

        outcome = verify_media(
            audio_result.stego_path,
            image_result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert "do not belong together" in outcome.reason

    def test_unreadable_cover(self, tmp_path, png_cover, keys):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        broken = tmp_path / "broken.png"
        broken.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

        outcome = verify_media(
            str(broken), result.manifest_path, public_key, start_secret=START_SECRET
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY


# --------------------------------------------------------------------------- #
# The honest limitation
# --------------------------------------------------------------------------- #


class TestScopeOfAuthenticity:
    def test_a_change_outside_the_payload_still_verifies(
        self, png_cover, tmp_path, keys
    ):
        """Demonstrated rather than hidden.

        Baseline verification authenticates the signed record and the recovered
        message. It says nothing about parts of the cover the payload does not
        occupy, and the GUI says so via AUTHENTIC_SCOPE_NOTICE.
        """
        _, public_key = keys
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=0,
        )

        array, descriptor = image_io.load_image(result.stego_path)
        flat, channels = image_stego.embeddable_stream(array)
        # Modify a sample well past the embedded region.
        untouched = result.embed_result.samples_written + 500
        assert untouched < flat.size
        modified = flat.copy()
        modified[untouched] ^= 0xFF

        stego = array.copy()
        stego[:, :, :channels] = modified.reshape(
            array.shape[0], array.shape[1], channels
        )
        altered = str(tmp_path / "altered.png")
        image_io.save_image(stego, altered, descriptor.container_format)

        altered_manifest = file_utils.manifest_path_for(altered)
        manifest_module.write_manifest(
            result.manifest, altered_manifest, overwrite=True
        )

        outcome = verify_media(altered, altered_manifest, public_key)

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert constants.AUTHENTIC_SCOPE_NOTICE in outcome.notes
        # The signature cannot see the change, but the manifest's file digest can,
        # and the receiver is told so without the verdict changing.
        assert outcome.details["file_digest_matches"] is False
        assert constants.FILE_CHANGED_NOTICE in outcome.notes

    def test_an_unmodified_file_matches_the_manifest_digest(
        self, png_cover, tmp_path, keys
    ):
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        outcome = verify_media(
            result.stego_path, result.manifest_path, public_key,
            start_secret=START_SECRET,
        )

        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.details["file_digest_matches"] is True
        assert constants.FILE_CHANGED_NOTICE not in outcome.notes

    def test_replay_of_an_unmodified_file_still_verifies(
        self, png_cover, tmp_path, keys
    ):
        """A timestamp and a nonce alone do not reject a replay, and we do not claim to."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)

        replay_directory = tmp_path / "replayed"
        replay_directory.mkdir()
        replayed_stego = replay_directory / os.path.basename(result.stego_path)
        replayed_stego.write_bytes(Path(result.stego_path).read_bytes())
        replayed_manifest = replay_directory / os.path.basename(result.manifest_path)
        replayed_manifest.write_bytes(Path(result.manifest_path).read_bytes())

        for _ in range(3):
            outcome = verify_media(
                str(replayed_stego),
                str(replayed_manifest),
                public_key,
                start_secret=START_SECRET,
            )
            assert outcome.verdict == verdicts.VERDICT_AUTHENTIC


# --------------------------------------------------------------------------- #
# Protect-side behaviour
# --------------------------------------------------------------------------- #


class TestProtect:
    def test_writes_both_files(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys)
        assert Path(result.stego_path).is_file()
        assert Path(result.manifest_path).is_file()

    def test_manifest_is_named_by_convention(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys)
        assert result.manifest_path == file_utils.manifest_path_for(result.stego_path)

    def test_the_cover_is_left_unchanged(self, png_cover, tmp_path, keys):
        before = Path(png_cover).read_bytes()
        do_protect(png_cover, tmp_path, keys)
        assert Path(png_cover).read_bytes() == before

    def test_required_secrets_are_reported(self, png_cover, tmp_path, keys):
        derived = do_protect(png_cover, tmp_path, keys)
        assert derived.required_secrets == ("start-location secret",)

        encrypted = do_protect(
            png_cover,
            tmp_path,
            keys,
            passphrase=PASSPHRASE,
            output_path=str(tmp_path / "enc.png"),
        )
        assert "message passphrase" in encrypted.required_secrets

    def test_manual_mode_needs_no_secret(self, png_cover, tmp_path, keys):
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=10,
        )
        assert result.required_secrets == ()

    def test_no_temporary_file_is_left_behind(self, png_cover, tmp_path, keys):
        do_protect(png_cover, tmp_path, keys)
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".partial-")]

    def test_an_occupied_manifest_path_is_refused_before_anything_is_written(
        self, png_cover, tmp_path, keys
    ):
        from app.crypto.errors import ManifestError

        output = tmp_path / "stego.png"
        Path(file_utils.manifest_path_for(output)).write_text("{}")
        before = sorted(p.name for p in tmp_path.iterdir())

        with pytest.raises(ManifestError, match="already occupied"):
            do_protect(png_cover, tmp_path, keys, output_path=str(output))
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    def test_a_failed_manifest_write_leaves_no_stego_file(
        self, png_cover, tmp_path, keys, monkeypatch
    ):
        from app.crypto import manifest as manifest_module
        from app.crypto.errors import ManifestError

        def refuse(*args, **kwargs):
            raise ManifestError("disk full")

        monkeypatch.setattr(manifest_module, "write_manifest", refuse)
        before = sorted(p.name for p in tmp_path.iterdir())

        with pytest.raises(ManifestError, match="disk full"):
            do_protect(png_cover, tmp_path, keys)
        assert sorted(p.name for p in tmp_path.iterdir()) == before

    def test_stego_digest_is_recorded(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys)
        assert result.manifest.stego_sha256 == hashing.file_sha256(
            result.stego_path
        )

    def test_derived_location_is_not_published(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys)
        assert result.manifest.start_location is None
        assert result.start_location is not None

    def test_neither_secret_appears_in_the_manifest(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys, passphrase=PASSPHRASE)
        text = Path(result.manifest_path).read_text(encoding="utf-8")
        assert START_SECRET not in text
        assert PASSPHRASE not in text

    def test_oversized_message_is_refused_before_writing(self, tmp_path, keys):
        """Input validation, with a figure the user can act on."""
        small = write_cover(
            str(tmp_path), make_cover(16, 16, 3), image_io.PNG, "small"
        )
        output = str(tmp_path / "stego.png")

        with pytest.raises(CapacityError, match="does not fit"):
            do_protect(
                small, tmp_path, keys, message=b"x" * 5_000, output_path=output
            )
        assert not Path(output).exists()

    def test_the_capacity_message_names_a_workable_size(self, tmp_path, keys):
        small = write_cover(
            str(tmp_path), make_cover(16, 16, 3), image_io.PNG, "small"
        )
        with pytest.raises(CapacityError) as caught:
            do_protect(
                small,
                tmp_path,
                keys,
                message=b"x" * 5_000,
                output_path=str(tmp_path / "s.png"),
            )
        assert "largest message that fits" in str(caught.value)

    def test_ecc_parameters_are_recorded(self, png_cover, tmp_path, keys):
        result = do_protect(
            png_cover,
            tmp_path,
            keys,
            ecc=ErrorCorrectionParameters(constants.ECC_REPETITION, 3),
        )
        assert result.manifest.ecc == ErrorCorrectionParameters(
            constants.ECC_REPETITION, 3
        )
        assert result.record.ecc is not None

    def test_metadata_is_recorded(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys, metadata={"team": "P1-1"})
        assert result.record.metadata == {"team": "P1-1"}

    def test_media_type_is_detected_not_assumed(self, wav_cover, tmp_path, keys):
        result = do_protect(wav_cover, tmp_path, keys, media_id="AUD-001")
        assert result.media_type == constants.MEDIA_AUDIO
        assert result.record.media_type == constants.MEDIA_AUDIO
        assert result.container_format == constants.CONTAINER_WAV


# --------------------------------------------------------------------------- #
# Result reporting
# --------------------------------------------------------------------------- #


class TestVerificationResult:
    def test_every_verdict_has_a_description(self):
        for verdict in verdicts.VERDICTS:
            assert verdicts.VERDICT_DESCRIPTIONS[verdict]

    def test_an_unknown_verdict_is_refused(self):
        with pytest.raises(ValueError, match="verdict must be one of"):
            verdicts.VerificationResult(verdict="MAYBE", reason="x")

    def test_summary_omits_the_recovered_plaintext(self, png_cover, tmp_path, keys):
        """The evidence log is committed; plaintext must not leak into it."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        outcome = verify_media(
            result.stego_path,
            result.manifest_path,
            public_key,
            start_secret=START_SECRET,
        )

        summary = json.dumps(outcome.as_dict())
        assert MESSAGE.decode() not in summary
        assert outcome.as_dict()["message_length"] == len(MESSAGE)

    def test_summary_is_json_serialisable_for_every_verdict(
        self, png_cover, tmp_path, keys, other_public_key
    ):
        result = do_protect(png_cover, tmp_path, keys)
        _, public_key = keys

        for key in (public_key, other_public_key):
            outcome = verify_media(
                result.stego_path,
                result.manifest_path,
                key,
                start_secret=START_SECRET,
            )
            json.dumps(outcome.as_dict())

    def test_flags_are_none_when_not_established(self, png_cover, tmp_path, keys):
        """None means "never got that far", which differs from False."""
        _, public_key = keys
        result = do_protect(png_cover, tmp_path, keys)
        plain = write_cover(
            str(tmp_path), make_cover(64, 64, 3, seed=9), image_io.PNG, "plain"
        )

        outcome = verify_media(
            plain, result.manifest_path, public_key, start_secret=START_SECRET
        )
        assert outcome.payload_found is False
        assert outcome.signature_valid is None
        assert outcome.hash_valid is None

    def test_details_are_copied_not_aliased(self):
        shared = {"stage": "one"}
        outcome = verdicts.VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY, reason="x", details=shared
        )
        shared["stage"] = "two"
        assert outcome.details["stage"] == "one"


class TestKeyErrorsStillRaise:
    """Faults that are not about the file under test are exceptions, not verdicts."""

    def test_missing_public_key_file(self, png_cover, tmp_path, keys):
        result = do_protect(png_cover, tmp_path, keys)
        with pytest.raises(KeyMaterialError, match="not found"):
            verify_media(
                result.stego_path,
                result.manifest_path,
                str(tmp_path / "absent.pem"),
                start_secret=START_SECRET,
            )

    def test_private_key_supplied_for_verification(self, png_cover, tmp_path, keys):
        private_key, _ = keys
        result = do_protect(png_cover, tmp_path, keys)
        with pytest.raises(KeyMaterialError, match="public key is required"):
            verify_media(
                result.stego_path,
                result.manifest_path,
                private_key,
                start_secret=START_SECRET,
            )
