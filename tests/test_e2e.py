"""End-to-end tests: the complete party A to party B workflow.

This file is the assignment's evidence. Everything else tests a layer; this tests
the thing the demonstration actually shows.

The A-to-B simulation is deliberately physical. Party A works in a sender
directory and party B in a receiver directory, and only the files a real transfer
would carry are copied across: the stego object, its companion manifest, and the
sender's public key. The private key stays behind, and the two shared secrets are
never written to any file at all. :class:`Transfer` enforces that, so a test cannot
accidentally verify using something the receiver would not have.

Required cases, from the project plan
-------------------------------------
Two positive cases minimum, three negative minimum, with at least one of each for
image and for audio. Implemented here:

positive
  1. PNG protected and verified
  2. WAV protected and verified
  3. PNG with an encrypted message
  4. BMP with a manually chosen start location
  5. MKV video protected and verified (the optional third medium)

negative
  1. corrupted embedded message in an image
  2. corrupted record and corrupted signature in audio
  3. wrong public key
  4. wrong start secret
  5. missing payload (an unprotected cover)
  6. a stego clip re-encoded with a lossy codec

Insufficient capacity is kept separate, as input validation rather than a
verification failure, which is what the plan asks for.

Three message sizes are covered as required: a short line, a long paragraph, and a
custom payload about confidentiality and integrity.

Results are written to ``evidence/results/`` so the run leaves the artefacts the
submission needs.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from app.analysis import quality_metrics
from app.crypto import key_manager
from app.crypto.encryption import MIN_SCRYPT_N
from app.crypto.envelope import ErrorCorrectionParameters
from app.stego import image_io
from app.stego.errors import CapacityError
from app.utils import constants, file_utils
from app.verification import media_compare, verdicts
from app.verification.protect import protect_media
from app.verification.verifier import verify_media
from conftest import (
    make_audio,
    make_cover,
    make_video_frames,
    write_audio_file,
    write_cover,
    write_video_file,
)

# Cheap scrypt: the production cost is asserted in tests/test_utils.py and would
# otherwise dominate this file's runtime.
FAST_SCRYPT = {"scrypt_n": MIN_SCRYPT_N, "scrypt_r": 8, "scrypt_p": 1}

START_SECRET = "the start location secret, shared out of band"
PASSPHRASE = "the message passphrase, shared separately"

# --------------------------------------------------------------------------- #
# The three required message sizes
# --------------------------------------------------------------------------- #

#: Short: one line, as a Learning Objective would be.
SHORT_MESSAGE = b"Apply cryptographic techniques to protect data integrity."

#: Long: a paragraph, as the Project Overview is.
LONG_MESSAGE = (
    b"This project is a graphical application for protecting and verifying media "
    b"files. It embeds a signed verification record into an image, audio or video "
    b"cover object using least significant bit replacement, at a selectable depth "
    b"from one to eight bits, beginning at a start location that is either chosen "
    b"directly or derived from a shared secret. The receiver recovers the record, "
    b"checks its digital signature against the sender's public key, recomputes the "
    b"digest of the recovered message, and reports a clear verdict. Verification "
    b"establishes the authenticity of the signed message record. It does not "
    b"establish that every part of the cover object is unchanged, and it does not "
    b"by itself reject a replayed file."
)

#: Custom: addresses confidentiality and integrity together, which is the case the
#: encrypted path exists for.
CUSTOM_MESSAGE = (
    b"CONFIDENTIAL - INF2005 ACW1. Integrity is provided by an RSA-PSS signature "
    b"over the verification record and the message together, so any change to "
    b"either is detected. Confidentiality is provided separately, by AES-256-GCM "
    b"under a key derived from a passphrase with scrypt. A concealed start "
    b"location is not encryption and provides neither property on its own."
)

MESSAGES = {
    "short": SHORT_MESSAGE,
    "long": LONG_MESSAGE,
    "custom": CUSTOM_MESSAGE,
}


# --------------------------------------------------------------------------- #
# Evidence collection
# --------------------------------------------------------------------------- #

_RESULTS: list[dict[str, Any]] = []


def record_case(
    case: str,
    kind: str,
    media_type: str,
    expected: str,
    observed: str,
    detail: str = "",
) -> None:
    """Record one case for the evidence artefacts written at session end."""
    _RESULTS.append(
        {
            "case": case,
            "kind": kind,
            "media_type": media_type,
            "expected": expected,
            "observed": observed,
            "passed": expected == observed,
            "detail": detail,
        }
    )


@pytest.fixture(scope="module", autouse=True)
def write_evidence():
    """Write the evidence artefacts once, after every case in this file has run."""
    _RESULTS.clear()
    yield

    if not _RESULTS:  # pragma: no cover - only when the module is deselected
        return

    directory = Path(__file__).resolve().parents[1] / "evidence" / "results"
    directory.mkdir(parents=True, exist_ok=True)

    file_utils.write_json_atomic(
        str(directory / "e2e_results.json"),
        {
            "suite": "end-to-end protect and verify",
            "total": len(_RESULTS),
            "passed": sum(1 for row in _RESULTS if row["passed"]),
            "cases": _RESULTS,
        },
        overwrite=True,
    )

    positives = [row for row in _RESULTS if row["kind"] == "positive"]
    negatives = [row for row in _RESULTS if row["kind"] == "negative"]
    validation = [row for row in _RESULTS if row["kind"] == "validation"]

    lines = [
        "# End-to-End Protect and Verify Results",
        "",
        "Generated by `tests/test_e2e.py`. Every row is one automated case.",
        "",
        f"- positive cases: {len(positives)}",
        f"- negative cases: {len(negatives)}",
        f"- input-validation cases: {len(validation)}",
        f"- total: {len(_RESULTS)}, passed: "
        f"{sum(1 for row in _RESULTS if row['passed'])}",
        "",
        "The assignment requires at least two positive and three negative cases, "
        "with at least one of each for image and for audio. Video is the optional "
        "third medium and is covered here as well, positively and negatively.",
        "",
        "| Case | Kind | Media | Expected | Observed | Result |",
        "|---|---|---|---|---|---|",
    ]
    for row in _RESULTS:
        lines.append(
            f"| {row['case']} | {row['kind']} | {row['media_type']} | "
            f"{row['expected']} | {row['observed']} | "
            f"{'PASS' if row['passed'] else 'FAIL'} |"
        )

    lines += [
        "",
        "## What AUTHENTIC means here",
        "",
        constants.AUTHENTIC_SCOPE_NOTICE,
        "",
        "## Why several failures share one verdict",
        "",
        constants.AMBIGUOUS_FAILURE_NOTICE,
        "",
    ]
    file_utils.write_text_atomic(
        str(directory / "e2e_results.md"), "\n".join(lines), overwrite=True
    )


# --------------------------------------------------------------------------- #
# The A-to-B transfer
# --------------------------------------------------------------------------- #


@dataclass
class Transfer:
    """A simulated transfer between two parties with separate directories.

    Party B's directory receives only what a real transfer would carry. The
    private key is never copied, and neither secret is ever written to a file, so
    a test that tries to verify with something the receiver would not have simply
    has nothing to reach for.
    """

    sender_directory: Path
    receiver_directory: Path
    public_key_path: str
    stego_name: str
    manifest_name: str

    @property
    def received_stego(self) -> str:
        return str(self.receiver_directory / self.stego_name)

    @property
    def received_manifest(self) -> str:
        return str(self.receiver_directory / self.manifest_name)

    @property
    def received_public_key(self) -> str:
        return str(self.receiver_directory / os.path.basename(self.public_key_path))

    def receiver_files(self) -> list[str]:
        return sorted(entry.name for entry in self.receiver_directory.iterdir())


@pytest.fixture(scope="module")
def sender_keys():
    private_key, public_key = key_manager.generate_key_pair(
        constants.RSA_MIN_KEY_SIZE
    )
    return private_key, public_key


@pytest.fixture(scope="module")
def impostor_keys():
    """An unrelated key pair, for the wrong-key case."""
    return key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)


@pytest.fixture()
def parties(tmp_path, sender_keys):
    """Two directories and a published public key."""
    _, public_key = sender_keys
    sender = tmp_path / "party_a_sender"
    receiver = tmp_path / "party_b_receiver"
    sender.mkdir()
    receiver.mkdir()

    public_key_path = str(sender / "sender_public.pem")
    key_manager.save_public_key(public_key, public_key_path)
    return sender, receiver, public_key_path


def send(sender_directory, receiver_directory, public_key_path, result) -> Transfer:
    """Copy exactly the files party B would download."""
    transfer = Transfer(
        sender_directory=Path(sender_directory),
        receiver_directory=Path(receiver_directory),
        public_key_path=public_key_path,
        stego_name=os.path.basename(result.stego_path),
        manifest_name=os.path.basename(result.manifest_path),
    )
    shutil.copyfile(result.stego_path, transfer.received_stego)
    shutil.copyfile(result.manifest_path, transfer.received_manifest)
    shutil.copyfile(public_key_path, transfer.received_public_key)
    return transfer


def protect_for_transfer(
    cover: str,
    sender_directory: Path,
    private_key,
    *,
    message: bytes = SHORT_MESSAGE,
    media_id: str = "IMG-001",
    lsb_depth: int = 3,
    name: str = "sent",
    **options,
):
    extension = os.path.splitext(cover)[1]
    return protect_media(
        cover,
        str(sender_directory / f"{name}{extension}"),
        message,
        private_key,
        media_id=media_id,
        lsb_depth=lsb_depth,
        start_method=options.pop("start_method", constants.START_METHOD_HMAC),
        start_secret=options.pop("start_secret", START_SECRET),
        **options,
        **FAST_SCRYPT,
    )


@pytest.fixture()
def png_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.PNG, "cover")


@pytest.fixture()
def bmp_cover(tmp_path):
    return write_cover(str(tmp_path), make_cover(96, 96, 3), image_io.BMP, "cover_bmp")


@pytest.fixture()
def wav_cover(tmp_path):
    return write_audio_file(str(tmp_path), make_audio(60_000))


@pytest.fixture()
def mkv_cover(tmp_path):
    """A short lossless clip. Small on purpose: encoding is the slow part here."""
    return write_video_file(
        str(tmp_path), make_video_frames(frame_count=10, height=48, width=64), "clip"
    )


# --------------------------------------------------------------------------- #
# The transfer itself
# --------------------------------------------------------------------------- #


class TestTransferMechanics:
    def test_the_receiver_gets_exactly_three_files(
        self, png_cover, parties, sender_keys
    ):
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        assert transfer.receiver_files() == sorted(
            [transfer.stego_name, transfer.manifest_name, "sender_public.pem"]
        )

    def test_the_private_key_never_leaves_the_sender(
        self, png_cover, parties, sender_keys
    ):
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        key_manager.save_private_key(private_key, str(sender / "sender_private.pem"))
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        assert "sender_private.pem" not in transfer.receiver_files()
        for name in transfer.receiver_files():
            assert b"PRIVATE KEY" not in (transfer.receiver_directory / name).read_bytes()

    def test_neither_secret_appears_in_any_transferred_file(
        self, png_cover, parties, sender_keys
    ):
        """Both secrets are shared out of band, so neither may be in a file."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            png_cover, sender, private_key, passphrase=PASSPHRASE
        )
        transfer = send(sender, receiver, public_key_path, result)

        for name in transfer.receiver_files():
            content = (transfer.receiver_directory / name).read_bytes()
            assert START_SECRET.encode() not in content
            assert PASSPHRASE.encode() not in content

    def test_the_protect_result_lists_what_still_has_to_be_shared(
        self, png_cover, parties, sender_keys
    ):
        sender, _, _ = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            png_cover, sender, private_key, passphrase=PASSPHRASE
        )

        assert set(result.required_secrets) == {
            "start-location secret",
            "message passphrase",
        }

    def test_the_receiver_can_verify_from_its_own_directory(
        self, png_cover, parties, sender_keys
    ):
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC

    def test_the_manifest_is_required(self, png_cover, parties, sender_keys):
        """Without it the receiver cannot locate the payload at all."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)
        os.unlink(transfer.received_manifest)

        outcome = verify_media(
            transfer.received_stego,
            None,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY

    def test_the_sender_cover_is_untouched(self, png_cover, parties, sender_keys):
        sender, _, _ = parties
        private_key, _ = sender_keys
        before = Path(png_cover).read_bytes()
        protect_for_transfer(png_cover, sender, private_key)
        assert Path(png_cover).read_bytes() == before


# --------------------------------------------------------------------------- #
# Positive cases
# --------------------------------------------------------------------------- #


class TestPositiveCases:
    @pytest.mark.parametrize("size", list(MESSAGES))
    def test_png_at_three_message_sizes(
        self, png_cover, parties, sender_keys, size
    ):
        """Positive case 1, across the three required message sizes."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        message = MESSAGES[size]

        result = protect_for_transfer(
            png_cover, sender, private_key, message=message, name=f"png_{size}"
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            f"PNG, {size} message ({len(message)} bytes)",
            "positive",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            f"{len(message)}-byte message, depth 3, derived start location",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == message

    @pytest.mark.parametrize("size", list(MESSAGES))
    def test_wav_at_three_message_sizes(
        self, wav_cover, parties, sender_keys, size
    ):
        """Positive case 2, across the three required message sizes."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        message = MESSAGES[size]

        result = protect_for_transfer(
            wav_cover,
            sender,
            private_key,
            message=message,
            media_id="AUD-001",
            name=f"wav_{size}",
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            f"WAV, {size} message ({len(message)} bytes)",
            "positive",
            constants.MEDIA_AUDIO,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            f"{len(message)}-byte message, depth 3, derived start location",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == message

    def test_encrypted_custom_payload(self, png_cover, parties, sender_keys):
        """Positive case 3: the confidentiality and integrity demonstration."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys

        result = protect_for_transfer(
            png_cover,
            sender,
            private_key,
            message=CUSTOM_MESSAGE,
            passphrase=PASSPHRASE,
            name="encrypted",
        )
        transfer = send(sender, receiver, public_key_path, result)

        # The plaintext must not be present anywhere in the transferred files.
        for name in transfer.receiver_files():
            assert CUSTOM_MESSAGE not in (
                transfer.receiver_directory / name
            ).read_bytes()

        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
            passphrase=PASSPHRASE,
        )

        record_case(
            "PNG, encrypted custom payload",
            "positive",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            "AES-256-GCM under a scrypt-derived key, encrypt-then-sign",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == CUSTOM_MESSAGE
        assert outcome.details["was_encrypted"] is True

    def test_bmp_with_a_manual_start_location(
        self, bmp_cover, parties, sender_keys
    ):
        """Positive case 4: the other container and the other start method."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys

        result = protect_for_transfer(
            bmp_cover,
            sender,
            private_key,
            message=SHORT_MESSAGE,
            start_method=constants.START_METHOD_MANUAL,
            start_secret=None,
            manual_start_location=5_000,
            name="manual",
        )
        transfer = send(sender, receiver, public_key_path, result)

        # No secret is needed for the manual method.
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
        )

        record_case(
            "BMP, manual start location",
            "positive",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            "start location 5000, signed into the record, no secret required",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.start_location == 5_000

    def test_video_protected_and_verified(self, mkv_cover, parties, sender_keys):
        """Positive case 5: the optional third medium, through the same workflow.

        The point of this case is that nothing in the transfer is video-specific. The
        same three files cross, the same secret is shared out of band, and the same
        call verifies them — the medium is decided by the cover's content and nothing
        above the stego layer had to know.
        """
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys

        result = protect_for_transfer(
            mkv_cover,
            sender,
            private_key,
            message=SHORT_MESSAGE,
            media_id="VID-001",
            lsb_depth=2,
            name="video",
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            f"MKV video, short message ({len(SHORT_MESSAGE)} bytes)",
            "positive",
            constants.MEDIA_VIDEO,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            "FFV1 in Matroska, depth 2, derived start location over the flat "
            "frame domain",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC
        assert outcome.message == SHORT_MESSAGE
        assert outcome.record.media_type == constants.MEDIA_VIDEO

    @pytest.mark.parametrize("depth", range(1, 9))
    def test_every_selectable_depth_survives_a_transfer(
        self, png_cover, parties, sender_keys, depth
    ):
        """The plan requires depths 1 to 8 to be selectable and to work."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys

        result = protect_for_transfer(
            png_cover,
            sender,
            private_key,
            message=SHORT_MESSAGE,
            lsb_depth=depth,
            name=f"depth{depth}",
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC


# --------------------------------------------------------------------------- #
# Negative cases
# --------------------------------------------------------------------------- #


class TestNegativeCases:
    def test_corrupted_message_in_an_image(self, png_cover, parties, sender_keys):
        """Negative case 1."""
        from app.attacks import registry

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result, str(sender / "corrupted.png")
        )
        run = registry.run_attack(
            "payload.message",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Image with a corrupted embedded message",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_SIGNATURE_INVALID,
            run.after.verdict,
            "the signature covers the message, so a change to it fails the signature",
        )
        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID

    def test_corrupted_record_in_audio(self, wav_cover, parties, sender_keys):
        """Negative case 2a."""
        from app.attacks import registry

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            wav_cover, sender, private_key, media_id="AUD-001"
        )
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result, str(sender / "corrupted_record.wav")
        )
        run = registry.run_attack(
            "payload.record",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Audio with a corrupted verification record",
            "negative",
            constants.MEDIA_AUDIO,
            verdicts.VERDICT_SIGNATURE_INVALID,
            run.after.verdict,
            "one digit of the signed nonce changed, length preserved",
        )
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID

    def test_corrupted_signature_in_audio(self, wav_cover, parties, sender_keys):
        """Negative case 2b."""
        from app.attacks import registry

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            wav_cover, sender, private_key, media_id="AUD-001"
        )
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result, str(sender / "corrupted_signature.wav")
        )
        run = registry.run_attack(
            "payload.signature",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Audio with a corrupted signature",
            "negative",
            constants.MEDIA_AUDIO,
            verdicts.VERDICT_SIGNATURE_INVALID,
            run.after.verdict,
            "one byte of the signature inverted",
        )
        assert run.after.verdict == verdicts.VERDICT_SIGNATURE_INVALID

    def test_wrong_public_key(self, png_cover, parties, sender_keys, impostor_keys):
        """Negative case 3."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        _, impostor_public_key = impostor_keys

        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)
        impostor_path = str(receiver / "impostor_public.pem")
        key_manager.save_public_key(impostor_public_key, impostor_path)

        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            impostor_path,
            start_secret=START_SECRET,
        )

        record_case(
            "Verified with the wrong public key",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_SIGNATURE_INVALID,
            outcome.verdict,
            "an unrelated RSA key pair",
        )
        assert outcome.verdict == verdicts.VERDICT_SIGNATURE_INVALID
        assert outcome.signature_valid is False

    def test_wrong_start_secret(self, png_cover, parties, sender_keys):
        """Negative case 4.

        The verdict is not asserted to a single value on purpose. A wrong secret
        puts the reader at the wrong offset, and what is found there is not
        predictable, so the honest assertion is that verification does not succeed
        and does not claim to know the cause.
        """
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret="not the agreed secret",
        )

        record_case(
            "Wrong start-location secret",
            "negative",
            constants.MEDIA_IMAGE,
            "not AUTHENTIC",
            "not AUTHENTIC"
            if outcome.verdict != verdicts.VERDICT_AUTHENTIC
            else outcome.verdict,
            f"observed {outcome.verdict}; the cause is not distinguishable",
        )
        assert outcome.verdict != verdicts.VERDICT_AUTHENTIC
        assert outcome.verdict != verdicts.VERDICT_WRONG_START_LOCATION

    def test_missing_payload(self, png_cover, parties, sender_keys, tmp_path):
        """Negative case 5: an unprotected cover, with a valid manifest."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        unprotected = write_cover(
            str(receiver), make_cover(96, 96, 3, seed=99), image_io.PNG, "unprotected"
        )
        outcome = verify_media(
            unprotected,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Unprotected cover, no payload present",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_PAYLOAD_MISSING,
            outcome.verdict,
            "a plain PNG that was never protected",
        )
        assert outcome.verdict == verdicts.VERDICT_PAYLOAD_MISSING
        assert outcome.payload_found is False
        assert constants.AMBIGUOUS_FAILURE_NOTICE in outcome.notes

    def test_tampered_manifest_caught_by_the_cross_check(
        self, png_cover, parties, sender_keys
    ):
        """A sixth negative case: the manifest is not signed, but it is cross-checked.

        ``message_length`` is chosen because it does *not* feed the start-location
        derivation, so extraction still succeeds and the mismatch has to be caught
        afterwards by comparing the manifest against the signed record. That is the
        mechanism this case is meant to demonstrate.
        """
        from app.attacks import registry

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result,
            str(sender / "tampered.manifest.json"),
            field="message_length",
        )
        run = registry.run_attack(
            "manifest.tamper",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Tampered manifest, caught by the cross-check",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_TAMPERED,
            run.after.verdict,
            "message_length edited; extraction still works, the comparison catches it",
        )
        assert run.after.verdict == verdicts.VERDICT_TAMPERED
        assert "message_length" in run.after.mismatched_fields
        assert run.after.signature_valid is True
        assert run.after.hash_valid is True

    def test_tampered_manifest_that_breaks_extraction(
        self, png_cover, parties, sender_keys
    ):
        """The other detection mechanism, for a field that drives the derivation.

        ``media_id`` is one of the keyed derivation's inputs, so changing it moves
        where the receiver looks and nothing is found. Also a detection, by a
        different route, and worth showing separately because the verdict differs.
        """
        from app.attacks import registry
        from app.attacks.payload_attacks import DERIVATION_INPUT_FIELDS

        assert "media_id" in DERIVATION_INPUT_FIELDS

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result, str(sender / "tampered_id.manifest.json"), field="media_id"
        )
        run = registry.run_attack(
            "manifest.tamper",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Tampered manifest, breaks the derived start location",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_PAYLOAD_MISSING,
            run.after.verdict,
            "media_id edited; it feeds the derivation, so nothing is found",
        )
        assert run.after.verdict == verdicts.VERDICT_PAYLOAD_MISSING
        assert run.matched_expectation

    def test_a_lossy_re_encode_of_a_video_destroys_the_payload(
        self, mkv_cover, parties, sender_keys
    ):
        """Negative case 6, and the one most likely to happen by accident.

        Uploading, sharing or editing a clip re-encodes it. Nothing hostile has to
        occur for the payload to be gone, which is why the output codec is fixed to a
        lossless one and why this case is worth showing next to the deliberate
        attacks rather than among them.
        """
        from app.attacks import registry

        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            mkv_cover,
            sender,
            private_key,
            media_id="VID-001",
            lsb_depth=2,
            name="video_attacked",
        )
        transfer = send(sender, receiver, public_key_path, result)

        context = registry.context_from_protect_result(
            result, str(sender / "recompressed.mkv")
        )
        run = registry.run_attack(
            "video.lossy",
            context,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Video re-encoded with a lossy codec",
            "negative",
            constants.MEDIA_VIDEO,
            "not AUTHENTIC",
            "not AUTHENTIC"
            if run.after.verdict != verdicts.VERDICT_AUTHENTIC
            else run.after.verdict,
            f"re-encoded with {run.outcome.details['codec']}; observed "
            f"{run.after.verdict}",
        )
        assert run.before.verdict == verdicts.VERDICT_AUTHENTIC
        assert run.after.verdict != verdicts.VERDICT_AUTHENTIC
        assert run.matched_expectation

    def test_wrong_passphrase_on_an_encrypted_message(
        self, png_cover, parties, sender_keys
    ):
        """A seventh negative case, specific to the confidentiality path."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            png_cover, sender, private_key, passphrase=PASSPHRASE
        )
        transfer = send(sender, receiver, public_key_path, result)

        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
            passphrase="not the agreed passphrase",
        )

        record_case(
            "Wrong message passphrase",
            "negative",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_CANNOT_VERIFY,
            outcome.verdict,
            "signature verified, so the record is genuine; decryption failed",
        )
        assert outcome.verdict == verdicts.VERDICT_CANNOT_VERIFY
        assert outcome.signature_valid is True


# --------------------------------------------------------------------------- #
# Input validation, kept separate from verification failures
# --------------------------------------------------------------------------- #


class TestInputValidation:
    def test_insufficient_capacity_is_refused_before_anything_is_written(
        self, tmp_path, parties, sender_keys
    ):
        """The plan asks for this as input validation, not a verification failure."""
        sender, _, _ = parties
        private_key, _ = sender_keys
        small = write_cover(
            str(tmp_path), make_cover(16, 16, 3), image_io.PNG, "small"
        )
        output = str(sender / "too_big.png")

        with pytest.raises(CapacityError) as caught:
            protect_media(
                small,
                output,
                LONG_MESSAGE,
                private_key,
                media_id="IMG-SMALL",
                lsb_depth=1,
                start_secret=START_SECRET,
                **FAST_SCRYPT,
            )

        record_case(
            "Payload exceeds capacity",
            "validation",
            constants.MEDIA_IMAGE,
            "refused before writing",
            "refused before writing",
            "a 16x16 cover at depth 1 cannot hold the long message",
        )
        assert not Path(output).exists()
        assert "largest message that fits" in str(caught.value)

    def test_a_greater_depth_makes_the_same_message_fit(
        self, tmp_path, parties, sender_keys
    ):
        """The capacity and depth trade-off, demonstrated rather than asserted."""
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        cover = write_cover(
            str(tmp_path), make_cover(48, 48, 3), image_io.PNG, "medium"
        )

        with pytest.raises(CapacityError):
            protect_media(
                cover,
                str(sender / "depth1.png"),
                LONG_MESSAGE,
                private_key,
                media_id="IMG-MED",
                lsb_depth=1,
                start_secret=START_SECRET,
                **FAST_SCRYPT,
            )

        result = protect_media(
            cover,
            str(sender / "depth6.png"),
            LONG_MESSAGE,
            private_key,
            media_id="IMG-MED",
            lsb_depth=6,
            start_secret=START_SECRET,
            **FAST_SCRYPT,
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        record_case(
            "Same message fits at a greater depth",
            "validation",
            constants.MEDIA_IMAGE,
            verdicts.VERDICT_AUTHENTIC,
            outcome.verdict,
            "refused at depth 1, accepted at depth 6 on a 48x48 cover",
        )
        assert outcome.verdict == verdicts.VERDICT_AUTHENTIC


# --------------------------------------------------------------------------- #
# The demonstration's supporting output
# --------------------------------------------------------------------------- #


class TestDemonstrationOutputs:
    def test_media_comparison_is_available_for_the_demo(
        self, png_cover, parties, sender_keys
    ):
        """The before-and-after table the plan asks to be displayed."""
        sender, _, _ = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)

        comparison = media_compare.compare(png_cover, result.stego_path, lsb_depth=3)

        assert comparison.structure_identical is True
        assert comparison.quality is not None
        assert comparison.quality.within_distortion_bound is True
        assert "Original" in comparison.as_text()

    def test_quality_degrades_as_depth_rises(
        self, png_cover, parties, sender_keys
    ):
        """The trade-off the GUI's depth control is meant to make visible."""
        sender, _, _ = parties
        private_key, _ = sender_keys
        psnr_values = []

        for depth in (1, 4, 8):
            result = protect_for_transfer(
                png_cover,
                sender,
                private_key,
                message=LONG_MESSAGE,
                lsb_depth=depth,
                name=f"quality{depth}",
            )
            report = quality_metrics.compare_quality(
                png_cover, result.stego_path, lsb_depth=depth
            )
            psnr_values.append(report.psnr_db)

        assert psnr_values == sorted(psnr_values, reverse=True)

    def test_the_verdict_summary_is_loggable_without_leaking_the_message(
        self, png_cover, parties, sender_keys
    ):
        sender, receiver, public_key_path = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(
            png_cover, sender, private_key, message=CUSTOM_MESSAGE
        )
        transfer = send(sender, receiver, public_key_path, result)
        outcome = verify_media(
            transfer.received_stego,
            transfer.received_manifest,
            transfer.received_public_key,
            start_secret=START_SECRET,
        )

        summary = json.dumps(outcome.as_dict())
        assert CUSTOM_MESSAGE.decode() not in summary
        assert outcome.as_dict()["message_length"] == len(CUSTOM_MESSAGE)

    def test_the_manifest_is_readable_by_a_person(
        self, png_cover, parties, sender_keys
    ):
        """It gets opened on screen during the demonstration."""
        sender, _, _ = parties
        private_key, _ = sender_keys
        result = protect_for_transfer(png_cover, sender, private_key)

        text = Path(result.manifest_path).read_text(encoding="utf-8")
        payload = json.loads(text)

        assert "\n" in text
        assert payload["lsb_depth"] == 3
        assert payload["start_method"] == constants.START_METHOD_HMAC
        assert payload["start_location"] is None
        assert payload["notice"] == constants.START_LOCATION_NOTICE
