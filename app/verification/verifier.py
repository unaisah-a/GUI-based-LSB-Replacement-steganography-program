"""The receiver side: locate, read, verify and report on a protected file.

This is the module that turns the layers below into an answer. It orchestrates and
decides; it implements no cryptography and no bit manipulation of its own.

The order of operations is the whole design
-------------------------------------------
::

    1. read and validate the companion manifest        (untrusted input)
    2. measure the medium                              (total sample count)
    3. resolve the start location                      (derive, or use the manual value)
    4. extract the payload bytes                       (opaque bytes out)
    5. parse the envelope                              (structure only)
    6. verify the signature                            <- nothing before this is trusted
    7. validate the record                             (now safe to interpret)
    8. decrypt, if the record says so
    9. recompute the message digest and compare
    10. cross-check the manifest against the signed record

Step 6 is the trust boundary. Everything before it is attacker-controlled: the
manifest arrived alongside the file, and the extracted bytes came out of a medium
anyone could have modified. So steps 1 to 5 only ever *validate structure* and
never act on a claim, and no value from the record is believed until the signature
has verified.

Putting decryption at step 8 rather than earlier is what makes a wrong signing key
report ``SIGNATURE_INVALID`` instead of surfacing as a decryption failure.

Failures are verdicts, not exceptions
-------------------------------------
:func:`verify_media` returns a :class:`~app.verification.verdicts.VerificationResult`
for every outcome a receiver can encounter, including a missing payload, a bad
signature, a wrong passphrase and a tampered manifest. It raises only for faults
that are not about the file being verified: an unreadable public key, or a
programming error in the arguments. That keeps the GUI's error handling simple — a
verdict is always something to display, never something to catch.
"""

from __future__ import annotations

import os
from typing import Any

from app.crypto import envelope as envelope_module
from app.crypto import manifest as manifest_module
from app.crypto import payload as payload_module
from app.crypto import signatures, start_location
from app.crypto.errors import (
    EncryptionError,
    EnvelopeError,
    ManifestError,
    RecordError,
    StartLocationError,
)
from app.crypto.key_manager import load_public_key
from app.robustness import error_correction
from app.robustness.redundancy import RedundancyError
from app.stego import media
from app.stego.errors import StegoError
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger
from app.verification import verdicts
from app.verification.verdicts import VerificationResult

__all__ = ["verify_extracted_payload", "verify_media"]

_log = get_logger(__name__)


def _resolve_public_key(public_key: Any) -> Any:
    """Accept a loaded key object or a path to a PEM file."""
    if isinstance(public_key, (str, os.PathLike)):
        return load_public_key(public_key)
    return public_key


def verify_media(
    stego_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str] | None,
    public_key: Any,
    *,
    start_secret: str | bytes | None = None,
    passphrase: str | bytes | None = None,
) -> VerificationResult:
    """Verify the protected file at *stego_path* and return a verdict.

    :param manifest_path: the companion manifest. Defaults to the conventional
        ``<stego file>.manifest.json`` beside the file.
    :param public_key: a loaded RSA public key, or a path to a PEM file.
    :param start_secret: required when the manifest declares the keyed start
        method. Shared out of band.
    :param passphrase: required when the message is encrypted. Shared out of band,
        separately from the start secret.
    :raises app.crypto.errors.KeyMaterialError: the public key cannot be loaded.
        Every other failure is reported as a verdict.
    """
    key = _resolve_public_key(public_key)
    resolved_manifest_path = (
        os.fspath(manifest_path)
        if manifest_path is not None
        else file_utils.manifest_path_for(stego_path)
    )
    name = file_utils.display_name(stego_path)

    # --- 1. The manifest, treated as untrusted ---------------------------- #
    try:
        manifest = manifest_module.read_manifest(resolved_manifest_path)
    except ManifestError as exc:
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=f"the companion manifest could not be used: {exc}",
            details={"stage": "manifest", "stego_file": name},
        )

    # --- 2. The medium ---------------------------------------------------- #
    try:
        capacity = media.measure(stego_path, manifest.lsb_depth)
    except StegoError as exc:
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=f"the file could not be read as a cover object: {exc}",
            details={"stage": "media", "stego_file": name},
        )

    if capacity.media_type != manifest.media_type:
        # Knowable without ambiguity, and worth saying plainly: the manifest
        # belongs to a different kind of file.
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=(
                f"the manifest describes {manifest.media_type} media but "
                f"{name} is {capacity.media_type} media; the manifest and the file "
                f"do not belong together"
            ),
            manifest_consistent=False,
            details={"stage": "media", "stego_file": name},
        )

    # --- 3. The start location -------------------------------------------- #
    # A missing secret is a user-input problem, not a wrong start location, and
    # the two must not be reported the same way. Checked here so that a
    # StartLocationError below can only mean the declared location genuinely does
    # not fit this medium, which is the one provable case.
    if manifest.start_method == constants.START_METHOD_HMAC and start_secret is None:
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=(
                f"the manifest declares the {constants.START_METHOD_HMAC!r} start "
                f"method, so the start-location secret is required to locate the "
                f"payload. It is shared separately from the file and its manifest"
            ),
            details={"stage": "start_location", "stego_file": name},
        )

    # The bytes on the medium are the envelope after any error-correcting code was
    # applied, so that is the length the start-location derivation and the extraction
    # bound both need. The manifest records the envelope's own length plus the code's
    # parameters, which is enough to compute it.
    embedded_length = error_correction.encoded_length(
        manifest.envelope_length, manifest.ecc
    )

    try:
        start = start_location.resolve_start_location(
            manifest.start_method,
            total_samples=capacity.total_samples,
            lsb_depth=manifest.lsb_depth,
            envelope_length=embedded_length,
            secret=start_secret,
            manual_start_location=manifest.start_location,
            media_id=manifest.media_id,
            media_type=manifest.media_type,
            nonce_hex=manifest.nonce_hex,
        )
    except StartLocationError as exc:
        # The one case where the start location is provably unusable, as opposed to
        # merely wrong: the declared position does not fit this medium at all.
        return VerificationResult(
            verdict=verdicts.VERDICT_WRONG_START_LOCATION,
            reason=str(exc),
            start_location_valid=False,
            details={"stage": "start_location", "stego_file": name},
        )

    # --- 4. Extraction ---------------------------------------------------- #
    try:
        extracted = media.extract(
            stego_path,
            manifest.lsb_depth,
            start,
            manifest_payload_length=embedded_length,
        )
    except StegoError as exc:
        return VerificationResult(
            verdict=verdicts.VERDICT_PAYLOAD_MISSING,
            reason=f"no payload could be read: {exc}",
            payload_found=False,
            start_location_valid=True,
            start_location=start,
            notes=(constants.AMBIGUOUS_FAILURE_NOTICE,),
            details={"stage": "extraction", "stego_file": name},
        )

    # --- 4b. Remove the error-correcting code ----------------------------- #
    #
    # Before the signature check, because the code exists precisely to repair damage
    # that would otherwise make the signature fail. The correction report is carried
    # into the result so the repair can be seen rather than assumed.
    correction = None
    if error_correction.is_active(manifest.ecc):
        try:
            extracted, correction = error_correction.decode(extracted, manifest.ecc)
        except RedundancyError as exc:
            return VerificationResult(
                verdict=verdicts.VERDICT_CANNOT_VERIFY,
                reason=(
                    f"the payload could not be decoded with the recorded "
                    f"error-correcting code: {exc}"
                ),
                payload_found=True,
                start_location_valid=True,
                start_location=start,
                notes=(constants.AMBIGUOUS_FAILURE_NOTICE,),
                details={"stage": "error_correction", "stego_file": name},
            )

    result = verify_extracted_payload(
        extracted,
        key,
        manifest=manifest,
        passphrase=passphrase,
        start_location_used=start,
        correction=correction,
    )
    _log.info(
        "verified %s: %s (%s)", name, result.verdict, result.reason
    )
    return result


def verify_extracted_payload(
    extracted: bytes,
    public_key: Any,
    *,
    manifest: manifest_module.Manifest | None = None,
    passphrase: str | bytes | None = None,
    start_location_used: int | None = None,
    correction: error_correction.CorrectionReport | None = None,
) -> VerificationResult:
    """Verify already-extracted payload bytes.

    Separated from :func:`verify_media` so the attack simulator and the tests can
    exercise the cryptographic half without going through a medium, and so the
    steps after extraction are testable in isolation.

    *extracted* must already have had any error-correcting code removed. Pass the
    resulting *correction* report so it can be carried into the result.
    """
    key = _resolve_public_key(public_key)
    shared = {
        "payload_found": True,
        "start_location_valid": True,
        "start_location": start_location_used,
    }
    correction_details = (
        {} if correction is None else {"error_correction": correction.as_dict()}
    )

    # --- 5. Envelope structure -------------------------------------------- #
    try:
        parsed = envelope_module.parse_envelope(extracted)
    except EnvelopeError as exc:
        # A wrong magic is the informative case: these bytes are not an envelope.
        # It still cannot say why, so the note travels with the verdict.
        return VerificationResult(
            verdict=verdicts.VERDICT_PAYLOAD_MISSING,
            reason=str(exc),
            payload_found=False,
            start_location_valid=True,
            start_location=start_location_used,
            notes=(constants.AMBIGUOUS_FAILURE_NOTICE,),
            details={"stage": "envelope"},
        )
    except RecordError as exc:
        # The framing was valid but the record was not decodable. Something is
        # there; it cannot be read.
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=f"a payload envelope was found but its record is malformed: {exc}",
            notes=(constants.AMBIGUOUS_FAILURE_NOTICE,),
            details={"stage": "record"},
            **shared,
        )

    # --- 6. The signature: the trust boundary ----------------------------- #
    if not signatures.verify_envelope_signature(parsed, key):
        return VerificationResult(
            verdict=verdicts.VERDICT_SIGNATURE_INVALID,
            reason=(
                "the payload signature did not verify against the supplied public "
                "key. Either the key is not the sender's, or the signed bytes were "
                "modified"
            ),
            signature_valid=False,
            details={"stage": "signature"},
            **shared,
        )

    # --- 7. The record, now safe to interpret ----------------------------- #
    try:
        record = envelope_module.VerificationRecord.from_dict(parsed.record)
    except RecordError as exc:
        # Unusual: correctly signed but not a record this build understands, which
        # is what a future format version looks like.
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=(
                f"the signature verified but the record could not be interpreted: "
                f"{exc}"
            ),
            signature_valid=True,
            details={"stage": "record"},
            **shared,
        )

    # --- 8 and 9. Decrypt, then compare digests --------------------------- #
    try:
        recovered = payload_module.recover_message(
            parsed, record, passphrase=passphrase
        )
    except EncryptionError as exc:
        # The signature already established that the ciphertext is the sender's, so
        # this points at the passphrase. It is still not provable which of a wrong
        # passphrase or a modified-then-resigned message applies, so the reason
        # states the situation rather than a conclusion.
        return VerificationResult(
            verdict=verdicts.VERDICT_CANNOT_VERIFY,
            reason=(
                f"the signature verified, so the record is genuine, but the message "
                f"could not be decrypted: {exc}"
            ),
            signature_valid=True,
            record=record,
            details={"stage": "decryption"},
            **shared,
        )

    if not recovered.hash_matches:
        return VerificationResult(
            verdict=verdicts.VERDICT_TAMPERED,
            reason=(
                "the signature verified, so the record is genuine, but the "
                "recovered message does not match the digest that was signed"
            ),
            signature_valid=True,
            hash_valid=False,
            record=record,
            details={"stage": "message_hash"},
            **shared,
        )

    # --- 10. The manifest against the signed record ----------------------- #
    mismatched: tuple[str, ...] = ()
    if manifest is not None:
        expected_length = envelope_module.envelope_length_for(
            len(parsed.record_bytes), len(parsed.message), len(parsed.signature)
        )
        mismatched = manifest_module.cross_check(
            manifest, record, envelope_length=expected_length
        )
        if mismatched:
            return VerificationResult(
                verdict=verdicts.VERDICT_TAMPERED,
                reason=(
                    f"the signature verified and the message is intact, but the "
                    f"companion manifest disagrees with the signed record on: "
                    f"{', '.join(mismatched)}"
                ),
                signature_valid=True,
                hash_valid=True,
                manifest_consistent=False,
                mismatched_fields=mismatched,
                record=record,
                message=recovered.message,
                details={"stage": "manifest_cross_check"},
                **shared,
            )

    notes = [constants.AUTHENTIC_SCOPE_NOTICE, constants.EXTRACTED_CONTENT_NOTICE]
    if record.start_method == constants.START_METHOD_HMAC:
        notes.append(constants.START_LOCATION_NOTICE)
    if correction is not None and correction.any_corrections:
        # Worth stating on a success: the payload arrived damaged and the code
        # repaired it, which is a materially different outcome from arriving intact.
        notes.append(correction.summary())

    return VerificationResult(
        verdict=verdicts.VERDICT_AUTHENTIC,
        reason=(
            f"the signature verified against the supplied public key and the "
            f"recovered {record.message_length}-byte message matches the digest "
            f"that was signed"
        ),
        signature_valid=True,
        hash_valid=True,
        manifest_consistent=True if manifest is not None else None,
        record=record,
        message=recovered.message,
        notes=tuple(notes),
        details={
            "stage": "complete",
            "was_encrypted": recovered.was_encrypted,
            "envelope_length": parsed.total_length,
            **correction_details,
        },
        **shared,
    )
