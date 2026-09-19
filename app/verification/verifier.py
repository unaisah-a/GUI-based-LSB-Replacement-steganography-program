"""End-to-end extraction, signature, manifest and message verification."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa

from app.crypto.key_manager import public_key_fingerprint
from app.crypto.manifest import Manifest, ManifestError, load_manifest
from app.crypto.payload import (
    MAX_SIGNATURE_BYTES,
    PayloadFormatError,
    message_hash_is_valid,
    parse_envelope,
    recover_message,
    verify_envelope_signature,
)
from app.crypto.start_location import derive_start_location
from app.services.media import inspect_carrier
from app.robustness.redundancy import decode_repetition3
from app.stego.audio_stego import extract_audio_lsb, extract_audio_lsb_bounded
from app.stego.image_stego import extract_image, extract_image_bounded
from app.stego.video_stego import extract_video, extract_video_bounded
from app.verification.verdicts import ResultBuilder, Verdict, VerificationResult


def resolve_start_location(
    media_path: str | Path,
    manifest: Manifest,
    start_secret: str | bytes | None,
) -> tuple[int, object]:
    carrier = inspect_carrier(
        media_path,
        manifest.media_type,
        video_frame_index=manifest.video_frame_index or 0,
    )
    required = carrier.required_samples(
        manifest.embedded_payload_length, manifest.lsb_count
    )
    if required > carrier.total_samples:
        raise ValueError(
            f"manifest payload needs {required} samples but the carrier has "
            f"{carrier.total_samples}"
        )
    if manifest.start_method == "manual":
        assert manifest.start_location is not None
        start = manifest.start_location
    else:
        if start_secret is None:
            raise ValueError("a start-location secret is required")
        start = derive_start_location(
            start_secret,
            total_samples=carrier.total_samples,
            required_samples=required,
            media_type=manifest.media_type,
            media_id=manifest.media_id,
            nonce=manifest.nonce,
            lsb_count=manifest.lsb_count,
        )
    if start + required > carrier.total_samples:
        raise ValueError("resolved start location leaves insufficient capacity")
    return start, carrier


def _extract(media_path: str | Path, manifest: Manifest, start: int) -> bytes:
    if manifest.robustness == "repetition-3":
        if manifest.media_type == "image":
            return extract_image_bounded(
                str(media_path),
                manifest.lsb_count,
                start,
                manifest.embedded_payload_length,
            )
        if manifest.media_type == "audio":
            return extract_audio_lsb_bounded(
                str(media_path),
                manifest.embedded_payload_length,
                lsb_count=manifest.lsb_count,
                start_location=start,
            )
        if manifest.media_type == "video":
            assert manifest.video_frame_index is not None
            return extract_video_bounded(
                str(media_path),
                manifest.embedded_payload_length,
                lsb_count=manifest.lsb_count,
                start_location=start,
                frame_index=manifest.video_frame_index,
            )
    if manifest.media_type == "image":
        return extract_image(
            str(media_path),
            manifest.lsb_count,
            start,
            manifest_payload_length=manifest.embedded_payload_length,
        )
    if manifest.media_type == "audio":
        return extract_audio_lsb(
            str(media_path),
            lsb_count=manifest.lsb_count,
            start_location=start,
            manifest_payload_length=manifest.embedded_payload_length,
        )
    if manifest.media_type == "video":
        assert manifest.video_frame_index is not None
        return extract_video(
            str(media_path),
            lsb_count=manifest.lsb_count,
            start_location=start,
            frame_index=manifest.video_frame_index,
            manifest_payload_length=manifest.embedded_payload_length,
        )
    raise ValueError("unsupported media type")


def _manifest_mismatches(manifest: Manifest, record: dict) -> list[str]:
    mismatches: list[str] = []
    extraction = record.get("extraction")
    if not isinstance(extraction, dict):
        return ["signed extraction settings are missing"]
    comparisons = {
        "media ID": (record.get("media_id"), manifest.media_id),
        "nonce": (record.get("nonce"), manifest.nonce),
        "media type": (extraction.get("media_type"), manifest.media_type),
        "LSB depth": (extraction.get("lsb_count"), manifest.lsb_count),
        "start method": (extraction.get("start_method"), manifest.start_method),
        "payload length": (extraction.get("payload_length"), manifest.payload_length),
        "robustness": (extraction.get("robustness"), manifest.robustness),
        "public-key fingerprint": (
            record.get("public_key_fingerprint"),
            manifest.public_key_fingerprint,
        ),
    }
    if manifest.start_method == "manual":
        comparisons["start location"] = (
            extraction.get("start_location"),
            manifest.start_location,
        )
    if manifest.media_type == "video":
        comparisons["video frame index"] = (
            extraction.get("video_frame_index"),
            manifest.video_frame_index,
        )
    for label, (signed_value, manifest_value) in comparisons.items():
        if signed_value != manifest_value:
            mismatches.append(label)
    return mismatches


def verify_media(
    media_path: str | Path,
    manifest_path: str | Path,
    public_key,
    *,
    start_secret: str | bytes | None = None,
    encryption_key: bytes | None = None,
) -> VerificationResult:
    """Verify a protected file and return a user-facing structured result."""
    result = ResultBuilder()
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        result.add("Manifest", False, str(exc))
        return result.result(Verdict.CANNOT_VERIFY, "The manifest could not be validated.")
    result.add("Manifest", True, "The companion manifest is well formed.")

    if not isinstance(public_key, rsa.RSAPublicKey):
        result.add("Trusted key", False, "The supplied key is not an RSA public key.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "A supported RSA public key is required for verification.",
        )
    if (
        public_key.key_size < 2048
        or (public_key.key_size + 7) // 8 > MAX_SIGNATURE_BYTES
    ):
        result.add("Trusted key", False, "The RSA public-key size is unsupported.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "The trusted public key is outside the supported size range.",
        )
    result.add("Trusted key", True, f"Loaded a {public_key.key_size}-bit RSA public key.")

    try:
        start, _carrier = resolve_start_location(media_path, manifest, start_secret)
    except Exception as exc:
        result.add("Start location", False, str(exc))
        result.not_run("Extraction", "No extraction location was available.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "The payload location could not be resolved.",
        )
    result.add(
        "Start location",
        True,
        f"Resolved sample index {start} using {manifest.start_method}.",
    )

    try:
        extracted = _extract(media_path, manifest, start)
    except Exception as exc:
        result.add("Extraction", False, str(exc))
        result.not_run("Signature", "No parseable payload was extracted.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "Extraction failed; the exact cause cannot be determined from the bit stream.",
            start_location=start,
        )
    extraction_detail = f"Extracted {len(extracted)} payload bytes."
    if manifest.robustness == "repetition-3":
        extraction_detail += (
            " Used the bounded manifest length; carrier header values remain untrusted."
        )
    result.add("Extraction", True, extraction_detail)

    if manifest.robustness == "repetition-3":
        try:
            extracted = decode_repetition3(extracted, manifest.payload_length)
        except ValueError as exc:
            result.add("Robust decoding", False, str(exc))
            return result.result(
                Verdict.CANNOT_VERIFY,
                "The redundant payload could not be decoded.",
                start_location=start,
            )
        result.add(
            "Robust decoding",
            True,
            "Applied bitwise majority voting to three stored copies.",
        )

    try:
        envelope = parse_envelope(extracted)
    except PayloadFormatError as exc:
        result.add("Payload format", False, str(exc))
        result.not_run("Signature", "The payload framing was invalid.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "The extracted bytes are not a supported payload.",
            start_location=start,
        )
    result.add("Payload format", True, "The versioned payload envelope is valid.")

    signature_valid = verify_envelope_signature(envelope, public_key)
    result.add(
        "Signature",
        signature_valid,
        "RSA-PSS signature is valid."
        if signature_valid
        else "RSA-PSS signature verification failed.",
    )
    if not signature_valid:
        return result.result(
            Verdict.SIGNATURE_INVALID,
            "Signature verification failed: the payload may have been altered, "
            "or the supplied public key may not match the signer.",
            record=envelope.record,
            start_location=start,
        )

    actual_fingerprint = public_key_fingerprint(public_key)
    identity_valid = actual_fingerprint == envelope.record.get("public_key_fingerprint")
    result.add(
        "Signer identity",
        identity_valid,
        "The signed key fingerprint matches the trusted key."
        if identity_valid
        else "The signed key fingerprint does not match the trusted key.",
    )
    mismatches = _manifest_mismatches(manifest, envelope.record)
    manifest_valid = not mismatches
    result.add(
        "Signed extraction settings",
        manifest_valid,
        "Manifest settings match the signed record."
        if manifest_valid
        else "Manifest differs from signed fields: " + ", ".join(mismatches),
    )
    if not identity_valid or not manifest_valid:
        return result.result(
            Verdict.TAMPERED,
            "Signed metadata and supplied verification information disagree.",
            record=envelope.record,
            start_location=start,
        )

    try:
        message = recover_message(envelope, encryption_key)
    except InvalidTag:
        result.add("Decryption", False, "AES-GCM authentication failed.")
        return result.result(
            Verdict.CANNOT_VERIFY,
            "The encrypted message could not be opened with the supplied key.",
            record=envelope.record,
            start_location=start,
        )
    except (PayloadFormatError, ValueError) as exc:
        result.add("Decryption", False, str(exc))
        return result.result(
            Verdict.CANNOT_VERIFY,
            "The message could not be recovered.",
            record=envelope.record,
            start_location=start,
        )
    result.add(
        "Decryption",
        True,
        "AES-GCM message recovered." if envelope.encrypted else "Payload was not encrypted.",
    )

    hash_valid = message_hash_is_valid(envelope, message)
    result.add(
        "Message hash",
        hash_valid,
        "Recovered message matches the signed SHA-256 digest."
        if hash_valid
        else "Recovered message differs from the signed SHA-256 digest.",
    )
    if not hash_valid:
        return result.result(
            Verdict.TAMPERED,
            "The recovered message failed its signed integrity check.",
            message=message,
            content_type=str(envelope.record.get("content_type", "")),
            record=envelope.record,
            start_location=start,
        )

    return result.result(
        Verdict.AUTHENTIC,
        "Message and signed record verified.",
        message=message,
        content_type=str(envelope.record.get("content_type", "")),
        record=envelope.record,
        start_location=start,
    )
