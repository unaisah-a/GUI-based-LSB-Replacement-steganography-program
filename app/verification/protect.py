"""The sender side: sign a message, hide it in a cover object, publish a manifest.

Why this lives beside the verifier
----------------------------------
Protecting and verifying are two halves of one workflow, and the halves have to
agree about the order of operations, which parameters are signed, and which are
published. Keeping them in the same package means a change to one is read next to
the other. :mod:`app.verification.verifier` implements the receiver half; this is
the sender half.

Neither half implements cryptography or bit manipulation. Both orchestrate.

The order of operations, and why it is forced
---------------------------------------------
::

    1. detect the cover's media type            (content, not extension)
    2. build and sign the payload envelope      -> envelope_length becomes known
    3. measure the cover's capacity             -> total_samples becomes known
    4. check the envelope fits                  (input validation, before any write)
    5. resolve the start location               (needs 2 and 3)
    6. embed
    6b. optionally match the cover's file size  (PNG only, and only if asked)
    7. write the companion manifest

Step 6b sits where it does for one reason: the manifest records a digest of the
stego file, so anything that rewrites that file has to happen *before* the manifest
is written. Doing it afterwards would leave a manifest describing a file that no
longer exists, which is exactly the kind of quiet inconsistency a receiver would hit
much later and be unable to explain.

Step 2 has to precede step 5 because a derived start location depends on the
envelope length, and step 5 has to precede step 6 for obvious reasons. That is
also why a *derived* start location is not part of the signed record: it does not
exist yet when the record is signed. A *manual* start location is chosen by the
user up front, so it is signed. See
:class:`app.crypto.envelope.VerificationRecord`.

Step 4 exists so that an oversized message is refused as input validation with a
message saying how much would fit, rather than surfacing later as "no start
location fits", which is true but unhelpful.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from app.crypto import manifest as manifest_module
from app.crypto import payload as payload_module
from app.crypto import signatures, start_location
from app.crypto.envelope import ErrorCorrectionParameters, VerificationRecord
from app.crypto.errors import StartLocationError
from app.robustness import error_correction
from app.stego import media
from app.stego.errors import CapacityError
from app.utils import constants, file_utils
from app.utils.logging_utils import get_logger

__all__ = ["ProtectResult", "protect_media"]

_log = get_logger(__name__)


@dataclass(frozen=True)
class ProtectResult:
    """Everything a protect operation produced.

    The two paths are what party A sends to party B. Both are needed: the manifest
    carries the non-secret parameters without which the payload cannot be located.
    """

    stego_path: str
    manifest_path: str
    manifest: manifest_module.Manifest
    record: VerificationRecord
    embed_result: media.UnifiedEmbedResult
    envelope_length: int
    #: Bytes actually written into the cover. Larger than :attr:`envelope_length` when
    #: an error-correcting code was applied; equal to it otherwise.
    embedded_length: int
    message_length: int
    encrypted: bool
    start_location: int
    #: Secrets the receiver needs, and the channel they must arrive by. Reported so
    #: a caller can tell the user what still has to be shared, rather than leaving
    #: them to discover it when verification fails.
    required_secrets: tuple[str, ...] = ()
    #: Present when file-size matching was requested. Carries the outcome, including
    #: a failure, because whether it worked depends on the individual file and the
    #: caller should be told rather than left to compare sizes itself.
    size_preservation: Any = None

    @property
    def media_type(self) -> str:
        return self.embed_result.media_type

    @property
    def container_format(self) -> str:
        return self.embed_result.container_format


def protect_media(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    message: bytes,
    private_key: Any,
    *,
    media_id: str,
    lsb_depth: int,
    start_method: str = constants.START_METHOD_HMAC,
    start_secret: str | bytes | None = None,
    manual_start_location: int | None = None,
    passphrase: str | bytes | None = None,
    ecc: ErrorCorrectionParameters | None = None,
    metadata: Mapping[str, Any] | None = None,
    manifest_path: str | os.PathLike[str] | None = None,
    match_cover_size: bool = False,
    overwrite: bool = False,
    scrypt_n: int = constants.SCRYPT_N,
    scrypt_r: int = constants.SCRYPT_R,
    scrypt_p: int = constants.SCRYPT_P,
) -> ProtectResult:
    """Protect *message* inside the cover at *input_path*.

    :param start_method: ``"hmac_prf"`` derives the location from *start_secret*;
        ``"manual"`` uses *manual_start_location* and signs it.
    :param passphrase: when supplied, the message is encrypted before signing.
    :param match_cover_size: try to make the stego file exactly the cover's size.
        Only meaningful for PNG, where compression makes the size move; WAV and BMP
        already preserve it and video is a full re-encode, so for those this is
        recorded as "not applicable" and nothing is done. Whether it succeeds depends
        on the individual file, so the outcome is reported in
        :attr:`ProtectResult.size_preservation` rather than promised. See
        :mod:`app.analysis.size_preservation`.
    :raises app.stego.errors.CapacityError: the payload does not fit. Raised before
        anything is written.
    :raises app.stego.errors.StegoError: the cover is unreadable or unsupported, or
        an argument fails validation.
    :raises app.crypto.errors.CryptoError: an argument fails a cryptographic
        validation, or a required secret is missing.
    """
    # 1. What kind of cover is this? Detected from content.
    media_type = media.detect_media_type(input_path)

    # 2. Build and sign the payload. Media-free, so this can happen first.
    prepared = payload_module.prepare_payload(
        message,
        private_key,
        media_id=media_id,
        media_type=media_type,
        lsb_depth=lsb_depth,
        start_method=start_method,
        start_location=(
            manual_start_location
            if start_method == constants.START_METHOD_MANUAL
            else None
        ),
        passphrase=passphrase,
        ecc=ecc,
        metadata=metadata,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )

    # 2b. Apply the error-correcting code, if one was requested.
    #
    # Applied to the whole signed envelope, so the record, the message and the
    # signature are all protected. The embedded payload is therefore larger than the
    # envelope, and it is the *embedded* length that drives capacity and the start
    # location. The manifest keeps recording the envelope's own length, with the code's
    # parameters beside it, so a receiver can compute the embedded length the same way.
    embedded_payload = error_correction.encode(prepared.envelope, ecc)
    embedded_length = len(embedded_payload)

    # 3. Measure the cover.
    capacity = media.measure(
        input_path, lsb_depth, payload_length=embedded_length
    )

    # 4. Refuse an oversized payload here, with a figure the user can act on.
    if not capacity.payload_fits:
        overhead = prepared.envelope_length - prepared.message_length
        fits = max(
            0,
            error_correction.largest_raw_payload(
                capacity.max_payload_length, ecc
            )
            - overhead,
        )
        coding = ""
        if error_correction.is_active(ecc):
            coding = (
                f", multiplied to {embedded_length} bytes by {ecc.scheme} coding at "
                f"factor {ecc.factor}"
            )
        raise CapacityError(
            f"the message does not fit: a {prepared.message_length}-byte message "
            f"becomes a {prepared.envelope_length}-byte signed payload{coding}, but "
            f"{file_utils.display_name(input_path)} holds at most "
            f"{capacity.max_payload_length} bytes at depth {lsb_depth}. The largest "
            f"message that fits at this depth is about {fits} bytes; a greater depth "
            f"or a larger cover would raise that"
        )

    # 5. Resolve where the payload goes, using the length actually embedded.
    start = start_location.resolve_start_location(
        start_method,
        total_samples=capacity.total_samples,
        lsb_depth=lsb_depth,
        envelope_length=embedded_length,
        secret=start_secret,
        manual_start_location=manual_start_location,
        media_id=media_id,
        media_type=media_type,
        nonce_hex=prepared.record.nonce_hex,
    )

    # 6. Embed.
    embed_result = media.embed(
        input_path,
        output_path,
        embedded_payload,
        lsb_depth,
        start,
        overwrite=overwrite,
    )

    # 6b. Optionally rewrite the stego file at the cover's exact size.
    #
    # Before the manifest, because the manifest records the file's digest. The pixels
    # are unchanged by this, so the payload still extracts and the signature still
    # covers the same bytes; only the container's compression and padding differ.
    size_result = None
    if match_cover_size:
        size_result = _match_cover_size(input_path, embed_result.output_path)

    # 7. Publish the non-secret parameters.
    manifest = manifest_module.Manifest.from_record(
        prepared.record,
        envelope_length=prepared.envelope_length,
        container_format=embed_result.container_format,
        resolved_start_location=start,
        stego_file_name=file_utils.display_name(embed_result.output_path),
        stego_sha256=file_utils.file_sha256(embed_result.output_path),
    )
    written_manifest_path = manifest_module.write_manifest(
        manifest,
        manifest_path,
        stego_path=None if manifest_path is not None else embed_result.output_path,
        overwrite=overwrite,
    )

    secrets: list[str] = []
    if start_method == constants.START_METHOD_HMAC:
        secrets.append("start-location secret")
    if prepared.encrypted:
        secrets.append("message passphrase")

    _log.info(
        "protected %s as %s (%s media, depth %d, start %d, %d-byte envelope, "
        "%d bytes embedded)",
        file_utils.display_name(input_path),
        file_utils.display_name(embed_result.output_path),
        media_type,
        lsb_depth,
        start,
        prepared.envelope_length,
        embedded_length,
    )

    return ProtectResult(
        stego_path=embed_result.output_path,
        manifest_path=written_manifest_path,
        manifest=manifest,
        record=prepared.record,
        embed_result=embed_result,
        envelope_length=prepared.envelope_length,
        embedded_length=embedded_length,
        message_length=prepared.message_length,
        encrypted=prepared.encrypted,
        start_location=start,
        required_secrets=tuple(secrets),
        size_preservation=size_result,
    )


def _match_cover_size(
    cover_path: str | os.PathLike[str], stego_path: str
) -> Any:
    """Rewrite *stego_path* at the cover's exact size where the container allows it.

    Returns a :class:`app.analysis.size_preservation.SizeResult` describing what
    happened, including the cases where nothing was done. A failure to match is a
    result, not an error: it depends on how the individual image compressed, and
    refusing to protect a file over it would be absurd.
    """
    from app.analysis import size_preservation

    if media.detect_media_type(stego_path) != constants.MEDIA_IMAGE:
        return size_preservation.size_outcome(cover_path, stego_path)

    container = file_utils.describe_file(stego_path).container_format
    if container != constants.CONTAINER_PNG:
        # BMP already preserves the size, so there is nothing to attempt.
        return size_preservation.size_outcome(cover_path, stego_path)

    return size_preservation.preserve_png_size(
        cover_path, stego_path, stego_path, overwrite=True
    )
