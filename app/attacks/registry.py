"""The catalogue of available attacks, and a runner that reports before and after.

The Attack Lab tab lists what :func:`available_attacks` returns for the media type
in hand, runs the chosen one, and shows the verdict before and after. The tests use
the same catalogue, so an attack cannot be added to one and forgotten in the other.

Each entry adapts an :class:`~app.attacks.base.AttackContext` to the signature its
own function wants. That keeps the attack functions readable and directly callable,
while the runner sees one uniform interface — all the per-attack argument shuffling
is confined to this table.

The payload and manifest attacks apply to every medium, because they operate on the
envelope rather than on samples. Only the medium-specific ones are filtered, and the
inside/outside pair exists for all three media so the same lesson can be shown
wherever the demonstration happens to be.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from app.attacks import audio_attacks, image_attacks, payload_attacks, video_attacks
from app.attacks.base import Attack, AttackContext, AttackError, AttackOutcome
from app.utils import constants
from app.verification.verdicts import VerificationResult
from app.verification.verifier import verify_media

__all__ = [
    "ATTACKS",
    "AttackRun",
    "attack_by_key",
    "available_attacks",
    "context_from_protect_result",
    "run_attack",
]

IMAGE_ONLY: Final[frozenset[str]] = frozenset({constants.MEDIA_IMAGE})
AUDIO_ONLY: Final[frozenset[str]] = frozenset({constants.MEDIA_AUDIO})
VIDEO_ONLY: Final[frozenset[str]] = frozenset({constants.MEDIA_VIDEO})
ANY_MEDIA: Final[frozenset[str]] = frozenset()


def _payload_call(function):
    """Adapt a payload attack, which needs the depth and start location."""

    def invoke(context: AttackContext) -> AttackOutcome:
        return function(
            context.stego_path,
            context.output_path,
            context.lsb_depth,
            context.start_location,
            overwrite=context.overwrite,
            ecc=context.ecc,
            **context.options,
        )

    return invoke


def _region_call(function):
    """Adapt an attack that needs to know where the payload region lies."""

    def invoke(context: AttackContext) -> AttackOutcome:
        return function(
            context.stego_path,
            context.output_path,
            context.start_location,
            context.samples_written,
            overwrite=context.overwrite,
            **context.options,
        )

    return invoke


def _inside_call(function):
    """Adapt an inside-the-payload attack, which also needs to know about the code."""

    def invoke(context: AttackContext) -> AttackOutcome:
        return function(
            context.stego_path,
            context.output_path,
            context.start_location,
            context.samples_written,
            overwrite=context.overwrite,
            ecc=context.ecc,
            **context.options,
        )

    return invoke


def _simple_call(function):
    """Adapt an attack that needs only the file and its options."""

    def invoke(context: AttackContext) -> AttackOutcome:
        return function(
            context.stego_path,
            context.output_path,
            overwrite=context.overwrite,
            **context.options,
        )

    return invoke


def _resign_call(context: AttackContext) -> AttackOutcome:
    if context.attacker_private_key is None:
        raise AttackError(
            "the re-signing attack needs a private key the attacker controls; "
            "supply attacker_private_key"
        )
    return payload_attacks.resign_with_substituted_message(
        context.stego_path,
        context.output_path,
        context.lsb_depth,
        context.start_location,
        context.attacker_private_key,
        overwrite=context.overwrite,
        ecc=context.ecc,
        **context.options,
    )


def _manifest_call(context: AttackContext) -> AttackOutcome:
    return payload_attacks.tamper_with_manifest(
        context.manifest_path,
        context.output_path,
        overwrite=context.overwrite,
        **context.options,
    )


def _verification_only(context: AttackContext) -> AttackOutcome:
    return AttackOutcome(
        name="verification input substitution", output_path=context.stego_path,
        description="Reverify the original file with a substituted receiver input; no file written.",
        expected_verdicts=frozenset(), target="verification",
    )


ATTACKS: Final[tuple[Attack, ...]] = (
    Attack(
        key="verification.wrong_key", label="Verify with the wrong public key",
        media_types=ANY_MEDIA, invoke=_verification_only, target="verification",
        summary="Use a fresh unrelated public key. The original file is unchanged.",
    ),
    Attack(
        key="verification.wrong_start", label="Verify with the wrong start secret",
        media_types=ANY_MEDIA, invoke=_verification_only, target="verification",
        summary="Use a different HMAC start location. Requires a derived start; failure is not proof of tampering.",
    ),
    # --- payload-targeted, media-agnostic ---------------------------------- #
    Attack(
        key="payload.record",
        label="Corrupt the signed record",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_record_section),
        summary="Invert a byte of the verification record, which the signature covers.",
    ),
    Attack(
        key="payload.message",
        label="Corrupt the message",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_message_section),
        summary=(
            "Invert a byte of the message. The signature covers the message too, so "
            "this fails the signature check rather than the digest comparison."
        ),
    ),
    Attack(
        key="payload.signature",
        label="Corrupt the signature",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_signature_section),
        summary="Invert a byte of the signature.",
    ),
    Attack(
        key="payload.magic",
        label="Destroy the envelope marker",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_envelope_magic),
        summary="Make the payload unrecognisable as a payload.",
    ),
    Attack(
        key="payload.length_header",
        label="Corrupt the length header",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_length_header),
        summary=(
            "Invert the one sample carrying the low bits of the unsigned 4-byte "
            "length header. The only single-sample change that gives "
            "PAYLOAD_MISSING rather than SIGNATURE_INVALID."
        ),
    ),
    Attack(
        key="payload.truncate",
        label="Truncate the payload",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.truncate_envelope),
        summary="Cut the envelope short so its declared lengths overrun the buffer.",
    ),
    Attack(
        key="payload.random_bits",
        label="Flip random payload bits",
        media_types=ANY_MEDIA,
        invoke=_payload_call(payload_attacks.corrupt_random_payload_bits),
        summary=(
            "Flip a proportion of payload bits at random. This is the attack that "
            "repetition coding can recover from."
        ),
    ),
    Attack(
        key="payload.resign",
        label="Substitute the message and re-sign",
        media_types=ANY_MEDIA,
        invoke=_resign_call,
        summary=(
            "The only route to TAMPERED: needs a signing key the attacker controls, "
            "and fails against a receiver holding the sender's key."
        ),
    ),
    # --- manifest ----------------------------------------------------------- #
    Attack(
        key="manifest.tamper",
        label="Edit the companion manifest",
        media_types=ANY_MEDIA,
        invoke=_manifest_call,
        summary=(
            "Change a published parameter. The manifest is not signed, but every "
            "field it publishes is also inside the signed record."
        ),
        target="manifest",
    ),
    # --- image -------------------------------------------------------------- #
    Attack(
        key="image.inside",
        label="Modify pixels inside the payload",
        media_types=IMAGE_ONLY,
        invoke=_inside_call(image_attacks.modify_pixels_inside_payload),
        summary=(
            "Invert the last samples of the payload region, which carry the "
            "signature. The header still reads, so the signature check fails."
        ),
    ),
    Attack(
        key="image.outside",
        label="Modify pixels outside the payload",
        media_types=IMAGE_ONLY,
        invoke=_region_call(image_attacks.modify_pixels_outside_payload),
        summary=(
            "Invert samples past the payload. Verification still succeeds, which is "
            "the honest scope of what it establishes."
        ),
    ),
    Attack(
        key="image.blank",
        label="Blank a region",
        media_types=IMAGE_ONLY,
        invoke=_simple_call(image_attacks.blank_region),
        summary="Set a rectangle to black, as an image editor would.",
    ),
    Attack(
        key="image.lossy",
        label="Re-encode as lossy JPEG",
        media_types=IMAGE_ONLY,
        invoke=_simple_call(image_attacks.recompress_as_lossy),
        summary="Show that lossy compression destroys the payload.",
    ),
    # --- audio -------------------------------------------------------------- #
    Attack(
        key="audio.inside",
        label="Corrupt samples inside the payload",
        media_types=AUDIO_ONLY,
        invoke=_inside_call(audio_attacks.corrupt_samples_inside_payload),
        summary=(
            "Invert the low byte of the last samples of the payload region, which "
            "carry the signature. The signature check fails."
        ),
    ),
    Attack(
        key="audio.outside",
        label="Corrupt samples outside the payload",
        media_types=AUDIO_ONLY,
        invoke=_region_call(audio_attacks.corrupt_samples_outside_payload),
        summary=(
            "Invert the low byte of samples past the payload. Verification still "
            "succeeds."
        ),
    ),
    Attack(
        key="audio.amplitude",
        label="Scale the amplitude",
        media_types=AUDIO_ONLY,
        invoke=_simple_call(audio_attacks.scale_amplitude),
        summary="A volume adjustment. Destroys the payload completely.",
    ),
    Attack(
        key="audio.resample",
        label="Resample",
        media_types=AUDIO_ONLY,
        invoke=_simple_call(audio_attacks.resample),
        summary="Change the sample rate. Destroys the payload completely.",
    ),
    Attack(
        key="audio.truncate",
        label="Truncate the recording",
        media_types=AUDIO_ONLY,
        invoke=_simple_call(audio_attacks.truncate_audio),
        summary="Cut the recording short.",
    ),
    # --- video -------------------------------------------------------------- #
    Attack(
        key="video.inside",
        label="Corrupt samples inside the payload",
        media_types=VIDEO_ONLY,
        invoke=_inside_call(video_attacks.corrupt_samples_inside_payload),
        summary=(
            "Invert the last samples of the payload region, which carry the "
            "signature. The signature check fails."
        ),
    ),
    Attack(
        key="video.outside",
        label="Corrupt samples outside the payload",
        media_types=VIDEO_ONLY,
        invoke=_region_call(video_attacks.corrupt_samples_outside_payload),
        summary=(
            "Invert samples past the payload. Verification still succeeds, even "
            "though the clip has visibly changed."
        ),
    ),
    Attack(
        key="video.drop_frames",
        label="Drop frames",
        media_types=VIDEO_ONLY,
        invoke=_simple_call(video_attacks.drop_frames),
        summary=(
            "Trim frames from the start. The payload is still in the file but the "
            "sample domain and every position have shifted."
        ),
    ),
    Attack(
        key="video.lossy",
        label="Re-encode with a lossy codec",
        media_types=VIDEO_ONLY,
        invoke=_simple_call(video_attacks.recompress_lossy),
        summary=(
            "What an upload or an edit does by default. Destroys the payload "
            "completely."
        ),
    ),
)


def available_attacks(media_type: str) -> tuple[Attack, ...]:
    """Return the attacks that apply to *media_type*."""
    return tuple(attack for attack in ATTACKS if attack.applies_to(media_type))


def attack_by_key(key: str) -> Attack:
    """Return the attack with the given key."""
    for attack in ATTACKS:
        if attack.key == key:
            return attack
    raise AttackError(
        f"unknown attack {key!r}; available keys are "
        f"{sorted(item.key for item in ATTACKS)}"
    )


def context_from_protect_result(
    result: Any,
    output_path: str,
    *,
    overwrite: bool = False,
    attacker_private_key: Any = None,
    **options: Any,
) -> AttackContext:
    """Build a context from an :class:`app.verification.protect.ProtectResult`.

    Saves every caller from unpacking the same five fields, and keeps the GUI and
    the tests building contexts the same way.
    """
    return AttackContext(
        stego_path=result.stego_path,
        manifest_path=result.manifest_path,
        output_path=output_path,
        lsb_depth=result.record.lsb_depth,
        start_location=result.start_location,
        samples_written=result.embed_result.samples_written,
        overwrite=overwrite,
        attacker_private_key=attacker_private_key,
        ecc=result.record.ecc,
        options=options,
    )


def context_from_manifest(
    stego_path: str,
    manifest_path: str,
    output_path: str,
    *,
    start_secret: str | bytes | None = None,
    overwrite: bool = False,
    attacker_private_key: Any = None,
    **options: Any,
) -> AttackContext:
    """Build a context from a received file and its manifest.

    This is the case an attacker, or the Attack Lab, actually faces: there is no
    ``ProtectResult`` because the protecting happened elsewhere. Everything the
    payload attacks need is recoverable from the manifest plus the medium — which is
    the point of publishing those parameters — except a derived start location, which
    also needs the shared secret.

    :raises AttackError: the manifest is unusable, the medium cannot be measured, or
        a derived start location was requested without the secret.
    """
    from app.crypto import manifest as manifest_module
    from app.crypto import start_location as start_location_module
    from app.crypto.errors import CryptoError
    from app.stego import media
    from app.stego.errors import StegoError

    try:
        manifest = manifest_module.read_manifest(manifest_path)
    except CryptoError as exc:
        raise AttackError(f"the manifest could not be used: {exc}") from exc

    try:
        capacity = media.measure(stego_path, manifest.lsb_depth)
    except StegoError as exc:
        raise AttackError(f"the file could not be measured: {exc}") from exc

    if (
        manifest.start_method == constants.START_METHOD_HMAC
        and start_secret is None
    ):
        raise AttackError(
            "this file uses a derived start location, so the start-location secret "
            "is needed to locate its payload before it can be attacked"
        )

    # What sits on the medium is the envelope after any error-correcting code, and it
    # is that length the derivation and the region extent are both measured in.
    from app.robustness import error_correction

    embedded_length = error_correction.encoded_length(
        manifest.envelope_length, manifest.ecc
    )

    try:
        start = start_location_module.resolve_start_location(
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
    except CryptoError as exc:
        raise AttackError(f"the start location could not be resolved: {exc}") from exc

    return AttackContext(
        stego_path=stego_path,
        manifest_path=manifest_path,
        output_path=output_path,
        lsb_depth=manifest.lsb_depth,
        start_location=start,
        samples_written=start_location_module.required_sample_count(
            embedded_length, manifest.lsb_depth
        ),
        overwrite=overwrite,
        attacker_private_key=attacker_private_key,
        ecc=manifest.ecc,
        options=options,
    )


@dataclass(frozen=True)
class AttackRun:
    """An attack applied to a protected file, with the verdict before and after."""

    attack: Attack
    outcome: AttackOutcome
    before: VerificationResult
    after: VerificationResult

    @property
    def verdict_changed(self) -> bool:
        return self.before.verdict != self.after.verdict

    @property
    def matched_expectation(self) -> bool:
        """Whether the observed verdict is one the attack said to expect."""
        return self.after.verdict in self.outcome.expected_verdicts

    def as_dict(self) -> dict[str, Any]:
        return {
            "attack": self.attack.key,
            "label": self.attack.label,
            "target": self.attack.target,
            "outcome": self.outcome.as_dict(),
            "verdict_before": self.before.verdict,
            "verdict_after": self.after.verdict,
            "verdict_changed": self.verdict_changed,
            "matched_expectation": self.matched_expectation,
            "reason_after": self.after.reason,
        }

    def as_text(self) -> str:
        return (
            f"{self.attack.label}\n"
            f"  {self.outcome.description}\n"
            f"  before: {self.before.verdict}\n"
            f"  after:  {self.after.verdict} ({self.after.reason})"
        )


def run_attack(
    key: str,
    context: AttackContext,
    public_key: Any,
    *,
    start_secret: str | bytes | None = None,
    passphrase: str | bytes | None = None,
) -> AttackRun:
    """Apply an attack and verify the file before and after.

    For a media attack the modified cover is verified against the original
    manifest. For a manifest attack the original cover is verified against the
    modified manifest. Getting that pairing right is the reason
    :attr:`app.attacks.base.Attack.target` exists.

    :raises AttackError: the attack cannot be carried out on this file.
    """
    attack = attack_by_key(key)

    before = verify_media(
        context.stego_path,
        context.manifest_path,
        public_key,
        start_secret=start_secret,
        passphrase=passphrase,
    )

    if attack.target == "verification":
        from dataclasses import replace

        from app.crypto import key_manager
        from app.crypto import manifest as manifest_module

        if before.verdict != constants.VERDICT_AUTHENTIC:
            raise AttackError("verify successfully with the original inputs before substituting an input")
        after_key, after_secret = public_key, start_secret
        if key == "verification.wrong_key":
            _, after_key = key_manager.generate_key_pair(constants.RSA_MIN_KEY_SIZE)
            expected = frozenset({constants.VERDICT_SIGNATURE_INVALID})
            description = "Used an unrelated public key; no file written."
        else:
            manifest = manifest_module.read_manifest(context.manifest_path)
            if manifest.start_method != constants.START_METHOD_HMAC:
                raise AttackError("wrong-secret demonstration requires an HMAC-derived start")
            # A different secret can collide in the finite location space. Ensure
            # the demonstration actually uses another location, or report failure.
            for attempt in range(64):
                candidate = f"attack-lab-wrong-start-{attempt}"
                other = context_from_manifest(
                    context.stego_path, context.manifest_path, context.output_path,
                    start_secret=candidate,
                )
                if other.start_location != context.start_location:
                    after_secret = candidate
                    break
            else:
                raise AttackError("could not find a different derived location in 64 attempts")
            expected = frozenset({constants.VERDICT_PAYLOAD_MISSING,
                                  constants.VERDICT_CANNOT_VERIFY,
                                  constants.VERDICT_SIGNATURE_INVALID})
            description = ("Used a different derived start location; no file written. "
                           "Wrong secrets, absent payloads and damaged framing can look alike.")
        outcome = replace(attack.invoke(context), description=description,
                          expected_verdicts=expected)
        after = verify_media(context.stego_path, context.manifest_path, after_key,
                             start_secret=after_secret, passphrase=passphrase)
        return AttackRun(attack, outcome, before, after)

    outcome = attack.invoke(context)

    if attack.target == "manifest":
        after_stego, after_manifest = context.stego_path, outcome.output_path
    else:
        after_stego, after_manifest = outcome.output_path, context.manifest_path

    after = verify_media(
        after_stego,
        after_manifest,
        public_key,
        start_secret=start_secret,
        passphrase=passphrase,
    )

    return AttackRun(attack=attack, outcome=outcome, before=before, after=after)
