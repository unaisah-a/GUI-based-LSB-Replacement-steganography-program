"""Verification verdicts and the result they travel in.

The six verdicts come from :mod:`app.utils.constants` rather than being restated
here, so the GUI can render the vocabulary without importing this layer and the
two can never drift apart.

On being honest about what a verdict means
------------------------------------------
Two rules govern how verdicts are assigned, and both exist because the tempting
alternative would overstate what the system knows.

**``AUTHENTIC`` is about the message, not the whole file.** It means the signature
over the verification record verified against the supplied public key, and the
recovered message's digest matches the digest that was signed. It does *not* mean
every part of the cover media is unchanged: a change outside the embedded region
leaves the payload intact and still verifies. It also does not reject a replayed
file, because a timestamp and a nonce alone cannot. :data:`VerificationResult.notes`
carries that caveat on every successful verification.

**``WRONG_START_LOCATION`` is used only when that is actually knowable.** A wrong
LSB depth, a wrong secret, an absent payload and sample corruption all produce
bit streams that are indistinguishable from one another, so guessing between them
would be inventing information. This verdict is reserved for the one case that can
be established without ambiguity: a manifest that declares a start location the
medium cannot accommodate, which is caught before extraction is attempted.
Everything genuinely ambiguous is ``CANNOT_VERIFY`` with the reason stated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from app.crypto.envelope import VerificationRecord
from app.utils import constants

__all__ = [
    "VERDICTS",
    "VERDICT_AUTHENTIC",
    "VERDICT_CANNOT_VERIFY",
    "VERDICT_PAYLOAD_MISSING",
    "VERDICT_SIGNATURE_INVALID",
    "VERDICT_TAMPERED",
    "VERDICT_WRONG_START_LOCATION",
    "VERDICT_DESCRIPTIONS",
    "VerificationResult",
    "is_success",
]

VERDICT_AUTHENTIC: Final[str] = constants.VERDICT_AUTHENTIC
VERDICT_TAMPERED: Final[str] = constants.VERDICT_TAMPERED
VERDICT_SIGNATURE_INVALID: Final[str] = constants.VERDICT_SIGNATURE_INVALID
VERDICT_PAYLOAD_MISSING: Final[str] = constants.VERDICT_PAYLOAD_MISSING
VERDICT_WRONG_START_LOCATION: Final[str] = constants.VERDICT_WRONG_START_LOCATION
VERDICT_CANNOT_VERIFY: Final[str] = constants.VERDICT_CANNOT_VERIFY

VERDICTS: Final[tuple[str, ...]] = constants.VERDICTS

#: One-line explanations, shown beside the verdict in the GUI. Written to be read
#: by someone who has not read the code.
VERDICT_DESCRIPTIONS: Final[dict[str, str]] = {
    VERDICT_AUTHENTIC: (
        "The signature verified against the supplied public key and the recovered "
        "message matches the digest that was signed."
    ),
    VERDICT_TAMPERED: (
        "The signature verified, so the record is genuine, but the recovered "
        "message does not match the digest it was signed with, or the published "
        "parameters disagree with the signed ones."
    ),
    VERDICT_SIGNATURE_INVALID: (
        "A payload was found and read, but its signature did not verify against "
        "the supplied public key. Either the key is not the sender's, or the "
        "signed bytes were modified."
    ),
    VERDICT_PAYLOAD_MISSING: (
        "No payload envelope was found at the location and settings given. This is "
        "equally consistent with an unprotected file, incorrect settings, an "
        "incorrect secret, and modified media."
    ),
    VERDICT_WRONG_START_LOCATION: (
        "The start location the manifest declares cannot be used with this file: it "
        "lies outside the medium, or leaves too little room for the payload."
    ),
    VERDICT_CANNOT_VERIFY: (
        "Verification could not be completed, and the cause cannot be determined "
        "from the evidence available."
    ),
}


def is_success(verdict: str) -> bool:
    """Return whether *verdict* is the single successful outcome."""
    return verdict == VERDICT_AUTHENTIC


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of verifying one file.

    The four boolean flags are the ones the team's agreed interface specifies.
    Each is ``None`` when the workflow did not get far enough to establish it,
    which is a meaningful distinction: ``signature_valid=False`` means a signature
    was checked and failed, while ``signature_valid=None`` means no payload was
    ever found to check.
    """

    verdict: str
    #: A specific, human-readable explanation. Never asserts a cause that cannot
    #: be established from the evidence.
    reason: str

    payload_found: bool | None = None
    signature_valid: bool | None = None
    hash_valid: bool | None = None
    start_location_valid: bool | None = None
    manifest_consistent: bool | None = None

    #: Present once the signature has verified and the record has been validated.
    record: VerificationRecord | None = None
    #: The recovered plaintext, present only on a successful verification. Callers
    #: must treat this as inert data: display it, never execute it or hand it to
    #: the operating system to open.
    message: bytes | None = None

    #: Manifest fields that disagreed with the signed record, if any.
    mismatched_fields: tuple[str, ...] = ()
    #: The start location actually used, once resolved.
    start_location: int | None = None
    #: Caveats that apply to this result, shown alongside it.
    notes: tuple[str, ...] = ()
    #: Extra facts for the GUI and the evidence log.
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(
                f"verdict must be one of {VERDICTS}, got {self.verdict!r}"
            )
        # Copy so a caller cannot mutate a frozen result's dictionary after the
        # fact; the dataclass is frozen but a shared dict would not be.
        object.__setattr__(self, "details", dict(self.details))

    @property
    def authentic(self) -> bool:
        return is_success(self.verdict)

    @property
    def description(self) -> str:
        """The standing explanation of this verdict, independent of this file."""
        return VERDICT_DESCRIPTIONS[self.verdict]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly summary, for the evidence log and the GUI.

        The recovered message is reported by length only. Writing plaintext into a
        log that is committed as submission evidence would defeat the point of
        having encrypted it.
        """
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "description": self.description,
            "payload_found": self.payload_found,
            "signature_valid": self.signature_valid,
            "hash_valid": self.hash_valid,
            "start_location_valid": self.start_location_valid,
            "manifest_consistent": self.manifest_consistent,
            "mismatched_fields": list(self.mismatched_fields),
            "start_location": self.start_location,
            "message_length": None if self.message is None else len(self.message),
            "media_id": None if self.record is None else self.record.media_id,
            "media_type": None if self.record is None else self.record.media_type,
            "timestamp": None if self.record is None else self.record.timestamp,
            "encrypted": None if self.record is None else self.record.encrypted,
            "notes": list(self.notes),
            "details": dict(self.details),
        }
