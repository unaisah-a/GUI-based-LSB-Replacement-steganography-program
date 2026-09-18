"""Attacks against the embedded payload itself, and against its manifest.

These are media-agnostic: they locate the embedded envelope, change part of it, and
write the result back into a copy of the cover. They are the attacks that produce
the sharpest verdicts, because each targets one specific part of the construction.

Section-targeted attacks
------------------------
Rather than flipping bits at random and hoping to hit something interesting, most
of these parse the envelope, modify a named section, and reassemble it. That makes
the expected verdict predictable and the demonstration explainable:

* corrupt the **signature** -> ``SIGNATURE_INVALID``
* corrupt the **record** -> ``SIGNATURE_INVALID`` (the record is signed)
* corrupt the **message** -> ``SIGNATURE_INVALID`` (the message is signed too)
* **truncate** the envelope -> ``PAYLOAD_MISSING``
* corrupt the **magic** -> ``PAYLOAD_MISSING``

Note that corrupting the message gives ``SIGNATURE_INVALID`` rather than
``TAMPERED``, because the signature covers the message. Reaching ``TAMPERED``
requires an attacker who can *re-sign*, which :func:`resign_with_substituted_message`
models explicitly using a key the attacker controls.

Random bit corruption is also offered, and its expected verdict set has several
members because where the corruption lands genuinely decides the outcome.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

import numpy as np

from app.attacks.base import AttackError, AttackOutcome, copy_for_attack
from app.crypto import envelope as envelope_module
from app.crypto import signatures
from app.stego import media
from app.utils import file_utils
from app.verification import verdicts

__all__ = [
    "corrupt_envelope_magic",
    "corrupt_message_section",
    "corrupt_random_payload_bits",
    "corrupt_record_section",
    "corrupt_signature_section",
    "resign_with_substituted_message",
    "tamper_with_manifest",
    "truncate_envelope",
]


def _read_raw(stego_path: str, lsb_depth: int, start_location: int) -> bytes:
    """Extract the bytes as they sit on the medium, whatever they are.

    This is what an attacker actually has access to. When an error-correcting code is
    in use these are the *encoded* bytes, and an attack that only damages bytes should
    work on them directly rather than pretending to understand the coding.
    """
    try:
        return media.extract(stego_path, lsb_depth, start_location)
    except Exception as exc:
        if isinstance(exc, AttackError):
            raise
        raise AttackError(
            f"could not read a payload from "
            f"{file_utils.display_name(stego_path)} at depth {lsb_depth} and start "
            f"location {start_location}: {exc}"
        ) from exc


def _read_envelope(
    stego_path: str, lsb_depth: int, start_location: int, ecc: Any = None
) -> tuple[bytes, envelope_module.ParsedEnvelope]:
    """Extract, remove any error-correcting code, and parse the envelope.

    Needed by the attacks that target a named section, because a section cannot be
    located without parsing and the encoded form is not parseable.
    """
    from app.robustness import error_correction

    extracted = _read_raw(stego_path, lsb_depth, start_location)

    try:
        if error_correction.is_active(ecc):
            extracted, _ = error_correction.decode(extracted, ecc)
        return extracted, envelope_module.parse_envelope(extracted)
    except Exception as exc:
        if isinstance(exc, AttackError):
            raise
        raise AttackError(
            f"could not read an envelope from "
            f"{file_utils.display_name(stego_path)} at depth {lsb_depth} and start "
            f"location {start_location}: {exc}"
        ) from exc


def _rewrite(
    cover_path: str,
    output_path: str,
    payload: bytes,
    lsb_depth: int,
    start_location: int,
    *,
    overwrite: bool,
    ecc: Any = None,
) -> str:
    """Embed *payload* into a fresh copy of the cover, replacing the old payload.

    The attack re-embeds into the *stego* file, so everything outside the payload
    region stays exactly as the sender left it and only the payload differs.

    Any error-correcting code is re-applied, so the result is a file the receiver can
    still read — which is what makes the resulting verdict meaningful rather than
    simply "unreadable".
    """
    from app.robustness import error_correction

    if error_correction.is_active(ecc):
        payload = error_correction.encode(payload, ecc)

    result = media.embed(
        cover_path,
        output_path,
        payload,
        lsb_depth,
        start_location,
        overwrite=overwrite,
    )
    return result.output_path


def _replace_section(
    stego_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    lsb_depth: int,
    start_location: int,
    *,
    section: str,
    overwrite: bool,
    ecc: Any = None,
) -> AttackOutcome:
    """Flip one byte inside a named envelope section and re-embed."""
    source = os.fspath(stego_path)
    _, parsed = _read_envelope(source, lsb_depth, start_location, ecc)

    record = bytearray(parsed.record_bytes)
    message = bytearray(parsed.message)
    signature = bytearray(parsed.signature)

    if section == "message":
        target = message
    elif section == "signature":
        target = signature
    else:  # pragma: no cover - internal
        raise AttackError(f"unknown envelope section {section!r}")

    if not target:
        raise AttackError(
            f"the {section} section of this envelope is empty, so there is nothing "
            f"to corrupt"
        )

    index = len(target) // 2
    original_byte = target[index]
    target[index] ^= 0xFF

    forged = envelope_module.build_envelope(
        bytes(record), bytes(message), bytes(signature), parsed.flags
    )
    written = _rewrite(
        source, os.fspath(output_path), forged, lsb_depth, start_location,
        overwrite=overwrite, ecc=ecc,
    )

    return AttackOutcome(
        name=f"corrupt {section} section",
        output_path=written,
        description=(
            f"Inverted byte {index} of the envelope's {section} section, which is "
            f"covered by the signature."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_SIGNATURE_INVALID}),
        target="payload",
        details={
            "section": section,
            "byte_index": index,
            "original_byte": original_byte,
            "modified_byte": target[index],
            "section_length": len(target),
        },
    )


def corrupt_record_section(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Substitute a structurally valid record that differs from the signed one.

    Two obvious implementations are both wrong, and it is worth recording why.

    A blind byte flip usually produces invalid UTF-8 or invalid JSON, so the verifier
    fails at *parsing* the record and reports ``CANNOT_VERIFY``. That is a real
    outcome but it demonstrates the parser, not the signature.

    Editing a field to a value of a **different length** changes the envelope length,
    which no longer matches the length the manifest published, so extraction rejects
    the payload and the receiver sees ``PAYLOAD_MISSING`` — again without ever
    reaching the signature.

    So the edit has to keep the record both well formed and exactly the same length.
    Changing one hexadecimal digit of the signed nonce does that: the nonce is always
    present, is fixed-length, and is covered by the signature. The failure then lands
    exactly where this attack is aimed.
    """
    source = os.fspath(stego_path)
    _, parsed = _read_envelope(source, lsb_depth, start_location, ecc)

    try:
        record = json.loads(parsed.record_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttackError(
            f"the embedded record could not be decoded, so it cannot be edited: {exc}"
        ) from exc

    original_nonce = record.get("nonce")
    if not isinstance(original_nonce, str) or not original_nonce:
        raise AttackError(
            "the embedded record has no nonce to edit, so this attack cannot run"
        )

    # Swap the final hex digit for a different one, preserving the length exactly.
    last = original_nonce[-1]
    replacement_digit = "0" if last != "0" else "1"
    forged_nonce = original_nonce[:-1] + replacement_digit
    record["nonce"] = forged_nonce
    forged_record = envelope_module.canonical_json(record)

    if len(forged_record) != len(parsed.record_bytes):  # pragma: no cover - guard
        raise AttackError(
            f"the edited record changed length ({len(parsed.record_bytes)} to "
            f"{len(forged_record)} bytes), which would be caught during extraction "
            f"rather than by the signature check"
        )

    forged = envelope_module.build_envelope(
        forged_record, parsed.message, parsed.signature, parsed.flags
    )
    written = _rewrite(
        source, os.fspath(output_path), forged, lsb_depth, start_location,
        overwrite=overwrite, ecc=ecc,
    )

    return AttackOutcome(
        name="corrupt record section",
        output_path=written,
        description=(
            f"Changed one digit of the record's signed nonce, from "
            f"...{original_nonce[-8:]} to ...{forged_nonce[-8:]}. The record stays "
            f"well formed and the same length, so the failure lands on the signature "
            f"that covers it."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_SIGNATURE_INVALID}),
        target="payload",
        details={
            "section": "record",
            "field": "nonce",
            "original": original_nonce,
            "modified": forged_nonce,
            "record_length": len(parsed.record_bytes),
            "length_preserved": True,
        },
    )


def corrupt_message_section(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Corrupt the message.

    Gives ``SIGNATURE_INVALID``, not ``TAMPERED``, because the signature covers the
    message as well as the record. An attacker who can only modify bytes cannot
    produce ``TAMPERED``; that needs a signing key.
    """
    return _replace_section(
        stego_path,
        output_path,
        lsb_depth,
        start_location,
        section="message",
        overwrite=overwrite,
        ecc=ecc,
    )


def corrupt_signature_section(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Corrupt the signature."""
    return _replace_section(
        stego_path,
        output_path,
        lsb_depth,
        start_location,
        section="signature",
        overwrite=overwrite,
        ecc=ecc,
    )


def corrupt_envelope_magic(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Destroy the envelope marker, so no payload appears to be present at all."""
    source = os.fspath(stego_path)
    extracted, _ = _read_envelope(source, lsb_depth, start_location, ecc)

    forged = bytearray(extracted)
    forged[0] ^= 0xFF
    written = _rewrite(
        source, os.fspath(output_path), bytes(forged), lsb_depth, start_location,
        overwrite=overwrite, ecc=ecc,
    )

    return AttackOutcome(
        name="corrupt envelope marker",
        output_path=written,
        description=(
            "Inverted the first byte of the envelope marker, so the extracted bytes "
            "no longer look like a payload at all."
        ),
        expected_verdicts=frozenset({verdicts.VERDICT_PAYLOAD_MISSING}),
        target="payload",
        details={"bytes_changed": 1},
    )


def truncate_envelope(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    keep_fraction: float = 0.5,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Cut the envelope short, so its declared section lengths overrun the buffer."""
    source = os.fspath(stego_path)
    extracted, _ = _read_envelope(source, lsb_depth, start_location, ecc)

    keep = max(1, int(len(extracted) * keep_fraction))
    truncated = extracted[:keep]
    written = _rewrite(
        source, os.fspath(output_path), truncated, lsb_depth, start_location,
        overwrite=overwrite, ecc=ecc,
    )

    return AttackOutcome(
        name="truncate payload",
        output_path=written,
        description=(
            f"Kept only the first {keep} of {len(extracted)} envelope bytes, so the "
            f"declared section lengths now overrun the payload."
        ),
        expected_verdicts=frozenset(
            {verdicts.VERDICT_PAYLOAD_MISSING, verdicts.VERDICT_CANNOT_VERIFY}
        ),
        target="payload",
        details={
            "original_length": len(extracted),
            "kept_length": keep,
        },
    )


def corrupt_random_payload_bits(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    *,
    bit_error_rate: float = 0.01,
    seed: int = 0,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Flip a proportion of the embedded payload's bits at random.

    This one deliberately works on the bytes **as they sit on the medium**, without
    decoding any error-correcting code first. That is the honest model of scattered
    transmission or storage damage, and it is the only way the coding demonstration
    means anything: if the attack decoded the code, damaged the envelope and
    re-encoded, the damage would be *inside* the protected data and no code could
    ever repair it.

    So with a code in place the flips land across the redundant copies, which is
    exactly the situation majority voting is built for.

    The expected verdict set has several members on purpose: where the corruption
    lands decides the outcome, and pretending otherwise would overstate what this
    attack does. When a code is active, ``AUTHENTIC`` joins the set, because
    surviving is a legitimate outcome rather than a failure of the attack.
    """
    if not 0 < bit_error_rate <= 1:
        raise AttackError(
            f"bit_error_rate must be greater than 0 and at most 1, got "
            f"{bit_error_rate}"
        )

    from app.robustness import error_correction

    source = os.fspath(stego_path)
    extracted = _read_raw(source, lsb_depth, start_location)

    bits = np.unpackbits(np.frombuffer(extracted, dtype=np.uint8))
    generator = np.random.default_rng(seed)
    flip_mask = generator.random(bits.size) < bit_error_rate
    flipped = int(flip_mask.sum())
    bits[flip_mask] ^= 1
    forged = np.packbits(bits).tobytes()[: len(extracted)]

    # Written back verbatim: the length is preserved and the code is *not* re-applied,
    # because the damage is meant to be to the coded bytes themselves.
    written = _rewrite(
        source, os.fspath(output_path), forged, lsb_depth, start_location,
        overwrite=overwrite, ecc=None,
    )

    coded = error_correction.is_active(ecc)
    expected = {
        verdicts.VERDICT_SIGNATURE_INVALID,
        verdicts.VERDICT_PAYLOAD_MISSING,
        verdicts.VERDICT_CANNOT_VERIFY,
    }
    if coded:
        expected.add(verdicts.VERDICT_AUTHENTIC)

    return AttackOutcome(
        name="corrupt random payload bits",
        output_path=written,
        description=(
            f"Flipped {flipped} of {bits.size} embedded payload bits at random "
            f"({bit_error_rate * 100:.2f}% target rate)"
            + (
                ", spread across the redundant copies so the receiver's code has a "
                "chance to repair them."
                if coded
                else "."
            )
        ),
        expected_verdicts=frozenset(expected),
        target="payload",
        details={
            "bit_error_rate": bit_error_rate,
            "bits_flipped": flipped,
            "total_bits": int(bits.size),
            "seed": seed,
            "error_correction_active": coded,
        },
    )


def _same_length_substitute(length: int) -> bytes:
    """Build a substitute message of exactly *length* bytes.

    The length has to match, and that is the interesting part of this attack. The
    companion manifest publishes ``envelope_length``, and the verifier passes it to
    the stego layer as a cross-check, so a substitution that changes the payload
    length is rejected during *extraction* and never reaches the signature at all —
    the receiver sees ``PAYLOAD_MISSING``.

    That is a useful property of publishing the length, and it means an attacker who
    wants to be judged on the signature has to preserve the length. Doing so here
    makes the attack demonstrate what it claims to.
    """
    filler = b"substituted by an attacker. "
    if length <= 0:
        return b""
    repeated = filler * (length // len(filler) + 1)
    return repeated[:length]


def resign_with_substituted_message(
    stego_path,
    output_path,
    lsb_depth,
    start_location,
    attacker_private_key: Any,
    *,
    substitute_message: bytes | None = None,
    overwrite: bool = False,
    ecc: Any = None,
) -> AttackOutcome:
    """Replace the message and re-sign, using a key the attacker controls.

    This is the only route to ``TAMPERED``: the record keeps the sender's original
    message digest while the message section holds different bytes, and the whole
    envelope is signed again so the signature check passes.

    Which verdict a receiver reaches depends on the key they hold:

    * the **attacker's** public key -> the signature verifies, the digest comparison
      fails, ``TAMPERED``
    * the **genuine sender's** public key -> the signature fails first,
      ``SIGNATURE_INVALID``

    The second is the result that matters, and the reason this attack does not work
    against a receiver who has the right key.

    *substitute_message* defaults to a message of the same length as the original.
    See :func:`_same_length_substitute` for why the length matters.
    """
    source = os.fspath(stego_path)
    _, parsed = _read_envelope(source, lsb_depth, start_location, ecc)

    replacement = (
        substitute_message
        if substitute_message is not None
        else _same_length_substitute(len(parsed.message))
    )
    length_preserved = len(replacement) == len(parsed.message)

    forged = signatures.sign_envelope(
        parsed.record_bytes, replacement, attacker_private_key, parsed.flags
    )
    written = _rewrite(
        source, os.fspath(output_path), forged, lsb_depth, start_location,
        overwrite=overwrite, ecc=ecc,
    )

    expected = {verdicts.VERDICT_TAMPERED, verdicts.VERDICT_SIGNATURE_INVALID}
    if not length_preserved:
        # The manifest's published envelope length no longer matches, so extraction
        # rejects the payload before the signature is examined.
        expected.add(verdicts.VERDICT_PAYLOAD_MISSING)

    return AttackOutcome(
        name="substitute message and re-sign",
        output_path=written,
        description=(
            f"Replaced the {len(parsed.message)}-byte message with "
            f"{len(replacement)} different bytes and re-signed the envelope with a "
            f"key the attacker controls, leaving the sender's original message "
            f"digest in the record."
        ),
        expected_verdicts=frozenset(expected),
        target="payload",
        details={
            "original_message_length": len(parsed.message),
            "substitute_message_length": len(replacement),
            "length_preserved": length_preserved,
            "note": (
                "TAMPERED only against a receiver holding the attacker's key; "
                "SIGNATURE_INVALID against a receiver holding the sender's key."
            ),
            "length_note": (
                "A substitution that changes the payload length is rejected during "
                "extraction by the manifest's published envelope length, before the "
                "signature is examined."
            ),
        },
    )


#: Manifest fields that feed the keyed start-location derivation.
#:
#: Changing any of these moves where the receiver looks, so extraction fails and the
#: verdict is ``PAYLOAD_MISSING`` — the tampering is detected, but by the reader
#: rather than by the cross-check. Changing any *other* published field leaves
#: extraction working and the mismatch is caught afterwards by comparing the
#: manifest against the signed record, giving ``TAMPERED``.
#:
#: Both outcomes are detections. The distinction matters only when choosing a field
#: to demonstrate one mechanism or the other.
DERIVATION_INPUT_FIELDS: Final[frozenset[str]] = frozenset(
    {"media_id", "media_type", "nonce", "lsb_depth", "envelope_length", "start_location"}
)


def tamper_with_manifest(
    manifest_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    *,
    field: str = "lsb_depth",
    value: Any = None,
    overwrite: bool = False,
) -> AttackOutcome:
    """Edit one field of the companion manifest.

    The manifest is not signed, so an attacker can change it freely. What they
    cannot do is make the change *undetectable*: every field they might alter is
    also inside the signed record.

    Which mechanism catches it depends on the field; see
    :data:`DERIVATION_INPUT_FIELDS`. To demonstrate the cross-check specifically,
    pick a field that does not feed the derivation, such as ``message_length``.
    """
    source = os.fspath(manifest_path)
    target = copy_for_attack(source, output_path, overwrite=overwrite)

    data = json.loads(Path(source).read_text(encoding="utf-8"))
    if field not in data:
        raise AttackError(
            f"the manifest has no field {field!r}; available fields are "
            f"{sorted(data)}"
        )

    original_value = data[field]
    if value is None:
        # Choose a plausible-but-different value automatically.
        if field == "lsb_depth":
            value = 8 if original_value != 8 else 1
        elif isinstance(original_value, bool):
            value = not original_value
        elif isinstance(original_value, int):
            value = original_value + 1
        elif isinstance(original_value, str):
            value = original_value + "-tampered"
        else:
            raise AttackError(
                f"cannot choose a replacement for field {field!r} automatically; "
                f"supply value explicitly"
            )

    data[field] = value
    file_utils.write_json_atomic(target, data, overwrite=True)

    expected = {verdicts.VERDICT_TAMPERED, verdicts.VERDICT_CANNOT_VERIFY}
    if field in DERIVATION_INPUT_FIELDS:
        # These drive extraction, so the usual outcome is that nothing is found at
        # all rather than a mismatch being detected afterwards.
        expected.add(verdicts.VERDICT_PAYLOAD_MISSING)
        expected.add(verdicts.VERDICT_WRONG_START_LOCATION)

    return AttackOutcome(
        name=f"tamper with manifest field {field}",
        output_path=target,
        description=(
            f"Changed the manifest's {field!r} from {original_value!r} to "
            f"{value!r}. The manifest is not signed, but every field it publishes "
            f"is also inside the signed record."
        ),
        expected_verdicts=frozenset(expected),
        target="manifest",
        details={"field": field, "original": original_value, "modified": value},
    )
