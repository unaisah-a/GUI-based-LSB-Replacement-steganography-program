"""Shared vocabulary for the attack simulator.

An attack takes a protected file and produces a modified copy, together with a
plain description of what it changed and what the verifier is expected to make of
it. The expectation is recorded so the Attack Lab can show "expected: TAMPERED,
observed: TAMPERED" side by side, and so the tests can assert on the pairing
rather than on a hardcoded verdict list.

The originals are never modified: every attack writes a new file. That matters for
a demonstration where the same protected file is attacked several different ways.

On "expected" verdicts
----------------------
Some attacks have one predictable outcome. Corrupting the signature always gives
``SIGNATURE_INVALID``; verifying with an unrelated key always gives the same.
Others genuinely do not: corrupting a random bit inside the payload may land in
the record, the message or the signature, and the resulting verdict differs
accordingly. :attr:`Attack.expected_verdicts` is therefore a *set* of acceptable
outcomes, not a single value, and for the honestly-unpredictable attacks it holds
more than one member. Claiming a single verdict for those would be inventing
precision.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.errors import AppError
from app.utils import file_utils

__all__ = [
    "Attack",
    "AttackContext",
    "AttackError",
    "AttackOutcome",
    "copy_for_attack",
]


class AttackError(AppError):
    """An attack that could not be carried out on the supplied file."""


@dataclass(frozen=True)
class AttackOutcome:
    """What an attack did."""

    name: str
    #: The modified copy. The input file is never changed.
    output_path: str
    #: What was changed, in terms a demonstration audience can follow.
    description: str
    #: Verdicts that are acceptable outcomes of this attack. More than one member
    #: means the outcome genuinely varies; see the module docstring.
    expected_verdicts: frozenset[str]
    #: Whether this attack targets the file, the manifest, or the verifier's inputs.
    target: str = "media"
    #: Numbers worth reporting: how many samples were touched, at what rate.
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", dict(self.details))
        object.__setattr__(
            self, "expected_verdicts", frozenset(self.expected_verdicts)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "output": file_utils.display_name(self.output_path),
            "description": self.description,
            "expected_verdicts": sorted(self.expected_verdicts),
            "target": self.target,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class AttackContext:
    """Everything any attack might need, gathered once.

    The individual attack functions take the arguments that suit them — a payload
    attack needs the depth and start location, an image attack needs the extent of
    the payload region, a manifest attack needs neither. Rather than forcing them all
    into one awkward signature, this carries the superset and each entry in
    :data:`app.attacks.registry.ATTACKS` adapts it to the call its function wants.
    All the heterogeneity therefore lives in one table.
    """

    stego_path: str
    manifest_path: str
    output_path: str
    lsb_depth: int
    start_location: int
    samples_written: int
    overwrite: bool = False
    #: A key the *attacker* controls, needed only by the re-signing attack.
    attacker_private_key: Any = None
    #: The error-correcting code applied to the payload, if any.
    #:
    #: Attacks that need to *parse* the envelope have to remove the code first and put
    #: it back afterwards, because what sits on the medium is the encoded form. Attacks
    #: that simply damage bytes do not care, and indeed should not: an attacker
    #: flipping bits does not know or need to know that a code is present.
    ecc: Any = None
    #: Per-attack tuning, such as a bit error rate or a manifest field name.
    options: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "options", dict(self.options))


@dataclass(frozen=True)
class Attack:
    """One available attack, as offered by the Attack Lab."""

    key: str
    label: str
    #: Which media types this applies to. Empty means any.
    media_types: frozenset[str]
    #: Adapts a context to the underlying function's own signature.
    invoke: Callable[[AttackContext], AttackOutcome]
    summary: str
    #: ``"media"`` attacks produce a modified cover; ``"manifest"`` attacks produce a
    #: modified sidecar and leave the cover alone. The runner has to verify the right
    #: pair afterwards, so it needs to know which.
    target: str = "media"

    def applies_to(self, media_type: str) -> bool:
        return not self.media_types or media_type in self.media_types


def copy_for_attack(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    overwrite: bool = False,
) -> str:
    """Copy *source* to *destination* so an attack can modify the copy.

    Byte-for-byte, preserving nothing else. Attacks that only need to change a few
    bytes copy first and patch the copy, which keeps the original available for a
    before-and-after comparison.
    """
    target = os.fspath(destination)
    if os.path.exists(target) and not overwrite:
        raise AttackError(
            f"attack output path is already occupied: "
            f"{file_utils.display_name(target)}"
        )
    directory = os.path.dirname(os.path.abspath(target))
    if not os.path.isdir(directory):
        raise AttackError(
            f"attack output directory does not exist for "
            f"{file_utils.display_name(target)}"
        )
    shutil.copyfile(os.fspath(source), target)
    return target
