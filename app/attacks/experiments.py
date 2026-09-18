"""Paired verification experiments and exportable Attack Lab evidence."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from app.attacks.payload_attacks import (
    AttackResult,
    add_seeded_payload_noise,
    corrupt_embedded_payload,
    corrupt_envelope_region,
    erase_payload_tail,
    modify_outside_payload,
)
from app.crypto.hashing import compute_sha256
from app.crypto.key_manager import public_key_fingerprint
from app.verification.verdicts import VerificationResult, Verdict
from app.verification.verifier import verify_media


MUTATING_SCENARIOS = {
    "payload-corruption",
    "record-corruption",
    "message-corruption",
    "signature-corruption",
    "payload-truncation",
    "seeded-noise",
    "outside-payload",
    "replay",
}
INPUT_SCENARIOS = {"wrong-public-key", "wrong-start-secret", "substitution"}
SCENARIOS = MUTATING_SCENARIOS | INPUT_SCENARIOS


@dataclass(frozen=True)
class VerificationEvidence:
    verdict: str
    summary: str
    checks: tuple[dict[str, str], ...]
    public_key_fingerprint: str
    media_path: str
    manifest_path: str
    message_length: int | None
    message_sha256: str | None


@dataclass(frozen=True)
class AttackEvidence:
    format: str
    version: int
    scenario: str
    seed: int
    severity: int
    fault_copies: int
    baseline: VerificationEvidence
    outcome: VerificationEvidence
    mutation: AttackResult | None
    limitation: str

    def to_dict(self) -> dict:
        value = asdict(self)
        value["baseline"]["checks"] = list(value["baseline"]["checks"])
        value["outcome"]["checks"] = list(value["outcome"]["checks"])
        return value


def _verification_evidence(
    result: VerificationResult,
    public_key,
    media_path: str | Path,
    manifest_path: str | Path,
) -> VerificationEvidence:
    message = result.message if result.verdict is Verdict.AUTHENTIC else None
    return VerificationEvidence(
        verdict=result.verdict.value,
        summary=result.summary,
        checks=tuple(
            {
                "name": check.name,
                "status": check.status.value,
                "detail": check.detail,
            }
            for check in result.checks
        ),
        public_key_fingerprint=public_key_fingerprint(public_key),
        media_path=str(Path(media_path)),
        manifest_path=str(Path(manifest_path)),
        message_length=None if message is None else len(message),
        message_sha256=None if message is None else compute_sha256(message),
    )


def _copy_attack(
    input_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool,
) -> AttackResult:
    source = Path(input_path).resolve()
    destination = Path(output_path).resolve()
    if source == destination:
        raise ValueError("replay output must be different from its input")
    if not destination.parent.is_dir():
        raise FileNotFoundError("replay output directory does not exist")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"replay output already exists: {destination.name}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary_name)
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return AttackResult(
        str(source),
        str(destination),
        "unchanged",
        "replay",
        -1,
        "Created a byte-identical replay copy; no freshness state was changed.",
        0,
    )


def run_attack_experiment(
    input_path: str | Path,
    manifest_path: str | Path,
    public_key,
    scenario: str,
    *,
    output_path: str | Path | None = None,
    start_secret: str | bytes | None = None,
    encryption_key: bytes | None = None,
    alternate_public_key=None,
    wrong_start_secret: str | bytes | None = None,
    substitute_manifest_path: str | Path | None = None,
    seed: int = 2005,
    severity: int = 8,
    fault_copies: int = 1,
    overwrite: bool = False,
) -> AttackEvidence:
    """Run a baseline verification and one controlled negative/boundary scenario."""
    if scenario not in SCENARIOS:
        raise ValueError("unsupported attack scenario")
    for value, name, minimum in (
        (seed, "seed", 0),
        (severity, "severity", 1),
        (fault_copies, "fault_copies", 1),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ValueError(f"{name} must be an integer of at least {minimum}")
    if fault_copies > 3:
        raise ValueError("fault_copies must not exceed three")

    baseline_result = verify_media(
        input_path,
        manifest_path,
        public_key,
        start_secret=start_secret,
        encryption_key=encryption_key,
    )
    if baseline_result.verdict is not Verdict.AUTHENTIC:
        raise ValueError(
            "baseline verification must be AUTHENTIC before an attack is demonstrated"
        )
    baseline = _verification_evidence(
        baseline_result, public_key, input_path, manifest_path
    )

    mutation: AttackResult | None = None
    outcome_media = input_path
    outcome_manifest = manifest_path
    outcome_key = public_key
    outcome_secret = start_secret
    limitation = "The outcome applies only to the configured hidden payload checks."

    if scenario in MUTATING_SCENARIOS:
        if output_path is None:
            raise ValueError(f"{scenario} requires a separate output path")
        outcome_media = output_path
        if scenario == "payload-corruption":
            mutation = corrupt_embedded_payload(
                input_path,
                output_path,
                manifest_path,
                start_secret=start_secret,
                overwrite=overwrite,
            )
        elif scenario in {
            "record-corruption",
            "message-corruption",
            "signature-corruption",
        }:
            mutation = corrupt_envelope_region(
                input_path,
                output_path,
                manifest_path,
                scenario.removesuffix("-corruption"),
                copies=fault_copies,
                start_secret=start_secret,
                overwrite=overwrite,
            )
        elif scenario == "payload-truncation":
            mutation = erase_payload_tail(
                input_path,
                output_path,
                manifest_path,
                byte_count=severity,
                start_secret=start_secret,
                overwrite=overwrite,
            )
        elif scenario == "seeded-noise":
            mutation = add_seeded_payload_noise(
                input_path,
                output_path,
                manifest_path,
                seed=seed,
                severity=severity,
                start_secret=start_secret,
                overwrite=overwrite,
            )
        elif scenario == "outside-payload":
            mutation = modify_outside_payload(
                input_path,
                output_path,
                manifest_path,
                start_secret=start_secret,
                overwrite=overwrite,
            )
            limitation = (
                "Expected boundary: verification authenticates the hidden signed record, "
                "not every byte or sample of the cover media."
            )
        else:
            mutation = _copy_attack(input_path, output_path, overwrite=overwrite)
            limitation = (
                "Expected boundary: verification has no replay cache or freshness policy, "
                "so a byte-identical signed bundle can authenticate again."
            )
    elif scenario == "wrong-public-key":
        if alternate_public_key is None:
            raise ValueError("wrong-public-key requires an alternate public key")
        outcome_key = alternate_public_key
        limitation = "The media is unchanged; only the trusted verification key differs."
    elif scenario == "wrong-start-secret":
        if wrong_start_secret is None or wrong_start_secret == start_secret:
            raise ValueError("a distinct wrong start secret is required")
        outcome_secret = wrong_start_secret
        limitation = "The media is unchanged; only the start-location secret differs."
    else:
        if substitute_manifest_path is None:
            raise ValueError("substitution requires a different manifest")
        if Path(substitute_manifest_path).resolve() == Path(manifest_path).resolve():
            raise ValueError("substitution manifest must differ from the baseline manifest")
        outcome_manifest = substitute_manifest_path
        limitation = (
            "The media is unchanged; this checks a substituted companion manifest. "
            "It does not add whole-cover binding or replay prevention."
        )

    outcome_result = verify_media(
        outcome_media,
        outcome_manifest,
        outcome_key,
        start_secret=outcome_secret,
        encryption_key=encryption_key,
    )
    outcome = _verification_evidence(
        outcome_result, outcome_key, outcome_media, outcome_manifest
    )
    return AttackEvidence(
        format="SMIV-ATTACK-EVIDENCE",
        version=1,
        scenario=scenario,
        seed=seed,
        severity=severity,
        fault_copies=fault_copies,
        baseline=baseline,
        outcome=outcome,
        mutation=mutation,
        limitation=limitation,
    )


def export_attack_evidence(
    evidence: AttackEvidence,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> None:
    if not isinstance(evidence, AttackEvidence):
        raise TypeError("evidence must be an AttackEvidence result")
    destination = Path(output_path).resolve()
    if not destination.parent.is_dir():
        raise FileNotFoundError("evidence output directory does not exist")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"evidence output already exists: {destination.name}")
    encoded = (json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.stage-", dir=str(destination.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
