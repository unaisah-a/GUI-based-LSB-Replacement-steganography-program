"""Verification verdicts and structured result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    AUTHENTIC = "AUTHENTIC"
    TAMPERED = "TAMPERED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    PAYLOAD_MISSING = "PAYLOAD_MISSING"
    WRONG_START_LOCATION = "WRONG_START_LOCATION"
    CANNOT_VERIFY = "CANNOT_VERIFY"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class VerificationCheck:
    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    verdict: Verdict
    summary: str
    checks: tuple[VerificationCheck, ...] = ()
    message: bytes | None = None
    content_type: str | None = None
    record: dict[str, Any] | None = None
    start_location: int | None = None

    @property
    def authentic(self) -> bool:
        return self.verdict is Verdict.AUTHENTIC


@dataclass
class ResultBuilder:
    checks: list[VerificationCheck] = field(default_factory=list)

    def add(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append(
            VerificationCheck(
                name,
                CheckStatus.PASS if passed else CheckStatus.FAIL,
                detail,
            )
        )

    def not_run(self, name: str, detail: str) -> None:
        self.checks.append(VerificationCheck(name, CheckStatus.NOT_RUN, detail))

    def result(
        self,
        verdict: Verdict,
        summary: str,
        **values: Any,
    ) -> VerificationResult:
        return VerificationResult(verdict, summary, tuple(self.checks), **values)
