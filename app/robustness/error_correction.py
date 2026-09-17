"""Applying and removing an error-correcting code, by recorded scheme.

One entry point each way, dispatching on the scheme named in the signed verification
record and the companion manifest. :mod:`app.robustness.redundancy` holds the
repetition primitives; this decides which scheme to use and reports what it did.

Where this sits in the pipeline
-------------------------------
The code is applied to the **whole signed envelope**, immediately before embedding,
and removed immediately after extraction::

    sender    message -> record + signature -> envelope -> encode -> embed
    receiver  extract -> decode -> envelope -> verify signature -> message

Applying it outside the envelope rather than inside is what makes it useful: the
signature, the record and the message are all protected, so corruption anywhere in
the payload can be repaired before the signature is checked. Applying it to the
message only would leave the signature itself unprotected, and a single flipped bit
there would fail verification no matter how well the message survived.

What a correction report is for
-------------------------------
Claiming that error correction works is easy; showing it is better. Every decode
reports how many bit positions had disagreeing copies, which is exactly the set of
bits the code repaired. A demonstration can corrupt a payload, watch the report say
how many bits were fixed, and see the verdict still come out ``AUTHENTIC``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from app.crypto.envelope import ErrorCorrectionParameters
from app.robustness import redundancy
from app.robustness.redundancy import RedundancyError
from app.utils import constants

__all__ = [
    "CorrectionReport",
    "RedundancyError",
    "decode",
    "encode",
    "encoded_length",
    "is_active",
    "largest_raw_payload",
    "majority_vote",
]


def majority_vote(copies: np.ndarray) -> np.ndarray:
    """Return the per-position majority of a ``(copies, positions)`` bit array.

    Exposed separately because it is the whole of the correction step, and worth being
    able to test and explain on its own.
    """
    array = np.ascontiguousarray(copies, dtype=np.uint8)
    if array.ndim != 2:
        raise RedundancyError(
            f"copies must be two-dimensional, got {array.ndim} dimensions"
        )
    count = array.shape[0]
    if count % 2 == 0:
        raise RedundancyError(
            f"a majority vote needs an odd number of copies, got {count}"
        )
    return (array.sum(axis=0) * 2 > count).astype(np.uint8)


@dataclass(frozen=True)
class CorrectionReport:
    """What a decode had to repair."""

    scheme: str
    factor: int
    #: Bits in the recovered payload.
    bits_examined: int
    #: Bit positions whose copies disagreed. These are the ones the code repaired.
    bits_corrected: int
    raw_length: int
    encoded_length: int

    @property
    def corrected_proportion(self) -> float:
        return self.bits_corrected / self.bits_examined if self.bits_examined else 0.0

    @property
    def any_corrections(self) -> bool:
        return self.bits_corrected > 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "factor": self.factor,
            "bits_examined": self.bits_examined,
            "bits_corrected": self.bits_corrected,
            "corrected_proportion": self.corrected_proportion,
            "raw_length": self.raw_length,
            "encoded_length": self.encoded_length,
        }

    def summary(self) -> str:
        """A sentence for the interface and the log."""
        if self.scheme == constants.ECC_NONE:
            return "No error-correcting code was applied."
        if not self.any_corrections:
            return (
                f"{self.scheme} coding at factor {self.factor} found no disagreement "
                f"between copies: nothing needed repairing."
            )
        return (
            f"{self.scheme} coding at factor {self.factor} repaired "
            f"{self.bits_corrected} of {self.bits_examined} bits "
            f"({self.corrected_proportion * 100:.4f}%) by majority vote."
        )


def is_active(parameters: ErrorCorrectionParameters | None) -> bool:
    """Whether these parameters call for any coding at all.

    ``None`` and an explicit ``"none"`` scheme both mean no coding, and both occur:
    the first when the sender never asked for it, the second when a record states it
    explicitly.
    """
    return parameters is not None and parameters.scheme != constants.ECC_NONE


def _validate(parameters: ErrorCorrectionParameters) -> ErrorCorrectionParameters:
    if parameters.scheme not in constants.ECC_SCHEMES:
        raise RedundancyError(
            f"unsupported error-correction scheme {parameters.scheme!r}; this build "
            f"implements {constants.ECC_SCHEMES}"
        )
    if parameters.scheme == constants.ECC_REPETITION:
        redundancy.validate_factor(parameters.factor)
    return parameters


def encoded_length(
    raw_length: int, parameters: ErrorCorrectionParameters | None
) -> int:
    """Return how many bytes will actually be embedded for a *raw_length* payload.

    Both sides need this: the sender to check capacity and to derive a start location,
    the receiver to know how many bytes to extract.
    """
    if not is_active(parameters):
        return raw_length
    _validate(parameters)  # type: ignore[arg-type]
    return redundancy.encoded_length(raw_length, parameters.factor)  # type: ignore[union-attr]


def largest_raw_payload(
    available_bytes: int, parameters: ErrorCorrectionParameters | None
) -> int:
    """Return the largest raw payload that fits once encoded.

    Used for the capacity read-out, so a user sees the cost of the code rather than
    discovering it when an embed is refused.
    """
    if not is_active(parameters):
        return available_bytes
    _validate(parameters)  # type: ignore[arg-type]
    return redundancy.max_raw_length(available_bytes, parameters.factor)  # type: ignore[union-attr]


def encode(data: bytes, parameters: ErrorCorrectionParameters | None) -> bytes:
    """Apply the recorded code to *data*, or return it unchanged if none applies."""
    if not is_active(parameters):
        return bytes(data)
    _validate(parameters)  # type: ignore[arg-type]

    if parameters.scheme == constants.ECC_REPETITION:  # type: ignore[union-attr]
        return redundancy.repetition_encode(data, parameters.factor)  # type: ignore[union-attr]

    # Unreachable while ECC_SCHEMES holds only these two, but an explicit failure is
    # better than silently returning unencoded data that the receiver will try to
    # decode.
    raise RedundancyError(  # pragma: no cover
        f"no encoder for scheme {parameters.scheme!r}"  # type: ignore[union-attr]
    )


def decode(
    encoded: bytes, parameters: ErrorCorrectionParameters | None
) -> tuple[bytes, CorrectionReport]:
    """Remove the recorded code from *encoded*, reporting what was repaired.

    :raises app.robustness.redundancy.RedundancyError: the payload is not a whole
        number of copies, or the scheme is not one this build implements.
    """
    payload = bytes(encoded)

    if not is_active(parameters):
        return payload, CorrectionReport(
            scheme=constants.ECC_NONE,
            factor=1,
            bits_examined=len(payload) * 8,
            bits_corrected=0,
            raw_length=len(payload),
            encoded_length=len(payload),
        )

    _validate(parameters)  # type: ignore[arg-type]
    factor = parameters.factor  # type: ignore[union-attr]

    if parameters.scheme == constants.ECC_REPETITION:  # type: ignore[union-attr]
        recovered, disagreed = redundancy.repetition_decode(payload, factor)
        return recovered, CorrectionReport(
            scheme=constants.ECC_REPETITION,
            factor=factor,
            bits_examined=int(disagreed.size),
            bits_corrected=int(disagreed.sum()),
            raw_length=len(recovered),
            encoded_length=len(payload),
        )

    raise RedundancyError(  # pragma: no cover
        f"no decoder for scheme {parameters.scheme!r}"  # type: ignore[union-attr]
    )
