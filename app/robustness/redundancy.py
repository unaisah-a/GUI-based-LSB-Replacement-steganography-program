"""Repetition coding: the redundancy primitive.

The scheme
----------
The payload's bit sequence is repeated *factor* times and the copies are laid end to
end, so an encoded payload is exactly ``factor`` times the size of the original::

    original    b0 b1 b2 ... bn
    encoded     b0 b1 b2 ... bn | b0 b1 b2 ... bn | b0 b1 b2 ... bn

Decoding reads the copies back and takes a majority vote at each bit position.

Why whole copies rather than consecutive repeats
------------------------------------------------
The obvious alternative repeats each bit in place — ``b0 b0 b0 b1 b1 b1`` — and for
*independent* random bit errors the two are equivalent. They differ completely for
*burst* errors, which is what damage to media actually looks like: a scribble over
part of an image, a click in a waveform, a corrupted block. Consecutive repetition
puts all three copies of a bit inside the burst, so all three are lost together and
the majority vote is worthless. Spreading the copies across the whole payload means a
burst destroys at most one copy of each bit it touches.

This is block interleaving, and it is the reason the encoding is worth having at all.

What it costs and what it buys
------------------------------
The cost is exact and unavoidable: a factor of 3 triples the payload, so the largest
message that fits drops to roughly a third. The benefit is that a payload can survive
corruption that would otherwise destroy it — up to just under half the copies of any
given bit.

It does not make LSB embedding robust in general. Amplitude scaling, resampling and
lossy recompression change *every* sample, so they overwhelm every copy at once and no
repetition factor helps. :mod:`app.attacks` demonstrates both outcomes.

Factors must be odd
-------------------
An even factor allows a tied vote, and any tie-break is a guess dressed up as a
decision. Odd factors are enforced.
"""

from __future__ import annotations

import numpy as np

from app.errors import AppError

__all__ = [
    "encoded_length",
    "max_raw_length",
    "repetition_decode",
    "repetition_encode",
    "validate_factor",
]


class RedundancyError(AppError):
    """A repetition factor or an encoded payload that cannot be used."""


def validate_factor(factor: object) -> int:
    """Return *factor* as an ``int``, or raise.

    Rejects even factors: a tie in the majority vote would have to be broken
    arbitrarily, and an arbitrary choice presented as a recovered bit is worse than
    no error correction at all.
    """
    if isinstance(factor, bool) or not isinstance(factor, int):
        raise RedundancyError(
            f"the repetition factor must be an integer, got {type(factor).__name__}"
        )
    if factor < 1:
        raise RedundancyError(
            f"the repetition factor must be at least 1, got {factor}"
        )
    if factor % 2 == 0:
        raise RedundancyError(
            f"the repetition factor must be odd so a majority vote cannot tie, "
            f"got {factor}"
        )
    return factor


def encoded_length(raw_length: int, factor: int) -> int:
    """Return the encoded size of a *raw_length*-byte payload.

    Exactly ``raw_length * factor``: the bit count is a multiple of eight and the
    factor multiplies it, so no padding is ever needed and the arithmetic is exact.
    Both the sender and the receiver rely on that to agree on how many bytes were
    embedded.
    """
    if isinstance(raw_length, bool) or not isinstance(raw_length, int) or raw_length < 0:
        raise RedundancyError(
            f"raw_length must be a non-negative integer, got {raw_length!r}"
        )
    return raw_length * validate_factor(factor)


def max_raw_length(available_bytes: int, factor: int) -> int:
    """Return the largest raw payload that fits in *available_bytes* once encoded."""
    if (
        isinstance(available_bytes, bool)
        or not isinstance(available_bytes, int)
        or available_bytes < 0
    ):
        raise RedundancyError(
            f"available_bytes must be a non-negative integer, got {available_bytes!r}"
        )
    return available_bytes // validate_factor(factor)


def repetition_encode(data: bytes, factor: int) -> bytes:
    """Repeat *data*'s bit sequence *factor* times, as whole interleaved copies."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise RedundancyError(
            f"data must be bytes-like, got {type(data).__name__}"
        )
    count = validate_factor(factor)
    # Whole copies laid end to end, which is the interleaving described above. The
    # payload is a whole number of bytes, so repeating the bytes repeats the bits.
    return bytes(data) * count


def repetition_decode(encoded: bytes, factor: int) -> tuple[bytes, np.ndarray]:
    """Recover the payload by majority vote, and report where the copies disagreed.

    Returns the recovered bytes and a boolean array marking the bit positions whose
    copies were not unanimous. Those are the positions the code actually repaired, and
    reporting them is what lets the demonstration show the correction working rather
    than merely claiming it.

    :raises RedundancyError: the encoded length is not a whole number of copies, which
        means the payload was truncated or the factor is wrong.
    """
    if not isinstance(encoded, (bytes, bytearray, memoryview)):
        raise RedundancyError(
            f"encoded must be bytes-like, got {type(encoded).__name__}"
        )
    count = validate_factor(factor)
    payload = bytes(encoded)

    if not payload:
        return b"", np.zeros(0, dtype=bool)
    if len(payload) % count != 0:
        raise RedundancyError(
            f"the encoded payload is {len(payload)} bytes, which is not a whole "
            f"number of {count} copies; it is truncated, or the recorded factor is "
            f"wrong"
        )

    if count == 1:
        return payload, np.zeros(len(payload) * 8, dtype=bool)

    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    copies = bits.reshape(count, -1)

    votes = copies.sum(axis=0)
    # Odd factor, so this is a strict majority with no tie possible.
    recovered = (votes * 2 > count).astype(np.uint8)
    disagreed = (votes != 0) & (votes != count)

    return np.packbits(recovered).tobytes(), disagreed
