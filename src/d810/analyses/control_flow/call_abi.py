"""Portable proof rules for narrowly-scoped call ABI corrections."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StackCallAbiEvidence:
    """Structural evidence available before Hex-Rays fixes one call type."""

    word_size: int
    outgoing_stack_offsets: tuple[int, ...]
    call_stack_deficit: int | None
    argument_values_proven: bool
    continuation_is_linear: bool
    continuation_reaches_proven_reentry: bool
    caller_stack_adjustment: int | None
    has_authoritative_type: bool


@dataclass(frozen=True, slots=True)
class StackCallAbiProof:
    """Exact fixed-arity callee-purged stack-call proof."""

    argument_count: int
    stack_argument_bytes: int
    callee_purges_stack: bool = True


def prove_three_argument_callee_purged_call(
    evidence: StackCallAbiEvidence,
) -> StackCallAbiProof | None:
    """Prove one three-argument callee-purged call or abstain.

    The deliberately narrow rule requires three complete word-sized outgoing
    stack cells, the matching call-site SP deficit, no caller cleanup, and a
    linear continuation into an independently proven CFG re-entry.  It does
    not infer a convention from push count alone.
    """
    word_size = int(evidence.word_size)
    argument_count = 3
    stack_argument_bytes = argument_count * word_size
    expected_offsets = tuple(
        range(-stack_argument_bytes, 0, word_size)
    ) if word_size > 0 else ()
    offsets = tuple(sorted(int(offset) for offset in evidence.outgoing_stack_offsets))
    if (
        word_size <= 0
        or evidence.has_authoritative_type
        or not evidence.argument_values_proven
        or not evidence.continuation_is_linear
        or not evidence.continuation_reaches_proven_reentry
        or evidence.call_stack_deficit != stack_argument_bytes
        or evidence.caller_stack_adjustment != 0
        or offsets != expected_offsets
    ):
        return None
    return StackCallAbiProof(
        argument_count=argument_count,
        stack_argument_bytes=stack_argument_bytes,
    )


__all__ = [
    "StackCallAbiEvidence",
    "StackCallAbiProof",
    "prove_three_argument_callee_purged_call",
]
