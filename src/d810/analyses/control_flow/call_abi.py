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


def project_detached_call_stack_point(
    *,
    native_spd: int,
    canonical_spd: int,
    route_call_delta: int,
) -> int | None:
    """Merge native and detached-route stack evidence exactly once.

    IDA may report the canonical function-frame SPD for a call discovered only
    through a detached route, in which case the raw PREOPT push depth completes
    the coordinate.  It may instead already include that push depth.  Those are
    the only two consistent observations; a third value is conflicting evidence
    and must not be projected into Hex-Rays' transient stack-point table.
    """
    native = int(native_spd)
    canonical = int(canonical_spd)
    delta = int(route_call_delta)
    if delta > 0:
        return None
    projected = canonical + delta
    if native == canonical:
        return projected
    if native == projected:
        return native
    return None


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
    expected_offsets = (
        tuple(range(-stack_argument_bytes, 0, word_size)) if word_size > 0 else ()
    )
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
    "project_detached_call_stack_point",
    "StackCallAbiEvidence",
    "StackCallAbiProof",
    "prove_three_argument_callee_purged_call",
]
