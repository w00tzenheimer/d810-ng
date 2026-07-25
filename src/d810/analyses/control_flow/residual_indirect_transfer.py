"""Pure proof gate for a residual two-way indirect-transfer fragment.

The Hex-Rays adapter normalizes a snippet MBA into
:class:`ResidualTransferCandidate`.  This layer deliberately knows nothing
about IDA: it validates only complete, already-evaluated microcode facts and
returns an immutable proof or abstains.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResidualTransferCandidate:
    """Normalized facts required to prove one conditional indirect transfer."""

    fragment_start_ea: int
    fragment_end_ea: int
    selector_stack_offset: int | None
    condition_code: int | None
    true_pointer_value: int | None
    false_pointer_value: int | None
    additive_base: int | None
    envelope_start_ea: int
    envelope_end_ea: int
    #: The selector may be a stack cell or the register-resident state variable.
    #: Exactly one identity is required by the proof gate.
    selector_register: int | None = None
    #: Pointer arithmetic width proven by the backend's active database.
    address_bits: int = 64


@dataclass(frozen=True, slots=True)
class ResidualIndirectTransferProof:
    """Complete microcode-level proof suitable for condition-preserving delivery."""

    fragment_start_ea: int
    fragment_end_ea: int
    selector_stack_offset: int | None
    condition_code: int
    true_target_ea: int
    false_target_ea: int
    selector_register: int | None = None
    resolver_kind: str = "residual_microcode"


@dataclass(frozen=True, slots=True)
class ResidualStackStateCandidate:
    """Normalized proof inputs for a stack-ferried conditional state.

    The orphan fragment proves that it reloads ``selector_stack_offset`` before
    an indirect transfer.  A separate, live microcode recovery proves that the
    prologue predicate stores one of two state constants into that same cell
    and maps those constants to dispatcher handlers.
    """

    fragment_start_ea: int
    fragment_end_ea: int
    selector_stack_offset: int | None
    predicate_ea: int | None
    predicate_condition_code: int | None
    true_state: int | None
    false_state: int | None
    state_targets: tuple[tuple[int, int], ...]
    envelope_start_ea: int
    envelope_end_ea: int


@dataclass(frozen=True, slots=True)
class ResidualStackStateTransferProof:
    """Proven prologue predicate routed to two recovered handler labels."""

    fragment_start_ea: int
    fragment_end_ea: int
    selector_stack_offset: int
    predicate_ea: int
    condition_code: int
    true_target_ea: int
    false_target_ea: int
    resolver_kind: str = "residual_stack_state"


def _in_envelope(ea: int, start: int, end: int) -> bool:
    return int(start) <= int(ea) < int(end)


def validate_residual_transfer(
    candidate: ResidualTransferCandidate,
) -> ResidualIndirectTransferProof | None:
    """Return a two-way proof only for fully-resolved, in-envelope facts.

    A candidate reaches this function only after a Hex-Rays snippet has shown a
    stack selector, conditional branch, two pointer loads, and additive target
    expression.  This final pure gate keeps malformed or ambiguous facts from
    reaching native byte-patch delivery.
    """
    if int(candidate.fragment_end_ea) <= int(candidate.fragment_start_ea):
        return None
    if int(candidate.envelope_end_ea) <= int(candidate.envelope_start_ea):
        return None
    values = (
        candidate.condition_code,
        candidate.true_pointer_value,
        candidate.false_pointer_value,
        candidate.additive_base,
    )
    if any(value is None for value in values):
        return None
    has_stack_selector = candidate.selector_stack_offset is not None
    has_register_selector = candidate.selector_register is not None
    if has_stack_selector == has_register_selector:
        return None
    if has_stack_selector and int(candidate.selector_stack_offset) < 0:
        return None
    if has_register_selector and int(candidate.selector_register) < 0:
        return None
    if not 0 <= int(candidate.condition_code) <= 0xF:
        return None

    if int(candidate.address_bits) not in (32, 64):
        return None
    mask = (1 << int(candidate.address_bits)) - 1
    true_target = (
        int(candidate.true_pointer_value) + int(candidate.additive_base)
    ) & mask
    false_target = (
        int(candidate.false_pointer_value) + int(candidate.additive_base)
    ) & mask
    if true_target == false_target:
        return None
    if not _in_envelope(
        true_target,
        candidate.envelope_start_ea,
        candidate.envelope_end_ea,
    ):
        return None
    if not _in_envelope(
        false_target,
        candidate.envelope_start_ea,
        candidate.envelope_end_ea,
    ):
        return None
    return ResidualIndirectTransferProof(
        fragment_start_ea=int(candidate.fragment_start_ea),
        fragment_end_ea=int(candidate.fragment_end_ea),
        selector_stack_offset=(
            int(candidate.selector_stack_offset) if has_stack_selector else None
        ),
        condition_code=int(candidate.condition_code),
        true_target_ea=true_target,
        false_target_ea=false_target,
        selector_register=(
            int(candidate.selector_register) if has_register_selector else None
        ),
    )


def validate_stack_state_transfer(
    candidate: ResidualStackStateCandidate,
) -> ResidualStackStateTransferProof | None:
    """Route two prologue state constants through an unambiguous state map.

    This accepts no inferred state values: both predicate arms, the shared
    stack-cell identity, and one in-envelope target for each state must already
    have been recovered from microcode.
    """
    if int(candidate.fragment_end_ea) <= int(candidate.fragment_start_ea):
        return None
    if int(candidate.envelope_end_ea) <= int(candidate.envelope_start_ea):
        return None
    values = (
        candidate.selector_stack_offset,
        candidate.predicate_ea,
        candidate.predicate_condition_code,
        candidate.true_state,
        candidate.false_state,
    )
    if any(value is None for value in values):
        return None
    if int(candidate.selector_stack_offset) < 0:
        return None
    if int(candidate.predicate_ea) <= 0:
        return None
    if not 0 <= int(candidate.predicate_condition_code) <= 0xF:
        return None

    routes: dict[int, int] = {}
    for state, target in candidate.state_targets:
        key = int(state) & 0xFFFFFFFFFFFFFFFF
        value = int(target) & 0xFFFFFFFFFFFFFFFF
        if key in routes and routes[key] != value:
            return None
        routes[key] = value
    true_target = routes.get(int(candidate.true_state) & 0xFFFFFFFFFFFFFFFF)
    false_target = routes.get(int(candidate.false_state) & 0xFFFFFFFFFFFFFFFF)
    if true_target is None or false_target is None or true_target == false_target:
        return None
    if not _in_envelope(
        true_target,
        candidate.envelope_start_ea,
        candidate.envelope_end_ea,
    ):
        return None
    if not _in_envelope(
        false_target,
        candidate.envelope_start_ea,
        candidate.envelope_end_ea,
    ):
        return None
    return ResidualStackStateTransferProof(
        fragment_start_ea=int(candidate.fragment_start_ea),
        fragment_end_ea=int(candidate.fragment_end_ea),
        selector_stack_offset=int(candidate.selector_stack_offset),
        predicate_ea=int(candidate.predicate_ea),
        condition_code=int(candidate.predicate_condition_code),
        true_target_ea=true_target,
        false_target_ea=false_target,
    )


__all__ = [
    "ResidualIndirectTransferProof",
    "ResidualStackStateCandidate",
    "ResidualStackStateTransferProof",
    "ResidualTransferCandidate",
    "validate_stack_state_transfer",
    "validate_residual_transfer",
]
