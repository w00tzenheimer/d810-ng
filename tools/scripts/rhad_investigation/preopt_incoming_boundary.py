"""Plan resolver-proven incoming edges for one imported PREOPT union.

This module is deliberately portable and mutation-free.  It classifies only
stable native-EA evidence; the IDA-backed probe binds those EAs to the current
MBA and performs the actual graph edits.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.detached_handler_island import (
    merge_detached_snippet_ranges,
)
from d810.core.typing import Collection, Mapping, Sequence


_MASK32 = 0xFFFFFFFF


class PreoptIncomingBoundaryAbstentionReason(str, Enum):
    """Why otherwise relevant resolver evidence was not selected."""

    CONFLICTING_DIRECT_EVIDENCE = "conflicting_direct_evidence"
    INCOMPLETE_CONDITIONAL_EVIDENCE = "incomplete_conditional_evidence"
    CONFLICTING_CONDITIONAL_EVIDENCE = "conflicting_conditional_evidence"


class PreoptDirectReplayMode(str, Enum):
    """Safe PREOPT mutation shape for one proven direct boundary."""

    ABSTAIN = "abstain"
    TERMINAL_GOTO = "terminal_goto"
    REDIRECT_EDGE = "redirect_edge"
    PRESERVE_CALL = "preserve_call"


def classify_preopt_direct_replay_shape(
    *,
    has_via: bool,
    source_nsucc: int,
    tail_is_call: bool,
    tail_is_goto: bool,
    tail_is_indirect_jump: bool,
    tail_is_closing: bool,
    via_is_adjacent: bool,
    successor_is_via: bool,
) -> PreoptDirectReplayMode:
    """Classify a direct replay without weakening Hex-Rays tail invariants."""
    if has_via:
        if source_nsucc not in (0, 1):
            return PreoptDirectReplayMode.ABSTAIN
        if source_nsucc == 1 and not successor_is_via:
            return PreoptDirectReplayMode.ABSTAIN
        if tail_is_call:
            return (
                PreoptDirectReplayMode.PRESERVE_CALL
                if via_is_adjacent
                else PreoptDirectReplayMode.ABSTAIN
            )
        if source_nsucc == 1 or tail_is_goto:
            return PreoptDirectReplayMode.REDIRECT_EDGE
        if tail_is_indirect_jump or not tail_is_closing:
            return PreoptDirectReplayMode.TERMINAL_GOTO
        return PreoptDirectReplayMode.ABSTAIN
    if source_nsucc == 0 and tail_is_closing and not tail_is_call:
        return PreoptDirectReplayMode.TERMINAL_GOTO
    return PreoptDirectReplayMode.ABSTAIN


@dataclass(frozen=True, slots=True)
class PreoptDirectIncomingBoundary:
    """One exact one-way state route entering the imported union."""

    source_ea: int
    target_ea: int
    state_constant: int
    state_register: int
    via_ea: int | None = None
    requires_literal_state_write: bool = True


@dataclass(frozen=True, slots=True)
class PreoptConditionalIncomingBoundary:
    """One exact live predicate whose one or both arms enter the union."""

    predicate_ea: int
    source_block_ea: int
    true_target_ea: int
    false_target_ea: int
    predicate_register: int | None
    predicate_size: int
    predicate_compare_register: int | None
    predicate_compare_constant: int | None
    state_register: int
    true_state: int
    false_state: int
    true_is_taken: bool
    preserve_live: bool


@dataclass(frozen=True, slots=True)
class PreoptConditionalArmOrientation:
    """Conditional arms oriented to the original PREOPT branch truth value."""

    false_target_ea: int
    true_target_ea: int
    false_state: int
    true_state: int


@dataclass(frozen=True, slots=True)
class PreoptIncomingBoundaryAbstention:
    source_ea: int
    reason: PreoptIncomingBoundaryAbstentionReason


@dataclass(frozen=True, slots=True)
class PreoptIncomingBoundaryPlan:
    direct: tuple[PreoptDirectIncomingBoundary, ...]
    conditional: tuple[PreoptConditionalIncomingBoundary, ...]
    abstentions: tuple[PreoptIncomingBoundaryAbstention, ...]


@dataclass(frozen=True, slots=True)
class PreoptIncomingTargetClosure:
    """Backward handler-owner closure needed to reach imported targets."""

    target_eas: tuple[int, ...]
    ambiguous_source_eas: tuple[int, ...]


def expand_preopt_boundary_target_closure(
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    imported_target_eas: Collection[int],
) -> PreoptIncomingTargetClosure:
    """Walk proven incoming routes backward through unique handler ownership."""
    range_candidates: dict[int, set[tuple[tuple[int, int], ...]]] = {}
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_handler_entry_route"
            or len(transfer.target_eas) != 1
        ):
            continue
        normalized = merge_detached_snippet_ranges(
            tuple(
                (int(start_ea), int(end_ea))
                for start_ea, end_ea in transfer.owned_native_ranges
            )
        )
        if normalized:
            range_candidates.setdefault(int(transfer.target_eas[0]), set()).add(
                normalized
            )
    handler_ranges = {
        target_ea: next(iter(candidates))
        for target_ea, candidates in range_candidates.items()
        if len(candidates) == 1
    }

    needed = {int(target_ea) for target_ea in imported_target_eas}
    ambiguous_sources: set[int] = set()
    changed = True
    while changed:
        changed = False
        for transfer in transfers:
            targets = {int(target_ea) for target_ea in transfer.target_eas}
            if targets.isdisjoint(needed):
                continue
            if transfer.resolver_kind == "residual_state_route_evidence":
                if (
                    transfer.selector_state_constant is None
                    or transfer.selector_state_var_reg is None
                    or len(transfer.target_eas) != 1
                ):
                    continue
                source_eas = (int(transfer.source_jmp_ea),)
            elif transfer.resolver_kind == "conditional_handler_bridge":
                if _conditional_boundary(transfer) is None:
                    continue
                source_eas = (
                    int(transfer.source_block_ea),
                    int(transfer.source_jmp_ea),
                )
            else:
                continue
            owners = {
                handler_ea
                for source_ea in source_eas
                for handler_ea, ranges in handler_ranges.items()
                if any(
                    int(start_ea) <= source_ea < int(end_ea)
                    for start_ea, end_ea in ranges
                )
            }
            if len(owners) > 1:
                ambiguous_sources.add(int(transfer.source_jmp_ea))
                continue
            if len(owners) == 1:
                owner = next(iter(owners))
                if owner not in needed:
                    needed.add(owner)
                    changed = True
    return PreoptIncomingTargetClosure(
        target_eas=tuple(sorted(needed)),
        ambiguous_source_eas=tuple(sorted(ambiguous_sources)),
    )


def orient_preopt_conditional_boundary(
    boundary: PreoptConditionalIncomingBoundary,
) -> PreoptConditionalArmOrientation:
    """Map normalized nonzero arms back to the original branch polarity."""
    if boundary.true_is_taken:
        return PreoptConditionalArmOrientation(
            false_target_ea=boundary.false_target_ea,
            true_target_ea=boundary.true_target_ea,
            false_state=boundary.false_state,
            true_state=boundary.true_state,
        )
    return PreoptConditionalArmOrientation(
        false_target_ea=boundary.true_target_ea,
        true_target_ea=boundary.false_target_ea,
        false_state=boundary.true_state,
        true_state=boundary.false_state,
    )


def exclude_direct_boundaries_with_conditional_source(
    direct: Sequence[PreoptDirectIncomingBoundary],
    conditional: Sequence[PreoptConditionalIncomingBoundary],
    *,
    source_identity_by_ea: Mapping[int, int],
) -> tuple[PreoptDirectIncomingBoundary, ...]:
    """Keep payload predicates atomic when direct evidence names one arm."""
    conditional_identities = {
        int(source_identity_by_ea[row.predicate_ea])
        for row in conditional
        if row.predicate_ea in source_identity_by_ea
    }
    return tuple(
        row
        for row in direct
        if row.source_ea not in source_identity_by_ea
        or int(source_identity_by_ea[row.source_ea]) not in conditional_identities
    )


def exclude_conflicting_direct_boundaries_by_source(
    direct: Sequence[PreoptDirectIncomingBoundary],
    *,
    source_identity_by_ea: Mapping[int, int],
) -> tuple[
    tuple[PreoptDirectIncomingBoundary, ...],
    tuple[int, ...],
]:
    """Reject a whole PREOPT block when direct proofs disagree within it."""
    rows_by_identity: dict[int, set[PreoptDirectIncomingBoundary]] = {}
    for row in direct:
        identity = source_identity_by_ea.get(int(row.source_ea))
        if identity is None:
            continue
        rows_by_identity.setdefault(int(identity), set()).add(row)
    conflicting_identities = {
        identity for identity, rows in rows_by_identity.items() if len(rows) > 1
    }
    conflicts = tuple(
        sorted(
            int(row.source_ea)
            for row in direct
            if source_identity_by_ea.get(int(row.source_ea)) in conflicting_identities
        )
    )
    selected = tuple(
        row
        for row in direct
        if source_identity_by_ea.get(int(row.source_ea)) not in conflicting_identities
    )
    return selected, conflicts


def _conditional_boundary(
    transfer: MaterializedIndirectTransfer,
) -> PreoptConditionalIncomingBoundary | None:
    if (
        transfer.condition_code != 5
        or transfer.true_target_ea is None
        or transfer.false_target_ea is None
        or transfer.predicate_true_state is None
        or transfer.predicate_false_state is None
        or transfer.predicate_true_is_taken is None
        or transfer.predicate_size is None
        or transfer.selector_state_var_reg is None
        or int(transfer.predicate_size) <= 0
    ):
        return None
    true_target_ea = int(transfer.true_target_ea)
    false_target_ea = int(transfer.false_target_ea)
    if true_target_ea == false_target_ea or {true_target_ea, false_target_ea} != {
        int(target_ea) for target_ea in transfer.target_eas
    }:
        return None
    return PreoptConditionalIncomingBoundary(
        predicate_ea=int(transfer.source_jmp_ea),
        source_block_ea=int(transfer.source_block_ea),
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_register=(
            None
            if transfer.predicate_register is None
            else int(transfer.predicate_register)
        ),
        predicate_size=int(transfer.predicate_size),
        predicate_compare_register=(
            None
            if transfer.predicate_compare_register is None
            else int(transfer.predicate_compare_register)
        ),
        predicate_compare_constant=(
            None
            if transfer.predicate_compare_constant is None
            else int(transfer.predicate_compare_constant)
        ),
        state_register=int(transfer.selector_state_var_reg),
        true_state=int(transfer.predicate_true_state) & _MASK32,
        false_state=int(transfer.predicate_false_state) & _MASK32,
        true_is_taken=bool(transfer.predicate_true_is_taken),
        preserve_live=bool(transfer.predicate_preserve_live),
    )


def plan_preopt_incoming_boundaries(
    transfers: Sequence[MaterializedIndirectTransfer],
    *,
    imported_target_eas: Collection[int],
) -> PreoptIncomingBoundaryPlan:
    """Select only unambiguous resolver proofs that enter an imported union."""
    imported_targets = {int(target_ea) for target_ea in imported_target_eas}
    direct_by_source: dict[int, set[PreoptDirectIncomingBoundary]] = {}
    conditional_by_source: dict[int, set[PreoptConditionalIncomingBoundary]] = {}
    incomplete_conditionals: set[int] = set()

    for transfer in transfers:
        transfer_targets = {int(target_ea) for target_ea in transfer.target_eas}
        if transfer_targets.isdisjoint(imported_targets):
            continue
        if transfer.resolver_kind == "residual_state_route_evidence":
            if (
                transfer.selector_state_constant is None
                or transfer.selector_state_var_reg is None
                or len(transfer.target_eas) != 1
            ):
                continue
            source_ea = int(transfer.source_jmp_ea)
            direct_by_source.setdefault(source_ea, set()).add(
                PreoptDirectIncomingBoundary(
                    source_ea=source_ea,
                    target_ea=int(transfer.target_eas[0]),
                    state_constant=(int(transfer.selector_state_constant) & _MASK32),
                    state_register=int(transfer.selector_state_var_reg),
                )
            )
            continue
        if transfer.resolver_kind != "conditional_handler_bridge":
            continue
        source_ea = int(transfer.source_jmp_ea)
        boundary = _conditional_boundary(transfer)
        if boundary is None:
            incomplete_conditionals.add(source_ea)
            continue
        conditional_by_source.setdefault(source_ea, set()).add(boundary)

    direct: list[PreoptDirectIncomingBoundary] = []
    conditional: list[PreoptConditionalIncomingBoundary] = []
    abstentions: list[PreoptIncomingBoundaryAbstention] = []
    for source_ea, candidates in sorted(direct_by_source.items()):
        if len(candidates) == 1:
            direct.append(next(iter(candidates)))
        else:
            abstentions.append(
                PreoptIncomingBoundaryAbstention(
                    source_ea,
                    PreoptIncomingBoundaryAbstentionReason.CONFLICTING_DIRECT_EVIDENCE,
                )
            )
    for source_ea in sorted(set(conditional_by_source) | incomplete_conditionals):
        candidates = conditional_by_source.get(source_ea, set())
        if source_ea in incomplete_conditionals:
            reason = (
                PreoptIncomingBoundaryAbstentionReason.INCOMPLETE_CONDITIONAL_EVIDENCE
            )
        elif len(candidates) != 1:
            reason = (
                PreoptIncomingBoundaryAbstentionReason.CONFLICTING_CONDITIONAL_EVIDENCE
            )
        else:
            conditional.append(next(iter(candidates)))
            continue
        abstentions.append(PreoptIncomingBoundaryAbstention(source_ea, reason))

    return PreoptIncomingBoundaryPlan(
        direct=tuple(sorted(direct, key=lambda row: (row.source_ea, row.target_ea))),
        conditional=tuple(
            sorted(
                conditional,
                key=lambda row: (
                    row.predicate_ea,
                    row.false_target_ea,
                    row.true_target_ea,
                ),
            )
        ),
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda row: (row.source_ea, row.reason.value),
            )
        ),
    )


__all__ = [
    "PreoptConditionalArmOrientation",
    "PreoptConditionalIncomingBoundary",
    "PreoptDirectIncomingBoundary",
    "PreoptIncomingBoundaryAbstention",
    "PreoptIncomingBoundaryAbstentionReason",
    "PreoptIncomingBoundaryPlan",
    "PreoptIncomingTargetClosure",
    "expand_preopt_boundary_target_closure",
    "exclude_conflicting_direct_boundaries_by_source",
    "exclude_direct_boundaries_with_conditional_source",
    "orient_preopt_conditional_boundary",
    "plan_preopt_incoming_boundaries",
]
