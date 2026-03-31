from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.cfg.flow.terminal_return import TerminalLoweringAction


class CarrierBucket(str, enum.Enum):
    """Semantic bucket for a suffix group's carrier profile."""

    BENIGN_SHARED_SUFFIX = "benign_shared_suffix"
    SUFFIX_AMBIGUOUS = "suffix_ambiguous"
    NEEDS_DIRECT_LOWERING = "needs_direct_lowering"


@dataclass(frozen=True, slots=True)
class SuffixGroupDecision:
    """Per-suffix-group grouped terminal-corridor decision."""

    shared_entry: int
    return_block: int
    suffix_serials: tuple[int, ...]
    handler_entries: tuple[int, ...]
    handler_count: int
    carrier_source_kinds: tuple[str, ...]
    has_state_const_carrier: bool
    carrier_bucket: CarrierBucket
    proof_resolved_count: int
    proof_unresolved_count: int
    corridor_length: int
    clonable: bool
    should_emit: bool
    rejection_reasons: tuple[str, ...]
    dtl_anchor_serials: tuple[int, ...] = ()


def classify_carrier_bucket(carrier_kinds: tuple[str, ...]) -> CarrierBucket:
    kinds_set = set(carrier_kinds)
    if "state_const" in kinds_set:
        return CarrierBucket.NEEDS_DIRECT_LOWERING

    ambiguous_kinds = {"unknown", "expr", "cursor_or_ptr"}
    if kinds_set & ambiguous_kinds:
        return CarrierBucket.SUFFIX_AMBIGUOUS

    return CarrierBucket.BENIGN_SHARED_SUFFIX


def compute_suffix_group_decision(
    *,
    forward_entries,
    corridor_info,
    semantic_action: TerminalLoweringAction,
) -> SuffixGroupDecision:
    handler_entries = tuple(sorted({int(entry.handler_entry) for entry in forward_entries}))
    handler_count = len(handler_entries)

    carrier_kinds = tuple(
        sorted({entry.carrier_source_kind.value for entry in forward_entries})
    )
    has_state_const = any(
        entry.carrier_source_kind.value == "state_const"
        for entry in forward_entries
    )

    proof_resolved = sum(
        1 for entry in forward_entries if entry.proof_status == "resolved"
    )
    proof_unresolved = sum(
        1 for entry in forward_entries if entry.proof_status == "unresolved"
    )

    carrier_bucket = classify_carrier_bucket(carrier_kinds)

    rejection_reasons: list[str] = []
    if semantic_action != TerminalLoweringAction.PRIVATE_TERMINAL_SUFFIX:
        rejection_reasons.append(
            "semantic_action=%s (need PRIVATE_TERMINAL_SUFFIX)"
            % semantic_action.value
        )
    if not corridor_info.clonable:
        rejection_reasons.append("corridor not clonable")
    if handler_count < 2:
        rejection_reasons.append("handler_count=%d < 2" % handler_count)
    if proof_resolved > 0:
        rejection_reasons.append(
            "proof_resolved=%d > 0 (some already resolved)" % proof_resolved
        )
    if carrier_bucket == CarrierBucket.BENIGN_SHARED_SUFFIX:
        rejection_reasons.append(
            "carrier_bucket=benign_shared_suffix (all real_const, structurally adequate)"
        )
    if carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING:
        rejection_reasons.append(
            "carrier_bucket=needs_direct_lowering (has state_const — dispatcher semantic leak)"
        )

    dtl_anchors = tuple(
        sorted(
            int(entry.handler_entry) for entry in forward_entries if entry.requires_dtl
        )
    )

    return SuffixGroupDecision(
        shared_entry=int(corridor_info.shared_entry),
        return_block=int(corridor_info.return_block),
        suffix_serials=tuple(int(serial) for serial in corridor_info.suffix_serials),
        handler_entries=handler_entries,
        handler_count=handler_count,
        carrier_source_kinds=carrier_kinds,
        has_state_const_carrier=has_state_const,
        carrier_bucket=carrier_bucket,
        proof_resolved_count=proof_resolved,
        proof_unresolved_count=proof_unresolved,
        corridor_length=int(corridor_info.corridor_length),
        clonable=bool(corridor_info.clonable),
        should_emit=len(rejection_reasons) == 0,
        rejection_reasons=tuple(rejection_reasons),
        dtl_anchor_serials=dtl_anchors,
    )


def select_direct_terminal_lowering_anchors(
    *,
    decision: SuffixGroupDecision,
    anchors: tuple[int, ...],
) -> tuple[int, ...]:
    if decision.carrier_bucket == CarrierBucket.NEEDS_DIRECT_LOWERING:
        return tuple(int(anchor) for anchor in anchors)
    if decision.dtl_anchor_serials:
        return tuple(int(anchor) for anchor in decision.dtl_anchor_serials)
    return ()


__all__ = [
    "CarrierBucket",
    "SuffixGroupDecision",
    "classify_carrier_bucket",
    "compute_suffix_group_decision",
    "select_direct_terminal_lowering_anchors",
]
