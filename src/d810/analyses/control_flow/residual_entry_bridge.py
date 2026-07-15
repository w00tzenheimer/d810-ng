"""Portable planning for a resolver-proven conditional entry bridge."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class EntryBridgeEvidence:
    """A live-microcode proof that one predicate selects two initial states."""

    predicate_ea: int
    condition_code: int
    predicate_stack_identity: tuple[int, int]
    stack_cell_identity: tuple[int, int]
    taken_state_constant: int
    fallthrough_state_constant: int
    source_store_ea: int
    canonical_stack_cell_identity: tuple[int, int] | None = None
    predicate_block_ea: int | None = None
    taken_arm_entry_ea: int | None = None
    fallthrough_arm_entry_ea: int | None = None
    conditional_tail_ea: int | None = None
    canonical_predicate_stack_identity: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class StateRoutingNode:
    """One resolver-materialized state comparison in the entry path."""

    source_block_ea: int
    patch_window_end_ea: int
    condition_code: int
    compared_state_constant: int
    true_target_ea: int
    false_target_ea: int


@dataclass(frozen=True, slots=True)
class ResidualEntryBridgePlan:
    """A fully proven condition-preserving entry-bridge delivery plan."""

    anchor_ea: int
    condition_code: int
    true_target_ea: int
    false_target_ea: int


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def condition_holds(condition_code: int, value: int, compared: int) -> bool | None:
    """Evaluate one x86 condition over proven 32-bit state constants."""
    unsigned_value = int(value) & 0xFFFFFFFF
    unsigned_compared = int(compared) & 0xFFFFFFFF
    signed_value = _signed32(unsigned_value)
    signed_compared = _signed32(unsigned_compared)
    return {
        2: unsigned_value < unsigned_compared,
        3: unsigned_value >= unsigned_compared,
        4: unsigned_value == unsigned_compared,
        5: unsigned_value != unsigned_compared,
        6: unsigned_value <= unsigned_compared,
        7: unsigned_value > unsigned_compared,
        12: signed_value < signed_compared,
        13: signed_value >= signed_compared,
        14: signed_value <= signed_compared,
        15: signed_value > signed_compared,
    }.get(int(condition_code))


def plan_residual_entry_bridge(
    *,
    evidence: EntryBridgeEvidence,
    initial_state: int,
    routing_nodes: Sequence[StateRoutingNode],
    live_state_targets: Mapping[int, int],
    residual_state_targets: Mapping[int, int],
    required_patch_size: int = 11,
) -> ResidualEntryBridgePlan | None:
    """Return a plan only when both bridge arms and the entry leaf are proven.

    The state-routing path is followed only with a concrete initial state.  A
    disconnected graph, duplicate source, unsupported condition, cycle, or too
    small patch window fails closed.
    """
    true_target = live_state_targets.get(int(evidence.taken_state_constant))
    false_target = residual_state_targets.get(int(evidence.fallthrough_state_constant))
    if true_target is None or false_target is None or true_target == false_target:
        return None
    by_source: dict[int, StateRoutingNode] = {}
    for node in routing_nodes:
        source = int(node.source_block_ea)
        if source in by_source:
            return None
        by_source[source] = node
    if not by_source:
        return None
    sources = frozenset(by_source)
    child_sources = {
        int(target)
        for node in by_source.values()
        for target in (node.true_target_ea, node.false_target_ea)
        if int(target) in sources
    }
    roots = sources - child_sources
    if len(roots) != 1:
        return None
    current = next(iter(roots))
    seen: set[int] = set()
    while current not in seen:
        seen.add(current)
        node = by_source[current]
        branch = condition_holds(
            node.condition_code, initial_state, node.compared_state_constant
        )
        if branch is None:
            return None
        selected_target = node.true_target_ea if branch else node.false_target_ea
        if int(selected_target) not in by_source:
            if (
                int(node.patch_window_end_ea) - int(node.source_block_ea)
                < int(required_patch_size)
            ):
                return None
            return ResidualEntryBridgePlan(
                anchor_ea=int(node.source_block_ea),
                condition_code=int(evidence.condition_code),
                true_target_ea=int(true_target),
                false_target_ea=int(false_target),
            )
        current = int(selected_target)
    return None


__all__ = [
    "EntryBridgeEvidence",
    "ResidualEntryBridgePlan",
    "StateRoutingNode",
    "condition_holds",
    "plan_residual_entry_bridge",
]
