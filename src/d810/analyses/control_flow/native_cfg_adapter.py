"""Convert portable native flow facts into semantic-closure CFG input."""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.native_semantic_closure import (
    NativeBlock,
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
    NativeTerminalKind,
)
from d810.core.typing import Collection, Mapping


@dataclass(frozen=True, slots=True)
class NativeFlowBlockFact:
    start_ea: int
    end_ea: int
    successor_eas: tuple[int, ...] = ()
    direct_branch_target_ea: int | None = None
    is_call_tail: bool = False
    is_conditional_jump_tail: bool = False
    is_return_tail: bool = False
    is_indirect_jump_tail: bool = False
    terminal_instruction_ea: int | None = None
    force_stop: bool = False
    cut_edges: tuple[NativeEdge, ...] = ()


def needs_native_flow_decode(fact: NativeFlowBlockFact | None) -> bool:
    """Treat incomplete FlowChart rows as requiring native re-decode."""
    if fact is None or int(fact.end_ea) <= int(fact.start_ea):
        return True
    if fact.force_stop:
        terminal_instruction_ea = fact.terminal_instruction_ea
        if terminal_instruction_ea is None:
            return False
        return any(
            edge.source_instruction_ea is not None
            and int(fact.start_ea)
            <= int(edge.source_instruction_ea)
            < int(terminal_instruction_ea)
            for edge in fact.cut_edges
        )
    if fact.is_indirect_jump_tail or fact.is_return_tail:
        return False
    successors = tuple(dict.fromkeys(int(ea) for ea in fact.successor_eas))
    if fact.is_conditional_jump_tail:
        return bool(
            len(successors) != 2
            or fact.direct_branch_target_ea is None
            or int(fact.direct_branch_target_ea) not in successors
        )
    if (
        len(successors) == 1
        and not fact.is_call_tail
        and fact.direct_branch_target_ea is None
        and successors[0] != int(fact.end_ea)
    ):
        return True
    return bool(
        len(successors) == 2
        and (
            fact.direct_branch_target_ea is None
            or int(fact.direct_branch_target_ea) not in successors
        )
    )


def can_decode_proven_native_successor(
    *,
    is_code: bool,
    owner_func_ea: int | None,
    requested_func_ea: int,
    resolver_proven_unmarked: bool = False,
) -> bool:
    """Admit executable direct successors unless IDA assigns another owner."""
    return bool(
        (is_code or resolver_proven_unmarked)
        and (owner_func_ea is None or int(owner_func_ea) == int(requested_func_ea))
    )


def has_native_semantic_boundary(
    *,
    resolver_cut: bool,
    is_return: bool,
    is_indirect_jump: bool,
    is_call: bool,
    direct_branch_target_ea: int | None,
    has_stop_feature: bool,
) -> bool:
    """Whether native instruction semantics, rather than IDA partitioning, end a block."""
    return bool(
        resolver_cut
        or is_return
        or is_indirect_jump
        or has_stop_feature
        or (direct_branch_target_ea is not None and not is_call)
    )


def is_native_direct_control_operand(
    *,
    operand_is_near: bool,
    is_call: bool,
    is_basic_block_end: bool,
    has_stop_feature: bool,
) -> bool:
    """Reject code-looking data operands unless the instruction controls flow."""
    return bool(operand_is_near and (is_call or is_basic_block_end or has_stop_feature))


def select_visited_native_flow_facts(
    facts_by_start_ea: Mapping[int, NativeFlowBlockFact],
    *,
    visited_entry_eas: Collection[int],
) -> tuple[NativeFlowBlockFact, ...]:
    """Select only facts reached while expanding resolver-proven seeds."""
    return tuple(
        facts_by_start_ea[entry_ea]
        for entry_ea in sorted({int(ea) for ea in visited_entry_eas})
        if entry_ea in facts_by_start_ea
    )


def traversable_native_successor_eas(
    fact: NativeFlowBlockFact,
) -> tuple[int, ...]:
    """Exclude a direct call target while retaining its continuation."""
    successors = tuple(dict.fromkeys(int(ea) for ea in fact.successor_eas))
    if not fact.is_call_tail or fact.direct_branch_target_ea is None:
        return successors
    direct_call_target_ea = int(fact.direct_branch_target_ea)
    return tuple(ea for ea in successors if ea != direct_call_target_ea)


def _outgoing_edges(fact: NativeFlowBlockFact) -> tuple[NativeEdge, ...]:
    if fact.is_return_tail:
        return ()
    if fact.force_stop or fact.is_indirect_jump_tail:
        cut_edges = fact.cut_edges
        if fact.is_indirect_jump_tail and not cut_edges:
            if fact.terminal_instruction_ea is None:
                raise ValueError(
                    "native indirect tail requires an exact instruction EA"
                )
            cut_edges = (
                NativeEdge(
                    NativeEdgeKind.INDIRECT,
                    resolver_proven=False,
                    provenance="native_indirect_without_resolver",
                    source_instruction_ea=int(fact.terminal_instruction_ea),
                ),
            )
        for edge in cut_edges:
            if (
                edge.kind is not NativeEdgeKind.INDIRECT
                or edge.source_instruction_ea is None
                or (edge.resolver_proven and edge.target_ea is None)
            ):
                raise ValueError(
                    "cut edges must be indirect transfers with an exact "
                    "source EA and every proven transfer must name a target"
                )
        return tuple(cut_edges)
    successors = traversable_native_successor_eas(fact)
    if len(successors) > 2:
        raise ValueError(
            f"native flow fact at 0x{int(fact.start_ea):X} has more than two successors"
        )
    if len(successors) == 2:
        branch_target = fact.direct_branch_target_ea
        if branch_target is None or int(branch_target) not in successors:
            raise ValueError(
                "conditional flow fact at "
                f"0x{int(fact.start_ea):X} lacks a unique branch target: "
                f"end=0x{int(fact.end_ea):X} "
                f"successors={tuple(hex(ea) for ea in successors)} "
                f"direct_target={None if branch_target is None else hex(int(branch_target))} "
                f"force_stop={fact.force_stop} "
                f"indirect={fact.is_indirect_jump_tail} "
                f"terminal={None if fact.terminal_instruction_ea is None else hex(int(fact.terminal_instruction_ea))}"
            )
        false_target = next(
            target for target in successors if target != int(branch_target)
        )
        return (
            NativeEdge(
                NativeEdgeKind.CONDITIONAL_TRUE,
                int(branch_target),
                source_instruction_ea=fact.terminal_instruction_ea,
            ),
            NativeEdge(
                NativeEdgeKind.CONDITIONAL_FALSE,
                false_target,
                source_instruction_ea=fact.terminal_instruction_ea,
            ),
        )
    if len(successors) == 1:
        kind = (
            NativeEdgeKind.DIRECT_JUMP
            if fact.direct_branch_target_ea == successors[0] and not fact.is_call_tail
            else NativeEdgeKind.FALLTHROUGH
        )
        return (
            NativeEdge(
                kind,
                successors[0],
                source_instruction_ea=fact.terminal_instruction_ea,
            ),
        )
    return ()


def build_native_cfg_from_flow_facts(
    facts: tuple[NativeFlowBlockFact, ...],
    *,
    excluded_entry_eas: Collection[int] = (),
    retained_entry_eas: Collection[int] = (),
) -> NativeCfg:
    """Build a fail-closed CFG while retaining explicitly requested seeds."""
    excluded = {int(ea) for ea in excluded_entry_eas}
    retained = {int(ea) for ea in retained_entry_eas}
    blocks = {}
    for fact in sorted(facts, key=lambda row: int(row.start_ea)):
        start_ea = int(fact.start_ea)
        if int(fact.end_ea) <= start_ea:
            continue
        if start_ea in excluded and start_ea not in retained:
            continue
        terminal = NativeTerminalKind.NONE
        if fact.is_return_tail:
            terminal = NativeTerminalKind.RETURN
        elif fact.force_stop or fact.is_indirect_jump_tail:
            terminal = NativeTerminalKind.STOP
        blocks[start_ea] = NativeBlock(
            start_ea=start_ea,
            end_ea=int(fact.end_ea),
            outgoing_edges=_outgoing_edges(fact),
            terminal=terminal,
        )
    return NativeCfg(blocks)


__all__ = [
    "NativeFlowBlockFact",
    "build_native_cfg_from_flow_facts",
    "can_decode_proven_native_successor",
    "has_native_semantic_boundary",
    "is_native_direct_control_operand",
    "needs_native_flow_decode",
    "select_visited_native_flow_facts",
    "traversable_native_successor_eas",
]
