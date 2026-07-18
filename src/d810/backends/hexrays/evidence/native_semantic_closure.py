"""Lift IDA native flow into the portable semantic-closure CFG model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_ua
import idaapi

from d810.analyses.control_flow.native_cfg_adapter import (
    NativeFlowBlockFact,
    build_native_cfg_from_flow_facts,
    can_decode_proven_native_successor,
    has_native_semantic_boundary,
    is_native_direct_control_operand,
    needs_native_flow_decode,
    select_visited_native_flow_facts,
    traversable_native_successor_eas,
)
from d810.analyses.control_flow.native_semantic_closure import (
    NativeCfg,
    NativeEdge,
    NativeEdgeKind,
)
from d810.core.typing import Collection, Mapping


class NativeCfgDecodeAbstentionReason(str, Enum):
    """Reasons native decoding stops without producing a flow fact."""

    NON_CODE_OR_FOREIGN_FUNCTION = "non_code_or_foreign_function"
    DECODE_FAILED = "decode_failed"
    INSTRUCTION_LIMIT_REACHED = "instruction_limit_reached"


@dataclass(frozen=True, slots=True)
class NativeCfgDecodeAbstention:
    """One native-EA-anchored failure to decode a requested CFG block."""

    reason: NativeCfgDecodeAbstentionReason
    entry_ea: int
    cursor_ea: int
    requested_func_ea: int
    owner_func_ea: int | None = None


@dataclass(frozen=True, slots=True)
class NativeSemanticCfgResult:
    """Portable native CFG and explicit native decode abstentions."""

    cfg: NativeCfg
    abstentions: tuple[NativeCfgDecodeAbstention, ...]


def _owner_func_ea(ea: int) -> int | None:
    owner = ida_funcs.get_func(int(ea))
    return None if owner is None else int(owner.start_ea)


def _is_code(ea: int) -> bool:
    return bool(ida_bytes.is_code(ida_bytes.get_full_flags(int(ea))))


def _cut_edges_for_range(
    start_ea: int,
    end_ea: int,
    resolver_cut_eas: Collection[int],
    resolver_target_eas_by_source: Mapping[int, Collection[int]],
) -> tuple[NativeEdge, ...]:
    edges = []
    for source_ea in sorted(
        int(candidate_ea)
        for candidate_ea in resolver_cut_eas
        if int(start_ea) <= int(candidate_ea) < int(end_ea)
    ):
        targets = tuple(
            dict.fromkeys(
                int(target_ea)
                for target_ea in resolver_target_eas_by_source.get(source_ea, ())
            )
        )
        if targets:
            edges.extend(
                NativeEdge(
                    NativeEdgeKind.INDIRECT,
                    target_ea,
                    resolver_proven=True,
                    provenance="resolver_proven_native_cut",
                    source_instruction_ea=source_ea,
                )
                for target_ea in targets
            )
        else:
            edges.append(
                NativeEdge(
                    NativeEdgeKind.INDIRECT,
                    provenance="ambiguous_resolver_native_cut",
                    source_instruction_ea=source_ea,
                )
            )
    return tuple(edges)


def _decode_missing_flow_block(
    function: ida_funcs.func_t,
    *,
    start_ea: int,
    resolver_cut_eas: Collection[int],
    resolver_target_eas_by_source: Mapping[int, Collection[int]],
    resolver_proven_unmarked: bool,
    abstentions: list[NativeCfgDecodeAbstention],
) -> NativeFlowBlockFact | None:
    start_ea = int(start_ea)
    requested_func_ea = int(function.start_ea)
    owner_func_ea = _owner_func_ea(start_ea)
    if not can_decode_proven_native_successor(
        is_code=_is_code(start_ea),
        owner_func_ea=owner_func_ea,
        requested_func_ea=requested_func_ea,
        resolver_proven_unmarked=resolver_proven_unmarked,
    ):
        abstentions.append(
            NativeCfgDecodeAbstention(
                NativeCfgDecodeAbstentionReason.NON_CODE_OR_FOREIGN_FUNCTION,
                entry_ea=start_ea,
                cursor_ea=start_ea,
                requested_func_ea=requested_func_ea,
                owner_func_ea=owner_func_ea,
            )
        )
        return None

    normalized_resolver_cut_eas = {int(source_ea) for source_ea in resolver_cut_eas}
    current_ea = start_ea
    for _instruction_count in range(10000):
        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, current_ea))
        if size <= 0:
            abstentions.append(
                NativeCfgDecodeAbstention(
                    NativeCfgDecodeAbstentionReason.DECODE_FAILED,
                    entry_ea=start_ea,
                    cursor_ea=current_ea,
                    requested_func_ea=requested_func_ea,
                    owner_func_ea=_owner_func_ea(current_ea),
                )
            )
            return None

        next_ea = current_ea + size
        instruction_features = int(instruction.get_canon_feature())
        is_call = bool(ida_idp.is_call_insn(instruction))
        is_basic_block_end = bool(ida_idp.is_basic_block_end(instruction, False))
        has_stop_feature = bool(instruction_features & int(ida_idp.CF_STOP))
        direct_target_ea = None
        if is_native_direct_control_operand(
            operand_is_near=(
                int(instruction.ops[0].type) in {int(idaapi.o_near), int(idaapi.o_far)}
            ),
            is_call=is_call,
            is_basic_block_end=is_basic_block_end,
            has_stop_feature=has_stop_feature,
        ):
            direct_target_ea = int(instruction.ops[0].addr)
        is_conditional_jump = bool(
            direct_target_ea is not None and not is_call and not has_stop_feature
        )

        force_stop = current_ea in normalized_resolver_cut_eas
        is_return = bool(ida_idp.is_ret_insn(instruction, 0))
        is_indirect = bool(ida_idp.is_indirect_jump_insn(instruction))
        if force_stop or is_return or is_indirect:
            return NativeFlowBlockFact(
                start_ea=start_ea,
                end_ea=next_ea,
                is_return_tail=is_return,
                is_indirect_jump_tail=is_indirect,
                terminal_instruction_ea=current_ea,
                force_stop=force_stop,
                cut_edges=_cut_edges_for_range(
                    current_ea,
                    next_ea,
                    normalized_resolver_cut_eas,
                    resolver_target_eas_by_source,
                ),
            )

        if has_native_semantic_boundary(
            resolver_cut=force_stop,
            is_return=is_return,
            is_indirect_jump=is_indirect,
            is_call=is_call,
            direct_branch_target_ea=direct_target_ea,
            has_stop_feature=has_stop_feature,
        ):
            if direct_target_ea is None:
                return NativeFlowBlockFact(
                    start_ea=start_ea,
                    end_ea=next_ea,
                    terminal_instruction_ea=current_ea,
                    force_stop=True,
                )
            successors = (direct_target_ea,)
            if ida_funcs.func_contains(function, next_ea) and (
                is_conditional_jump
                or ida_bytes.is_flow(ida_bytes.get_full_flags(next_ea))
            ):
                successors += (next_ea,)
            return NativeFlowBlockFact(
                start_ea=start_ea,
                end_ea=next_ea,
                successor_eas=successors,
                direct_branch_target_ea=direct_target_ea,
                is_conditional_jump_tail=is_conditional_jump,
            )

        next_owner_func_ea = _owner_func_ea(next_ea)
        if not can_decode_proven_native_successor(
            is_code=_is_code(next_ea),
            owner_func_ea=next_owner_func_ea,
            requested_func_ea=requested_func_ea,
            resolver_proven_unmarked=True,
        ):
            abstentions.append(
                NativeCfgDecodeAbstention(
                    NativeCfgDecodeAbstentionReason.NON_CODE_OR_FOREIGN_FUNCTION,
                    entry_ea=start_ea,
                    cursor_ea=next_ea,
                    requested_func_ea=requested_func_ea,
                    owner_func_ea=next_owner_func_ea,
                )
            )
            return NativeFlowBlockFact(
                start_ea=start_ea,
                end_ea=next_ea,
                force_stop=True,
            )
        current_ea = next_ea

    abstentions.append(
        NativeCfgDecodeAbstention(
            NativeCfgDecodeAbstentionReason.INSTRUCTION_LIMIT_REACHED,
            entry_ea=start_ea,
            cursor_ea=current_ea,
            requested_func_ea=requested_func_ea,
            owner_func_ea=_owner_func_ea(current_ea),
        )
    )
    return None


def _flowchart_facts(
    function: ida_funcs.func_t,
    resolver_cut_eas: Collection[int],
    resolver_target_eas_by_source: Mapping[int, Collection[int]],
) -> dict[int, NativeFlowBlockFact]:
    normalized_resolver_cut_eas = {int(source_ea) for source_ea in resolver_cut_eas}
    facts_by_start_ea = {}
    for flow_block in ida_gdl.FlowChart(function):
        start_ea = int(flow_block.start_ea)
        end_ea = int(flow_block.end_ea)
        tail_ea = int(ida_bytes.prev_head(end_ea, start_ea))
        instruction = ida_ua.insn_t()
        decoded = (
            tail_ea != int(idaapi.BADADDR)
            and int(ida_ua.decode_insn(instruction, tail_ea)) > 0
        )
        instruction_features = int(instruction.get_canon_feature()) if decoded else 0
        is_call_tail = bool(decoded and ida_idp.is_call_insn(instruction))
        is_basic_block_end = bool(
            decoded and ida_idp.is_basic_block_end(instruction, False)
        )
        has_stop_feature = bool(instruction_features & int(ida_idp.CF_STOP))
        direct_target_ea = None
        if decoded and is_native_direct_control_operand(
            operand_is_near=(
                int(instruction.ops[0].type) in {int(idaapi.o_near), int(idaapi.o_far)}
            ),
            is_call=is_call_tail,
            is_basic_block_end=is_basic_block_end,
            has_stop_feature=has_stop_feature,
        ):
            direct_target_ea = int(instruction.ops[0].addr)
        is_conditional_jump_tail = bool(
            decoded
            and direct_target_ea is not None
            and not is_call_tail
            and not has_stop_feature
        )
        facts_by_start_ea[start_ea] = NativeFlowBlockFact(
            start_ea=start_ea,
            end_ea=end_ea,
            successor_eas=tuple(
                int(successor.start_ea) for successor in flow_block.succs()
            ),
            direct_branch_target_ea=direct_target_ea,
            is_call_tail=is_call_tail,
            is_conditional_jump_tail=is_conditional_jump_tail,
            is_return_tail=bool(decoded and ida_idp.is_ret_insn(instruction, 0)),
            is_indirect_jump_tail=bool(
                decoded and ida_idp.is_indirect_jump_insn(instruction)
            ),
            terminal_instruction_ea=tail_ea if decoded else None,
            force_stop=(
                not decoded
                or any(
                    start_ea <= cut_ea < end_ea
                    for cut_ea in normalized_resolver_cut_eas
                )
            ),
            cut_edges=_cut_edges_for_range(
                start_ea,
                end_ea,
                normalized_resolver_cut_eas,
                resolver_target_eas_by_source,
            ),
        )
    return facts_by_start_ea


def build_native_semantic_cfg(
    function: ida_funcs.func_t,
    *,
    live_native_eas: Collection[int],
    seed_eas: Collection[int],
    resolver_target_eas_by_source: Mapping[int, Collection[int]],
    resolver_cut_eas: Collection[int] | None = None,
    resolver_proven_unmarked_entry_eas: Collection[int] = (),
) -> NativeSemanticCfgResult:
    """Lift resolver-seeded native flow without exposing live IDA objects.

    ``live_native_eas`` is instruction-backed live ownership supplied by the
    caller. Address-only external frontier placeholders are not live ownership
    and must not appear in that collection.
    """
    live_eas = {int(ea) for ea in live_native_eas}
    seeds = {int(ea) for ea in seed_eas}
    normalized_target_eas_by_source = {
        int(source_ea): tuple(int(target_ea) for target_ea in target_eas)
        for source_ea, target_eas in resolver_target_eas_by_source.items()
    }
    normalized_resolver_cut_eas = (
        tuple(normalized_target_eas_by_source)
        if resolver_cut_eas is None
        else tuple(int(source_ea) for source_ea in resolver_cut_eas)
    )
    proven_unmarked_entries = {
        int(entry_ea) for entry_ea in resolver_proven_unmarked_entry_eas
    }
    facts_by_start_ea = _flowchart_facts(
        function,
        normalized_resolver_cut_eas,
        normalized_target_eas_by_source,
    )
    abstentions = []
    pending = list(seeds)
    visited = set()
    while pending:
        entry_ea = int(pending.pop())
        if entry_ea in visited:
            continue
        visited.add(entry_ea)
        if entry_ea in live_eas and entry_ea not in seeds:
            continue
        fact = facts_by_start_ea.get(entry_ea)
        if needs_native_flow_decode(fact):
            fact = _decode_missing_flow_block(
                function,
                start_ea=entry_ea,
                resolver_cut_eas=normalized_resolver_cut_eas,
                resolver_target_eas_by_source=normalized_target_eas_by_source,
                resolver_proven_unmarked=entry_ea in proven_unmarked_entries,
                abstentions=abstentions,
            )
            if fact is None:
                continue
            facts_by_start_ea[entry_ea] = fact
        if fact is None:
            continue
        if fact.force_stop or fact.is_indirect_jump_tail:
            proven_cut_targets = tuple(
                int(edge.target_ea)
                for edge in fact.cut_edges
                if edge.resolver_proven and edge.target_ea is not None
            )
            proven_unmarked_entries.update(proven_cut_targets)
            pending.extend(proven_cut_targets)
            continue
        if fact.is_return_tail:
            continue
        successors = traversable_native_successor_eas(fact)
        proven_unmarked_entries.update(successors)
        pending.extend(successors)

    cfg = build_native_cfg_from_flow_facts(
        select_visited_native_flow_facts(
            facts_by_start_ea,
            visited_entry_eas=visited,
        ),
        excluded_entry_eas=live_eas,
        retained_entry_eas=seeds,
    )
    return NativeSemanticCfgResult(
        cfg=cfg,
        abstentions=tuple(
            sorted(
                abstentions,
                key=lambda item: (
                    item.entry_ea,
                    item.cursor_ea,
                    item.reason.value,
                    item.owner_func_ea is None,
                    item.owner_func_ea or 0,
                ),
            )
        ),
    )


__all__ = [
    "NativeCfgDecodeAbstention",
    "NativeCfgDecodeAbstentionReason",
    "NativeSemanticCfgResult",
    "build_native_semantic_cfg",
]
