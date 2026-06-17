from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.recovered_machine import (
    ExitPathEffectSummary,
    ExitPathEffect,
)
from d810.ir.flowgraph import InsnKind, OperandKind
from d810.ir.semantics import PredicateKind
from d810.transforms.graph_modification import (
    ExitPathLoweringKind,
    ExitPathLoweringGroup,
    ExitPathLoweringSite,
    RedirectGoto,
)


@dataclass(frozen=True, slots=True)
class PrivateTerminalSuffixExecutionPlan:
    modifications: tuple[object, ...]
    owned_blocks: frozenset[int]
    owned_edges: frozenset[tuple[int, int]]
    safeguard_min_required: int


@dataclass(frozen=True, slots=True)
class ExitPathLoweringExecutionPlan:
    modifications: tuple[object, ...]
    owned_blocks: frozenset[int]
    owned_edges: frozenset[tuple[int, int]]
    sites: tuple[ExitPathLoweringSite, ...]
    supported_sites: tuple[ExitPathLoweringSite, ...]
    exit_path_effect_summaries: tuple[ExitPathEffectSummary, ...] = ()


def plan_private_terminal_suffix_execution(
    *,
    flow_graph,
    builder,
    anchors: tuple[int, ...],
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> PrivateTerminalSuffixExecutionPlan:
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    pts_anchor_set = set(int(anchor) for anchor in anchors)

    return_blk = flow_graph.get_block(return_block_serial)
    if return_blk is not None:
        for pred_serial in return_blk.preds:
            if pred_serial in pts_anchor_set:
                continue
            pred_blk = flow_graph.get_block(pred_serial)
            if (
                pred_blk is not None
                and pred_blk.nsucc == 1
                and getattr(pred_blk, "tail_kind", InsnKind.UNKNOWN) != InsnKind.GOTO
            ):
                modifications.append(
                    builder.convert_to_goto(
                        source_block=int(pred_serial),
                        target_block=int(return_block_serial),
                    )
                )

    modifications.append(
        builder.private_terminal_suffix_group(
            anchors=tuple(int(anchor) for anchor in anchors),
            shared_entry_serial=int(shared_entry_serial),
            return_block_serial=int(return_block_serial),
            suffix_serials=tuple(int(serial) for serial in suffix_serials),
        )
    )

    owned_blocks.update(int(anchor) for anchor in anchors)
    owned_blocks.update(int(serial) for serial in suffix_serials)
    owned_blocks.add(int(shared_entry_serial))
    owned_blocks.add(int(return_block_serial))

    return PrivateTerminalSuffixExecutionPlan(
        modifications=tuple(modifications),
        owned_blocks=frozenset(owned_blocks),
        owned_edges=frozenset(
            (int(anchor), int(shared_entry_serial)) for anchor in anchors
        ),
        safeguard_min_required=len(modifications),
    )


def _prove_and_classify_anchor(
    *,
    flow_graph: object,
    anchor_serial: int,
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> ExitPathLoweringSite | None:
    get_block = getattr(flow_graph, "get_block", None)
    anchor_blk = get_block(anchor_serial) if callable(get_block) else None
    if anchor_blk is None or getattr(anchor_blk, "nsucc", 0) != 1:
        return None
    succs = tuple(int(succ) for succ in getattr(anchor_blk, "succs", ()) or ())
    if len(succs) != 1 or succs[0] != int(shared_entry_serial):
        return None

    interior_serials = tuple(
        int(serial) for serial in suffix_serials if serial != return_block_serial
    )
    if not interior_serials:
        return None

    return ExitPathLoweringSite(
        anchor_serial=int(anchor_serial),
        kind=ExitPathLoweringKind.CLONE_MATERIALIZER,
        materializer_serials=interior_serials,
    )


def plan_direct_terminal_lowering_execution(
    *,
    flow_graph: object,
    builder,
    anchors: tuple[int, ...],
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> ExitPathLoweringExecutionPlan:
    sites: list[ExitPathLoweringSite] = []
    for anchor_serial in anchors:
        site = _prove_and_classify_anchor(
            flow_graph=flow_graph,
            anchor_serial=int(anchor_serial),
            shared_entry_serial=int(shared_entry_serial),
            return_block_serial=int(return_block_serial),
            suffix_serials=tuple(int(serial) for serial in suffix_serials),
        )
        if site is not None:
            sites.append(site)

    supported_sites = tuple(
        site
        for site in sites
        if site.kind
        in (
            ExitPathLoweringKind.RETURN_CONST,
            ExitPathLoweringKind.CLONE_MATERIALIZER,
        )
    )

    modifications: tuple[object, ...] = ()
    if supported_sites:
        modifications = (
            builder.direct_terminal_lowering(
                sites=list(supported_sites),
                shared_entry_serial=int(shared_entry_serial),
                return_block_serial=int(return_block_serial),
                suffix_serials=tuple(int(serial) for serial in suffix_serials),
            ),
        )

    owned_blocks: set[int] = set(int(anchor) for anchor in anchors)
    owned_blocks.update(int(serial) for serial in suffix_serials)
    owned_blocks.add(int(shared_entry_serial))
    owned_blocks.add(int(return_block_serial))

    return ExitPathLoweringExecutionPlan(
        modifications=modifications,
        owned_blocks=frozenset(owned_blocks),
        owned_edges=frozenset(
            (int(anchor), int(shared_entry_serial)) for anchor in anchors
        ),
        sites=tuple(sites),
        supported_sites=supported_sites,
    )


def _stack_offset_from_address(operand: object | None) -> int | None:
    if operand is None:
        return None
    if getattr(operand, "kind", None) is OperandKind.STACK:
        off = getattr(operand, "stkoff", None)
        return int(off) if off is not None else None
    if getattr(operand, "kind", None) is OperandKind.ADDRESS:
        inner = getattr(operand, "sub_l", None)
        if inner is not None:
            return _stack_offset_from_address(inner)
        refs = tuple(getattr(operand, "stack_refs", ()) or ())
        if len(refs) == 1:
            return int(refs[0])
    refs = tuple(getattr(operand, "stack_refs", ()) or ())
    if len(refs) == 1:
        return int(refs[0])
    return None


def _reg_of(operand: object | None) -> int | None:
    if operand is not None and getattr(operand, "kind", None) is OperandKind.REGISTER:
        reg = getattr(operand, "reg", None)
        return int(reg) if reg is not None else None
    return None


def _number_value(operand: object | None) -> int | None:
    if operand is not None and getattr(operand, "kind", None) is OperandKind.NUMBER:
        value = getattr(operand, "value", None)
        return int(value) if value is not None else None
    return None


def _collect_linear_predecessor_exit_path(
    flow_graph: object,
    *,
    anchor_serial: int,
    stop_at_serial: int,
    max_blocks: int = 16,
) -> tuple[int, ...]:
    """Return the unique non-dispatch predecessor chain ending at ``anchor``."""

    path: list[int] = []
    current = int(anchor_serial)
    seen: set[int] = set()
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return (current,)

    while current not in seen and len(path) < max_blocks:
        seen.add(current)
        path.append(current)
        block = get_block(current)
        if block is None:
            break
        preds = [
            int(pred)
            for pred in tuple(getattr(block, "preds", ()) or ())
            if int(pred) != int(stop_at_serial)
        ]
        if not preds:
            break
        if len(preds) != 1:
            candidates = tuple(
                _collect_linear_predecessor_exit_path(
                    flow_graph,
                    anchor_serial=int(pred),
                    stop_at_serial=int(stop_at_serial),
                    max_blocks=max_blocks - len(path),
                )
                for pred in preds
            )
            prefix = max(candidates, key=len, default=())
            return tuple(prefix + tuple(reversed(path)))
        current = preds[0]
    return tuple(reversed(path))


def _alias_map_for_path(flow_graph: object, path_blocks: tuple[int, ...]) -> dict[int, int]:
    aliases: dict[int, int] = {}
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return aliases
    for serial in path_blocks:
        block = get_block(int(serial))
        if block is None:
            continue
        for insn in tuple(getattr(block, "insn_snapshots", ()) or ()):
            if getattr(insn, "kind", None) is not InsnKind.MOV:
                continue
            dst_reg = _reg_of(getattr(insn, "d", None))
            if dst_reg is None:
                continue
            address = _stack_offset_from_address(getattr(insn, "l", None))
            if address is None:
                aliases.pop(dst_reg, None)
            else:
                aliases[dst_reg] = int(address)
    return aliases


def _store_target_offset(insn: object, aliases: dict[int, int]) -> int | None:
    target = getattr(insn, "d", None)
    offset = _stack_offset_from_address(target)
    if offset is not None:
        return int(offset)
    reg = _reg_of(target)
    if reg is not None:
        return aliases.get(reg)
    return None


def _alias_offset_after_block_for_reg(
    flow_graph: object,
    *,
    serial: int,
    target_reg: int,
    dispatcher_entry: int,
    visited: frozenset[tuple[str, int, int]] = frozenset(),
    max_blocks: int = 16,
) -> int | None:
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return None
    key = ("after", int(serial), int(target_reg))
    if key in visited or len(visited) >= max_blocks:
        return None
    block = get_block(int(serial))
    if block is None:
        return None

    aliases: dict[int, int] = {}
    entry_offset = _alias_offset_at_block_entry_for_reg(
        flow_graph,
        block=block,
        target_reg=int(target_reg),
        dispatcher_entry=int(dispatcher_entry),
        visited=visited | {key},
        max_blocks=max_blocks,
    )
    if entry_offset is not None:
        aliases[int(target_reg)] = int(entry_offset)

    for insn in tuple(getattr(block, "insn_snapshots", ()) or ()):
        if getattr(insn, "kind", None) is not InsnKind.MOV:
            continue
        if _reg_of(getattr(insn, "d", None)) != int(target_reg):
            continue
        offset = _stack_offset_from_address(getattr(insn, "l", None))
        if offset is None:
            aliases.pop(int(target_reg), None)
        else:
            aliases[int(target_reg)] = int(offset)
    return aliases.get(int(target_reg))


def _alias_offset_at_block_entry_for_reg(
    flow_graph: object,
    *,
    block: object,
    target_reg: int,
    dispatcher_entry: int,
    visited: frozenset[tuple[str, int, int]] = frozenset(),
    max_blocks: int = 16,
) -> int | None:
    block_serial = getattr(block, "serial", None)
    if block_serial is None:
        return None
    key = ("entry", int(block_serial), int(target_reg))
    if key in visited or len(visited) >= max_blocks:
        return None
    pred_serials = [
        int(pred)
        for pred in tuple(getattr(block, "preds", ()) or ())
        if int(pred) != int(dispatcher_entry)
    ]
    if not pred_serials:
        return None

    offsets: list[int] = []
    for pred_serial in pred_serials:
        offset = _alias_offset_after_block_for_reg(
            flow_graph,
            serial=int(pred_serial),
            target_reg=int(target_reg),
            dispatcher_entry=int(dispatcher_entry),
            visited=visited | {key},
            max_blocks=max_blocks,
        )
        if offset is None:
            return None
        offsets.append(int(offset))
    if offsets and len(set(offsets)) == 1:
        return offsets[0]
    return None


def _incoming_alias_offset_for_reg(
    flow_graph: object,
    *,
    block: object,
    target_reg: int,
    dispatcher_entry: int,
) -> int | None:
    block_serial = getattr(block, "serial", None)
    if block_serial is not None:
        same_block = _alias_map_for_path(flow_graph, (int(block_serial),)).get(
            int(target_reg)
        )
        if same_block is not None:
            return int(same_block)
    return _alias_offset_at_block_entry_for_reg(
        flow_graph,
        block=block,
        target_reg=int(target_reg),
        dispatcher_entry=int(dispatcher_entry),
    )


def _expected_terminal_successor(
    tail: object,
    *,
    terminal_state: int,
    state_var_stkoff: int,
    succs: tuple[int, ...],
) -> int | None:
    if len(succs) != 2 or not getattr(tail, "is_conditional_jump", False):
        return None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    left_state = int(state_var_stkoff) in tuple(getattr(left, "stack_refs", ()) or ())
    right_state = int(state_var_stkoff) in tuple(getattr(right, "stack_refs", ()) or ())
    left_value = _number_value(left)
    right_value = _number_value(right)
    compares_terminal = (
        (left_state and right_value == int(terminal_state))
        or (right_state and left_value == int(terminal_state))
    )
    if not compares_terminal:
        return None
    predicate = getattr(tail, "branch_predicate", None)
    if predicate is PredicateKind.EQ:
        return int(succs[1])
    if predicate is PredicateKind.NE:
        return int(succs[0])
    return None


def _return_block_for_terminal(
    flow_graph: object,
    *,
    terminal_block_serial: int,
    dispatcher_entry_serial: int,
    terminal_state: int,
    state_var_stkoff: int,
) -> int | None:
    get_block = getattr(flow_graph, "get_block", None)
    block = get_block(int(terminal_block_serial)) if callable(get_block) else None
    if block is None:
        return None
    succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
    if int(dispatcher_entry_serial) not in succs:
        return None
    tail = getattr(block, "tail", None)
    expected = _expected_terminal_successor(
        tail,
        terminal_state=int(terminal_state),
        state_var_stkoff=int(state_var_stkoff),
        succs=succs,
    )
    if expected is None:
        return None
    return_block = get_block(expected) if callable(get_block) else None
    if return_block is None or getattr(return_block, "nsucc", len(getattr(return_block, "succs", ()))) != 0:
        return None
    return int(expected)


def _prove_exit_path_effect_site(
    flow_graph: object,
    redirect: RedirectGoto,
    *,
    dispatcher_entry_serial: int,
    state_var_stkoff: int,
) -> tuple[ExitPathLoweringSite, ExitPathEffectSummary, int] | None:
    get_block = getattr(flow_graph, "get_block", None)
    if not callable(get_block):
        return None
    terminal_serial = int(redirect.new_target)
    terminal_block = get_block(terminal_serial)
    if terminal_block is None:
        return None
    succs = tuple(int(succ) for succ in getattr(terminal_block, "succs", ()) or ())
    if len(succs) != 2 or int(dispatcher_entry_serial) not in succs:
        return None

    path_blocks = _collect_linear_predecessor_exit_path(
        flow_graph,
        anchor_serial=int(redirect.from_serial),
        stop_at_serial=int(dispatcher_entry_serial),
    )
    aliases = _alias_map_for_path(flow_graph, path_blocks)
    state_store_value: int | None = None
    result_store_offsets: list[int] = []
    for insn in tuple(getattr(terminal_block, "insn_snapshots", ()) or ()):
        if getattr(insn, "kind", None) is not InsnKind.STORE:
            continue
        target = _store_target_offset(insn, aliases)
        if target is None:
            target_reg = _reg_of(getattr(insn, "d", None))
            if target_reg is not None:
                target = _incoming_alias_offset_for_reg(
                    flow_graph,
                    block=terminal_block,
                    target_reg=int(target_reg),
                    dispatcher_entry=int(dispatcher_entry_serial),
                )
        if target is None:
            continue
        if int(target) == int(state_var_stkoff):
            state_store_value = _number_value(getattr(insn, "l", None))
        else:
            result_store_offsets.append(int(target))
    if state_store_value is None or not result_store_offsets:
        return None
    return_block = _return_block_for_terminal(
        flow_graph,
        terminal_block_serial=terminal_serial,
        dispatcher_entry_serial=int(dispatcher_entry_serial),
        terminal_state=int(state_store_value),
        state_var_stkoff=int(state_var_stkoff),
    )
    if return_block is None:
        return None
    effects = (
        ExitPathEffect(
            kind="store",
            target="state_slot",
            value=int(state_store_value),
            payload={"stkoff": int(state_var_stkoff)},
        ),
        ExitPathEffect(
            kind="store",
            target="result_slot",
            payload={"stkoffs": tuple(sorted(set(result_store_offsets)))},
        ),
    )
    exit_path = ExitPathEffectSummary(
        initial_state=0,
        terminal_state=int(state_store_value),
        path_blocks=path_blocks + (terminal_serial,),
        terminal_block=terminal_serial,
        effects=effects,
        enumerated_inputs_complete=True,
        deterministic=True,
        terminal_reachable=True,
        provenance=("exit_path_effect_summary", "state_store_branch_to_stop"),
    )
    site = ExitPathLoweringSite(
        anchor_serial=int(redirect.from_serial),
        kind=ExitPathLoweringKind.CLONE_MATERIALIZER,
        materializer_serials=tuple(
            int(serial)
            for serial in path_blocks + (terminal_serial,)
            if int(serial) != int(redirect.from_serial)
        ),
        skip_terminal_control_tail=True,
    )
    return site, exit_path, int(return_block)


def plan_state_exit_path_effect_lowerings(
    *,
    flow_graph: object,
    modifications: tuple[object, ...],
    dispatcher_entry_serial: int,
    state_var_stkoff: int,
) -> ExitPathLoweringExecutionPlan:
    """Replace proven dispatcher redirects with direct terminal materializers.

    A site is accepted only when the redirected target stores the dispatcher state
    slot to the terminal constant, stores a non-state result slot, and its own
    state comparison routes that constant to the function STOP block.  The
    ordinary ``RedirectGoto`` for that anchor is then removed by the caller and
    replaced with a DTL group that clones only the materializer body.
    """

    supported: list[ExitPathLoweringSite] = []
    exit_path_effect_summaries: list[ExitPathEffectSummary] = []
    return_blocks: set[int] = set()
    for mod in modifications:
        if not isinstance(mod, RedirectGoto):
            continue
        if int(mod.old_target) != int(dispatcher_entry_serial):
            continue
        proof = _prove_exit_path_effect_site(
            flow_graph,
            mod,
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            state_var_stkoff=int(state_var_stkoff),
        )
        if proof is None:
            continue
        site, exit_path, return_block = proof
        supported.append(site)
        exit_path_effect_summaries.append(exit_path)
        return_blocks.add(int(return_block))

    modifications_out: tuple[object, ...] = ()
    if supported and len(return_blocks) == 1:
        (return_block,) = tuple(return_blocks)
        modifications_out = (
            ExitPathLoweringGroup(
                shared_entry_serial=int(dispatcher_entry_serial),
                return_block_serial=int(return_block),
                suffix_serials=(int(return_block),),
                sites=tuple(supported),
                reason="exit_path_effect_direct_lowering",
            ),
        )

    return ExitPathLoweringExecutionPlan(
        modifications=modifications_out,
        owned_blocks=frozenset(
            int(site.anchor_serial) for site in supported
        ),
        owned_edges=frozenset(
            (int(site.anchor_serial), int(dispatcher_entry_serial))
            for site in supported
        ),
        sites=tuple(supported),
        supported_sites=tuple(supported),
        exit_path_effect_summaries=tuple(exit_path_effect_summaries),
    )


__all__ = [
    "ExitPathLoweringExecutionPlan",
    "PrivateTerminalSuffixExecutionPlan",
    "plan_direct_terminal_lowering_execution",
    "plan_private_terminal_suffix_execution",
    "plan_state_exit_path_effect_lowerings",
]
