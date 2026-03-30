from __future__ import annotations

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.hodur._residual_handoff_bridge import (
    _resolve_state_via_valranges,
    resolve_singleton_state_write_value,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.exit_transition_discovery import (
    resolve_state_var_stkoff as discover_state_var_stkoff,
)
from d810.recon.flow.residual_handoff_discovery import (
    has_live_exact_residual_handoff,
)


def resolve_state_var_stkoff(snapshot: object, state_machine: object) -> int | None:
    return discover_state_var_stkoff(
        detector=getattr(snapshot, "detector", None),
        state_var=getattr(state_machine, "state_var", None),
    )


def supports_projected_replanning(flow_graph: object) -> bool:
    return isinstance(flow_graph, FlowGraph)


def flow_graph_block_serials(flow_graph: object) -> set[int]:
    blocks = getattr(flow_graph, "blocks", None)
    if blocks is None:
        return set()
    try:
        return set(blocks.keys())
    except Exception:
        return set()


def collect_dead_dispatcher_root_cleanup_modifications(
    projected_flow_graph: FlowGraph,
    *,
    dispatcher_serial: int,
    original_stop_serial: int | None,
    original_blocks: set[int],
) -> list[RedirectGoto]:
    if not projected_flow_graph.blocks:
        return []
    if dispatcher_serial < 0 or original_stop_serial is None:
        return []
    stop_serial = int(original_stop_serial)
    entry_serial = getattr(projected_flow_graph, "entry_serial", None)
    reachable_blocks = compute_reachable_blocks(
        projected_flow_graph,
        start_serial=entry_serial,
    )
    filtered: list[RedirectGoto] = []
    for block_serial in sorted(projected_flow_graph.blocks.keys()):
        if block_serial not in original_blocks:
            continue
        if block_serial in {dispatcher_serial, stop_serial}:
            continue
        if reachable_blocks is not None and block_serial in reachable_blocks:
            continue
        block = projected_flow_graph.get_block(block_serial)
        if block is None:
            continue
        if tuple(getattr(block, "preds", ())) != ():
            continue
        if getattr(block, "block_type", None) == ida_hexrays.BLT_2WAY:
            continue
        succs = tuple(getattr(block, "succs", ()))
        if len(succs) != 1:
            continue
        old_target = int(succs[0])
        if old_target == stop_serial:
            continue
        if old_target != dispatcher_serial:
            continue
        filtered.append(
            RedirectGoto(
                from_serial=int(block_serial),
                old_target=old_target,
                new_target=stop_serial,
            )
        )
    filtered.sort(key=lambda mod: mod.from_serial)
    return filtered


def collect_lfg_residual_dispatcher_predecessors(
    flow_graph: object,
    dispatcher_serial: int,
    *,
    bst_node_blocks: set[int],
    reachable_from_serial: int | None = None,
) -> tuple[int, ...]:
    return collect_residual_dispatcher_predecessors(
        flow_graph,
        dispatcher_serial,
        bst_node_blocks=bst_node_blocks,
        reachable_from_serial=reachable_from_serial,
    )


def is_original_pre_header_candidate(
    flow_graph: object | None,
    *,
    pre_header_serial: int | None,
    entry_serial: int | None,
) -> bool:
    if flow_graph is None or pre_header_serial is None or entry_serial is None:
        return False
    if pre_header_serial == entry_serial:
        return True
    try:
        entry_block = flow_graph.get_block(entry_serial)
    except Exception:
        return False
    if entry_block is None:
        return False
    succs = tuple(getattr(entry_block, "succs", ()))
    return len(succs) == 1 and succs[0] == pre_header_serial


def resolve_lfg_singleton_state_write_value(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
) -> int | None:
    return resolve_singleton_state_write_value(
        mba,
        block_serial,
        state_var_stkoff=state_var_stkoff,
    )


def has_live_exact_lfg_residual_handoff(
    snapshot: object,
    residual_preds: tuple[int, ...],
    *,
    resolve_state_var_stkoff_fn,
) -> bool:
    mba = getattr(snapshot, "mba", None)
    bst_result = getattr(snapshot, "bst_result", None)
    state_machine = getattr(snapshot, "state_machine", None)
    if mba is None or bst_result is None or state_machine is None:
        return False
    state_var_stkoff = resolve_state_var_stkoff_fn(snapshot, state_machine)
    dispatcher = getattr(bst_result, "dispatcher", None)
    return has_live_exact_residual_handoff(
        mba,
        residual_preds,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        resolve_state_via_valranges=_resolve_state_via_valranges(),
    )


__all__ = [
    "collect_dead_dispatcher_root_cleanup_modifications",
    "collect_lfg_residual_dispatcher_predecessors",
    "flow_graph_block_serials",
    "has_live_exact_lfg_residual_handoff",
    "is_original_pre_header_candidate",
    "resolve_lfg_singleton_state_write_value",
    "resolve_state_var_stkoff",
    "supports_projected_replanning",
]
