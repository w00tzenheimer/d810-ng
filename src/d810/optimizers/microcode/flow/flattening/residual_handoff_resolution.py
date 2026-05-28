"""Residual handoff resolution with optional evaluator-backed state recovery.

This module is the narrow enriched layer above
``d810.recon.flow.residual_handoff_discovery``. Discovery stays pure; this
module only injects ``resolve_state_via_valranges`` when available.
"""

from __future__ import annotations

from d810.evaluator.hexrays_microcode.tracker import MopTracker, get_all_possibles_values
from d810.evaluator.hexrays_microcode.valranges import resolve_state_via_valranges
from d810.recon.flow.linearized_state_dag import LinearizedStateDag, StateDagEdge
from d810.recon.flow.residual_handoff_discovery import (
    has_live_exact_residual_handoff as discover_has_live_exact_residual_handoff,
    resolve_effective_target_entry as discover_effective_target_entry,
    resolve_immediate_handoff_target,
    resolve_singleton_state_write_value as discover_singleton_state_write_value,
    resolve_synthesized_handoff_target as discover_synthesized_handoff_target,
)


def _resolve_state_via_valranges():
    return resolve_state_via_valranges


def _mop_tracker_cls():
    return MopTracker


def _all_possible_values():
    return get_all_possibles_values


def has_live_exact_residual_handoff_with_valranges(
    mba: object,
    residual_preds: tuple[int, ...],
    *,
    state_var_stkoff: int | None,
    dispatcher: object | None,
) -> bool:
    return discover_has_live_exact_residual_handoff(
        mba,
        residual_preds,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        resolve_state_via_valranges=_resolve_state_via_valranges(),
    )


def resolve_singleton_state_write_value(
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
) -> int | None:
    return discover_singleton_state_write_value(
        mba,
        block_serial,
        state_var_stkoff=state_var_stkoff,
        resolve_state_via_valranges=_resolve_state_via_valranges(),
    )


def resolve_predecessor_state_values(
    mba: object,
    *,
    pred_serial: int,
    state_var: object,
    max_nb_block: int = 20,
    max_path: int = 15,
) -> tuple[int, ...]:
    """Resolve concrete state values reaching one predecessor via MopTracker."""
    if mba is None or state_var is None:
        return ()
    try:
        pred_blk = mba.get_mblock(int(pred_serial))
    except Exception:
        return ()
    if pred_blk is None or getattr(pred_blk, "tail", None) is None:
        return ()

    tracker_cls = _mop_tracker_cls()
    collect_values = _all_possible_values()
    if tracker_cls is None or collect_values is None:
        return ()

    tracker = tracker_cls(
        [state_var],
        max_nb_block=max_nb_block,
        max_path=max_path,
    )
    tracker.reset()
    histories = tracker.search_backward(pred_blk, pred_blk.tail)
    values = collect_values(histories, [state_var])
    concrete = sorted(
        {
            int(entry[0])
            for entry in values
            if entry and entry[0] is not None
        }
    )
    return tuple(concrete)


def resolve_synthesized_handoff_target(
    dag: LinearizedStateDag,
    mba: object,
    block_serial: int,
    *,
    state_var_stkoff: int | None,
    bst_node_blocks: set[int],
    dispatcher: object | None,
    via_pred: int | None = None,
) -> tuple[int, int] | None:
    return discover_synthesized_handoff_target(
        dag,
        mba,
        block_serial,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=bst_node_blocks,
        dispatcher=dispatcher,
        via_pred=via_pred,
        resolve_state_via_valranges=_resolve_state_via_valranges(),
    )


def resolve_effective_target_entry(
    dag: LinearizedStateDag,
    edge: StateDagEdge,
    *,
    bst_node_blocks: set[int],
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object,
) -> int | None:
    resolution = discover_effective_target_entry(
        dag,
        edge,
        bst_node_blocks=bst_node_blocks,
        state_var_stkoff=state_var_stkoff,
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
        mba=mba,
        resolve_state_via_valranges=_resolve_state_via_valranges(),
    )
    return resolution.target_entry


def is_semantic_handoff_redirect(
    dag: LinearizedStateDag,
    edge: StateDagEdge,
    *,
    source_block: int,
    target_entry: int,
    state_var_stkoff: int | None,
    dispatcher_lookup: object | None,
    dispatcher: object | None,
    mba: object | None,
) -> bool:
    immediate_handoff = resolve_immediate_handoff_target(
        dag,
        mba,
        source_block,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=set(),
        dispatcher_lookup=dispatcher_lookup,
        dispatcher=dispatcher,
    )
    if immediate_handoff is not None and immediate_handoff[1] == target_entry:
        return True
    via_pred = edge.ordered_path[-2] if len(edge.ordered_path) >= 2 else None
    synthesized_handoff = resolve_synthesized_handoff_target(
        dag,
        mba,
        source_block,
        state_var_stkoff=state_var_stkoff,
        bst_node_blocks=set(),
        dispatcher=dispatcher,
        via_pred=via_pred,
    )
    return synthesized_handoff is not None and synthesized_handoff[1] == target_entry


__all__ = [
    "has_live_exact_residual_handoff_with_valranges",
    "is_semantic_handoff_redirect",
    "resolve_predecessor_state_values",
    "resolve_effective_target_entry",
    "resolve_singleton_state_write_value",
    "resolve_synthesized_handoff_target",
]
