"""Hodur-local bridge for residual handoff discovery requiring Hex-Rays helpers."""

from __future__ import annotations

from d810.recon.flow.linearized_state_dag import LinearizedStateDag, StateDagEdge
from d810.recon.flow.residual_handoff_discovery import (
    resolve_effective_target_entry as discover_effective_target_entry,
    resolve_immediate_handoff_target,
    resolve_singleton_state_write_value as discover_singleton_state_write_value,
    resolve_synthesized_handoff_target as discover_synthesized_handoff_target,
)


def _resolve_state_via_valranges():
    try:
        from d810.evaluator.hexrays_microcode.valranges import resolve_state_via_valranges
    except Exception:
        resolve_state_via_valranges = None
    return resolve_state_via_valranges


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
    "is_semantic_handoff_redirect",
    "resolve_effective_target_entry",
    "resolve_singleton_state_write_value",
    "resolve_synthesized_handoff_target",
]
