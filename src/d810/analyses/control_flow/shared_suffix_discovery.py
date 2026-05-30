"""Pure shared-suffix discovery helpers for residual handoff planning."""

from __future__ import annotations

from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    RedirectSourceKind,
)
from d810.analyses.control_flow.residual_handoff_discovery import (
    resolve_nonexact_dispatch_target,
    resolve_owner_family_fallback_entry,
    resolve_redirect_safe_target_entry,
)


def _target_reaches_source_ignoring_blocks(
    flow_graph: object,
    *,
    target_entry: int,
    source_block: int,
    ignored_blocks: set[int],
    limit: int = 256,
) -> bool:
    if target_entry == source_block:
        return True

    worklist: list[int] = [int(target_entry)]
    seen: set[int] = set()
    while worklist and len(seen) < limit:
        current = worklist.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == source_block:
            return True
        try:
            succs = tuple(flow_graph.successors(current))
        except Exception:
            block = flow_graph.get_block(current)
            succs = tuple(getattr(block, "succs", ())) if block is not None else ()
        for succ in succs:
            succ_serial = int(succ)
            if succ_serial in ignored_blocks or succ_serial in seen:
                continue
            worklist.append(succ_serial)
    return False


def has_prior_branch_cut_for_state(
    dag: LinearizedStateDag,
    *,
    source_block: int,
    state_value: int | None,
    bst_node_blocks: set[int],
    dispatcher: object | None = None,
) -> bool:
    """Return whether ``source_block`` is only a tail inside an earlier cut."""
    if state_value is None:
        return False

    raw_value = state_value & 0xFFFFFFFF
    for edge in dag.edges:
        if edge.kind not in (
            SemanticEdgeKind.TRANSITION,
            SemanticEdgeKind.CONDITIONAL_TRANSITION,
        ):
            continue
        if edge.target_state is None or (edge.target_state & 0xFFFFFFFF) != raw_value:
            continue
        if edge.source_anchor.kind != RedirectSourceKind.CONDITIONAL_BRANCH:
            continue
        if source_block not in edge.ordered_path:
            continue
        path_index = edge.ordered_path.index(source_block)
        if path_index <= 0:
            continue
        try:
            branch_index = edge.ordered_path.index(edge.source_anchor.block_serial)
        except ValueError:
            branch_index = None
        if (
            branch_index is not None
            and path_index == len(edge.ordered_path) - 1
            and path_index == branch_index + 1
        ):
            # Allow residual cleanup on the immediate one-way leaf tail of a
            # conditional corridor. These blocks still carry the raw state
            # write, so suppressing the residual handoff there prevents the
            # semantic-entry redirect the user actually wants.
            continue
        target_entry = resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None and edge.target_state is not None and edge.target_key is None:
            target_entry = resolve_nonexact_dispatch_target(
                dag,
                edge.target_state,
                source_block=edge.source_anchor.block_serial,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
                dispatcher_lookup=(
                    getattr(dispatcher, "lookup", None) if dispatcher is not None else None
                ),
            )
        if target_entry is None or target_entry in bst_node_blocks:
            continue
        if target_entry == source_block:
            continue
        return True
    return False


def is_shared_suffix_conditional_tail(
    dag: LinearizedStateDag,
    *,
    source_block: int,
) -> bool:
    """Return whether ``source_block`` is a conditional tail in a shared suffix."""
    if not any(source_block in node.shared_suffix_blocks for node in dag.nodes):
        return False
    for edge in dag.edges:
        if edge.source_anchor.kind != RedirectSourceKind.CONDITIONAL_BRANCH:
            continue
        if source_block not in edge.ordered_path:
            continue
        path_index = edge.ordered_path.index(source_block)
        if path_index <= 0:
            continue
        try:
            branch_index = edge.ordered_path.index(edge.source_anchor.block_serial)
        except ValueError:
            branch_index = None
        if (
            branch_index is not None
            and path_index == len(edge.ordered_path) - 1
            and path_index == branch_index + 1
        ):
            # Immediate one-way leaf tails still carry the raw state write for
            # the corridor arm. They should be eligible for residual cleanup
            # instead of being treated as a shared-suffix blocker.
            continue
        return True
    return False


def can_rewrite_shared_suffix_family_fallback(
    dag: LinearizedStateDag,
    *,
    source_block: int,
    target_entry: int,
    current_preds: tuple[int, ...],
    bst_node_blocks: set[int],
    flow_graph: object | None = None,
) -> bool:
    """Return whether a shared-suffix feeder tail may use family fallback."""
    current_preds = tuple(int(pred) for pred in current_preds)
    if not current_preds:
        return False
    if len(current_preds) == 1:
        via_pred = current_preds[0]
    else:
        if flow_graph is None:
            return False
        for pred_serial in current_preds:
            try:
                pred_block = flow_graph.get_block(pred_serial)
            except Exception:
                pred_block = None
            if pred_block is None:
                return False
            pred_succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
            if pred_succs != (int(source_block),):
                return False
        return True
    expected_fallback = resolve_owner_family_fallback_entry(
        dag,
        via_pred=via_pred,
        source_block=source_block,
        bst_node_blocks=bst_node_blocks,
    )
    if expected_fallback is not None and expected_fallback == target_entry:
        return True
    if flow_graph is None:
        return False
    try:
        via_pred_block = flow_graph.get_block(via_pred)
    except Exception:
        via_pred_block = None
    if via_pred_block is None:
        return False
    via_pred_succs = tuple(int(succ) for succ in getattr(via_pred_block, "succs", ()))
    if via_pred_succs == (int(source_block),):
        return True
    for pred_serial in tuple(getattr(via_pred_block, "preds", ())):
        try:
            pred_block = flow_graph.get_block(pred_serial)
        except Exception:
            pred_block = None
        succs = tuple(getattr(pred_block, "succs", ())) if pred_block is not None else ()
        if len(succs) == 2 and via_pred in succs and target_entry in succs:
            return True
    return False


def pred_split_target_reaches_via_pred(
    flow_graph: object,
    *,
    target_entry: int,
    via_pred: int,
    source_block: int,
    ignored_blocks: set[int],
    limit: int = 256,
) -> bool:
    """Return whether ``target_entry`` can already reach ``via_pred``."""
    pred_ignored = set(ignored_blocks)
    pred_ignored.add(source_block)
    return _target_reaches_source_ignoring_blocks(
        flow_graph,
        target_entry=target_entry,
        source_block=via_pred,
        ignored_blocks=pred_ignored,
        limit=limit,
    )


__all__ = [
    "can_rewrite_shared_suffix_family_fallback",
    "has_prior_branch_cut_for_state",
    "is_shared_suffix_conditional_tail",
    "pred_split_target_reaches_via_pred",
]
