from __future__ import annotations

from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind


def collect_common_return_corridor(
    dag,
    flow_graph,
    *,
    condition_chain_blocks: set[int],
    dispatcher_serial: int,
) -> set[int]:
    return_paths: list[set[int]] = []
    for edge in dag.edges:
        if edge.kind == SemanticEdgeKind.CONDITIONAL_RETURN and edge.ordered_path:
            return_paths.append({int(serial) for serial in edge.ordered_path})

    if not return_paths:
        return set()

    common_return_corridor = set(return_paths[0])
    for path in return_paths[1:]:
        common_return_corridor &= path
    if not common_return_corridor:
        return set()

    condition_chain_set = set(int(block) for block in condition_chain_blocks)
    condition_chain_set.add(int(dispatcher_serial))
    earliest = min(common_return_corridor)
    walk_serial = earliest
    for _ in range(5):
        walk_blk = flow_graph.get_block(walk_serial)
        if walk_blk is None:
            break
        preds = list(flow_graph.predecessors(walk_serial))
        best_pred: int | None = None
        for pred_serial in sorted(preds, reverse=True):
            pred_blk = flow_graph.get_block(pred_serial)
            if (
                pred_blk is not None
                and pred_blk.nsucc == 1
                and pred_serial not in condition_chain_set
                and pred_serial not in common_return_corridor
            ):
                best_pred = pred_serial
                break
        if best_pred is None:
            break
        common_return_corridor.add(best_pred)
        walk_serial = best_pred

    return common_return_corridor


__all__ = ["collect_common_return_corridor"]
