from __future__ import annotations


def snapshot_reconstruction_dag(logger, *, dag, mba, strategy_name: str) -> None:
    try:
        from d810.core.diag import get_diag_db
        diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
        if diag_db is not None:
            from d810.core.diag.snapshot import (
                DagEdge,
                DagNode,
                snapshot_dag,
                snapshot_mba,
            )
            import json as _json

            snap_id = snapshot_mba(
                diag_db,
                [],
                label=f"{strategy_name}_state_write_reconstruction_dag",
                func_ea=mba.entry_ea if mba is not None else 0,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )

            dag_nodes = []
            for node in dag.nodes:
                dag_nodes.append(DagNode(
                    state=int(node.key.state_const) if node.key.state_const is not None else 0,
                    state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                    entry_block=int(node.entry_anchor),
                    classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                    shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                ))

            dag_edges = []
            for eidx, edge in enumerate(dag.edges):
                dag_edges.append(DagEdge(
                    edge_id=eidx,
                    source_state=int(edge.source_key.state_const) if edge.source_key.state_const is not None else None,
                    target_state=int(edge.target_key.state_const) if edge.target_key is not None and edge.target_key.state_const is not None else None,
                    edge_kind=str(edge.kind.name) if hasattr(edge.kind, "name") else str(edge.kind),
                    source_block=int(edge.source_anchor.block_serial) if edge.source_anchor is not None else None,
                    source_arm=edge.source_anchor.branch_arm if edge.source_anchor is not None else None,
                    target_entry=int(edge.target_entry_anchor) if edge.target_entry_anchor is not None else None,
                    ordered_path=_json.dumps([int(s) for s in edge.ordered_path]) if edge.ordered_path else "[]",
                ))

            snapshot_dag(diag_db, snap_id, dag_nodes, dag_edges)
    except Exception:
        logger.warning(
            "Early diagnostic DAG snapshot failed (non-critical)",
            exc_info=True,
        )


def snapshot_reconstruction_post_apply(
    logger,
    *,
    dag,
    modifications: list,
    mba,
    strategy_name: str,
) -> None:
    try:
        from d810.core.diag import get_diag_db
        diag_db = get_diag_db(mba.entry_ea if mba is not None else 0)
        if diag_db is not None:
            from d810.core.diag.snapshot import (
                DagEdge,
                DagNode,
                Modification,
                snapshot_dag,
                snapshot_mba,
                snapshot_modifications,
            )
            import json as _json

            snap_id = snapshot_mba(
                diag_db,
                [],
                label=f"{strategy_name}_state_write_reconstruction_post_apply",
                func_ea=mba.entry_ea if mba is not None else 0,
                maturity="MMAT_GLBOPT1",
                phase="post_apply",
            )

            dag_nodes = []
            for node in dag.nodes:
                dag_nodes.append(DagNode(
                    state=int(node.key.state_const) if node.key.state_const is not None else 0,
                    state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                    entry_block=int(node.entry_anchor),
                    classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                    shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                ))

            dag_edges = []
            for eidx, edge in enumerate(dag.edges):
                dag_edges.append(DagEdge(
                    edge_id=eidx,
                    source_state=int(edge.source_key.state_const) if edge.source_key.state_const is not None else None,
                    target_state=int(edge.target_key.state_const) if edge.target_key is not None and edge.target_key.state_const is not None else None,
                    edge_kind=str(edge.kind.name) if hasattr(edge.kind, "name") else str(edge.kind),
                    source_block=int(edge.source_anchor.block_serial) if edge.source_anchor is not None else None,
                    source_arm=edge.source_anchor.branch_arm if edge.source_anchor is not None else None,
                    target_entry=int(edge.target_entry_anchor) if edge.target_entry_anchor is not None else None,
                    ordered_path=_json.dumps([int(s) for s in edge.ordered_path]) if edge.ordered_path else "[]",
                ))

            snapshot_dag(diag_db, snap_id, dag_nodes, dag_edges)

            mod_snapshots = []
            for midx, mod in enumerate(modifications):
                mod_type = type(mod).__name__
                source_block = (
                    getattr(mod, "from_serial", None)
                    or getattr(mod, "source_block", None)
                    or getattr(mod, "src_block", None)
                    or getattr(mod, "block_serial", None)
                )
                target_block = (
                    getattr(mod, "new_target", None)
                    or getattr(mod, "goto_target", None)
                    or getattr(mod, "conditional_target", None)
                )
                old_target = getattr(mod, "old_target", None)
                mod_snapshots.append(Modification(
                    mod_index=midx,
                    mod_type=mod_type,
                    source_block=int(source_block) if source_block is not None else None,
                    target_block=int(target_block) if target_block is not None else None,
                    old_target=int(old_target) if old_target is not None else None,
                    status="emitted",
                ))

            snapshot_modifications(diag_db, snap_id, mod_snapshots)
    except Exception:
        logger.warning(
            "Diagnostic DAG/modifications snapshot failed (non-critical)",
            exc_info=True,
        )


__all__ = [
    "snapshot_reconstruction_dag",
    "snapshot_reconstruction_post_apply",
]
