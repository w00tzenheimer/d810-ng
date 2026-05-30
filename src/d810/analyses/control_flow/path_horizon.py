"""Path-horizon resolution for ordered DAG corridors."""

from __future__ import annotations

from dataclasses import replace

from d810.core import logging
from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind, StateDagEdge
from d810.analyses.control_flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
    find_last_state_write_site_on_path_snapshot,
    find_state_write_sites_snapshot,
)

logger = logging.getLogger(__name__)


def resolve_transition_path_horizon(
    edge: StateDagEdge,
    *,
    flow_graph,
    ordered_path: tuple[int, ...],
    state_var_stkoff: int,
    constant_result: SnapshotConstantFixpointResult,
) -> tuple[int, StateWriteSite] | None:
    """Resolve the last semantic state write that proves ``edge`` on ``ordered_path``."""
    resolved: tuple[int, StateWriteSite] | None = None

    if edge.last_write_site is not None:
        write_block, write_ea = edge.last_write_site
        path_set = set(ordered_path)
        if write_block in path_set:
            site = StateWriteSite(
                block_serial=write_block,
                state_value=(
                    int(edge.target_state & 0xFFFFFFFF)
                    if edge.target_state is not None
                    else 0
                ),
                insn_ea=write_ea,
                insn_index=0,
            )
            resolved = (write_block, site)
            logger.info(
                "RECON DAG: using DFS-proven write_site at blk[%d]:0x%x",
                write_block,
                write_ea,
            )

    if resolved is None:
        resolved = find_last_state_write_site_on_path_snapshot(
            flow_graph,
            ordered_path,
            state_var_stkoff,
            in_stk_maps=constant_result.in_stk_maps,
            in_reg_maps=constant_result.in_reg_maps,
        )

    if resolved is None and edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
        for path_serial in reversed(ordered_path):
            block_snap = flow_graph.get_block(path_serial)
            if block_snap is None:
                continue
            sites = find_state_write_sites_snapshot(
                flow_graph,
                path_serial,
                state_var_stkoff,
                initial_stk_map=constant_result.in_stk_maps.get(path_serial),
                initial_reg_map=constant_result.in_reg_maps.get(path_serial),
            )
            if sites:
                site = sites[-1]
                expected = int(edge.target_state & 0xFFFFFFFF)
                if int(site.state_value & 0xFFFFFFFF) != expected:
                    site = replace(site, state_value=expected)
                resolved = (int(path_serial), site)
                logger.info(
                    "RECON DAG: conditional fallback horizon at blk[%d] "
                    "(DFS-trusted, per-block evaluator)",
                    path_serial,
                )
                break

    if resolved is None and edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
        mop_s = 3
        for path_serial in reversed(ordered_path):
            block_snap = flow_graph.get_block(path_serial)
            if block_snap is None:
                continue
            for insn_idx, insn in enumerate(reversed(block_snap.insn_snapshots)):
                dest = getattr(insn, "d", None)
                if dest is None:
                    continue
                if getattr(dest, "t", None) != mop_s:
                    continue
                dest_stkoff = getattr(dest, "stkoff", None)
                if dest_stkoff is None:
                    s_ref = getattr(dest, "s", None)
                    dest_stkoff = (
                        getattr(s_ref, "off", None)
                        if s_ref is not None
                        else None
                    )
                if dest_stkoff is None or int(dest_stkoff) != int(state_var_stkoff):
                    continue
                actual_insn_idx = len(block_snap.insn_snapshots) - 1 - insn_idx
                site = StateWriteSite(
                    block_serial=path_serial,
                    state_value=int(edge.target_state & 0xFFFFFFFF),
                    insn_ea=int(insn.ea),
                    insn_index=actual_insn_idx,
                )
                resolved = (int(path_serial), site)
                logger.info(
                    "RECON DAG: conditional fallback horizon at blk[%d] "
                    "(DFS-trusted, raw dest scan)",
                    path_serial,
                )
                break
            if resolved is not None:
                break

    return resolved


__all__ = ["resolve_transition_path_horizon"]
