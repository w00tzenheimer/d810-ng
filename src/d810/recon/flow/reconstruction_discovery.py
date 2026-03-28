"""Discovery helpers for reconstruction-first Hodur planning."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.recon.flow.exit_transition_discovery import resolve_state_var_stkoff
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
)
from d810.recon.flow.path_horizon import resolve_transition_path_horizon
from d810.recon.flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
)
from d810.recon.flow.target_entry_resolution import resolve_edge_target_entry


@dataclass(frozen=True, slots=True)
class ReconstructionCandidateSeed:
    """Discovered corridor facts for one reconstruction candidate."""

    horizon_block: int
    site: StateWriteSite
    target_entry: int
    original_dispatcher_entry: int | None = None


def collect_shared_suffix_blocks(dag: LinearizedStateDag) -> set[int]:
    """Collect all shared suffix blocks referenced by the DAG."""
    shared_blocks: set[int] = set()
    for node in dag.nodes:
        shared_blocks.update(int(serial) for serial in node.shared_suffix_blocks)
    return shared_blocks


def classify_artifact_return_blocks(
    flow_graph: object,
    *,
    state_var_stkoff: int,
    state_constants: set[int],
) -> set[int]:
    """Identify return-artifact blocks that forward dead state values."""
    MOP_N = int(ida_hexrays.mop_n)
    MOP_S = int(ida_hexrays.mop_S)
    m_xdu = int(ida_hexrays.m_xdu)
    m_mov = int(ida_hexrays.m_mov)

    artifact_blocks: set[int] = set()
    for serial, blk in flow_graph.blocks.items():
        for insn in blk.insn_snapshots:
            if insn.opcode == m_xdu:
                l_op = insn.l
                d_op = insn.d
                if (
                    l_op is not None
                    and d_op is not None
                    and getattr(l_op, "t", None) == MOP_S
                    and getattr(d_op, "t", None) == MOP_S
                    and getattr(l_op, "stkoff", None) is not None
                    and getattr(d_op, "stkoff", None) is not None
                    and int(l_op.stkoff) == state_var_stkoff
                    and int(d_op.stkoff) != state_var_stkoff
                ):
                    artifact_blocks.add(serial)
                    break
            if insn.opcode == m_mov:
                l_op = insn.l
                d_op = insn.d
                if (
                    l_op is not None
                    and d_op is not None
                    and getattr(l_op, "t", None) == MOP_N
                    and getattr(d_op, "t", None) == MOP_S
                    and getattr(l_op, "value", None) is not None
                    and getattr(d_op, "stkoff", None) is not None
                    and int(d_op.stkoff) != state_var_stkoff
                    and (int(l_op.value) & 0xFFFFFFFF) in state_constants
                ):
                    artifact_blocks.add(serial)
                    break
    return artifact_blocks


def discover_reconstruction_candidate_seed(
    edge: StateDagEdge,
    *,
    flow_graph: object,
    node_by_key: dict[StateDagNodeKey, StateDagNode],
    state_var_stkoff: int,
    constant_result: SnapshotConstantFixpointResult,
    dispatcher_region: set[int],
) -> tuple[ReconstructionCandidateSeed | None, str | None]:
    """Resolve the discovery-only facts needed to plan one reconstruction."""
    if edge.kind not in (
        SemanticEdgeKind.TRANSITION,
        SemanticEdgeKind.CONDITIONAL_TRANSITION,
    ):
        return None, "unsupported_edge_kind"

    if edge.target_state is None:
        return None, "missing_target_state"

    ordered_path = tuple(int(serial) for serial in edge.ordered_path)
    if not ordered_path:
        return None, "missing_ordered_path"

    resolved = resolve_transition_path_horizon(
        edge,
        flow_graph=flow_graph,
        ordered_path=ordered_path,
        state_var_stkoff=state_var_stkoff,
        constant_result=constant_result,
    )
    if resolved is None:
        return None, "missing_path_horizon"

    horizon_block, site = resolved
    expected_state = int(edge.target_state & 0xFFFFFFFF)
    if int(site.state_value & 0xFFFFFFFF) != expected_state:
        return None, "state_mismatch"

    resolution = resolve_edge_target_entry(
        edge,
        node_by_key=node_by_key,
        dispatcher_region=dispatcher_region,
    )
    if resolution.target_entry is None:
        return None, resolution.rejection_reason or "missing_target_entry"

    return (
        ReconstructionCandidateSeed(
            horizon_block=int(horizon_block),
            site=site,
            target_entry=int(resolution.target_entry),
            original_dispatcher_entry=(
                int(resolution.original_dispatcher_entry)
                if resolution.original_dispatcher_entry is not None
                else None
            ),
        ),
        None,
    )


__all__ = [
    "ReconstructionCandidateSeed",
    "classify_artifact_return_blocks",
    "collect_shared_suffix_blocks",
    "discover_reconstruction_candidate_seed",
    "resolve_state_var_stkoff",
]
