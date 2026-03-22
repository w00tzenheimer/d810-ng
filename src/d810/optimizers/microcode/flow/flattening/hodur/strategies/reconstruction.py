"""Experimental DAG-driven reconstruction strategy.

This strategy is reconstruction-first rather than dispatcher-first. It walks
semantic DAG edges, finds the deepest proven state-write horizon on each edge's
concrete corridor, and then rebuilds the corridor with the least invasive
rewrite that still removes the dispatcher handoff:

- direct truncation when the horizon is private and its trailing glue is clean
- predecessor split when a shared/merged block is uniquely reached via one pred
- grouped duplication when several predecessors of one shared block need
  different semantic targets
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, replace

import ida_hexrays

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.graph_modification import NopInstructions
from d810.cfg.plan import compile_patch_plan
from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateDagNodeKey,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
    find_last_state_write_site_on_path_snapshot,
    find_state_write_sites_snapshot,
    run_snapshot_constant_fixpoint,
)
from d810.recon.flow.transition_builder import (
    TransitionResult,
    _get_state_var_stkoff,
)

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["StateWriteReconstructionStrategy"]


@dataclass(frozen=True, slots=True)
class ReconstructionCandidate:
    """One proven semantic corridor that can be rebuilt without the dispatcher."""

    edge: StateDagEdge
    horizon_block: int
    site: StateWriteSite
    target_entry: int
    first_shared_block: int | None
    via_pred: int | None
    emission_mode: str


class StateWriteReconstructionStrategy:
    """Reconstruct proven semantic corridors from state-write horizons."""

    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "state_write_reconstruction"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    @staticmethod
    def _resolve_state_var_stkoff(snapshot, state_machine) -> int | None:
        detector = getattr(snapshot, "detector", None)
        if detector is not None:
            stkoff = _get_state_var_stkoff(detector)
            if stkoff is not None:
                return int(stkoff)

        state_var = getattr(state_machine, "state_var", None)
        if state_var is None:
            return None
        if getattr(state_var, "t", None) == getattr(ida_hexrays, "mop_S", None):
            s = getattr(state_var, "s", None)
            off = getattr(s, "off", None) if s is not None else None
            if off is not None:
                return int(off)
        return None

    @staticmethod
    def _shared_suffix_blocks(dag: LinearizedStateDag) -> set[int]:
        shared_blocks: set[int] = set()
        for node in dag.nodes:
            shared_blocks.update(int(serial) for serial in node.shared_suffix_blocks)
        return shared_blocks

    @staticmethod
    def _edge_kind_name(edge: StateDagEdge) -> str:
        kind = getattr(edge.kind, "name", None)
        return kind if isinstance(kind, str) else str(edge.kind)

    @staticmethod
    def _source_kind_name(edge: StateDagEdge) -> str:
        kind = getattr(edge.source_anchor.kind, "name", None)
        return kind if isinstance(kind, str) else str(edge.source_anchor.kind)

    @classmethod
    def _make_edge_metadata(
        cls,
        edge: StateDagEdge,
        *,
        horizon_block: int | None = None,
        site: StateWriteSite | None = None,
        target_entry: int | None = None,
        first_shared_block: int | None = None,
        via_pred: int | None = None,
        emission_mode: str | None = None,
        rejection_reason: str | None = None,
    ) -> dict[str, int | str | None]:
        return {
            "edge_kind": cls._edge_kind_name(edge),
            "source_kind": cls._source_kind_name(edge),
            "source_block": int(edge.source_anchor.block_serial),
            "branch_arm": (
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            "target_state": (
                int(edge.target_state & 0xFFFFFFFF)
                if edge.target_state is not None
                else None
            ),
            "target_entry_anchor": (
                int(edge.target_entry_anchor)
                if edge.target_entry_anchor is not None
                else None
            ),
            "horizon_block": int(horizon_block) if horizon_block is not None else None,
            "state_value": (
                int(site.state_value & 0xFFFFFFFF)
                if site is not None
                else None
            ),
            "state_write_ea": int(site.insn_ea) if site is not None else None,
            "first_shared_block": (
                int(first_shared_block) if first_shared_block is not None else None
            ),
            "via_pred": int(via_pred) if via_pred is not None else None,
            "emission_mode": emission_mode,
            "rejection_reason": rejection_reason,
        }

    @staticmethod
    def _node_maps(
        dag: LinearizedStateDag,
    ) -> tuple[
        dict[StateDagNodeKey, StateDagNode],
        dict[StateDagNodeKey, tuple[StateDagEdge, ...]],
        dict[int, tuple[StateDagNode, ...]],
    ]:
        node_by_key = {node.key: node for node in dag.nodes}
        outgoing_by_key: defaultdict[StateDagNodeKey, list[StateDagEdge]] = defaultdict(list)
        nodes_by_entry_anchor: defaultdict[int, list[StateDagNode]] = defaultdict(list)
        for node in dag.nodes:
            nodes_by_entry_anchor[int(node.entry_anchor)].append(node)
        for dag_edge in dag.edges:
            outgoing_by_key[dag_edge.source_key].append(dag_edge)
        return (
            node_by_key,
            {key: tuple(edges) for key, edges in outgoing_by_key.items()},
            {anchor: tuple(nodes) for anchor, nodes in nodes_by_entry_anchor.items()},
        )

    @staticmethod
    def _resolve_target_node(
        edge: StateDagEdge,
        *,
        node_by_key: dict[StateDagNodeKey, StateDagNode],
        nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]],
    ) -> StateDagNode | None:
        if edge.target_key is not None:
            return node_by_key.get(edge.target_key)
        if edge.target_entry_anchor is None:
            return None
        candidates = nodes_by_entry_anchor.get(int(edge.target_entry_anchor), ())
        if len(candidates) != 1:
            return None
        return candidates[0]

    @classmethod
    def _select_single_relay_edge(
        cls,
        node: StateDagNode,
        *,
        flow_graph,
        outgoing_by_key: dict[StateDagNodeKey, tuple[StateDagEdge, ...]],
    ) -> StateDagEdge | None:
        if int(node.entry_anchor) != int(node.handler_serial):
            return None
        if node.local_edges or node.shared_suffix_blocks:
            return None

        entry_snapshot = flow_graph.get_block(int(node.entry_anchor))
        if entry_snapshot is None or entry_snapshot.npred != 1 or entry_snapshot.nsucc != 1:
            return None

        relay_edges = tuple(
            edge
            for edge in outgoing_by_key.get(node.key, ())
            if edge.kind in (
                SemanticEdgeKind.TRANSITION,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
            )
            and edge.target_entry_anchor is not None
            and edge.source_anchor.kind == RedirectSourceKind.UNCONDITIONAL
            and int(edge.source_anchor.block_serial) == int(node.entry_anchor)
        )
        if len(relay_edges) != 1:
            return None
        return relay_edges[0]

    @classmethod
    def _resolve_edge_target_entry(
        cls,
        edge: StateDagEdge,
        *,
        flow_graph,
        node_by_key: dict[StateDagNodeKey, StateDagNode],
        outgoing_by_key: dict[StateDagNodeKey, tuple[StateDagEdge, ...]],
        nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]],
        dispatcher_region: set[int],
    ) -> tuple[int | None, str | None]:
        target_entry = edge.target_entry_anchor
        if target_entry is None:
            return None, "missing_target_entry"
        target_entry = int(target_entry)
        if target_entry in dispatcher_region:
            # The handler's entry_anchor is in the dispatcher/BST region.
            # This often happens when handler_range_map has a catch-all
            # entry with handler_serial=dispatcher, causing resolve_handler()
            # to return the dispatcher node.
            #
            # Strategy: first try non-BST blocks from the target node,
            # then fall back to finding another node with the same
            # target_state but a non-dispatcher handler_serial.
            target_node = node_by_key.get(edge.target_key)
            resolved_non_bst: int | None = None

            # Tier 1: check target node's own blocks
            if target_node is not None:
                candidate_blocks: list[int] = [int(target_node.entry_anchor)]
                candidate_blocks.extend(int(b) for b in target_node.exclusive_blocks)
                candidate_blocks.extend(int(b) for b in target_node.owned_blocks)
                candidate_blocks.extend(int(b) for b in target_node.shared_suffix_blocks)
                for candidate in candidate_blocks:
                    if candidate not in dispatcher_region:
                        resolved_non_bst = candidate
                        break

            # Tier 2: look up another node with the same state_const
            # but a non-dispatcher handler_serial
            if resolved_non_bst is None and edge.target_state is not None:
                for key, node in node_by_key.items():
                    if (
                        key.state_const == edge.target_state
                        and int(node.entry_anchor) not in dispatcher_region
                    ):
                        resolved_non_bst = int(node.entry_anchor)
                        break

            if resolved_non_bst is not None:
                target_entry = resolved_non_bst
                logger.info(
                    "RECON DAG: dispatcher_target_entry resolved non-BST "
                    "entry blk[%d] (original blk[%d] in dispatcher region)",
                    target_entry,
                    int(edge.target_entry_anchor),
                )
            else:
                return None, "dispatcher_target_entry"

        # DISABLED: relay collapsing causes handler orphaning — wire to immediate target.
        # The relay-following loop below would chase chains A->B->C and collapse
        # to A->C, orphaning B.  With relay collapsing off, we always wire to
        # the immediate DAG edge target.
        #
        # current_node = cls._resolve_target_node(
        #     edge,
        #     node_by_key=node_by_key,
        #     nodes_by_entry_anchor=nodes_by_entry_anchor,
        # )
        # visited_keys: set[StateDagNodeKey] = set()
        # relay_hops = 0
        # while current_node is not None:
        #     if current_node.key in visited_keys:
        #         return None, "target_relay_cycle"
        #     visited_keys.add(current_node.key)
        #
        #     relay_edge = cls._select_single_relay_edge(
        #         current_node,
        #         flow_graph=flow_graph,
        #         outgoing_by_key=outgoing_by_key,
        #     )
        #     if relay_edge is None:
        #         break
        #
        #     next_entry = relay_edge.target_entry_anchor
        #     if next_entry is None:
        #         return None, "target_relay_missing_entry"
        #     next_entry = int(next_entry)
        #     if next_entry in dispatcher_region:
        #         return None, "target_relay_dispatcher_entry"
        #
        #     target_entry = next_entry
        #     relay_hops += 1
        #     if relay_hops > 8:
        #         return None, "target_relay_depth"
        #     current_node = cls._resolve_target_node(
        #         relay_edge,
        #         node_by_key=node_by_key,
        #         nodes_by_entry_anchor=nodes_by_entry_anchor,
        #     )

        return target_entry, None

    @staticmethod
    def _resolve_old_target(
        flow_graph,
        source_block: int,
        ordered_path: tuple[int, ...],
    ) -> int | None:
        block = flow_graph.get_block(source_block)
        if block is None:
            return None
        if source_block in ordered_path:
            idx = ordered_path.index(source_block)
            if idx + 1 < len(ordered_path):
                next_block = int(ordered_path[idx + 1])
                if next_block in tuple(block.succs):
                    return next_block
        if block.nsucc == 1:
            return int(block.succs[0])
        return None

    @staticmethod
    def _is_shared_block(
        flow_graph,
        block_serial: int,
        *,
        shared_suffix_blocks: set[int],
    ) -> bool:
        if block_serial in shared_suffix_blocks:
            return True
        block = flow_graph.get_block(block_serial)
        return bool(block is not None and block.npred > 1)

    @classmethod
    def _first_shared_block_index(
        cls,
        flow_graph,
        ordered_path: tuple[int, ...],
        *,
        start_index: int,
        shared_suffix_blocks: set[int],
        dispatcher_region: set[int],
    ) -> int | None:
        for index in range(start_index, len(ordered_path)):
            block_serial = int(ordered_path[index])
            if block_serial in dispatcher_region:
                continue
            if cls._is_shared_block(
                flow_graph,
                block_serial,
                shared_suffix_blocks=shared_suffix_blocks,
            ):
                return index
        return None

    @classmethod
    def _first_boundary_index(
        cls,
        flow_graph,
        ordered_path: tuple[int, ...],
        *,
        start_index: int,
        shared_suffix_blocks: set[int],
        dispatcher_region: set[int],
    ) -> int | None:
        for index in range(start_index, len(ordered_path)):
            block_serial = int(ordered_path[index])
            if block_serial in dispatcher_region or cls._is_shared_block(
                flow_graph,
                block_serial,
                shared_suffix_blocks=shared_suffix_blocks,
            ):
                return index
        return None

    @staticmethod
    def _compute_reachable_blocks(
        flow_graph: object,
        *,
        start_serial: int | None,
        limit: int = 4096,
    ) -> set[int] | None:
        if start_serial is None:
            return None
        try:
            start_block = flow_graph.get_block(start_serial)
        except Exception:
            start_block = None
        if start_block is None:
            return None

        reachable: set[int] = set()
        worklist: list[int] = [int(start_serial)]
        while worklist and len(reachable) < limit:
            current = worklist.pop()
            if current in reachable:
                continue
            reachable.add(current)
            try:
                succs = tuple(flow_graph.successors(current))
            except Exception:
                block = flow_graph.get_block(current)
                succs = tuple(getattr(block, "succs", ())) if block is not None else ()
            for succ in succs:
                succ_serial = int(succ)
                if succ_serial not in reachable:
                    worklist.append(succ_serial)
        return reachable

    @staticmethod
    def _collect_dispatcher_predecessors(
        flow_graph: object,
        dispatcher_serial: int,
        *,
        bst_node_blocks: set[int],
    ) -> tuple[int, ...]:
        if dispatcher_serial < 0:
            return ()
        try:
            dispatcher_block = flow_graph.get_block(dispatcher_serial)
        except Exception:
            dispatcher_block = None
        if dispatcher_block is None:
            return ()
        residual: list[int] = []
        for serial in sorted(tuple(getattr(dispatcher_block, "preds", ()))):
            if serial == dispatcher_serial or serial in bst_node_blocks:
                continue
            residual.append(int(serial))
        return tuple(residual)

    @classmethod
    def _collect_residual_dispatcher_predecessors(
        cls,
        flow_graph: object,
        dispatcher_serial: int,
        *,
        bst_node_blocks: set[int],
        reachable_from_serial: int | None = None,
    ) -> tuple[int, ...]:
        residual = cls._collect_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
        )
        reachable_blocks = cls._compute_reachable_blocks(
            flow_graph,
            start_serial=reachable_from_serial,
        )
        if reachable_blocks is None:
            return residual
        return tuple(serial for serial in residual if serial in reachable_blocks)

    @staticmethod
    def _is_backward_same_corridor_target(
        ordered_path: tuple[int, ...],
        *,
        rewrite_block: int,
        target_entry: int,
    ) -> bool:
        if rewrite_block not in ordered_path or target_entry not in ordered_path:
            return False
        return ordered_path.index(target_entry) <= ordered_path.index(rewrite_block)

    @classmethod
    def _can_emit_direct(
        cls,
        edge: StateDagEdge,
        flow_graph,
        ordered_path: tuple[int, ...],
        *,
        horizon_index: int,
        site: StateWriteSite,
        shared_suffix_blocks: set[int],
        dispatcher_region: set[int],
    ) -> bool:
        horizon_block = int(ordered_path[horizon_index])
        block = flow_graph.get_block(horizon_block)
        if block is None or block.nsucc != 1 or block.npred > 1:
            return False
        if cls._is_shared_block(
            flow_graph,
            horizon_block,
            shared_suffix_blocks=shared_suffix_blocks,
        ):
            return False
        if (
            edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
            and horizon_block == int(edge.source_anchor.block_serial)
        ):
            return False

        boundary_index = cls._first_boundary_index(
            flow_graph,
            ordered_path,
            start_index=horizon_index + 1,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )
        end_index = len(ordered_path) if boundary_index is None else boundary_index
        for index in range(horizon_index + 1, end_index):
            block_serial = int(ordered_path[index])
            curr = flow_graph.get_block(block_serial)
            if curr is None or curr.nsucc != 1 or curr.npred != 1:
                return False
            if cls._is_shared_block(
                flow_graph,
                block_serial,
                shared_suffix_blocks=shared_suffix_blocks,
            ):
                return False
        return True

    @classmethod
    def _can_emit_conditional_arm(
        cls,
        edge: StateDagEdge,
        flow_graph,
        ordered_path: tuple[int, ...],
        *,
        horizon_index: int,
        site: StateWriteSite,
        dispatcher_serial: int,
    ) -> bool:
        """Accept conditional transition edges where horizon is the branch block.

        Unlike _can_emit_direct (which requires nsucc==1), this accepts 2-way
        blocks. The Jcc stays alive; we redirect specific arms.
        """
        if edge.kind != SemanticEdgeKind.CONDITIONAL_TRANSITION:
            return False

        horizon_block = ordered_path[horizon_index]
        if horizon_block != int(edge.source_anchor.block_serial):
            return False

        block = flow_graph.get_block(horizon_block)
        if block is None or block.nsucc != 2:
            return False

        branch_arm = edge.source_anchor.branch_arm
        if branch_arm is None:
            return False

        logger.info(
            "RECON DAG: conditional_arm candidate: horizon=%d, branch_arm=%d",
            horizon_block, branch_arm,
        )
        return True

    @classmethod
    def _build_candidate(
        cls,
        edge: StateDagEdge,
        *,
        flow_graph,
        node_by_key: dict[StateDagNodeKey, StateDagNode],
        outgoing_by_key: dict[StateDagNodeKey, tuple[StateDagEdge, ...]],
        nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]],
        state_var_stkoff: int,
        constant_result: SnapshotConstantFixpointResult,
        shared_suffix_blocks: set[int],
        dispatcher_region: set[int],
        dispatcher_serial: int = -1,
    ) -> tuple[ReconstructionCandidate | None, dict[str, int | str | None] | None]:
        if edge.kind not in (
            SemanticEdgeKind.TRANSITION,
            SemanticEdgeKind.CONDITIONAL_TRANSITION,
        ):
            return None, cls._make_edge_metadata(
                edge,
                rejection_reason="unsupported_edge_kind",
            )

        if edge.target_state is None:
            return None, cls._make_edge_metadata(
                edge,
                rejection_reason="missing_target_state",
            )

        ordered_path = tuple(int(serial) for serial in edge.ordered_path)
        if not ordered_path:
            return None, cls._make_edge_metadata(
                edge,
                rejection_reason="missing_ordered_path",
            )

        resolved: tuple[int, StateWriteSite] | None = None

        # Fast path: use DFS-proven write site from DAG edge
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
                    write_block, write_ea,
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
            # Fallback for CONDITIONAL_TRANSITION edges: the live DFS already
            # proved this transition exists but the snapshot path evaluator
            # could not re-derive the constant (e.g. MBA-computed values with
            # mba=None).  Walk the path in reverse, first trying the per-block
            # evaluator with fixpoint maps, then a raw destination scan.
            for rev_idx, path_serial in enumerate(reversed(ordered_path)):
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
                    # Override state_value with DFS-proven target if the
                    # snapshot evaluator resolved a different (stale) value.
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
                # Last resort: raw scan for any instruction writing to state
                # var stkoff, trusting the DFS-proven target_state entirely.
                MOP_S = 3
                for rev_idx, path_serial in enumerate(reversed(ordered_path)):
                    block_snap = flow_graph.get_block(path_serial)
                    if block_snap is None:
                        continue
                    for insn_idx, insn in enumerate(
                        reversed(block_snap.insn_snapshots)
                    ):
                        dest = getattr(insn, "d", None)
                        if dest is None:
                            continue
                        if getattr(dest, "t", None) != MOP_S:
                            continue
                        dest_stkoff = getattr(dest, "stkoff", None)
                        if dest_stkoff is None:
                            s_ref = getattr(dest, "s", None)
                            dest_stkoff = (
                                getattr(s_ref, "off", None)
                                if s_ref is not None
                                else None
                            )
                        if dest_stkoff is not None and int(dest_stkoff) == int(
                            state_var_stkoff
                        ):
                            actual_insn_idx = (
                                len(block_snap.insn_snapshots) - 1 - insn_idx
                            )
                            site = StateWriteSite(
                                block_serial=path_serial,
                                state_value=int(edge.target_state & 0xFFFFFFFF),
                                insn_ea=int(insn.ea),
                                insn_index=actual_insn_idx,
                            )
                            resolved = (int(path_serial), site)
                            logger.info(
                                "RECON DAG: conditional fallback horizon at "
                                "blk[%d] (DFS-trusted, raw dest scan)",
                                path_serial,
                            )
                            break
                    if resolved is not None:
                        break

        if resolved is None:
            return None, cls._make_edge_metadata(
                edge,
                rejection_reason="missing_path_horizon",
            )

        horizon_block, site = resolved
        expected_state = int(edge.target_state & 0xFFFFFFFF)
        if int(site.state_value & 0xFFFFFFFF) != expected_state:
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                rejection_reason="state_mismatch",
            )

        target_entry, target_entry_rejection = cls._resolve_edge_target_entry(
            edge,
            flow_graph=flow_graph,
            node_by_key=node_by_key,
            outgoing_by_key=outgoing_by_key,
            nodes_by_entry_anchor=nodes_by_entry_anchor,
            dispatcher_region=dispatcher_region,
        )
        if target_entry is None:
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                rejection_reason=target_entry_rejection or "missing_target_entry",
            )

        if cls._is_backward_same_corridor_target(
            ordered_path,
            rewrite_block=horizon_block,
            target_entry=target_entry,
        ):
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                target_entry=target_entry,
                rejection_reason="backward_same_corridor_target",
            )

        try:
            horizon_index = ordered_path.index(int(horizon_block))
        except ValueError:
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                target_entry=target_entry,
                rejection_reason="horizon_not_on_path",
            )

        first_shared_index = cls._first_shared_block_index(
            flow_graph,
            ordered_path,
            start_index=horizon_index,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )
        first_shared_block = (
            int(ordered_path[first_shared_index])
            if first_shared_index is not None
            else None
        )

        if cls._can_emit_direct(
            edge,
            flow_graph,
            ordered_path,
            horizon_index=horizon_index,
            site=site,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        ):
            return (
                ReconstructionCandidate(
                    edge=edge,
                    horizon_block=int(horizon_block),
                    site=site,
                    target_entry=int(target_entry),
                    first_shared_block=first_shared_block,
                    via_pred=None,
                    emission_mode="direct",
                ),
                None,
            )

        if cls._can_emit_conditional_arm(
            edge,
            flow_graph,
            ordered_path,
            horizon_index=horizon_index,
            site=site,
            dispatcher_serial=dispatcher_serial,
        ):
            return (
                ReconstructionCandidate(
                    edge=edge,
                    horizon_block=int(ordered_path[horizon_index]),
                    site=site,
                    target_entry=int(target_entry),
                    first_shared_block=None,
                    via_pred=None,
                    emission_mode="conditional_arm",
                ),
                None,
            )

        if first_shared_index is None:
            rejection_reason = (
                "blocked_side_effects"
                if site.unsafe_trailing_insn_eas
                else "no_shared_rewrite_site"
            )
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                target_entry=target_entry,
                rejection_reason=rejection_reason,
            )

        via_pred = (
            int(ordered_path[first_shared_index - 1])
            if first_shared_index > 0
            else None
        )
        shared_block = int(ordered_path[first_shared_index])
        shared_snapshot = flow_graph.get_block(shared_block)
        if (
            via_pred is None
            or shared_snapshot is None
            or via_pred not in tuple(shared_snapshot.preds)
        ):
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                target_entry=target_entry,
                first_shared_block=shared_block,
                via_pred=via_pred,
                rejection_reason="missing_via_pred",
            )

        return (
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(horizon_block),
                site=site,
                target_entry=int(target_entry),
                first_shared_block=shared_block,
                via_pred=int(via_pred),
                emission_mode="pred_split",
            ),
            None,
        )

    @classmethod
    def _record_accept(
        cls,
        metadata: list[dict[str, int | str | None]],
        candidate: ReconstructionCandidate,
    ) -> None:
        metadata.append(
            cls._make_edge_metadata(
                candidate.edge,
                horizon_block=candidate.horizon_block,
                site=candidate.site,
                target_entry=candidate.target_entry,
                first_shared_block=candidate.first_shared_block,
                via_pred=candidate.via_pred,
                emission_mode=candidate.emission_mode,
            )
        )

    @classmethod
    def _emit_direct_candidate(
        cls,
        candidate: ReconstructionCandidate,
        *,
        flow_graph,
        mba,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        accepted_metadata: list[dict[str, int | str | None]],
        rejected_metadata: list[dict[str, int | str | None]],
    ) -> bool:
        ordered_path = tuple(int(serial) for serial in candidate.edge.ordered_path)
        old_target = cls._resolve_old_target(
            flow_graph,
            candidate.horizon_block,
            ordered_path,
        )
        if old_target is None or old_target == candidate.target_entry:
            rejected_metadata.append(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=candidate.first_shared_block,
                    rejection_reason="noop_or_missing_old_target",
                )
            )
            return False

        state_write_ea = int(candidate.site.insn_ea)
        modifications.append(
            NopInstructions(
                block_serial=int(candidate.horizon_block),
                insn_eas=(state_write_ea,),
            )
        )
        modifications.append(
            builder.goto_redirect(
                source_block=candidate.horizon_block,
                target_block=candidate.target_entry,
                old_target=old_target,
            )
        )
        owned_blocks.add(int(candidate.horizon_block))
        owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))
        cls._record_accept(accepted_metadata, candidate)
        logger.info(
            "RECON DAG: direct %s state=0x%08X -> %s (nopped=%d)",
            blk_label(mba, candidate.horizon_block),
            candidate.site.state_value & 0xFFFFFFFF,
            blk_label(mba, candidate.target_entry),
            1,  # single state-write NOP
        )
        return True

    @classmethod
    def _emit_conditional_arm_candidate(
        cls,
        candidate: ReconstructionCandidate,
        flow_graph,
        builder: ModificationBuilder,
        *,
        node_by_key: dict[StateDagNodeKey, StateDagNode],
        dispatcher_serial: int,
    ) -> tuple[list, int]:
        """Emit modifications for a conditional-arm candidate.

        NOPs the state-write instruction and redirects the transition arm
        to the resolved target handler entry. When the passthrough arm also
        targets the dispatcher, redirects it to the current state's entry
        anchor.
        """
        modifications: list = []
        count = 0
        edge = candidate.edge
        branch_arm = edge.source_anchor.branch_arm
        horizon_block = candidate.horizon_block

        block = flow_graph.get_block(horizon_block)
        if block is None:
            return modifications, 0

        # NOP only the state-write instruction
        state_write_ea = int(candidate.site.insn_ea)
        modifications.append(
            NopInstructions(
                block_serial=horizon_block,
                insn_eas=(state_write_ea,),
            )
        )

        transition_arm_target = int(block.succs[branch_arm])
        other_arm = 1 - branch_arm
        other_arm_target = int(block.succs[other_arm])
        both_arms_to_dispatcher = (
            transition_arm_target == dispatcher_serial
            and other_arm_target == dispatcher_serial
        )

        # Resolve current state entry for passthrough arm
        current_entry: int | None = None
        if other_arm_target == dispatcher_serial:
            source_node = node_by_key.get(edge.source_key)
            if source_node is not None and edge.source_key.state_const is not None:
                current_entry = source_node.entry_anchor

        if both_arms_to_dispatcher:
            # Both arms go to dispatcher -- cannot use edge_redirect (would
            # redirect both via old_target match). Handle by arm index.
            # RedirectBranch only modifies arm=1.
            if branch_arm == 1:
                modifications.append(
                    builder.edge_redirect(
                        source_block=horizon_block,
                        target_block=candidate.target_entry,
                        old_target=dispatcher_serial,
                    )
                )
                count += 1
                # Passthrough is arm=0 -- left as residual
            else:
                # branch_arm == 0: transition is fallthrough, passthrough is arm=1
                if current_entry is not None:
                    modifications.append(
                        builder.edge_redirect(
                            source_block=horizon_block,
                            target_block=current_entry,
                            old_target=dispatcher_serial,
                        )
                    )
                    count += 1
                # Transition is arm=0 -- left as residual
        else:
            # Normal case: at most one arm targets dispatcher.
            if transition_arm_target == dispatcher_serial:
                modifications.append(
                    builder.edge_redirect(
                        source_block=horizon_block,
                        target_block=candidate.target_entry,
                        old_target=dispatcher_serial,
                    )
                )
                count += 1

            if other_arm_target == dispatcher_serial and current_entry is not None:
                if other_arm == 1:
                    modifications.append(
                        builder.edge_redirect(
                            source_block=horizon_block,
                            target_block=current_entry,
                            old_target=dispatcher_serial,
                        )
                    )
                    count += 1

        return modifications, count

    @classmethod
    def _resolve_passthrough_blocks(
        cls,
        candidate: ReconstructionCandidate,
        flow_graph,
        builder: ModificationBuilder,
        *,
        dispatcher_serial: int,
        current_state_entry: int | None,
    ) -> list:
        """Redirect dispatcher-pointing arms of passthrough blocks on corridor path.

        Intermediate blocks on the ordered_path (between the source anchor and the
        horizon) may have edges that point back to the dispatcher with an unchanged
        state variable.  For 1-way blocks this emits a goto redirect; for 2-way
        blocks with arm=1 pointing to the dispatcher it emits an edge redirect.
        """
        if current_state_entry is None:
            return []

        modifications: list = []
        edge = candidate.edge
        ordered_path = tuple(int(serial) for serial in edge.ordered_path)

        for serial in ordered_path:
            if serial == candidate.horizon_block:
                continue  # horizon handled by main emission

            block = flow_graph.get_block(serial)
            if block is None:
                continue

            if block.nsucc == 1:
                if int(block.succs[0]) == dispatcher_serial:
                    modifications.append(
                        builder.goto_redirect(
                            source_block=serial,
                            target_block=current_state_entry,
                            old_target=dispatcher_serial,
                        )
                    )
            elif block.nsucc == 2:
                for arm in (0, 1):
                    if int(block.succs[arm]) == dispatcher_serial:
                        # RedirectBranch only handles arm=1
                        if arm == 1:
                            modifications.append(
                                builder.edge_redirect(
                                    source_block=serial,
                                    target_block=current_state_entry,
                                    old_target=dispatcher_serial,
                                )
                            )
                        # arm=0: left as residual (fallthrough limitation)
                        break

        return modifications

    @classmethod
    def _emit_shared_group(
        cls,
        shared_block: int,
        candidates: list[ReconstructionCandidate],
        *,
        flow_graph,
        mba,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        accepted_metadata: list[dict[str, int | str | None]],
        rejected_metadata: list[dict[str, int | str | None]],
    ) -> int:
        shared_snapshot = flow_graph.get_block(shared_block)
        if shared_snapshot is None:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="missing_shared_block",
                )
                for candidate in candidates
            )
            return 0

        by_pred: dict[int, ReconstructionCandidate] = {}
        for candidate in candidates:
            assert candidate.via_pred is not None
            existing = by_pred.get(candidate.via_pred)
            if existing is None:
                by_pred[candidate.via_pred] = candidate
                continue
            if existing.target_entry == candidate.target_entry:
                continue
            rejected_metadata.append(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="shared_block_conflict",
                )
            )
            return 0

        if not by_pred:
            return 0

        ordered_candidates = [by_pred[pred] for pred in sorted(by_pred)]
        old_target = cls._resolve_old_target(
            flow_graph,
            shared_block,
            tuple(int(serial) for serial in ordered_candidates[0].edge.ordered_path),
        )
        if old_target is None:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="missing_old_target",
                )
                for candidate in ordered_candidates
            )
            return 0

        shared_preds = tuple(int(pred) for pred in shared_snapshot.preds)
        candidate_preds = {int(candidate.via_pred) for candidate in ordered_candidates}
        non_candidate_preds = [
            pred for pred in shared_preds if pred not in candidate_preds
        ]

        per_pred_targets: list[tuple[int, int]]
        if len(ordered_candidates) == 1:
            candidate = ordered_candidates[0]
            if candidate.target_entry == old_target:
                rejected_metadata.append(
                    cls._make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason="noop_or_missing_old_target",
                    )
                )
                return 0
            if not non_candidate_preds:
                rejected_metadata.append(
                    cls._make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=shared_block,
                        via_pred=candidate.via_pred,
                        rejection_reason="missing_keep_pred",
                    )
                )
                return 0
            per_pred_targets = [
                (int(non_candidate_preds[0]), int(old_target)),
                (int(candidate.via_pred), int(candidate.target_entry)),
            ]
        elif non_candidate_preds:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="shared_group_requires_multi_clone",
                )
                for candidate in ordered_candidates
            )
            return 0
        elif len(ordered_candidates) == 2:
            keep_index = next(
                (
                    index
                    for index, candidate in enumerate(ordered_candidates)
                    if int(candidate.target_entry) == int(old_target)
                ),
                0,
            )
            first = ordered_candidates[keep_index]
            second = ordered_candidates[1 - keep_index]
            per_pred_targets = [
                (int(first.via_pred), int(first.target_entry)),
                (int(second.via_pred), int(second.target_entry)),
            ]
        else:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="shared_group_too_wide",
                )
                for candidate in ordered_candidates
            )
            return 0

        # NOP state-write instructions BEFORE duplication so the clone
        # inherits the already-NOPed block content.  Deduplicate by
        # (block_serial, insn_ea) in case multiple candidates share a site.
        seen_nop_sites: set[tuple[int, int]] = set()
        nopped_count = 0
        for candidate in ordered_candidates:
            nop_key = (int(candidate.site.block_serial), int(candidate.site.insn_ea))
            if nop_key in seen_nop_sites:
                continue
            seen_nop_sites.add(nop_key)
            modifications.append(
                NopInstructions(
                    block_serial=nop_key[0],
                    insn_eas=(nop_key[1],),
                )
            )
            nopped_count += 1

        modifications.append(
            builder.duplicate_and_redirect(
                source_block=shared_block,
                per_pred_targets=per_pred_targets,
            )
        )
        owned_blocks.add(int(shared_block))
        for _, target_entry in per_pred_targets:
            owned_edges.add((int(shared_block), int(target_entry)))
        for candidate in ordered_candidates:
            cls._record_accept(
                accepted_metadata,
                replace(candidate, emission_mode="duplicate_and_redirect"),
            )
        logger.info(
            "RECON DAG: duplicate-and-redirect %s preds=%s nopped=%d",
            blk_label(mba, shared_block),
            [
                (blk_label(mba, pred), blk_label(mba, target))
                for pred, target in per_pred_targets
            ],
            nopped_count,
        )
        return len(ordered_candidates)

    def is_applicable(self, snapshot) -> bool:
        sm = snapshot.state_machine
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if sm is None or flow_graph is None or bst_result is None:
            return False
        if not sm.handlers:
            return False
        return self._resolve_state_var_stkoff(snapshot, sm) is not None

    def plan(self, snapshot):
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        bst_result = snapshot.bst_result
        flow_graph = snapshot.flow_graph
        mba = snapshot.mba
        assert sm is not None
        assert bst_result is not None
        assert flow_graph is not None

        state_var_stkoff = self._resolve_state_var_stkoff(snapshot, sm)
        if state_var_stkoff is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=sm.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
        )
        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            state_var_stkoff,
        )

        dispatcher_region = set(dag.bst_node_blocks)
        if dag.dispatcher_entry_serial >= 0:
            dispatcher_region.add(int(dag.dispatcher_entry_serial))
        shared_suffix_blocks = self._shared_suffix_blocks(dag)
        node_by_key, outgoing_by_key, nodes_by_entry_anchor = self._node_maps(dag)

        dispatcher_serial = int(dag.dispatcher_entry_serial)

        raw_candidates: list[ReconstructionCandidate] = []
        rejected_metadata: list[dict[str, int | str | None]] = []
        edge_kind_counts = Counter(
            self._edge_kind_name(e) for e in dag.edges
        )
        logger.info(
            "RECON DAG: edge distribution: %s",
            ", ".join(f"{k}={v}" for k, v in edge_kind_counts.most_common()),
        )
        for edge in dag.edges:
            candidate, rejection = self._build_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=node_by_key,
                outgoing_by_key=outgoing_by_key,
                nodes_by_entry_anchor=nodes_by_entry_anchor,
                state_var_stkoff=state_var_stkoff,
                constant_result=constant_result,
                shared_suffix_blocks=shared_suffix_blocks,
                dispatcher_region=dispatcher_region,
                dispatcher_serial=dispatcher_serial,
            )
            if candidate is not None:
                raw_candidates.append(candidate)
            elif rejection is not None:
                rejected_metadata.append(rejection)

        if not raw_candidates:
            logger.info(
                "RECON DAG: no proven corridors across %d semantic edges (rejections=%d)",
                len(dag.edges),
                len(rejected_metadata),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            return None

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        accepted_metadata: list[dict[str, int | str | None]] = []

        direct_groups: defaultdict[int, list[ReconstructionCandidate]] = defaultdict(list)
        shared_groups: defaultdict[int, list[ReconstructionCandidate]] = defaultdict(list)
        conditional_arm_candidates: list[ReconstructionCandidate] = []
        for candidate in raw_candidates:
            if candidate.emission_mode == "conditional_arm":
                conditional_arm_candidates.append(candidate)
            elif candidate.emission_mode == "direct":
                direct_groups[int(candidate.horizon_block)].append(candidate)
            else:
                assert candidate.first_shared_block is not None
                shared_groups[int(candidate.first_shared_block)].append(candidate)

        for candidate in conditional_arm_candidates:
            mods, count = self._emit_conditional_arm_candidate(
                candidate,
                flow_graph,
                builder,
                node_by_key=node_by_key,
                dispatcher_serial=dispatcher_serial,
            )
            if mods:
                modifications.extend(mods)
                owned_blocks.add(int(candidate.horizon_block))
                owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))
                self._record_accept(accepted_metadata, candidate)

                # Resolve passthrough blocks on the corridor path
                source_node = node_by_key.get(candidate.edge.source_key)
                pt_entry: int | None = None
                if source_node is not None and candidate.edge.source_key.state_const is not None:
                    pt_entry = source_node.entry_anchor
                pt_mods = self._resolve_passthrough_blocks(
                    candidate, flow_graph, builder,
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry,
                )
                modifications.extend(pt_mods)

                logger.info(
                    "RECON DAG: conditional_arm %s state=0x%08X -> %s (arm=%d, redirects=%d, passthrough=%d)",
                    blk_label(mba, candidate.horizon_block),
                    candidate.site.state_value & 0xFFFFFFFF,
                    blk_label(mba, candidate.target_entry),
                    candidate.edge.source_anchor.branch_arm or 0,
                    count,
                    len(pt_mods),
                )

        for horizon_block in sorted(direct_groups):
            group = direct_groups[horizon_block]
            targets = {candidate.target_entry for candidate in group}
            if len(targets) > 1:
                rejected_metadata.extend(
                    self._make_edge_metadata(
                        candidate.edge,
                        horizon_block=candidate.horizon_block,
                        site=candidate.site,
                        target_entry=candidate.target_entry,
                        first_shared_block=candidate.first_shared_block,
                        rejection_reason="direct_conflict",
                    )
                    for candidate in group
                )
                continue
            direct_candidate = group[0]
            self._emit_direct_candidate(
                direct_candidate,
                flow_graph=flow_graph,
                mba=mba,
                builder=builder,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                accepted_metadata=accepted_metadata,
                rejected_metadata=rejected_metadata,
            )
            # Resolve passthrough blocks for CONDITIONAL_TRANSITION direct candidates
            if direct_candidate.edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
                source_node = node_by_key.get(direct_candidate.edge.source_key)
                pt_entry_d: int | None = None
                if (
                    source_node is not None
                    and direct_candidate.edge.source_key.state_const is not None
                ):
                    pt_entry_d = source_node.entry_anchor
                pt_mods_d = self._resolve_passthrough_blocks(
                    direct_candidate, flow_graph, builder,
                    dispatcher_serial=dispatcher_serial,
                    current_state_entry=pt_entry_d,
                )
                modifications.extend(pt_mods_d)

        for shared_block in sorted(shared_groups):
            self._emit_shared_group(
                shared_block,
                shared_groups[shared_block],
                flow_graph=flow_graph,
                mba=mba,
                builder=builder,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                accepted_metadata=accepted_metadata,
                rejected_metadata=rejected_metadata,
            )

        if not modifications:
            logger.info(
                "RECON DAG: all %d candidate corridors were rejected during emission",
                len(raw_candidates),
            )
            if rejected_metadata:
                reason_counts = Counter(
                    (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                    for r in rejected_metadata
                )
                for (kind, reason), count in reason_counts.most_common():
                    logger.info(
                        "  edge_kind=%s rejection_reason=%s count=%d",
                        kind, reason, count,
                    )
            return None

        logger.info(
            "RECON DAG: accepted %d/%d candidate corridors (rejections=%d)",
            len(accepted_metadata),
            len(raw_candidates),
            len(rejected_metadata),
        )
        if rejected_metadata:
            reason_counts = Counter(
                (r.get("edge_kind", "?"), r.get("rejection_reason", "unknown"))
                for r in rejected_metadata
            )
            for (kind, reason), count in reason_counts.most_common():
                logger.info(
                    "  edge_kind=%s rejection_reason=%s count=%d",
                    kind, reason, count,
                )

        residual_dispatcher_preds: tuple[int, ...] = ()
        allow_post_apply_bst_cleanup = True
        post_apply_bst_cleanup_reason: str | None = None
        if dispatcher_serial >= 0:
            projected_flow_graph = flow_graph
            try:
                patch_plan = compile_patch_plan(modifications, flow_graph)
                projected_flow_graph = project_post_state(flow_graph, patch_plan)
            except Exception:
                projected_flow_graph = flow_graph
            residual_dispatcher_preds = self._collect_residual_dispatcher_predecessors(
                projected_flow_graph,
                dispatcher_serial,
                bst_node_blocks=dispatcher_region,
                reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
            )
            if residual_dispatcher_preds:
                allow_post_apply_bst_cleanup = False
                post_apply_bst_cleanup_reason = "residual_dispatcher_predecessors"
                logger.info(
                    "RECON DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
                    [blk_label(mba, serial) for serial in residual_dispatcher_preds],
                )

            # ------------------------------------------------------------------
            # Pre-header redirect: wire function entry to first handler
            # ------------------------------------------------------------------
            dispatcher = getattr(bst_result, "dispatcher", None)
            _bst_set = set(dag.bst_node_blocks)
            _bst_set.add(dispatcher_serial)

            if (
                dispatcher is not None
                and dag.pre_header_serial is not None
                and dag.initial_state is not None
            ):
                resolved = dispatcher.lookup(dag.initial_state)
                if resolved is not None and int(resolved) not in _bst_set:
                    pre_blk = flow_graph.get_block(dag.pre_header_serial)
                    if pre_blk is not None and pre_blk.nsucc == 1:
                        old = int(pre_blk.succs[0])
                        if old == dispatcher_serial or old in _bst_set:
                            modifications.append(
                                builder.goto_redirect(
                                    source_block=dag.pre_header_serial,
                                    target_block=int(resolved),
                                    old_target=old,
                                )
                            )
                            logger.info(
                                "RECON BRIDGE: pre-header blk[%d] -> blk[%d]",
                                dag.pre_header_serial, int(resolved),
                            )

            # ------------------------------------------------------------------
            # Bridge Builder: force-wire unclaimed DAG edge targets
            # ------------------------------------------------------------------
            # The strict corridor emitter handled the clean edges.
            # Now wire every remaining semantic edge the DAG mapped.

            # Step 1: Gather all target entries and source blocks that were
            # successfully claimed by the strict corridor emitter.
            claimed_targets: set[int] = set()
            claimed_sources: set[int] = set()
            for mod in modifications:
                # Collect targets: RedirectGoto/RedirectBranch/EdgeRedirectViaPredSplit
                if hasattr(mod, "new_target"):
                    claimed_targets.add(int(mod.new_target))
                # ConvertToGoto
                if hasattr(mod, "goto_target"):
                    claimed_targets.add(int(mod.goto_target))
                # CreateConditionalRedirect
                if hasattr(mod, "conditional_target"):
                    claimed_targets.add(int(mod.conditional_target))
                if hasattr(mod, "fallthrough_target"):
                    claimed_targets.add(int(mod.fallthrough_target))
                # DuplicateAndRedirect: per_pred_targets is ((pred, target), ...)
                if hasattr(mod, "per_pred_targets"):
                    for _pred, _tgt in mod.per_pred_targets:
                        claimed_sources.add(int(_pred))
                        claimed_targets.add(int(_tgt))
                # Collect sources to avoid double-wiring the same exit block
                if hasattr(mod, "from_serial"):
                    claimed_sources.add(int(mod.from_serial))
                if hasattr(mod, "source_serial"):
                    claimed_sources.add(int(mod.source_serial))
                if hasattr(mod, "source_block"):
                    claimed_sources.add(int(mod.source_block))
                if hasattr(mod, "src_block"):
                    claimed_sources.add(int(mod.src_block))
                if hasattr(mod, "block_serial"):
                    claimed_sources.add(int(mod.block_serial))

            # Step 2: Scan DAG edges for unclaimed targets
            bridge_mods: list = []

            for edge in dag.edges:
                if edge.target_entry_anchor is None:
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in _bst_set:
                    continue  # Target is in dispatcher/BST region
                if target_entry in claimed_targets:
                    continue  # Already wired by strict emitter

                # This target is unclaimed — find the exit block to wire from.
                # Walk ordered_path to find the last non-BST block.
                if not edge.ordered_path:
                    continue

                exit_block: int | None = None
                for serial in reversed(edge.ordered_path):
                    if serial not in _bst_set:
                        exit_block = serial
                        break

                if exit_block is None:
                    continue

                # Skip if this exit block is already the source of a modification
                if exit_block in claimed_sources:
                    continue

                block = flow_graph.get_block(exit_block)
                if block is None:
                    continue

                # Check if exit_block already points to the target
                already_wired = any(
                    int(block.succs[i]) == target_entry
                    for i in range(block.nsucc)
                )
                if already_wired:
                    claimed_targets.add(target_entry)
                    continue

                if block.nsucc == 1:
                    # 1-way block: redirect goto to target handler entry
                    old_target = int(block.succs[0])
                    if old_target == dispatcher_serial or old_target in _bst_set:
                        # NOP the state-write instruction if known
                        if edge.last_write_site is not None:
                            _ws_blk, _ws_ea = edge.last_write_site
                            bridge_mods.append(
                                NopInstructions(
                                    block_serial=int(_ws_blk),
                                    insn_eas=(int(_ws_ea),),
                                )
                            )
                        else:
                            logger.debug(
                                "RECON BRIDGE: no last_write_site for "
                                "blk[%d] -> blk[%d], skipping NOP",
                                exit_block, target_entry,
                            )
                        bridge_mods.append(
                            builder.goto_redirect(
                                source_block=exit_block,
                                target_block=target_entry,
                                old_target=old_target,
                            )
                        )
                        claimed_targets.add(target_entry)
                        claimed_sources.add(exit_block)
                        logger.info(
                            "RECON BRIDGE: wire blk[%d] -> blk[%d] (1-way)",
                            exit_block, target_entry,
                        )
                elif block.nsucc == 2:
                    # 2-way block: find which arm points to BST/dispatcher
                    for arm in range(2):
                        arm_target = int(block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # NOP the state-write instruction if known
                                if edge.last_write_site is not None:
                                    _ws_blk, _ws_ea = edge.last_write_site
                                    bridge_mods.append(
                                        NopInstructions(
                                            block_serial=int(_ws_blk),
                                            insn_eas=(int(_ws_ea),),
                                        )
                                    )
                                else:
                                    logger.debug(
                                        "RECON BRIDGE: no last_write_site for "
                                        "blk[%d].arm%d -> blk[%d], skipping NOP",
                                        exit_block, arm, target_entry,
                                    )
                                bridge_mods.append(
                                    builder.edge_redirect(
                                        source_block=exit_block,
                                        target_block=target_entry,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_targets.add(target_entry)
                                claimed_sources.add(exit_block)
                                logger.info(
                                    "RECON BRIDGE: wire blk[%d].arm%d -> blk[%d] (2-way)",
                                    exit_block, arm, target_entry,
                                )
                            break

            if bridge_mods:
                modifications.extend(bridge_mods)
                logger.info(
                    "RECON BRIDGE: %d bridge edges for unclaimed handler entries",
                    len(bridge_mods),
                )

            # ------------------------------------------------------------------
            # Feeder Redirect: redirect remaining dispatcher feeders
            # ------------------------------------------------------------------
            # After the Bridge Builder wires exit blocks TO unclaimed handler
            # entries, some blocks still feed the dispatcher via goto.  Scan
            # ALL DAG edges whose source anchor still points at the dispatcher
            # or BST region and redirect them to the resolved target entry.

            feeder_mods: list = []

            for edge in dag.edges:
                if edge.kind == SemanticEdgeKind.UNKNOWN:
                    continue
                if edge.target_entry_anchor is None:
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in _bst_set:
                    continue

                src_serial = int(edge.source_anchor.block_serial)
                if src_serial in claimed_sources:
                    continue  # Already handled by strict emitter or bridge

                src_block = flow_graph.get_block(src_serial)
                if src_block is None:
                    continue

                # Check if any successor is the dispatcher or a BST block
                has_dispatcher_succ = False
                for arm in range(src_block.nsucc):
                    if (
                        int(src_block.succs[arm]) == dispatcher_serial
                        or int(src_block.succs[arm]) in _bst_set
                    ):
                        has_dispatcher_succ = True
                        break

                if not has_dispatcher_succ:
                    continue

                if src_block.nsucc == 1:
                    old_target = int(src_block.succs[0])
                    if old_target == dispatcher_serial or old_target in _bst_set:
                        # NOP the state-write instruction if known
                        if edge.last_write_site is not None:
                            _ws_blk, _ws_ea = edge.last_write_site
                            feeder_mods.append(
                                NopInstructions(
                                    block_serial=int(_ws_blk),
                                    insn_eas=(int(_ws_ea),),
                                )
                            )
                        else:
                            logger.debug(
                                "RECON FEEDER: no last_write_site for "
                                "blk[%d] -> blk[%d], skipping NOP",
                                src_serial, target_entry,
                            )
                        feeder_mods.append(
                            builder.goto_redirect(
                                source_block=src_serial,
                                target_block=target_entry,
                                old_target=old_target,
                            )
                        )
                        claimed_sources.add(src_serial)
                        claimed_targets.add(target_entry)
                        logger.info(
                            "RECON BRIDGE: feeder blk[%d] -> blk[%d] (1-way)",
                            src_serial, target_entry,
                        )
                elif src_block.nsucc == 2:
                    for arm in range(2):
                        arm_target = int(src_block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # NOP the state-write instruction if known
                                if edge.last_write_site is not None:
                                    _ws_blk, _ws_ea = edge.last_write_site
                                    feeder_mods.append(
                                        NopInstructions(
                                            block_serial=int(_ws_blk),
                                            insn_eas=(int(_ws_ea),),
                                        )
                                    )
                                else:
                                    logger.debug(
                                        "RECON FEEDER: no last_write_site for "
                                        "blk[%d].arm%d -> blk[%d], skipping NOP",
                                        src_serial, arm, target_entry,
                                    )
                                feeder_mods.append(
                                    builder.edge_redirect(
                                        source_block=src_serial,
                                        target_block=target_entry,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_sources.add(src_serial)
                                claimed_targets.add(target_entry)
                                logger.info(
                                    "RECON BRIDGE: feeder blk[%d].arm%d -> blk[%d] (2-way)",
                                    src_serial, arm, target_entry,
                                )
                            break

            # Fallback: resolve feeder target via snapshot constant fixpoint
            # For blocks writing a known state constant to stkoff whose DAG
            # edge source_anchor did not match above.
            if (
                constant_result is not None
                and state_var_stkoff is not None
                and hasattr(constant_result, "out_stk_maps")
                and dispatcher is not None
            ):
                # Collect residual feeder candidates: all blocks that still
                # point to the dispatcher/BST but weren't claimed.
                for blk_serial in flow_graph.blocks:
                    if blk_serial in claimed_sources:
                        continue
                    blk = flow_graph.get_block(blk_serial)
                    if blk is None or blk.nsucc != 1:
                        continue
                    old = int(blk.succs[0])
                    if old != dispatcher_serial and old not in _bst_set:
                        continue
                    out_map = constant_result.out_stk_maps.get(blk_serial, {})
                    state_val = out_map.get(state_var_stkoff)
                    if state_val is None:
                        continue
                    resolved = dispatcher.lookup(state_val)
                    if resolved is None or int(resolved) in _bst_set:
                        continue
                    # Fixpoint feeder has no DAG edge, so no last_write_site.
                    # State-write NOP would require block instruction scan
                    # (IDA runtime only) — skip for now.
                    logger.debug(
                        "RECON FEEDER: fixpoint blk[%d] has no "
                        "last_write_site, skipping NOP",
                        blk_serial,
                    )
                    feeder_mods.append(
                        builder.goto_redirect(
                            source_block=blk_serial,
                            target_block=int(resolved),
                            old_target=old,
                        )
                    )
                    claimed_sources.add(blk_serial)
                    logger.info(
                        "RECON BRIDGE: fixpoint feeder blk[%d] -> blk[%d] (state=0x%x)",
                        blk_serial, int(resolved), state_val,
                    )

            if feeder_mods:
                modifications.extend(feeder_mods)
                logger.info(
                    "RECON BRIDGE: %d feeder redirects for residual dispatcher feeders",
                    len(feeder_mods),
                )

            # ------------------------------------------------------------------
            # Return Path Wiring: connect CONDITIONAL_RETURN edges
            # ------------------------------------------------------------------
            # Use source_anchor to identify the exact source block and arm,
            # then wire the return arm through BST to the return corridor.
            # A 2-way block may have its transition arm already claimed;
            # the return arm is independent and can still be wired.

            return_mods: list = []
            return_skipped: list[tuple[int, str]] = []
            for edge in dag.edges:
                if edge.kind != SemanticEdgeKind.CONDITIONAL_RETURN:
                    continue

                src_serial = edge.source_anchor.block_serial
                src_arm = edge.source_anchor.branch_arm

                if not edge.ordered_path:
                    return_skipped.append((src_serial, "empty_ordered_path"))
                    continue

                # Find the return target: the first non-BST block on the
                # path AFTER the source block.  Fall back to the last
                # non-BST block on the path.
                ordered = tuple(int(s) for s in edge.ordered_path)
                past_source = False
                wire_target: int | None = None
                for serial in ordered:
                    if serial == src_serial:
                        past_source = True
                        continue
                    if past_source and serial not in _bst_set:
                        wire_target = serial
                        break
                # Fallback: last non-BST block that is not the source
                if wire_target is None:
                    for serial in reversed(ordered):
                        if serial != src_serial and serial not in _bst_set:
                            wire_target = serial
                            break

                if wire_target is None:
                    return_skipped.append((src_serial, "no_wire_target"))
                    continue

                block = flow_graph.get_block(src_serial)
                if block is None:
                    return_skipped.append((src_serial, "block_not_found"))
                    continue

                # --- 1-way source block ---
                if block.nsucc == 1:
                    if src_serial in claimed_sources:
                        return_skipped.append(
                            (src_serial, "claimed_1way"),
                        )
                        continue
                    old_target = int(block.succs[0])
                    if old_target == wire_target:
                        return_skipped.append(
                            (src_serial, "already_wired_1way"),
                        )
                        continue
                    if old_target not in _bst_set:
                        # Successor is a handler block, not BST — path
                        # is intact, nothing to redirect.
                        return_skipped.append(
                            (src_serial, "intact_1way"),
                        )
                        continue
                    return_mods.append(
                        builder.goto_redirect(
                            source_block=src_serial,
                            target_block=wire_target,
                            old_target=old_target,
                        )
                    )
                    claimed_sources.add(src_serial)
                    logger.info(
                        "RECON RETURN: wire blk[%d] -> blk[%d] "
                        "(return path, 1-way)",
                        src_serial, wire_target,
                    )

                # --- 2-way source block ---
                elif block.nsucc == 2:
                    # Determine which arm to wire.  Prefer the arm
                    # indicated by source_anchor.branch_arm; if not
                    # available, pick the arm pointing into the BST.
                    candidate_arms: list[int] = []
                    if src_arm is not None:
                        candidate_arms = [src_arm]
                    else:
                        candidate_arms = [0, 1]

                    wired = False
                    for arm in candidate_arms:
                        if arm >= block.nsucc:
                            continue
                        arm_target = int(block.succs[arm])
                        if arm_target == wire_target:
                            # This arm already reaches the return block
                            return_skipped.append(
                                (src_serial, f"already_wired_arm{arm}"),
                            )
                            wired = True
                            break
                        if arm_target not in _bst_set:
                            # Arm reaches a non-BST block — the path
                            # from this arm is already intact.  Check
                            # if it transitively reaches wire_target.
                            return_skipped.append(
                                (src_serial, f"intact_arm{arm}"),
                            )
                            wired = True
                            break
                        # Arm points to BST — wire it to the return
                        # corridor.
                        return_mods.append(
                            builder.edge_redirect(
                                source_block=src_serial,
                                target_block=wire_target,
                                old_target=arm_target,
                            )
                        )
                        claimed_sources.add(src_serial)
                        logger.info(
                            "RECON RETURN: wire blk[%d].arm%d -> "
                            "blk[%d] (return path, 2-way)",
                            src_serial, arm, wire_target,
                        )
                        wired = True
                        break
                    if not wired:
                        return_skipped.append(
                            (src_serial, "no_eligible_arm"),
                        )
                else:
                    return_skipped.append(
                        (src_serial, f"unexpected_nsucc_{block.nsucc}"),
                    )

            if return_mods:
                modifications.extend(return_mods)
            logger.info(
                "RECON RETURN: %d return path edges wired, %d skipped",
                len(return_mods), len(return_skipped),
            )
            for blk_ser, reason in return_skipped:
                logger.info(
                    "RECON RETURN: skip blk[%d] reason=%s",
                    blk_ser, reason,
                )

            # DISABLED: Force-Wire unnecessary when relay collapsing is off.
            # With immediate-target wiring, handlers that were previously
            # orphaned by relay collapsing now have their natural predecessors
            # preserved.  Force-Wire was solving the symptom (orphaned handlers)
            # rather than the root cause (relay collapsing skipping intermediates).
            force_wire_mods: list = []

            # ------------------------------------------------------------------
            # Re-project to update residual preds and BST cleanup gate
            # ------------------------------------------------------------------
            all_extra_mods = bridge_mods + return_mods + feeder_mods + force_wire_mods
            if all_extra_mods:
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(
                        flow_graph, patch_plan,
                    )
                except Exception:
                    projected_flow_graph = flow_graph
                residual_dispatcher_preds = (
                    self._collect_residual_dispatcher_predecessors(
                        projected_flow_graph,
                        dispatcher_serial,
                        bst_node_blocks=dispatcher_region,
                        reachable_from_serial=getattr(
                            projected_flow_graph, "entry_serial", None,
                        ),
                    )
                )
                if not residual_dispatcher_preds:
                    allow_post_apply_bst_cleanup = True
                    post_apply_bst_cleanup_reason = None
                    logger.info(
                        "RECON BRIDGE: cleared all residual dispatcher feeders — BST cleanup enabled",
                    )
                else:
                    logger.info(
                        "RECON BRIDGE: residual still has %d feeders: %s",
                        len(residual_dispatcher_preds),
                        [blk_label(mba, s) for s in residual_dispatcher_preds],
                    )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(owned_blocks),
                transitions_resolved=len(accepted_metadata),
                blocks_freed=len(owned_blocks),
                conflict_density=0.0,
            ),
            risk_score=0.25,
            metadata={
                "mode": "experimental_reconstruction",
                "reconstruction_sites": tuple(accepted_metadata),
                "reconstruction_rejections": tuple(rejected_metadata),
                "allow_post_apply_bst_cleanup": allow_post_apply_bst_cleanup,
                "post_apply_bst_cleanup_reason": post_apply_bst_cleanup_reason,
                "residual_dispatcher_preds": residual_dispatcher_preds,
                "safeguard_min_required": 1,
            },
            modifications=modifications,
        )
