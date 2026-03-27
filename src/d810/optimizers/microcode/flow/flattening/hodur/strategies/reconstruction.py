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
from d810.cfg.entry_island_rescue import (
    EntryIslandRescueOption,
    build_entry_island_rescue_modification,
    build_entry_island_rescue_options,
)
from d810.cfg.graph_modification import (
    NopInstructions,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
)
from d810.cfg.mod_claims import collect_mod_claims
from d810.cfg.shared_corridor import (
    first_boundary_index,
    first_shared_block_index,
    is_backward_same_corridor_target,
    is_shared_block,
    resolve_old_target,
)
from d810.cfg.lowering_selector import (
    SharedFeederContext,
    SharedFeederLoweringKind,
    SharedGroupCandidate,
    SharedGroupContext,
    select_shared_feeder_lowering,
    plan_shared_group_duplication,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.reconstruction_emission import plan_reconstruction_emission
from d810.cfg.terminal_family_split import (
    TerminalFamilySplitCandidate,
    build_terminal_family_split_proposals,
)
from d810.cfg.plan import compile_patch_plan, is_block_creating_modification
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
from d810.recon.flow.graph_reachability import (
    collect_dispatcher_predecessors,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
    edge_reachable_frontier,
    graph_reaches_block,
    pick_deepest_rescue_frontier,
)
from d810.recon.flow.dag_index import (
    build_dag_node_maps,
    incoming_edges_by_target_entry,
    resolve_target_node,
    semantic_entry_anchors,
)
from d810.recon.flow.edge_metadata import edge_kind_name, make_edge_metadata
from d810.recon.flow.entry_island import lift_target_entry_to_island_entry
from d810.recon.flow.state_machine_analysis import (
    SnapshotConstantFixpointResult,
    StateWriteSite,
    run_snapshot_constant_fixpoint,
)
from d810.recon.flow.path_horizon import resolve_transition_path_horizon
from d810.recon.flow.terminal_family import (
    TerminalFamilyCandidate,
    TerminalFamilySeed,
    TerminalFamilySeedProbe,
    build_terminal_family_candidates,
    candidate_shared_suffix_entries,
    collect_linear_terminal_path,
    find_last_terminal_write,
    find_prev_terminal_write_to_locator,
    insn_is_copy_like,
    is_projected_only_block,
    is_state_var_dest,
    probe_terminal_family_seed,
    resolve_terminal_edge_entry,
    resolve_terminal_source_arm_entry,
    resolve_terminal_value_chain,
    seed_terminal_family_probes,
    terminal_candidate_key,
    terminal_locator_key,
    terminal_source_signature,
    terminal_value_family_signature,
    terminal_write_signature,
)
from d810.recon.flow.target_entry_resolution import resolve_edge_target_entry
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
    def _classify_artifact_return_blocks(
        flow_graph,
        state_var_stkoff: int,
        state_constants: set[int],
    ) -> set[int]:
        """Identify blocks that are m_xdu/m_mov artifacts writing state var to return slot.

        Artifact blocks zero-extend or move the dead state variable into the
        return slot (a different stack variable).  These blocks should be
        bypassed during Return Path Wiring because they propagate the
        obfuscation state constant into the decompiled return value.

        The classifier looks for two patterns:

        1. **m_xdu artifact**: ``m_xdu  state_var -> other_stkvar`` where
           src.stkoff == state_var_stkoff and dest.stkoff != state_var_stkoff.
        2. **m_mov const artifact**: ``m_mov  #state_const -> stkvar`` where
           the immediate value is a known state constant.

        Args:
            flow_graph: Snapshot flow graph with block/instruction data.
            state_var_stkoff: Stack offset of the dispatcher state variable.
            state_constants: Set of known state constant values.

        Returns:
            Set of block serials classified as artifact return blocks.
        """
        MOP_N = int(ida_hexrays.mop_n)
        MOP_S = int(ida_hexrays.mop_S)
        m_xdu = int(ida_hexrays.m_xdu)
        m_mov = int(ida_hexrays.m_mov)

        artifact_blocks: set[int] = set()
        for serial, blk in flow_graph.blocks.items():
            for insn in blk.insn_snapshots:
                # Diagnostic: log first instruction of target blocks
                if serial in (27, 41, 47, 71, 207) and insn is blk.insn_snapshots[0]:
                    logger.info(
                        "RECON RETURN: classify blk[%d] insn0: "
                        "opcode=%s l.t=%s l.stkoff=%s d.t=%s d.stkoff=%s",
                        serial, insn.opcode,
                        getattr(getattr(insn, "l", None), "t", "?"),
                        getattr(getattr(insn, "l", None), "stkoff", "?"),
                        getattr(getattr(insn, "d", None), "t", "?"),
                        getattr(getattr(insn, "d", None), "stkoff", "?"),
                    )
                # Pattern 1: m_xdu with src=state_var, dest=other stkvar
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
                # Pattern 2: m_mov with imm state constant to stkvar
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
        return make_edge_metadata(
            edge,
            horizon_block=horizon_block,
            site=site,
            target_entry=target_entry,
            first_shared_block=first_shared_block,
            via_pred=via_pred,
            emission_mode=emission_mode,
            rejection_reason=rejection_reason,
        )

    @staticmethod
    def _node_maps(
        dag: LinearizedStateDag,
    ) -> tuple[
        dict[StateDagNodeKey, StateDagNode],
        dict[StateDagNodeKey, tuple[StateDagEdge, ...]],
        dict[int, tuple[StateDagNode, ...]],
    ]:
        maps = build_dag_node_maps(dag)
        return (
            maps.node_by_key,
            maps.outgoing_by_key,
            maps.nodes_by_entry_anchor,
        )

    @staticmethod
    def _resolve_target_node(
        edge: StateDagEdge,
        *,
        node_by_key: dict[StateDagNodeKey, StateDagNode],
        nodes_by_entry_anchor: dict[int, tuple[StateDagNode, ...]],
    ) -> StateDagNode | None:
        return resolve_target_node(
            edge,
            node_by_key=node_by_key,
            nodes_by_entry_anchor=nodes_by_entry_anchor,
        )

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
        resolution = resolve_edge_target_entry(
            edge,
            node_by_key=node_by_key,
            dispatcher_region=dispatcher_region,
        )
        if (
            resolution.target_entry is not None
            and resolution.original_dispatcher_entry is not None
        ):
            logger.info(
                "RECON DAG: dispatcher_target_entry resolved non-BST "
                "entry blk[%d] (original blk[%d] in dispatcher region)",
                resolution.target_entry,
                resolution.original_dispatcher_entry,
            )
        if resolution.target_entry is None:
            return None, resolution.rejection_reason

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
        return resolution.target_entry, None

    @staticmethod
    def _resolve_old_target(
        flow_graph,
        source_block: int,
        ordered_path: tuple[int, ...],
    ) -> int | None:
        return resolve_old_target(flow_graph, source_block, ordered_path)

    @staticmethod
    def _is_shared_block(
        flow_graph,
        block_serial: int,
        *,
        shared_suffix_blocks: set[int],
    ) -> bool:
        return is_shared_block(
            flow_graph,
            block_serial,
            shared_suffix_blocks=shared_suffix_blocks,
        )

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
        return first_shared_block_index(
            flow_graph,
            ordered_path,
            start_index=start_index,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )

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
        return first_boundary_index(
            flow_graph,
            ordered_path,
            start_index=start_index,
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
        )

    @staticmethod
    def _compute_reachable_blocks(
        flow_graph: object,
        *,
        start_serial: int | None,
        limit: int = 4096,
    ) -> set[int] | None:
        return compute_reachable_blocks(
            flow_graph,
            start_serial=start_serial,
            limit=limit,
        )

    @staticmethod
    def _collect_dispatcher_predecessors(
        flow_graph: object,
        dispatcher_serial: int,
        *,
        bst_node_blocks: set[int],
    ) -> tuple[int, ...]:
        return collect_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
        )

    @classmethod
    def _collect_residual_dispatcher_predecessors(
        cls,
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

    @staticmethod
    def _semantic_entry_anchors(dag: LinearizedStateDag) -> set[int]:
        return semantic_entry_anchors(dag)

    @staticmethod
    def _incoming_edges_by_target_entry(
        dag: LinearizedStateDag,
    ) -> dict[int, tuple[StateDagEdge, ...]]:
        return incoming_edges_by_target_entry(dag)

    @staticmethod
    def _collect_mod_claims(
        modifications: list,
    ) -> tuple[set[int], set[int]]:
        return collect_mod_claims(modifications)

    @classmethod
    def _edge_reachable_frontier(
        cls,
        edge: StateDagEdge,
        *,
        reachable_blocks: set[int],
        dispatcher_region: set[int],
    ) -> int | None:
        return edge_reachable_frontier(
            ordered_path=tuple(int(serial) for serial in edge.ordered_path),
            source_block=int(edge.source_anchor.block_serial),
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )

    @classmethod
    def _graph_reaches_block(
        cls,
        flow_graph: object,
        *,
        source_block: int,
        target_block: int,
        limit: int = 512,
    ) -> bool:
        return graph_reaches_block(
            flow_graph,
            source_block=source_block,
            target_block=target_block,
            limit=limit,
        )

    @classmethod
    def _pick_deepest_rescue_frontier(
        cls,
        flow_graph: object,
        candidates: tuple[int, ...],
    ) -> int | None:
        return pick_deepest_rescue_frontier(flow_graph, candidates)

    @classmethod
    def _lift_target_entry_to_island_entry(
        cls,
        target_entry: int,
        *,
        incoming_by_target_entry: dict[int, tuple[StateDagEdge, ...]],
        semantic_entry_anchors: set[int],
        reachable_blocks: set[int],
        dispatcher_region: set[int],
    ) -> int:
        return lift_target_entry_to_island_entry(
            target_entry,
            incoming_by_target_entry=incoming_by_target_entry,
            semantic_entry_anchors=semantic_entry_anchors,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
        )

    @classmethod
    def _entry_island_rescue_options(
        cls,
        source_block: int,
        *,
        lifted_entry: int,
        projected_flow_graph,
        reachable_blocks: set[int],
        dispatcher_region: set[int],
        claimed_sources: set[int],
    ) -> tuple[EntryIslandRescueOption, ...]:
        return build_entry_island_rescue_options(
            source_block,
            lifted_entry=lifted_entry,
            projected_flow_graph=projected_flow_graph,
            reachable_blocks=reachable_blocks,
            dispatcher_region=dispatcher_region,
            claimed_sources=claimed_sources,
        )

    @classmethod
    def _build_entry_island_rescue_modification(
        cls,
        option: EntryIslandRescueOption,
        *,
        builder: ModificationBuilder,
    ):
        return build_entry_island_rescue_modification(option, builder=builder)

    @classmethod
    def _score_entry_island_rescue_option(
        cls,
        option: EntryIslandRescueOption,
        *,
        base_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        baseline_reachable_count: int,
        baseline_reachable_blocks: set[int],
    ) -> tuple[tuple[int, int, int, int, int], object, object] | None:
        candidate_mod = cls._build_entry_island_rescue_modification(
            option,
            builder=builder,
        )

        try:
            patch_plan = compile_patch_plan(modifications + [candidate_mod], base_flow_graph)
            projected_flow_graph = project_post_state(base_flow_graph, patch_plan)
        except Exception:
            return None

        reachable_blocks = cls._compute_reachable_blocks(
            projected_flow_graph,
            start_serial=getattr(projected_flow_graph, "entry_serial", None),
        )
        if not reachable_blocks or option.lifted_entry not in reachable_blocks:
            return None

        reachable_count_delta = len(reachable_blocks) - baseline_reachable_count
        if reachable_count_delta < 0:
            return None

        preserved_old_target = 1 if (
            option.old_target in baseline_reachable_blocks
            and option.old_target in reachable_blocks
        ) else 0
        mode_rank = 1 if option.via_pred is None else 0
        via_rank = int(option.via_pred) if option.via_pred is not None else -1
        score = (
            reachable_count_delta,
            preserved_old_target,
            mode_rank,
            int(option.source_block),
            via_rank,
        )
        return score, candidate_mod, projected_flow_graph

    @classmethod
    def _emit_entry_island_rescues(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        mba,
    ) -> int:
        semantic_entry_anchors = cls._semantic_entry_anchors(dag) - dispatcher_region
        incoming_by_target_entry = cls._incoming_edges_by_target_entry(dag)
        current_projected_flow_graph = projected_flow_graph
        emitted = 0

        while True:
            reachable_blocks = cls._compute_reachable_blocks(
                current_projected_flow_graph,
                start_serial=getattr(current_projected_flow_graph, "entry_serial", None),
            )
            if not reachable_blocks:
                break

            baseline_reachable_count = len(reachable_blocks)
            claimed_sources, claimed_targets = cls._collect_mod_claims(modifications)
            seen_options: set[tuple[int, int, int | None]] = set()
            best_score: tuple[int, int, int, int, int] | None = None
            best_option: EntryIslandRescueOption | None = None
            best_modification = None
            best_projected_flow_graph = None

            for edge in dag.edges:
                if edge.target_entry_anchor is None:
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in dispatcher_region:
                    continue

                lifted_entry = cls._lift_target_entry_to_island_entry(
                    target_entry,
                    incoming_by_target_entry=incoming_by_target_entry,
                    semantic_entry_anchors=semantic_entry_anchors,
                    reachable_blocks=reachable_blocks,
                    dispatcher_region=dispatcher_region,
                )
                if (
                    lifted_entry in dispatcher_region
                    or lifted_entry in reachable_blocks
                    or lifted_entry in claimed_targets
                ):
                    continue

                source_block = cls._edge_reachable_frontier(
                    edge,
                    reachable_blocks=reachable_blocks,
                    dispatcher_region=dispatcher_region,
                )
                if source_block is None:
                    continue

                for option in cls._entry_island_rescue_options(
                    source_block,
                    lifted_entry=lifted_entry,
                    projected_flow_graph=current_projected_flow_graph,
                    reachable_blocks=reachable_blocks,
                    dispatcher_region=dispatcher_region,
                    claimed_sources=claimed_sources,
                ):
                    option_key = (
                        int(option.source_block),
                        int(option.lifted_entry),
                        int(option.via_pred) if option.via_pred is not None else None,
                    )
                    if option_key in seen_options:
                        continue
                    seen_options.add(option_key)

                    scored = cls._score_entry_island_rescue_option(
                        option,
                        base_flow_graph=base_flow_graph,
                        builder=builder,
                        modifications=modifications,
                        baseline_reachable_count=baseline_reachable_count,
                        baseline_reachable_blocks=reachable_blocks,
                    )
                    if scored is None:
                        continue

                    score, candidate_mod, candidate_projected = scored
                    if best_score is not None and score <= best_score:
                        continue
                    best_score = score
                    best_option = option
                    best_modification = candidate_mod
                    best_projected_flow_graph = candidate_projected

            if best_option is None or best_modification is None or best_projected_flow_graph is None:
                break

            modifications.append(best_modification)
            current_projected_flow_graph = best_projected_flow_graph
            emitted += 1
            logger.info(
                "RECON DAG: entry-island rescue %s -> %s%s (delta=%+d)",
                blk_label(mba, best_option.source_block),
                blk_label(mba, best_option.lifted_entry),
                (
                    f" via_pred={blk_label(mba, best_option.via_pred)}"
                    if best_option.via_pred is not None
                    else ""
                ),
                best_score[0] if best_score is not None else 0,
            )

        return emitted

    @classmethod
    def _emit_late_island_rescues(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        dispatcher=None,
        mba,
    ) -> int:
        """Rescue unreachable handler bodies behind dead BST nodes.

        After linearization kills the dispatcher, handler chains that were
        only reachable through BST nodes become islands.  This method finds
        such islands by looking *through* BST nodes for unreachable
        non-dispatcher successors, then wires them from reachable blocks
        identified via DAG edge paths or the IntervalDispatcher.
        """
        current_projected_flow_graph = projected_flow_graph
        emitted = 0

        while True:
            reachable_blocks = cls._compute_reachable_blocks(
                current_projected_flow_graph,
                start_serial=getattr(
                    current_projected_flow_graph, "entry_serial", None,
                ),
            )
            if not reachable_blocks:
                break

            baseline_reachable_count = len(reachable_blocks)
            claimed_sources, _claimed_targets = cls._collect_mod_claims(
                modifications,
            )
            seen_options: set[tuple[int, int, int | None]] = set()
            best_score: tuple[int, int, int, int, int] | None = None
            best_option: EntryIslandRescueOption | None = None
            best_modification = None
            best_projected_flow_graph = None

            for edge in dag.edges:
                if edge.target_entry_anchor is None:
                    continue
                target_entry = int(edge.target_entry_anchor)
                # Only consider edges whose target IS in dispatcher region
                # (BST passthrough).
                if target_entry not in dispatcher_region:
                    continue

                target_snapshot = current_projected_flow_graph.get_block(
                    target_entry,
                )
                if target_snapshot is None:
                    continue

                for succ in sorted(int(s) for s in target_snapshot.succs):
                    if succ in dispatcher_region or succ in reachable_blocks:
                        continue
                    # succ is unreachable non-dispatcher behind a BST node.

                    source_block = cls._edge_reachable_frontier(
                        edge,
                        reachable_blocks=reachable_blocks,
                        dispatcher_region=dispatcher_region,
                    )
                    if source_block is None:
                        logger.info(
                            "RECON DAG: late island rescue: no reachable "
                            "frontier for BST passthrough blk[%d] -> "
                            "blk[%d] (edge src=%s)",
                            target_entry,
                            succ,
                            blk_label(
                                mba,
                                int(edge.source_anchor.block_serial),
                            ),
                        )
                        continue

                    for option in cls._entry_island_rescue_options(
                        source_block,
                        lifted_entry=succ,
                        projected_flow_graph=current_projected_flow_graph,
                        reachable_blocks=reachable_blocks,
                        dispatcher_region=dispatcher_region,
                        claimed_sources=claimed_sources,
                    ):
                        option_key = (
                            int(option.source_block),
                            int(option.lifted_entry),
                            (
                                int(option.via_pred)
                                if option.via_pred is not None
                                else None
                            ),
                        )
                        if option_key in seen_options:
                            continue
                        seen_options.add(option_key)

                        scored = cls._score_entry_island_rescue_option(
                            option,
                            base_flow_graph=base_flow_graph,
                            builder=builder,
                            modifications=modifications,
                            baseline_reachable_count=baseline_reachable_count,
                            baseline_reachable_blocks=reachable_blocks,
                        )
                        if scored is None:
                            continue

                        score, candidate_mod, candidate_projected = scored
                        if best_score is not None and score <= best_score:
                            continue
                        best_score = score
                        best_option = option
                        best_modification = candidate_mod
                        best_projected_flow_graph = candidate_projected

            if (
                best_option is None
                or best_modification is None
                or best_projected_flow_graph is None
            ):
                break

            modifications.append(best_modification)
            current_projected_flow_graph = best_projected_flow_graph
            emitted += 1
            logger.info(
                "RECON DAG: late island rescue %s -> %s%s "
                "via BST passthrough (delta=%+d)",
                blk_label(mba, best_option.source_block),
                blk_label(mba, best_option.lifted_entry),
                (
                    f" via_pred={blk_label(mba, best_option.via_pred)}"
                    if best_option.via_pred is not None
                    else ""
                ),
                best_score[0] if best_score is not None else 0,
            )

        # Diagnostic: if no rescue fired, dump dispatcher rows for
        # unreachable non-dispatcher blocks with BST-only predecessors.
        if emitted == 0 and dispatcher is not None:
            reachable_blocks = cls._compute_reachable_blocks(
                current_projected_flow_graph,
                start_serial=getattr(
                    current_projected_flow_graph, "entry_serial", None,
                ),
            ) or set()
            for serial in sorted(int(s) for s in current_projected_flow_graph.blocks):
                if serial in reachable_blocks or serial in dispatcher_region:
                    continue
                snap = current_projected_flow_graph.get_block(serial)
                if snap is None:
                    continue
                preds = [int(p) for p in snap.preds]
                if not preds or not all(p in dispatcher_region for p in preds):
                    continue
                # unreachable non-dispatcher with BST-only preds
                rows_info = []
                search_targets = {serial} | {int(p) for p in preds}
                for row in getattr(dispatcher, "_rows", ()):
                    if int(row.target) in search_targets:
                        rows_info.append(
                            f"[0x{row.lo:X}..0x{row.hi:X})->blk[{row.target}]"
                        )
                logger.info(
                    "RECON DAG: late island rescue diagnostic: "
                    "unreachable blk[%d] bst_preds=%s dispatcher_rows=[%s]",
                    serial,
                    preds,
                    ", ".join(rows_info) if rows_info else "none",
                )

        return emitted

    @staticmethod
    def _terminal_locator_key(mop: object | None) -> tuple[object, ...] | None:
        return terminal_locator_key(mop)

    @classmethod
    def _terminal_source_signature(cls, mop: object | None) -> tuple[object, ...]:
        return terminal_source_signature(mop)

    @classmethod
    def _terminal_write_signature(cls, insn: object) -> tuple[object, ...]:
        return terminal_write_signature(insn)

    @staticmethod
    def _insn_is_copy_like(insn: object) -> bool:
        return insn_is_copy_like(insn)

    @staticmethod
    def _is_state_var_dest(insn: object, state_var_stkoff: int | None) -> bool:
        return is_state_var_dest(insn, state_var_stkoff)

    @classmethod
    def _resolve_terminal_source_arm_entry(
        cls,
        source_serial: int,
        branch_arm: int | None,
        *,
        projected_flow_graph,
        dispatcher_region: set[int],
    ) -> int | None:
        return resolve_terminal_source_arm_entry(
            source_serial,
            branch_arm,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
        )

    @staticmethod
    def _is_projected_only_block(
        block_serial: int,
        *,
        base_flow_graph,
    ) -> bool:
        return is_projected_only_block(
            block_serial,
            base_flow_graph=base_flow_graph,
        )

    @classmethod
    def _probe_terminal_family_seed(
        cls,
        seed: TerminalFamilySeed,
        *,
        base_flow_graph,
        projected_flow_graph,
        dispatcher_region: set[int],
        reachable_blocks: set[int],
    ) -> TerminalFamilySeedProbe:
        return probe_terminal_family_seed(
            seed,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            reachable_blocks=reachable_blocks,
        )

    @classmethod
    def _log_source_unreachable_diagnostic(
        cls,
        source_serial: int,
        *,
        projected_flow_graph,
        reachable_blocks: set[int],
        dispatcher_region: set[int],
        mba,
    ) -> None:
        """Log diagnostic context when a terminal-family seed source is unreachable."""
        source_snap = projected_flow_graph.get_block(source_serial)
        if source_snap is None:
            logger.info(
                "RECON RETURN: source_unreachable diagnostic %s: "
                "not in projected flow graph",
                blk_label(mba, source_serial),
            )
            return

        preds = sorted(int(p) for p in source_snap.preds)
        pred_info = []
        for p in preds:
            if p in reachable_blocks:
                status = "reachable"
            elif p in dispatcher_region:
                status = "dispatcher"
            else:
                status = "unreachable"
            pred_info.append(f"blk[{p}]={status}")

        # BFS backward through non-dispatcher preds to map the island.
        visited: set[int] = set()
        queue: list[int] = [source_serial]
        frontier: int | None = None
        while queue and len(visited) < 64:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current != source_serial and current in reachable_blocks:
                frontier = current
                break
            snap = projected_flow_graph.get_block(current)
            if snap is None:
                continue
            for pred in sorted(int(p) for p in snap.preds):
                if pred not in visited and pred not in dispatcher_region:
                    queue.append(pred)

        island_blocks = sorted(visited - {source_serial})

        logger.info(
            "RECON RETURN: source_unreachable diagnostic %s "
            "preds=[%s] nearest_reachable=%s island_blocks=%s",
            blk_label(mba, source_serial),
            ", ".join(pred_info),
            blk_label(mba, frontier) if frontier is not None else "None",
            [blk_label(mba, b) for b in island_blocks],
        )

    @classmethod
    def _resolve_terminal_edge_entry(
        cls,
        edge: StateDagEdge,
        *,
        projected_flow_graph,
        dispatcher_region: set[int],
    ) -> int | None:
        return resolve_terminal_edge_entry(
            edge,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
        )

    @classmethod
    def _collect_linear_terminal_path(
        cls,
        projected_flow_graph,
        *,
        start_block: int,
        dispatcher_region: set[int],
        limit: int = 64,
    ) -> tuple[int, ...] | None:
        return collect_linear_terminal_path(
            projected_flow_graph,
            start_block=start_block,
            dispatcher_region=dispatcher_region,
            limit=limit,
        )

    @classmethod
    def _find_last_terminal_write(
        cls,
        projected_flow_graph,
        *,
        path: tuple[int, ...],
        state_var_stkoff: int | None,
    ) -> tuple[int, int, object] | None:
        return find_last_terminal_write(
            projected_flow_graph,
            path=path,
            state_var_stkoff=state_var_stkoff,
        )

    @classmethod
    def _find_prev_terminal_write_to_locator(
        cls,
        projected_flow_graph,
        *,
        path: tuple[int, ...],
        locator: tuple[object, ...],
        before_block: int,
        before_insn_index: int,
        state_var_stkoff: int | None,
    ) -> tuple[int, int, object] | None:
        return find_prev_terminal_write_to_locator(
            projected_flow_graph,
            path=path,
            locator=locator,
            before_block=before_block,
            before_insn_index=before_insn_index,
            state_var_stkoff=state_var_stkoff,
        )

    @classmethod
    def _resolve_terminal_value_chain(
        cls,
        projected_flow_graph,
        *,
        path: tuple[int, ...],
        state_var_stkoff: int | None,
    ) -> tuple[tuple[int, int, object], ...]:
        return resolve_terminal_value_chain(
            projected_flow_graph,
            path=path,
            state_var_stkoff=state_var_stkoff,
        )

    @classmethod
    def _terminal_value_family_signature(
        cls,
        chain: tuple[tuple[int, int, object], ...],
    ) -> tuple[object, ...]:
        return terminal_value_family_signature(chain)

    @classmethod
    def _terminal_candidate_key(
        cls,
        candidate: TerminalFamilyCandidate,
    ) -> tuple[int, int | None, int, tuple[int, ...]]:
        return terminal_candidate_key(candidate)

    @classmethod
    def _candidate_shared_suffix_entries(
        cls,
        candidates: tuple[TerminalFamilyCandidate, ...],
    ) -> dict[tuple[int, int | None, int, tuple[int, ...]], int]:
        return candidate_shared_suffix_entries(candidates)


    @classmethod
    def _seed_terminal_family_candidates(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        dispatcher_region: set[int],
        reachable_blocks: set[int],
        mba,
    ) -> tuple[TerminalFamilySeedProbe, ...]:
        probes = seed_terminal_family_probes(
            dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            reachable_blocks=reachable_blocks,
        )
        for probe in probes:
            seed = probe.seed
            logger.info(
                "RECON RETURN: terminal-family seed src=%s%s origins=%s "
                "source_reachable=%s source_nsucc=%s arm_target=%s arm_target_origin=%s "
                "family_entry=%s family_entry_origin=%s projected_path=%s stop=%s "
                "rejection=%s path=%s",
                blk_label(mba, int(seed.source_block)),
                f".arm{seed.branch_arm}" if seed.branch_arm is not None else "",
                list(probe.seed_origins),
                probe.source_reachable,
                probe.source_nsucc,
                blk_label(mba, probe.arm_target) if probe.arm_target is not None else "None",
                "projected_only" if probe.arm_target_projected_only else "base",
                blk_label(mba, probe.family_entry) if probe.family_entry is not None else "None",
                "projected_only" if probe.family_entry_projected_only else "base",
                [blk_label(mba, serial) for serial in probe.path_projected_only_blocks],
                blk_label(mba, probe.stop_block) if probe.stop_block is not None else "None",
                probe.rejection_reason,
                probe.path,
                )
            if probe.rejection_reason == "source_unreachable":
                cls._log_source_unreachable_diagnostic(
                    int(seed.source_block),
                    projected_flow_graph=projected_flow_graph,
                    reachable_blocks=reachable_blocks,
                    dispatcher_region=dispatcher_region,
                    mba=mba,
                )
        return probes

    @classmethod
    def _collect_terminal_family_candidates(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        dispatcher_region: set[int],
        reachable_blocks: set[int],
        state_var_stkoff: int | None,
        mba,
    ) -> tuple[TerminalFamilyCandidate, ...]:
        seed_probes = cls._seed_terminal_family_candidates(
            dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=projected_flow_graph,
            dispatcher_region=dispatcher_region,
            reachable_blocks=reachable_blocks,
            mba=mba,
        )
        candidates = list(
            build_terminal_family_candidates(
                seed_probes,
                projected_flow_graph=projected_flow_graph,
                state_var_stkoff=state_var_stkoff,
            )
        )

        candidate_suffix_entries = cls._candidate_shared_suffix_entries(tuple(candidates))
        for candidate in candidates:
            candidate_key = cls._terminal_candidate_key(candidate)
            logger.info(
                "RECON RETURN: terminal-family inspect src=%s%s family_entry=%s "
                "shared_suffix_entry=%s writer=%s materializer=%s "
                "materializer_chain=%s stop=%s signature=%s rejection=accepted "
                "path=%s lineage=%s",
                blk_label(mba, candidate.source_block),
                (
                    f".arm{candidate.branch_arm}"
                    if candidate.branch_arm is not None
                    else ""
                ),
                blk_label(mba, candidate.family_entry),
                (
                    blk_label(mba, candidate_suffix_entries[candidate_key])
                    if candidate_key in candidate_suffix_entries
                    else "None"
                ),
                blk_label(mba, candidate.writer_block) if candidate.writer_block is not None else "None",
                blk_label(mba, candidate.materializer_block) if candidate.materializer_block is not None else "None",
                [blk_label(mba, serial) for serial in candidate.materializer_chain_blocks],
                blk_label(mba, candidate.stop_block),
                candidate.value_family_signature,
                candidate.path,
                [hex(ea) for ea in candidate.lineage_eas],
            )

        return tuple(candidates)

    @classmethod
    def _select_terminal_family_split(
        cls,
        candidates: tuple[TerminalFamilyCandidate, ...],
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        mba,
    ):
        current_reachable = cls._compute_reachable_blocks(
            projected_flow_graph,
            start_serial=getattr(projected_flow_graph, "entry_serial", None),
        )
        if not current_reachable:
            return None

        baseline_reachable_count = len(current_reachable)
        split_candidates = tuple(
            TerminalFamilySplitCandidate(
                source_block=int(candidate.source_block),
                branch_arm=(
                    int(candidate.branch_arm)
                    if candidate.branch_arm is not None
                    else None
                ),
                family_entry=int(candidate.family_entry),
                path=tuple(int(s) for s in candidate.path),
                value_family_signature=candidate.value_family_signature,
                lineage_eas=tuple(int(ea) for ea in candidate.lineage_eas),
            )
            for candidate in candidates
        )

        for proposal in build_terminal_family_split_proposals(
            split_candidates,
            projected_flow_graph=projected_flow_graph,
        ):
            suffix_serials = proposal.suffix_serials
            selected_anchors = list(proposal.selected_anchors)
            selected_candidates = [
                candidates[index] for index in proposal.selected_candidate_indexes
            ]
            primary_signature = proposal.primary_signature

            candidate_mod = cls._build_terminal_family_split_modification(
                builder=builder,
                anchors=tuple(selected_anchors),
                suffix_serials=suffix_serials,
                projected_flow_graph=projected_flow_graph,
            )
            if candidate_mod is None:
                continue

            try:
                patch_plan = compile_patch_plan(modifications + [candidate_mod], base_flow_graph)
                candidate_projected = project_post_state(base_flow_graph, patch_plan)
            except Exception as exc:
                logger.info(
                    "RECON RETURN: terminal-family split candidate shared_entry=%s stop=%s "
                    "rejection=projection_error error=%s",
                    blk_label(mba, int(suffix_serials[0])),
                    blk_label(mba, int(suffix_serials[-1])),
                    exc,
                )
                continue

            candidate_reachable = cls._compute_reachable_blocks(
                candidate_projected,
                start_serial=getattr(candidate_projected, "entry_serial", None),
            )
            if candidate_reachable is None or len(candidate_reachable) < baseline_reachable_count:
                logger.info(
                    "RECON RETURN: terminal-family split candidate shared_entry=%s stop=%s "
                    "rejection=reachable_regression before=%d after=%s anchors=%s",
                    blk_label(mba, int(suffix_serials[0])),
                    blk_label(mba, int(suffix_serials[-1])),
                    baseline_reachable_count,
                    len(candidate_reachable) if candidate_reachable is not None else None,
                    [blk_label(mba, anchor) for anchor in selected_anchors],
                )
                continue

            return (
                candidate_mod,
                candidate_projected,
                suffix_serials,
                tuple(selected_anchors),
                tuple(selected_candidates),
                primary_signature,
            )

        return None

    @classmethod
    def _candidate_anchor_for_suffix(
        cls,
        candidate: TerminalFamilyCandidate,
        *,
        suffix_serials: tuple[int, ...],
        projected_flow_graph,
    ) -> int | None:
        if candidate.path[-len(suffix_serials):] != suffix_serials:
            return None
        if len(candidate.path) > len(suffix_serials):
            anchor_serial = int(candidate.path[-len(suffix_serials) - 1])
        elif candidate.family_entry == suffix_serials[0]:
            anchor_serial = int(candidate.source_block)
        else:
            return None

        anchor_block = projected_flow_graph.get_block(anchor_serial)
        if anchor_block is None or anchor_block.nsucc != 1:
            return None
        if int(anchor_block.succs[0]) != int(suffix_serials[0]):
            return None
        return anchor_serial

    @classmethod
    def _build_terminal_family_split_modification(
        cls,
        *,
        builder: ModificationBuilder,
        anchors: tuple[int, ...],
        suffix_serials: tuple[int, ...],
        projected_flow_graph=None,
    ):
        shared_entry = int(suffix_serials[0])
        stop_block = int(suffix_serials[-1])
        # Validate: suffix must still be a linear ... -> 0-way chain
        # in the projected flow graph.  Prior modifications (corridor
        # redirects, PTS from earlier iterations) may have changed the
        # suffix topology.
        if projected_flow_graph is not None:
            for idx, serial in enumerate(suffix_serials):
                blk = projected_flow_graph.get_block(serial)
                if blk is None:
                    logger.info(
                        "PTS gate: suffix blk[%d] not in projected graph, skipping",
                        serial,
                    )
                    return None
                if idx < len(suffix_serials) - 1:
                    if blk.nsucc != 1:
                        logger.info(
                            "PTS gate: interior suffix blk[%d] nsucc=%d, skipping",
                            serial, blk.nsucc,
                        )
                        return None
                else:
                    if blk.nsucc != 0:
                        logger.info(
                            "PTS gate: final suffix blk[%d] nsucc=%d, skipping",
                            serial, blk.nsucc,
                        )
                        return None
        if len(anchors) == 1:
            return builder.private_terminal_suffix(
                anchor_serial=int(anchors[0]),
                shared_entry_serial=shared_entry,
                return_block_serial=stop_block,
                suffix_serials=suffix_serials,
                reason="terminal_family_split",
            )
        return builder.private_terminal_suffix_group(
            anchors=anchors,
            shared_entry_serial=shared_entry,
            return_block_serial=stop_block,
            suffix_serials=suffix_serials,
            reason="terminal_family_split",
        )

    @classmethod
    def _emit_terminal_family_splits(
        cls,
        dag: LinearizedStateDag,
        *,
        base_flow_graph,
        projected_flow_graph,
        builder: ModificationBuilder,
        modifications: list,
        dispatcher_region: set[int],
        state_var_stkoff: int | None,
        mba,
    ) -> int:
        current_projected_flow_graph = projected_flow_graph
        emitted = 0

        while True:
            reachable_blocks = cls._compute_reachable_blocks(
                current_projected_flow_graph,
                start_serial=getattr(current_projected_flow_graph, "entry_serial", None),
            )
            if not reachable_blocks:
                break

            candidates = cls._collect_terminal_family_candidates(
                dag,
                base_flow_graph=base_flow_graph,
                projected_flow_graph=current_projected_flow_graph,
                dispatcher_region=dispatcher_region,
                reachable_blocks=reachable_blocks,
                state_var_stkoff=state_var_stkoff,
                mba=mba,
            )
            if len(candidates) < 2:
                break

            selected = cls._select_terminal_family_split(
                candidates,
                base_flow_graph=base_flow_graph,
                projected_flow_graph=current_projected_flow_graph,
                builder=builder,
                modifications=modifications,
                mba=mba,
            )
            if selected is None:
                break

            (
                candidate_mod,
                candidate_projected,
                suffix_serials,
                selected_anchors,
                selected_candidates,
                primary_signature,
            ) = selected
            modifications.append(candidate_mod)
            current_projected_flow_graph = candidate_projected
            emitted += 1
            logger.info(
                "RECON RETURN: terminal-family split shared_entry=%s stop=%s anchors=%s keep_signature=%s",
                blk_label(mba, int(suffix_serials[0])),
                blk_label(mba, int(suffix_serials[-1])),
                [blk_label(mba, anchor) for anchor in selected_anchors],
                primary_signature,
            )
            for candidate in selected_candidates:
                logger.info(
                    "RECON RETURN: privatized family src=%s%s family_entry=%s "
                    "shared_suffix_entry=%s writer=%s materializer=%s "
                    "materializer_chain=%s stop=%s signature=%s lineage=%s",
                    blk_label(mba, candidate.source_block),
                    (
                        f".arm{candidate.branch_arm}"
                        if candidate.branch_arm is not None
                        else ""
                    ),
                    blk_label(mba, candidate.family_entry),
                    blk_label(mba, int(suffix_serials[0])),
                    blk_label(mba, candidate.writer_block) if candidate.writer_block is not None else "None",
                    blk_label(mba, candidate.materializer_block) if candidate.materializer_block is not None else "None",
                    [blk_label(mba, serial) for serial in candidate.materializer_chain_blocks],
                    blk_label(mba, candidate.stop_block),
                    candidate.value_family_signature,
                    [hex(ea) for ea in candidate.lineage_eas],
                )

        return emitted

    @staticmethod
    def _is_backward_same_corridor_target(
        ordered_path: tuple[int, ...],
        *,
        rewrite_block: int,
        target_entry: int,
    ) -> bool:
        return is_backward_same_corridor_target(
            ordered_path,
            rewrite_block=rewrite_block,
            target_entry=target_entry,
        )

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

        resolved = resolve_transition_path_horizon(
            edge,
            flow_graph=flow_graph,
            ordered_path=ordered_path,
            state_var_stkoff=state_var_stkoff,
            constant_result=constant_result,
        )

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

        emission_decision = plan_reconstruction_emission(
            flow_graph,
            ordered_path,
            horizon_block=int(horizon_block),
            source_anchor_block=int(edge.source_anchor.block_serial),
            source_branch_arm=(
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            is_conditional_transition=(
                edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION
            ),
            shared_suffix_blocks=shared_suffix_blocks,
            dispatcher_region=dispatcher_region,
            has_unsafe_trailing_insns=bool(site.unsafe_trailing_insn_eas),
        )

        if not emission_decision.accepted:
            return None, cls._make_edge_metadata(
                edge,
                horizon_block=horizon_block,
                site=site,
                target_entry=target_entry,
                first_shared_block=emission_decision.first_shared_block,
                via_pred=emission_decision.via_pred,
                rejection_reason=emission_decision.rejection_reason,
            )

        if emission_decision.emission_mode == "direct":
            return (
                ReconstructionCandidate(
                    edge=edge,
                    horizon_block=int(horizon_block),
                    site=site,
                    target_entry=int(target_entry),
                    first_shared_block=emission_decision.first_shared_block,
                    via_pred=None,
                    emission_mode="direct",
                ),
                None,
            )

        if emission_decision.emission_mode == "conditional_arm":
            logger.info(
                "RECON DAG: conditional_arm candidate: horizon=%d, branch_arm=%d",
                int(horizon_block),
                int(edge.source_anchor.branch_arm),
            )
            return (
                ReconstructionCandidate(
                    edge=edge,
                    horizon_block=int(horizon_block),
                    site=site,
                    target_entry=int(target_entry),
                    first_shared_block=None,
                    via_pred=None,
                    emission_mode="conditional_arm",
                ),
                None,
            )

        return (
            ReconstructionCandidate(
                edge=edge,
                horizon_block=int(horizon_block),
                site=site,
                target_entry=int(target_entry),
                first_shared_block=emission_decision.first_shared_block,
                via_pred=int(emission_decision.via_pred),
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
        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
        # modifications.append(
        #     NopInstructions(
        #         block_serial=int(candidate.horizon_block),
        #         insn_eas=(state_write_ea,),
        #     )
        # )
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

        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
        # state_write_ea = int(candidate.site.insn_ea)
        # modifications.append(
        #     NopInstructions(
        #         block_serial=horizon_block,
        #         insn_eas=(state_write_ea,),
        #     )
        # )

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
        dispatcher_serial: int,
        bst_node_blocks: set[int],
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

        if all(int(candidate.target_entry) == int(old_target) for candidate in ordered_candidates):
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason="noop_or_missing_old_target",
                )
                for candidate in ordered_candidates
            )
            return 0

        shared_group_plan = plan_shared_group_duplication(
            SharedGroupContext(
                shared_block=int(shared_block),
                old_target=int(old_target),
                shared_preds=tuple(int(pred) for pred in shared_snapshot.preds),
                candidates=tuple(
                    SharedGroupCandidate(
                        via_pred=int(candidate.via_pred),
                        target_entry=int(candidate.target_entry),
                    )
                    for candidate in ordered_candidates
                ),
            )
        )
        if not shared_group_plan.accepted:
            rejected_metadata.extend(
                cls._make_edge_metadata(
                    candidate.edge,
                    horizon_block=candidate.horizon_block,
                    site=candidate.site,
                    target_entry=candidate.target_entry,
                    first_shared_block=shared_block,
                    via_pred=candidate.via_pred,
                    rejection_reason=shared_group_plan.rejection_reason,
                )
                for candidate in ordered_candidates
            )
            return 0
        per_pred_targets = list(shared_group_plan.per_pred_targets)

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
            "RECON DAG: duplicate-and-redirect %s preds=%s",
            blk_label(mba, shared_block),
            [
                (blk_label(mba, pred), blk_label(mba, target))
                for pred, target in per_pred_targets
            ],
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
        _corrected_dag_out: list = []
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
            corrected_dag_out=_corrected_dag_out,
        )
        # dag: stale augmented DAG (baseline behavior).  Used for phase 1
        # corridor candidates so redirect targets are identical to baseline.
        # corrected_dag: augmented DAG with dispatcher-validated supplemental
        # anchors.  Used for late phases (bridge, feeder, island rescue,
        # terminal family) that benefit from correct supplemental targets.
        corrected_dag = _corrected_dag_out[0] if _corrected_dag_out else dag
        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            state_var_stkoff,
        )

        # --- Early DAG-only diagnostic snapshot (fires even if no modifications) ---
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

                _early_snap_id = snapshot_mba(
                    diag_db,
                    [],
                    label=f"{self.name}_state_write_reconstruction_dag",
                    func_ea=mba.entry_ea if mba is not None else 0,
                    maturity="MMAT_GLBOPT1",
                    phase="post_apply",
                )

                _early_dag_nodes = []
                for node in dag.nodes:
                    _early_dag_nodes.append(DagNode(
                        state=int(node.key.state_const) if node.key.state_const is not None else 0,
                        state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                        entry_block=int(node.entry_anchor),
                        classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                        shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                    ))

                _early_dag_edges = []
                for eidx, edge in enumerate(dag.edges):
                    _early_dag_edges.append(DagEdge(
                        edge_id=eidx,
                        source_state=int(edge.source_key.state_const) if edge.source_key.state_const is not None else None,
                        target_state=int(edge.target_key.state_const) if edge.target_key is not None and edge.target_key.state_const is not None else None,
                        edge_kind=str(edge.kind.name) if hasattr(edge.kind, "name") else str(edge.kind),
                        source_block=int(edge.source_anchor.block_serial) if edge.source_anchor is not None else None,
                        source_arm=edge.source_anchor.branch_arm if edge.source_anchor is not None else None,
                        target_entry=int(edge.target_entry_anchor) if edge.target_entry_anchor is not None else None,
                        ordered_path=_json.dumps([int(s) for s in edge.ordered_path]) if edge.ordered_path else "[]",
                    ))

                snapshot_dag(diag_db, _early_snap_id, _early_dag_nodes, _early_dag_edges)
        except Exception:
            logger.warning(
                "Early diagnostic DAG snapshot failed (non-critical)",
                exc_info=True,
            )

        # Phase 1 uses dag (stale augmented — identical to baseline) so
        # that corridor redirect targets are unchanged.  Late phases below
        # switch to corrected_dag.
        dispatcher_region = set(dag.bst_node_blocks)
        if dag.dispatcher_entry_serial >= 0:
            dispatcher_region.add(int(dag.dispatcher_entry_serial))
        shared_suffix_blocks = self._shared_suffix_blocks(dag)
        node_by_key, outgoing_by_key, nodes_by_entry_anchor = self._node_maps(dag)

        dispatcher_serial = int(dag.dispatcher_entry_serial)

        raw_candidates: list[ReconstructionCandidate] = []
        rejected_metadata: list[dict[str, int | str | None]] = []
        edge_kind_counts = Counter(
            edge_kind_name(e) for e in dag.edges
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

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        accepted_metadata: list[dict[str, int | str | None]] = []

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
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.

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
                dispatcher_serial=dispatcher_serial,
                bst_node_blocks=dispatcher_region,
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
            # Fall through to Bridge Builder and Feeder redirect sections
            # which can wire edges rejected by the strict corridor emitter.
        else:
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

        projected_flow_graph = flow_graph
        # corrected_dag is available for late phases but not yet wired in.
        _ = corrected_dag  # suppress unused warning

        residual_dispatcher_preds: tuple[int, ...] = ()
        allow_post_apply_bst_cleanup = True
        post_apply_bst_cleanup_reason: str | None = None
        if dispatcher_serial >= 0:
            try:
                patch_plan = compile_patch_plan(modifications, flow_graph)
                projected_flow_graph = project_post_state(flow_graph, patch_plan)
            except Exception:
                projected_flow_graph = flow_graph

            entry_island_rescue_count = self._emit_entry_island_rescues(
                corrected_dag,
                base_flow_graph=flow_graph,
                projected_flow_graph=projected_flow_graph,
                builder=builder,
                modifications=modifications,
                dispatcher_region=dispatcher_region,
                mba=mba,
            )
            if entry_island_rescue_count:
                logger.info(
                    "RECON DAG: entry-island rescue emitted %d redirects",
                    entry_island_rescue_count,
                )
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
            # Shared-group predecessor-edge peel preserves the shared source on
            # its old target without emitting a direct modification for that
            # source block. Carry strict-emitter ownership forward so bridge and
            # feeder passes treat those sources as already handled.
            claimed_sources.update(int(block_serial) for block_serial in owned_blocks)

            # Step 1b: Build suppressed source->target pairs from structural
            # rejections (e.g. backward_same_corridor_target) to prevent
            # Bridge/Feeder from wiring edges that _build_candidate
            # intentionally refused for safety reasons.
            _structural_rejection_reasons = frozenset({
                "backward_same_corridor_target",
            })
            suppressed_bridge_pairs: set[tuple[int, int]] = set()
            for rej in rejected_metadata:
                if rej.get("rejection_reason") in _structural_rejection_reasons:
                    _rej_src = rej.get("source_block")
                    _rej_tgt = rej.get("target_entry_anchor")
                    if _rej_src is not None and _rej_tgt is not None:
                        suppressed_bridge_pairs.add((int(_rej_src), int(_rej_tgt)))

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
                # Fall back to source_anchor.block_serial for empty paths.
                exit_block: int | None = None
                if edge.ordered_path:
                    for serial in reversed(edge.ordered_path):
                        if serial not in _bst_set:
                            exit_block = serial
                            break
                else:
                    # Empty ordered_path: use source_anchor directly
                    src = int(edge.source_anchor.block_serial)
                    if src not in _bst_set:
                        exit_block = src

                if exit_block is None:
                    continue

                # Skip structurally suppressed edges (e.g. backward corridor)
                if (exit_block, target_entry) in suppressed_bridge_pairs:
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
                        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                        # if edge.last_write_site is not None:
                        #     _ws_blk, _ws_ea = edge.last_write_site
                        #     bridge_mods.append(
                        #         NopInstructions(
                        #             block_serial=int(_ws_blk),
                        #             insn_eas=(int(_ws_ea),),
                        #         )
                        #     )
                        # else:
                        #     logger.debug(
                        #         "RECON BRIDGE: no last_write_site for "
                        #         "blk[%d] -> blk[%d], skipping NOP",
                        #         exit_block, target_entry,
                        #     )
                        _bridge_tag = (
                            "empty-path direct wire"
                            if not edge.ordered_path
                            else "1-way"
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
                            "RECON BRIDGE: wire blk[%d] -> blk[%d] (%s)",
                            exit_block, target_entry, _bridge_tag,
                        )
                elif block.nsucc == 2:
                    # 2-way block: find which arm points to BST/dispatcher
                    for arm in range(2):
                        arm_target = int(block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                                # if edge.last_write_site is not None:
                                #     _ws_blk, _ws_ea = edge.last_write_site
                                #     bridge_mods.append(
                                #         NopInstructions(
                                #             block_serial=int(_ws_blk),
                                #             insn_eas=(int(_ws_ea),),
                                #         )
                                #     )
                                # else:
                                #     logger.debug(
                                #         "RECON BRIDGE: no last_write_site for "
                                #         "blk[%d].arm%d -> blk[%d], skipping NOP",
                                #         exit_block, arm, target_entry,
                                #     )
                                _bridge_tag_2 = (
                                    "empty-path direct wire"
                                    if not edge.ordered_path
                                    else "2-way"
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
                                    "RECON BRIDGE: wire blk[%d].arm%d -> blk[%d] (%s)",
                                    exit_block, arm, target_entry, _bridge_tag_2,
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
                if edge.target_entry_anchor is None:
                    continue
                # UNKNOWN edges with valid target_entry_anchor are DFS-proven
                # transitions whose snapshot state writes were unresolvable.
                # They are safe to wire via the feeder redirect.
                if edge.kind not in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    SemanticEdgeKind.UNKNOWN,
                ):
                    continue
                target_entry = int(edge.target_entry_anchor)
                if target_entry in _bst_set:
                    continue

                src_serial = int(edge.source_anchor.block_serial)
                if src_serial in claimed_sources:
                    continue  # Already handled by strict emitter or bridge

                # Skip structurally suppressed edges (e.g. backward corridor)
                if (src_serial, target_entry) in suppressed_bridge_pairs:
                    continue

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
                        # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                        # if edge.last_write_site is not None:
                        #     _ws_blk, _ws_ea = edge.last_write_site
                        #     feeder_mods.append(
                        #         NopInstructions(
                        #             block_serial=int(_ws_blk),
                        #             insn_eas=(int(_ws_ea),),
                        #         )
                        #     )
                        # else:
                        #     logger.debug(
                        #         "RECON FEEDER: no last_write_site for "
                        #         "blk[%d] -> blk[%d], skipping NOP",
                        #         src_serial, target_entry,
                        #     )
                        _feeder_tag = (
                            "UNKNOWN 1-way"
                            if edge.kind == SemanticEdgeKind.UNKNOWN
                            else "1-way"
                        )
                        proj_src = projected_flow_graph.get_block(src_serial)
                        src_npred = len(proj_src.preds) if proj_src is not None else 0
                        pred_succs: tuple[int, ...] = ()
                        feeder_context = SharedFeederContext(
                            source_serial=src_serial,
                            source_pred_count=src_npred,
                            ordered_path=tuple(
                                int(node) for node in (edge.ordered_path or ())
                            ),
                            via_pred_succs=(),
                            target_entry=target_entry,
                            dispatcher_serial=dispatcher_serial,
                            bst_node_blocks=frozenset(_bst_set),
                            target_reaches_pred=False,
                        )
                        edge_pred = feeder_context.via_pred
                        if edge_pred is not None:
                            pred_block = projected_flow_graph.get_block(edge_pred)
                            if pred_block is not None:
                                pred_succs = tuple(
                                    int(succ) for succ in getattr(pred_block, "succs", ())
                                )
                        target_reaches_pred = (
                            target_reaches_source_ignoring_blocks(
                                projected_flow_graph,
                                target_entry=target_entry,
                                source_block=edge_pred,
                                ignored_blocks=_bst_set | {dispatcher_serial, src_serial},
                            )
                            if edge_pred is not None
                            else False
                        )
                        lowering = select_shared_feeder_lowering(
                            SharedFeederContext(
                                source_serial=feeder_context.source_serial,
                                source_pred_count=feeder_context.source_pred_count,
                                ordered_path=feeder_context.ordered_path,
                                via_pred_succs=pred_succs,
                                target_entry=feeder_context.target_entry,
                                dispatcher_serial=feeder_context.dispatcher_serial,
                                bst_node_blocks=feeder_context.bst_node_blocks,
                                target_reaches_pred=target_reaches_pred,
                            )
                        )
                        if not lowering.accepted:
                            logger.info(
                                "RECON BRIDGE: feeder blk[%d] -> blk[%d] rejected (%s)",
                                src_serial,
                                target_entry,
                                lowering.reason,
                            )
                            continue
                        if lowering.kind == SharedFeederLoweringKind.PRED_SCOPED_CLONE:
                            feeder_mods.append(
                                builder.duplicate_and_redirect(
                                    source_block=src_serial,
                                    per_pred_targets=[
                                        (lowering.via_pred, target_entry),
                                    ],
                                )
                            )
                            _feeder_tag += " pred-scoped"
                            claimed_sources.add(src_serial)
                        elif (
                            lowering.kind == SharedFeederLoweringKind.PRED_EDGE_PEEL
                            and lowering.via_pred is not None
                        ):
                            feeder_mods.append(
                                builder.edge_redirect(
                                    source_block=lowering.via_pred,
                                    target_block=target_entry,
                                    old_target=src_serial,
                                )
                            )
                            _feeder_tag += " pred-edge"
                            claimed_sources.add(lowering.via_pred)
                        else:
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
                            "RECON BRIDGE: feeder blk[%d] -> blk[%d] (%s npred=%d via_pred=%s)",
                            src_serial,
                            target_entry,
                            _feeder_tag,
                            src_npred,
                            lowering.via_pred,
                        )
                elif src_block.nsucc == 2:
                    for arm in range(2):
                        arm_target = int(src_block.succs[arm])
                        if arm_target == dispatcher_serial or arm_target in _bst_set:
                            if arm == 1:  # RedirectBranch only handles arm=1
                                # DISABLED: state-write NOPing is display-only — IDA DCE handles at later maturity
                                # if edge.last_write_site is not None:
                                #     _ws_blk, _ws_ea = edge.last_write_site
                                #     feeder_mods.append(
                                #         NopInstructions(
                                #             block_serial=int(_ws_blk),
                                #             insn_eas=(int(_ws_ea),),
                                #         )
                                #     )
                                # else:
                                #     logger.debug(
                                #         "RECON FEEDER: no last_write_site for "
                                #         "blk[%d].arm%d -> blk[%d], skipping NOP",
                                #         src_serial, arm, target_entry,
                                #     )
                                _feeder_tag_2 = (
                                    "UNKNOWN 2-way"
                                    if edge.kind == SemanticEdgeKind.UNKNOWN
                                    else "2-way"
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
                                    "RECON BRIDGE: feeder blk[%d].arm%d -> blk[%d] (%s)",
                                    src_serial, arm, target_entry, _feeder_tag_2,
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
            # Artifact return block classification: identify m_xdu / m_mov
            # blocks that copy the dead state variable into the return slot.
            # ------------------------------------------------------------------
            artifact_return_blocks: set[int] = set()
            if state_var_stkoff is not None:
                _state_consts = sm.state_constants if sm is not None else set()
                logger.info(
                    "RECON RETURN: classifying artifacts: "
                    "state_var_stkoff=%s, flow_graph blocks=%d, "
                    "state_constants count=%d",
                    state_var_stkoff, len(flow_graph.blocks),
                    len(_state_consts),
                )
                artifact_return_blocks = self._classify_artifact_return_blocks(
                    flow_graph, state_var_stkoff, _state_consts,
                )
                if artifact_return_blocks:
                    logger.info(
                        "RECON RETURN: artifact return blocks: %s",
                        sorted(artifact_return_blocks),
                    )
                else:
                    logger.info(
                        "RECON RETURN: NO artifact blocks found "
                        "(classifier returned empty set)",
                    )

            # ------------------------------------------------------------------
            # Return Path Wiring: path-local return lowering for
            # CONDITIONAL_RETURN edges using DAG shared-suffix info
            # ------------------------------------------------------------------
            # Instead of a generic hop-walk that follows flow_graph
            # successors (which may traverse m_xdu artifact blocks), use
            # the DAG's ordered_path and shared_suffix_blocks to identify
            # the correct return anchor and shared suffix entry.
            #
            # For each CONDITIONAL_RETURN edge:
            #   1. Look up the source node's shared_suffix_blocks
            #   2. Find the first shared suffix block in the ordered_path
            #   3. The "return anchor" is the block just before the suffix
            #   4. Wire the anchor's arm to the shared suffix entry

            return_mods: list = []
            return_skipped: list[tuple[int, str]] = []

            # Precompute the common return corridor: blocks that appear
            # in ALL CONDITIONAL_RETURN edge paths.  This identifies
            # blk[217]/blk[218] as the universal return corridor.
            _ret_paths: list[set[int]] = []
            for _e in dag.edges:
                if _e.kind == SemanticEdgeKind.CONDITIONAL_RETURN and _e.ordered_path:
                    _ret_paths.append({int(s) for s in _e.ordered_path})
            common_return_corridor: set[int] = set()
            if _ret_paths:
                common_return_corridor = _ret_paths[0]
                for _p in _ret_paths[1:]:
                    common_return_corridor &= _p
            # Extend the corridor backward: walk 1-way predecessors of
            # the earliest common corridor block to find the full return
            # corridor chain (e.g., blk[217] → blk[218] → blk[219]).
            # The paths may omit early corridor blocks due to pass-1
            # block serial drift.
            if common_return_corridor:
                earliest = min(common_return_corridor)
                _walk_serial = earliest
                for _ in range(5):  # max 5 backward hops
                    _walk_blk = flow_graph.get_block(_walk_serial)
                    if _walk_blk is None:
                        break
                    # Find 1-way predecessors of this block
                    preds = list(flow_graph.predecessors(_walk_serial))
                    logger.info(
                        "RECON RETURN: corridor backward walk blk[%d] "
                        "preds=%s shared_suffix_blocks=%s",
                        _walk_serial, preds, sorted(shared_suffix_blocks),
                    )
                    extended = False
                    # Pick the highest-serial 1-way predecessor that
                    # is not BST, not dispatcher, not already in corridor.
                    # The return corridor entry (blk[217]) typically has
                    # the highest serial among 1-way predecessors.
                    best_pred: int | None = None
                    for pred_serial in sorted(preds, reverse=True):
                        pred_blk = flow_graph.get_block(pred_serial)
                        if (
                            pred_blk is not None
                            and pred_blk.nsucc == 1
                            and pred_serial not in _bst_set
                            and pred_serial != dispatcher_serial
                            and pred_serial not in common_return_corridor
                        ):
                            best_pred = pred_serial
                            break
                    if best_pred is not None:
                        common_return_corridor.add(best_pred)
                        _walk_serial = best_pred
                        extended = True
                    if not extended:
                        break
            if common_return_corridor:
                logger.info(
                    "RECON RETURN: common return corridor blocks: %s",
                    sorted(common_return_corridor),
                )

            for edge in dag.edges:
                if edge.kind != SemanticEdgeKind.CONDITIONAL_RETURN:
                    continue

                src_serial = int(edge.source_anchor.block_serial)
                src_arm = edge.source_anchor.branch_arm

                if not edge.ordered_path:
                    return_skipped.append((src_serial, "empty_ordered_path"))
                    continue

                ordered = tuple(int(s) for s in edge.ordered_path)

                if len(ordered) < 2:
                    return_skipped.append((src_serial, "path_too_short"))
                    continue

                # Look up the source node to get shared_suffix_blocks
                source_node = node_by_key.get(edge.source_key)
                node_shared_suffix: set[int] = set()
                if source_node is not None:
                    node_shared_suffix = {
                        int(b) for b in source_node.shared_suffix_blocks
                    }

                # Determine the shared suffix entry block.
                # Use ONLY the node-local shared_suffix_blocks that are
                # on the return corridor (predecessors of the last block
                # in the ordered_path).  The suffix entry is the block
                # in the suffix set that is a predecessor of the terminal,
                # NOT the dispatcher or unrelated shared blocks.
                suffix_entry_serial: int | None = None
                anchor_serial: int | None = None
                if len(ordered) >= 2:
                    terminal = ordered[-1]
                    # Use the common return corridor directly (not per-node
                    # suffix).  The corridor entry is the lowest-serial
                    # block in the corridor that is not the terminal.
                    corridor_candidates = sorted(
                        b for b in common_return_corridor
                        if b != terminal
                    )
                    if not corridor_candidates:
                        # Fall back to node-local suffix
                        corridor_candidates = sorted(
                            b for b in node_shared_suffix
                            if b != terminal
                            and b not in _bst_set
                            and b != dispatcher_serial
                        )
                    if corridor_candidates:
                        suffix_entry_serial = corridor_candidates[0]

                    # The anchor is the source block itself (it's the
                    # block whose arm we need to rewire to the corridor).
                    # For edges like src=blk[206], the anchor IS blk[206]
                    # — its fallthrough should reach the suffix entry.
                    anchor_serial = src_serial

                if suffix_entry_serial is None:
                    # No shared suffix info — fall back to simple last-hop
                    # redirect.
                    # Use the last non-BST block pair in the ordered_path.
                    fallback_emitted = False
                    for hop_idx in range(len(ordered) - 1):
                        from_serial = ordered[hop_idx]
                        expected_next = ordered[hop_idx + 1]
                        if from_serial in _bst_set or from_serial in claimed_sources:
                            continue
                        from_block = flow_graph.get_block(from_serial)
                        if from_block is None:
                            continue
                        if from_block.nsucc == 1:
                            old_target = int(from_block.succs[0])
                            if old_target == expected_next:
                                continue
                            return_mods.append(
                                builder.goto_redirect(
                                    source_block=from_serial,
                                    target_block=expected_next,
                                    old_target=old_target,
                                )
                            )
                            claimed_sources.add(from_serial)
                            logger.info(
                                "RECON RETURN: fallback wire blk[%d] -> blk[%d] (1-way)",
                                from_serial, expected_next,
                            )
                            fallback_emitted = True
                            break
                        elif from_block.nsucc == 2:
                            check_arms = (
                                [src_arm]
                                if from_serial == src_serial and src_arm is not None
                                else [0, 1]
                            )
                            for arm in check_arms:
                                if arm >= from_block.nsucc:
                                    continue
                                arm_target = int(from_block.succs[arm])
                                if arm_target == expected_next:
                                    fallback_emitted = True
                                    break
                                return_mods.append(
                                    builder.edge_redirect(
                                        source_block=from_serial,
                                        target_block=expected_next,
                                        old_target=arm_target,
                                    )
                                )
                                claimed_sources.add(from_serial)
                                logger.info(
                                    "RECON RETURN: fallback wire blk[%d].arm%d -> blk[%d] (2-way)",
                                    from_serial, arm, expected_next,
                                )
                                fallback_emitted = True
                                break
                            if fallback_emitted:
                                break
                    if not fallback_emitted:
                        return_skipped.append(
                            (src_serial, "no_suffix_fallback_exhausted"),
                        )
                    continue

                # Shared suffix entry determined from node's shared_suffix_blocks.
                # anchor_serial determined as last non-suffix block in path.

                logger.info(
                    "RECON RETURN: path-local edge src=blk[%d] path=%s "
                    "suffix_entry=blk[%d] anchor=blk[%d]",
                    src_serial, ordered, suffix_entry_serial, anchor_serial,
                )

                # Skip BST anchors and already-claimed anchors
                if anchor_serial in _bst_set:
                    return_skipped.append(
                        (anchor_serial, "anchor_in_bst"),
                    )
                    continue
                if anchor_serial in claimed_sources:
                    return_skipped.append(
                        (anchor_serial, "anchor_claimed"),
                    )
                    continue

                anchor_block = flow_graph.get_block(anchor_serial)
                if anchor_block is None:
                    return_skipped.append(
                        (anchor_serial, "anchor_block_not_found"),
                    )
                    continue

                # Check if the anchor already points to the suffix entry
                if anchor_block.nsucc == 1:
                    old_target = int(anchor_block.succs[0])
                    if old_target == suffix_entry_serial:
                        # Already correct — nothing to do
                        logger.info(
                            "RECON RETURN: blk[%d] already points to "
                            "suffix entry blk[%d]",
                            anchor_serial, suffix_entry_serial,
                        )
                        continue
                    # Wire anchor to suffix entry, bypassing artifact
                    return_mods.append(
                        builder.goto_redirect(
                            source_block=anchor_serial,
                            target_block=suffix_entry_serial,
                            old_target=old_target,
                        )
                    )
                    claimed_sources.add(anchor_serial)
                    logger.info(
                        "RECON RETURN: wire blk[%d] -> blk[%d] "
                        "(bypass artifact blk[%d], 1-way)",
                        anchor_serial, suffix_entry_serial, old_target,
                    )

                elif anchor_block.nsucc == 2:
                    # For 2-way anchor, use the specific arm from
                    # source_anchor when anchor is the source block,
                    # otherwise check both arms.
                    if anchor_serial == src_serial and src_arm is not None:
                        check_arms = [src_arm]
                    else:
                        check_arms = [0, 1]

                    wired = False
                    for arm in check_arms:
                        if arm >= anchor_block.nsucc:
                            continue
                        arm_target = int(anchor_block.succs[arm])
                        if arm_target == suffix_entry_serial:
                            # Arm already correct
                            wired = True
                            break
                        if arm == 0:
                            # Fallthrough arm: classify as artifact or
                            # real return-value setter using the pre-
                            # computed artifact_return_blocks set.
                            artifact_blk = flow_graph.get_block(arm_target)
                            if (
                                artifact_blk is not None
                                and artifact_blk.nsucc == 1
                                and arm_target in artifact_return_blocks
                                and arm_target not in claimed_sources
                            ):
                                artifact_old = int(artifact_blk.succs[0])
                                return_mods.append(
                                    builder.goto_redirect(
                                        source_block=arm_target,
                                        target_block=suffix_entry_serial,
                                        old_target=artifact_old,
                                    )
                                )
                                claimed_sources.add(arm_target)
                                logger.info(
                                    "RECON RETURN: redirect artifact blk[%d] -> blk[%d]",
                                    arm_target, suffix_entry_serial,
                                )
                                wired = True
                                break
                            else:
                                # Real return-value setter — leave alone
                                logger.info(
                                    "RECON RETURN: skip arm0 blk[%d] (real return writer)",
                                    arm_target,
                                )
                                wired = True
                                break
                        else:
                            # Taken arm — use edge_redirect normally
                            return_mods.append(
                                builder.edge_redirect(
                                    source_block=anchor_serial,
                                    target_block=suffix_entry_serial,
                                    old_target=arm_target,
                                )
                            )
                        claimed_sources.add(anchor_serial)
                        logger.info(
                            "RECON RETURN: wire blk[%d].arm%d -> blk[%d] "
                            "(bypass artifact blk[%d], 2-way)",
                            anchor_serial, arm, suffix_entry_serial,
                            arm_target,
                        )
                        wired = True
                        break
                    if not wired:
                        return_skipped.append(
                            (anchor_serial, "no_eligible_arm"),
                        )
                else:
                    return_skipped.append(
                        (anchor_serial,
                         f"unexpected_nsucc_{anchor_block.nsucc}"),
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
            projected_flow_graph = flow_graph
            if all_extra_mods:
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(
                        flow_graph, patch_plan,
                    )
                except Exception:
                    projected_flow_graph = flow_graph

                late_entry_island_rescue_count = self._emit_entry_island_rescues(
                    dag,
                    base_flow_graph=flow_graph,
                    projected_flow_graph=projected_flow_graph,
                    builder=builder,
                    modifications=modifications,
                    dispatcher_region=dispatcher_region,
                    mba=mba,
                )
                if late_entry_island_rescue_count:
                    logger.info(
                        "RECON DAG: post-bridge entry-island rescue emitted %d redirects",
                        late_entry_island_rescue_count,
                    )
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

                # Late island rescue: reconnect handler bodies that are
                # unreachable because they sit behind dead BST nodes.
                late_island_rescue_count = self._emit_late_island_rescues(
                    dag,
                    base_flow_graph=flow_graph,
                    projected_flow_graph=projected_flow_graph,
                    builder=builder,
                    modifications=modifications,
                    dispatcher_region=dispatcher_region,
                    dispatcher=getattr(bst_result, "dispatcher", None),
                    mba=mba,
                )
                if late_island_rescue_count:
                    logger.info(
                        "RECON DAG: late island rescue emitted %d redirects",
                        late_island_rescue_count,
                    )
                    try:
                        patch_plan = compile_patch_plan(modifications, flow_graph)
                        projected_flow_graph = project_post_state(
                            flow_graph, patch_plan,
                        )
                    except Exception:
                        projected_flow_graph = flow_graph

            terminal_family_split_count = self._emit_terminal_family_splits(
                dag,
                base_flow_graph=flow_graph,
                projected_flow_graph=projected_flow_graph,
                builder=builder,
                modifications=modifications,
                dispatcher_region=dispatcher_region,
                state_var_stkoff=state_var_stkoff,
                mba=mba,
            )
            if terminal_family_split_count:
                logger.info(
                    "RECON RETURN: late terminal-family split emitted %d privatizations",
                    terminal_family_split_count,
                )
                try:
                    patch_plan = compile_patch_plan(modifications, flow_graph)
                    projected_flow_graph = project_post_state(
                        flow_graph, patch_plan,
                    )
                except Exception:
                    projected_flow_graph = flow_graph

        # Final guard: if no modifications after all emission phases, return None.
        if not modifications:
            logger.info(
                "RECON DAG: no modifications produced across strict + bridge + feeder phases",
            )
            return None

        # --- Diagnostic snapshot: DAG + modifications (gated behind D810_DIAG_SNAPSHOT=1) ---
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

                # Create a snapshot anchor for this DAG
                snap_id = snapshot_mba(
                    diag_db,
                    [],  # No block data here — executor captures full MBA
                    label=f"{self.name}_state_write_reconstruction_post_apply",
                    func_ea=mba.entry_ea if mba is not None else 0,
                    maturity="MMAT_GLBOPT1",
                    phase="post_apply",
                )

                # Build DAG node snapshots
                dag_nodes = []
                for node in dag.nodes:
                    dag_nodes.append(DagNode(
                        state=int(node.key.state_const) if node.key.state_const is not None else 0,
                        state_hex=f"0x{node.key.state_const:08X}" if node.key.state_const is not None else "None",
                        entry_block=int(node.entry_anchor),
                        classification=str(node.kind.name) if hasattr(node.kind, "name") else str(node.kind),
                        shared_suffix=_json.dumps(sorted(int(b) for b in node.shared_suffix_blocks)) if node.shared_suffix_blocks else None,
                    ))

                # Build DAG edge snapshots
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

                # Build modification snapshots
                mod_snapshots = []
                for midx, mod in enumerate(modifications):
                    mod_type = type(mod).__name__
                    source_block = getattr(mod, "from_serial", None) or getattr(mod, "source_block", None) or getattr(mod, "src_block", None) or getattr(mod, "block_serial", None)
                    target_block = getattr(mod, "new_target", None) or getattr(mod, "goto_target", None) or getattr(mod, "conditional_target", None)
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

        # Split fragment when block-creating ops and PTS share a batch.
        # Block-creating ops (duplicate_and_redirect) shift serials, making
        # PTS suffix serials stale by the time PTS executes.  Splitting lets
        # PTS run against the settled graph after block creators are applied.
        _PTS_TYPES = (PrivateTerminalSuffix, PrivateTerminalSuffixGroup)
        pts_mods = [m for m in modifications if isinstance(m, _PTS_TYPES)]
        has_block_creators = any(is_block_creating_modification(m) for m in modifications)

        if pts_mods and has_block_creators:
            # Drop PTS from this batch — block-creating ops shift serials,
            # making suffix serials stale. PTS will be re-discovered on the
            # next optimizer invocation when the planner runs against the
            # settled post-creation flow graph with correct serials.
            non_pts_mods = [m for m in modifications if not isinstance(m, _PTS_TYPES)]
            logger.info(
                "RECON: deferring %d PTS mods to next invocation "
                "(block-creating ops would shift suffix serials)",
                len(pts_mods),
            )
            modifications = non_pts_mods

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
