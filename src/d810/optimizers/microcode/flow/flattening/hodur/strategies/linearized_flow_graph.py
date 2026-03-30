"""LinearizedFlowGraphStrategy -- DAG-driven branch stitching.

Builds a live :class:`LinearizedStateDag` from the current CFG and uses that
state-level semantic graph as the planning surface for redirect emission.

The current implementation prefers DAG-selected path tails and branch anchors,
and now also allows direct rewrites of shared 1-way dispatcher tails when the
tail block itself proves the same state->handler mapping. This lets LFG absorb
the late orphan-goto cases that previously required backward_pred_resolution.
"""
from __future__ import annotations

import ida_hexrays

from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.dag_redirect_execution import (
    DagRedirectExecutionContext,
    DagRedirectMutableState,
    execute_dag_redirect_fallback,
)
from d810.cfg.dispatcher_backedge_disconnect_execution import (
    execute_dispatcher_backedge_disconnects,
)
from d810.cfg.graph_modification import (
    RedirectGoto,
)
from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedFlowGraphPlanSetup,
    build_linearized_flow_graph_planning_callbacks,
    build_linearized_flow_graph_planning_context,
    execute_linearized_flow_graph_planning,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.path_tail_redirect_execution import (
    PathTailRedirectExecutionContext,
    PathTailRedirectMutableState,
    execute_path_tail_redirect,
)
from d810.cfg.projected_alias_normalization_planning import (
    apply_projected_alias_normalization_actions,
    collect_projected_alias_normalization_actions,
)
from d810.cfg.residual_branch_anchor_execution import (
    ResidualBranchAnchorExecutionContext,
    ResidualBranchAnchorMutableState,
    execute_residual_branch_anchor_handoff,
)
from d810.cfg.residual_dispatcher_handoff_execution import (
    ResidualDispatcherHandoffMutableState,
    build_residual_dispatcher_handoff_execution_context,
    execute_residual_dispatcher_handoffs,
)
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import (
    blk_label,
)
from d810.optimizers.microcode.flow.flattening.hodur._residual_handoff_bridge import (
    is_semantic_handoff_redirect,
    resolve_effective_target_entry,
    resolve_synthesized_handoff_target,
)
from d810.recon.flow.graph_reachability import (
    collect_dispatcher_predecessors,
)
from d810.recon.flow.dag_index import build_dag_node_maps
from d810.recon.flow.dag_redirect_discovery import (
    find_foreign_exact_entry_owner,
    select_plannable_dag_edges,
)
from d810.recon.flow.linearized_dag_round_discovery import (
    build_linearized_dag_round_summary,
)
from d810.recon.flow.residual_handoff_discovery import (
    collect_residual_source_handoff_facts,
    iter_residual_prefix_handoffs,
    resolve_assignment_map_handoff_target,
    resolve_contextual_dag_entry_for_state,
    resolve_cover_fallback_entry_for_state,
    resolve_dag_entry_for_state,
    resolve_immediate_handoff_target,
    resolve_normalized_alias_entry_for_state,
    resolve_projected_snapshot_handoff_target,
    resolve_projected_path_tail_target,
    resolve_redirect_safe_entry_from_node,
    resolve_redirect_safe_target_entry,
)
from d810.recon.flow.shared_suffix_discovery import (
    can_rewrite_shared_suffix_family_fallback,
    has_prior_branch_cut_for_state,
    is_shared_suffix_conditional_tail,
    pred_split_target_reaches_via_pred,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_reporting import (
    log_dag_redirect_fallback_outcome,
    log_path_tail_redirect_outcome,
    log_residual_dispatcher_handoff_outcomes,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_rerun import (
    allow_same_maturity_rerun,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_utils import (
    collect_dead_dispatcher_root_cleanup_modifications as collect_dead_dispatcher_root_cleanup_modifications_impl,
    collect_lfg_residual_dispatcher_predecessors,
    flow_graph_block_serials as flow_graph_block_serials_impl,
    has_live_exact_lfg_residual_handoff,
    is_original_pre_header_candidate as is_original_pre_header_candidate_impl,
    resolve_lfg_singleton_state_write_value,
    resolve_state_var_stkoff as resolve_state_var_stkoff_impl,
    supports_projected_replanning as supports_projected_replanning_impl,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    StateDagEdge,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.state_machine_analysis import build_mba_view_from_flow_graph
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
)
from d810.recon.flow.transition_builder import TransitionResult

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
        DispatcherStateMachine,
    )
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.linearized_flow_graph", logging.DEBUG)

__all__ = ["LinearizedFlowGraphStrategy"]


def _prepare_linearized_flow_graph_plan_setup(
    *,
    snapshot: object,
    state_machine: object,
    bst_result: object,
    flow_graph: object,
    mba: object | None,
    same_maturity_rerun: bool,
) -> LinearizedFlowGraphPlanSetup:
    bst_node_blocks = frozenset(
        int(block)
        for block in (getattr(bst_result, "bst_node_blocks", set()) or set())
    )
    builder = ModificationBuilder.from_snapshot(snapshot)
    state_var_stkoff = LinearizedFlowGraphStrategy._resolve_state_var_stkoff(
        snapshot,
        state_machine,
    )
    dispatcher = getattr(bst_result, "dispatcher", None)
    blocked_sources = frozenset(
        int(serial)
        for serial in (getattr(snapshot, "lfg_redirected_blocks", ()) or ())
    )
    dispatcher_region = bst_node_blocks
    original_blocks = frozenset(
        int(block)
        for block in LinearizedFlowGraphStrategy._flow_graph_block_serials(flow_graph)
    )
    transition_result = TransitionResult(
        transitions=list(state_machine.transitions),
        handlers=dict(state_machine.handlers),
        assignment_map=dict(state_machine.assignment_map),
        initial_state=state_machine.initial_state,
        pre_header_serial=getattr(bst_result, "pre_header_serial", None),
        strategy_name="linearized_flow_graph",
        resolved_count=len(state_machine.transitions),
    )

    raw_pre_header = (
        None if same_maturity_rerun else getattr(bst_result, "pre_header_serial", None)
    )
    entry_serial = getattr(getattr(snapshot, "reachability", None), "entry_serial", None)
    pre_header_serial = (
        raw_pre_header
        if LinearizedFlowGraphStrategy._is_original_pre_header_candidate(
            flow_graph,
            pre_header_serial=raw_pre_header,
            entry_serial=entry_serial,
        )
        else None
    )
    if raw_pre_header is not None and pre_header_serial is None:
        logger.info(
            "LFG DAG: suppressing non-entry pre-header candidate %s (entry=%s)",
            blk_label(mba, raw_pre_header),
            blk_label(mba, entry_serial) if entry_serial is not None else "<none>",
        )

    projectable = bool(
        LinearizedFlowGraphStrategy._supports_projected_replanning(flow_graph)
    )
    round_limit = 1 if same_maturity_rerun else 2
    return LinearizedFlowGraphPlanSetup(
        builder=builder,
        state_var_stkoff=state_var_stkoff,
        dispatcher=dispatcher,
        blocked_sources=blocked_sources,
        dispatcher_region=dispatcher_region,
        bst_node_blocks=bst_node_blocks,
        original_blocks=original_blocks,
        transition_result=transition_result,
        pre_header_serial=pre_header_serial,
        projectable=projectable,
        round_limit=round_limit,
    )


def _log_linearized_flow_graph_plan_result(
    *,
    mba: object | None,
    result: object,
) -> None:
    if result.unresolved_bst_targets:
        logger.info(
            "LFG DAG: preserving BST cleanup because %d targets still resolve only inside BST region",
            result.unresolved_bst_targets,
        )
    if result.cleanup_gate_reason == "residual_dispatcher_predecessors":
        logger.info(
            "LFG DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
            [blk_label(mba, serial) for serial in result.residual_dispatcher_preds],
        )

    logger.info(
        "LFG DAG: emitted %d redirects (%d unconditional, %d conditional); "
        "%d terminal edges ignored, %d unknown edges ignored, %d skipped conflicts; "
        "%d BST disconnects",
        result.transition_count + result.conditional_count,
        result.transition_count,
        result.conditional_count,
        result.terminal_skipped,
        result.unknown_skipped,
        result.skipped_count,
        result.disconnect_count,
    )


def _build_linearized_flow_graph_plan_fragment(
    *,
    strategy_name: str,
    family: str,
    prerequisites: list[str],
    state_machine: object,
    bst_node_blocks: frozenset[int],
    result: object,
) -> PlanFragment:
    ownership = OwnershipScope(
        blocks=result.owned_blocks,
        edges=result.owned_edges,
        transitions=result.owned_transitions,
    )
    benefit = BenefitMetrics(
        handlers_resolved=len(state_machine.handlers),
        transitions_resolved=result.transition_count + result.conditional_count,
        blocks_freed=len(bst_node_blocks),
        conflict_density=0.0,
    )
    return PlanFragment(
        strategy_name=strategy_name,
        family=family,
        modifications=list(result.modifications),
        ownership=ownership,
        prerequisites=prerequisites,
        expected_benefit=benefit,
        risk_score=0.1,
        metadata={
            "handlers_visited": len(state_machine.handlers),
            "resolved_count": result.transition_count + result.conditional_count,
            "dag_transition_count": result.transition_count,
            "dag_conditional_count": result.conditional_count,
            "dag_terminal_skipped": result.terminal_skipped,
            "dag_unknown_skipped": result.unknown_skipped,
            "skipped_count": result.skipped_count,
            "disconnect_count": result.disconnect_count,
            "allow_post_apply_bst_cleanup": result.cleanup_gate_reason is None,
            "post_apply_bst_cleanup_reason": result.cleanup_gate_reason,
            "residual_dispatcher_preds": result.residual_dispatcher_preds,
            "residual_dispatcher_redirect_count": result.residual_dispatcher_redirect_count,
            "residual_dispatcher_normalized_count": result.residual_dispatcher_normalized_count,
            "dead_island_cleanup_count": result.dead_island_cleanup_count,
            "unresolved_bst_targets": result.unresolved_bst_targets,
            "bst_convert_count": 0,
            "goto_nop_count": 0,
            "goto_skip_count": 0,
            "nop_state_values": {},
            "safeguard_min_required": 1,
        },
    )


class LinearizedFlowGraphStrategy:
    """Emit DAG-selected redirect edits for branch-anchored handler exits."""

    _MAX_PROJECTED_PLANNING_ROUNDS = 4

    @property
    def name(self) -> str:
        """Return the strategy identifier."""
        return "linearized_flow_graph"

    @property
    def family(self) -> str:
        """Return the strategy family."""
        return FAMILY_DIRECT

    # No prerequisites -- this is a standalone first-pass strategy.
    prerequisites: list[str] = []
    _applied: set[tuple[int, int]] = set()  # (func_ea, maturity) already processed
    _last_successful_residual_dispatcher_pred_counts: dict[tuple[int, int], int] = {}
    _same_count_exact_rerun_used: set[tuple[int, int]] = set()

    @staticmethod
    def _resolve_state_var_stkoff(
        snapshot: AnalysisSnapshot,
        sm: DispatcherStateMachine,
    ) -> int | None:
        return resolve_state_var_stkoff_impl(snapshot, sm)

    @staticmethod
    def _supports_projected_replanning(flow_graph: object) -> bool:
        return supports_projected_replanning_impl(flow_graph)

    @staticmethod
    def _flow_graph_block_serials(flow_graph: object) -> set[int]:
        return flow_graph_block_serials_impl(flow_graph)

    @classmethod
    def _resolve_singleton_state_write_value(
        cls,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
    ) -> int | None:
        return resolve_lfg_singleton_state_write_value(
            mba,
            block_serial,
            state_var_stkoff=state_var_stkoff,
        )

    @classmethod
    def _collect_dead_dispatcher_root_cleanup_modifications(
        cls,
        projected_flow_graph,
        *,
        dispatcher_serial: int,
        original_stop_serial: int | None,
        original_blocks: set[int],
    ) -> list[RedirectGoto]:
        return collect_dead_dispatcher_root_cleanup_modifications_impl(
            projected_flow_graph,
            dispatcher_serial=dispatcher_serial,
            original_stop_serial=original_stop_serial,
            original_blocks=original_blocks,
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
        return collect_lfg_residual_dispatcher_predecessors(
            flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
            reachable_from_serial=reachable_from_serial,
        )

    @classmethod
    def _resolve_redirect_safe_entry_from_node(cls, *args, **kwargs):
        return resolve_redirect_safe_entry_from_node(*args, **kwargs)

    @classmethod
    def _resolve_redirect_safe_target_entry(cls, *args, **kwargs):
        return resolve_redirect_safe_target_entry(*args, **kwargs)

    @classmethod
    def _resolve_contextual_dag_entry_for_state(cls, *args, **kwargs):
        return resolve_contextual_dag_entry_for_state(*args, **kwargs)

    @classmethod
    def _resolve_normalized_alias_entry_for_state(cls, *args, **kwargs):
        return resolve_normalized_alias_entry_for_state(*args, **kwargs)

    @classmethod
    def _resolve_cover_fallback_entry_for_state(cls, *args, **kwargs):
        return resolve_cover_fallback_entry_for_state(*args, **kwargs)

    @classmethod
    def _resolve_projected_path_tail_target(cls, *args, **kwargs):
        return resolve_projected_path_tail_target(*args, **kwargs)

    @classmethod
    def _resolve_immediate_handoff_target(cls, *args, **kwargs):
        return resolve_immediate_handoff_target(*args, **kwargs)

    @classmethod
    def _resolve_projected_snapshot_handoff_target(cls, *args, **kwargs):
        return resolve_projected_snapshot_handoff_target(*args, **kwargs)

    @classmethod
    def _resolve_assignment_map_handoff_target(cls, *args, **kwargs):
        return resolve_assignment_map_handoff_target(*args, **kwargs)

    @classmethod
    def _resolve_synthesized_handoff_target(cls, *args, **kwargs):
        return resolve_synthesized_handoff_target(*args, **kwargs)

    @classmethod
    def _resolve_effective_target_entry(cls, *args, **kwargs):
        return resolve_effective_target_entry(*args, **kwargs)

    @classmethod
    def _emit_residual_branch_anchor_handoff(
        cls,
        *,
        edge: StateDagEdge,
        source_block: int,
        via_pred: int,
        prefix_target: int,
        projected_flow_graph: object,
        bst_node_blocks: set[int],
        dispatcher_serial: int,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_2way: dict[tuple[int, int], int],
        ignored_blocks: set[int],
        residual_ignored_blocks: set[int],
        mba: object | None,
    ) -> bool:
        result = execute_residual_branch_anchor_handoff(
            ResidualBranchAnchorExecutionContext(
                edge=edge,
                source_block=int(source_block),
                via_pred=int(via_pred),
                prefix_target=int(prefix_target),
                projected_flow_graph=projected_flow_graph,
                bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
                dispatcher_serial=int(dispatcher_serial),
                block_succ_map=builder.block_succ_map,
                ignored_blocks=frozenset(int(block) for block in ignored_blocks),
                residual_ignored_blocks=frozenset(
                    int(block) for block in residual_ignored_blocks
                ),
            ),
            state=ResidualBranchAnchorMutableState(
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_2way=claimed_2way,
            ),
        )
        if not result.accepted:
            return False
        if result.already_claimed:
            return True
        assert result.branch_source is not None
        assert result.prefix_target is not None
        assert result.via_pred is not None
        assert result.edge_kind_name is not None
        logger.info(
            "LFG DAG: residual branch handoff %s -> %s (bypassing %s -> %s via %s)",
            blk_label(mba, int(result.branch_source)),
            blk_label(mba, int(result.prefix_target)),
            blk_label(mba, int(result.via_pred)),
            blk_label(mba, source_block),
            result.edge_kind_name,
        )
        return True

    @staticmethod
    def _is_original_pre_header_candidate(
        flow_graph: object | None,
        *,
        pre_header_serial: int | None,
        entry_serial: int | None,
    ) -> bool:
        return is_original_pre_header_candidate_impl(
            flow_graph,
            pre_header_serial=pre_header_serial,
            entry_serial=entry_serial,
        )

    @classmethod
    def _allow_same_maturity_rerun(
        cls,
        snapshot: AnalysisSnapshot,
        *,
        consume_retry: bool,
    ) -> bool:
        """Return whether a same-maturity rerun should proceed.

        This must stay side-effect free when ``consume_retry`` is False because
        the planner probes applicability before calling ``plan()``.  The retry
        token is only consumed from ``plan()`` so the second check does not
        spend the allowance before a fragment is actually built.
        """
        return allow_same_maturity_rerun(
            snapshot=snapshot,
            consume_retry=consume_retry,
            logger=logger,
            collect_residual_dispatcher_predecessors=cls._collect_residual_dispatcher_predecessors,
            collect_dispatcher_predecessors=collect_dispatcher_predecessors,
            has_live_exact_residual_handoff=cls._has_live_exact_residual_handoff,
            last_successful_residual_dispatcher_pred_counts=cls._last_successful_residual_dispatcher_pred_counts,
            same_count_exact_rerun_used=cls._same_count_exact_rerun_used,
        )

    # ------------------------------------------------------------------
    # Applicability
    # ------------------------------------------------------------------

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        """Return True when the snapshot has a state machine with handlers,
        a BST result with ``handler_state_map``, and a known ``initial_state``.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            True if the transition graph can be traversed.
        """
        mba = snapshot.mba
        if mba is not None:
            func_ea = mba.entry_ea
            maturity = mba.maturity
            if (func_ea, maturity) in LinearizedFlowGraphStrategy._applied:
                if not self._allow_same_maturity_rerun(
                    snapshot,
                    consume_retry=False,
                ):
                    return False

        sm = snapshot.state_machine
        if sm is None or not sm.handlers:
            return False
        if sm.initial_state is None:
            return False

        bst = snapshot.bst_result
        if bst is None:
            return False
        handler_state_map = getattr(bst, "handler_state_map", None) or {}
        if not handler_state_map:
            return False
        return True

    @classmethod
    def _has_live_exact_residual_handoff(
        cls,
        snapshot: AnalysisSnapshot,
        residual_preds: tuple[int, ...],
    ) -> bool:
        return has_live_exact_lfg_residual_handoff(
            snapshot,
            residual_preds,
            resolve_state_var_stkoff_fn=cls._resolve_state_var_stkoff,
        )

    # ------------------------------------------------------------------
    # Plan
    # ------------------------------------------------------------------

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        """Produce a :class:`PlanFragment` by stitching the transition graph.

        Iterates EVERY resolved edge in the state machine transition graph
        and emits a redirect for each one.  Then NOPs all state variable
        writes in handler blocks so the BST dispatcher becomes dead code.

        Args:
            snapshot: Immutable analysis snapshot for the current function.

        Returns:
            A :class:`PlanFragment` with redirect modifications, or ``None``
            when the strategy has nothing to contribute.
        """
        mba = snapshot.mba
        if mba is not None and (mba.entry_ea, mba.maturity) in self._applied:
            if not self._allow_same_maturity_rerun(snapshot, consume_retry=True):
                return None
        elif not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        assert sm is not None  # guaranteed by is_applicable
        bst_result = snapshot.bst_result
        assert bst_result is not None
        flow_graph = snapshot.flow_graph
        if flow_graph is None:
            logger.info("LFG: no flow_graph available, skipping")
            return None
        func_ea = getattr(mba, "entry_ea", None)
        maturity = getattr(mba, "maturity", None)
        same_maturity_rerun = (
            func_ea is not None
            and maturity is not None
            and (func_ea, maturity) in self._applied
        )

        dag_setup = _prepare_linearized_flow_graph_plan_setup(
            snapshot=snapshot,
            state_machine=sm,
            bst_result=bst_result,
            flow_graph=flow_graph,
            mba=mba,
            same_maturity_rerun=bool(same_maturity_rerun),
        )
        dag_result = execute_linearized_flow_graph_planning(
            build_linearized_flow_graph_planning_context(
                flow_graph=flow_graph,
                mba=mba,
                state_machine=sm,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                setup=dag_setup,
            ),
            callbacks=build_linearized_flow_graph_planning_callbacks(
                snapshot=snapshot,
                state_machine=sm,
                bst_result=bst_result,
                mba=mba,
                setup=dag_setup,
                discover_round_summary=build_linearized_dag_round_summary,
                build_projected_mba=build_mba_view_from_flow_graph,
                project_flow_graph=lambda base_flow_graph, modifications: project_post_state(
                    base_flow_graph,
                    compile_patch_plan(modifications, base_flow_graph),
                ),
                resolve_redirect_safe_target_entry=self._resolve_redirect_safe_target_entry,
                resolve_initial_entry=resolve_dag_entry_for_state,
                emit_dag_redirect=self._emit_dag_redirect,
                collect_residual_dispatcher_predecessors=self._collect_residual_dispatcher_predecessors,
                emit_residual_dispatcher_handoffs=self._emit_residual_dispatcher_handoffs,
                disconnect_bst_comparison_nodes=self._disconnect_bst_comparison_nodes,
                build_live_dag=build_live_linearized_state_dag_from_graph,
                build_transition_report=build_dispatcher_transition_report_from_graph,
                select_plannable_edges=select_plannable_dag_edges,
            ),
        )
        if not dag_result.accepted:
            logger.info("LFG: DAG produced no redirect modifications")
            return None

        _log_linearized_flow_graph_plan_result(
            mba=mba,
            result=dag_result,
        )
        return _build_linearized_flow_graph_plan_fragment(
            strategy_name=self.name,
            family=self.family,
            prerequisites=self.prerequisites,
            state_machine=sm,
            bst_node_blocks=dag_setup.bst_node_blocks,
            result=dag_result,
        )

    @classmethod
    def _emit_residual_dispatcher_handoffs(
        cls,
        *,
        dag: LinearizedStateDag,
        state_machine: DispatcherStateMachine | None,
        projected_flow_graph: object,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        claimed_2way: dict[tuple[int, int], int],
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None = None,
        mba: object | None = None,
        redirected_blocks: set[int] | None = None,
    ) -> int:
        result = execute_residual_dispatcher_handoffs(
            build_residual_dispatcher_handoff_execution_context(
                dag=dag,
                state_machine=state_machine,
                projected_flow_graph=projected_flow_graph,
                dispatcher_serial=int(dispatcher_serial),
                bst_node_blocks=bst_node_blocks,
                block_succ_map=builder.block_succ_map,
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
                collect_residual_dispatcher_predecessors=cls._collect_residual_dispatcher_predecessors,
                build_projected_mba=build_mba_view_from_flow_graph,
                collect_residual_source_handoff_facts=collect_residual_source_handoff_facts,
                iter_residual_prefix_handoffs=iter_residual_prefix_handoffs,
                can_rewrite_shared_suffix_family_fallback=can_rewrite_shared_suffix_family_fallback,
                has_prior_branch_cut_for_state=has_prior_branch_cut_for_state,
                is_shared_suffix_conditional_tail=is_shared_suffix_conditional_tail,
                pred_split_target_reaches_via_pred=pred_split_target_reaches_via_pred,
                resolve_synthesized_handoff_target=cls._resolve_synthesized_handoff_target,
                resolve_projected_path_tail_target=cls._resolve_projected_path_tail_target,
                resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
            ),
            state=ResidualDispatcherHandoffMutableState(
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_1way=claimed_1way,
                claimed_2way=claimed_2way,
                redirected_blocks=redirected_blocks,
            ),
        )
        log_residual_dispatcher_handoff_outcomes(
            logger,
            mba=mba,
            outcomes=result.outcomes,
        )
        return int(result.redirected_count)

    @classmethod
    def _normalize_projected_alias_handoffs(
        cls,
        *,
        dag: LinearizedStateDag,
        projected_flow_graph: object,
        dispatcher_serial: int,
        redirected_blocks: set[int],
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        mba: object,
    ) -> int:
        actions = collect_projected_alias_normalization_actions(
            dag=dag,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=int(dispatcher_serial),
            redirected_blocks={int(block) for block in redirected_blocks},
            bst_node_blocks={int(block) for block in bst_node_blocks},
            modifications=modifications,
            emitted=emitted,
            resolve_projected_path_tail_target=cls._resolve_projected_path_tail_target,
        )
        apply_projected_alias_normalization_actions(
            actions,
            modifications=modifications,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            claimed_1way=claimed_1way,
        )
        for action in actions:
            logger.info(
                "LFG DAG: normalized projected residual handoff %s -> %s (was %s)",
                blk_label(mba, int(action.source_block)),
                blk_label(mba, int(action.target_entry)),
                blk_label(mba, int(action.current_target)),
            )
        return len(actions)

    @classmethod
    def _emit_path_tail_redirect(
        cls,
        *,
        edge: StateDagEdge,
        target_entry: int | None = None,
        dag: LinearizedStateDag,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int] | None = None,
        claimed_exits: dict[int, int],
        claimed_path_edges: dict[tuple[int, int], int],
        blocked_sources: set[int],
        terminal_source_keys: set[object],
        terminal_source_handlers: set[int],
        terminal_source_owned_blocks: set[int],
        terminal_protected_blocks: set[int],
        report_exit_handlers: set[int],
        report_exit_owned_blocks: set[int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        flow_graph: object,
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        dispatcher: object | None = None,
        mba: object | None = None,
    ) -> bool:
        result = execute_path_tail_redirect(
            PathTailRedirectExecutionContext(
                edge=edge,
                dag=dag,
                target_entry=target_entry,
                flow_graph=flow_graph,
                block_succ_map=builder.block_succ_map,
                report_exit_handlers=frozenset(report_exit_handlers),
                report_exit_owned_blocks=frozenset(report_exit_owned_blocks),
                terminal_protected_blocks=frozenset(terminal_protected_blocks),
                bst_node_blocks=frozenset(bst_node_blocks),
                dispatcher_region=frozenset(dispatcher_region),
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
                resolve_effective_target_entry=cls._resolve_effective_target_entry,
                resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
                find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
                is_semantic_handoff_redirect=is_semantic_handoff_redirect,
            ),
            state=PathTailRedirectMutableState(
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_1way=claimed_1way,
                claimed_exits=claimed_exits,
                claimed_path_edges=claimed_path_edges,
                blocked_sources=blocked_sources,
            ),
        )
        return log_path_tail_redirect_outcome(
            logger,
            mba=mba,
            edge=edge,
            result=result,
        )

    @classmethod
    def _emit_dag_redirect(
        cls,
        *,
        edge: StateDagEdge,
        dag: LinearizedStateDag,
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
        claimed_2way: dict[tuple[int, int], int],
        claimed_exits: dict[int, int],
        claimed_path_edges: dict[tuple[int, int], int],
        blocked_sources: set[int],
        terminal_source_keys: set[object],
        terminal_source_handlers: set[int],
        terminal_source_owned_blocks: set[int],
        terminal_protected_blocks: set[int],
        report_exit_handlers: set[int],
        report_exit_owned_blocks: set[int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        flow_graph: object,
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        mba: object,
        dispatcher: object | None = None,
    ) -> bool:
        target_node = (
            build_dag_node_maps(dag).node_by_key.get(edge.target_key)
            if edge.target_key is not None
            else None
        )
        target_entry = cls._resolve_effective_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        )
        if (
            target_node is not None
            and target_entry is not None
            and edge.target_entry_anchor is not None
            and target_entry != edge.target_entry_anchor
        ):
            logger.info(
                "LFG DAG: retargeted stale BST entry %s -> semantic entry %s for %s",
                blk_label(mba, edge.target_entry_anchor),
                blk_label(mba, target_entry),
                target_node.state_label,
            )
        if target_entry is None:
            if edge.target_entry_anchor is not None:
                logger.info(
                    "LFG DAG: skipping %s -> %s because target remains inside BST region",
                    blk_label(mba, edge.source_anchor.block_serial),
                    blk_label(mba, edge.target_entry_anchor),
                )
            return False

        if cls._emit_path_tail_redirect(
            edge=edge,
            target_entry=target_entry,
            dag=dag,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_exits=claimed_exits,
            claimed_path_edges=claimed_path_edges,
            blocked_sources=blocked_sources,
            terminal_source_keys=terminal_source_keys,
            terminal_source_handlers=terminal_source_handlers,
            terminal_source_owned_blocks=terminal_source_owned_blocks,
            terminal_protected_blocks=terminal_protected_blocks,
            report_exit_handlers=report_exit_handlers,
            report_exit_owned_blocks=report_exit_owned_blocks,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
            flow_graph=flow_graph,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        ):
            return True

        if edge.target_entry_anchor is not None and target_entry != edge.target_entry_anchor:
            logger.info(
                "LFG DAG: skipping stale raw target %s in favor of semantic entry %s",
                blk_label(mba, edge.target_entry_anchor),
                blk_label(mba, target_entry),
            )

        result = execute_dag_redirect_fallback(
            DagRedirectExecutionContext(
                edge=edge,
                dag=dag,
                target_entry=int(target_entry),
                flow_graph=flow_graph,
                block_succ_map=builder.block_succ_map,
                block_nsucc_map=builder.block_nsucc_map,
                report_exit_handlers=frozenset(report_exit_handlers),
                report_exit_owned_blocks=frozenset(report_exit_owned_blocks),
                terminal_source_owned_blocks=frozenset(terminal_source_owned_blocks),
                terminal_protected_blocks=frozenset(terminal_protected_blocks),
                blocked_sources=frozenset(blocked_sources),
                bst_node_blocks=frozenset(bst_node_blocks),
                dispatcher_region=frozenset(dispatcher_region),
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
                is_semantic_handoff_redirect=is_semantic_handoff_redirect,
            ),
            state=DagRedirectMutableState(
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_1way=claimed_1way,
                claimed_2way=claimed_2way,
            ),
        )
        return log_dag_redirect_fallback_outcome(
            logger,
            mba=mba,
            edge=edge,
            result=result,
        )

    # ------------------------------------------------------------------
    # Resolved state machine DOT graph
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # EXIT state resolution via handler_state_map
    # ------------------------------------------------------------------

    @staticmethod
    def _disconnect_bst_comparison_nodes(
        bst_node_blocks: set[int],
        dispatcher_serial: int,
        builder: ModificationBuilder,
        modifications: list,
        emitted: set[tuple[int, int]],
        *,
        mba: object | None = None,
    ) -> int:
        """Convert 2-way blocks with dispatcher back-edges to 1-way.

        After linearization, handler exits have been redirected to their
        target handler entries and state variable writes have been NOP'd.
        However, some 2-way blocks (BST comparison nodes or handler
        conditionals) may still have the dispatcher as one successor.
        These back-edges create ``while`` loops in the decompiled output.

        Emits :class:`ConvertToGoto` keeping the non-dispatcher successor.

        Args:
            bst_node_blocks: Set of BST comparison block serials.
            dispatcher_serial: Serial of the dispatcher entry block.
            builder: Modification builder for emitting graph edits.
            modifications: List to append new modifications to.
            emitted: Set of ``(from, to)`` pairs for dedup.

        Returns:
            Number of blocks disconnected from the dispatcher.
        """
        result = execute_dispatcher_backedge_disconnects(
            block_nsucc_map=builder.block_nsucc_map,
            block_succ_map=builder.block_succ_map,
            dispatcher_serial=int(dispatcher_serial),
            bst_node_blocks={int(block) for block in bst_node_blocks},
            emitted=emitted,
            convert_to_goto=builder.convert_to_goto,
            modifications=modifications,
        )
        for plan in result.plans:
            logger.info(
                "BST_DISCONNECT: %s (%s) 2-way -> 1-way goto "
                "%s (removed dispatcher back-edge to %s)",
                blk_label(mba, int(plan.source_block))
                if mba
                else f"blk[{int(plan.source_block)}]",
                "BST" if plan.is_bst else "handler",
                blk_label(mba, int(plan.keep_target))
                if mba
                else f"blk[{int(plan.keep_target)}]",
                blk_label(mba, dispatcher_serial) if mba else f"blk[{dispatcher_serial}]",
            )
        return result.count
