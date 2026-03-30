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
from d810.cfg.graph_modification import (
    RedirectGoto,
)
from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedDagPlannableEdge,
    LinearizedDagRoundSummary,
    LinearizedFlowGraphPlanningContext,
    execute_linearized_flow_graph_planning,
)
from d810.cfg.plan import compile_patch_plan
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
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
    FAMILY_DIRECT,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_planning import (
    build_linearized_dag_round_summary_adapter,
    build_linearized_flow_graph_planning_callbacks,
    execute_linearized_flow_graph_strategy_plan,
    prepare_linearized_flow_graph_plan_setup,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_redirects import (
    emit_dag_redirect as execute_lfg_dag_redirect,
    emit_path_tail_redirect as execute_lfg_path_tail_redirect,
)
from d810.optimizers.microcode.flow.flattening.hodur._linearized_flow_graph_residuals import (
    disconnect_bst_comparison_nodes as execute_lfg_bst_disconnects,
    emit_residual_branch_anchor_handoff as execute_lfg_residual_branch_anchor_handoff,
    emit_residual_dispatcher_handoffs as execute_lfg_residual_dispatcher_handoffs,
    normalize_projected_alias_handoffs as execute_lfg_alias_normalization,
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
        return execute_lfg_residual_branch_anchor_handoff(
            logger,
            edge=edge,
            source_block=source_block,
            via_pred=via_pred,
            prefix_target=prefix_target,
            projected_flow_graph=projected_flow_graph,
            bst_node_blocks=bst_node_blocks,
            dispatcher_serial=dispatcher_serial,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_2way=claimed_2way,
            ignored_blocks=ignored_blocks,
            residual_ignored_blocks=residual_ignored_blocks,
            mba=mba,
        )

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

        return execute_linearized_flow_graph_strategy_plan(
            snapshot=snapshot,
            state_machine=sm,
            bst_result=bst_result,
            flow_graph=flow_graph,
            mba=mba,
            logger=logger,
            same_maturity_rerun=bool(same_maturity_rerun),
            strategy_name=self.name,
            family=self.family,
            prerequisites=self.prerequisites,
            build_modification_builder=ModificationBuilder.from_snapshot,
            resolve_state_var_stkoff=self._resolve_state_var_stkoff,
            supports_projected_replanning=self._supports_projected_replanning,
            flow_graph_block_serials=self._flow_graph_block_serials,
            is_original_pre_header_candidate=self._is_original_pre_header_candidate,
            transition_result_cls=TransitionResult,
            round_summary_adapter=build_linearized_dag_round_summary_adapter,
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
        return execute_lfg_residual_dispatcher_handoffs(
            logger,
            dag=dag,
            state_machine=state_machine,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
            redirected_blocks=redirected_blocks,
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
        )

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
        return execute_lfg_alias_normalization(
            logger,
            dag=dag,
            projected_flow_graph=projected_flow_graph,
            dispatcher_serial=dispatcher_serial,
            redirected_blocks=redirected_blocks,
            bst_node_blocks=bst_node_blocks,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            emitted=emitted,
            claimed_1way=claimed_1way,
            mba=mba,
            resolve_projected_path_tail_target=cls._resolve_projected_path_tail_target,
        )

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
        return execute_lfg_path_tail_redirect(
            logger,
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
            resolve_effective_target_entry=cls._resolve_effective_target_entry,
            resolve_immediate_handoff_target=cls._resolve_immediate_handoff_target,
            find_foreign_exact_entry_owner=find_foreign_exact_entry_owner,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
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
        return execute_lfg_dag_redirect(
            logger,
            edge=edge,
            dag=dag,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_2way=claimed_2way,
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
            build_dag_node_maps=build_dag_node_maps,
            resolve_effective_target_entry=cls._resolve_effective_target_entry,
            emit_path_tail_redirect=cls._emit_path_tail_redirect,
            is_semantic_handoff_redirect=is_semantic_handoff_redirect,
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
        return execute_lfg_bst_disconnects(
            logger,
            bst_node_blocks=bst_node_blocks,
            dispatcher_serial=dispatcher_serial,
            builder=builder,
            modifications=modifications,
            emitted=emitted,
            mba=mba,
        )
