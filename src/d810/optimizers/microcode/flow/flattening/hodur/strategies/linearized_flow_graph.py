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
from d810.cfg.dispatcher_backedge_disconnect_planning import (
    plan_dispatcher_backedge_disconnects,
)
from d810.cfg.exit_transition_planning import (
    ExitRedirectAttempt,
    plan_exit_redirects,
)
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.linearized_flow_graph_fragment_planning import (
    LinearizedDagPlannableEdge,
    LinearizedDagRoundSummary,
    LinearizedFlowGraphPlanningCallbacks,
    LinearizedFlowGraphPlanningContext,
    execute_linearized_flow_graph_planning,
)
from d810.cfg.lowering_selector import (
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.residual_dispatcher_handoff_execution import (
    ResidualDispatcherHandoffExecutionContext,
    ResidualDispatcherHandoffMutableState,
    execute_residual_dispatcher_handoffs,
)
from d810.cfg.residual_dispatcher_source_planning import (
    ResidualDispatcherSourcePlanKind,
)
from d810.cfg.residual_handoff_modification_planning import (
    apply_residual_branch_anchor_emission_plan,
    plan_residual_branch_anchor_emission,
)
from d810.cfg.path_tail_redirect_execution import (
    PathTailRedirectExecutionContext,
    PathTailRedirectMutableState,
    execute_path_tail_redirect,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.projected_alias_normalization_planning import (
    apply_projected_alias_normalization_actions,
    collect_projected_alias_normalization_actions,
)
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur._residual_handoff_bridge import (
    _resolve_state_via_valranges,
    is_semantic_handoff_redirect,
    resolve_effective_target_entry,
    resolve_singleton_state_write_value,
    resolve_synthesized_handoff_target,
)
from d810.recon.flow.bst_analysis import _forward_eval_insn, analyze_bst_dispatcher
from d810.recon.flow.graph_reachability import (
    collect_dispatcher_predecessors,
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
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
    block_has_state_var_write,
    collect_residual_source_handoff_facts,
    dispatcher_exact_state_target,
    dispatcher_has_exact_state_row,
    has_live_exact_residual_handoff,
    is_raw_state_label,
    iter_residual_prefix_handoffs,
    resolve_assignment_map_handoff_target,
    resolve_contextual_dag_entry_for_state,
    resolve_cover_fallback_entry_for_state,
    resolve_dag_entry_for_state,
    resolve_evaluated_handoff_state_via_pred,
    resolve_immediate_handoff_target,
    resolve_loopback_alias_fallback_entry,
    resolve_nonexact_dispatch_target,
    resolve_nonlocal_state_entry,
    resolve_normalized_alias_entry_for_state,
    resolve_owner_family_fallback_entry,
    resolve_owner_semantic_entry_for_blocks,
    resolve_projected_snapshot_handoff_target,
    resolve_projected_path_tail_target,
    resolve_path_lead_entry_from_node,
    resolve_redirect_safe_entry_from_node,
    resolve_redirect_safe_target_entry,
    state_has_semantic_support,
)
from d810.recon.flow.shared_suffix_discovery import (
    can_rewrite_shared_suffix_family_fallback,
    has_prior_branch_cut_for_state,
    is_shared_suffix_conditional_tail,
    pred_split_target_reaches_via_pred,
)
from d810.recon.flow.resolved_graph_reporting import (
    build_resolved_state_machine_dot_report,
)
from d810.recon.flow.exit_transition_discovery import (
    resolve_state_var_stkoff as discover_state_var_stkoff,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_CLEANUP,
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateNodeKind,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.state_machine_analysis import build_mba_view_from_flow_graph
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
)
from d810.recon.flow.transition_builder import TransitionResult, _get_state_var_stkoff
from d810.recon.flow.transition_builder import _convert_bst_to_result

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
        return discover_state_var_stkoff(
            detector=getattr(snapshot, "detector", None),
            state_var=getattr(sm, "state_var", None),
        )

    @staticmethod
    def _supports_projected_replanning(flow_graph: object) -> bool:
        return isinstance(flow_graph, FlowGraph)

    @staticmethod
    def _flow_graph_block_serials(flow_graph: object) -> set[int]:
        blocks = getattr(flow_graph, "blocks", None)
        if blocks is None:
            return set()
        try:
            return set(blocks.keys())
        except Exception:
            return set()

    @classmethod
    def _resolve_singleton_state_write_value(
        cls,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
    ) -> int | None:
        return resolve_singleton_state_write_value(
            mba,
            block_serial,
            state_var_stkoff=state_var_stkoff,
        )

    @classmethod
    def _collect_dead_dispatcher_root_cleanup_modifications(
        cls,
        projected_flow_graph: FlowGraph,
        *,
        dispatcher_serial: int,
        original_stop_serial: int | None,
        original_blocks: set[int],
    ) -> list[RedirectGoto]:
        if not projected_flow_graph.blocks:
            return []
        if dispatcher_serial < 0 or original_stop_serial is None:
            return []
        stop_serial = int(original_stop_serial)
        entry_serial = getattr(projected_flow_graph, "entry_serial", None)
        reachable_blocks = compute_reachable_blocks(
            projected_flow_graph,
            start_serial=entry_serial,
        )
        filtered: list[RedirectGoto] = []
        for block_serial in sorted(projected_flow_graph.blocks.keys()):
            if block_serial not in original_blocks:
                continue
            if block_serial in {dispatcher_serial, stop_serial}:
                continue
            if reachable_blocks is not None and block_serial in reachable_blocks:
                continue
            block = projected_flow_graph.get_block(block_serial)
            if block is None:
                continue
            if tuple(getattr(block, "preds", ())) != ():
                continue
            if getattr(block, "block_type", None) == ida_hexrays.BLT_2WAY:
                continue
            succs = tuple(getattr(block, "succs", ()))
            if len(succs) != 1:
                continue
            old_target = int(succs[0])
            if old_target == stop_serial:
                continue
            if old_target != dispatcher_serial:
                continue
            filtered.append(
                RedirectGoto(
                    from_serial=int(block_serial),
                    old_target=old_target,
                    new_target=stop_serial,
                )
            )
        filtered.sort(key=lambda mod: mod.from_serial)
        return filtered

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
        source_anchor = edge.source_anchor
        branch_source = source_anchor.block_serial
        branch_block = projected_flow_graph.get_block(branch_source)
        if branch_block is None:
            return False
        branch_succs = tuple(int(succ) for succ in tuple(getattr(branch_block, "succs", ())))
        old_target = resolve_redirect_old_target(
            branch_source,
            source_succs=tuple(builder.block_succ_map.get(branch_source, ())),
            ordered_path=tuple(int(node) for node in edge.ordered_path),
            target_entry_anchor=(
                int(edge.target_entry_anchor)
                if edge.target_entry_anchor is not None
                else None
            ),
            source_branch_arm=(
                int(edge.source_anchor.branch_arm)
                if edge.source_anchor.branch_arm is not None
                else None
            ),
            source_is_conditional_branch=(
                edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
            ),
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=ignored_blocks,
        )
        decision = plan_residual_branch_anchor_emission(
            is_conditional_branch_source=(
                source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
            ),
            branch_source=int(branch_source),
            source_block=int(source_block),
            via_pred=int(via_pred),
            prefix_target=int(prefix_target),
            branch_succs=branch_succs,
            old_target=int(old_target),
            ordered_path=tuple(int(node) for node in edge.ordered_path),
            dispatcher_serial=int(dispatcher_serial),
            bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
            target_reaches_branch=target_reaches_source_ignoring_blocks(
                projected_flow_graph,
                target_entry=prefix_target,
                source_block=branch_source,
                ignored_blocks=(residual_ignored_blocks | {source_block, via_pred}),
            ),
            claimed_branch_target=claimed_2way.get((branch_source, old_target)),
            owned_transition=(
                (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                if edge.source_key.state_const is not None and edge.target_state is not None
                else None
            ),
            edge_kind_name=edge.kind.name.lower(),
        )
        if not decision.accepted:
            return False
        if decision.already_claimed:
            return True
        apply_residual_branch_anchor_emission_plan(
            decision,
            modifications=modifications,
            claimed_2way=claimed_2way,
            emitted=emitted,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
        )
        logger.info(
            "LFG DAG: residual branch handoff %s -> %s (bypassing %s -> %s via %s)",
            blk_label(mba, int(decision.branch_source)),
            blk_label(mba, int(decision.prefix_target)),
            blk_label(mba, int(decision.via_pred)),
            blk_label(mba, source_block),
            decision.edge_kind_name,
        )
        return True

    @staticmethod
    def _is_original_pre_header_candidate(
        flow_graph: object | None,
        *,
        pre_header_serial: int | None,
        entry_serial: int | None,
    ) -> bool:
        """Return whether ``pre_header_serial`` still belongs to the entry corridor.

        Later projected CFGs can leave arbitrary predecessorless blocks behind.
        Those are not real function pre-headers and must not be rewired to the
        initial state family.
        """
        if flow_graph is None or pre_header_serial is None or entry_serial is None:
            return False
        if pre_header_serial == entry_serial:
            return True
        try:
            entry_block = flow_graph.get_block(entry_serial)
        except Exception:
            return False
        if entry_block is None:
            return False
        succs = tuple(getattr(entry_block, "succs", ()))
        return len(succs) == 1 and succs[0] == pre_header_serial

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
        mba = snapshot.mba
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if mba is None or flow_graph is None or bst_result is None:
            return False
        func_ea = mba.entry_ea
        maturity = mba.maturity
        key = (func_ea, maturity)
        residual_preds = cls._collect_residual_dispatcher_predecessors(
            flow_graph,
            snapshot.bst_dispatcher_serial,
            bst_node_blocks=set(
                getattr(bst_result, "bst_node_blocks", ()) or ()
            ),
            reachable_from_serial=getattr(flow_graph, "entry_serial", None),
        )
        raw_residual_preds = collect_dispatcher_predecessors(
            flow_graph,
            snapshot.bst_dispatcher_serial,
            bst_node_blocks=set(
                getattr(bst_result, "bst_node_blocks", ()) or ()
            ),
        )
        effective_residual_preds = raw_residual_preds or residual_preds
        if not effective_residual_preds:
            logger.info(
                "LFG: already applied for func 0x%X at maturity %d",
                func_ea, maturity,
            )
            return False
        previous_residual_count = (
            cls._last_successful_residual_dispatcher_pred_counts.get(key)
        )
        if (
            previous_residual_count is not None
            and len(effective_residual_preds) >= previous_residual_count
        ):
            if (
                key not in cls._same_count_exact_rerun_used
                and cls._has_live_exact_residual_handoff(
                    snapshot,
                    effective_residual_preds,
                )
            ):
                if consume_retry:
                    cls._same_count_exact_rerun_used.add(key)
                logger.info(
                    "LFG: allowing one same-count rerun for func 0x%X at maturity %d because live residual exact handoffs remain: %s",
                    func_ea,
                    maturity,
                    effective_residual_preds,
                )
                return True
            if (
                key not in cls._same_count_exact_rerun_used
                and len(effective_residual_preds) == previous_residual_count
                and effective_residual_preds
            ):
                if consume_retry:
                    cls._same_count_exact_rerun_used.add(key)
                logger.info(
                    "LFG: allowing one exploratory same-count rerun for func 0x%X at maturity %d because residual dispatcher preds remain: %s",
                    func_ea,
                    maturity,
                    effective_residual_preds,
                )
                return True
            logger.info(
                "LFG: suppressing same-maturity rerun for func 0x%X at maturity %d "
                "because residual dispatcher preds did not improve (%d -> %d)",
                func_ea,
                maturity,
                previous_residual_count,
                len(effective_residual_preds),
            )
            return False
        cls._same_count_exact_rerun_used.discard(key)
        logger.info(
            "LFG: allowing same-maturity rerun for func 0x%X with residual dispatcher preds %s",
            func_ea,
            effective_residual_preds,
        )
        return True

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
        mba = snapshot.mba
        bst_result = snapshot.bst_result
        sm = snapshot.state_machine
        if mba is None or bst_result is None or sm is None:
            return False
        state_var_stkoff = cls._resolve_state_var_stkoff(snapshot, sm)
        dispatcher = getattr(bst_result, "dispatcher", None)
        return has_live_exact_residual_handoff(
            mba,
            residual_preds,
            state_var_stkoff=state_var_stkoff,
            dispatcher=dispatcher,
            resolve_state_via_valranges=_resolve_state_via_valranges(),
        )

    @classmethod
    def _build_dag_round_summary(
        cls,
        *,
        snapshot: AnalysisSnapshot,
        state_machine: DispatcherStateMachine,
        bst_result: object,
        transition_result: TransitionResult,
        current_flow_graph: object,
        dag_round_mba: object | None,
        dispatcher_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        bst_node_blocks: frozenset[int],
    ) -> LinearizedDagRoundSummary:
        resolved_summary = build_linearized_dag_round_summary(
            current_flow_graph=current_flow_graph,
            transition_result=transition_result,
            dispatcher_serial=dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=pre_header_serial,
            initial_state=state_machine.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(sorted(bst_node_blocks)),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=dag_round_mba,
            handlers=state_machine.handlers,
            build_live_dag=build_live_linearized_state_dag_from_graph,
            build_transition_report=build_dispatcher_transition_report_from_graph,
            select_plannable_edges=select_plannable_dag_edges,
        )
        plannable_edges = tuple(
            LinearizedDagPlannableEdge(
                edge=entry.edge,
                source_anchor_block=int(entry.source_anchor_block),
                ordered_path=tuple(int(node) for node in entry.ordered_path),
                target_entry_anchor=(
                    int(entry.target_entry_anchor)
                    if entry.target_entry_anchor is not None
                    else None
                ),
                is_conditional_transition=bool(entry.is_conditional_transition),
                requires_safe_target_resolution=bool(
                    entry.requires_safe_target_resolution
                ),
            )
            for entry in resolved_summary.plannable_edges
        )
        return LinearizedDagRoundSummary(
            dag=resolved_summary.dag,
            plannable_edges=plannable_edges,
            report_exit_handlers=frozenset(
                int(handler) for handler in resolved_summary.report_exit_handlers
            ),
            report_exit_owned_blocks=frozenset(
                int(block) for block in resolved_summary.report_exit_owned_blocks
            ),
            terminal_source_keys=frozenset(resolved_summary.terminal_source_keys),
            terminal_source_handlers=frozenset(
                int(handler) for handler in resolved_summary.terminal_source_handlers
            ),
            terminal_source_owned_blocks=frozenset(
                int(block) for block in resolved_summary.terminal_source_owned_blocks
            ),
            terminal_protected_blocks=frozenset(
                int(block) for block in resolved_summary.terminal_protected_blocks
            ),
            terminal_skipped=int(resolved_summary.terminal_skipped),
            unknown_skipped=int(resolved_summary.unknown_skipped),
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

        # DAG-driven semantic planner. Rebuild against a projected CFG within
        # this stage so later corridor edges exposed by earlier redirects can
        # still be emitted into the same fragment.
        dag_bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )
        dag_builder = ModificationBuilder.from_snapshot(snapshot)
        dag_state_var_stkoff = self._resolve_state_var_stkoff(snapshot, sm)
        dag_dispatcher = getattr(bst_result, "dispatcher", None)
        dag_blocked_sources: set[int] = {
            int(serial) for serial in getattr(snapshot, "lfg_redirected_blocks", ()) or ()
        }
        dag_dispatcher_region: set[int] = set(dag_bst_node_blocks)
        dag_original_blocks = self._flow_graph_block_serials(flow_graph)

        dag_transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        raw_dag_pre_header = (
            None if same_maturity_rerun else getattr(bst_result, "pre_header_serial", None)
        )
        entry_serial = getattr(getattr(snapshot, "reachability", None), "entry_serial", None)
        dag_pre_header = (
            raw_dag_pre_header
            if self._is_original_pre_header_candidate(
                flow_graph,
                pre_header_serial=raw_dag_pre_header,
                entry_serial=entry_serial,
            )
            else None
        )
        if raw_dag_pre_header is not None and dag_pre_header is None:
            logger.info(
                "LFG DAG: suppressing non-entry pre-header candidate %s (entry=%s)",
                blk_label(mba, raw_dag_pre_header),
                blk_label(mba, entry_serial) if entry_serial is not None else "<none>",
            )
        dag_projectable = self._supports_projected_replanning(flow_graph)
        # Keep projection for post-plan safety checks. A same-maturity rerun is
        # intentionally narrower: only residual dispatcher feeders should be
        # reconsidered. Replaying full semantic-edge planning against an
        # already-mutated CFG is what produced the pass-2 no-op/self-corridor
        # rewrites in the live sample.
        dag_round_limit = 1 if same_maturity_rerun else 2
        dag_result = execute_linearized_flow_graph_planning(
            LinearizedFlowGraphPlanningContext(
                flow_graph=flow_graph,
                builder=dag_builder,
                mba=mba,
                state_machine=sm,
                dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                bst_node_blocks=frozenset(int(block) for block in dag_bst_node_blocks),
                dispatcher_region=frozenset(int(block) for block in dag_dispatcher_region),
                state_var_stkoff=dag_state_var_stkoff,
                dispatcher_lookup=(
                    dag_dispatcher.lookup if dag_dispatcher is not None else None
                ),
                dispatcher=dag_dispatcher,
                pre_header_serial=dag_pre_header,
                original_blocks=frozenset(int(block) for block in dag_original_blocks),
                same_maturity_rerun=bool(same_maturity_rerun),
                projectable=bool(dag_projectable),
                round_limit=int(dag_round_limit),
                initial_state=(
                    int(sm.initial_state) if sm.initial_state is not None else None
                ),
                blocked_sources=frozenset(
                    int(serial) for serial in dag_blocked_sources
                ),
            ),
            callbacks=LinearizedFlowGraphPlanningCallbacks(
                build_round_summary=lambda current_flow_graph, dag_round_mba: self._build_dag_round_summary(
                    snapshot=snapshot,
                    state_machine=sm,
                    bst_result=bst_result,
                    transition_result=dag_transition_result,
                    current_flow_graph=current_flow_graph,
                    dag_round_mba=dag_round_mba,
                    dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                    state_var_stkoff=dag_state_var_stkoff,
                    pre_header_serial=dag_pre_header,
                    bst_node_blocks=frozenset(int(block) for block in dag_bst_node_blocks),
                ),
                build_projected_mba=build_mba_view_from_flow_graph,
                project_flow_graph=lambda base_flow_graph, modifications: project_post_state(
                    base_flow_graph,
                    compile_patch_plan(modifications, base_flow_graph),
                ),
                resolve_redirect_safe_target_entry=lambda dag, edge, bst_node_blocks: self._resolve_redirect_safe_target_entry(
                    dag,
                    edge,
                    bst_node_blocks=set(int(block) for block in bst_node_blocks),
                ),
                resolve_initial_entry=lambda dag, initial_state, bst_node_blocks: resolve_dag_entry_for_state(
                    dag,
                    initial_state,
                    bst_node_blocks=set(int(block) for block in bst_node_blocks),
                ),
                emit_dag_redirect=lambda *,
                    edge,
                    dag,
                    flow_graph,
                    state,
                    report_exit_handlers,
                    report_exit_owned_blocks,
                    terminal_source_keys,
                    terminal_source_handlers,
                    terminal_source_owned_blocks,
                    terminal_protected_blocks: self._emit_dag_redirect(
                        edge=edge,
                        dag=dag,
                        builder=dag_builder,
                        modifications=state.modifications,
                        owned_blocks=state.owned_blocks,
                        owned_edges=state.owned_edges,
                        owned_transitions=state.owned_transitions,
                        emitted=state.emitted,
                        claimed_1way=state.claimed_1way,
                        claimed_2way=state.claimed_2way,
                        claimed_exits=state.claimed_exits,
                        claimed_path_edges=state.claimed_path_edges,
                        blocked_sources=state.blocked_sources,
                        terminal_source_keys=set(terminal_source_keys),
                        terminal_source_handlers=set(terminal_source_handlers),
                        terminal_source_owned_blocks=set(terminal_source_owned_blocks),
                        terminal_protected_blocks=set(terminal_protected_blocks),
                        report_exit_handlers=set(report_exit_handlers),
                        report_exit_owned_blocks=set(report_exit_owned_blocks),
                        bst_node_blocks=set(int(block) for block in dag_bst_node_blocks),
                        dispatcher_region=set(int(block) for block in dag_dispatcher_region),
                        flow_graph=flow_graph,
                        state_var_stkoff=dag_state_var_stkoff,
                        dispatcher_lookup=(
                            dag_dispatcher.lookup if dag_dispatcher is not None else None
                        ),
                        dispatcher=dag_dispatcher,
                        mba=mba,
                    ),
                collect_residual_dispatcher_predecessors=lambda current_flow_graph, dispatcher_serial, bst_node_blocks, reachable_from_serial: self._collect_residual_dispatcher_predecessors(
                    current_flow_graph,
                    dispatcher_serial,
                    bst_node_blocks=set(int(block) for block in bst_node_blocks),
                    reachable_from_serial=reachable_from_serial,
                ),
                emit_residual_dispatcher_handoffs=lambda *,
                    dag,
                    projected_flow_graph,
                    state,
                    redirected_blocks: self._emit_residual_dispatcher_handoffs(
                        dag=dag,
                        state_machine=sm,
                        projected_flow_graph=projected_flow_graph,
                        dispatcher_serial=int(snapshot.bst_dispatcher_serial),
                        bst_node_blocks=set(int(block) for block in dag_bst_node_blocks),
                        builder=dag_builder,
                        modifications=state.modifications,
                        owned_blocks=state.owned_blocks,
                        owned_edges=state.owned_edges,
                        owned_transitions=state.owned_transitions,
                        emitted=state.emitted,
                        claimed_1way=state.claimed_1way,
                        claimed_2way=state.claimed_2way,
                        state_var_stkoff=dag_state_var_stkoff,
                        dispatcher_lookup=(
                            dag_dispatcher.lookup if dag_dispatcher is not None else None
                        ),
                        dispatcher=dag_dispatcher,
                        mba=mba,
                        redirected_blocks=redirected_blocks,
                    ),
                disconnect_bst_comparison_nodes=lambda bst_node_blocks, dispatcher_serial, state: self._disconnect_bst_comparison_nodes(
                    set(int(block) for block in bst_node_blocks),
                    dispatcher_serial,
                    dag_builder,
                    state.modifications,
                    state.emitted,
                    mba=mba,
                ),
            ),
        )

        if not dag_result.accepted:
            logger.info("LFG: DAG produced no redirect modifications")
            return None

        if dag_result.unresolved_bst_targets:
            logger.info(
                "LFG DAG: preserving BST cleanup because %d targets still resolve only inside BST region",
                dag_result.unresolved_bst_targets,
            )
        if dag_result.cleanup_gate_reason == "residual_dispatcher_predecessors":
            logger.info(
                "LFG DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
                [blk_label(mba, serial) for serial in dag_result.residual_dispatcher_preds],
            )

        logger.info(
            "LFG DAG: emitted %d redirects (%d unconditional, %d conditional); "
            "%d terminal edges ignored, %d unknown edges ignored, %d skipped conflicts; "
            "%d BST disconnects",
            dag_result.transition_count + dag_result.conditional_count,
            dag_result.transition_count,
            dag_result.conditional_count,
            dag_result.terminal_skipped,
            dag_result.unknown_skipped,
            dag_result.skipped_count,
            dag_result.disconnect_count,
        )

        dag_ownership = OwnershipScope(
            blocks=dag_result.owned_blocks,
            edges=dag_result.owned_edges,
            transitions=dag_result.owned_transitions,
        )
        dag_benefit = BenefitMetrics(
            handlers_resolved=len(sm.handlers),
            transitions_resolved=dag_result.transition_count + dag_result.conditional_count,
            blocks_freed=len(dag_bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=list(dag_result.modifications),
            ownership=dag_ownership,
            prerequisites=self.prerequisites,
            expected_benefit=dag_benefit,
            risk_score=0.1,
            metadata={
                "handlers_visited": len(sm.handlers),
                "resolved_count": dag_result.transition_count + dag_result.conditional_count,
                "dag_transition_count": dag_result.transition_count,
                "dag_conditional_count": dag_result.conditional_count,
                "dag_terminal_skipped": dag_result.terminal_skipped,
                "dag_unknown_skipped": dag_result.unknown_skipped,
                "skipped_count": dag_result.skipped_count,
                "disconnect_count": dag_result.disconnect_count,
                "allow_post_apply_bst_cleanup": dag_result.cleanup_gate_reason is None,
                "post_apply_bst_cleanup_reason": dag_result.cleanup_gate_reason,
                "residual_dispatcher_preds": dag_result.residual_dispatcher_preds,
                "residual_dispatcher_redirect_count": dag_result.residual_dispatcher_redirect_count,
                "residual_dispatcher_normalized_count": dag_result.residual_dispatcher_normalized_count,
                "dead_island_cleanup_count": dag_result.dead_island_cleanup_count,
                "unresolved_bst_targets": dag_result.unresolved_bst_targets,
                "bst_convert_count": 0,
                "goto_nop_count": 0,
                "goto_skip_count": 0,
                "nop_state_values": {},
                "safeguard_min_required": 1,
            },
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
        residual_preds = cls._collect_residual_dispatcher_predecessors(
            projected_flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
            reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
        )
        residual_mba_view = build_mba_view_from_flow_graph(projected_flow_graph)
        analysis_mba = residual_mba_view if residual_mba_view is not None else mba
        result = execute_residual_dispatcher_handoffs(
            ResidualDispatcherHandoffExecutionContext(
                dag=dag,
                state_machine=state_machine,
                projected_flow_graph=projected_flow_graph,
                dispatcher_serial=int(dispatcher_serial),
                bst_node_blocks=frozenset(int(block) for block in bst_node_blocks),
                residual_preds=tuple(int(pred) for pred in residual_preds),
                block_succ_map={
                    int(block): tuple(int(succ) for succ in succs)
                    for block, succs in builder.block_succ_map.items()
                },
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                analysis_mba=analysis_mba,
                live_mba=(mba if mba is not None else None),
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

        for outcome in result.outcomes:
            source_block = int(outcome.source_block)
            source_plan = outcome.source_plan
            if not source_plan.accepted:
                if source_plan.rejection_reason == "shared_suffix_conditional_tail":
                    logger.info(
                        "LFG DAG: residual handoff %s -> %s suppressed because %s is a shared-suffix tail of an earlier conditional corridor",
                        blk_label(mba, source_block),
                        blk_label(mba, int(source_plan.target_entry)),
                        blk_label(mba, source_block),
                    )
                elif source_plan.rejection_reason == "prior_branch_cut":
                    logger.info(
                        "LFG DAG: residual handoff %s -> %s suppressed because an earlier conditional corridor already owns state 0x%X",
                        blk_label(mba, source_block),
                        blk_label(mba, int(source_plan.target_entry)),
                        int(source_plan.state_value),
                    )
                elif source_plan.rejection_reason == "cycle_risk":
                    logger.info(
                        "LFG DAG: residual handoff %s -> %s still forms a non-dispatcher cycle, skipping",
                        blk_label(mba, source_block),
                        blk_label(mba, int(source_plan.target_entry)),
                    )
                elif source_plan.rejection_reason == "live_oneway_noop":
                    logger.info(
                        "LFG DAG: residual handoff %s already targets %s, skipping live no-op",
                        blk_label(mba, source_block),
                        blk_label(mba, int(source_plan.target_entry)),
                    )
                continue

            if source_plan.kind == ResidualDispatcherSourcePlanKind.PRED_SPLIT:
                for selection in source_plan.pred_splits:
                    logger.info(
                        "LFG DAG: residual dispatcher pred-split %s via %s -> %s (state 0x%X)",
                        blk_label(mba, source_block),
                        blk_label(mba, int(selection.via_pred)),
                        blk_label(mba, int(selection.target_entry)),
                        int(selection.state_value),
                    )
            elif source_plan.kind == ResidualDispatcherSourcePlanKind.GOTO:
                logger.info(
                    "LFG DAG: residual dispatcher handoff %s -> %s (state 0x%X)",
                    blk_label(mba, source_block),
                    blk_label(mba, int(source_plan.target_entry)),
                    int(source_plan.state_value),
                )
            elif source_plan.kind == ResidualDispatcherSourcePlanKind.PREFIX_PEEL:
                logger.info(
                    "LFG DAG: residual prefix handoff %s -> %s (bypassing %s via %s)",
                    blk_label(mba, int(source_plan.via_pred)),
                    blk_label(mba, int(source_plan.prefix_target)),
                    blk_label(mba, source_block),
                    source_plan.edge_kind_name,
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
        if not result.accepted:
            source_block = result.source_block
            target_entry = result.target_entry
            if (
                result.rejection_reason == "foreign_exact_entry_owner"
                and result.foreign_exact_owner_label is not None
                and source_block is not None
                and target_entry is not None
            ):
                logger.info(
                    "LFG DAG: skipping %s -> %s because %s is the exact entry for %s, not source corridor %s",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                    blk_label(mba, source_block),
                    result.foreign_exact_owner_label,
                    result.source_state_const
                    if result.source_state_const is not None
                    else edge.source_key.handler_serial,
                )
            elif (
                result.rejection_reason == "backward_same_corridor"
                and source_block is not None
                and target_entry is not None
            ):
                logger.info(
                    "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif (
                result.rejection_reason == "target_reaches_source"
                and source_block is not None
                and target_entry is not None
            ):
                logger.info(
                    "LFG DAG: skipping %s -> %s because target already reaches source",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif (
                result.rejection_reason == "shared_handoff_conflict"
                and result.shared_handoff is not None
                and source_block is not None
                and target_entry is not None
            ):
                logger.info(
                    "LFG DAG: skipping %s -> %s because %s already proves concrete shared handoff %s for state 0x%X",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                    blk_label(mba, source_block),
                    blk_label(mba, result.shared_handoff[1]),
                    result.shared_handoff[0],
                )
            return False

        assert result.kind is not None
        assert result.source_block is not None
        assert result.target_entry is not None
        source_block = result.source_block
        target_entry = result.target_entry
        via_pred = result.via_pred
        if result.kind == "shared_goto":
            logger.info(
                "LFG DAG: shared tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
        elif result.kind == "direct_goto":
            logger.info(
                "LFG DAG: path-tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
        elif result.kind == "pred_split":
            assert via_pred is not None
            logger.info(
                "LFG DAG: path-tail pred-split %s via %s -> %s",
                blk_label(mba, source_block),
                blk_label(mba, via_pred),
                blk_label(mba, target_entry),
            )
        elif result.kind == "duplicate":
            assert via_pred is not None
            logger.info(
                "LFG DAG: path-tail duplicate %s via %s -> %s",
                blk_label(mba, source_block),
                blk_label(mba, via_pred),
                blk_label(mba, target_entry),
            )
        return True

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
        target_node = build_dag_node_maps(dag).node_by_key.get(edge.target_key) if edge.target_key is not None else None
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
        assert result.source_block is not None
        assert result.target_entry is not None
        source_block = result.source_block
        target_entry = result.target_entry
        if result.allowed_semantic_handoff_backreach:
            logger.info(
                "LFG DAG: allowing semantic handoff %s -> %s despite existing backreach",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )
        if not result.accepted:
            if result.rejection_reason == "backward_same_corridor":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif result.rejection_reason == "target_reaches_source":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target already reaches source",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif result.rejection_reason == "live_oneway_noop":
                logger.info(
                    "LFG DAG: skipping %s -> %s because live CFG already has that 1-way handoff",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif result.rejection_reason == "branch_conflict":
                assert result.old_target is not None
                assert result.existing_target is not None
                logger.info(
                    "LFG DAG: conflict on 2-way %s old=%s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, result.old_target),
                    blk_label(mba, result.existing_target),
                    blk_label(mba, target_entry),
                )
            elif result.rejection_reason == "oneway_conflict":
                assert result.existing_target is not None
                logger.info(
                    "LFG DAG: conflict on 1-way %s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, result.existing_target),
                    blk_label(mba, target_entry),
                )
            return False
        logger.info(
            "LFG DAG: resolved %s -> %s via %s (%s)",
            blk_label(mba, source_block),
            blk_label(mba, target_entry),
            edge.kind.name.lower(),
            edge.source_anchor.kind.name.lower(),
        )
        return True

    # ------------------------------------------------------------------
    # Resolved state machine DOT graph
    # ------------------------------------------------------------------

    @staticmethod
    def _emit_resolved_graph_dot(
        sm: DispatcherStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        emitted: set[tuple[int, int]],
        skipped_count: int,
    ) -> None:
        """Emit a DOT graph showing the RESOLVED transition graph.

        This shows the forward-evaluated transitions with self-loops resolved
        to real next states, unlike the raw state machine graph which shows
        OLLVM MBA self-loops.

        Args:
            sm: The Hodur state machine with handlers and transitions.
            bst_result: BST analysis result with handler_state_map.
            handler_state_map: Mapping of handler serial -> state value.
            emitted: Set of (from_block, to_block) pairs that were successfully
                redirected.
            skipped_count: Number of transitions that could not be resolved.
        """
        if not logger.info_on:
            return

        report = build_resolved_state_machine_dot_report(
            sm,
            bst_result,
            handler_state_map,
        )

        logger.info(
            "LFG resolved graph: %d nodes, %d edges, %d resolved, "
            "%d unresolved, %d exits, %d conditional",
            report.node_count,
            report.edge_count,
            report.resolved_count,
            report.unresolved_count,
            report.exit_count,
            report.conditional_count,
        )

        # Emit DOT graph
        logger.info("LFG_RESOLVED_GRAPH_DOT_START")
        for line in report.dot_lines:
            logger.info(line)
        logger.info("LFG_RESOLVED_GRAPH_DOT_END")

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
        plans = plan_dispatcher_backedge_disconnects(
            block_nsucc_map=builder.block_nsucc_map,
            block_succ_map=builder.block_succ_map,
            dispatcher_serial=int(dispatcher_serial),
            bst_node_blocks={int(block) for block in bst_node_blocks},
            emitted=emitted,
        )

        for plan in plans:
            emitted.add((int(plan.source_block), int(plan.keep_target)))
            modifications.append(
                builder.convert_to_goto(int(plan.source_block), int(plan.keep_target))
            )
            logger.info(
                "BST_DISCONNECT: %s (%s) 2-way -> 1-way goto "
                "%s (removed dispatcher back-edge to %s)",
                blk_label(mba, int(plan.source_block)) if mba else f"blk[{int(plan.source_block)}]",
                "BST" if plan.is_bst else "handler",
                blk_label(mba, int(plan.keep_target)) if mba else f"blk[{int(plan.keep_target)}]",
                blk_label(mba, dispatcher_serial) if mba else f"blk[{dispatcher_serial}]",
            )

        return len(plans)
