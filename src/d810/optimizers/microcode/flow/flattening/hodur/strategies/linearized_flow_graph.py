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
from d810.cfg.dag_redirect_modification_planning import (
    DagRedirectFallbackContext,
    plan_dag_redirect_fallback,
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
from d810.cfg.lowering_selector import (
    is_backward_same_corridor_target,
    is_live_oneway_noop,
    is_valid_pred_split_pair,
    resolve_redirect_old_target,
    target_reaches_source_ignoring_blocks,
)
from d810.cfg.residual_dispatcher_attempt_building import (
    ResidualGotoAttemptBuildContext,
    ResidualPredSplitAttemptBuildContext,
    ResidualPrefixAttemptBuildContext,
    build_residual_goto_attempt,
    build_residual_pred_split_attempt,
    build_residual_prefix_attempt,
)
from d810.cfg.residual_dispatcher_source_planning import (
    ResidualDispatcherSourceContext,
    ResidualDispatcherSourcePlanKind,
    apply_residual_dispatcher_source_plan,
    plan_residual_dispatcher_source,
)
from d810.cfg.residual_handoff_planning import (
    ResidualGotoAttempt,
    ResidualPrefixAttempt,
    ResidualPredSplitAttempt,
)
from d810.cfg.residual_handoff_modification_planning import (
    plan_projected_alias_handoff_normalization,
    plan_residual_branch_anchor_emission,
)
from d810.cfg.path_tail_modification_planning import (
    PathTailEmissionKind,
    PathTailRedirectContext,
    apply_path_tail_emission_plan,
    plan_path_tail_redirect,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.projected_alias_normalization_planning import (
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
        assert decision.modification is not None
        modifications.append(decision.modification)
        claimed_2way[(int(decision.branch_source), int(decision.old_target))] = int(
            decision.prefix_target
        )
        emitted.add((int(decision.branch_source), int(decision.prefix_target)))
        owned_blocks.add(int(decision.branch_source))
        owned_edges.add((int(decision.branch_source), int(decision.prefix_target)))
        if decision.owned_transition is not None:
            owned_transitions.add(decision.owned_transition)
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
        dag_modifications: list = []
        dag_owned_blocks: set[int] = set()
        dag_owned_edges: set[tuple[int, int]] = set()
        dag_owned_transitions: set[tuple[int, int]] = set()
        dag_emitted: set[tuple[int, int]] = set()
        dag_claimed_1way: dict[int, int] = {}
        dag_claimed_2way: dict[tuple[int, int], int] = {}
        dag_claimed_exits: dict[int, int] = {}
        dag_claimed_path_edges: dict[tuple[int, int], int] = {}
        dag_blocked_sources: set[int] = {
            int(serial) for serial in getattr(snapshot, "lfg_redirected_blocks", ()) or ()
        }
        dag_skipped_count = 0
        dag_transition_count = 0
        dag_conditional_count = 0
        dag_terminal_skipped = 0
        dag_unknown_skipped = 0
        dag_unresolved_bst_targets = 0
        dag_dispatcher_region: set[int] = set(dag_bst_node_blocks)
        dag_original_blocks = self._flow_graph_block_serials(flow_graph)
        if dag_blocked_sources:
            logger.info(
                "LFG DAG: starting with %d externally-claimed source blocks",
                len(dag_blocked_sources),
            )

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
        dag_current_flow_graph = flow_graph
        dag_projectable = self._supports_projected_replanning(flow_graph)
        # Keep projection for post-plan safety checks. A same-maturity rerun is
        # intentionally narrower: only residual dispatcher feeders should be
        # reconsidered. Replaying full semantic-edge planning against an
        # already-mutated CFG is what produced the pass-2 no-op/self-corridor
        # rewrites in the live sample.
        dag_round_limit = 1 if same_maturity_rerun else 2
        dag_latest = None

        for dag_round_index in range(dag_round_limit):
            dag_round_mba = (
                mba
                if dag_round_index == 0 or not dag_projectable
                else build_mba_view_from_flow_graph(dag_current_flow_graph)
            )
            dag_latest = build_live_linearized_state_dag_from_graph(
                dag_current_flow_graph,
                dag_transition_result,
                dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
                state_var_stkoff=dag_state_var_stkoff,
                pre_header_serial=dag_pre_header,
                initial_state=sm.initial_state,
                handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
                bst_node_blocks=tuple(sorted(dag_bst_node_blocks)),
                diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
                dispatcher=getattr(bst_result, "dispatcher", None),
                mba=dag_round_mba,
                prefer_local_corridors=True,
            )
            dag_report = build_dispatcher_transition_report_from_graph(
                dag_current_flow_graph,
                dag_transition_result,
                dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
                state_var_stkoff=dag_state_var_stkoff,
                pre_header_serial=dag_pre_header,
                initial_state=sm.initial_state,
                handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
                bst_node_blocks=tuple(sorted(dag_bst_node_blocks)),
                diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            )
            report_exit_handlers = {
                row.handler_serial
                for row in dag_report.rows
                if row.kind == TransitionKind.EXIT
            }
            dag_nonterminal_source_handlers = {
                edge.source_key.handler_serial
                for edge in dag_latest.edges
                if edge.kind
                in (
                    SemanticEdgeKind.TRANSITION,
                    SemanticEdgeKind.CONDITIONAL_TRANSITION,
                )
            }
            report_exit_handlers -= dag_nonterminal_source_handlers
            report_exit_owned_blocks = {
                block_serial
                for handler in sm.handlers.values()
                if handler.check_block in report_exit_handlers
                for block_serial in {handler.check_block, *handler.handler_blocks}
            }
            dag_terminal_source_keys = {
                edge.source_key
                for edge in dag_latest.edges
                if edge.kind
                in (
                    SemanticEdgeKind.CONDITIONAL_RETURN,
                    SemanticEdgeKind.EXIT_ROUTINE,
                    SemanticEdgeKind.UNKNOWN,
                )
            }
            dag_terminal_source_handlers = {
                edge.source_key.handler_serial
                for edge in dag_latest.edges
                if edge.kind
                in (
                    SemanticEdgeKind.CONDITIONAL_RETURN,
                    SemanticEdgeKind.EXIT_ROUTINE,
                    SemanticEdgeKind.UNKNOWN,
                )
            }
            dag_terminal_source_owned_blocks = {
                block_serial
                for node in dag_latest.nodes
                if node.handler_serial in dag_terminal_source_handlers
                for block_serial in node.owned_blocks
            }
            dag_terminal_protected_blocks = {
                block_serial
                for edge in dag_latest.edges
                if edge.kind
                in (
                    SemanticEdgeKind.CONDITIONAL_RETURN,
                    SemanticEdgeKind.EXIT_ROUTINE,
                    SemanticEdgeKind.UNKNOWN,
                )
                for block_serial in edge.ordered_path
            }
            dag_terminal_skipped = sum(
                1
                for edge in dag_latest.edges
                if edge.kind
                in (SemanticEdgeKind.CONDITIONAL_RETURN, SemanticEdgeKind.EXIT_ROUTINE)
            )
            dag_unknown_skipped = sum(
                1
                for edge in dag_latest.edges
                if edge.kind == SemanticEdgeKind.UNKNOWN
            )

            dag_round_unresolved_bst_targets = 0
            dag_round_start = len(dag_modifications)
            if not same_maturity_rerun:
                for edge in select_plannable_dag_edges(dag_latest):
                    safe_target_entry = None
                    if edge.target_entry_anchor is not None:
                        safe_target_entry = self._resolve_redirect_safe_target_entry(
                            dag_latest,
                            edge,
                            bst_node_blocks=dag_bst_node_blocks,
                        )
                        if safe_target_entry is None:
                            dag_round_unresolved_bst_targets += 1
                    if edge.source_anchor.block_serial not in dag_original_blocks:
                        continue
                    if any(
                        block_serial not in dag_original_blocks
                        for block_serial in edge.ordered_path
                    ):
                        continue
                    if (
                        safe_target_entry is not None
                        and safe_target_entry not in dag_original_blocks
                    ):
                        continue
                    if self._emit_dag_redirect(
                        edge=edge,
                        dag=dag_latest,
                        builder=dag_builder,
                        modifications=dag_modifications,
                        owned_blocks=dag_owned_blocks,
                        owned_edges=dag_owned_edges,
                        owned_transitions=dag_owned_transitions,
                        emitted=dag_emitted,
                        claimed_1way=dag_claimed_1way,
                        claimed_2way=dag_claimed_2way,
                        claimed_exits=dag_claimed_exits,
                        claimed_path_edges=dag_claimed_path_edges,
                        blocked_sources=dag_blocked_sources,
                        terminal_source_keys=dag_terminal_source_keys,
                        terminal_source_handlers=dag_terminal_source_handlers,
                        terminal_source_owned_blocks=dag_terminal_source_owned_blocks,
                        terminal_protected_blocks=dag_terminal_protected_blocks,
                        report_exit_handlers=report_exit_handlers,
                        report_exit_owned_blocks=report_exit_owned_blocks,
                        bst_node_blocks=dag_bst_node_blocks,
                        dispatcher_region=dag_dispatcher_region,
                        flow_graph=dag_current_flow_graph,
                        state_var_stkoff=dag_state_var_stkoff,
                        dispatcher_lookup=(
                            dag_dispatcher.lookup if dag_dispatcher is not None else None
                        ),
                        dispatcher=dag_dispatcher,
                        mba=mba,
                    ):
                        if edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
                            dag_conditional_count += 1
                        else:
                            dag_transition_count += 1
                    else:
                        dag_skipped_count += 1

            dag_initial_entry = (
                resolve_dag_entry_for_state(
                    dag_latest,
                    sm.initial_state,
                    bst_node_blocks=dag_bst_node_blocks,
                )
                if sm.initial_state is not None
                else None
            )
            if (
                dag_pre_header is not None
                and dag_initial_entry is not None
                and dag_pre_header in dag_original_blocks
                and dag_initial_entry in dag_original_blocks
                and dag_pre_header not in dag_claimed_1way
            ):
                dag_modifications.append(
                    dag_builder.goto_redirect(
                        source_block=dag_pre_header,
                        target_block=dag_initial_entry,
                    )
                )
                dag_owned_blocks.add(dag_pre_header)
                dag_owned_edges.add((dag_pre_header, dag_initial_entry))
                dag_claimed_1way[dag_pre_header] = dag_initial_entry
                dag_transition_count += 1
                logger.info(
                    "LFG DAG: pre-header %s -> %s (state 0x%X)",
                    blk_label(mba, dag_pre_header),
                    blk_label(mba, dag_initial_entry),
                    sm.initial_state if sm.initial_state is not None else 0,
                )

            dag_unresolved_bst_targets = dag_round_unresolved_bst_targets
            dag_round_added = len(dag_modifications) - dag_round_start
            if dag_round_added <= 0:
                break
            if not dag_projectable or dag_round_index + 1 >= dag_round_limit:
                break
            try:
                dag_patch_plan = compile_patch_plan(dag_modifications, flow_graph)
                dag_current_flow_graph = project_post_state(flow_graph, dag_patch_plan)
                logger.info(
                    "LFG DAG: projected planning round %d -> %d blocks",
                    dag_round_index + 1,
                    len(dag_current_flow_graph.blocks),
                )
            except Exception:
                logger.warning(
                    "LFG DAG: projected replanning failed after round %d",
                    dag_round_index + 1,
                    exc_info=True,
                )
                break

        dag = dag_latest
        dag_cleanup_gate_reason: str | None = None
        dag_residual_dispatcher_preds: tuple[int, ...] = ()

        dag_residual_redirect_count = 0
        dag_residual_normalized_count = 0
        # Only normalize residual dispatcher rewrites discovered after the
        # first projection. Primary DAG/planned redirects already target
        # semantic entries; feeding them back through projected path-tail
        # normalization over-collapses them onto later corridor blocks.
        dag_normalizable_redirect_blocks: set[int] = set()
        if dag_projectable and dag_modifications:
            try:
                dag_patch_plan = compile_patch_plan(dag_modifications, flow_graph)
                dag_final_flow_graph = project_post_state(flow_graph, dag_patch_plan)
            except Exception:
                dag_final_flow_graph = dag_current_flow_graph
        else:
            dag_final_flow_graph = dag_current_flow_graph

        if dag_final_flow_graph is not None:
            dag_residual_dispatcher_preds = self._collect_residual_dispatcher_predecessors(
                dag_final_flow_graph,
                snapshot.bst_dispatcher_serial,
                bst_node_blocks=dag_bst_node_blocks,
                reachable_from_serial=getattr(dag_final_flow_graph, "entry_serial", None),
            )
            if dag_residual_dispatcher_preds:
                dag_residual_redirect_count = self._emit_residual_dispatcher_handoffs(
                    dag=dag,
                    state_machine=sm,
                    projected_flow_graph=dag_final_flow_graph,
                    dispatcher_serial=snapshot.bst_dispatcher_serial,
                    bst_node_blocks=dag_bst_node_blocks,
                    builder=dag_builder,
                    modifications=dag_modifications,
                    owned_blocks=dag_owned_blocks,
                    owned_edges=dag_owned_edges,
                    owned_transitions=dag_owned_transitions,
                    emitted=dag_emitted,
                    claimed_1way=dag_claimed_1way,
                    claimed_2way=dag_claimed_2way,
                    state_var_stkoff=dag_state_var_stkoff,
                    dispatcher_lookup=(
                        dag_dispatcher.lookup if dag_dispatcher is not None else None
                    ),
                    dispatcher=dag_dispatcher,
                    mba=mba,
                    redirected_blocks=dag_normalizable_redirect_blocks,
                )
                if dag_residual_redirect_count:
                    dag_patch_plan = compile_patch_plan(dag_modifications, flow_graph)
                    dag_final_flow_graph = project_post_state(flow_graph, dag_patch_plan)
                dag_residual_dispatcher_preds = self._collect_residual_dispatcher_predecessors(
                    dag_final_flow_graph,
                    snapshot.bst_dispatcher_serial,
                    bst_node_blocks=dag_bst_node_blocks,
                    reachable_from_serial=getattr(dag_final_flow_graph, "entry_serial", None),
                )
                if dag_residual_dispatcher_preds:
                    dag_cleanup_gate_reason = "residual_dispatcher_predecessors"
                    logger.info(
                        "LFG DAG: preserving post-apply BST cleanup because residual non-BST dispatcher predecessors remain: %s",
                        [blk_label(mba, serial) for serial in dag_residual_dispatcher_preds],
                    )

        if not dag_modifications:
            logger.info("LFG: DAG produced no redirect modifications")
            return None

        assert dag is not None

        if dag_unresolved_bst_targets or dag_cleanup_gate_reason is not None:
            dag_disconnect_count = 0
            if dag_unresolved_bst_targets:
                logger.info(
                    "LFG DAG: preserving BST cleanup because %d targets still resolve only inside BST region",
                    dag_unresolved_bst_targets,
                )
            if dag_cleanup_gate_reason is None and dag_unresolved_bst_targets:
                dag_cleanup_gate_reason = "unresolved_bst_targets"
        else:
            dag_disconnect_count = self._disconnect_bst_comparison_nodes(
                dag_bst_node_blocks,
                snapshot.bst_dispatcher_serial,
                dag_builder,
                dag_modifications,
                dag_emitted,
                mba=mba,
            )

        logger.info(
            "LFG DAG: emitted %d redirects (%d unconditional, %d conditional); "
            "%d terminal edges ignored, %d unknown edges ignored, %d skipped conflicts; "
            "%d BST disconnects",
            dag_transition_count + dag_conditional_count,
            dag_transition_count,
            dag_conditional_count,
            dag_terminal_skipped,
            dag_unknown_skipped,
            dag_skipped_count,
            dag_disconnect_count,
        )

        dag_handlers_visited = len(sm.handlers)
        dag_ownership = OwnershipScope(
            blocks=frozenset(dag_owned_blocks),
            edges=frozenset(dag_owned_edges),
            transitions=frozenset(dag_owned_transitions),
        )
        dag_benefit = BenefitMetrics(
            handlers_resolved=dag_handlers_visited,
            transitions_resolved=dag_transition_count + dag_conditional_count,
            blocks_freed=len(dag_bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=dag_modifications,
            ownership=dag_ownership,
            prerequisites=self.prerequisites,
            expected_benefit=dag_benefit,
            risk_score=0.1,
            metadata={
                "handlers_visited": dag_handlers_visited,
                "resolved_count": dag_transition_count + dag_conditional_count,
                "dag_transition_count": dag_transition_count,
                "dag_conditional_count": dag_conditional_count,
                "dag_terminal_skipped": dag_terminal_skipped,
                "dag_unknown_skipped": dag_unknown_skipped,
                "skipped_count": dag_skipped_count,
                "disconnect_count": dag_disconnect_count,
                "allow_post_apply_bst_cleanup": dag_cleanup_gate_reason is None,
                "post_apply_bst_cleanup_reason": dag_cleanup_gate_reason,
                "residual_dispatcher_preds": dag_residual_dispatcher_preds,
                "residual_dispatcher_redirect_count": dag_residual_redirect_count,
                "residual_dispatcher_normalized_count": dag_residual_normalized_count,
                "dead_island_cleanup_count": 0,
                "unresolved_bst_targets": dag_unresolved_bst_targets,
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
        redirected = 0
        ignored_blocks = set(bst_node_blocks)
        ignored_blocks.add(dispatcher_serial)
        pred_split_emitted: set[tuple[int, int, int]] = set()
        prefix_emitted: set[tuple[int, int, int]] = set()
        residual_preds = cls._collect_residual_dispatcher_predecessors(
            projected_flow_graph,
            dispatcher_serial,
            bst_node_blocks=bst_node_blocks,
            reachable_from_serial=getattr(projected_flow_graph, "entry_serial", None),
        )
        residual_ignored_blocks = ignored_blocks | set(residual_preds)
        residual_mba_view = build_mba_view_from_flow_graph(projected_flow_graph)
        analysis_mba = residual_mba_view if residual_mba_view is not None else mba

        for source_block in residual_preds:
            block = projected_flow_graph.get_block(source_block)
            if block is None:
                continue
            succs = tuple(getattr(block, "succs", ()))
            if succs != (dispatcher_serial,):
                continue
            if source_block in claimed_1way:
                continue
            current_preds = tuple(int(pred) for pred in getattr(block, "preds", ()))
            handoff_facts = collect_residual_source_handoff_facts(
                dag,
                state_machine=state_machine,
                projected_flow_graph=projected_flow_graph,
                source_block=source_block,
                current_preds=current_preds,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                analysis_mba=analysis_mba,
                live_mba=(mba if mba is not None else None),
            )
            logger.info(
                "LFG DAG DEBUG residual %s: assignment_map=%s projected_snapshot=%s projected=%s state_write=%s immediate=%s synthesized=%s live_immediate=%s live_synthesized=%s preds=%s succs=%s",
                blk_label(mba, source_block),
                handoff_facts.assignment_map_handoff,
                handoff_facts.projected_snapshot_handoff,
                handoff_facts.projected_path_handoff,
                handoff_facts.source_has_state_write,
                handoff_facts.immediate_handoff,
                handoff_facts.synthesized_handoff,
                handoff_facts.live_immediate_handoff,
                handoff_facts.live_synthesized_handoff,
                handoff_facts.current_preds,
                succs,
            )

            prefix_before_attempts: list[ResidualPrefixAttempt] = []
            for edge, via_pred, prefix_target in iter_residual_prefix_handoffs(
                dag,
                source_block=source_block,
                bst_node_blocks=bst_node_blocks,
                dispatcher=dispatcher,
            ):
                source_anchor = edge.source_anchor
                branch_source = source_anchor.block_serial
                branch_block = projected_flow_graph.get_block(branch_source)
                if branch_block is None:
                    continue
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
                prefix_before_attempts.append(
                    build_residual_prefix_attempt(
                        ResidualPrefixAttemptBuildContext(
                            via_pred=int(via_pred),
                            prefix_target=int(prefix_target),
                            claimed_branch_target=claimed_2way.get((branch_source, old_target)),
                            owned_transition=(
                                (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                                if edge.source_key.state_const is not None and edge.target_state is not None
                                else None
                            ),
                            edge_kind_name=edge.kind.name.lower(),
                            is_conditional_branch_source=(
                                source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                            ),
                            branch_source=branch_source,
                            source_block=source_block,
                            branch_succs=branch_succs,
                            old_target=old_target,
                            ordered_path=tuple(int(node) for node in edge.ordered_path),
                            dispatcher_serial=dispatcher_serial,
                            bst_node_blocks=frozenset(bst_node_blocks),
                            target_reaches_branch=target_reaches_source_ignoring_blocks(
                                projected_flow_graph,
                                target_entry=prefix_target,
                                source_block=branch_source,
                                ignored_blocks=(residual_ignored_blocks | {source_block, via_pred}),
                            ),
                        )
                    )
                )

            pred_split_attempts: list[ResidualPredSplitAttempt] = []
            goto_attempt: ResidualGotoAttempt | None = None
            prefix_after_attempts: list[ResidualPrefixAttempt] = []

            if handoff_facts.handoff is None:
                for via_pred in current_preds:
                    pred_handoff = None
                    if handoff_facts.source_has_state_write:
                        pred_handoff = cls._resolve_synthesized_handoff_target(
                            dag,
                            analysis_mba,
                            source_block,
                            state_var_stkoff=state_var_stkoff,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher=dispatcher,
                            via_pred=via_pred,
                        )
                        if pred_handoff is None and mba is not None and analysis_mba is not mba:
                            pred_handoff = cls._resolve_synthesized_handoff_target(
                                dag,
                                mba,
                                source_block,
                                state_var_stkoff=state_var_stkoff,
                                bst_node_blocks=bst_node_blocks,
                                dispatcher=dispatcher,
                                via_pred=via_pred,
                            )
                    if pred_handoff is None:
                        pred_handoff = cls._resolve_projected_path_tail_target(
                            dag,
                            source_block=source_block,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher=dispatcher,
                            predecessor_hints=(via_pred,),
                            require_predecessor_match=True,
                        )
                    if pred_handoff is None:
                        pred_handoff = cls._resolve_synthesized_handoff_target(
                            dag,
                            analysis_mba,
                            source_block,
                            state_var_stkoff=state_var_stkoff,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher=dispatcher,
                            via_pred=via_pred,
                        )
                    if pred_handoff is None and mba is not None and analysis_mba is not mba:
                        pred_handoff = cls._resolve_synthesized_handoff_target(
                            dag,
                            mba,
                            source_block,
                            state_var_stkoff=state_var_stkoff,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher=dispatcher,
                            via_pred=via_pred,
                        )
                    if pred_handoff is None:
                        pred_handoff = cls._resolve_immediate_handoff_target(
                            dag,
                            analysis_mba,
                            via_pred,
                            state_var_stkoff=state_var_stkoff,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher_lookup=(
                                getattr(dispatcher, "lookup", None)
                                if dispatcher is not None
                                else dispatcher_lookup
                            ),
                            dispatcher=dispatcher,
                        )
                    if pred_handoff is None:
                        continue
                    state_value, target_entry = pred_handoff
                    emit_key = (source_block, via_pred, target_entry)
                    pred_split_attempts.append(
                        build_residual_pred_split_attempt(
                            ResidualPredSplitAttemptBuildContext(
                                via_pred=int(via_pred),
                                target_entry=int(target_entry),
                                state_value=int(state_value),
                                source_block=int(source_block),
                                dispatcher_serial=int(dispatcher_serial),
                                bst_node_blocks=frozenset(bst_node_blocks),
                                valid_pair=is_valid_pred_split_pair(
                                    source_block,
                                    via_pred=via_pred,
                                    source_succs=tuple(builder.block_succ_map.get(source_block, ())),
                                    via_pred_succs=tuple(builder.block_succ_map.get(via_pred, ())),
                                ),
                                target_reaches_via_pred=pred_split_target_reaches_via_pred(
                                    projected_flow_graph,
                                    target_entry=target_entry,
                                    via_pred=via_pred,
                                    source_block=source_block,
                                    ignored_blocks=residual_ignored_blocks,
                                ),
                                already_emitted=emit_key in pred_split_emitted,
                            )
                        )
                    )
            else:
                state_value, target_entry = handoff_facts.handoff
                allow_family_fallback_tail = can_rewrite_shared_suffix_family_fallback(
                    dag,
                    source_block=source_block,
                    target_entry=target_entry,
                    current_preds=current_preds,
                    bst_node_blocks=bst_node_blocks,
                    flow_graph=projected_flow_graph,
                )
                goto_attempt = build_residual_goto_attempt(
                    ResidualGotoAttemptBuildContext(
                        target_entry=int(target_entry),
                        state_value=int(state_value),
                        source_block=int(source_block),
                        dispatcher_serial=int(dispatcher_serial),
                        bst_node_blocks=frozenset(bst_node_blocks),
                        allow_family_fallback_tail=allow_family_fallback_tail,
                        is_shared_suffix_conditional_tail=is_shared_suffix_conditional_tail(
                            dag,
                            source_block=source_block,
                        ),
                        has_prior_branch_cut=has_prior_branch_cut_for_state(
                            dag,
                            source_block=source_block,
                            state_value=state_value,
                            bst_node_blocks=bst_node_blocks,
                            dispatcher=dispatcher,
                        ),
                        target_reaches_source=target_reaches_source_ignoring_blocks(
                            projected_flow_graph,
                            target_entry=target_entry,
                            source_block=source_block,
                            ignored_blocks=residual_ignored_blocks,
                        ),
                        already_emitted=(source_block, target_entry) in emitted,
                        live_oneway_noop=is_live_oneway_noop(
                            source_succs=tuple(builder.block_succ_map.get(source_block, ())),
                            target_entry=target_entry,
                        ),
                    )
                )

                for edge, via_pred, prefix_target in iter_residual_prefix_handoffs(
                    dag,
                    source_block=source_block,
                    bst_node_blocks=bst_node_blocks,
                    dispatcher=dispatcher,
                ):
                    pred_block = projected_flow_graph.get_block(via_pred)
                    if pred_block is None:
                        continue
                    pred_succs = tuple(getattr(pred_block, "succs", ()))
                    prefix_key = (via_pred, source_block, prefix_target)
                    source_anchor = edge.source_anchor
                    branch_source = source_anchor.block_serial
                    branch_block = projected_flow_graph.get_block(branch_source)
                    branch_succs = (
                        tuple(int(succ) for succ in tuple(getattr(branch_block, "succs", ())))
                        if branch_block is not None
                        else ()
                    )
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
                    prefix_after_attempts.append(
                        build_residual_prefix_attempt(
                            ResidualPrefixAttemptBuildContext(
                                via_pred=int(via_pred),
                                prefix_target=int(prefix_target),
                                claimed_branch_target=claimed_2way.get((branch_source, old_target)),
                                owned_transition=(
                                    (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                                    if edge.source_key.state_const is not None and edge.target_state is not None
                                    else None
                                ),
                                edge_kind_name=edge.kind.name.lower(),
                                is_conditional_branch_source=(
                                    source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                                ),
                                branch_source=(branch_source if branch_block is not None else None),
                                source_block=source_block,
                                branch_succs=branch_succs,
                                old_target=old_target,
                                ordered_path=tuple(int(node) for node in edge.ordered_path),
                                dispatcher_serial=dispatcher_serial,
                                bst_node_blocks=frozenset(bst_node_blocks),
                                target_reaches_branch=target_reaches_source_ignoring_blocks(
                                    projected_flow_graph,
                                    target_entry=prefix_target,
                                    source_block=branch_source,
                                    ignored_blocks=(residual_ignored_blocks | {source_block, via_pred}),
                                ) if branch_block is not None else False,
                                via_pred_succs=tuple(int(succ) for succ in pred_succs),
                                target_reaches_pred=target_reaches_source_ignoring_blocks(
                                    projected_flow_graph,
                                    target_entry=prefix_target,
                                    source_block=via_pred,
                                    ignored_blocks=residual_ignored_blocks | {source_block},
                                ),
                                already_emitted=prefix_key in prefix_emitted,
                                existing_target=claimed_1way.get(via_pred),
                                via_pred_succ_count=len(pred_succs),
                            )
                        )
                    )

            source_plan = plan_residual_dispatcher_source(
                ResidualDispatcherSourceContext(
                    source_block=int(source_block),
                    dispatcher_serial=int(dispatcher_serial),
                    prefix_before_attempts=tuple(prefix_before_attempts),
                    pred_split_attempts=tuple(pred_split_attempts),
                    goto_attempt=goto_attempt,
                    prefix_after_attempts=tuple(prefix_after_attempts),
                )
            )
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

            apply_residual_dispatcher_source_plan(
                source_plan,
                modifications=modifications,
                claimed_1way=claimed_1way,
                claimed_2way=claimed_2way,
                emitted=emitted,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                pred_split_emitted=pred_split_emitted,
                prefix_emitted=prefix_emitted,
                redirected_blocks=redirected_blocks,
            )

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

            redirected += int(source_plan.redirected_count)

        return redirected

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

        for action in actions:
            if action.replace_index is not None:
                modifications[action.replace_index] = action.modification
                if action.replaced_target is not None:
                    emitted.discard((int(action.source_block), int(action.replaced_target)))
            else:
                modifications.append(action.modification)
            claimed_1way[int(action.source_block)] = int(action.target_entry)
            emitted.add((int(action.source_block), int(action.target_entry)))
            owned_blocks.add(int(action.source_block))
            owned_edges.add((int(action.source_block), int(action.target_entry)))
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
        if target_entry is None:
            target_entry = cls._resolve_effective_target_entry(
                dag,
                edge,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
                mba=mba,
            )
        if target_entry is None:
            return False
        if claimed_1way is None:
            claimed_1way = {}
        if not edge.ordered_path or edge.target_entry_anchor is None:
            return False
        source_block = edge.ordered_path[-1]
        foreign_exact_owner = find_foreign_exact_entry_owner(
            dag,
            source_key=edge.source_key,
            source_block=source_block,
        )
        backward_same_corridor = is_backward_same_corridor_target(
            ordered_path=tuple(int(node) for node in edge.ordered_path),
            source_block=source_block,
            target_entry=target_entry,
        )
        allow_semantic_handoff = is_semantic_handoff_redirect(
            dag,
            edge,
            source_block=source_block,
            target_entry=target_entry,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        )
        target_reaches_source = target_reaches_source_ignoring_blocks(
            flow_graph,
            target_entry=target_entry,
            source_block=source_block,
            ignored_blocks=set(dispatcher_region) | set(bst_node_blocks),
        )
        if allow_semantic_handoff and target_reaches_source:
            logger.info(
                "LFG DAG: allowing semantic handoff %s -> %s despite existing backreach",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )

        source_snapshot = flow_graph.get_block(source_block)

        old_target = resolve_redirect_old_target(
            source_block,
            source_succs=tuple(builder.block_succ_map.get(source_block, ())),
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
            dispatcher_region=dispatcher_region,
        )

        emit_key = (source_block, target_entry)

        npreds = len(tuple(source_snapshot.preds)) if source_snapshot is not None else 0
        shared_handoff = None
        if npreds > 1:
            shared_handoff = cls._resolve_immediate_handoff_target(
                dag,
                mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
                bst_node_blocks=bst_node_blocks,
                dispatcher_lookup=dispatcher_lookup,
                dispatcher=dispatcher,
            )
        via_pred = edge.ordered_path[-2] if len(edge.ordered_path) >= 2 else None
        other_preds = tuple(
            pred for pred in tuple(getattr(source_snapshot, "preds", ()))
            if pred != via_pred
        )
        decision = plan_path_tail_redirect(
            PathTailRedirectContext(
                source_block=int(source_block),
                target_entry=int(target_entry),
                source_handler_is_report_exit=(
                    edge.source_key.handler_serial in report_exit_handlers
                ),
                ordered_path_head_is_report_exit=(
                    bool(edge.ordered_path) and edge.ordered_path[0] in report_exit_handlers
                ),
                source_in_report_exit_owned=(source_block in report_exit_owned_blocks),
                source_blocked=(source_block in blocked_sources),
                source_terminal_protected=(source_block in terminal_protected_blocks),
                foreign_exact_owner_label=(
                    foreign_exact_owner.state_label
                    if foreign_exact_owner is not None
                    else None
                ),
                backward_same_corridor=bool(backward_same_corridor),
                allow_semantic_handoff=bool(allow_semantic_handoff),
                target_reaches_source=bool(target_reaches_source),
                source_nsucc=(
                    int(source_snapshot.nsucc)
                    if source_snapshot is not None
                    else None
                ),
                source_npred=(
                    int(npreds)
                    if source_snapshot is not None
                    else None
                ),
                source_succs=tuple(int(succ) for succ in getattr(source_snapshot, "succs", ())),
                source_preds=tuple(int(pred) for pred in getattr(source_snapshot, "preds", ())),
                old_target=(int(old_target) if old_target is not None else None),
                emitted_already=(emit_key in emitted),
                shared_handoff_target=(
                    int(shared_handoff[1]) if shared_handoff is not None else None
                ),
                via_pred=(int(via_pred) if via_pred is not None else None),
                via_pred_succs=tuple(int(succ) for succ in builder.block_succ_map.get(via_pred, ())),
                existing_exit_target=claimed_exits.get(source_block),
                existing_1way_target=claimed_1way.get(source_block),
                existing_path_edge_target=(
                    claimed_path_edges.get((source_block, via_pred))
                    if via_pred is not None
                    else None
                ),
                via_pred_blocked=(via_pred in blocked_sources if via_pred is not None else False),
                via_pred_terminal_protected=(
                    via_pred in terminal_protected_blocks if via_pred is not None else False
                ),
                source_is_conditional_branch=(
                    edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
                ),
                source_anchor_block=int(edge.source_anchor.block_serial),
                source_branch_arm=(
                    int(edge.source_anchor.branch_arm)
                    if edge.source_anchor.branch_arm is not None
                    else None
                ),
                other_preds=tuple(int(pred) for pred in other_preds),
            )
        )
        if not decision.accepted or decision.emission_plan is None:
            if decision.rejection_reason == "foreign_exact_entry_owner" and foreign_exact_owner is not None:
                logger.info(
                    "LFG DAG: skipping %s -> %s because %s is the exact entry for %s, not source corridor %s",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                    blk_label(mba, source_block),
                    foreign_exact_owner.state_label,
                    edge.source_key.state_const
                    if edge.source_key.state_const is not None
                    else edge.source_key.handler_serial,
                )
            elif decision.rejection_reason == "backward_same_corridor":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "target_reaches_source":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target already reaches source",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "shared_handoff_conflict" and shared_handoff is not None:
                logger.info(
                    "LFG DAG: skipping %s -> %s because %s already proves concrete shared handoff %s for state 0x%X",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                    blk_label(mba, source_block),
                    blk_label(mba, shared_handoff[1]),
                    shared_handoff[0],
                )
            return False
        plan = decision.emission_plan
        apply_path_tail_emission_plan(
            plan,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
            claimed_exits=claimed_exits,
            claimed_path_edges=claimed_path_edges,
            blocked_sources=blocked_sources,
            owned_transition=(
                (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                if edge.source_key.state_const is not None and edge.target_state is not None
                else None
            ),
        )

        if plan.kind == PathTailEmissionKind.SHARED_GOTO:
            logger.info(
                "LFG DAG: shared tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
        elif plan.kind == PathTailEmissionKind.DIRECT_GOTO:
            logger.info(
                "LFG DAG: path-tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
        elif plan.kind == PathTailEmissionKind.PRED_SPLIT:
            assert via_pred is not None
            logger.info(
                "LFG DAG: path-tail pred-split %s via %s -> %s",
                blk_label(mba, source_block),
                blk_label(mba, via_pred),
                blk_label(mba, target_entry),
            )
        elif plan.kind == PathTailEmissionKind.DUPLICATE:
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

        source_block = edge.source_anchor.block_serial
        allow_semantic_handoff = is_semantic_handoff_redirect(
            dag,
            edge,
            source_block=source_block,
            target_entry=target_entry,
            state_var_stkoff=state_var_stkoff,
            dispatcher_lookup=dispatcher_lookup,
            dispatcher=dispatcher,
            mba=mba,
        )
        target_reaches_source = target_reaches_source_ignoring_blocks(
            flow_graph,
            target_entry=target_entry,
            source_block=source_block,
            ignored_blocks=set(dispatcher_region) | set(bst_node_blocks),
        )
        if allow_semantic_handoff and target_reaches_source:
            logger.info(
                "LFG DAG: allowing semantic handoff %s -> %s despite existing backreach",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
            )

        emit_key = (source_block, target_entry)

        nsucc = builder.block_nsucc_map.get(source_block, 1)
        old_target = resolve_redirect_old_target(
            source_block,
            source_succs=tuple(builder.block_succ_map.get(source_block, ())),
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
            dispatcher_region=dispatcher_region,
        )
        branch_key = (
            (source_block, int(old_target))
            if nsucc == 2 and old_target is not None
            else None
        )
        decision = plan_dag_redirect_fallback(
            DagRedirectFallbackContext(
                source_block=int(source_block),
                target_entry=int(target_entry),
                source_handler_is_report_exit=(
                    edge.source_key.handler_serial in report_exit_handlers
                ),
                ordered_path_head_is_report_exit=(
                    bool(edge.ordered_path) and edge.ordered_path[0] in report_exit_handlers
                ),
                source_equals_target=(int(source_block) == int(target_entry)),
                backward_same_corridor=is_backward_same_corridor_target(
                    ordered_path=tuple(int(node) for node in edge.ordered_path),
                    source_block=source_block,
                    target_entry=target_entry,
                ),
                allow_semantic_handoff=bool(allow_semantic_handoff),
                target_reaches_source=bool(target_reaches_source),
                source_blocked=(source_block in blocked_sources),
                source_terminal_protected=(source_block in terminal_protected_blocks),
                source_in_report_exit_owned=(source_block in report_exit_owned_blocks),
                source_in_terminal_source_owned_transition=(
                    edge.kind == SemanticEdgeKind.TRANSITION
                    and source_block in terminal_source_owned_blocks
                ),
                ordered_path_ends_at_source=(
                    not edge.ordered_path or source_block == edge.ordered_path[-1]
                ),
                emitted_already=(emit_key in emitted),
                nsucc=int(nsucc),
                old_target=(int(old_target) if old_target is not None else None),
                source_succs=tuple(int(succ) for succ in builder.block_succ_map.get(source_block, ())),
                edge_is_transition=(edge.kind == SemanticEdgeKind.TRANSITION),
                live_oneway_noop=is_live_oneway_noop(
                    source_succs=tuple(builder.block_succ_map.get(source_block, ())),
                    target_entry=target_entry,
                ),
                claimed_1way_target=claimed_1way.get(source_block),
                claimed_2way_target=(
                    claimed_2way.get(branch_key)
                    if branch_key is not None
                    else None
                ),
            )
        )
        if not decision.accepted or decision.emission_plan is None:
            if decision.rejection_reason == "backward_same_corridor":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target is earlier in the same corridor",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "target_reaches_source":
                logger.info(
                    "LFG DAG: skipping %s -> %s because target already reaches source",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "live_oneway_noop":
                logger.info(
                    "LFG DAG: skipping %s -> %s because live CFG already has that 1-way handoff",
                    blk_label(mba, source_block),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "branch_conflict":
                assert old_target is not None
                logger.info(
                    "LFG DAG: conflict on 2-way %s old=%s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, old_target),
                    blk_label(mba, decision.emission_plan.existing_target),
                    blk_label(mba, target_entry),
                )
            elif decision.rejection_reason == "oneway_conflict":
                logger.info(
                    "LFG DAG: conflict on 1-way %s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, decision.emission_plan.existing_target),
                    blk_label(mba, target_entry),
                )
            return False

        emission_plan = decision.emission_plan
        modifications.append(emission_plan.modification)
        if emission_plan.claim_2way_key is not None and emission_plan.claim_2way_target is not None:
            claimed_2way[emission_plan.claim_2way_key] = emission_plan.claim_2way_target
        if emission_plan.claim_1way_target is not None:
            claimed_1way[source_block] = emission_plan.claim_1way_target

        emitted.add(emit_key)
        owned_blocks.add(source_block)
        owned_edges.add((source_block, target_entry))
        if edge.source_key.state_const is not None and edge.target_state is not None:
            owned_transitions.add(
                (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
            )
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
