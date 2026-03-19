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
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.plan import compile_patch_plan
from d810.core import logging
from d810.core.typing import TYPE_CHECKING

from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
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
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.state_machine_analysis import build_mba_view_from_flow_graph
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report_from_graph,
)
from d810.recon.flow.transition_builder import TransitionResult, _get_state_var_stkoff

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
                logger.info(
                    "LFG: already applied for func 0x%X at maturity %d",
                    func_ea, maturity,
                )
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
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        assert sm is not None  # guaranteed by is_applicable
        bst_result = snapshot.bst_result
        assert bst_result is not None
        mba = snapshot.mba
        flow_graph = snapshot.flow_graph
        if flow_graph is None:
            logger.info("LFG: no flow_graph available, skipping")
            return None

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
        dag_blocked_sources: set[int] = set()
        dag_skipped_count = 0
        dag_transition_count = 0
        dag_conditional_count = 0
        dag_terminal_skipped = 0
        dag_unknown_skipped = 0
        dag_unresolved_bst_targets = 0
        dag_dispatcher_region: set[int] = set(dag_bst_node_blocks)
        dag_original_blocks = self._flow_graph_block_serials(flow_graph)

        for handler in sm.handlers.values():
            dag_owned_blocks.add(handler.check_block)
            dag_owned_blocks.update(handler.handler_blocks)

        dag_transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        dag_pre_header = getattr(bst_result, "pre_header_serial", None)
        dag_current_flow_graph = flow_graph
        dag_projectable = self._supports_projected_replanning(flow_graph)
        # Keep projection for post-plan safety checks, but do not re-discover
        # semantic edges from a partially rewritten CFG inside the same LFG
        # stage. That intermediate graph is structurally valid yet can collapse
        # exact handler families onto dispatcher-adjacent prefixes, which then
        # feeds bad redirects back into the planner.
        dag_round_limit = 1
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
            for edge in self._select_plannable_edges(dag_latest):
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
                    mba=mba,
                ):
                    if edge.kind == SemanticEdgeKind.CONDITIONAL_TRANSITION:
                        dag_conditional_count += 1
                    else:
                        dag_transition_count += 1
                else:
                    dag_skipped_count += 1

            dag_initial_entry = (
                self._resolve_dag_entry_for_state(
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
                "unresolved_bst_targets": dag_unresolved_bst_targets,
                "bst_convert_count": 0,
                "goto_nop_count": 0,
                "goto_skip_count": 0,
                "nop_state_values": {},
            },
        )

        handler_state_map: dict[int, int] = dict(
            getattr(bst_result, "handler_state_map", {}) or {}
        )
        # Backfill handler_state_map from IntervalDispatcher so that
        # handlers reachable only via wide BST range intervals are
        # included in all downstream resolution (exit states, BST
        # default discovery, DOT graph, coverage checks).
        # handler_state_map shape: {handler_serial: state_value}
        _dispatcher = getattr(bst_result, "dispatcher", None)
        if _dispatcher is not None:
            _existing_handler_serials = set(handler_state_map.keys())
            # Count how many rows map to each target.  Targets that
            # appear in multiple disjoint intervals are catch-all /
            # default blocks, NOT real handlers -- skip them.
            from collections import Counter as _Counter
            _target_freq: dict[int, int] = _Counter(
                r.target for r in _dispatcher._rows
            )
            for _row in _dispatcher._rows:
                if _row.target in _existing_handler_serials:
                    continue
                if _target_freq[_row.target] > 1:
                    continue  # catch-all / default block
                # Use lo as representative state value for this range.
                handler_state_map[_row.target] = _row.lo
                logger.info(
                    "LFG: INTERVAL_BACKFILL %s <- state 0x%X "
                    "(range [0x%X, 0x%X))",
                    blk_label(mba, _row.target), _row.lo, _row.lo, _row.hi,
                )
        pre_header_serial: int | None = getattr(
            bst_result, "pre_header_serial", None
        )
        bst_node_blocks: set[int] = set(
            getattr(bst_result, "bst_node_blocks", set()) or set()
        )

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        owned_transitions: set[tuple[int, int]] = set()

        resolved_count = 0
        skipped_count = 0
        # Track which (from_block, to_serial) pairs have been emitted to
        # avoid duplicate redirects when the same exit block appears in
        # multiple transitions.
        emitted: set[tuple[int, int]] = set()
        # Track which 1-way blocks already have a redirect emitted to
        # detect conflicting redirects on shared tail blocks.
        claimed_1way: dict[int, int] = {}  # from_block -> first target_entry

        initial_state = sm.initial_state
        assert initial_state is not None

        # Collect handler block ownership from all known handlers.
        for handler in sm.handlers.values():
            owned_blocks.add(handler.check_block)
            owned_blocks.update(handler.handler_blocks)

        # Build dispatcher region: BST nodes + blocks outside handler
        # ownership.  Used to identify which successor of a 2-way block
        # leads back to the dispatcher (the leg to replace).
        dispatcher_region: set[int] = set(bst_node_blocks)

        # Pre-compute the handler_range_map for catch-all fallback.
        # resolve_target_via_bst() intentionally skips wide ranges
        # (span >= 0xFFFF0000) to avoid false positives during normal
        # resolution.  However, unresolved states that genuinely belong
        # to the BST default/catch-all handler should still be linked.
        range_map: dict[int, tuple[int | None, int | None]] = getattr(
            bst_result, "handler_range_map", {}
        ) or {}

        # -----------------------------------------------------------------
        # 0. INTERVAL DISPATCHER RESOLUTION  (PRIMARY)
        #
        # Walk ALL handler block chains and scan for m_mov #const, %state_var.
        # Resolve each constant via IntervalDispatcher.lookup().  This runs
        # FIRST so that IntervalDispatcher is the primary transition authority;
        # IntervalDispatcher is the sole transition authority (no fallback).
        # Populates `emitted` and `claimed_1way` so step 1 skips covered blocks.
        # -----------------------------------------------------------------
        _interval_resolved = 0
        _id_dispatcher = getattr(bst_result, "dispatcher", None)
        if _id_dispatcher is not None and mba is not None:
            # Resolve state variable stkoff (reuse uncovered logic).
            _id_stkoff: int | None = None
            _id_detector = snapshot.detector
            if _id_detector is not None:
                try:
                    _id_stkoff = _get_state_var_stkoff(_id_detector)
                except Exception:
                    pass
            if _id_stkoff is None and sm.state_var is not None:
                try:
                    if sm.state_var.t == ida_hexrays.mop_S:
                        _id_stkoff = sm.state_var.s.off
                except Exception:
                    pass

            if _id_stkoff is not None:
                # Build set of handler entry serials to avoid walking into
                # other handlers' blocks.
                _id_handler_entries: set[int] = set(handler_state_map.keys())

                # Use a queue for the outer loop so range-match targets
                # discovered during scanning get visited transitively.
                _id_outer_queue: list[int] = sorted(handler_state_map.keys())
                _id_outer_visited: set[int] = set(_id_outer_queue)

                while _id_outer_queue:
                    _id_entry_serial = _id_outer_queue.pop(0)
                    # Walk the handler's block chain: follow 1-way successors
                    # until hitting dispatcher, BST node, or another handler.
                    _id_visited: set[int] = set()
                    _id_queue: list[int] = [_id_entry_serial]

                    while _id_queue:
                        _id_blk_serial = _id_queue.pop(0)
                        if _id_blk_serial in _id_visited:
                            continue
                        _id_visited.add(_id_blk_serial)

                        # Skip BST nodes.
                        if _id_blk_serial in bst_node_blocks:
                            continue

                        try:
                            _id_blk = mba.get_mblock(_id_blk_serial)
                        except (AttributeError, IndexError):
                            continue
                        if _id_blk is None:
                            continue

                        # Check if this block already has a redirect emitted
                        # from it (any target).
                        _id_already_redirected = any(
                            src == _id_blk_serial for src, _ in emitted
                        )

                        # Scan instructions for m_mov #const, %state_var.
                        _id_insn = _id_blk.head
                        while _id_insn is not None:
                            if _id_insn.opcode == ida_hexrays.m_mov:
                                _id_d = _id_insn.d
                                if (
                                    _id_d is not None
                                    and _id_d.t == ida_hexrays.mop_S
                                    and _id_d.s is not None
                                    and _id_d.s.off == _id_stkoff
                                    and _id_insn.l is not None
                                    and _id_insn.l.t == ida_hexrays.mop_n
                                ):
                                    _id_const = _id_insn.l.nnn.value
                                    _id_target = _id_dispatcher.lookup(
                                        _id_const,
                                    )
                                    if (
                                        _id_target is not None
                                        and _id_target != _id_blk_serial
                                        and not _id_already_redirected
                                    ):
                                        _id_emit_key = (
                                            _id_blk_serial,
                                            _id_target,
                                        )
                                        if _id_emit_key not in emitted:
                                            # Check 1-way conflict.
                                            _id_nsucc = (
                                                builder.block_nsucc_map.get(
                                                    _id_blk_serial, 1,
                                                )
                                            )
                                            if _id_nsucc == 2:
                                                # 2-way: find dispatcher-bound leg.
                                                _id_old_target: int | None = None
                                                _id_from_succs = (
                                                    builder.block_succ_map.get(
                                                        _id_blk_serial, (),
                                                    )
                                                )
                                                for _id_s in _id_from_succs:
                                                    if _id_s in bst_node_blocks:
                                                        _id_old_target = _id_s
                                                        break
                                                if _id_old_target is None:
                                                    for _id_s in _id_from_succs:
                                                        if _id_s not in owned_blocks:
                                                            _id_old_target = _id_s
                                                            break
                                                if _id_old_target is None:
                                                    for _id_s in _id_from_succs:
                                                        if _id_s in dispatcher_region:
                                                            _id_old_target = _id_s
                                                            break
                                                if _id_old_target is None:
                                                    for _id_s in _id_from_succs:
                                                        if _id_s != _id_target:
                                                            _id_old_target = _id_s
                                                            break
                                                if _id_old_target is not None:
                                                    _id_mod = builder.edge_redirect(
                                                        source_block=_id_blk_serial,
                                                        target_block=_id_target,
                                                        old_target=_id_old_target,
                                                    )
                                                    modifications.append(_id_mod)
                                                    emitted.add(_id_emit_key)
                                                    owned_edges.add(_id_emit_key)
                                                    _interval_resolved += 1
                                                    logger.info(
                                                        "LFG INTERVAL: resolved "
                                                        "%s -> %s (const 0x%X, "
                                                        "2-way old_target=%s)",
                                                        blk_label(mba, _id_blk_serial),
                                                        blk_label(mba, _id_target),
                                                        _id_const,
                                                        blk_label(mba, _id_old_target),
                                                    )
                                                    # Chain: queue target for
                                                    # transitive resolution.
                                                    if _id_target not in _id_outer_visited:
                                                        _id_outer_visited.add(_id_target)
                                                        _id_handler_entries.add(_id_target)
                                                        _id_outer_queue.append(_id_target)
                                                        logger.info(
                                                            "LFG INTERVAL CHAIN: "
                                                            "queued range-match "
                                                            "target %s for "
                                                            "transitive resolution",
                                                            blk_label(mba, _id_target),
                                                        )
                                            else:
                                                # 1-way.
                                                if _id_blk_serial in claimed_1way:
                                                    if (
                                                        claimed_1way[_id_blk_serial]
                                                        != _id_target
                                                    ):
                                                        logger.info(
                                                            "LFG INTERVAL: CONFLICT "
                                                            "on 1-way %s: already "
                                                            "-> %s, skipping -> %s "
                                                            "(const 0x%X)",
                                                            blk_label(mba, _id_blk_serial),
                                                            blk_label(
                                                                mba,
                                                                claimed_1way[_id_blk_serial],
                                                            ),
                                                            blk_label(mba, _id_target),
                                                            _id_const,
                                                        )
                                                else:
                                                    _id_mod = builder.goto_redirect(
                                                        source_block=_id_blk_serial,
                                                        target_block=_id_target,
                                                    )
                                                    modifications.append(_id_mod)
                                                    emitted.add(_id_emit_key)
                                                    claimed_1way[_id_blk_serial] = (
                                                        _id_target
                                                    )
                                                    owned_edges.add(_id_emit_key)
                                                    _interval_resolved += 1
                                                    logger.info(
                                                        "LFG INTERVAL: resolved "
                                                        "%s -> %s (const 0x%X)",
                                                        blk_label(mba, _id_blk_serial),
                                                        blk_label(mba, _id_target),
                                                        _id_const,
                                                    )
                                                    # Chain: queue target for
                                                    # transitive resolution.
                                                    if _id_target not in _id_outer_visited:
                                                        _id_outer_visited.add(_id_target)
                                                        _id_handler_entries.add(_id_target)
                                                        _id_outer_queue.append(_id_target)
                                                        logger.info(
                                                            "LFG INTERVAL CHAIN: "
                                                            "queued range-match "
                                                            "target %s for "
                                                            "transitive resolution",
                                                            blk_label(mba, _id_target),
                                                        )
                                                    break  # one redirect per 1-way block
                            _id_insn = _id_insn.next

                        # Follow successors for chain walking (BFS depth 1
                        # from entry -- follow 1-way successors staying within
                        # handler ownership, not crossing into other handlers).
                        try:
                            _id_nsucc_walk = _id_blk.nsucc()
                            for _id_si in range(_id_nsucc_walk):
                                _id_succ = _id_blk.succ(_id_si)
                                if _id_succ in bst_node_blocks:
                                    # Enter BST default blocks to find state
                                    # writes, but don't follow their successors
                                    # deeper into the BST tree.
                                    if _id_already_redirected:
                                        continue
                                    try:
                                        _id_bst_blk = mba.get_mblock(
                                            _id_succ,
                                        )
                                    except (AttributeError, IndexError):
                                        continue
                                    if _id_bst_blk is None:
                                        continue
                                    _id_bst_insn = _id_bst_blk.head
                                    while _id_bst_insn is not None:
                                        if (
                                            _id_bst_insn.opcode
                                            == ida_hexrays.m_mov
                                            and _id_bst_insn.d is not None
                                            and _id_bst_insn.d.t
                                            == ida_hexrays.mop_S
                                            and _id_bst_insn.d.s is not None
                                            and _id_bst_insn.d.s.off
                                            == _id_stkoff
                                            and _id_bst_insn.l is not None
                                            and _id_bst_insn.l.t
                                            == ida_hexrays.mop_n
                                        ):
                                            _id_bst_const = (
                                                _id_bst_insn.l.nnn.value
                                            )
                                            _id_bst_target = (
                                                _id_dispatcher.lookup(
                                                    _id_bst_const,
                                                )
                                            )
                                            if (
                                                _id_bst_target is not None
                                                and _id_bst_target
                                                != _id_blk_serial
                                            ):
                                                _id_bst_emit_key = (
                                                    _id_blk_serial,
                                                    _id_bst_target,
                                                )
                                                if (
                                                    _id_bst_emit_key
                                                    not in emitted
                                                ):
                                                    _id_bst_nsucc = (
                                                        builder.block_nsucc_map.get(
                                                            _id_blk_serial,
                                                            1,
                                                        )
                                                    )
                                                    if _id_bst_nsucc == 2:
                                                        _id_bst_mod = (
                                                            builder.edge_redirect(
                                                                source_block=_id_blk_serial,
                                                                target_block=_id_bst_target,
                                                                old_target=_id_succ,
                                                            )
                                                        )
                                                    else:
                                                        _id_bst_mod = (
                                                            builder.goto_redirect(
                                                                source_block=_id_blk_serial,
                                                                target_block=_id_bst_target,
                                                            )
                                                        )
                                                    modifications.append(
                                                        _id_bst_mod,
                                                    )
                                                    emitted.add(
                                                        _id_bst_emit_key,
                                                    )
                                                    if _id_bst_nsucc != 2:
                                                        claimed_1way[
                                                            _id_blk_serial
                                                        ] = _id_bst_target
                                                    owned_edges.add(
                                                        _id_bst_emit_key,
                                                    )
                                                    _interval_resolved += 1
                                                    logger.info(
                                                        "LFG INTERVAL "
                                                        "BST-DEFAULT: "
                                                        "resolved %s -> %s "
                                                        "(const 0x%X from "
                                                        "BST blk %s)",
                                                        blk_label(
                                                            mba,
                                                            _id_blk_serial,
                                                        ),
                                                        blk_label(
                                                            mba,
                                                            _id_bst_target,
                                                        ),
                                                        _id_bst_const,
                                                        blk_label(
                                                            mba,
                                                            _id_succ,
                                                        ),
                                                    )
                                                    # Chain: queue target
                                                    # for transitive
                                                    # resolution.
                                                    if (
                                                        _id_bst_target
                                                        not in _id_outer_visited
                                                    ):
                                                        _id_outer_visited.add(
                                                            _id_bst_target,
                                                        )
                                                        _id_handler_entries.add(
                                                            _id_bst_target,
                                                        )
                                                        _id_outer_queue.append(
                                                            _id_bst_target,
                                                        )
                                                        logger.info(
                                                            "LFG INTERVAL "
                                                            "CHAIN: queued "
                                                            "range-match "
                                                            "target %s for "
                                                            "transitive "
                                                            "resolution",
                                                            blk_label(
                                                                mba,
                                                                _id_bst_target,
                                                            ),
                                                        )
                                                    break
                                        _id_bst_insn = _id_bst_insn.next
                                    continue  # Don't BFS deeper into BST
                                if (
                                    _id_succ not in _id_visited
                                    and (
                                        _id_succ not in _id_handler_entries
                                        or _id_succ == _id_entry_serial
                                    )
                                ):
                                    _id_queue.append(_id_succ)
                        except Exception:
                            pass

            logger.info(
                "LFG INTERVAL: resolved %d transitions via "
                "IntervalDispatcher across all handler blocks (primary pass)",
                _interval_resolved,
            )
        resolved_count += _interval_resolved

        # REMOVED: sm.transitions fallback — IntervalDispatcher is sole authority.
        # sm.transitions has BST walker wrong-branch bugs (0x6E958F99 → 0x11CD1DA3).
        # IntervalDispatcher.lookup() is the single source of truth.

        # A1 handler chain block redirect pass DISABLED: chain blocks inside
        # handlers may be mid-handler, not handler exits. Redirecting them to
        # the next handler's entry short-circuits handler bodies, causing DCE.
        # Needs redesign: chain blocks should be redirected within the handler's
        # internal flow, not to the exit target handler.
        chain_redirect_count = 0

        # -----------------------------------------------------------------
        # 1b. Resolve EXIT states via handler_state_map.
        #
        #     Some handlers have no outgoing transition because the walker
        #     entered a BST comparison node instead of the real handler body.
        #     handler_state_map knows the correct entry block for each state.
        #     We BFS from the correct entry to find state variable writes
        #     (m_mov #const, state_var) and resolve the target handler.
        # -----------------------------------------------------------------
        exit_resolved_count = self._resolve_exit_states(
            snapshot=snapshot,
            sm=sm,
            bst_result=bst_result,
            handler_state_map=handler_state_map,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
            builder=builder,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            owned_transitions=owned_transitions,
            emitted=emitted,
            claimed_1way=claimed_1way,
        )
        resolved_count += exit_resolved_count

        # NOTE: _applied marking moved to unflattener post-success loop.
        # Strategies must NOT mark themselves applied during planning —
        # if the fragment later gate-fails, standalone strategies would
        # be incorrectly suppressed.
        mba = snapshot.mba

        # -----------------------------------------------------------------
        # 1c. Discover transitions through BST default blocks via DFS
        #     forward evaluation.
        #
        #     Some handlers exit through BST default blocks with
        #     MBA-computed state values (e.g., v7 ^ v8) that the
        #     analysis-phase walker cannot resolve.  evaluate_handler_paths
        #     carries per-handler operand context through BST nodes and
        #     can forward-evaluate these expressions to discover the
        #     concrete exit state, which is then resolved via the BST
        #     to find the target handler entry.
        # -----------------------------------------------------------------
        try:
            bst_default_count = self._discover_bst_default_transitions(
                snapshot=snapshot,
                sm=sm,
                bst_result=bst_result,
                handler_state_map=handler_state_map,
                bst_node_blocks=bst_node_blocks,
                dispatcher_region=dispatcher_region,
                builder=builder,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                owned_transitions=owned_transitions,
                emitted=emitted,
                claimed_1way=claimed_1way,
            )
        except Exception:
            logger.warning(
                "LFG: BST-default discovery failed, continuing with "
                "%d main redirects", resolved_count, exc_info=True,
            )
            bst_default_count = 0
        resolved_count += bst_default_count

        # -----------------------------------------------------------------
        # 2. Wire pre-header to initial handler entry.
        # -----------------------------------------------------------------
        initial_entry = resolve_target_via_bst(bst_result, initial_state)
        if pre_header_serial is not None and initial_entry is not None:
            # Skip if the transition loop already redirected the pre-header
            # block (avoids duplicate goto_redirect → BAD_NSUCC on 1-way).
            if pre_header_serial not in claimed_1way:
                mod = builder.goto_redirect(
                    source_block=pre_header_serial,
                    target_block=initial_entry,
                )
                modifications.append(mod)
                owned_blocks.add(pre_header_serial)
                owned_edges.add((pre_header_serial, initial_entry))
                claimed_1way[pre_header_serial] = initial_entry
                logger.info(
                    "LFG: pre-header %s -> initial handler %s "
                    "(state 0x%X)",
                    blk_label(mba, pre_header_serial),
                    blk_label(mba, initial_entry),
                    initial_state,
                )
            else:
                logger.info(
                    "LFG: pre-header %s already redirected, "
                    "skipping duplicate pre-header wire",
                    blk_label(mba, pre_header_serial),
                )

        if not modifications:
            logger.info("LFG: no modifications emitted")
            return None

        # 2b. Emit resolved state machine DOT graph for diagnostics.
        self._emit_resolved_graph_dot(
            sm, bst_result, handler_state_map, emitted, skipped_count,
        )

        # -----------------------------------------------------------------
        # 3. NOP state variable writes in ALL mba blocks.
        #    After redirecting exits, state variable assignments are dead
        #    code.  Leaving them alive keeps BST comparison blocks
        #    reachable, creating spurious while-loops in the decompiled
        #    output.  Shared tail blocks between handlers and the BST
        #    dispatcher also write the state variable but aren't in any
        #    handler's block set, so we scan ALL mba blocks (excluding BST
        #    node blocks which READ the state variable).
        # -----------------------------------------------------------------
        redirected_states: set[int] = {
            t.from_state for t in sm.transitions
            if t.from_state is not None
            and (
                (t.from_block, resolve_target_via_bst(bst_result, t.to_state))
                in emitted
                or resolve_target_via_bst(bst_result, t.to_state) is not None
            )
        }
        # EXPERIMENT: NOPs disabled
        # nop_mods, nop_blocks, nop_state_values = self._nop_state_variable_writes(
        #     snapshot, builder, owned_blocks, redirected_states,
        #     bst_node_blocks,
        # )
        # modifications.extend(nop_mods)
        # owned_blocks.update(nop_blocks)
        nop_mods, nop_blocks, nop_state_values = [], set(), {}

        # -----------------------------------------------------------------
        # 3b. NOP m_goto @dispatcher in single-owner handler blocks.
        #     After state variable writes are NOP'd, explicit m_goto
        #     instructions targeting the dispatcher still keep it
        #     reachable.  NOP these gotos (turning the block into a
        #     dead-end) instead of redirecting to avoid shared-block DCE.
        #     Only safe for blocks with npred<=1.
        # -----------------------------------------------------------------
        dispatcher_serial = snapshot.bst_dispatcher_serial
        # EXPERIMENT: NOPs disabled (dispatcher gotos)
        # goto_nop_mods, goto_nop_count, goto_skip_count = (
        #     self._nop_dispatcher_gotos(
        #         snapshot, dispatcher_serial, bst_node_blocks, builder,
        #     )
        # )
        # modifications.extend(goto_nop_mods)
        goto_nop_mods, goto_nop_count, goto_skip_count = [], 0, 0

        # -----------------------------------------------------------------
        # 4. Disconnect 2-way blocks with dispatcher back-edges.
        #    After linearization, some 2-way blocks (BST comparison nodes
        #    or handler conditionals) still have the dispatcher as one
        #    successor.  These back-edges create while loops in the
        #    decompiled output.  Convert such blocks from 2-way to 1-way
        #    via ConvertToGoto, keeping the non-dispatcher successor.
        # -----------------------------------------------------------------
        disconnect_count = self._disconnect_bst_comparison_nodes(
            bst_node_blocks, dispatcher_serial, builder, modifications, emitted,
            mba=mba,
        )

        # -----------------------------------------------------------------
        # 4b. Convert remaining BST comparison blocks to unconditional gotos.
        #     After linearization, handler exits bypass the dispatcher/BST
        #     entirely.  However, IDA rebuilds edges from instruction
        #     operands, so the BST comparison tree (m_jae/m_jnz testing the
        #     state var) survives as while-loop nesting.  Converting each
        #     remaining BST 2-way block to a 1-way goto destroys the
        #     comparison instruction, making the BST dead code.
        #
        #     This is complementary to _disconnect_bst_comparison_nodes
        #     which only handles blocks with the dispatcher as a successor.
        #     This pass catches BST-internal nodes (e.g., BST node -> BST
        #     node) that don't directly reference the dispatcher.
        # -----------------------------------------------------------------
        flow_graph = snapshot.flow_graph
        # EXPERIMENT: Re-enabled with NOPs OFF to test BST read-side kill
        bst_convert_count = self._convert_bst_nodes_to_goto(
            bst_node_blocks, flow_graph, builder, modifications, emitted,
            mba=mba,
        )
        bst_convert_count = 0

        logger.info(
            "LFG: emitted %d redirects (%d exit-resolved, %d bst-default) "
            "+ %d chain redirects, %d stvar NOPs across %d blocks, "
            "%d goto NOPs (%d shared-skipped), %d BST disconnects, "
            "%d BST-node conversions "
            "(%d skipped)",
            resolved_count,
            exit_resolved_count,
            bst_default_count,
            chain_redirect_count,
            len(nop_mods),
            len(nop_blocks),
            goto_nop_count,
            goto_skip_count,
            disconnect_count,
            bst_convert_count,
            skipped_count,
        )

        # =============================================================
        # DISPATCHER COVERAGE DIAGNOSTIC
        #
        # Log which dispatcher predecessor blocks are NOT covered by
        # any redirect emission.  These are the edges keeping the BST
        # alive and represent missing transitions in the state machine.
        # =============================================================
        flow_graph = snapshot.flow_graph
        if flow_graph is not None and snapshot.bst_dispatcher_serial >= 0:
            dispatcher_snap = flow_graph.get_block(
                snapshot.bst_dispatcher_serial,
            )
            if dispatcher_snap is not None:
                # Collect all from_block serials that got a redirect.
                redirected_blocks: set[int] = set()
                for m in modifications:
                    for attr in (
                        "from_serial",
                        "block_serial",
                        "source_block",
                        "src_block",
                    ):
                        val = getattr(m, attr, None)
                        if val is not None:
                            redirected_blocks.add(val)
                            break

                uncovered: list[tuple[int, int, int, list[int], bool]] = []
                for pred in dispatcher_snap.preds:
                    if pred in redirected_blocks:
                        continue
                    if pred in bst_node_blocks:
                        continue  # BST internal, expected
                    pred_snap = flow_graph.get_block(pred)
                    nsucc = len(pred_snap.succs) if pred_snap else -1
                    succs = list(pred_snap.succs) if pred_snap else []
                    npred = len(pred_snap.preds) if pred_snap else -1

                    # Check if any transition has this block as from_block.
                    has_transition = any(
                        t.from_block == pred for t in sm.transitions
                    )
                    uncovered.append(
                        (pred, nsucc, npred, succs, has_transition),
                    )

                logger.info(
                    "DIAG_COVERAGE: dispatcher %s has %d preds, "
                    "%d redirected, %d BST, %d uncovered non-BST",
                    blk_label(mba, snapshot.bst_dispatcher_serial),
                    len(dispatcher_snap.preds),
                    len(redirected_blocks & set(dispatcher_snap.preds)),
                    sum(
                        1
                        for p in dispatcher_snap.preds
                        if p in bst_node_blocks
                    ),
                    len(uncovered),
                )
                for pred, nsucc, npred, succs, has_trans in uncovered:
                    logger.info(
                        "DIAG_COVERAGE: uncovered %s nsucc=%d npred=%d "
                        "succs=%s has_transition=%s",
                        blk_label(mba, pred),
                        nsucc,
                        npred,
                        succs,
                        has_trans,
                    )

                # -------------------------------------------------------------
                # UNCOVERED DISPATCHER PREDECESSOR RESOLUTION
                #
                # For each uncovered 1-way dispatcher predecessor, scan its
                # instructions for ``m_mov #const, %state_var``.  Resolve the
                # constant via BST to find the target handler entry, then emit
                # a goto_redirect to wire the block directly to the handler.
                # -------------------------------------------------------------
                uncovered_1way = [
                    (pred, nsucc, npred, succs, has_trans)
                    for pred, nsucc, npred, succs, has_trans in uncovered
                    if nsucc == 1
                ]
                if uncovered_1way and mba is not None:
                    # Resolve state variable stkoff.
                    _uc_stkoff: int | None = None
                    _uc_detector = snapshot.detector
                    if _uc_detector is not None:
                        try:
                            _uc_stkoff = _get_state_var_stkoff(_uc_detector)
                        except Exception:
                            pass
                    if _uc_stkoff is None and sm.state_var is not None:
                        try:
                            if sm.state_var.t == ida_hexrays.mop_S:
                                _uc_stkoff = sm.state_var.s.off
                        except Exception:
                            pass

                    _uc_dispatcher = getattr(bst_result, "dispatcher", None)
                    _uc_resolved = 0

                    if _uc_stkoff is not None:
                        for uc_serial, _, _, _, _ in uncovered_1way:
                            try:
                                blk = mba.get_mblock(uc_serial)
                            except (AttributeError, IndexError):
                                continue
                            if blk is None:
                                continue

                            # Scan instructions for m_mov #const, %state_var.
                            insn = blk.head
                            while insn is not None:
                                if insn.opcode == ida_hexrays.m_mov:
                                    d = insn.d
                                    if (
                                        d is not None
                                        and d.t == ida_hexrays.mop_S
                                        and d.s is not None
                                        and d.s.off == _uc_stkoff
                                        and insn.l is not None
                                        and insn.l.t == ida_hexrays.mop_n
                                    ):
                                        const_val = insn.l.nnn.value
                                        target = resolve_target_via_bst(
                                            bst_result, const_val,
                                        )
                                        if target is None and _uc_dispatcher is not None:
                                            target = _uc_dispatcher.lookup(const_val)
                                        if target is not None and target != uc_serial:
                                            emit_key = (uc_serial, target)
                                            if emit_key not in emitted:
                                                # Check claimed_1way conflict.
                                                if uc_serial in claimed_1way:
                                                    if claimed_1way[uc_serial] != target:
                                                        logger.info(
                                                            "LFG UNCOVERED: CONFLICT on "
                                                            "1-way %s: already -> %s, "
                                                            "skipping -> %s (const 0x%X)",
                                                            blk_label(mba, uc_serial),
                                                            blk_label(mba, claimed_1way[uc_serial]),
                                                            blk_label(mba, target),
                                                            const_val,
                                                        )
                                                else:
                                                    mod = builder.goto_redirect(
                                                        source_block=uc_serial,
                                                        target_block=target,
                                                    )
                                                    modifications.append(mod)
                                                    emitted.add(emit_key)
                                                    claimed_1way[uc_serial] = target
                                                    owned_edges.add((uc_serial, target))
                                                    resolved_count += 1
                                                    _uc_resolved += 1
                                                    logger.info(
                                                        "LFG UNCOVERED: resolved %s -> %s "
                                                        "(const 0x%X)",
                                                        blk_label(mba, uc_serial),
                                                        blk_label(mba, target),
                                                        const_val,
                                                    )
                                                break  # one redirect per block
                                insn = insn.next

                    logger.info(
                        "LFG UNCOVERED: resolved %d of %d uncovered "
                        "1-way dispatcher predecessors",
                        _uc_resolved, len(uncovered_1way),
                    )

        handlers_visited = len(sm.handlers)
        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(owned_edges),
            transitions=frozenset(owned_transitions),
        )
        benefit = BenefitMetrics(
            handlers_resolved=handlers_visited,
            transitions_resolved=resolved_count,
            blocks_freed=len(bst_node_blocks),
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=self.prerequisites,
            expected_benefit=benefit,
            risk_score=0.1,
            metadata={
                "handlers_visited": handlers_visited,
                "resolved_count": resolved_count,
                "chain_redirect_count": chain_redirect_count,
                "exit_resolved_count": exit_resolved_count,
                "bst_default_count": bst_default_count,
                "interval_resolved_count": _interval_resolved,
                "skipped_count": skipped_count,
                "disconnect_count": disconnect_count,
                "bst_convert_count": bst_convert_count,
                "goto_nop_count": goto_nop_count,
                "goto_skip_count": goto_skip_count,
                "nop_state_values": nop_state_values,
            },
        )

    @staticmethod
    def _resolve_state_var_stkoff(
        snapshot: AnalysisSnapshot,
        sm: DispatcherStateMachine,
    ) -> int | None:
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                stkoff = None
            if stkoff is not None:
                return stkoff
        if sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    return sm.state_var.s.off
            except Exception:
                pass
        return None

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

    @staticmethod
    def _collect_residual_dispatcher_predecessors(
        flow_graph: object,
        dispatcher_serial: int,
        *,
        bst_node_blocks: set[int],
    ) -> tuple[int, ...]:
        if dispatcher_serial < 0:
            return ()

        residual: list[int] = []
        for serial in sorted(
            LinearizedFlowGraphStrategy._flow_graph_block_serials(flow_graph)
        ):
            if serial == dispatcher_serial or serial in bst_node_blocks:
                continue
            block = flow_graph.get_block(serial)
            if block is None:
                continue
            if dispatcher_serial in tuple(getattr(block, "succs", ())):
                residual.append(serial)
        return tuple(residual)

    @staticmethod
    def _edge_priority(edge: StateDagEdge) -> int:
        if edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH:
            return 0
        if edge.source_anchor.kind == RedirectSourceKind.EXIT_BLOCK:
            return 1
        return 2

    @classmethod
    def _select_plannable_edges(
        cls,
        dag: LinearizedStateDag,
    ) -> tuple[StateDagEdge, ...]:
        return tuple(
            sorted(
                (
                    edge
                    for edge in dag.edges
                    if edge.kind
                    in (
                        SemanticEdgeKind.TRANSITION,
                        SemanticEdgeKind.CONDITIONAL_TRANSITION,
                    )
                    and edge.target_entry_anchor is not None
                ),
                key=lambda edge: (
                    0 if edge.kind == SemanticEdgeKind.TRANSITION else 1,
                    -(len(edge.ordered_path)),
                    edge.source_anchor.block_serial,
                    -1
                    if edge.source_anchor.branch_arm is None
                    else edge.source_anchor.branch_arm,
                    edge.kind.value,
                    edge.target_entry_anchor if edge.target_entry_anchor is not None else -1,
                    cls._edge_priority(edge),
                ),
            )
        )

    @staticmethod
    def _resolve_dag_entry_for_state(
        dag: LinearizedStateDag,
        state_value: int | None,
        *,
        bst_node_blocks: set[int] | None = None,
    ) -> int | None:
        if state_value is None:
            return None
        for node in dag.nodes:
            if node.key.state_const == state_value:
                return LinearizedFlowGraphStrategy._resolve_redirect_safe_entry_from_node(
                    node,
                    bst_node_blocks=bst_node_blocks or set(),
                )
        for node in dag.nodes:
            lo = node.key.range_lo
            hi = node.key.range_hi
            if lo is None or hi is None:
                continue
            if lo <= state_value <= hi:
                return LinearizedFlowGraphStrategy._resolve_redirect_safe_entry_from_node(
                    node,
                    bst_node_blocks=bst_node_blocks or set(),
                )
        return None

    @staticmethod
    def _resolve_redirect_safe_entry_from_node(
        node,
        *,
        bst_node_blocks: set[int],
    ) -> int | None:
        candidates = (
            node.entry_anchor,
            *node.exclusive_blocks,
            *node.owned_blocks,
        )
        for block_serial in candidates:
            if block_serial not in bst_node_blocks:
                return block_serial
        return node.entry_anchor if node.entry_anchor not in bst_node_blocks else None

    @classmethod
    def _resolve_redirect_safe_target_entry(
        cls,
        dag: LinearizedStateDag,
        edge: StateDagEdge,
        *,
        bst_node_blocks: set[int],
    ) -> int | None:
        target_entry = edge.target_entry_anchor
        node_by_key = {node.key: node for node in dag.nodes}
        target_node = node_by_key.get(edge.target_key) if edge.target_key is not None else None
        if target_node is not None:
            safe_target_entry = cls._resolve_redirect_safe_entry_from_node(
                target_node,
                bst_node_blocks=bst_node_blocks,
            )
            if safe_target_entry is not None:
                return safe_target_entry
        if target_entry is None or target_entry in bst_node_blocks:
            return None
        return target_entry

    @staticmethod
    def _resolve_edge_old_target(
        source_block: int,
        edge: StateDagEdge,
        builder: ModificationBuilder,
        *,
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
    ) -> int | None:
        succs = tuple(builder.block_succ_map.get(source_block, ()))
        if not succs:
            return None
        if (
            edge.source_anchor.kind == RedirectSourceKind.CONDITIONAL_BRANCH
            and edge.source_anchor.branch_arm is not None
            and edge.source_anchor.branch_arm < len(succs)
        ):
            return succs[edge.source_anchor.branch_arm]

        if source_block in edge.ordered_path:
            path_index = edge.ordered_path.index(source_block)
            if path_index + 1 < len(edge.ordered_path):
                candidate = edge.ordered_path[path_index + 1]
                if candidate in succs:
                    return candidate

        for succ in succs:
            if succ in bst_node_blocks:
                return succ
        for succ in succs:
            if succ in dispatcher_region:
                return succ
        if edge.target_entry_anchor is not None:
            for succ in succs:
                if succ != edge.target_entry_anchor:
                    return succ
        return succs[0]

    @staticmethod
    def _is_valid_pred_split_pair(
        source_block: int,
        via_pred: int | None,
        builder: ModificationBuilder,
    ) -> bool:
        if via_pred is None:
            return False
        if builder.block_nsucc_map.get(source_block, 1) != 1:
            return False
        if builder.block_nsucc_map.get(via_pred, 1) != 1:
            return False
        succs = tuple(builder.block_succ_map.get(via_pred, ()))
        return len(succs) == 1 and succs[0] == source_block

    @staticmethod
    def _can_duplicate_path_tail(
        source_block: int,
        via_pred: int | None,
        edge: StateDagEdge,
        flow_graph: object,
    ) -> bool:
        if via_pred is None:
            return False
        src_snapshot = flow_graph.get_block(source_block)
        pred_snapshot = flow_graph.get_block(via_pred)
        if src_snapshot is None or pred_snapshot is None:
            return False
        if src_snapshot.nsucc != 1:
            return False
        if pred_snapshot.nsucc == 1:
            return tuple(pred_snapshot.succs) == (source_block,)
        if pred_snapshot.nsucc != 2:
            return False
        if (
            edge.source_anchor.kind != RedirectSourceKind.CONDITIONAL_BRANCH
            or edge.source_anchor.block_serial != via_pred
            or edge.source_anchor.branch_arm != 1
        ):
            return False
        succs = tuple(pred_snapshot.succs)
        return len(succs) == 2 and succs[1] == source_block

    @staticmethod
    def _block_writes_redirected_state(
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None,
        dispatcher_lookup: object | None,
        target_entry: int,
    ) -> bool:
        if (
            mba is None
            or state_var_stkoff is None
            or dispatcher_lookup is None
            or not callable(dispatcher_lookup)
        ):
            return False
        try:
            block = mba.get_mblock(block_serial)
        except Exception:
            return False
        if block is None:
            return False

        resolved_targets: set[int] = set()
        insn = block.head
        while insn is not None:
            if insn.opcode == ida_hexrays.m_mov:
                d = insn.d
                l = insn.l
                if (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s is not None
                    and d.s.off == state_var_stkoff
                    and l is not None
                    and l.t == ida_hexrays.mop_n
                ):
                    try:
                        resolved = dispatcher_lookup(l.nnn.value)
                    except Exception:
                        resolved = None
                    if resolved is not None:
                        resolved_targets.add(int(resolved))
            insn = insn.next
        return resolved_targets == {target_entry}

    @classmethod
    def _emit_path_tail_redirect(
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
    ) -> bool:
        if not edge.ordered_path or edge.target_entry_anchor is None:
            return False
        if edge.source_key.handler_serial in report_exit_handlers:
            return False
        if edge.ordered_path and edge.ordered_path[0] in report_exit_handlers:
            return False

        source_block = edge.ordered_path[-1]
        target_entry = cls._resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
        )
        if target_entry is None:
            return False
        if source_block == target_entry:
            return False
        if source_block in report_exit_owned_blocks:
            return False
        if source_block in blocked_sources:
            return False
        if source_block in terminal_protected_blocks:
            return False

        source_snapshot = flow_graph.get_block(source_block)
        if source_snapshot is None or source_snapshot.nsucc != 1:
            return False

        old_target = cls._resolve_edge_old_target(
            source_block,
            edge,
            builder,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
        )
        if old_target is None or old_target == target_entry:
            return False

        emit_key = (source_block, target_entry)
        if emit_key in emitted:
            return False

        npreds = len(tuple(source_snapshot.preds))
        if (
            npreds > 1
            and cls._block_writes_redirected_state(
                mba,
                source_block,
                state_var_stkoff=state_var_stkoff,
                dispatcher_lookup=dispatcher_lookup,
                target_entry=target_entry,
            )
        ):
            existing_target = claimed_exits.get(source_block)
            if existing_target is not None:
                if existing_target == target_entry:
                    return False
                return False
            existing_1way_target = claimed_1way.get(source_block)
            if existing_1way_target is not None:
                if existing_1way_target == target_entry:
                    return False
                return False
            modifications.append(
                builder.goto_redirect(
                    source_block=source_block,
                    target_block=target_entry,
                    old_target=old_target,
                )
            )
            claimed_exits[source_block] = target_entry
            claimed_1way[source_block] = target_entry
            emitted.add(emit_key)
            owned_blocks.add(source_block)
            owned_edges.add((source_block, target_entry))
            if edge.source_key.state_const is not None and edge.target_state is not None:
                owned_transitions.add(
                    (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                )
            logger.info(
                "LFG DAG: shared tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
            return True

        if npreds <= 1:
            existing_target = claimed_exits.get(source_block)
            if existing_target is not None:
                if existing_target == target_entry:
                    return False
                return False
            existing_1way_target = claimed_1way.get(source_block)
            if existing_1way_target is not None:
                if existing_1way_target == target_entry:
                    return False
                return False
            modifications.append(
                builder.goto_redirect(
                    source_block=source_block,
                    target_block=target_entry,
                    old_target=old_target,
                )
            )
            claimed_exits[source_block] = target_entry
            claimed_1way[source_block] = target_entry
            emitted.add(emit_key)
            owned_blocks.add(source_block)
            owned_edges.add((source_block, target_entry))
            if edge.source_key.state_const is not None and edge.target_state is not None:
                owned_transitions.add(
                    (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                )
            logger.info(
                "LFG DAG: path-tail redirect %s -> %s via %s",
                blk_label(mba, source_block),
                blk_label(mba, target_entry),
                edge.kind.name.lower(),
            )
            return True

        via_pred = edge.ordered_path[-2] if len(edge.ordered_path) >= 2 else None
        if cls._is_valid_pred_split_pair(source_block, via_pred, builder):
            assert via_pred is not None
            if via_pred in blocked_sources:
                return False
            if via_pred in terminal_protected_blocks:
                return False
            edge_key = (source_block, via_pred)
            existing_target = claimed_path_edges.get(edge_key)
            if existing_target is not None:
                if existing_target == target_entry:
                    return False
                return False
            modifications.append(
                builder.edge_redirect(
                    source_block=source_block,
                    target_block=target_entry,
                    old_target=old_target,
                    via_pred=via_pred,
                )
            )
            claimed_path_edges[edge_key] = target_entry
            blocked_sources.add(via_pred)
            emitted.add(emit_key)
            owned_blocks.add(source_block)
            owned_blocks.add(via_pred)
            owned_edges.add((source_block, target_entry))
            if edge.source_key.state_const is not None and edge.target_state is not None:
                owned_transitions.add(
                    (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                )
            logger.info(
                "LFG DAG: path-tail pred-split %s via %s -> %s",
                blk_label(mba, source_block),
                blk_label(mba, via_pred),
                blk_label(mba, target_entry),
            )
            return True

        if cls._can_duplicate_path_tail(source_block, via_pred, edge, flow_graph):
            assert via_pred is not None
            if via_pred in blocked_sources:
                return False
            other_preds = [
                pred for pred in tuple(source_snapshot.preds)
                if pred != via_pred
            ]
            if other_preds:
                modifications.append(
                    builder.duplicate_and_redirect(
                        source_block=source_block,
                        per_pred_targets=[
                            (other_preds[0], old_target),
                            (via_pred, target_entry),
                        ],
                    )
                )
                blocked_sources.add(via_pred)
                emitted.add(emit_key)
                owned_blocks.add(source_block)
                owned_blocks.add(via_pred)
                owned_blocks.add(other_preds[0])
                owned_edges.add((source_block, target_entry))
                if edge.source_key.state_const is not None and edge.target_state is not None:
                    owned_transitions.add(
                        (edge.source_key.state_const, edge.target_state & 0xFFFFFFFF)
                    )
                logger.info(
                    "LFG DAG: path-tail duplicate %s via %s -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, via_pred),
                    blk_label(mba, target_entry),
                )
                return True

        return False

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
    ) -> bool:
        node_by_key = {node.key: node for node in dag.nodes}
        target_node = node_by_key.get(edge.target_key) if edge.target_key is not None else None
        target_entry = cls._resolve_redirect_safe_target_entry(
            dag,
            edge,
            bst_node_blocks=bst_node_blocks,
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
        if edge.source_key.handler_serial in report_exit_handlers:
            return False
        if edge.ordered_path and edge.ordered_path[0] in report_exit_handlers:
            return False
        if source_block == target_entry:
            return False
        if source_block in blocked_sources:
            return False
        if source_block in terminal_protected_blocks:
            return False
        if source_block in report_exit_owned_blocks:
            return False
        if (
            edge.kind == SemanticEdgeKind.TRANSITION
            and source_block in terminal_source_owned_blocks
        ):
            return False
        if edge.ordered_path and source_block != edge.ordered_path[-1]:
            return False

        emit_key = (source_block, target_entry)
        if emit_key in emitted:
            return False

        nsucc = builder.block_nsucc_map.get(source_block, 1)
        if nsucc == 2 and edge.kind == SemanticEdgeKind.TRANSITION:
            return False
        old_target = cls._resolve_edge_old_target(
            source_block,
            edge,
            builder,
            bst_node_blocks=bst_node_blocks,
            dispatcher_region=dispatcher_region,
        )
        if nsucc == 2:
            if old_target is None or old_target == target_entry:
                return False
            branch_key = (source_block, old_target)
            existing_target = claimed_2way.get(branch_key)
            if existing_target is not None:
                if existing_target == target_entry:
                    return False
                logger.info(
                    "LFG DAG: conflict on 2-way %s old=%s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, old_target),
                    blk_label(mba, existing_target),
                    blk_label(mba, target_entry),
                )
                return False
            modifications.append(
                builder.edge_redirect(
                    source_block=source_block,
                    target_block=target_entry,
                    old_target=old_target,
                )
            )
            claimed_2way[branch_key] = target_entry
        else:
            existing_target = claimed_1way.get(source_block)
            if existing_target is not None and existing_target != target_entry:
                logger.info(
                    "LFG DAG: conflict on 1-way %s: already -> %s, skipping -> %s",
                    blk_label(mba, source_block),
                    blk_label(mba, existing_target),
                    blk_label(mba, target_entry),
                )
                return False
            modifications.append(
                builder.goto_redirect(
                    source_block=source_block,
                    target_block=target_entry,
                    old_target=old_target,
                )
            )
            claimed_1way[source_block] = target_entry

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

        # Build reverse map: state_value -> handler serial (entry block)
        state_to_serial: dict[int, int] = {}
        for serial, state_val in handler_state_map.items():
            state_to_serial[state_val] = serial

        # Classify each handler and collect edges
        #
        # Categories:
        #   resolved   - has at least one successfully redirected transition
        #   exit       - terminal handler (no outgoing transitions)
        #   unresolved - has transitions but none were resolved
        #   conditional - has 2+ distinct to_states (branching handler)

        # Group transitions by from_state
        transitions_by_from: dict[int, list] = {}
        for t in sm.transitions:
            if t.from_state is not None:
                transitions_by_from.setdefault(t.from_state, []).append(t)

        # Track per-handler resolution status
        node_states: set[int] = set()  # all handler state values
        resolved_edges: list[tuple[int, int, bool]] = []  # (from_state, to_state, is_conditional)
        exit_states: set[int] = set()
        unresolved_states: set[int] = set()

        # Collect the range_map for fallback resolution (same logic as plan())
        range_map: dict[int, tuple[int | None, int | None]] = getattr(
            bst_result, "handler_range_map", {}
        ) or {}

        for state_val, handler in sm.handlers.items():
            node_states.add(state_val)
            handler_transitions = transitions_by_from.get(state_val, [])

            if not handler_transitions:
                exit_states.add(state_val)
                continue

            has_resolved = False
            for t in handler_transitions:
                # Resolve to_state the same way plan() does
                target_entry = resolve_target_via_bst(bst_result, t.to_state)
                if target_entry is None:
                    for serial, (low, high) in range_map.items():
                        lo = low if low is not None else 0
                        hi = high if high is not None else 0xFFFFFFFF
                        if lo <= t.to_state <= hi:
                            target_entry = serial
                            break

                if target_entry is not None:
                    # Map target serial back to state value
                    target_state = handler_state_map.get(target_entry)
                    if target_state is not None:
                        resolved_edges.append(
                            (state_val, target_state, t.is_conditional)
                        )
                        has_resolved = True
                    else:
                        # Target is a known block but not in handler_state_map
                        # (could be a non-handler block). Still mark as resolved.
                        has_resolved = True

            if not has_resolved:
                unresolved_states.add(state_val)

        # Deduplicate edges (same from/to pair may appear from multiple transitions)
        seen_edges: set[tuple[int, int, bool]] = set()
        unique_edges: list[tuple[int, int, bool]] = []
        for edge in resolved_edges:
            if edge not in seen_edges:
                seen_edges.add(edge)
                unique_edges.append(edge)

        # Count conditional nodes (handlers with 2+ distinct targets)
        targets_per_handler: dict[int, set[int]] = {}
        for from_s, to_s, _ in unique_edges:
            targets_per_handler.setdefault(from_s, set()).add(to_s)
        conditional_states: set[int] = {
            s for s, targets in targets_per_handler.items() if len(targets) >= 2
        }

        # Build DOT lines
        dot: list[str] = []
        dot.append("digraph resolved_state_machine {")
        dot.append("    rankdir=LR;")
        dot.append("    node [shape=record];")

        # START node
        initial_state = sm.initial_state
        if initial_state is not None:
            dot.append("")
            dot.append("    START [shape=point];")
            dot.append('    START -> "0x%08X";' % initial_state)

        # Node declarations
        dot.append("")
        for state_val in sorted(node_states):
            serial = state_to_serial.get(state_val, -1)
            label_parts = ["0x%08X" % state_val, "blk[%d]" % serial]

            if state_val in exit_states:
                label_parts.append("EXIT")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=lightgreen];'
                    % (state_val, "\\n".join(label_parts))
                )
            elif state_val in unresolved_states:
                label_parts.append("UNRESOLVED")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=orange];'
                    % (state_val, "\\n".join(label_parts))
                )
            elif state_val in conditional_states:
                label_parts.append("BRANCH")
                dot.append(
                    '    "0x%08X" [label="%s" style=filled fillcolor=lightskyblue];'
                    % (state_val, "\\n".join(label_parts))
                )
            else:
                dot.append(
                    '    "0x%08X" [label="%s"];'
                    % (state_val, "\\n".join(label_parts))
                )

        # Edges
        dot.append("")
        for from_s, to_s, is_cond in unique_edges:
            if is_cond:
                dot.append(
                    '    "0x%08X" -> "0x%08X" [color=blue];'
                    % (from_s, to_s)
                )
            else:
                dot.append(
                    '    "0x%08X" -> "0x%08X";' % (from_s, to_s)
                )

        # Self-loop for unresolved states
        for state_val in sorted(unresolved_states):
            dot.append(
                '    "0x%08X" -> "0x%08X" [style=dashed color=red];'
                % (state_val, state_val)
            )

        dot.append("}")

        # Summary counts
        n_resolved = len(node_states) - len(exit_states) - len(unresolved_states)
        n_edges = len(unique_edges)

        logger.info(
            "LFG resolved graph: %d nodes, %d edges, %d resolved, "
            "%d unresolved, %d exits, %d conditional",
            len(node_states),
            n_edges,
            n_resolved,
            len(unresolved_states),
            len(exit_states),
            len(conditional_states),
        )

        # Emit DOT graph
        logger.info("LFG_RESOLVED_GRAPH_DOT_START")
        for line in dot:
            logger.info(line)
        logger.info("LFG_RESOLVED_GRAPH_DOT_END")

    # ------------------------------------------------------------------
    # EXIT state resolution via handler_state_map
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_exit_states(
        snapshot: AnalysisSnapshot,
        sm: DispatcherStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
    ) -> int:
        """Resolve EXIT handlers whose walker entered a BST node instead of
        the real handler body.

        For each handler state that has NO outgoing transition in
        ``sm.transitions``, look up the correct entry block via the inverted
        ``handler_state_map``, BFS from that block to find ``m_mov #const,
        state_var`` instructions, then resolve the constant via the BST to
        wire the handler exit to the correct target.

        Returns:
            Number of redirects emitted by this pass.
        """
        mba = snapshot.mba
        if mba is None:
            return 0

        # Build inverted map: state_value -> correct handler entry serial.
        # handler_state_map shape: {handler_serial: state_value}
        state_to_entry: dict[int, int] = {
            v: k for k, v in handler_state_map.items()
        }
        # Also store the dispatcher reference for fallback lookup on
        # states that are only reachable via wide BST range intervals.
        _exit_dispatcher = getattr(bst_result, "dispatcher", None)

        # Resolve state variable stkoff (same logic as _nop_state_variable_writes).
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info(
                "LFG EXIT: cannot resolve state_var stkoff, skipping"
            )
            return 0

        # Identify states with outgoing transitions.
        states_with_outgoing: set[int] = {
            t.from_state for t in sm.transitions
            if t.from_state is not None
        }

        # Also exclude self-loop-skipped states: states where the only
        # transitions have from_block == target_entry (already skipped in
        # main loop).
        self_loop_only: set[int] = set()
        for state_val, handler in sm.handlers.items():
            if state_val not in states_with_outgoing:
                continue
            handler_transitions = [
                t for t in sm.transitions if t.from_state == state_val
            ]
            all_self_loop = True
            for t in handler_transitions:
                target = resolve_target_via_bst(bst_result, t.to_state)
                if target is None or t.from_block != target:
                    all_self_loop = False
                    break
            if all_self_loop and handler_transitions:
                self_loop_only.add(state_val)

        # Find EXIT states: handlers with no outgoing transition (or only
        # self-loops that were skipped).
        exit_states: list[int] = []
        for state_val in sm.handlers:
            if state_val in states_with_outgoing and state_val not in self_loop_only:
                continue
            exit_states.append(state_val)

        if not exit_states:
            logger.info("LFG EXIT: no EXIT states found")
            return 0

        logger.info(
            "LFG EXIT: found %d EXIT states: %s",
            len(exit_states),
            ["0x%X" % s for s in exit_states],
        )

        resolved_count = 0
        max_bfs_depth = 6

        for state_val in exit_states:
            handler = sm.handlers[state_val]
            correct_entry = state_to_entry.get(state_val)
            # Fallback: use IntervalDispatcher for range-matched states.
            if correct_entry is None and _exit_dispatcher is not None:
                correct_entry = _exit_dispatcher.lookup(state_val)
                if correct_entry is not None:
                    logger.info(
                        "LFG EXIT: DISP_LOOKUP state 0x%X -> %s "
                        "(via IntervalDispatcher)",
                        state_val,
                        blk_label(mba, correct_entry),
                    )
            if correct_entry is None:
                if state_val in self_loop_only:
                    logger.info(
                        "LFG EXIT: skipping self-loop state 0x%X "
                        "(not in handler_state_map)",
                        state_val,
                    )
                    continue
                # BST boundary state — try direct BST walk to find target block.
                dispatcher_serial = snapshot.bst_dispatcher_serial
                if dispatcher_serial >= 0 and bst_node_blocks:
                    target_serial = resolve_via_bst_walk(
                        mba, dispatcher_serial, state_val, bst_node_blocks,
                    )
                    if target_serial is not None:
                        # Find from_block: look for a transition that writes
                        # this state value so we know the exit block.
                        from_block: int | None = None
                        for t in sm.transitions:
                            if t.to_state == state_val:
                                from_block = t.from_block
                                break
                        if from_block is None:
                            # Fallback: use handler's check/entry block.
                            from_block = (
                                handler.handler_blocks[0]
                                if handler.handler_blocks
                                else handler.check_block
                            )
                        if from_block in bst_node_blocks:
                            logger.info(
                                "LFG EXIT: BST walk skipping state 0x%X "
                                "— from_block %s is BST node",
                                state_val,
                                blk_label(mba, from_block),
                            )
                            continue
                        if from_block != target_serial:
                            emit_key = (from_block, target_serial)
                            if emit_key not in emitted:
                                emitted.add(emit_key)
                                from_nsucc = builder.block_nsucc_map.get(
                                    from_block, 1,
                                )
                                if from_nsucc == 2:
                                    bst_old_target: int | None = None
                                    from_succs = builder.block_succ_map.get(
                                        from_block, (),
                                    )
                                    for succ_serial in from_succs:
                                        if succ_serial in bst_node_blocks:
                                            bst_old_target = succ_serial
                                            break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial not in owned_blocks:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial in dispatcher_region:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is None:
                                        for succ_serial in from_succs:
                                            if succ_serial != target_serial:
                                                bst_old_target = succ_serial
                                                break
                                    if bst_old_target is not None:
                                        mod = builder.edge_redirect(
                                            source_block=from_block,
                                            target_block=target_serial,
                                            old_target=bst_old_target,
                                        )
                                        modifications.append(mod)
                                        owned_edges.add(
                                            (from_block, target_serial),
                                        )
                                        resolved_count += 1
                                        logger.info(
                                            "LFG EXIT: BST walk resolved "
                                            "state 0x%X: %s -> %s "
                                            "(2-way, old_target=%s)",
                                            state_val,
                                            blk_label(mba, from_block),
                                            blk_label(mba, target_serial),
                                            blk_label(mba, bst_old_target),
                                        )
                                        continue
                                else:
                                    if from_block in claimed_1way:
                                        first_target = claimed_1way[from_block]
                                        if first_target != target_serial:
                                            logger.info(
                                                "LFG EXIT: BST walk CONFLICT "
                                                "on 1-way %s: already "
                                                "-> %s, skipping "
                                                "-> %s",
                                                blk_label(mba, from_block),
                                                blk_label(mba, first_target),
                                                blk_label(mba, target_serial),
                                            )
                                            continue
                                        else:
                                            continue
                                    mod = builder.goto_redirect(
                                        source_block=from_block,
                                        target_block=target_serial,
                                    )
                                    claimed_1way[from_block] = target_serial
                                    modifications.append(mod)
                                    owned_edges.add(
                                        (from_block, target_serial),
                                    )
                                    resolved_count += 1
                                    logger.info(
                                        "LFG EXIT: BST walk resolved "
                                        "state 0x%X: %s -> %s "
                                        "(1-way)",
                                        state_val,
                                        blk_label(mba, from_block),
                                        blk_label(mba, target_serial),
                                    )
                                    continue
                logger.info(
                    "LFG EXIT: state 0x%X not in handler_state_map "
                    "and BST walk failed, skipping",
                    state_val,
                )
                continue

            current_entry = handler.handler_blocks[0] if handler.handler_blocks else handler.check_block

            logger.info(
                "LFG EXIT: state 0x%X: handler entry %s, "
                "correct entry %s%s",
                state_val,
                blk_label(mba, current_entry),
                blk_label(mba, correct_entry),
                " (MISMATCH)" if current_entry != correct_entry else "",
            )

            # BFS from the correct entry block to find m_mov #const, state_var.
            visited: set[int] = set()
            queue: list[tuple[int, int]] = [(correct_entry, 0)]  # (serial, depth)
            found_writes: list[tuple[int, int, int]] = []  # (blk_serial, insn_ea, const_value)

            while queue:
                blk_serial, depth = queue.pop(0)
                if blk_serial in visited:
                    continue
                visited.add(blk_serial)

                # Skip BST nodes -- they compare the state var, not write it.
                if blk_serial in bst_node_blocks:
                    continue

                try:
                    blk = mba.get_mblock(blk_serial)  # type: ignore[attr-defined]
                except (AttributeError, IndexError):
                    continue
                if blk is None:
                    continue

                # Walk all instructions in this block looking for
                # m_mov #const, state_var.
                insn = blk.head
                while insn is not None:
                    if insn.opcode == ida_hexrays.m_mov:
                        d = insn.d
                        if (
                            d is not None
                            and d.t == ida_hexrays.mop_S
                            and d.s is not None
                            and d.s.off == stkoff
                            and insn.l is not None
                            and insn.l.t == ida_hexrays.mop_n
                        ):
                            const_val = insn.l.nnn.value
                            found_writes.append(
                                (blk_serial, insn.ea, const_val)
                            )
                            logger.info(
                                "LFG EXIT: state 0x%X: found m_mov #0x%X, "
                                "state_var in %s",
                                state_val,
                                const_val,
                                blk_label(mba, blk_serial),
                            )
                    insn = insn.next

                # Continue BFS to successors within depth limit.
                if depth < max_bfs_depth:
                    try:
                        nsucc = blk.nsucc()
                        for i in range(nsucc):
                            succ_serial = blk.succ(i)
                            if succ_serial not in visited:
                                queue.append((succ_serial, depth + 1))
                    except Exception:
                        pass

            if not found_writes:
                logger.info(
                    "LFG EXIT: state 0x%X: no state var writes found via "
                    "BFS from %s (depth %d, visited %d blocks)",
                    state_val,
                    blk_label(mba, correct_entry),
                    max_bfs_depth,
                    len(visited),
                )
                continue

            # For each found write, resolve the target handler and emit a
            # redirect from the write block back to the correct handler.
            for write_blk, write_ea, exit_state_value in found_writes:
                target_entry = resolve_target_via_bst(
                    bst_result, exit_state_value
                )
                if target_entry is None:
                    logger.info(
                        "LFG EXIT: state 0x%X: exit value 0x%X from "
                        "%s resolves to None, skipping",
                        state_val,
                        exit_state_value,
                        blk_label(mba, write_blk),
                    )
                    continue

                # Skip self-loop redirects.
                if write_blk == target_entry:
                    logger.info(
                        "LFG EXIT: state 0x%X: skipping self-loop "
                        "%s -> %s",
                        state_val,
                        blk_label(mba, write_blk),
                        blk_label(mba, target_entry),
                    )
                    continue

                emit_key = (write_blk, target_entry)
                if emit_key in emitted:
                    continue
                emitted.add(emit_key)

                # Determine from_block: the block that writes the exit
                # state and needs its successor redirected.  For 1-way
                # blocks this is the write block itself.  For 2-way
                # blocks we find the dispatcher-bound successor leg.
                from_block = write_blk
                from_nsucc = builder.block_nsucc_map.get(from_block, 1)

                if from_nsucc == 2:
                    bst_old_target: int | None = None
                    from_succs = builder.block_succ_map.get(
                        from_block, ()
                    )
                    for succ_serial in from_succs:
                        if succ_serial in bst_node_blocks:
                            bst_old_target = succ_serial
                            break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial not in owned_blocks:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial in dispatcher_region:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial != target_entry:
                                bst_old_target = succ_serial
                                break

                    if bst_old_target is None:
                        logger.info(
                            "LFG EXIT: state 0x%X: cannot determine "
                            "old_target for 2-way %s, skipping",
                            state_val,
                            blk_label(mba, from_block),
                        )
                        continue

                    mod = builder.edge_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                        old_target=bst_old_target,
                    )
                else:
                    # 1-way: check for shared tail conflict.
                    if from_block in claimed_1way:
                        first_target = claimed_1way[from_block]
                        if first_target != target_entry:
                            logger.info(
                                "LFG EXIT: CONFLICT on 1-way %s: "
                                "already -> %s, skipping -> %s",
                                blk_label(mba, from_block),
                                blk_label(mba, first_target),
                                blk_label(mba, target_entry),
                            )
                            continue
                        else:
                            continue  # already emitted
                    mod = builder.goto_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                    )
                    claimed_1way[from_block] = target_entry

                modifications.append(mod)
                owned_edges.add((from_block, target_entry))
                owned_transitions.add((state_val, exit_state_value))
                resolved_count += 1

                logger.info(
                    "LFG EXIT: resolved state 0x%X: %s -> %s "
                    "(exit value 0x%X)",
                    state_val,
                    blk_label(mba, from_block),
                    blk_label(mba, target_entry),
                    exit_state_value,
                )

        logger.info(
            "LFG: resolved %d EXIT states via handler_state_map",
            resolved_count,
        )
        return resolved_count

    # ------------------------------------------------------------------
    # BST default block transition discovery via DFS forward evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_bst_default_transitions(
        snapshot: AnalysisSnapshot,
        sm: DispatcherStateMachine,
        bst_result: object,
        handler_state_map: dict[int, int],
        bst_node_blocks: set[int],
        dispatcher_region: set[int],
        builder: ModificationBuilder,
        modifications: list,
        owned_blocks: set[int],
        owned_edges: set[tuple[int, int]],
        owned_transitions: set[tuple[int, int]],
        emitted: set[tuple[int, int]],
        claimed_1way: dict[int, int],
    ) -> int:
        """Discover handler transitions through BST default blocks via DFS.

        Some handlers exit through BST default blocks whose state values
        are computed via MBA expressions (e.g., ``v7 ^ v8``).  The
        analysis-phase walker cannot resolve these because multi-predecessor
        constant folding fails.  :func:`evaluate_handler_paths` carries
        per-handler operand context through BST nodes and can
        forward-evaluate these expressions to discover the concrete exit
        state.

        This method iterates all handlers, runs ``evaluate_handler_paths``
        on each, and for any newly-discovered transition whose target
        handler entry is not yet covered by an emitted redirect, emits a
        redirect modification.

        Returns:
            Number of new redirects emitted.
        """
        mba = snapshot.mba
        if mba is None:
            return 0

        # Resolve state variable stkoff (same pattern as _resolve_exit_states).
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info(
                "LFG BST-default: cannot resolve state_var stkoff, skipping"
            )
            return 0

        # Compute the set of handler entry serials already targeted by
        # an emitted redirect.  These are the *targets* (second element)
        # of each emitted (from_block, to_block) pair.
        covered_entries: set[int] = {to_blk for _, to_blk in emitted}

        # All handler entry serials from the handler_state_map.
        all_handler_entries: set[int] = set(handler_state_map.keys())
        uncovered_entries: set[int] = all_handler_entries - covered_entries

        if not uncovered_entries:
            logger.info(
                "LFG BST-default: all %d handler entries already covered",
                len(all_handler_entries),
            )
            return 0

        # Only run BST default discovery when enough handlers are uncovered
        # to justify the risk. Small numbers indicate the main loop + exit resolver
        # already handled the function well.
        uncovered_ratio = len(uncovered_entries) / len(handler_state_map) if handler_state_map else 0
        if len(uncovered_entries) < 3 and uncovered_ratio < 0.15:
            logger.info(
                "LFG BST-default: skipping, %d uncovered (%.0f%%) below both thresholds",
                len(uncovered_entries), uncovered_ratio * 100,
            )
            return 0

        logger.info(
            "LFG BST-default: %d uncovered handler entries out of %d: %s",
            len(uncovered_entries),
            len(all_handler_entries),
            sorted(uncovered_entries),
        )

        # Build the set of handler entry blocks for the DFS boundary guard.
        handler_entry_blocks: set[int] = set(handler_state_map.values())

        resolved_count = 0

        for handler_state, handler_entry in handler_state_map.items():
            # Run DFS forward evaluation from this handler.
            paths = evaluate_handler_paths(
                mba=mba,
                entry_serial=handler_entry,
                incoming_state=handler_state,
                bst_node_blocks=bst_node_blocks,
                state_var_stkoff=stkoff,
                handler_entry_blocks=handler_entry_blocks,
            )

            for path_result in paths:
                if path_result.final_state is None:
                    continue

                final_state = path_result.final_state & 0xFFFFFFFF
                from_block = path_result.exit_block

                # Resolve the final state to a handler entry serial.
                target_entry = resolve_target_via_bst(
                    bst_result, final_state,
                )
                if target_entry is None:
                    continue

                # Only interested in transitions to uncovered entries.
                if target_entry not in uncovered_entries:
                    continue

                # Skip self-loop redirects.
                if from_block == target_entry:
                    continue

                # Deduplicate.
                emit_key = (from_block, target_entry)
                if emit_key in emitted:
                    continue
                emitted.add(emit_key)

                # Don't redirect from a block that's already committed
                # to redirect to a covered handler.
                source_serial = from_block
                if source_serial in owned_blocks:
                    continue

                # Emit the redirect (same pattern as main loop).
                from_nsucc = builder.block_nsucc_map.get(from_block, 1)

                if from_nsucc == 2:
                    bst_old_target: int | None = None
                    from_succs = builder.block_succ_map.get(
                        from_block, (),
                    )
                    for succ_serial in from_succs:
                        if succ_serial in bst_node_blocks:
                            bst_old_target = succ_serial
                            break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial not in owned_blocks:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial in dispatcher_region:
                                bst_old_target = succ_serial
                                break
                    if bst_old_target is None:
                        for succ_serial in from_succs:
                            if succ_serial != target_entry:
                                bst_old_target = succ_serial
                                break

                    if bst_old_target is None:
                        logger.info(
                            "LFG BST-default: cannot determine old_target "
                            "for 2-way %s, skipping",
                            blk_label(mba, from_block),
                        )
                        continue

                    mod = builder.edge_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                        old_target=bst_old_target,
                    )
                else:
                    # 1-way: check for shared tail conflict.
                    if from_block in claimed_1way:
                        first_target = claimed_1way[from_block]
                        if first_target != target_entry:
                            logger.info(
                                "LFG BST-default: CONFLICT on 1-way "
                                "%s: already -> %s, skipping "
                                "-> %s",
                                blk_label(mba, from_block),
                                blk_label(mba, first_target),
                                blk_label(mba, target_entry),
                            )
                            continue
                        else:
                            continue  # already emitted
                    mod = builder.goto_redirect(
                        source_block=from_block,
                        target_block=target_entry,
                    )
                    claimed_1way[from_block] = target_entry

                modifications.append(mod)
                owned_edges.add((from_block, target_entry))
                owned_transitions.add((handler_state, final_state))
                resolved_count += 1

                # Mark this entry as covered so subsequent iterations
                # don't re-discover the same target.
                uncovered_entries.discard(target_entry)

                logger.info(
                    "LFG BST-default: discovered transition "
                    "handler 0x%X %s -> state 0x%X -> "
                    "handler %s (from_block=%s)",
                    handler_state,
                    blk_label(mba, handler_entry),
                    final_state,
                    blk_label(mba, target_entry),
                    blk_label(mba, from_block),
                )

            # Early exit: all uncovered entries now covered.
            if not uncovered_entries:
                break

        logger.info(
            "LFG BST-default: discovered %d new transitions, "
            "%d entries still uncovered",
            resolved_count,
            len(uncovered_entries),
        )
        return resolved_count

    # ------------------------------------------------------------------
    # State variable write NOPing
    # ------------------------------------------------------------------

    @staticmethod
    def _nop_state_variable_writes(
        snapshot: AnalysisSnapshot,
        builder: ModificationBuilder,
        handler_blocks: set[int],
        redirected_states: set[int],
        bst_node_blocks: set[int],
    ) -> tuple[list, set[int], dict[int, int]]:
        """NOP instructions that write to the state variable in ALL mba blocks.

        After handler exits are redirected away from the BST dispatcher, ALL
        state variable writes are dead code -- the state variable is only read
        by BST comparison blocks, which become unreachable once writes stop.

        This scans every block in the mba (not just handler-owned blocks)
        because shared tail blocks between handlers and the BST dispatcher
        also write the state variable but aren't in any handler's block set.

        BST node blocks are excluded because they READ the state variable
        (comparison blocks), not write it.

        Args:
            snapshot: Immutable analysis snapshot for the current function.
            builder: Modification builder for emitting NOP edits.
            handler_blocks: Set of block serials belonging to handlers.
            redirected_states: Set of handler from_state values that had at
                least one successful redirect emitted.
            bst_node_blocks: Set of BST node block serials to exclude from
                NOPing (these READ the state variable).

        Returns:
            A tuple of (list of NOP modifications, set of block serials
            touched, dict mapping block_serial to NOP'd constant value for
            blocks where the source operand was mop_n).
        """
        logger.info(
            "LFG NOP: entering _nop_state_variable_writes "
            "(redirected_states=%d, handler_blocks=%d, bst_node_blocks=%d)",
            len(redirected_states), len(handler_blocks), len(bst_node_blocks),
        )
        sm = snapshot.state_machine
        if sm is None:
            logger.info("LFG NOP: sm is None, bailing")
            return [], set()

        # Resolve state variable stack offset.
        stkoff: int | None = None
        detector = snapshot.detector
        if detector is not None:
            try:
                stkoff = _get_state_var_stkoff(detector)
            except Exception:
                pass
        if stkoff is None and sm.state_var is not None:
            try:
                if sm.state_var.t == ida_hexrays.mop_S:
                    stkoff = sm.state_var.s.off
            except Exception:
                pass

        if stkoff is None:
            logger.info("LFG: cannot resolve state_var stkoff, skipping NOP pass")
            return [], set()

        mba = snapshot.mba
        if mba is None:
            logger.info("LFG NOP: snapshot.mba is None, bailing")
            return [], set()
        logger.info(
            "LFG NOP: stkoff=0x%x, mba.qty=%d, bst_node_blocks=%s",
            stkoff, mba.qty, sorted(bst_node_blocks),
        )

        modifications: list = []
        nop_blocks: set[int] = set()
        nop_state_values: dict[int, int] = {}
        nop_count = 0
        blocks_scanned = 0
        serial = -1

        try:
            for blk_idx in range(mba.qty):  # type: ignore[attr-defined]
                try:
                    blk = mba.get_mblock(blk_idx)  # type: ignore[attr-defined]
                except (AttributeError, IndexError):
                    continue
                if blk is None:
                    continue

                serial = blk.serial

                # Skip BST node blocks -- they READ the state variable
                # (comparison blocks), not write it.
                if serial in bst_node_blocks:
                    continue

                blocks_scanned += 1
                insn = blk.head
                while insn is not None:
                    # Check if the destination operand writes to the state variable.
                    d = insn.d
                    if (
                        d is not None
                        and d.t == ida_hexrays.mop_S
                        and d.s is not None
                        and d.s.off == stkoff
                    ):
                        modifications.append(
                            builder.nop_instruction(
                                source_block=serial,
                                instruction_ea=insn.ea,
                            )
                        )
                        nop_blocks.add(serial)
                        nop_count += 1
                        # Record the NOP'd constant value when the source
                        # operand is a numeric constant (mop_n).
                        l = insn.l
                        if l is not None and l.t == ida_hexrays.mop_n:
                            nop_state_values[serial] = l.nnn.value
                            logger.info(
                                "LFG NOP: %s recorded NOP'd state value 0x%X",
                                blk_label(mba, serial),
                                nop_state_values[serial],
                            )
                    insn = insn.next
        except Exception as exc:
            logger.info(
                "LFG NOP: scan loop CRASHED at %s after scanning %d blocks, "
                "%d NOPs so far: %s",
                blk_label(mba, serial), blocks_scanned, nop_count, exc,
            )

        logger.info(
            "LFG: NOP'd %d state variable writes across %d blocks "
            "(scanned %d of %d total, excluded %d BST node blocks, "
            "%d constant values recorded)",
            nop_count,
            len(nop_blocks),
            blocks_scanned,
            mba.qty,
            len(bst_node_blocks),
            len(nop_state_values),
        )

        return modifications, nop_blocks, nop_state_values

    @staticmethod
    def _nop_dispatcher_gotos(
        snapshot: AnalysisSnapshot,
        dispatcher_serial: int,
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
    ) -> tuple[list, int, int]:
        """Disabled -- dispatcher goto NOPs are no longer emitted.

        Previously NOP'd ``m_goto @dispatcher`` instructions in handler blocks.
        This caused issues with blocks becoming unreachable dead-ends before
        the dispatcher was fully disconnected.  The BST disconnect pass
        (step 4) handles dispatcher back-edge removal more safely.

        Returns:
            An empty tuple of ``([], 0, 0)``.
        """
        return [], 0, 0

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
        if dispatcher_serial < 0:
            return 0

        # Build set of block serials that already have a redirect from
        # the main handler-linearization pass.  These blocks must NOT
        # receive a second conflicting redirect.
        already_redirected: set[int] = {src for src, _ in emitted}

        disconnect_count = 0
        # Scan ALL blocks in the flow graph, not just BST nodes.
        for serial in sorted(builder.block_nsucc_map):
            # Skip the dispatcher itself.
            if serial == dispatcher_serial:
                continue
            # Skip blocks already handled by the main redirect pass.
            if serial in already_redirected:
                continue

            nsucc = builder.block_nsucc_map.get(serial, 0)
            if nsucc != 2:
                continue

            succs = list(builder.block_succ_map.get(serial, ()))
            if len(succs) != 2:
                continue

            succ0, succ1 = succs[0], succs[1]

            # Check if either successor is the dispatcher.
            if succ0 != dispatcher_serial and succ1 != dispatcher_serial:
                continue

            # Keep the non-dispatcher successor.
            keep_serial = succ1 if succ0 == dispatcher_serial else succ0

            emit_key = (serial, keep_serial)
            if emit_key in emitted:
                continue
            emitted.add(emit_key)

            mod = builder.convert_to_goto(serial, keep_serial)
            modifications.append(mod)
            disconnect_count += 1

            is_bst = serial in bst_node_blocks
            logger.info(
                "BST_DISCONNECT: %s (%s) 2-way -> 1-way goto "
                "%s (removed dispatcher back-edge to %s)",
                blk_label(mba, serial) if mba else f"blk[{serial}]",
                "BST" if is_bst else "handler",
                blk_label(mba, keep_serial) if mba else f"blk[{keep_serial}]",
                blk_label(mba, dispatcher_serial) if mba else f"blk[{dispatcher_serial}]",
            )

        return disconnect_count

    @staticmethod
    def _convert_bst_nodes_to_goto(
        bst_node_blocks: set[int],
        flow_graph: object | None,
        builder: ModificationBuilder,
        modifications: list,
        emitted: set[tuple[int, int]],
        *,
        mba: object | None = None,
    ) -> int:
        """Convert BST comparison blocks from 2-way to unconditional goto.

        After linearization, handler exits bypass the dispatcher/BST
        entirely.  However, IDA rebuilds edges from instruction operands,
        so the BST comparison tree (``m_jae``/``m_jnz`` testing the state
        var) survives as ``while``-loop nesting.  Converting each BST
        2-way block to a 1-way goto destroys the comparison instruction,
        making the BST dead code.

        This is complementary to :meth:`_disconnect_bst_comparison_nodes`
        which only handles blocks with the dispatcher as a direct
        successor.  This pass catches BST-internal nodes (BST node to
        BST node edges) that were not covered.

        Args:
            bst_node_blocks: Set of BST comparison block serials.
            flow_graph: The flow graph snapshot (``snapshot.flow_graph``).
            builder: Modification builder for emitting graph edits.
            modifications: List to append new modifications to.
            emitted: Set of ``(from, to)`` pairs for dedup.

        Returns:
            Number of BST blocks converted to goto.
        """
        if flow_graph is None or not bst_node_blocks:
            return 0

        _BLT_2WAY = ida_hexrays.BLT_2WAY
        already_redirected: set[int] = {src for src, _ in emitted}
        bst_converted = 0

        for bst_serial in sorted(bst_node_blocks):
            # Skip blocks already handled by disconnect or redirect passes.
            if bst_serial in already_redirected:
                continue

            bst_snap = flow_graph.get_block(bst_serial)
            if bst_snap is None:
                continue
            if bst_snap.block_type != _BLT_2WAY:
                logger.debug(
                    "BST_CONVERT: skip %s -- not BLT_2WAY (type=%d)",
                    blk_label(mba, bst_serial) if mba else f"blk[{bst_serial}]",
                    bst_snap.block_type,
                )
                continue
            if len(bst_snap.succs) < 1:
                logger.debug(
                    "BST_CONVERT: skip %s -- no successors",
                    blk_label(mba, bst_serial) if mba else f"blk[{bst_serial}]",
                )
                continue

            # Use fallthrough successor (succs[0]) as the goto target.
            fallthrough_target = bst_snap.succs[0]

            emit_key = (bst_serial, fallthrough_target)
            if emit_key in emitted:
                continue
            emitted.add(emit_key)

            modifications.append(
                builder.convert_to_goto(bst_serial, fallthrough_target),
            )
            bst_converted += 1
            logger.info(
                "BST_CONVERT: %s 2-way -> goto %s",
                blk_label(mba, bst_serial) if mba else f"blk[{bst_serial}]",
                blk_label(mba, fallthrough_target) if mba else f"blk[{fallthrough_target}]",
            )

        if bst_converted > 0:
            logger.info(
                "BST comparison elimination: %d/%d BST blocks converted "
                "to goto",
                bst_converted, len(bst_node_blocks),
            )
        return bst_converted

    @staticmethod
    def _disconnect_bst_entries(
        bst_node_blocks: set[int],
        builder: ModificationBuilder,
        owned_edges: set[tuple[int, int]],
        modifications: list,
        emitted: set[tuple[int, int]],
        stop_serial: int = -1,
    ) -> int:
        """Disconnect BST leaf -> handler entry edges.

        After linearization, handler entries are reachable via goto chains.
        BST leaf comparison nodes still have edges pointing to handler entries,
        keeping the BST tree alive in the decompiled output.  This pass
        redirects those BST leaf -> handler edges to BLT_STOP, making
        handler entries ONLY reachable via the linearized goto chain.
        The BST tree becomes dead-ended and IDA DCEs it.

        Args:
            bst_node_blocks: Set of BST node block serials.
            builder: Modification builder for emitting edge redirects.
            owned_edges: Set of (from, to) edges from the linearization pass.
            modifications: List to append new modifications to.
            emitted: Set of (from, to) pairs for dedup.
            stop_serial: Serial of BLT_STOP block (redirect target).

        Returns:
            Number of BST leaf edges disconnected.
        """
        if stop_serial < 0:
            return 0
        linearized_entries: set[int] = {target for _, target in owned_edges}

        disconnect_count = 0
        disconnected_nodes: set[int] = set()
        for bst_serial in sorted(bst_node_blocks):
            nsucc = builder.block_nsucc_map.get(bst_serial, 0)
            if nsucc != 2:
                continue

            succs = list(builder.block_succ_map.get(bst_serial, ()))
            if len(succs) != 2:
                continue

            for idx, succ in enumerate(succs):
                if bst_serial in disconnected_nodes:
                    break  # only one redirect per BST node
                if succ not in linearized_entries:
                    continue
                if succ in bst_node_blocks:
                    continue  # internal BST edge, not a leaf -> handler
                other_succ = succs[1 - idx]
                if other_succ == stop_serial:
                    continue  # other succ is already BLT_STOP, skip

                emit_key = ("bst_disconnect", bst_serial, succ)
                if emit_key in emitted:
                    continue

                mod = builder.edge_redirect(
                    source_block=bst_serial,
                    target_block=stop_serial,
                    old_target=succ,
                )
                modifications.append(mod)
                emitted.add(emit_key)
                disconnected_nodes.add(bst_serial)
                disconnect_count += 1
                logger.info(
                    "LFG BST-DISCONNECT: blk[%d] edge to handler blk[%d] "
                    "-> redirected to BLT_STOP blk[%d]",  # no mba available in this static method
                    bst_serial,
                    succ,
                    stop_serial,
                )

        return disconnect_count
