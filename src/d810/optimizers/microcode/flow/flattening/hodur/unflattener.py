"""Thin orchestrator for the Hodur strategy-based unflattening pipeline.

This module contains the new ``HodurUnflattener`` class which replaces the
monolithic implementation in ``unflattener_hodur.py``.  All heavy analysis
logic lives in the hodur sub-package; this class is a thin coordinator that:

1. Detects the Hodur state machine via :class:`HodurStateMachineDetector`.
2. Builds an immutable :class:`AnalysisSnapshot`.
3. Collects :class:`PlanFragment` objects from each registered strategy.
4. Composes the pipeline via :class:`UnflatteningPlanner`.
5. Applies it via :class:`TransactionalExecutor`.

Gate operation mode: ``GATE_SELECT`` — full recon + gate enforcement + planner
hint influence.  See :class:`~d810.core.gate_modes.GateOperationMode`.

# ORCHESTRATOR_BOUNDARY: This module is a thin coordinator.  It does NOT
# perform strategy selection, conflict resolution, or pipeline reordering.
# Those are owned exclusively by the UnflatteningPlanner (see planner.py).
#
# After planner.plan() returns:
#   - The pipeline is passed to executor.execute_pipeline() WITHOUT
#     modification (no filtering, reordering, insertion, or dropping).
#   - Executor results are mapped to provenance lifecycle phases
#     (APPLIED, GATE_FAILED, PREFLIGHT_REJECTED, BYPASSED) -- this is
#     lifecycle bookkeeping, not re-arbitration.
"""
from __future__ import annotations

import ida_hexrays
from pathlib import Path

from d810.core import logging
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_formatters import format_mop_t
from d810.recon.flow.dispatcher_detection import (
    DispatcherCache,
)
from d810.optimizers.microcode.flow.flattening.generic import GenericUnflatteningRule
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HODUR_STATE_UPDATE_OPCODES,
    MAX_STATE_CONSTANTS_HODUR,
    MIN_STATE_CONSTANT,
    MIN_STATE_CONSTANTS,
    HodurStateMachineDetector,
)
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    HandlerPathResult,
    HodurStateMachine,
    Pass0RedirectRecord,
)
from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import ALL_STRATEGIES
from d810.optimizers.microcode.flow.flattening.hodur.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.hodur.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    GateAccounting,
    PipelineProvenance,
    PlannerInputs,
)
from d810.cfg.flow.graph_checks import SemanticGate
from d810.hexrays.mutation.cfg_mutations import make_2way_block_goto

from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    StageResult,
    VerificationGate,
)
from d810.optimizers.microcode.flow.flattening.hodur.executor import (
    TransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_terminal_return_audit_from_store,
    load_transition_report_from_store,
    record_return_frontier_stage,
    save_terminal_return_audit_to_store,
    save_transition_report_to_store,
    write_return_frontier_artifact_from_store,
)

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)


class HodurUnflattener(GenericUnflatteningRule):
    """Unflattener for Hodur-style while-loop state machines.

    This rule detects and removes control flow flattening that uses nested
    while(1) loops with a state variable, as seen in Hodur malware.

    Orchestrates a strategy pipeline:

    1. :class:`~hodur.analysis.HodurStateMachineDetector` detects the state
       machine.
    2. An immutable :class:`~hodur.snapshot.AnalysisSnapshot` is constructed.
    3. Each registered strategy proposes a
       :class:`~hodur.strategy.PlanFragment`.
    4. :class:`~hodur.planner.UnflatteningPlanner` composes the pipeline.
    5. :class:`~hodur.executor.TransactionalExecutor` applies stages.
    """

    DESCRIPTION = "Remove Hodur-style while-loop control flow flattening"
    DEFAULT_UNFLATTENING_MATURITIES = [
        ida_hexrays.MMAT_GLBOPT1,
        ida_hexrays.MMAT_GLBOPT2,
    ]
    RETURN_FRONTIER_AUDIT_ENABLED: bool = True  # Default on for debugging
    DEFAULT_MAX_PASSES = 3
    HARD_MAX_PASSES = 10
    MOP_TRACKER_MAX_NB_BLOCK = 100
    MOP_TRACKER_MAX_NB_PATH = 100

    CONFIG_SCHEMA = GenericUnflatteningRule.CONFIG_SCHEMA + (
        ConfigParam(
            "min_state_constant",
            int,
            MIN_STATE_CONSTANT,
            "Minimum value to qualify as a state constant",
        ),
        ConfigParam(
            "min_state_constants",
            int,
            MIN_STATE_CONSTANTS,
            "Minimum unique state constants for state machine detection",
        ),
        ConfigParam(
            "max_state_constants",
            int,
            MAX_STATE_CONSTANTS_HODUR,
            "Maximum state constants before classifying as OLLVM-style",
        ),
        ConfigParam(
            "max_passes",
            int,
            DEFAULT_MAX_PASSES,
            "Maximum unflattening passes",
        ),
        ConfigParam(
            "allow_legacy_block_creation",
            bool,
            True,
            "Allow legacy live block-creating edits until symbolic PatchPlan materialization lands",
        ),
    )

    def __init__(self) -> None:
        super().__init__()
        self.state_machine: HodurStateMachine | None = None
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.min_state_constant = MIN_STATE_CONSTANT
        self.min_state_constants = MIN_STATE_CONSTANTS
        self.max_state_constants = MAX_STATE_CONSTANTS_HODUR
        self.allow_legacy_block_creation = True
        self._actual_pass_count: int = 0
        self._current_tracked_maturity: int = ida_hexrays.MMAT_ZERO
        self._resolved_transitions: set[tuple[int, int]] = set()
        self._initial_transitions: list | None = None
        self._detector: HodurStateMachineDetector | None = None
        self._pass0_redirect_ledger: list[Pass0RedirectRecord] = []
        self._pass0_handler_entries: set[int] = set()
        self._last_redirect_meta: dict | None = None
        self._last_provenance: PipelineProvenance | None = None

        # Strategy pipeline components — disable fallback strategies until
        # rollback infrastructure is reliable (see semantic-gate-replacement plan).
        _DISABLED_STRATEGIES = {
            "PredPatchFallbackStrategy",
            "ConditionalForkFallbackStrategy",
            "AssignmentMapFallbackStrategy",
        }
        self._strategies = [
            cls()
            for cls in ALL_STRATEGIES
            if cls.__name__ not in _DISABLED_STRATEGIES
        ]
        unflat_logger.info(
            "Active strategies: %s",
            [type(s).__name__ for s in self._strategies],
        )
        self._planner = UnflatteningPlanner(PipelinePolicy())
        self._gate = SemanticGate()
        self._cfg_translator = IDAIRTranslator()

        # Return frontier audit components
        self._return_site_provider = HodurReturnSiteProvider()
        self._audit_return_sites: tuple = ()  # Populated at pre_plan, reused across stages

    def configure(self, kwargs: dict) -> None:
        super().configure(kwargs)
        if "min_state_constant" in self.config:
            self.min_state_constant = int(self.config["min_state_constant"])
        if "min_state_constants" in self.config:
            self.min_state_constants = int(self.config["min_state_constants"])
        if "max_state_constants" in self.config:
            self.max_state_constants = int(self.config["max_state_constants"])
        if "max_passes" in self.config:
            self.max_passes = int(self.config["max_passes"])
        if "allow_legacy_block_creation" in self.config:
            self.allow_legacy_block_creation = bool(
                self.config["allow_legacy_block_creation"]
            )

    def check_if_rule_should_be_used(self, blk: ida_hexrays.mblock_t) -> bool:
        """Check if this rule should be applied."""
        if not super().check_if_rule_should_be_used(blk):
            return False

        # Reset pass count on maturity change
        if self.mba.maturity != self._current_tracked_maturity:
            self._current_tracked_maturity = self.mba.maturity
            self._actual_pass_count = 0
            self.max_passes = self.DEFAULT_MAX_PASSES
            self._resolved_transitions = set()
            self._initial_transitions = None
            self._pass0_redirect_ledger = []
            self._pass0_handler_entries = set()
            self._last_redirect_meta = None
            # Reset audit for new maturity
            if self.RETURN_FRONTIER_AUDIT_ENABLED:
                self._audit_return_sites = ()

        # Gate on actual Hodur runs, not block callback count
        if self._actual_pass_count >= self.max_passes:
            return False

        return True

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point — planner + strategy pipeline."""
        self.mba = blk.mba

        if not self.check_if_rule_should_be_used(blk):
            return 0

        unflat_logger.debug(
            "HodurUnflattener: Starting pass %d/%d at maturity %d",
            self._actual_pass_count,
            self.max_passes,
            self.cur_maturity,
        )

        if self._actual_pass_count == 0:
            self._pass0_redirect_ledger = []
            self._pass0_handler_entries = set()
            self._last_redirect_meta = None

        # 1. Detect state machine
        detector = HodurStateMachineDetector(
            self.mba,
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
        )
        state_machine = detector.detect()
        self._detector = detector

        if state_machine is None:
            # Fallback to robust cache analysis
            cache = DispatcherCache.get_or_create(self.mba)
            analysis = cache.analyze()
            if analysis.is_conditional_chain:
                state_machine = self._build_state_machine_from_cache(analysis)

        if state_machine is None:
            unflat_logger.info("No Hodur state machine detected")
            self._actual_pass_count += 1
            return 0

        self.state_machine = state_machine

        # Save full transition list from first detection for carry-forward
        if self._actual_pass_count == 0:
            self._initial_transitions = list(state_machine.transitions)

        # Log the detected structure
        self._log_state_machine()

        # 2. Build immutable snapshot (includes BST analysis, reachability, etc.)
        snapshot = self._build_snapshot(self.mba, state_machine, detector)

        # 3-4. PLANNER_AUTHORITY: planner owns strategy polling + pipeline composition
        transition_report = load_transition_report_from_store(
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
        )
        return_frontier_audit = load_return_frontier_audit_from_store(
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
        )
        terminal_return_audit = load_terminal_return_audit_from_store(
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
        )
        planner_inputs = PlannerInputs(
            total_handlers=snapshot.handler_count,
            handler_transitions=transition_report,
            return_frontier=return_frontier_audit,
            terminal_return_audit=terminal_return_audit,
        )
        pipeline, provenance = self._planner.plan(
            snapshot, self._strategies, inputs=planner_inputs,
        )

        # Return frontier audit: pre_plan stage (after fragment collection so
        # handler_paths from DirectLinearization strategy are available)
        if self.RETURN_FRONTIER_AUDIT_ENABLED:
            handler_paths = self._extract_handler_paths_from_fragments(pipeline)
            try:
                self._audit_pre_plan(snapshot, handler_paths=handler_paths)
            except Exception:
                unflat_logger.debug("_audit_pre_plan failed (non-critical), continuing")

        if not pipeline:
            unflat_logger.info("No strategy produced a plan fragment")
            self._actual_pass_count += 1
            return 0

        self._last_provenance = provenance
        unflat_logger.info("Planner provenance: %s", provenance.summary())

        # Return frontier audit: post_plan stage (mods queued but not applied)
        if self.RETURN_FRONTIER_AUDIT_ENABLED and self._audit_return_sites:
            try:
                self._record_audit_stage("post_plan")
            except Exception:
                unflat_logger.debug("_record_audit_stage(post_plan) failed (non-critical)")

        # 5. EXECUTOR_BOUNDARY: executor consumes pipeline in-order, no reordering
        executor = TransactionalExecutor(
            self.mba,
            gate=self._gate,
            allow_legacy_block_creation=self.allow_legacy_block_creation,
        )
        results = executor.execute_pipeline(pipeline, total_handlers=snapshot.handler_count)

        nb_changes = executor.total_changes

        # 5b. ORCHESTRATOR_BOUNDARY: update provenance phases from executor outcomes
        # (lifecycle bookkeeping only -- no re-selection or pipeline mutation)
        for frag, result in zip(pipeline, results):
            acct: GateAccounting | None = result.metadata.get("gate_accounting")
            if result.success:
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.APPLIED,
                    reason_code=DecisionReasonCode.ACCEPTED,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "preflight":
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.PREFLIGHT_REJECTED,
                    reason_code=DecisionReasonCode.REJECTED_PREFLIGHT,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "safeguard":
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_GATE_SAFEGUARD,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "semantic_gate":
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_GATE_SEMANTIC,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )
            elif result.failure_phase == "post_apply_contract":
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_GATE,
                    reason_detail=result.error,
                    gate_accounting=acct,
                )
            elif not result.success:
                provenance = provenance.update_phase(
                    frag.strategy_name,
                    DecisionPhase.GATE_FAILED,
                    reason_code=DecisionReasonCode.REJECTED_TRANSACTION,
                    reason_detail=result.error or "execution failed",
                    gate_accounting=acct,
                )
        # Mark unexecuted pipeline tail (fragments after early abort) as BYPASSED
        for frag in pipeline[len(results):]:
            provenance = provenance.update_phase(
                frag.strategy_name,
                DecisionPhase.BYPASSED,
                reason_code=DecisionReasonCode.BYPASSED_PIPELINE_ABORT,
                reason_detail="pipeline aborted before this fragment was executed",
            )
        self._last_provenance = provenance

        # Record planner outcome via flow context callback
        if self.flow_context is not None and hasattr(self.flow_context, 'report_outcome'):
            self.flow_context.report_outcome(provenance, "planner")

        # Persist terminal return audit from executor results (for next pass)
        for result in results:
            audit = result.metadata.get("terminal_return_audit")
            if audit is not None:
                save_terminal_return_audit_to_store(
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    audit=audit,
                    log_dir=self.log_dir,
                )
                break

        # Return frontier audit: post_apply stage
        if self.RETURN_FRONTIER_AUDIT_ENABLED and self._audit_return_sites:
            try:
                self._record_audit_stage("post_apply")
            except Exception:
                unflat_logger.debug("_record_audit_stage(post_apply) failed (non-critical)")

        # 5c. Post-apply: disconnect BST comparison nodes and dispatcher
        # Gate to first pass only — BST cleanup invalidates state analysis,
        # so a second Hodur pass would crash (RuntimeError 52719).
        bst_cleanup_ran = False
        if nb_changes > 0 and self._actual_pass_count == 0 and snapshot.bst_result is not None:
            bst_cleanup_edges = self._post_apply_bst_cleanup(
                snapshot.bst_result.bst_node_blocks,
                snapshot.bst_dispatcher_serial,
            )
            if bst_cleanup_edges > 0:
                nb_changes += bst_cleanup_edges
                bst_cleanup_ran = True

        # 6. Log summary
        self._log_pipeline_results(results, nb_changes)
        unflat_logger.info("Provenance: %s", provenance.phase_summary())
        if unflat_logger.debug_on:
            import json
            unflat_logger.debug(
                "Provenance detail: %s",
                json.dumps(provenance.to_dict(), indent=2),
            )

        # Adaptive convergence: extend max_passes when making progress
        if nb_changes > 0 and self.max_passes < self.HARD_MAX_PASSES:
            self.max_passes += 1
            unflat_logger.debug(
                "HodurUnflattener: progress detected, extending max_passes to %d",
                self.max_passes,
            )

        # Update resolved transitions tracking
        if nb_changes > 0:
            for t in state_machine.transitions:
                self._resolved_transitions.add((t.from_state, t.to_state))

        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            self._actual_pass_count,
            nb_changes,
        )

        if nb_changes == 0:
            unflat_logger.info(
                "HodurUnflattener: convergence reached at pass %d, maturity %d",
                self._actual_pass_count,
                self.cur_maturity,
            )

        self._actual_pass_count += 1

        # Return frontier audit: post_pipeline stage + artifact write
        if self.RETURN_FRONTIER_AUDIT_ENABLED and self._audit_return_sites:
            try:
                self._record_audit_stage("post_pipeline")
                write_return_frontier_artifact_from_store(
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    log_dir=self.log_dir,
                    artifact_dir=Path(f".tmp/recon/{self.cur_maturity}"),
                )
                audit = load_return_frontier_audit_from_store(
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    log_dir=self.log_dir,
                )
                if audit is not None:
                    audit.summary_log()
            except Exception:
                unflat_logger.debug("post_pipeline audit failed (non-critical)")

        # BST cleanup invalidates dispatcher/BST state — suppress re-iteration
        # so IDA does not invoke Hodur again on the cleaned CFG.
        if bst_cleanup_ran:
            unflat_logger.info(
                "BST cleanup modified CFG — suppressing Hodur re-iteration"
            )
            nb_changes = 0

        return nb_changes

    # ------------------------------------------------------------------
    # Return frontier audit helpers
    # ------------------------------------------------------------------

    def _build_successor_map(self) -> dict[int, list[int]]:
        """Build successor map from current MBA state."""
        succs: dict[int, list[int]] = {}
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            succs[i] = [blk.succ(j) for j in range(blk.nsucc())]
        return succs

    def _find_exit_blocks(self) -> frozenset[int]:
        """Find blocks with 0 successors (function exits)."""
        exits: set[int] = set()
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk.nsucc() == 0:
                exits.add(i)
        return frozenset(exits)

    def _extract_handler_paths_from_fragments(
        self, fragments: list
    ) -> "dict[int, list[HandlerPathResult]]":
        """Extract handler_paths from the DirectLinearization fragment metadata.

        Iterates collected fragments and returns the handler_paths dict from
        the first fragment that contains it (direct_handler_linearization strategy).
        Falls back to empty dict when no fragment provides handler_paths.

        Args:
            fragments: List of PlanFragment objects collected from strategies.

        Returns:
            Mapping of handler_serial -> list[HandlerPathResult], or empty dict.
        """
        for fragment in fragments:
            hp = fragment.metadata.get("handler_paths")
            if hp:
                unflat_logger.info(
                    "Extracted handler_paths from fragment '%s': %d handlers",
                    fragment.strategy_name,
                    len(hp),
                )
                return hp
        return {}

    def _audit_pre_plan(
        self,
        snapshot: AnalysisSnapshot,
        handler_paths: "dict[int, list[HandlerPathResult]] | None" = None,
    ) -> None:
        """Collect return sites and record pre_plan audit stage.

        Builds return sites from the dispatcher transition report (handler-centric),
        so each EXIT/UNKNOWN handler becomes a distinct site keyed by handler_serial.
        Falls back to MBA exit block scan when the transition report is unavailable.

        Args:
            snapshot: Current immutable analysis snapshot.
            handler_paths: Optional mapping of handler_serial -> evaluated paths
                (retained for signature compatibility; no longer the primary source).
        """
        from d810.recon.flow.transition_report import build_dispatcher_transition_report

        # Build return_sites once per maturity level
        if not self._audit_return_sites:
            report = load_transition_report_from_store(
                func_ea=self.mba.entry_ea,
                maturity=self.cur_maturity,
                log_dir=self.log_dir,
            )
            used_report = False
            if report is not None and report.rows:
                self._audit_return_sites = self._return_site_provider.collect_return_sites(
                    report
                )
                used_report = True
                unflat_logger.info(
                    "RETURN_FRONTIER_AUDIT: using recon-store transition report "
                    "(%d rows -> %d sites)",
                    len(report.rows),
                    len(self._audit_return_sites),
                )
            elif snapshot.bst_dispatcher_serial >= 0:
                try:
                    stkoff = self._get_effective_state_var_stkoff(snapshot.state_machine)
                    report = build_dispatcher_transition_report(
                        snapshot.mba,
                        snapshot.bst_dispatcher_serial,
                        state_var_stkoff=stkoff,
                    )
                    save_transition_report_to_store(
                        func_ea=self.mba.entry_ea,
                        maturity=self.cur_maturity,
                        report=report,
                        log_dir=self.log_dir,
                    )
                except Exception as exc:
                    report = None
                    unflat_logger.info(
                        "RETURN_FRONTIER_AUDIT: transition report failed (diagnostic only): %s",
                        exc,
                    )

            if report is not None and report.rows and not used_report:
                self._audit_return_sites = self._return_site_provider.collect_return_sites(
                    report
                )
                unflat_logger.info(
                    "RETURN_FRONTIER_AUDIT: using transition report (%d rows -> %d sites)",
                    len(report.rows),
                    len(self._audit_return_sites),
                )
            if not self._audit_return_sites and handler_paths:
                # Fallback: use handler_paths from DirectLinearization fragment
                self._audit_return_sites = self._return_site_provider.collect_return_sites_legacy(
                    snapshot, handler_paths
                )
                unflat_logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to handler_paths (%d handlers -> %d sites)",
                    len(handler_paths),
                    len(self._audit_return_sites),
                )
            if not self._audit_return_sites:
                # Last resort: derive return sites from MBA exit blocks (nsucc==0)
                from d810.cfg.flow.return_frontier import ReturnSite

                exits = self._find_exit_blocks()
                sites: list[ReturnSite] = []
                for blk_serial in sorted(exits):
                    site = ReturnSite(
                        site_id=f"hodur_exit_{blk_serial}",
                        origin_block=blk_serial,
                        guard_hash=f"{blk_serial:016x}",
                        expected_terminal_kind="return",
                        provenance="pre_plan_exit_block_scan",
                    )
                    sites.append(site)
                self._audit_return_sites = tuple(sites)
                unflat_logger.info(
                    "RETURN_FRONTIER_AUDIT: fallback to exit block scan (%d sites)",
                    len(self._audit_return_sites),
                )

        succs = self._build_successor_map()
        exits = self._find_exit_blocks()
        result = record_return_frontier_stage(
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
            return_sites=tuple(self._audit_return_sites),
            successors=succs,
            entry=0,
            exits=exits,
            stage_name="pre_plan",
        )
        unflat_logger.info(
            "RETURN_FRONTIER_AUDIT[pre_plan]: sites=%d broken=%d (diagnostic only, not gated)",
            result.metrics.get("total_sites", 0),
            result.metrics.get("broken_count", 0),
        )

    def _record_audit_stage(self, stage_name: str) -> None:
        """Record a return frontier audit stage from current MBA state."""
        succs = self._build_successor_map()
        exits = self._find_exit_blocks()
        result = record_return_frontier_stage(
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
            return_sites=tuple(self._audit_return_sites),
            successors=succs,
            entry=0,
            exits=exits,
            stage_name=stage_name,
        )
        unflat_logger.info(
            "RETURN_FRONTIER_AUDIT[%s]: sites=%d broken=%d (diagnostic only, not gated)",
            stage_name,
            result.metrics.get("total_sites", 0),
            result.metrics.get("broken_count", 0),
        )

    def _build_snapshot(
        self,
        mba: ida_hexrays.mba_t,
        state_machine: HodurStateMachine,
        detector: HodurStateMachineDetector,
    ) -> AnalysisSnapshot:
        """Build an immutable AnalysisSnapshot from current mba state.

        Runs BST analysis, reachability BFS, and caches auxiliary results
        into the frozen snapshot for strategies to consume without re-computing.
        """
        # BST analysis
        bst_result = None
        bst_dispatcher_serial = -1
        if state_machine.handlers:
            entry_serial = list(state_machine.handlers.values())[0].check_block
            bst_stkoff = self._get_effective_state_var_stkoff(state_machine)
            try:
                from d810.recon.flow.bst_analysis import analyze_bst_dispatcher

                raw_bst = analyze_bst_dispatcher(
                    mba,
                    dispatcher_entry_serial=entry_serial,
                    state_var_stkoff=bst_stkoff,
                )
                if raw_bst is not None and len(raw_bst.handler_state_map) > 0:
                    bst_result = raw_bst
                    bst_dispatcher_serial = entry_serial
            except Exception:
                bst_result = None

        # Lift virtual CFG snapshot once per pass for strategy planning.
        flow_graph = self._cfg_translator.lift(mba)

        # Dispatcher cache
        dispatcher_cache = DispatcherCache.get_or_create(mba)

        # Reachability BFS from block 0
        reachability = self._compute_reachability_info(mba)

        # Supplement transitions from initial detection on subsequent passes
        if self._actual_pass_count > 0 and self._initial_transitions is not None:
            detected_keys = {
                (t.from_state, t.to_state) for t in state_machine.transitions
            }
            supplemented = 0
            for t in self._initial_transitions:
                key = (t.from_state, t.to_state)
                if key not in self._resolved_transitions and key not in detected_keys:
                    state_machine.transitions.append(t)
                    supplemented += 1
            if supplemented:
                unflat_logger.debug(
                    "HodurUnflattener: supplemented %d transitions from initial "
                    "detection (resolved: %d, re-detected: %d)",
                    supplemented,
                    len(self._resolved_transitions),
                    len(detected_keys),
                )

        return AnalysisSnapshot(
            mba=mba,
            state_machine=state_machine,
            detector=detector,
            dispatcher_cache=dispatcher_cache,
            bst_result=bst_result,
            bst_dispatcher_serial=bst_dispatcher_serial,
            reachability=reachability,
            maturity=mba.maturity,
            pass_number=self._actual_pass_count,
            resolved_transitions=frozenset(self._resolved_transitions),
            initial_transitions=tuple(self._initial_transitions or []),
            flow_graph=flow_graph,
        )

    def _get_effective_state_var_stkoff(
        self, state_machine: HodurStateMachine | None = None
    ) -> int | None:
        """Return the stack offset of the state variable, or None on failure.

        Matches the original monolith semantics: returns None so that
        ``analyze_bst_dispatcher`` can auto-detect the stkoff.
        """
        # Try detector first (passes detector object, not mop_t)
        if self._detector is not None:
            try:
                from d810.recon.flow.transition_builder import (
                    _get_state_var_stkoff,
                )

                stkoff = _get_state_var_stkoff(self._detector)
                if stkoff is not None:
                    return stkoff
            except Exception:
                pass

        # Fallback: read mop_S.s.off directly from state_machine.state_var
        sm = state_machine if state_machine is not None else self.state_machine
        if sm is None or sm.state_var is None:
            return None
        import ida_hexrays
        if sm.state_var.t == ida_hexrays.mop_S:
            return sm.state_var.s.off
        return None

    def _compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        """BFS from block 0 to compute reachable block set."""
        qty = mba.qty
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is not None:
                for i in range(blk.nsucc()):
                    queue.append(blk.succ(i))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=qty,
        )

    def _log_state_machine(self) -> None:
        """Log the detected state machine structure."""
        if self.state_machine is None:
            return

        unflat_logger.info("=== Hodur State Machine ===")
        unflat_logger.info(
            "State variable: %s",
            (
                format_mop_t(self.state_machine.state_var)
                if self.state_machine.state_var
                else "unknown"
            ),
        )
        unflat_logger.info(
            "Initial state: %s",
            (
                hex(self.state_machine.initial_state)
                if self.state_machine.initial_state
                else "unknown"
            ),
        )
        unflat_logger.info(
            "State constants: %s",
            ", ".join(hex(c) for c in sorted(self.state_machine.state_constants)),
        )
        unflat_logger.info("Transitions:")
        for t in self.state_machine.transitions:
            unflat_logger.info(
                "  %s -> %s (block %d)",
                hex(t.from_state) if t.from_state is not None else "None",
                hex(t.to_state),
                t.from_block,
            )

    def _log_pipeline_results(
        self, results: list[StageResult], nb_changes: int
    ) -> None:
        """Log a summary of the pipeline execution results."""
        stages_ok = sum(1 for r in results if r.success)
        stages_fail = sum(1 for r in results if not r.success)
        unflat_logger.info(
            "Pipeline results: %d changes, %d stages ok, %d stages failed",
            nb_changes,
            stages_ok,
            stages_fail,
        )
        for result in results:
            if not result.success:
                unflat_logger.warning(
                    "Stage %s failed: %s", result.strategy_name, result.error
                )
            else:
                unflat_logger.debug(
                    "Stage %s: %d edits, reachability=%.2f",
                    result.strategy_name,
                    result.edits_applied,
                    result.reachability_after,
                )

    def _queue_handler_redirect(
        self,
        path: "HandlerPathResult",
        target: int,
        reason: str,
        claimed_exits: dict[int, int],
        claimed_edges: dict[tuple[int, int], int],
        bst_node_blocks: set[int],
        deferred: object | None = None,
    ) -> bool:
        """Queue a goto redirect for one handler exit path, using edge-level split on conflict.

        Fast path: if path.exit_block not yet claimed, queue a plain goto_change.
        Conflict path: if exit_block already claimed for a different target, attempt
        an edge-level redirect (EDGE_REDIRECT_VIA_PRED_SPLIT) using the predecessor
        from path.ordered_path.  Falls back to walking earlier path segments if the
        immediate predecessor edge is already claimed.

        Args:
            path: DFS path result (exit_block, ordered_path, etc.)
            target: Block serial of the desired redirect target.
            reason: Human-readable description string for logging/queuing.
            claimed_exits: Tracks block_serial -> target for already-claimed exits.
            claimed_edges: Tracks (src_block, via_pred) -> target for edge-level claims.
            bst_node_blocks: BST comparison node serials (should not be cloned).

        Returns:
            True if a redirect was successfully queued or already resolved, False on failure.
        """
        def _safe_npred(blk: "ida_hexrays.mblock_t | None") -> int:
            if blk is None:
                return -1
            try:
                return int(blk.npred())
            except Exception:
                return -1

        _deferred = deferred if deferred is not None else self.deferred
        self._last_redirect_meta = None
        exit_blk = self.mba.get_mblock(path.exit_block)

        # Fast path: exit block not yet claimed by any handler.
        if path.exit_block not in claimed_exits:
            _deferred.queue_goto_change(
                block_serial=path.exit_block,
                new_target=target,
                rule_priority=550,
                description=reason,
            )
            claimed_exits[path.exit_block] = target
            unflat_logger.info(
                "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=None"
                " decision=plain reason=%s via_pred_npred=None",
                path.exit_block, target, reason,
            )
            self._last_redirect_meta = {
                "kind": "plain",
                "source_block": path.exit_block,
                "via_pred": None,
                "target": target,
            }
            return True

        # Already claimed for the same target — no-op.
        if claimed_exits[path.exit_block] == target:
            self._last_redirect_meta = {
                "kind": "already_claimed",
                "source_block": path.exit_block,
                "via_pred": None,
                "target": target,
            }
            return True

        # Conflict: exit_block claimed for a different target. Use edge-level redirect.
        if len(path.ordered_path) >= 2:
            via_pred = path.ordered_path[-2]
        else:
            unflat_logger.warning(
                "EDGE_REDIRECT: no via_pred for exit blk[%d] -> target %d "
                "(ordered_path too short: %s)",
                path.exit_block, target, path.ordered_path,
            )
            unflat_logger.info(
                "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=None"
                " decision=skip reason=ordered_path_too_short via_pred_npred=None",
                path.exit_block, target,
            )
            return False

        # Determine old_target (current successor of exit_block leading to dispatcher).
        old_target = 0
        if exit_blk is not None and exit_blk.nsucc() > 0:
            old_target = exit_blk.succ(0)

        # Check if this specific edge is already claimed.
        edge_key = (path.exit_block, via_pred)
        if edge_key in claimed_edges:
            if claimed_edges[edge_key] == target:
                self._last_redirect_meta = {
                    "kind": "already_claimed_edge",
                    "source_block": path.exit_block,
                    "via_pred": via_pred,
                    "target": target,
                }
                return True  # Already claimed for same target.
            # Escalate: walk backward through ordered_path to find an unclaimed edge.
            unflat_logger.info(
                "EDGE_ESCALATION: edge (%d, %d) claimed for %d, searching earlier segment for target %d",
                path.exit_block, via_pred, claimed_edges[edge_key], target,
            )
            found_src: int | None = None
            found_pred: int | None = None
            for i in range(len(path.ordered_path) - 2, 0, -1):
                seg_src = path.ordered_path[i]
                seg_pred = path.ordered_path[i - 1]
                seg_key = (seg_src, seg_pred)
                if seg_key not in claimed_edges and seg_src not in bst_node_blocks:
                    # Validate edge-split preconditions before accepting this pair.
                    seg_src_blk = self.mba.get_mblock(seg_src)
                    seg_pred_blk = self.mba.get_mblock(seg_pred)
                    if seg_src_blk is None or seg_pred_blk is None:
                        continue
                    if seg_src_blk.nsucc() != 1:
                        continue
                    if seg_pred_blk.nsucc() != 1:
                        continue
                    if not any(
                        seg_pred_blk.succ(j) == seg_src
                        for j in range(seg_pred_blk.nsucc())
                    ):
                        continue
                    found_src = seg_src
                    found_pred = seg_pred
                    break
            if found_src is None or found_pred is None:
                unflat_logger.warning(
                    "EDGE_REDIRECT: all path segments claimed for exit blk[%d] -> target %d, "
                    "cannot queue redirect",
                    path.exit_block, target,
                )
                unflat_logger.info(
                    "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                    " decision=skip reason=all_segments_claimed via_pred_npred=None",
                    path.exit_block, target, via_pred,
                )
                return False
            src_block = found_src
            use_pred = found_pred
            src_blk = self.mba.get_mblock(src_block)
            old_target = src_blk.succ(0) if src_blk is not None and src_blk.nsucc() > 0 else 0
            _use_pred_blk = self.mba.get_mblock(use_pred)
            _use_pred_npred = _safe_npred(_use_pred_blk)
            unflat_logger.info(
                "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                " decision=escalated reason=prior_edge_claimed via_pred_npred=%d",
                path.exit_block, target, use_pred, _use_pred_npred,
            )
        else:
            src_block = path.exit_block
            use_pred = via_pred
            _via_pred_blk = self.mba.get_mblock(use_pred)
            _via_pred_npred = _safe_npred(_via_pred_blk)
            unflat_logger.info(
                "REDIRECT_DECISION: exit_blk=%d target=%d via_pred=%d"
                " decision=edge_split reason=exit_claimed via_pred_npred=%d",
                path.exit_block, target, use_pred, _via_pred_npred,
            )

        unflat_logger.info(
            "EDGE_REDIRECT: exit blk[%d] -> target %d conflicts with claimed=%d; "
            "using edge_redirect(src=%d, old=%d, new=%d, via_pred=%d)",
            path.exit_block, target, claimed_exits[path.exit_block],
            src_block, old_target, target, use_pred,
        )
        _deferred.queue_edge_redirect(
            src_block=src_block,
            old_target=old_target,
            new_target=target,
            via_pred=use_pred,
            rule_priority=550,
            description=reason,
        )
        claimed_edges[(src_block, use_pred)] = target
        self._last_redirect_meta = {
            "kind": "edge",
            "source_block": src_block,
            "via_pred": use_pred,
            "target": target,
        }
        return True

    def _post_apply_bst_cleanup(
        self,
        bst_node_blocks: "BSTNodeMap",
        dispatcher_serial: int,
    ) -> int:
        """Sever handler->dispatcher back-edges to eliminate the dispatcher as loop header.

        After linearization, handler exits that couldn't be resolved still have
        edges to the dispatcher (despite NOP'd goto instructions). These edges
        keep the dispatcher as a loop header, creating while loops.

        This method removes these edges by making the blocks 0-way (no successors).
        Handler entries keep their BST predecessors for reachability.
        No blocks are removed or redirected.
        """
        mba = self.mba
        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return 0

        # --- Diagnostic: dispatcher predecessors BEFORE cleanup ---
        unflat_logger.info(
            "Dispatcher blk[%d] npred=%d BEFORE cleanup",
            dispatcher_serial, disp_blk.npred(),
        )
        for i in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(i)
            pred_blk = mba.get_mblock(pred_serial)
            in_bst = pred_serial in bst_serials
            nsucc = pred_blk.nsucc() if pred_blk else -1
            succ_info: list[str] = []
            if pred_blk and nsucc > 0:
                for si in range(nsucc):
                    succ_info.append(str(pred_blk.succ(si)))
            tail_op = "none"
            if pred_blk and pred_blk.tail:
                tail_op = pred_blk.tail.dstr()
            unflat_logger.info(
                "  pred blk[%d] nsucc=%d in_bst=%s succs=[%s] tail=%s",
                pred_serial, nsucc, in_bst,
                ",".join(succ_info), tail_op,
            )

        severed = 0
        severed_2way = 0
        for serial in range(mba.qty):
            if serial in bst_serials:
                continue  # Skip BST/dispatcher blocks
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            if blk.nsucc() != 1:
                continue  # Only handle 1-way blocks
            if blk.succ(0) != dispatcher_serial:
                continue  # Only handle blocks going to dispatcher

            # Sever the edge: make this block 0-way
            blk.succset._del(dispatcher_serial)
            disp_blk.predset._del(serial)
            blk.mark_lists_dirty()
            severed += 1

        # Handle 2-way blocks with one arm going to dispatcher.
        # Convert them to 1-way gotos keeping the non-dispatcher successor.
        for serial in range(mba.qty):
            if serial in bst_serials:
                continue
            blk = mba.get_mblock(serial)
            if blk is None or blk.nsucc() != 2:
                continue
            succ0, succ1 = blk.succ(0), blk.succ(1)
            if succ0 == dispatcher_serial:
                keep_serial = succ1
            elif succ1 == dispatcher_serial:
                keep_serial = succ0
            else:
                continue  # Neither successor is dispatcher
            unflat_logger.info(
                "BST cleanup: converting 2-way blk[%d] (succs=%d,%d) to goto blk[%d]",
                serial, succ0, succ1, keep_serial,
            )
            try:
                make_2way_block_goto(blk, keep_serial, verify=False)
                severed_2way += 1
            except Exception as exc:
                unflat_logger.warning(
                    "BST cleanup: failed to convert 2-way blk[%d]: %s",
                    serial, exc,
                )

        if severed > 0 or severed_2way > 0:
            disp_blk.mark_lists_dirty()

        # Phase 3 (DISABLED): NOP'ing BST/dispatcher block instructions to
        # prevent IDA from regenerating conditional branches at later
        # maturities was attempted but all variants fail:
        #   - NOP BST blocks + sever edges -> INTERR 52719 (orphaned blocks)
        #   - NOP BST blocks, keep edges -> segfault (2-way with no jcc)
        #   - NOP BST body only (keep tail jcc) -> segfault (broken DU chains)
        #   - NOP dispatcher only -> massive handler DCE (state var defs lost)
        #   - NOP tail goto on severed handler blocks -> DCE (0-way dead-ends)
        # IDA's def-use chains depend on BST variable definitions; any NOP
        # in these blocks cascades into handler body elimination.

        # --- Diagnostic: dispatcher predecessors AFTER cleanup ---
        unflat_logger.info(
            "Dispatcher blk[%d] npred=%d AFTER cleanup (severed_1way=%d, severed_2way=%d)",
            dispatcher_serial, disp_blk.npred(), severed, severed_2way,
        )
        for i in range(disp_blk.npred()):
            pred_serial = disp_blk.pred(i)
            pred_blk = mba.get_mblock(pred_serial)
            in_bst = pred_serial in bst_serials
            nsucc = pred_blk.nsucc() if pred_blk else -1
            succ_info_after: list[str] = []
            if pred_blk and nsucc > 0:
                for si in range(nsucc):
                    succ_info_after.append(str(pred_blk.succ(si)))
            unflat_logger.info(
                "  remaining pred blk[%d] nsucc=%d in_bst=%s succs=[%s]",
                pred_serial, nsucc, in_bst,
                ",".join(succ_info_after),
            )

        total_severed = severed + severed_2way
        unflat_logger.info(
            "BST cleanup: severed %d handler->dispatcher back-edges "
            "(%d 1-way, %d 2-way converted to goto)",
            total_severed, severed, severed_2way,
        )
        return total_severed

    def _build_state_machine_from_cache(
        self, analysis: object
    ) -> HodurStateMachine | None:
        """Build a HodurStateMachine from a DispatcherAnalysis cache result.

        This fallback path is used when the primary detector does not find a
        state machine but the dispatcher cache identifies a conditional chain.
        In the strategy-pipeline architecture the primary path (BST-based
        direct linearization) handles the vast majority of cases, so this
        fallback returns ``None`` to let the pipeline attempt recovery on the
        next maturity pass.
        """
        unflat_logger.debug(
            "_build_state_machine_from_cache: cache-based fallback not implemented "
            "in strategy-pipeline mode; returning None"
        )
        return None
