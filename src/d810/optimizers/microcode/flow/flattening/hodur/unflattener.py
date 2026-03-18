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
from d810.hexrays.mutation.cfg_mutations import (
    change_1way_block_successor,
    make_2way_block_goto,
)

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
        self._last_bst_serials: set[int] | None = None
        self._last_dispatcher_serial: int = -1
        self._last_func_ea: int = 0
        # EA-based identification (serials drift between maturities)
        self._last_bst_block_eas: set[int] = set()
        self._last_dispatcher_ea: int = 0

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
                bst_result=snapshot.bst_result,
            )
            if bst_cleanup_edges > 0:
                nb_changes += bst_cleanup_edges
                bst_cleanup_ran = True

            # Diagnostic: backward dispatcher-predecessor scan
            state_var = getattr(snapshot.state_machine, "state_var", None)
            if state_var is not None and state_var.t == ida_hexrays.mop_S:
                self._diagnostic_backward_scan(
                    dispatcher_serial=snapshot.bst_dispatcher_serial,
                    bst_node_blocks=snapshot.bst_result.bst_node_blocks,
                    state_var_stkoff=state_var.s.off,
                    bst_result=snapshot.bst_result,
                    state_var_mop=state_var,
                )

            # Phase 3: diagnostic — log unreachable BST block count
            # (PruneUnreachable disabled: remove_block fails at GLBOPT1
            # with INTERR 51920 regardless of preparation. Keeping
            # diagnostic BFS to track unreachability.)
            bst_serials = set(snapshot.bst_result.bst_node_blocks) | {snapshot.bst_dispatcher_serial}
            self._prune_unreachable_bst_blocks(bst_serials)

            # Persist BST serials + dispatcher serial for hxe_glbopt PruneUnreachable
            self._last_bst_serials = bst_serials
            self._last_dispatcher_serial = snapshot.bst_dispatcher_serial
            self._last_func_ea = self.mba.entry_ea
            # Persist BST block start_ea values (serials drift between maturities)
            self._last_bst_block_eas = set()
            for s in bst_serials:
                blk = self.mba.get_mblock(s)
                if blk is not None:
                    self._last_bst_block_eas.add(blk.start)
            self._last_dispatcher_ea = (
                self.mba.get_mblock(snapshot.bst_dispatcher_serial).start
                if snapshot.bst_dispatcher_serial >= 0
                and self.mba.get_mblock(snapshot.bst_dispatcher_serial) is not None
                else 0
            )

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

    def _dump_post_apply_cfg_dot(
        self,
        dispatcher_serial: int,
        bst_node_blocks: "BSTNodeMap",
    ) -> None:
        """Dump post-apply CFG as DOT graph for linearization verification."""
        mba = self.mba
        bst_serials = set(bst_node_blocks) | {dispatcher_serial}

        lines: list[str] = ["--- POST_APPLY_CFG_DOT_START ---"]
        lines.append("digraph post_apply_cfg {")
        lines.append("  rankdir=TB;")

        dispatcher_preds: list[int] = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue

            # Color: BST=red, handler=lightblue, dispatcher=orange
            if i == dispatcher_serial:
                color = "orange"
                label = f"DISPATCHER\\nblk[{i}]"
            elif i in bst_serials:
                color = "lightcoral"
                label = f"BST\\nblk[{i}]"
            else:
                color = "lightblue"
                label = f"blk[{i}]"

            # Check if any successor is dispatcher
            goes_to_disp = False
            for si in range(blk.nsucc()):
                if blk.succ(si) == dispatcher_serial:
                    goes_to_disp = True

            if goes_to_disp and i not in bst_serials:
                color = "yellow"  # handler block still pointing to dispatcher
                dispatcher_preds.append(i)

            lines.append(
                f'  blk{i} [label="{label}" style=filled fillcolor={color}];'
            )

            for si in range(blk.nsucc()):
                succ = blk.succ(si)
                edge_color = "red" if succ == dispatcher_serial else "black"
                lines.append(f"  blk{i} -> blk{succ} [color={edge_color}];")

        lines.append("}")
        lines.append("--- POST_APPLY_CFG_DOT_END ---")

        for line in lines:
            unflat_logger.info(line)

        unflat_logger.info(
            "POST_APPLY_CFG: %d blocks, %d BST, %d still->dispatcher: %s",
            mba.qty, len(bst_serials), len(dispatcher_preds), dispatcher_preds,
        )

    def _post_apply_bst_cleanup(
        self,
        bst_node_blocks: "BSTNodeMap",
        dispatcher_serial: int,
        bst_result: object | None = None,
    ) -> int:
        """Sever handler->dispatcher back-edges to eliminate the dispatcher as loop header.

        After linearization, handler exits that couldn't be resolved still have
        edges to the dispatcher (despite NOP'd goto instructions). These edges
        keep the dispatcher as a loop header, creating while loops.

        Phase 0 backward-resolves dispatcher predecessors that still have
        ``goto dispatcher`` operands, redirecting them to their target handler
        via ``change_1way_block_successor``.

        Phase 1 severs 1-way handler->dispatcher edges (edge-only: removes from
        succset/predset, marks dirty).

        Phase 2 converts 2-way blocks with one arm going to dispatcher into 1-way
        gotos keeping the non-dispatcher successor.

        Handler entries keep their BST predecessors for reachability.
        """
        mba = self.mba
        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        # --- DOT dump: post-apply CFG before any edge severing ---
        self._dump_post_apply_cfg_dot(dispatcher_serial, bst_node_blocks)

        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return 0

        # --- Phase 0: backward-resolve dispatcher predecessors ---
        # DISABLED: backward_resolve does direct MBA manipulation outside
        # CfgTransactionEngine. All resolution should go through the
        # backward_pred strategy via the pipeline.
        backward_resolved = 0
        # if bst_result is not None:
        #     state_var = getattr(self, "state_machine", None)
        #     sv = getattr(state_var, "state_var", None) if state_var else None
        #     if sv is not None and sv.t == ida_hexrays.mop_S and sv.s is not None:
        #         backward_resolved = self._backward_resolve_dispatcher_preds(
        #             dispatcher_serial, bst_node_blocks, bst_result,
        #             state_var_stkoff=sv.s.off,
        #             state_var_mop=sv,
        #         )

        # --- Diagnostic: dispatcher predecessors BEFORE Phase 1 cleanup ---
        unflat_logger.info(
            "Dispatcher blk[%d] npred=%d BEFORE cleanup (backward_resolved=%d)",
            dispatcher_serial, disp_blk.npred(), backward_resolved,
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

            blk.succset._del(dispatcher_serial)
            disp_blk.predset._del(blk.serial)
            blk.mark_lists_dirty()
            severed += 1
            unflat_logger.info(
                "BST cleanup: severed 1-way blk[%d] -> dispatcher edge",
                blk.serial,
            )

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

        # Phase 3 (old, DISABLED): NOP'ing BST/dispatcher block instructions to
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
            "Dispatcher blk[%d] npred=%d AFTER cleanup "
            "(severed_1way=%d, severed_2way=%d)",
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

        total_severed = severed + severed_2way + backward_resolved
        unflat_logger.info(
            "BST cleanup: severed %d handler->dispatcher back-edges "
            "(%d backward-resolved, %d 1-way, %d 2-way converted to goto)",
            total_severed, backward_resolved, severed, severed_2way,
        )

        # --- Phase 3: sever dispatcher OUTGOING edges to BST comparison blocks ---
        # When the dispatcher has no remaining predecessors, its outgoing edges
        # to BST comparison blocks keep the BST tree reachable.  IDA follows
        # these edges and reconstructs the comparison tree, generating while
        # loops.  Severing them disconnects the BST entirely.
        if disp_blk.npred() == 0:
            succ_serials = [disp_blk.succ(i) for i in range(disp_blk.nsucc())]
            for succ_serial in succ_serials:
                succ_blk = mba.get_mblock(succ_serial)
                if succ_blk is not None:
                    succ_blk.predset._del(dispatcher_serial)
                    succ_blk.mark_lists_dirty()
            disp_blk.succset.clear()
            disp_blk.mark_lists_dirty()
            if succ_serials:
                unflat_logger.info(
                    "BST cleanup: severed %d outgoing dispatcher edges to %s",
                    len(succ_serials), succ_serials,
                )

        return total_severed

    def _prune_unreachable_bst_blocks(self, bst_serials: set[int]) -> int:
        """Remove unreachable BST/dispatcher blocks after linearization.

        Performs a forward BFS from block 0, identifies unreachable BST blocks,
        and removes them using hrtng's DeleteBlock pattern: sever outgoing edges,
        remove instructions via ``remove_from_block`` (NOT ``make_nop``!), set
        block type to ``BLT_NONE``, then ``remove_block``.

        Args:
            bst_serials: Set of BST comparison block serials + dispatcher serial.

        Returns:
            Number of blocks successfully removed.
        """
        from collections import deque

        mba = self.mba

        # Forward BFS from block 0
        visited: set[int] = set()
        queue: deque[int] = deque([0])
        while queue:
            serial = queue.popleft()
            if serial in visited:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for si in range(blk.nsucc()):
                succ = blk.succ(si)
                if succ not in visited:
                    queue.append(succ)

        # Identify unreachable BST blocks
        all_serials = set(range(mba.qty))
        unreachable = all_serials - visited
        unreachable_bst = unreachable & bst_serials

        unflat_logger.info(
            "PruneUnreachable: %d/%d blocks reachable, %d unreachable total, "
            "%d unreachable BST blocks",
            len(visited), mba.qty, len(unreachable), len(unreachable_bst),
        )

        # NOTE: remove_block at GLBOPT1 fails with INTERR 51920 regardless
        # of preparation (edge severing, remove_from_block, forward order).
        # Block removal requires MMAT_LOCOPT maturity (see hrtng).
        # Keeping diagnostic BFS only for now.
        return 0

    def _eval_mba_expression(
        self,
        mop: "ida_hexrays.mop_t",
        blk: "ida_hexrays.mblock_t",
        mba: "ida_hexrays.mbl_array_t",
        bst_serials: set[int],
        depth: int = 0,
    ) -> int | None:
        """Recursively evaluate a microcode operand to a constant.

        Handles: ``mop_n`` (literal), ``mop_S``/``mop_r`` (resolve from
        predecessor blocks), ``mop_d`` (sub-expression with binary ops).

        Args:
            mop: The operand to evaluate.
            blk: The block containing the instruction that uses *mop*.
            mba: The microcode block array.
            bst_serials: Set of BST-internal block serials to avoid walking into.
            depth: Recursion depth guard (max 8).

        Returns:
            Resolved 32-bit constant value, or ``None`` if unresolvable.
        """
        if depth > 8:
            return None
        if mop is None:
            return None

        # --- Literal constant -------------------------------------------------
        if mop.t == ida_hexrays.mop_n:
            return mop.nnn.value

        # --- Stack variable or register — backward-scan for literal def -------
        if mop.t in (ida_hexrays.mop_S, ida_hexrays.mop_r):
            target_stkoff = mop.s.off if mop.t == ida_hexrays.mop_S else None
            target_reg = mop.r if mop.t == ida_hexrays.mop_r else None

            search_blk = blk
            for _ in range(8):
                insn = search_blk.tail
                while insn is not None:
                    if insn.d is not None:
                        match = False
                        if (
                            target_stkoff is not None
                            and insn.d.t == ida_hexrays.mop_S
                            and insn.d.s is not None
                            and insn.d.s.off == target_stkoff
                        ):
                            match = True
                        elif (
                            target_reg is not None
                            and insn.d.t == ida_hexrays.mop_r
                            and insn.d.r == target_reg
                        ):
                            match = True

                        if match and insn.l is not None:
                            if insn.l.t == ida_hexrays.mop_n:
                                return insn.l.nnn.value
                            # Recurse for non-literal source
                            return self._eval_mba_expression(
                                insn.l, search_blk, mba, bst_serials,
                                depth + 1,
                            )
                    insn = insn.prev

                # Walk to single predecessor
                if search_blk.npred() != 1:
                    break
                pred_serial = search_blk.pred(0)
                if pred_serial in bst_serials:
                    break
                search_blk = mba.get_mblock(pred_serial)
                if search_blk is None:
                    break

            return None

        # --- Sub-expression (result of another instruction) -------------------
        if mop.t == ida_hexrays.mop_d:
            sub_insn = mop.d
            if sub_insn is None:
                return None

            # Binary operations
            _BINARY_OPS = {
                ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
                ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
            }
            if sub_insn.opcode in _BINARY_OPS:
                left = self._eval_mba_expression(
                    sub_insn.l, blk, mba, bst_serials, depth + 1,
                )
                right = self._eval_mba_expression(
                    sub_insn.r, blk, mba, bst_serials, depth + 1,
                )
                if left is not None and right is not None:
                    mask = 0xFFFFFFFF  # 32-bit state variable
                    if sub_insn.opcode == ida_hexrays.m_xor:
                        return (left ^ right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_sub:
                        return (left - right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_add:
                        return (left + right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_and:
                        return (left & right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_or:
                        return (left | right) & mask
                    elif sub_insn.opcode == ida_hexrays.m_mul:
                        return (left * right) & mask

            # Unary: m_xdu (zero-extend), m_xds (sign-extend)
            m_xdu = getattr(ida_hexrays, "m_xdu", -1)
            m_xds = getattr(ida_hexrays, "m_xds", -1)
            if sub_insn.opcode in (m_xdu, m_xds):
                return self._eval_mba_expression(
                    sub_insn.l, blk, mba, bst_serials, depth + 1,
                )

            return None

        return None

    # Binary opcodes for 3-operand state var writes (d = op(l, r))
    _STATE_WRITE_BINARY_OPS: frozenset[int] = frozenset()  # populated at import

    @staticmethod
    def _init_binary_ops() -> frozenset[int]:
        """Lazily initialize binary op set (ida_hexrays may not be loaded)."""
        return frozenset({
            ida_hexrays.m_xor, ida_hexrays.m_sub, ida_hexrays.m_add,
            ida_hexrays.m_and, ida_hexrays.m_or, ida_hexrays.m_mul,
        })

    def _resolve_state_write_insn(
        self,
        insn: "ida_hexrays.minsn_t",
        blk: "ida_hexrays.mblock_t",
        mba: "ida_hexrays.mbl_array_t",
        bst_serials: set[int],
    ) -> int | None:
        """Resolve the value written by *insn* to the state variable.

        Handles:
        - ``m_mov d = l``: simple copy, resolve ``l``.
        - 3-operand binary ops (``m_sub``, ``m_xor``, ``m_add``, etc.):
          resolve both ``l`` and ``r``, apply the operation.
        - Fallback: try ``_eval_mba_expression`` on ``l`` alone (legacy).

        Returns:
            Resolved 32-bit constant, or ``None`` if unresolvable.
        """
        # Lazy-init the binary ops frozenset
        if not self._STATE_WRITE_BINARY_OPS:
            HodurUnflattener._STATE_WRITE_BINARY_OPS = self._init_binary_ops()

        mask = 0xFFFFFFFF  # 32-bit state variable

        # --- m_mov: d = l ---
        if insn.opcode == ida_hexrays.m_mov:
            if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
                return insn.l.nnn.value
            # Try recursive MBA eval on source operand
            return self._eval_mba_expression(
                insn.l, blk, mba, bst_serials,
            )

        # --- 3-operand binary ops: d = op(l, r) ---
        if insn.opcode in self._STATE_WRITE_BINARY_OPS:
            left = self._eval_mba_expression(
                insn.l, blk, mba, bst_serials,
            )
            right = self._eval_mba_expression(
                insn.r, blk, mba, bst_serials,
            )
            if left is not None and right is not None:
                if insn.opcode == ida_hexrays.m_xor:
                    return (left ^ right) & mask
                elif insn.opcode == ida_hexrays.m_sub:
                    return (left - right) & mask
                elif insn.opcode == ida_hexrays.m_add:
                    return (left + right) & mask
                elif insn.opcode == ida_hexrays.m_and:
                    return (left & right) & mask
                elif insn.opcode == ida_hexrays.m_or:
                    return (left | right) & mask
                elif insn.opcode == ida_hexrays.m_mul:
                    return (left * right) & mask
                unflat_logger.info(
                    "BACKWARD_RESOLVE: 3-op %d(0x%X, 0x%X) -> resolved",
                    insn.opcode, left, right,
                )
            return None

        # --- Fallback: try MBA eval on l only (covers mop_d sub-expressions) ---
        if insn.l is not None and insn.l.t == ida_hexrays.mop_n:
            return insn.l.nnn.value
        return self._eval_mba_expression(
            insn.l, blk, mba, bst_serials,
        )

    def _backward_resolve_dispatcher_preds(
        self,
        dispatcher_serial: int,
        bst_node_blocks: "BSTNodeMap",
        bst_result: object,
        state_var_stkoff: int,
        state_var_mop: object,
    ) -> int:
        """Backward-resolve handler exits that still target the dispatcher.

        For each dispatcher predecessor that is NOT a BST-internal node,
        walk instructions backward from the block tail looking for a write to
        the state variable.  When a literal constant (or depth-1 copy chain,
        or valrange fallback) resolves the value, look up the target handler
        via BST and redirect the block successor using
        :func:`change_1way_block_successor`.

        This runs BEFORE Phase 1 edge severing so resolved exits get proper
        instruction-operand redirects instead of raw edge removal.

        Args:
            dispatcher_serial: Serial of the dispatcher block.
            bst_node_blocks: BST node block map from analysis.
            bst_result: ``BSTAnalysisResult`` for BST target resolution.
            state_var_stkoff: Stack offset of the state variable.
            state_var_mop: ``mop_t`` for the state variable (``mop_S``).

        Returns:
            Number of blocks successfully redirected.
        """
        from d810.evaluator.hexrays_microcode.valranges import (
            resolve_state_via_valranges,
        )
        from d810.recon.flow.bst_model import resolve_target_via_bst

        mba = self.mba
        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return 0

        for pi in range(disp_blk.npred()):
            ps = disp_blk.pred(pi)
            pb = mba.get_mblock(ps)
            if pb is None:
                continue
            # Count instructions
            ic = 0
            ins = pb.head
            while ins:
                ic += 1
                ins = ins.next
            unflat_logger.info(
                "BACKWARD_RESOLVE: dispatcher pred blk[%d] start_ea=0x%X ninsn=%d npred=%d nsucc=%d",
                ps, pb.start, ic, pb.npred(), pb.nsucc(),
            )

        unflat_logger.info(
            "BACKWARD_RESOLVE: mop_S=%d mop_n=%d mop_r=%d mop_d=%d",
            ida_hexrays.mop_S, ida_hexrays.mop_n,
            ida_hexrays.mop_r, ida_hexrays.mop_d,
        )

        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        pred_serials = [disp_blk.pred(i) for i in range(disp_blk.npred())]

        redirected = 0
        _diag_pred_count = 0  # counter for per-insn diagnostic (first 3 preds)
        for pred_serial in pred_serials:
            # Skip BST-internal nodes
            if pred_serial in bst_serials:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: skipping blk[%d] — in bst_serials",
                    pred_serial,
                )
                continue

            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue

            # Only handle 1-way blocks targeting the dispatcher
            if pred_blk.nsucc() != 1 or pred_blk.succ(0) != dispatcher_serial:
                continue

            _diag_pred_count += 1
            _diag_verbose = _diag_pred_count <= 3

            # Try backward resolution: walk instructions backward from tail
            resolved_value: int | None = None
            _diag_found_write = False

            cur_ins = pred_blk.tail
            while cur_ins is not None:
                # Per-instruction destination diagnostic (first 3 preds only)
                if _diag_verbose:
                    unflat_logger.info(
                        "BACKWARD_RESOLVE: blk[%d] insn opcode=%d d.t=%d "
                        "d.s.off=0x%X (looking for 0x%X)",
                        pred_serial,
                        cur_ins.opcode,
                        cur_ins.d.t if cur_ins.d else -1,
                        cur_ins.d.s.off
                        if (
                            cur_ins.d
                            and cur_ins.d.t == ida_hexrays.mop_S
                            and cur_ins.d.s
                        )
                        else 0,
                        state_var_stkoff,
                    )
                if (
                    cur_ins.d is not None
                    and cur_ins.d.t == ida_hexrays.mop_S
                    and cur_ins.d.s is not None
                    and cur_ins.d.s.off == state_var_stkoff
                ):
                    _diag_found_write = True
                    # Found a write to the state variable — evaluate
                    # using full instruction semantics
                    resolved_value = self._resolve_state_write_insn(
                        cur_ins, pred_blk, mba, bst_serials,
                    )
                    if resolved_value is not None:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] resolved state write "
                            "-> 0x%X (opcode=%d)",
                            pred_serial,
                            resolved_value & 0xFFFFFFFF,
                            cur_ins.opcode,
                        )
                    elif cur_ins.l is not None and cur_ins.l.t in (
                        ida_hexrays.mop_r, ida_hexrays.mop_S,
                    ):
                        _MOP_TYPE_NAMES = {
                            1: "mop_r(reg)", 12: "mop_S(stkvar)",
                        }
                        _src_desc = _MOP_TYPE_NAMES.get(
                            cur_ins.l.t, "mop_%d" % cur_ins.l.t,
                        )
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] state_var_write: "
                            "opcode=%d src_type=%d(%s) src=%s "
                            "-> trying depth-1 copy chain",
                            pred_serial, cur_ins.opcode, cur_ins.l.t,
                            _src_desc, str(cur_ins.l),
                        )
                        resolved_value = self._backward_scan_depth1(
                            pred_blk, cur_ins.l,
                        )
                        if resolved_value is None:
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] depth-1 copy chain "
                                "FAILED to resolve",
                                pred_serial,
                            )
                    else:
                        _src_t = cur_ins.l.t if cur_ins.l is not None else -1
                        _src_str = str(cur_ins.l) if cur_ins.l is not None else "None"
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] state_var_write: "
                            "opcode=%d src_type=%d src=%s "
                            "-> NOT resolvable (unhandled)",
                            pred_serial, cur_ins.opcode, _src_t, _src_str,
                        )
                    break
                cur_ins = cur_ins.prev

            if not _diag_found_write:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: blk[%d] NO state_var_write found "
                    "(stkoff=0x%X) in any instruction — trying cross-block walk",
                    pred_serial, state_var_stkoff,
                )
                # Cross-block predecessor walking: when the current dispatcher
                # predecessor has no state_var write (OLLVM shared-tail pattern),
                # walk the single-predecessor chain up to 8 blocks deep looking
                # for the state variable write in an ancestor block.
                walk_blk = pred_blk
                for _xb_depth in range(1, 9):
                    # Per-depth diagnostic: log each block visited
                    if _diag_verbose:
                        _insn_count = 0
                        _cnt_ins = walk_blk.head
                        while _cnt_ins:
                            _insn_count += 1
                            _cnt_ins = _cnt_ins.next
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: visiting blk[%d] "
                            "start_ea=0x%X ninsn=%d npred=%d",
                            pred_serial, _xb_depth, walk_blk.serial,
                            walk_blk.start, _insn_count, walk_blk.npred(),
                        )
                        if walk_blk.serial in bst_serials:
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: blk[%d] is BST — skipping",
                                pred_serial, _xb_depth, walk_blk.serial,
                            )
                    if walk_blk.npred() > 1:
                        # Multi-predecessor: resolve each arm independently
                        # (hrtng Tier 3 pattern)
                        if _diag_verbose:
                            pred_list = [walk_blk.pred(i) for i in range(walk_blk.npred())]
                            unflat_logger.info(
                                "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: multi-pred blk[%d] "
                                "npred=%d preds=%s, trying per-arm",
                                pred_serial, _xb_depth, walk_blk.serial,
                                walk_blk.npred(), pred_list,
                            )
                        per_pred_results: list[tuple[int, int]] = []
                        for _arm_idx in range(walk_blk.npred()):
                            arm_pred_serial = walk_blk.pred(_arm_idx)
                            if arm_pred_serial in bst_serials:
                                continue
                            arm_blk = mba.get_mblock(arm_pred_serial)
                            if arm_blk is None:
                                continue

                            if _diag_verbose:
                                arm_insn_summary = []
                                _tmp = arm_blk.tail
                                for _ in range(3):
                                    if _tmp is None:
                                        break
                                    arm_insn_summary.append(
                                        f"op={_tmp.opcode} d.t={_tmp.d.t if _tmp.d else -1}"
                                    )
                                    _tmp = _tmp.prev
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] npred=%d insns=[%s]",
                                    pred_serial, arm_pred_serial, arm_blk.npred(),
                                    ", ".join(arm_insn_summary),
                                )

                            # Walk this arm backward looking for state var write
                            arm_value: int | None = None
                            arm_walk = arm_blk
                            for _arm_depth in range(8):
                                _arm_insn = arm_walk.tail
                                while _arm_insn is not None:
                                    if _diag_verbose:
                                        unflat_logger.info(
                                            "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                            "depth-%d insn op=%d d.t=%d d.s.off=0x%X",
                                            pred_serial, arm_walk.serial,
                                            _arm_depth, _arm_insn.opcode,
                                            _arm_insn.d.t if _arm_insn.d else -1,
                                            _arm_insn.d.s.off
                                            if (
                                                _arm_insn.d
                                                and _arm_insn.d.t == ida_hexrays.mop_S
                                                and _arm_insn.d.s
                                            )
                                            else 0,
                                        )
                                    # Same state_var_write check as existing code
                                    if (
                                        _arm_insn.d is not None
                                        and _arm_insn.d.t == ida_hexrays.mop_S
                                        and _arm_insn.d.s is not None
                                        and _arm_insn.d.s.off == state_var_stkoff
                                    ):
                                        arm_value = self._resolve_state_write_insn(
                                            _arm_insn, arm_walk, mba,
                                            bst_serials,
                                        )
                                        if arm_value is not None:
                                            unflat_logger.info(
                                                "BACKWARD_RESOLVE: blk[%d] "
                                                "arm blk[%d] resolved "
                                                "-> 0x%X (opcode=%d)",
                                                pred_serial,
                                                arm_pred_serial,
                                                arm_value & 0xFFFFFFFF,
                                                _arm_insn.opcode,
                                            )
                                        break  # found write
                                    _arm_insn = _arm_insn.prev

                                if arm_value is not None:
                                    break
                                # Continue if single-pred
                                if arm_walk.npred() != 1:
                                    break
                                _next = arm_walk.pred(0)
                                if _next in bst_serials:
                                    break
                                arm_walk = mba.get_mblock(_next)
                                if arm_walk is None:
                                    break

                            if arm_value is not None:
                                per_pred_results.append(
                                    (arm_pred_serial, arm_value),
                                )
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                    "-> literal 0x%X",
                                    pred_serial, arm_pred_serial, arm_value,
                                )
                            else:
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arm blk[%d] "
                                    "-> UNRESOLVED",
                                    pred_serial, arm_pred_serial,
                                )

                        # Check if all arms agree on one BST target
                        if per_pred_results:
                            targets: set[int] = set()
                            for _, val in per_pred_results:
                                t = resolve_target_via_bst(bst_result, val)
                                if t is not None:
                                    targets.add(t)

                            if len(targets) == 1:
                                target_serial = next(iter(targets))
                                if change_1way_block_successor(
                                    pred_blk, target_serial, verify=False,
                                ):
                                    redirected += 1
                                    unflat_logger.info(
                                        "BACKWARD_RESOLVE: blk[%d] RESOLVED "
                                        "-> blk[%d] (all %d arms agree)",
                                        pred_serial,
                                        target_serial,
                                        len(per_pred_results),
                                    )
                                    break  # resolved — exit xblock loop
                            elif len(targets) > 1:
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] arms DISAGREE: "
                                    "targets=%s (needs block duplication "
                                    "— not yet implemented)",
                                    pred_serial,
                                    {hex(t) for t in targets},
                                )
                        break  # multi-pred — done with this xblock walk
                    if walk_blk.npred() == 0:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "npred=0, stopping walk",
                            pred_serial, _xb_depth,
                        )
                        break
                    _xb_pred_serial = walk_blk.pred(0)
                    if _xb_pred_serial in bst_serials:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "reached BST blk[%d], stopping",
                            pred_serial, _xb_depth, _xb_pred_serial,
                        )
                        break
                    _xb_pred_blk = mba.get_mblock(_xb_pred_serial)
                    if _xb_pred_blk is None:
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                            "pred blk[%d] is None, stopping",
                            pred_serial, _xb_depth, _xb_pred_serial,
                        )
                        break

                    # Walk instructions backward in predecessor looking for
                    # state var write (same pattern as the current-block scan)
                    _xb_insn = _xb_pred_blk.tail
                    while _xb_insn is not None:
                        if (
                            _xb_insn.d is not None
                            and _xb_insn.d.t == ida_hexrays.mop_S
                            and _xb_insn.d.s is not None
                            and _xb_insn.d.s.off == state_var_stkoff
                        ):
                            _diag_found_write = True
                            # Found state var write — evaluate full
                            # instruction semantics
                            _xb_resolved = self._resolve_state_write_insn(
                                _xb_insn, _xb_pred_blk, mba, bst_serials,
                            )
                            if _xb_resolved is not None:
                                resolved_value = _xb_resolved
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                                    "resolved 0x%X in pred blk[%d] (opcode=%d)",
                                    pred_serial, _xb_depth,
                                    resolved_value & 0xFFFFFFFF,
                                    _xb_pred_serial, _xb_insn.opcode,
                                )
                            elif _xb_insn.l is not None and _xb_insn.l.t in (
                                ida_hexrays.mop_r, ida_hexrays.mop_S,
                            ):
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] xblock-depth-%d: "
                                    "state_var_write in pred blk[%d] "
                                    "src_type=%d (reg/stkvar copy — continue walk)",
                                    pred_serial, _xb_depth,
                                    _xb_pred_serial, _xb_insn.l.t,
                                )
                                # Reset flag so we continue walking from this
                                # predecessor to resolve the copy chain
                                _diag_found_write = False
                            else:
                                _xb_src_t = (
                                    _xb_insn.l.t
                                    if _xb_insn.l is not None
                                    else -1
                                )
                                unflat_logger.info(
                                    "BACKWARD_RESOLVE: blk[%d] "
                                    "xblock-depth-%d: "
                                    "state_var_write in pred blk[%d] "
                                    "src_type=%d opcode=%d (unhandled)",
                                    pred_serial, _xb_depth,
                                    _xb_pred_serial, _xb_src_t,
                                    _xb_insn.opcode,
                                )
                            break
                        _xb_insn = _xb_insn.prev

                    if _diag_found_write:
                        # Either resolved a literal or hit an unhandled type
                        break

                    # No write in this predecessor — continue walking
                    walk_blk = _xb_pred_blk
                else:
                    # Exhausted max depth without finding write
                    unflat_logger.info(
                        "BACKWARD_RESOLVE: blk[%d] xblock walk exhausted "
                        "max depth (8) without finding state_var_write",
                        pred_serial,
                    )

            # Fallback: valrange resolution
            if resolved_value is None and pred_blk.tail is not None and state_var_mop is not None:
                try:
                    val = resolve_state_via_valranges(
                        pred_blk, state_var_mop, pred_blk.tail,
                    )
                    if val is not None:
                        resolved_value = val
                        unflat_logger.info(
                            "BACKWARD_RESOLVE: blk[%d] valrange fallback "
                            "resolved state=0x%X",
                            pred_serial, val & 0xFFFFFFFF,
                        )
                except Exception:
                    pass

            if resolved_value is None:
                unflat_logger.info(
                    "BACKWARD_RESOLVE: blk[%d] UNRESOLVED after all attempts",
                    pred_serial,
                )
                continue

            # Look up target handler via BST
            try:
                target = resolve_target_via_bst(bst_result, resolved_value)
            except Exception:
                target = None

            if target is None:
                continue

            # Redirect the block successor to the target handler
            try:
                change_1way_block_successor(pred_blk, target, verify=False)
                redirected += 1
                unflat_logger.info(
                    "backward resolved blk[%d] state=0x%X -> handler blk[%d]",
                    pred_serial, resolved_value & 0xFFFFFFFF, target,
                )
            except Exception as exc:
                unflat_logger.warning(
                    "backward resolve blk[%d] state=0x%X -> blk[%d] FAILED: %s",
                    pred_serial, resolved_value & 0xFFFFFFFF, target, exc,
                )

        if redirected > 0:
            unflat_logger.info(
                "backward_resolve: redirected %d/%d dispatcher predecessors",
                redirected, len(pred_serials),
            )

        return redirected

    def _diagnostic_backward_scan(
        self,
        dispatcher_serial: int,
        bst_node_blocks: "BSTNodeMap",
        state_var_stkoff: int,
        bst_result: object,
        state_var_mop: object,
    ) -> None:
        """Diagnostic: backward-resolve state constants from dispatcher predecessors.

        Iterates all remaining dispatcher predecessors AFTER linearization +
        BST cleanup, tries to backward-resolve the state constant each one
        writes, and logs coverage.  This tells us how many unresolved handler
        exits could potentially be chained via a backward-scan approach.

        **This is diagnostic only — no CFG modifications are emitted.**

        Args:
            dispatcher_serial: Serial of the dispatcher block.
            bst_node_blocks: BST node block map from analysis.
            state_var_stkoff: Stack offset of the state variable.
            bst_result: ``BSTAnalysisResult`` for BST target resolution.
            state_var_mop: ``mop_t`` for the state variable (``mop_S``).
        """
        from d810.evaluator.hexrays_microcode.valranges import (
            resolve_state_via_valranges,
        )
        from d810.recon.flow.bst_model import resolve_target_via_bst

        mba = self.mba
        disp_blk = mba.get_mblock(dispatcher_serial)
        if disp_blk is None:
            return

        bst_serials: set[int] = set(bst_node_blocks)
        bst_serials.add(dispatcher_serial)

        pred_serials = [disp_blk.pred(i) for i in range(disp_blk.npred())]

        # Counters
        already_redirected = 0
        literal_count = 0
        copy_chain_count = 0
        valrange_count = 0
        unresolved_count = 0
        target_found = 0
        unresolved_details: list[str] = []

        for pred_serial in pred_serials:
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                unresolved_count += 1
                unresolved_details.append(
                    f"blk[{pred_serial}]: block is None"
                )
                continue

            # Check if already redirected (successor is NOT dispatcher and
            # NOT in BST node set)
            is_redirected = True
            for si in range(pred_blk.nsucc()):
                s = pred_blk.succ(si)
                if s == dispatcher_serial or s in bst_serials:
                    is_redirected = False
                    break
            if pred_blk.nsucc() == 0:
                # 0-way blocks (severed) — check if they were BST nodes
                is_redirected = pred_serial not in bst_serials

            if is_redirected:
                already_redirected += 1
                continue

            # Skip BST-internal nodes — they are part of the comparison tree,
            # not handler exits.
            if pred_serial in bst_serials:
                already_redirected += 1
                continue

            # Try backward resolution: walk instructions backward from tail
            resolved_value: int | None = None
            resolution_method: str = "UNRESOLVED"

            cur_ins = pred_blk.tail
            while cur_ins is not None:
                # Check if this instruction writes to the state variable
                if (
                    cur_ins.d is not None
                    and cur_ins.d.t == ida_hexrays.mop_S
                    and cur_ins.d.s is not None
                    and cur_ins.d.s.off == state_var_stkoff
                ):
                    # Found a write to the state variable
                    if cur_ins.l is not None and cur_ins.l.t == ida_hexrays.mop_n:
                        # Source is a literal constant
                        resolved_value = cur_ins.l.nnn.value
                        resolution_method = "LITERAL"
                        break
                    elif cur_ins.l is not None and cur_ins.l.t in (
                        ida_hexrays.mop_r, ida_hexrays.mop_S,
                    ):
                        # Source is a register or stack copy — try depth-1
                        src_op = cur_ins.l
                        resolved_value = self._backward_scan_depth1(
                            pred_blk, src_op,
                        )
                        if resolved_value is not None:
                            resolution_method = "COPY_CHAIN"
                            break
                    # Write found but source not resolvable here
                    break
                cur_ins = cur_ins.prev

            # Fallback: try valrange resolution
            if resolved_value is None and pred_blk.tail is not None:
                try:
                    val = resolve_state_via_valranges(
                        pred_blk, state_var_mop, pred_blk.tail,
                    )
                    if val is not None:
                        resolved_value = val
                        resolution_method = "VALRANGE"
                except Exception:
                    pass

            # Tally results
            if resolved_value is not None:
                if resolution_method == "LITERAL":
                    literal_count += 1
                elif resolution_method == "COPY_CHAIN":
                    copy_chain_count += 1
                elif resolution_method == "VALRANGE":
                    valrange_count += 1

                # Try BST lookup
                try:
                    target = resolve_target_via_bst(bst_result, resolved_value)
                    if target is not None:
                        target_found += 1
                        unflat_logger.debug(
                            "BACKWARD_SCAN: blk[%d] %s value=0x%X -> target blk[%d]",
                            pred_serial, resolution_method,
                            resolved_value & 0xFFFFFFFF, target,
                        )
                    else:
                        unflat_logger.debug(
                            "BACKWARD_SCAN: blk[%d] %s value=0x%X -> NO BST target",
                            pred_serial, resolution_method,
                            resolved_value & 0xFFFFFFFF,
                        )
                except Exception:
                    unflat_logger.debug(
                        "BACKWARD_SCAN: blk[%d] %s value=0x%X -> BST lookup error",
                        pred_serial, resolution_method,
                        resolved_value & 0xFFFFFFFF,
                    )
            else:
                unresolved_count += 1
                # Gather detail for debug
                tail_str = pred_blk.tail.dstr() if pred_blk.tail else "none"
                unresolved_details.append(
                    f"blk[{pred_serial}]: nsucc={pred_blk.nsucc()} tail={tail_str}"
                )

        # Summary log
        total_preds = len(pred_serials)
        resolved_total = literal_count + copy_chain_count + valrange_count
        unflat_logger.info(
            "BACKWARD_SCAN: dispatcher has %d predecessors: "
            "%d already redirected, %d literal, %d copy-chain, "
            "%d valrange, %d unresolved. %d with valid BST targets.",
            total_preds, already_redirected, literal_count,
            copy_chain_count, valrange_count, unresolved_count,
            target_found,
        )

        # Log unresolved details at DEBUG
        for detail in unresolved_details:
            unflat_logger.debug("BACKWARD_SCAN unresolved: %s", detail)

    def _backward_scan_depth1(
        self,
        origin_blk: object,
        src_op: object,
    ) -> int | None:
        """Try one level of copy-chain resolution for a register/stack source.

        If *origin_blk* has exactly one predecessor, walk that predecessor's
        instructions backward looking for a write to *src_op* with an ``mop_n``
        (literal) source.

        Args:
            origin_blk: The block whose tail writes src_op to state var.
            src_op: The source operand (``mop_r`` or ``mop_S``) to trace.

        Returns:
            Concrete integer value if found, otherwise ``None``.
        """
        if origin_blk.npred() != 1:
            return None

        pred_serial = origin_blk.pred(0)
        pred_blk = self.mba.get_mblock(pred_serial)
        if pred_blk is None:
            return None

        cur_ins = pred_blk.tail
        while cur_ins is not None:
            if cur_ins.d is not None and cur_ins.d.t == src_op.t:
                # Match by type-specific identity
                match = False
                if src_op.t == ida_hexrays.mop_r:
                    match = cur_ins.d.r == src_op.r
                elif src_op.t == ida_hexrays.mop_S:
                    match = (
                        cur_ins.d.s is not None
                        and src_op.s is not None
                        and cur_ins.d.s.off == src_op.s.off
                    )
                if match and cur_ins.l is not None and cur_ins.l.t == ida_hexrays.mop_n:
                    return cur_ins.l.nnn.value
            cur_ins = cur_ins.prev

        return None

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
