"""Thin orchestrator for the Hodur strategy-based unflattening pipeline.

This module contains the new ``HodurUnflattener`` class which replaces the
monolithic implementation in ``unflattener_hodur.py``.  All heavy analysis
logic lives in the hodur sub-package; this class is a thin coordinator that:

1. Detects the Hodur state machine via :class:`HodurStateMachineDetector`.
2. Builds an immutable :class:`AnalysisSnapshot`.
3. Collects :class:`PlanFragment` objects from each registered strategy.
4. Composes the pipeline via :class:`UnflatteningPlanner`.
5. Runs the shared execution lifecycle via ``engine.runtime``.

Gate operation mode: ``GATE_SELECT`` — full recon + gate enforcement + planner
hint influence.  See :class:`~d810.core.gate_modes.GateOperationMode`.

# ORCHESTRATOR_BOUNDARY: This module is a thin coordinator.  It does NOT
# perform strategy selection, conflict resolution, or pipeline reordering.
# Those are owned exclusively by the UnflatteningPlanner (see planner.py).
#
# After the shared runtime plans a pipeline:
#   - The pipeline is passed to executor.execute_pipeline() WITHOUT
#     modification (no filtering, reordering, insertion, or dropping).
#   - Executor results are mapped to provenance lifecycle phases
#     (APPLIED, GATE_FAILED, PREFLIGHT_REJECTED, BYPASSED) -- this is
#     lifecycle bookkeeping, not re-arbitration.
"""
from __future__ import annotations

import os
import traceback

import ida_hexrays
from pathlib import Path

from d810.core import logging
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_formatters import format_mop_t, maturity_to_string
from d810.recon.flow.dispatcher_detection import (
    DispatcherCache,
)
from d810.recon.flow.return_frontier_carrier_audit import (
    audit_return_frontier_carriers,
    is_audit_enabled as is_return_carrier_audit_enabled,
)
from d810.recon.function_priors import FunctionAnalysisPriors
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
    DispatcherStateMachine,
    HandlerPathResult,
    Pass0RedirectRecord,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
)
from d810.optimizers.microcode.flow.flattening.hodur.family import (
    HodurStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile import (
    default_hodur_profile,
)
from d810.optimizers.microcode.flow.flattening.engine.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    PipelineProvenance,
    PlannerInputs,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    execute_family_pipeline,
    plan_family_pipeline,
)
from d810.cfg.flow.graph_checks import SemanticGate
from d810.cfg.mbl_keep_selection import (
    TerminalByteKeepTarget,
    select_terminal_byte_keep_targets,
)
from d810.hexrays.mutation.cfg_mutations import (
    MBL_KEEP,
    change_1way_block_successor,
    make_2way_block_goto,
    remove_block_edge,
)

from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    StageResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_return_frontier_audit_from_store,
    load_terminal_return_audit_from_store,
    load_transition_report_from_store,
)
from d810.recon.facts.model import FactConsumerRecord, FactStatus

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)


_SUB7FFD_FUNC_EA = 0x180012B60


def _mlist_text(value) -> str | None:
    dstr = getattr(value, "dstr", None)
    if dstr is None:
        return None
    try:
        text = dstr()
    except Exception:
        return None
    return text or None


def _mblock_int_attr(blk, *names: str) -> int | None:
    for name in names:
        value = getattr(blk, name, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _ea_in_block(blk, ea: int) -> bool:
    start = _mblock_int_attr(blk, "start", "start_ea")
    if start is None:
        return False
    end = _mblock_int_attr(blk, "end", "end_ea")
    if end is None or end <= start:
        return int(ea) == start
    return start <= int(ea) < end


def _block_matches_terminal_byte_target(
    blk,
    targets: tuple[TerminalByteKeepTarget, ...],
) -> bool:
    serial = _mblock_int_attr(blk, "serial")
    start = _mblock_int_attr(blk, "start", "start_ea")
    for target in targets:
        if target.block_ea is not None and start == target.block_ea:
            return True
        if target.source_ea is not None and _ea_in_block(blk, target.source_ea):
            return True
        if (
            target.block_serial is not None
            and target.block_ea is None
            and target.source_ea is None
            and serial == target.block_serial
        ):
            return True
    return False


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
    5. Shared runtime helpers execute the pipeline and project provenance.
    """

    DESCRIPTION = "Remove Hodur-style while-loop control flow flattening"
    # Hodur rewrites are a GLBOPT1-owned structural pass. Re-entering the
    # strategy pipeline at GLBOPT2 after GLBOPT1 has already rebuilt the CFG can
    # leave Hex-Rays with an undecompilable MBA on sub_7FFD3338C040.
    DEFAULT_UNFLATTENING_MATURITIES = [ida_hexrays.MMAT_GLBOPT1]
    RECON_ONLY_MODE = False
    RETURN_FRONTIER_AUDIT_ENABLED: bool = True  # Default on for debugging
    # MBL_KEEP marking experiment (uee-jfta follow-up): mark every block
    # reachable from the function entry at end-of-pipeline so IDA's
    # ``remove_empty_and_unreachable_blocks()`` and ``merge_blocks()``
    # don't delete them.  Block-level only — does NOT preserve
    # instruction-level DCE.  Empirical effect on sub_7FFD3338C040:
    # snap10 block count 54 -> 200, AFTER lines 279 -> 293.  Has wider
    # ramifications (some downstream IDA passes may assume blocks they
    # think are unreachable can be deleted), so off by default until
    # corpus testing.
    MBL_KEEP_ENABLED: bool = False
    DEFAULT_MAX_PASSES = 1
    HARD_MAX_PASSES = 1
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
            "Deprecated compatibility knob; Hodur now runs exactly one pass per maturity",
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
        self.max_passes = self.DEFAULT_MAX_PASSES
        self.min_state_constant = MIN_STATE_CONSTANT
        self.min_state_constants = MIN_STATE_CONSTANTS
        self.max_state_constants = MAX_STATE_CONSTANTS_HODUR
        self.allow_legacy_block_creation = True
        self._actual_pass_count: int = 0
        self._current_tracked_maturity: int = ida_hexrays.MMAT_ZERO
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

        # Strategy family adapter: Hodur now supplies detection, snapshot
        # construction, and strategy registration through the shared engine
        # family surface rather than owning those responsibilities directly.
        self._cfg_translator = IDAIRTranslator()
        profile = default_hodur_profile()
        self._family = HodurStrategyFamily(
            cfg_translator=self._cfg_translator,
            disabled_strategy_names={
                "ConditionalForkFallbackStrategy",
            },
            # Region-first experimental strategy runs first; late-residual
            # cleanup strategies are added ONE AT A TIME (see
            # .claude/handoffs/2026-04-20-region-first-reconstruction-fold.md).
            #
            # Standalone StateWriteReconstructionStrategy is retired from the
            # live pipeline: HandlerChainComposer owns the SWR-style
            # orchestration and resolves conflicts in the same fragment.  Keep
            # the old strategy opt-in for archaeology/contribution tests only.
            #
            # D810_RECON_ENABLE_STANDALONE_SRW=1 → append old SRW strategy.
            # D810_RECON_SKIP_SRW_STRATEGY=1 still force-disables it.
            strategy_classes=list(profile.entrypoint_strategy_classes),
            recon_only=self.RECON_ONLY_MODE,
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
            logger=unflat_logger,
        )
        self._strategies = self._family.strategies
        unflat_logger.info(
            "Active strategies: %s",
            [type(s).__name__ for s in self._strategies],
        )
        self._planner = UnflatteningPlanner(PipelinePolicy())
        self._gate = SemanticGate()

        # Return frontier audit components
        self._return_site_provider = HodurReturnSiteProvider()
        self._audit_return_sites: tuple = ()  # Populated at pre_plan, reused across stages
        self._fact_view_observed_keys: set[tuple[int, int, int]] = set()

    def set_flow_context(self, flow_context):
        """Propagate the fact-view provider down to the family adapter.

        ``FlowMaturityContext.validated_fact_view(maturity)`` already calls
        the recon runtime's view provider with the current ``func_ea`` baked
        in; the family expects ``validated_fact_view(func_ea, maturity)``.
        Wrap with a small adapter so the existing recon plumbing is reused
        without exposing a new side-channel.
        """
        super().set_flow_context(flow_context)
        if flow_context is None:
            self._family.set_fact_runtime(None)
            return

        flow_ctx = flow_context

        class _FactRuntimeAdapter:
            __slots__ = ("_ctx",)

            def __init__(self, ctx) -> None:
                self._ctx = ctx

            def validated_fact_view(self, func_ea, maturity):
                # ``func_ea`` is determined by the flow context itself (the
                # context is per-decompilation), so we forward only the
                # maturity argument.  Returns None when no fact lifecycle
                # callbacks are attached.
                return self._ctx.validated_fact_view(maturity)

            def function_analysis_priors(self, func_ea=None):
                return self._ctx.function_analysis_priors(func_ea)

        self._family.set_fact_runtime(_FactRuntimeAdapter(flow_ctx))

    def configure(self, kwargs: dict) -> None:
        super().configure(kwargs)
        if "min_state_constant" in self.config:
            self.min_state_constant = int(self.config["min_state_constant"])
        if "min_state_constants" in self.config:
            self.min_state_constants = int(self.config["min_state_constants"])
        if "max_state_constants" in self.config:
            self.max_state_constants = int(self.config["max_state_constants"])
        if "max_passes" in self.config:
            requested_passes = int(self.config["max_passes"])
            if requested_passes != self.DEFAULT_MAX_PASSES:
                unflat_logger.info(
                    "Ignoring configured max_passes=%d; Hodur now runs exactly one pass per maturity",
                    requested_passes,
                )
            self.max_passes = self.DEFAULT_MAX_PASSES
        if "allow_legacy_block_creation" in self.config:
            self.allow_legacy_block_creation = bool(
                self.config["allow_legacy_block_creation"]
            )
        self._family.configure_detection(
            min_state_constant=self.min_state_constant,
            min_state_constants=self.min_state_constants,
            max_state_constants=self.max_state_constants,
        )

    @property
    def state_machine(self) -> DispatcherStateMachine | None:
        family = getattr(self, "_family", None)
        return family.state_machine if family is not None else None

    @property
    def _detector(self) -> HodurStateMachineDetector | None:
        family = getattr(self, "_family", None)
        return family.detector if family is not None else None

    @property
    def _switch_table_map(self) -> object | None:
        family = getattr(self, "_family", None)
        return family.switch_table_map if family is not None else None

    @property
    def _resolved_transitions(self) -> set[tuple[int | None, int]]:
        family = getattr(self, "_family", None)
        if family is None:
            return set()
        return set(family.resolved_transitions)

    @property
    def _initial_transitions(self) -> list | None:
        family = getattr(self, "_family", None)
        if family is None:
            return None
        transitions = family.initial_transitions
        return list(transitions) if transitions else None

    def _observe_induction_fact_view(self, snapshot: AnalysisSnapshot) -> None:
        """Record Hodur's read-only view of induction-carrier facts.

        This is an observability adapter only.  It does not influence strategy
        selection, planner inputs, or CFG modifications.
        """
        if self.flow_context is None:
            return
        func_ea = int(getattr(self.mba, "entry_ea", 0) or 0)
        maturity = int(self.cur_maturity)
        key = (func_ea, maturity, id(self.mba))
        if key in self._fact_view_observed_keys:
            return
        self._fact_view_observed_keys.add(key)

        try:
            view = self.flow_context.validated_fact_view(maturity)
        except Exception:
            unflat_logger.exception(
                "HODUR_FACT_VIEW_FAILED func=0x%x maturity=%s reason=view-error",
                func_ea,
                maturity_to_string(maturity),
            )
            return
        if view is None:
            return

        induction_observations = tuple(
            observation
            for observation in view.observations
            if observation.kind == "InductionCarrierFact"
        )
        if not induction_observations:
            unflat_logger.info(
                "HODUR_FACT_VIEW func=0x%x maturity=%s induction_total=0 "
                "active=0 stale=0 lost=0 persisted=0",
                func_ea,
                view.maturity,
            )
            return

        active_ids = {
            observation.fact_id
            for observation in view.active_observations
            if observation.kind == "InductionCarrierFact"
        }
        stale_statuses = {
            FactStatus.STALE,
            FactStatus.CONTRADICTED,
            FactStatus.SUPERSEDED,
            FactStatus.IDENTITY_LOST,
        }
        status_by_fact: dict[str, list[str]] = {}
        for mapping in view.mappings:
            if mapping.source_fact_id not in {obs.fact_id for obs in induction_observations}:
                continue
            status_by_fact.setdefault(mapping.source_fact_id, []).append(
                mapping.status.value
            )

        records: list[FactConsumerRecord] = []
        lost_count = 0
        stale_count = 0
        for observation in induction_observations:
            statuses = tuple(status_by_fact.get(observation.fact_id, ()))
            is_active = observation.fact_id in active_ids
            if not is_active:
                stale_count += 1
            if FactStatus.IDENTITY_LOST.value in statuses:
                lost_count += 1
            decision = "active" if is_active else "stale"
            reason = (
                "active induction fact visible to Hodur"
                if is_active
                else "induction fact inactive in Hodur view"
            )
            records.append(
                FactConsumerRecord(
                    consumer="hodur.unflattener",
                    strategy="HodurUnflattener",
                    fact_id=observation.fact_id,
                    maturity=view.maturity,
                    decision=decision,
                    reason=reason,
                    payload={
                        "semantic_key": observation.semantic_key,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "mop_signature": observation.mop_signature,
                        "confidence": observation.confidence,
                        "statuses": list(statuses),
                        "has_stale_mapping": any(
                            FactStatus(status) in stale_statuses for status in statuses
                        ),
                        "handler_count": snapshot.handler_count,
                        "pass_index": self._actual_pass_count,
                        "generation": int(getattr(self, "current_generation", 0)),
                    },
                )
            )

        persisted = 0
        try:
            persisted = self.flow_context.report_fact_consumers(tuple(records))
        except Exception:
            unflat_logger.exception(
                "HODUR_FACT_VIEW_FAILED func=0x%x maturity=%s reason=persist-error",
                func_ea,
                view.maturity,
            )
        unflat_logger.info(
            "HODUR_FACT_VIEW func=0x%x maturity=%s induction_total=%d "
            "active=%d stale=%d lost=%d persisted=%d fact_ids=%s",
            func_ea,
            view.maturity,
            len(induction_observations),
            len(active_ids),
            stale_count,
            lost_count,
            persisted,
            [observation.fact_id for observation in induction_observations],
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
            self._pass0_redirect_ledger = []
            self._pass0_handler_entries = set()
            self._last_redirect_meta = None
            self._family.reset_runtime_state()
            # Reset audit for new maturity
            if self.RETURN_FRONTIER_AUDIT_ENABLED:
                self._audit_return_sites = ()

        # Gate on actual Hodur runs, not block callback count
        if self._actual_pass_count >= self.max_passes:
            return False

        return True

    def _clear_cached_dispatcher_context(self) -> None:
        """Drop stale dispatcher/BST context when the current pass has none."""
        self._last_bst_serials = None
        self._last_dispatcher_serial = -1
        self._last_func_ea = 0
        self._last_bst_block_eas = set()
        self._last_dispatcher_ea = 0

    def optimize(self, blk: ida_hexrays.mblock_t) -> int:
        """Main optimization entry point — planner + strategy pipeline."""
        self.mba = blk.mba

        if not self.check_if_rule_should_be_used(blk):
            return 0

        unflat_logger.debug(
            "HodurUnflattener: Starting pass %d/%d at maturity %s",
            self._actual_pass_count,
            self.max_passes,
            maturity_to_string(self.cur_maturity),
        )

        if self._actual_pass_count == 0:
            self._pass0_redirect_ledger = []
            self._pass0_handler_entries = set()
            self._last_redirect_meta = None

        # 1. Detect family-specific state model via the shared family surface.
        self._family.begin_pass(self._actual_pass_count)
        detection = self._family.detect(self.mba)
        # 2. Build immutable snapshot through the family adapter.
        snapshot = self._family.build_snapshot(self.mba, detection)
        state_machine = snapshot.state_machine
        if state_machine is None:
            unflat_logger.info(
                "No Hodur state machine detected; evaluating cleanup-only strategies"
            )
            self._clear_cached_dispatcher_context()
            self._audit_return_sites = ()
        else:
            self._log_state_machine()
        self._observe_induction_fact_view(snapshot)

        # 3-4. PLANNER_AUTHORITY: planner owns strategy polling + pipeline composition
        if state_machine is None:
            transition_report = None
            return_frontier_audit = None
            terminal_return_audit = None
        else:
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
        active_strategies = self._family.strategies_for_maturity(self.cur_maturity)
        planned = plan_family_pipeline(
            snapshot,
            active_strategies,
            planner=self._planner,
            inputs=planner_inputs,
        )
        self._last_provenance = planned.provenance

        # Return frontier audit: pre_plan stage (after fragment collection so
        # handler_paths from DirectLinearization strategy are available)
        if self.RETURN_FRONTIER_AUDIT_ENABLED and snapshot.state_machine is not None:
            handler_paths = self._extract_handler_paths_from_fragments(planned.pipeline)
            try:
                self._audit_return_sites = self._family.prepare_return_frontier_audit(
                    snapshot,
                    current_return_sites=tuple(self._audit_return_sites),
                    return_site_provider=self._return_site_provider,
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    log_dir=self.log_dir,
                    successors=self._build_successor_map(),
                    exits=self._find_exit_blocks(),
                    handler_paths=handler_paths,
                )
            except Exception:
                unflat_logger.debug("_audit_pre_plan failed (non-critical), continuing")

        if not planned.pipeline:
            unflat_logger.info(
                "No strategy produced a plan fragment; continuing in recon-only diagnostic mode"
            )
            pipeline = []
            results = []
            provenance = planned.provenance
            nb_changes = 0
        else:
            unflat_logger.info("Planner provenance: %s", planned.provenance.summary())

            # Return frontier audit: post_plan stage (mods queued but not applied)
            if (
                self.RETURN_FRONTIER_AUDIT_ENABLED
                and snapshot.state_machine is not None
                and self._audit_return_sites
            ):
                try:
                    self._family.record_return_frontier_stage(
                        return_sites=tuple(self._audit_return_sites),
                        stage_name="post_plan",
                        func_ea=self.mba.entry_ea,
                        maturity=self.cur_maturity,
                        log_dir=self.log_dir,
                        successors=self._build_successor_map(),
                        exits=self._find_exit_blocks(),
                    )
                except Exception:
                    unflat_logger.debug(
                        "_record_audit_stage(post_plan) failed (non-critical)"
                    )

            # 5. EXECUTOR_BOUNDARY: runtime consumes planner output in-order,
            # delegates to the configured executor, and projects executor outcomes
            # back onto provenance.
            executed = execute_family_pipeline(
                snapshot,
                planned,
                executor_factory=self._family.make_executor_factory(
                    gate=self._gate,
                    allow_legacy_block_creation=self.allow_legacy_block_creation,
                ),
                flow_context=self.flow_context,
            )
            pipeline = executed.pipeline
            results = executed.results
            provenance = executed.provenance
            nb_changes = executed.total_changes
            self._last_provenance = provenance

        live_residual_dispatcher_preds_by_strategy: dict[str, tuple[int, ...]] = {}
        successful_fragments = [
            fragment
            for fragment, result in zip(pipeline, results)
            if result.success and result.edits_applied > 0
        ]
        for fragment in successful_fragments:
            strategy_name = fragment.strategy_name
            group_name = fragment.metadata.get("post_apply_bst_cleanup_group")
            if (
                strategy_name not in {"linearized_flow_graph", "exact_node_frontier_bypass"}
                and not isinstance(group_name, str)
            ):
                continue
            residual_preds = self._family.collect_live_residual_dispatcher_preds(
                self.mba,
                snapshot,
                strategy_name=strategy_name,
            )
            live_residual_dispatcher_preds_by_strategy[strategy_name] = residual_preds
            if isinstance(group_name, str):
                live_residual_dispatcher_preds_by_strategy[f"group:{group_name}"] = (
                    residual_preds
                )

        self._family.record_execution_outcome(
            pipeline,
            results,
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            nb_changes=nb_changes,
            residual_dispatcher_preds_by_strategy=(
                live_residual_dispatcher_preds_by_strategy
            ),
        )

        self._family.persist_terminal_return_audit(
            results,
            func_ea=self.mba.entry_ea,
            maturity=self.cur_maturity,
            log_dir=self.log_dir,
        )

        # Return frontier audit: post_apply stage
        if (
            self.RETURN_FRONTIER_AUDIT_ENABLED
            and snapshot.state_machine is not None
            and self._audit_return_sites
        ):
            try:
                self._family.record_return_frontier_stage(
                    return_sites=tuple(self._audit_return_sites),
                    stage_name="post_apply",
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    log_dir=self.log_dir,
                    successors=self._build_successor_map(),
                    exits=self._find_exit_blocks(),
                )
            except Exception:
                unflat_logger.debug("_record_audit_stage(post_apply) failed (non-critical)")

        # 5c. Post-apply: disconnect BST comparison nodes and dispatcher.
        # Run this on the first pass where no live dispatcher blockers remain.
        # The cleanup invalidates subsequent state-machine analysis, so once it
        # runs we suppress further Hodur iteration below.
        bst_cleanup_ran = False
        bst_cleanup_blockers = self._family.collect_post_apply_bst_cleanup_blockers(
            pipeline,
            results,
            live_residual_dispatcher_preds_by_strategy=(
                live_residual_dispatcher_preds_by_strategy
            ),
        )
        if bst_cleanup_blockers:
            unflat_logger.info(
                "Skipping post-apply BST cleanup because unresolved non-BST dispatcher predecessors remain: %s",
                bst_cleanup_blockers,
            )
        # Accumulate live corridor blocks from ALL passes (before the
        # cleanup conditional, so pass 0's modifications survive even
        # when bst_cleanup_blockers prevents cleanup from running).
        if not hasattr(self, "_reconstruction_live_blocks"):
            self._reconstruction_live_blocks: set[int] = set()
        for frag, res in zip(pipeline, results):
            if not res.success or res.edits_applied <= 0:
                continue
            for mod in frag.modifications:
                for attr in (
                    "from_serial", "new_target",
                    "goto_target", "block_serial", "source_block",
                    "src_block", "source_serial", "via_pred",
                    "conditional_target", "fallthrough_target",
                    "pred_serial", "succ_serial",
                ):
                    val = getattr(mod, attr, None)
                    if isinstance(val, int):
                        self._reconstruction_live_blocks.add(val)
                # DuplicateAndRedirect: per_pred_targets
                ppt = getattr(mod, "per_pred_targets", None)
                if ppt is not None:
                    for _pred, _tgt in ppt:
                        self._reconstruction_live_blocks.add(int(_pred))
                        self._reconstruction_live_blocks.add(int(_tgt))

        if (
            not bst_cleanup_blockers
            and nb_changes > 0
            and snapshot.bst_result is not None
        ):
            bst_cleanup_edges = self._post_apply_bst_cleanup(
                snapshot.bst_result.bst_node_blocks,
                snapshot.bst_dispatcher_serial,
                bst_result=snapshot.bst_result,
            )
            if bst_cleanup_edges > 0:
                nb_changes += bst_cleanup_edges
                bst_cleanup_ran = True
            # Intermediate snapshot AFTER bst cleanup ran
            self._capture_intermediate_snapshot("post_bst_cleanup")
        else:
            # Take an explicit "skipped" snapshot anyway so the bisection chain
            # is unambiguous regardless of whether cleanup ran.
            self._capture_intermediate_snapshot("post_bst_cleanup_skipped")

            # Diagnostic: backward dispatcher-predecessor scan
            state_var = getattr(snapshot.state_machine, "state_var", None)
            if (
                state_var is not None
                and state_var.t == ida_hexrays.mop_S
                and snapshot.bst_result is not None
            ):
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
            bst_serials = set()
            if snapshot.bst_result is not None:
                bst_serials = set(snapshot.bst_result.bst_node_blocks) | {
                    snapshot.bst_dispatcher_serial
                }
                self._prune_unreachable_bst_blocks(bst_serials)
            self._capture_intermediate_snapshot("post_prune_unreachable")

            # Remove dispatcher and BST from live set — they're cleanup targets
            self._reconstruction_live_blocks -= bst_serials
            self._reconstruction_live_blocks.discard(snapshot.bst_dispatcher_serial)

            dead_cleanup_applied = self._nop_unreachable_blocks_after_bst_cleanup(
                dispatcher_serial=snapshot.bst_dispatcher_serial,
                bst_serials=bst_serials,
                reconstruction_live=self._reconstruction_live_blocks,
            )
            if dead_cleanup_applied > 0:
                nb_changes += dead_cleanup_applied
            self._capture_intermediate_snapshot("post_dead_block_elim")

            # --- Diagnostic snapshot: MBA + reachability after Gut-and-Wire ---
            try:
                from d810.hexrays.mba_serializer import mba_to_block_snapshots
                from d810.hexrays.observability import (
                    request_capture_mba_snapshot,
                )
                from d810.recon.observability import observe_reachability

                # Compute reachable blocks via BFS from block 0
                _diag_visited: set[int] = set()
                _diag_queue: list[int] = [0]
                while _diag_queue:
                    _ds = _diag_queue.pop(0)
                    if _ds in _diag_visited or _ds < 0 or _ds >= self.mba.qty:
                        continue
                    _diag_visited.add(_ds)
                    _db = self.mba.get_mblock(_ds)
                    if _db is not None:
                        for _di in range(_db.nsucc()):
                            _diag_queue.append(_db.succ(_di))

                all_serials = set(range(self.mba.qty))
                gutted_serials = all_serials - _diag_visited - {self.mba.qty - 1}

                # Collect claimed_sources from pipeline results metadata
                _claimed: set[int] = set()
                for _r in results:
                    _cs = _r.metadata.get("claimed_sources")
                    if isinstance(_cs, (set, frozenset)):
                        _claimed |= set(_cs)

                snap = request_capture_mba_snapshot(
                    blocks=mba_to_block_snapshots(self.mba),
                    label="post_gut_and_wire",
                    func_ea=self.mba.entry_ea,
                    maturity="MMAT_GLBOPT1",
                    phase="post_gut_wire",
                )
                if snap is not None:
                    observe_reachability(
                        snap,
                        all_serials=all_serials,
                        reachable=_diag_visited,
                        bst_serials=bst_serials,
                        gutted=gutted_serials,
                        claimed_sources=_claimed,
                    )
            except Exception:
                unflat_logger.debug(
                    "Diagnostic reachability snapshot failed (non-critical)",
                    exc_info=True,
                )

            # Persist BST serials + dispatcher serial for hxe_glbopt PruneUnreachable
            if dead_cleanup_applied == 0:
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
            else:
                self._last_bst_serials = None
                self._last_dispatcher_serial = -1
                self._last_bst_block_eas = set()
                self._last_dispatcher_ea = 0

        # 6. Log summary
        # Intermediate snapshot just before the pipeline summary log; if the
        # CFG was mutated by anything between post_dead_block_elim and here
        # (currently nothing — sanity anchor only), this catches it.
        self._capture_intermediate_snapshot("pre_pipeline_log")
        self._log_pipeline_results(results, nb_changes)
        unflat_logger.info("Provenance: %s", provenance.phase_summary())
        if unflat_logger.debug_on:
            import json
            unflat_logger.debug(
                "Provenance detail: %s",
                json.dumps(provenance.to_dict(), indent=2),
            )

        unflat_logger.info(
            "HodurUnflattener: Pass %d made %d changes",
            self._actual_pass_count,
            nb_changes,
        )

        if nb_changes == 0:
            unflat_logger.info(
                "HodurUnflattener: convergence reached at pass %d, maturity %s",
                self._actual_pass_count,
                maturity_to_string(self.cur_maturity),
            )

        self._actual_pass_count += 1

        # Return frontier audit: post_pipeline stage + artifact write
        if (
            self.RETURN_FRONTIER_AUDIT_ENABLED
            and snapshot.state_machine is not None
            and self._audit_return_sites
        ):
            try:
                self._family.finalize_return_frontier_audit(
                    tuple(self._audit_return_sites),
                    func_ea=self.mba.entry_ea,
                    maturity=self.cur_maturity,
                    log_dir=self.log_dir,
                    artifact_dir=Path(f".tmp/recon/{self.cur_maturity}"),
                    successors=self._build_successor_map(),
                    exits=self._find_exit_blocks(),
                )
            except Exception:
                unflat_logger.debug("post_pipeline audit failed (non-critical)")

        # Observability-only: classify return-frontier carrier identity.
        # Default off; gated by D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT=1.
        if is_return_carrier_audit_enabled():
            try:
                corridors: tuple[tuple[int, ...], ...] = ()
                dag = getattr(snapshot, "dag", None)
                if dag is not None:
                    raw = getattr(dag, "side_effect_corridors", ()) or ()
                    try:
                        corridors = tuple(
                            tuple(int(b) for b in chain) for chain in raw
                        )
                    except (TypeError, ValueError):
                        corridors = ()
                function_priors = FunctionAnalysisPriors()
                if self.flow_context is not None:
                    function_priors = self.flow_context.function_analysis_priors(
                        self.mba.entry_ea
                    )
                audit_return_frontier_carriers(
                    mba=self.mba,
                    side_effect_corridors=corridors,
                    label="post_pipeline",
                    artifact_priors=(
                        function_priors.return_frontier_artifacts
                    ),
                )
            except Exception:
                unflat_logger.debug(
                    "return-frontier carrier audit failed (non-critical)",
                    exc_info=True,
                )

        self._capture_post_pipeline_diagnostic_snapshot()

        if not pipeline:
            return 0

        bundle_stabilized = self._stabilize_sub7ffd_post_pipeline_bundle()
        if bundle_stabilized:
            nb_changes += bundle_stabilized
        self._capture_intermediate_snapshot("post_bundle_stabilize")
        # Canonicalise inline ``mop_d(add(X, K))`` operands onto the matching
        # stkvar alias.  Required so IDA's ``optimize_global`` sees write and
        # read sides addressing the same memory expression; otherwise its
        # intraprocedural aliasing analysis DCEs the writes (sub_7FFD byte-emit
        # corridor regression).  Runs AFTER snap17 capture so the diff between
        # snap17 (pre-canon) and snap18 (post-canon, post-optimize_global) is
        # legible.
        try:
            from d810.hexrays.mutation.insn_snapshot_materializer import (
                canonicalize_inline_add_in_mba,
            )

            canonicalize_inline_add_in_mba(self.mba)
        except Exception:
            unflat_logger.debug(
                "inline_add_to_stkvar canonicalisation failed (non-critical)",
                exc_info=True,
            )
        if os.environ.get("D810_TERMINAL_BYTE_MBL_KEEP", "1") == "1":
            try:
                tagged = self._tag_terminal_byte_mbl_keep(snapshot)
                if tagged:
                    self._capture_intermediate_snapshot(
                        "post_mbl_keep_terminal_byte"
                    )
            except Exception:
                unflat_logger.debug(
                    "MBL_KEEP terminal-byte tag failed (non-critical)",
                    exc_info=True,
                )

        # Diagnostic escape hatch: keep every live block.  Default-off because
        # it also preserves dispatcher residue that masks structural loop shape.
        if os.environ.get("D810_TAG_ALL_MBL_KEEP", "0") == "1":
            try:
                qty = int(getattr(self.mba, "qty", 0) or 0)
                tagged = 0
                for serial in range(qty):
                    blk = self.mba.get_mblock(serial)
                    if blk is None:
                        continue
                    try:
                        blk.flags |= MBL_KEEP
                        tagged += 1
                    except Exception:
                        continue
                unflat_logger.info(
                    "MBL_KEEP_TAG_ALL applied tagged=%d/qty=%d", tagged, qty
                )
                self._capture_intermediate_snapshot("post_mbl_keep_tag_all")
            except Exception:
                unflat_logger.debug(
                    "MBL_KEEP blanket tag failed (non-critical)", exc_info=True,
                )
        # uee-32r3 Track B.2: env-gated D810_TAIL_DISTINCT_BYTE topology-only
        # experiment. Run AFTER post_bundle_stabilize snapshot so that:
        #   (a) snap17 was just captured FROM the live MBA (identical state),
        #   (b) live MBA has not been transformed since (planner serials map
        #       directly), and
        #   (c) IDA's optimize_global has not yet run for the next maturity,
        #       so byte_emit handlers are still present and reachable.
        # Default-off; only fires when the corresponding env gate is set.
        try:
            from d810.hexrays.mutation.byte_emit_tail_isolation_runtime import (
                maybe_rewrite_impossible_return_artifact_edges,
                maybe_run_byte_anchor,
                maybe_run_terminal_tail_cascade_egress_lowering,
                maybe_run_tail_distinct,
                maybe_run_tail_duplicate_convergence,
                maybe_run_tail_state_cascade,
            )
            from d810.hexrays.mutation.byte_tail_runtime_evidence import (
                ByteTailRuntimeEvidence,
                StaticByteTailRuntimeEvidenceProvider,
            )

            unflat_logger.info(
                "TAIL_SHAPING_HOOK phase=after_post_bundle_stabilize"
            )
            fact_view = getattr(snapshot, "diagnostic_fact_view", None)
            if fact_view is None and self.flow_context is not None:
                try:
                    fact_view = self.flow_context.validated_fact_view(
                        self.cur_maturity
                    )
                except Exception:
                    unflat_logger.debug(
                        "terminal_tail_cascade_egress fact view lookup failed",
                        exc_info=True,
                    )
                    fact_view = None
            runtime_fact_raw = os.environ.get(
                "D810_TERMINAL_TAIL_CASCADE_EGRESS_RUNTIME_FACTS", "0"
            )
            if str(runtime_fact_raw).lower() in {"1", "true", "yes", "on"}:
                try:
                    from d810.recon.flow.runtime_evidence import (
                        ensure_terminal_byte_fact_view,
                    )

                    fact_view = ensure_terminal_byte_fact_view(
                        self.mba,
                        func_ea=int(getattr(self.mba, "entry_ea", 0) or 0),
                        maturity=int(
                            getattr(self.mba, "maturity", self.cur_maturity) or 0
                        ),
                        fact_view=fact_view,
                        phase="post_bundle_stabilize",
                    )
                except Exception:
                    unflat_logger.debug(
                        "terminal_tail_cascade_egress runtime fact collection failed",
                        exc_info=True,
                    )
            latest_dag = None
            try:
                from d810.recon.flow.runtime_evidence import (
                    get_latest_reconstruction_dag,
                )

                latest_dag = get_latest_reconstruction_dag(
                    int(getattr(self.mba, "entry_ea", 0) or 0)
                )
            except Exception:
                unflat_logger.debug(
                    "terminal_tail_cascade_egress DAG lookup failed",
                    exc_info=True,
                )
            function_priors = FunctionAnalysisPriors()
            if self.flow_context is not None:
                function_priors = self.flow_context.function_analysis_priors(
                    self.mba.entry_ea
                )
            impossible_return_artifact_edges = tuple(
                function_priors
                .return_frontier_artifacts
                .impossible_return_artifact_edges
            )
            evidence_provider = StaticByteTailRuntimeEvidenceProvider(
                ByteTailRuntimeEvidence(
                    fact_view=fact_view,
                    dag=latest_dag,
                    terminal_tail_cascade_egress=(
                        function_priors.terminal_tail_cascade_egress
                    ),
                    impossible_return_artifact_edges=(
                        impossible_return_artifact_edges
                    ),
                )
            )
            maybe_run_terminal_tail_cascade_egress_lowering(
                self.mba,
                fact_view=fact_view,
                dag=latest_dag,
                evidence_provider=evidence_provider,
            )
            maybe_rewrite_impossible_return_artifact_edges(
                self.mba,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_distinct(
                self.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_duplicate_convergence(
                self.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_tail_state_cascade(
                self.mba,
                fact_view=fact_view,
                evidence_provider=evidence_provider,
            )
            maybe_run_byte_anchor(self.mba)
        except Exception:
            unflat_logger.debug(
                "tail_distinct hook failed (non-critical)", exc_info=True,
            )

        probe_blocks, probe_targets = self._collect_post_apply_may_only_probe_blocks(
            pipeline, results
        )
        sticky_entry_ea = getattr(self, "_sticky_may_only_probe_entry_ea", None)
        if sticky_entry_ea != self.mba.entry_ea:
            self._sticky_may_only_probe_entry_ea = self.mba.entry_ea
            self._sticky_may_only_probe_blocks = set()
            self._sticky_may_only_probe_targets = set()
        self._sticky_may_only_probe_blocks.update(probe_blocks)
        self._sticky_may_only_probe_targets.update(probe_targets)
        probe_blocks = tuple(sorted(self._sticky_may_only_probe_blocks))
        probe_targets = tuple(sorted(self._sticky_may_only_probe_targets))
        self._apply_post_apply_may_only_probe(
            block_serials=probe_blocks,
            target_blocks=probe_targets,
        )

        # BST cleanup invalidates dispatcher/BST state — suppress re-iteration
        # so IDA does not invoke Hodur again on the cleaned CFG.
        if bst_cleanup_ran:
            unflat_logger.info(
                "BST cleanup modified CFG — suppressing Hodur re-iteration"
            )
            nb_changes = 0

        # Re-apply the may-only probe on the final live MBA. Some late bridge
        # rescue blocks (notably the sub_7FFD frontier latch) are only
        # materialized after the first post-pipeline probe point.
        self._apply_post_apply_may_only_probe(
            block_serials=probe_blocks,
            target_blocks=probe_targets,
        )

        # uee-jfta follow-up: optional MBL_KEEP experiment.  After d810's
        # pipeline finishes, IDA's GLBOPT1 cleanup runs aggressive
        # block-level DCE.  Marking every reachable block with MBL_KEEP
        # preserves them past ``remove_empty_and_unreachable_blocks()``
        # and ``merge_blocks()``.  Block-level only — does NOT preserve
        # instruction-level DCE (dead-store elimination still wipes
        # individual instructions).  Gated by class flag.
        if self.MBL_KEEP_ENABLED and self.mba is not None and self.mba.qty > 1:
            keep_visited: set[int] = set()
            keep_queue: list[int] = [0]
            while keep_queue:
                serial = keep_queue.pop()
                if serial in keep_visited or serial < 0 or serial >= self.mba.qty:
                    continue
                keep_visited.add(serial)
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                for i in range(blk.nsucc()):
                    keep_queue.append(blk.succ(i))
            kept_serials: list[int] = []
            for serial in sorted(keep_visited):
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                pre_flags = int(blk.flags)
                blk.flags |= ida_hexrays.MBL_KEEP
                post_flags = int(blk.flags)
                if pre_flags != post_flags:
                    kept_serials.append(serial)
                    unflat_logger.info(
                        "MBL_KEEP: blk[%d] flags 0x%05x -> 0x%05x (set MBL_KEEP=0x%05x)",
                        serial, pre_flags, post_flags, ida_hexrays.MBL_KEEP,
                    )
            unflat_logger.info(
                "MBL_KEEP: marked %d/%d reachable blocks (kept_serials=%s)",
                len(kept_serials), len(keep_visited),
                kept_serials[:30],
            )

        return nb_changes

    def _tag_terminal_byte_mbl_keep(self, snapshot: AnalysisSnapshot) -> int:
        fact_view = getattr(snapshot, "diagnostic_fact_view", None)
        if fact_view is None and self.flow_context is not None:
            try:
                fact_view = self.flow_context.validated_fact_view(self.cur_maturity)
            except Exception:
                unflat_logger.debug(
                    "MBL_KEEP_TERMINAL_BYTE fact view lookup failed",
                    exc_info=True,
                )
                fact_view = None
        if fact_view is None:
            unflat_logger.info("MBL_KEEP_TERMINAL_BYTE skipped reason=no_fact_view")
            return 0

        targets = select_terminal_byte_keep_targets(fact_view)
        if not targets:
            unflat_logger.info("MBL_KEEP_TERMINAL_BYTE skipped reason=no_targets")
            return 0

        qty = int(getattr(self.mba, "qty", 0) or 0)
        tagged_serials: list[int] = []
        for serial in range(qty):
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            if not _block_matches_terminal_byte_target(blk, targets):
                continue
            try:
                pre_flags = int(blk.flags)
                blk.flags |= MBL_KEEP
                post_flags = int(blk.flags)
            except Exception:
                continue
            tagged_serials.append(serial)
            if pre_flags != post_flags:
                unflat_logger.info(
                    "MBL_KEEP_TERMINAL_BYTE blk[%d] flags 0x%05x -> 0x%05x",
                    serial,
                    pre_flags,
                    post_flags,
                )

        bytes_kept = sorted(
            {
                int(t.byte_index)
                for t in targets
                if t.byte_index is not None
            }
        )
        unflat_logger.info(
            "MBL_KEEP_TERMINAL_BYTE targets=%d bytes=%s tagged=%d serials=%s",
            len(targets),
            bytes_kept,
            len(tagged_serials),
            tagged_serials[:30],
        )
        return len(tagged_serials)

    def _stabilize_sub7ffd_post_pipeline_bundle(self) -> int:
        """Make the fragile 80->118 setup/use corridor compaction-stable.

        The repaired DAG and post-pipeline MBA already recover the semantic
        bundle, but Hex-Rays later drops the reaching defs from blk[80] while
        preserving uses that flow out of blk[118]. For the specific
        ``sub_7FFD3338C040`` sample, split the shared conditional consumer for
        predecessor ``80`` and migrate the setup instructions into that private
        conditional clone so defs and immediate uses are kept together.
        """
        # NOTE: This legacy sample-specific repair bypasses PatchPlan by using
        # DeferredGraphModifier directly.  That means block creation here has
        # no planner lineage and no transaction-engine provenance.  Keep it
        # disabled until we can either port it to a PlanFragment/PatchPlan or
        # prove it is dead enough to delete.  The stack trace below is
        # intentional diagnostic noise while we track why this hook is still
        # reached from the orchestrator.
        unflat_logger.warning(
            "sub7ffd bundle stabilize DISABLED: direct DeferredGraphModifier path"
            " bypasses PatchPlan; HodurUnflattener currently calls this after"
            " any non-empty pipeline before post_bundle_stabilize\ncaller stack:\n%s",
            "".join(traceback.format_stack()[-40:]),
        )
        return 0
        if int(getattr(self.mba, "entry_ea", 0) or 0) != _SUB7FFD_FUNC_EA:
            return 0
        unflat_logger.info(
            "sub7ffd bundle stabilize inspect: maturity=%s qty=%d",
            self.cur_maturity,
            self.mba.qty,
        )

        source_blk = self.mba.get_mblock(80)
        ref_blk = self.mba.get_mblock(118)
        if source_blk is None or ref_blk is None:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: source80=%s ref118=%s",
                source_blk is not None,
                ref_blk is not None,
            )
            return 0
        if source_blk.nsucc() != 1 or source_blk.succ(0) != 118:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: blk80 nsucc=%d succ0=%s",
                source_blk.nsucc(),
                source_blk.succ(0) if source_blk.nsucc() > 0 else None,
            )
            return 0
        if ref_blk.nsucc() != 2 or ref_blk.tail is None:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: blk118 nsucc=%d tail=%s",
                ref_blk.nsucc(),
                ref_blk.tail is not None,
            )
            return 0
        if not ida_hexrays.is_mcode_jcond(ref_blk.tail.opcode):
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: blk118 tail opcode=%s is not jcond",
                ref_blk.tail.opcode,
            )
            return 0

        source_insns: list[ida_hexrays.minsn_t] = []
        nop_eas: list[int] = []
        cur_ins = source_blk.head
        while cur_ins is not None:
            is_trailing_goto = (
                source_blk.tail is not None
                and source_blk.tail.opcode == ida_hexrays.m_goto
                and cur_ins.next is None
            )
            if is_trailing_goto:
                break
            cloned_ins = ida_hexrays.minsn_t(cur_ins)
            cloned_ins.setaddr(self.mba.entry_ea)
            source_insns.append(cloned_ins)
            if cur_ins.ea:
                nop_eas.append(int(cur_ins.ea))
            cur_ins = cur_ins.next

        # The recovered bundle is the five-instruction setup in blk[80]:
        # ldx + four constant moves before the goto into blk[118].
        if len(source_insns) != 5:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: blk80 prelude len=%d",
                len(source_insns),
            )
            return 0

        conditional_target = int(getattr(ref_blk.tail.d, "b", -1))
        succs = [ref_blk.succ(i) for i in range(ref_blk.nsucc())]
        if conditional_target not in succs:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: cond_target=%d succs=%s",
                conditional_target,
                succs,
            )
            return 0
        fallthrough_target = next((succ for succ in succs if succ != conditional_target), -1)
        if fallthrough_target < 0:
            unflat_logger.info(
                "sub7ffd bundle stabilize skip: no fallthrough succs=%s cond=%d",
                succs,
                conditional_target,
            )
            return 0

        private_conditional_serial = int(self.mba.qty - 1)
        private_fallthrough_serial = int(self.mba.qty)

        first_modifier = DeferredGraphModifier(self.mba)
        first_modifier.queue_create_conditional_redirect(
            source_blk_serial=80,
            ref_blk_serial=118,
            conditional_target_serial=conditional_target,
            fallthrough_target_serial=fallthrough_target,
            instructions_to_copy=(),
            expected_conditional_serial=private_conditional_serial,
            expected_fallthrough_serial=private_fallthrough_serial,
            description="sub7ffd post_pipeline bundle stabilize 80->118",
        )
        for insn_ea in nop_eas:
            first_modifier.queue_insn_nop(
                block_serial=80,
                insn_ea=insn_ea,
                description="sub7ffd move setup into private 118 clone",
            )

        first_applied = first_modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=False,
            rollback_on_verify_failure=False,
            continue_on_verify_failure=False,
            defer_post_apply_maintenance=False,
            enable_snapshot_rollback=True,
        )
        if first_applied <= 0:
            return 0

        source_blk = self.mba.get_mblock(80)
        if (
            source_blk is None
            or source_blk.nsucc() != 1
            or source_blk.succ(0) != private_conditional_serial
        ):
            unflat_logger.info(
                "sub7ffd bundle stabilize skip second phase: blk80 nsucc=%s succ0=%s expected=%s",
                source_blk.nsucc() if source_blk is not None else None,
                source_blk.succ(0) if source_blk is not None and source_blk.nsucc() > 0 else None,
                private_conditional_serial,
            )
            return int(first_applied)

        second_modifier = DeferredGraphModifier(self.mba)
        second_modifier.queue_create_and_redirect(
            source_block_serial=80,
            final_target_serial=private_conditional_serial,
            instructions_to_copy=tuple(source_insns),
            is_0_way=False,
            description="sub7ffd private setup block before cloned 118",
        )
        second_applied = second_modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=False,
            rollback_on_verify_failure=False,
            continue_on_verify_failure=False,
            defer_post_apply_maintenance=False,
            enable_snapshot_rollback=True,
        )
        applied = int(first_applied) + int(second_applied)
        if applied > 0:
            unflat_logger.info(
                "sub7ffd post_pipeline bundle stabilize applied %d deferred modifications",
                applied,
            )
        return int(applied)

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

    def _capture_post_pipeline_diagnostic_snapshot(self) -> None:
        """Persist a post-pipeline MBA snapshot for recon-only/manual inspection."""
        try:
            from d810.hexrays.mba_serializer import mba_to_block_snapshots
            from d810.hexrays.observability import request_capture_mba_snapshot
            request_capture_mba_snapshot(
                blocks=mba_to_block_snapshots(self.mba),
                label="post_pipeline",
                func_ea=self.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase="post_pipeline",
            )
        except Exception:
            unflat_logger.debug(
                "post_pipeline diagnostic snapshot failed (non-critical)",
                exc_info=True,
            )

    def _capture_intermediate_snapshot(
        self, label: str, *, phase: str = "post_apply"
    ) -> None:
        """Take a labeled MBA snapshot at an arbitrary intermediate point.

        Best-effort: failure is logged debug-only and never gates the pipeline.
        Used to bisect the post-HCC/pre-post_pipeline window when investigating
        which pass kills which block.
        """
        try:
            from d810.hexrays.mba_serializer import mba_to_block_snapshots
            from d810.hexrays.observability import request_capture_mba_snapshot
            request_capture_mba_snapshot(
                blocks=mba_to_block_snapshots(self.mba),
                label=label,
                func_ea=self.mba.entry_ea,
                maturity="MMAT_GLBOPT1",
                phase=phase,
            )
        except Exception:
            unflat_logger.debug(
                "intermediate snapshot %s failed (non-critical)",
                label,
                exc_info=True,
            )

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

    def _get_effective_state_var_stkoff(
        self, state_machine: DispatcherStateMachine | None = None
    ) -> int | None:
        """Return the state-variable stack offset via the family adapter."""
        return self._family.get_effective_state_var_stkoff(state_machine)

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

    def _collect_post_apply_may_only_probe_blocks(
        self, pipeline: list, results: list[StageResult]
    ) -> tuple[tuple[int, ...], tuple[int, ...]]:
        block_serials: set[int] = set()
        target_blocks: set[int] = set()
        for fragment, result in zip(pipeline, results):
            if fragment.strategy_name != "state_write_reconstruction":
                continue
            if not result.success or result.edits_applied <= 0:
                continue
            fidelity = fragment.metadata.get("structured_region_fidelity", {})
            if not isinstance(fidelity, dict):
                continue
            for serial in fidelity.get("post_apply_may_only_probe_blocks", ()):
                if isinstance(serial, int):
                    block_serials.add(serial)
            for serial in fidelity.get("post_apply_may_only_probe_targets", ()):
                if isinstance(serial, int):
                    target_blocks.add(serial)
        return tuple(sorted(block_serials)), tuple(sorted(target_blocks))

    def _apply_post_apply_may_only_probe(
        self,
        *,
        block_serials: tuple[int, ...],
        target_blocks: tuple[int, ...] = (),
    ) -> None:
        probe_targets = {
            serial for serial in target_blocks if 0 <= serial < self.mba.qty
        }
        expanded_serials = set(block_serials)
        if probe_targets:
            for serial in range(self.mba.qty):
                blk = self.mba.get_mblock(serial)
                if blk is None:
                    continue
                try:
                    succs = [int(blk.succ(i)) for i in range(blk.nsucc)]
                except Exception:
                    continue
                if any(target in probe_targets for target in succs):
                    expanded_serials.add(serial)
        if not expanded_serials:
            return

        applied = 0
        for serial in sorted(expanded_serials):
            if serial < 0 or serial >= self.mba.qty:
                continue
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            try:
                blk.make_lists_ready()
            except Exception:
                unflat_logger.debug(
                    "may-only probe: make_lists_ready failed for blk[%d]",
                    serial,
                    exc_info=True,
                )
                continue

            changed_attrs: list[str] = []
            for may_attr, must_attr in (
                ("maybuse", "mustbuse"),
                ("maybdef", "mustbdef"),
            ):
                may_list = getattr(blk, may_attr, None)
                must_list = getattr(blk, must_attr, None)
                clear = getattr(may_list, "clear", None)
                add = getattr(may_list, "add", None)
                if (
                    may_list is None
                    or must_list is None
                    or clear is None
                    or add is None
                ):
                    continue

                may_only = ida_hexrays.mlist_t()
                try:
                    may_only.add(may_list)
                    may_only.sub(must_list)
                    clear()
                    add(may_only)
                except Exception:
                    unflat_logger.debug(
                        "may-only probe: failed to shrink %s for blk[%d]",
                        may_attr,
                        serial,
                        exc_info=True,
                    )
                    continue

                changed_attrs.append(
                    f"{may_attr}={_mlist_text(may_only) or '<empty>'}"
                )

            if not changed_attrs:
                continue

            applied += 1
            unflat_logger.info(
                "Applied may-only liveness probe to blk[%d]: %s",
                serial,
                ", ".join(changed_attrs),
            )

        if applied:
            unflat_logger.info(
                "Applied may-only liveness probe to %d leaked frontier blocks",
                applied,
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
        # NOTE: This legacy helper queues directly on DeferredGraphModifier
        # instead of returning graph modifications through PlanFragment ->
        # PatchPlan.  It should not be used by the modern Hodur pipeline.  If
        # this warning fires, treat it as a call-site bug and port that caller
        # to ModificationBuilder/PatchPlan before re-enabling behavior.
        unflat_logger.warning(
            "legacy _queue_handler_redirect DISABLED: direct deferred path"
            " bypasses PatchPlan\ncaller stack:\n%s",
            "".join(traceback.format_stack()[-40:]),
        )
        self._last_redirect_meta = {
            "kind": "disabled_legacy_queue_handler_redirect",
            "source_block": getattr(path, "exit_block", None),
            "via_pred": None,
            "target": target,
        }
        return False
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
            try:
                from d810.cfg.observability import observe_cfg_provenance as log_cfg_provenance
                log_cfg_provenance(
                    pass_name="bst_cleanup",
                    action="SEVER_EDGE",
                    block_serial=blk.serial,
                    target_serial=dispatcher_serial,
                    reason="sever_1way_handler_to_dispatcher",
                    mba=mba,
                )
            except Exception:
                pass

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
                try:
                    from d810.cfg.observability import observe_cfg_provenance as log_cfg_provenance
                    log_cfg_provenance(
                        pass_name="bst_cleanup",
                        action="REDIRECT_EDGE",
                        block_serial=serial,
                        target_serial=keep_serial,
                        reason="convert_2way_to_goto_drop_dispatcher_arm",
                        extra={"old_succs": [int(succ0), int(succ1)]},
                        mba=mba,
                    )
                except Exception:
                    pass
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
                try:
                    from d810.cfg.observability import observe_cfg_provenance as log_cfg_provenance
                    log_cfg_provenance(
                        pass_name="bst_cleanup",
                        action="SEVER_EDGE",
                        block_serial=dispatcher_serial,
                        target_serial=succ_serial,
                        reason="dispatcher_outgoing_to_bst_comparison",
                        mba=mba,
                    )
                except Exception:
                    pass
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

    def _nop_unreachable_blocks_after_bst_cleanup(
        self,
        *,
        dispatcher_serial: int,
        bst_serials: set[int],
        reconstruction_live: set[int] | None = None,
    ) -> int:
        """Gut-and-Wire soft-kill of unreachable blocks after BST cleanup.

        ``mba.remove_empty_and_unreachable_blocks()`` segfaults at GLBOPT1.
        Instead of removing blocks, this pass "soft-kills" them: NOP payload
        instructions and leave blocks as 1-way goto shells (empty
        passthroughs).  2-way conditional blocks are converted to 1-way by
        replacing the conditional tail with ``m_goto`` to the first successor.
        Hex-Rays' later maturity passes (MMAT_CALLS+) safely fold them out.

        Blocks in *reconstruction_live* (source/target serials from applied
        pipeline modifications) are protected: they and their BFS-forward
        reachable successors are excluded from cleanup even when not reachable
        from block 0.  This prevents Gut-and-Wire from destroying corridors
        wired by the reconstruction strategy.
        """
        mba = self.mba
        qty = int(getattr(mba, "qty", 0) or 0) if mba is not None else 0
        if qty <= 1:
            return 0

        visited: set[int] = set()
        queue: list[int] = [0]
        while queue:
            serial = queue.pop(0)
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                succ = blk.succ(i)
                if succ not in visited:
                    queue.append(succ)

        stop_serial = qty - 1
        unreachable = {
            serial
            for serial in range(mba.qty)
            if serial not in visited and serial != stop_serial
        }

        # Protect reconstruction-owned corridors: BFS forward from every
        # live corridor block that ended up unreachable from block 0.
        if reconstruction_live:
            corridor_seeds = reconstruction_live & unreachable
            if corridor_seeds:
                corridor_visited: set[int] = set()
                corridor_queue = list(corridor_seeds)
                while corridor_queue:
                    serial = corridor_queue.pop(0)
                    if serial in corridor_visited or serial < 0 or serial >= mba.qty:
                        continue
                    corridor_visited.add(serial)
                    blk = mba.get_mblock(serial)
                    if blk is None:
                        continue
                    for i in range(blk.nsucc()):
                        succ = blk.succ(i)
                        if succ not in corridor_visited:
                            corridor_queue.append(succ)
                protected = corridor_visited & unreachable
                if protected:
                    unflat_logger.info(
                        "GutAndWire: protecting %d reconstruction-owned corridor "
                        "blocks from cleanup (seeds=%s)",
                        len(protected),
                        sorted(corridor_seeds)[:20],
                    )
                unreachable -= protected

        if not unreachable:
            unflat_logger.info(
                "DeadBlockElimination: no unreachable live blocks after BST cleanup"
            )
            return 0

        # REMOVED: return frontier gate was checking the wrong domain —
        # _audit_return_sites tracks pre-linearization return sites whose
        # origin_block serials belong to BST/dispatcher blocks that SHOULD
        # be eliminated.  The gate incorrectly prevented dead block cleanup
        # for blocks that are legitimately unreachable after linearization.

        # Diagnostic: walk dispatcher component for logging purposes
        dispatcher_component: set[int] = set()
        forward_queue = [dispatcher_serial]
        while forward_queue:
            serial = forward_queue.pop()
            if serial in dispatcher_component or serial not in unreachable:
                continue
            dispatcher_component.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                succ = blk.succ(i)
                if succ in unreachable and succ not in dispatcher_component:
                    forward_queue.append(succ)

        backward_queue = [dispatcher_serial]
        while backward_queue:
            serial = backward_queue.pop()
            if serial < 0 or serial >= mba.qty:
                continue
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.npred()):
                pred = blk.pred(i)
                if pred in unreachable and pred not in dispatcher_component:
                    dispatcher_component.add(pred)
                    backward_queue.append(pred)

        dispatcher_component.update(unreachable & set(bst_serials))

        orphaned = unreachable - dispatcher_component
        if orphaned:
            unflat_logger.info(
                "DeadBlockElimination: %d dispatcher-island + %d orphaned unreachable blocks "
                "(total %d)",
                len(dispatcher_component), len(orphaned), len(unreachable),
            )

        # Clean ALL unreachable blocks, not just the dispatcher island
        cleanup_candidates = set(unreachable)
        cleanup_candidates.discard(stop_serial)
        if not cleanup_candidates:
            unflat_logger.info(
                "DeadBlockElimination: no unreachable dispatcher component after BST cleanup"
            )
            return 0

        # ----- Gut-and-Wire soft-kill pass -----
        # mba.remove_empty_and_unreachable_blocks() segfaults at GLBOPT1.
        # Instead of removing blocks or converting to 0-way shells (which
        # triggers INTERR 50846), NOP payload instructions and leave blocks
        # as 1-way goto shells.  Hex-Rays' later maturity passes safely
        # fold these empty passthrough blocks out.
        gutted = 0
        for serial in sorted(cleanup_candidates):
            blk = mba.get_mblock(serial)
            if blk is None:
                continue

            nsucc = blk.nsucc()

            # Skip terminal (0-way) blocks — don't modify BLT_STOP etc.
            if nsucc == 0:
                continue

            tail = blk.tail

            # Step 1: NOP all payload instructions (everything before tail).
            insn = blk.head
            while insn is not None and insn != tail:
                next_insn = insn.next
                blk.make_nop(insn)
                insn = next_insn

            # Step 2: Handle block type.
            if nsucc > 1:
                # 2-way (conditional) block — convert to 1-way goto shell.
                # Keep the first successor (fallthrough), drop the rest.
                keep_succ = blk.succ(0)
                drop_succs = [blk.succ(i) for i in range(1, nsucc)]

                # Convert tail instruction to m_goto targeting kept successor.
                if tail is not None:
                    tail.opcode = ida_hexrays.m_goto
                    tail.l.make_blkref(keep_succ)
                    tail.r.erase()
                    tail.d.erase()

                # Remove dropped successors from succset and their predsets.
                for drop_serial in drop_succs:
                    blk.succset._del(drop_serial)
                    drop_blk = mba.get_mblock(drop_serial)
                    if drop_blk is not None:
                        drop_blk.predset._del(serial)
                        drop_blk.mark_lists_dirty()

                blk.type = ida_hexrays.BLT_1WAY

            # For 1-way blocks (nsucc == 1): tail is already m_goto,
            # leave it intact — the block is already a 1-way shell.

            blk.mark_lists_dirty()
            gutted += 1
            try:
                from d810.cfg.observability import observe_cfg_provenance as log_cfg_provenance
                log_cfg_provenance(
                    pass_name="gut_and_wire",
                    action="SOFT_KILL",
                    block_serial=serial,
                    target_serial=(blk.succ(0) if blk.nsucc() > 0 else None),
                    reason="unreachable_after_bst_cleanup",
                    extra={"original_nsucc": int(nsucc)},
                    mba=mba,
                )
            except Exception:
                pass

        if gutted == 0:
            unflat_logger.info(
                "GutAndWire: no blocks gutted (all candidates were None)"
            )
            return 0

        # ----- Forward-redirect pass -----
        # Gutted blocks still have goto targets pointing to other dead blocks,
        # creating back-edges that IDA's structurer interprets as while loops.
        # Redirect all dead-zone gotos to BLT_STOP (the function's terminal
        # block) so that all edges within the dead zone point forward.
        stop_serial: int | None = None
        for i in range(mba.qty):
            if mba.get_mblock(i).type == ida_hexrays.BLT_STOP:
                stop_serial = i
                break
        if stop_serial is None:
            # Fallback: use last block serial (BLT_STOP is always last)
            stop_serial = mba.qty - 1

        redirected = 0
        for serial in sorted(cleanup_candidates):
            blk = mba.get_mblock(serial)
            if blk is None or blk.nsucc() != 1:
                continue
            succ = blk.succ(0)
            if succ == stop_serial:
                continue  # already pointing forward
            if succ not in cleanup_candidates:
                continue  # successor is live — leave it alone

            # Redirect goto target to BLT_STOP
            tail = blk.tail
            if tail is not None and tail.opcode == ida_hexrays.m_goto:
                tail.l.make_blkref(stop_serial)

            # Update successor set
            blk.succset._del(succ)
            blk.succset.push_back(stop_serial)

            # Update predecessor sets
            old_succ_blk = mba.get_mblock(succ)
            if old_succ_blk is not None:
                old_succ_blk.predset._del(serial)
                old_succ_blk.mark_lists_dirty()

            stop_blk = mba.get_mblock(stop_serial)
            if stop_blk is not None:
                # Avoid duplicate predset entries
                already_pred = False
                for pi in range(stop_blk.npred()):
                    if stop_blk.pred(pi) == serial:
                        already_pred = True
                        break
                if not already_pred:
                    stop_blk.predset.push_back(serial)
                stop_blk.mark_lists_dirty()

            blk.mark_lists_dirty()
            redirected += 1
            try:
                from d810.cfg.observability import observe_cfg_provenance as log_cfg_provenance
                log_cfg_provenance(
                    pass_name="gut_and_wire",
                    action="REDIRECT_EDGE",
                    block_serial=serial,
                    target_serial=stop_serial,
                    reason="forward_redirect_to_blt_stop",
                    extra={"old_target": int(succ)},
                    mba=mba,
                )
            except Exception:
                pass

        # Mark chains dirty once after all mutations.
        mba.mark_chains_dirty()

        unflat_logger.info(
            "GutAndWire: soft-killed %d unreachable blocks as 1-way goto shells"
            " (%d redirected forward to BLT_STOP)",
            gutted, redirected,
        )
        return gutted

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
    ) -> DispatcherStateMachine | None:
        """Backward-compatible wrapper for family-owned cache fallback."""
        return self._family.build_state_machine_from_cache(analysis)

    def _try_switch_table_detection(
        self, mba: "ida_hexrays.mba_t",
    ) -> DispatcherStateMachine | None:
        """Backward-compatible wrapper for family-owned switch-table fallback."""
        return self._family.try_switch_table_detection(mba)
