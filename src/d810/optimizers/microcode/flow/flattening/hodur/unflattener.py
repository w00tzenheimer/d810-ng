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

import ida_hexrays

from d810.core import logging
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.flattening.unflattening_rule_lifecycle import (
    ComposedUnflatteningRule,
)
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.flattening.hodur.analysis import (
    HODUR_STATE_CHECK_OPCODES,
    HODUR_STATE_UPDATE_OPCODES,
    MAX_STATE_CONSTANTS_HODUR,
    MIN_STATE_CONSTANT,
    MIN_STATE_CONSTANTS,
    HodurStateMachineDetector,
)
from d810.backends.hexrays.evidence.datamodel import (
    DispatcherStateMachine,
    Pass0RedirectRecord,
)
from d810.optimizers.microcode.flow.flattening.hodur.family import (
    HodurStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.hodur.profile import (
    default_hodur_profile,
)
from d810.optimizers.microcode.flow.flattening.hodur.runtime_services import (
    HodurRuntimeServices,
)
from d810.optimizers.microcode.flow.flattening.hodur.rule_services import (
    HodurRuleServices,
)
from d810.optimizers.microcode.flow.flattening.engine.planner import (
    PipelinePolicy,
    UnflatteningPlanner,
)
from d810.analyses.control_flow.provenance import (
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    FamilyContext,
)
from d810.optimizers.microcode.flow.flattening.engine.state_machine_runtime import (
    run_state_machine_family_pass,
)
from d810.analyses.control_flow.graph_checks import SemanticGate
from d810.optimizers.microcode.flow.flattening.hodur.return_sites import (
    HodurReturnSiteProvider,
)
unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)


class HodurUnflattener(ComposedUnflatteningRule):
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

    CONFIG_SCHEMA = ComposedUnflatteningRule.CONFIG_SCHEMA + (
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
        self._profile = profile
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
        self._rule_services = HodurRuleServices(self)
        self._services = HodurRuntimeServices(self._rule_services)

        # Return frontier audit components
        self._return_site_provider = HodurReturnSiteProvider()
        self._audit_return_sites: tuple = ()  # Populated at pre_plan, reused across stages
        self._fact_view_observed_keys: set[tuple[int, int, int]] = set()
        self._last_live_residual_dispatcher_preds_by_strategy: dict[
            str, tuple[int, ...]
        ] = {}

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

        self._last_live_residual_dispatcher_preds_by_strategy = {}
        result = run_state_machine_family_pass(
            family=self._family,
            profile=self._profile,
            context=FamilyContext.from_rule(self, blk),
            services=self._services,
        )
        return result.total_changes
